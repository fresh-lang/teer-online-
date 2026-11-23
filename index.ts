import { createClient } from "npm:@supabase/supabase-js@2";
import bcrypt from "npm:bcryptjs@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const APP_ORIGINS = (Deno.env.get("APP_ORIGINS") ?? "*").split(",").map((s) => s.trim());
const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const corsHeaders = (origin: string | null) => {
  const allowed = APP_ORIGINS.includes("*") || (origin !== null && APP_ORIGINS.includes(origin));
  return {
    "Access-Control-Allow-Origin": allowed ? (APP_ORIGINS.includes("*") ? "*" : origin!) : "null",
    "Access-Control-Allow-Headers": "authorization, x-session-token, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
};

const json = (data: unknown, status = 200, origin: string | null = null) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(origin), "Content-Type": "application/json; charset=utf-8" },
  });

const encoder = new TextEncoder();
const toB64Url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
const fromB64Url = (value: string) => {
  const b64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const raw = atob(b64 + "=".repeat((4 - b64.length % 4) % 4));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
};

async function passwordHash(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" }, key, 256,
  );
  return `pbkdf2-sha256$310000$${toB64Url(salt)}$${toB64Url(new Uint8Array(bits))}`;
}

async function verifyPassword(password: string, stored: string): Promise<{ valid: boolean; legacyBcrypt: boolean }> {
  if (stored.startsWith("pbkdf2-sha256$")) {
    const parts = stored.split("$");
    if (parts.length !== 4 || parts[0] !== "pbkdf2-sha256") return { valid: false, legacyBcrypt: false };
    const iterations = Number(parts[1]);
    if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 1000000) return { valid: false, legacyBcrypt: false };
    try {
      const salt = fromB64Url(parts[2]);
      const expected = fromB64Url(parts[3]);
      const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
      const actual = new Uint8Array(await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256,
      ));
      if (actual.length !== expected.length) return { valid: false, legacyBcrypt: false };
      let diff = 0;
      for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
      return { valid: diff === 0, legacyBcrypt: false };
    } catch {
      return { valid: false, legacyBcrypt: false };
    }
  }

  // Older bright-task registrations used bcrypt. Accept them once, then upgrade
  // the stored hash to PBKDF2 after a successful login.
  if (/^\$2[aby]\$/.test(stored)) {
    try {
      return { valid: await bcrypt.compare(password, stored), legacyBcrypt: true };
    } catch {
      return { valid: false, legacyBcrypt: true };
    }
  }
  return { valid: false, legacyBcrypt: false };
}

async function sha256Hex(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function cleanPhone(value: unknown): string {
  return String(value ?? "").replace(/\D/g, "");
}
function validPassword(value: unknown): value is string {
  return typeof value === "string" && value.length >= 8 && value.length <= 128;
}
function asOne<T>(value: T | T[] | null): T | null {
  return Array.isArray(value) ? (value[0] ?? null) : value;
}

async function rpc<T>(name: string, args: Record<string, unknown>): Promise<T> {
  const { data, error } = await supabase.rpc(name, args);
  if (error) throw new Error(error.message);
  return data as T;
}

async function makeSession(userId: string) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = toB64Url(tokenBytes);
  const tokenHash = await sha256Hex(token);
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  await rpc("api_create_session", {
    p_user_id: userId,
    p_token_hash: tokenHash,
    p_expires_at: expiresAt,
  });
  return { token, expires_at: expiresAt };
}

async function getSession(req: Request) {
  // Custom app session tokens are NOT JWTs. Send them in x-session-token.
  // Authorization remains reserved for the Supabase publishable/anon API key.
  const token = (req.headers.get("x-session-token") ?? "").trim();
  if (token.length < 30 || token.length > 200) return null;
  const tokenHash = await sha256Hex(token);
  const result = await rpc<unknown>("api_get_session_user", { p_token_hash: tokenHash });
  const rawUser = asOne(
    result as Record<string, unknown> | Record<string, unknown>[] | null,
  );
  if (!rawUser) return null;

  // SQL api_get_session_user returns "user_id", not "id".
  const userId = rawUser.id ?? rawUser.user_id;
  if (typeof userId !== "string" || !userId) return null;

  return {
    ...rawUser,
    id: userId,
    phone: cleanPhone(rawUser.phone),
  };
}

async function requireAdmin(user: Record<string, unknown> | null) {
  if (!user || typeof user.phone !== "string") return false;
  const phone = cleanPhone(user.phone);
  if (phone.length !== 10) return false;
  const { data, error } = await supabase.from("admin_allowlist")
    .select("phone")
    .eq("phone", phone)
    .eq("is_active", true)
    .maybeSingle();
  if (error) throw new Error("Admin authorization check failed");
  return Boolean(data);
}


// Khanapara Teer source verification. The source page's current result is accepted
// only when its FR/SR pair matches the newest archive row and the page update date.
const KHANAPARA_SOURCE_URL = "https://teer-result.com/khanapara-teer-result/";
const KHANAPARA_GROUNDS_SOURCE_URL = "https://shillongteergrounds.in/khanapara-teer-result-today/";
const KHANAPARA_MARKET = "Khanapara Teer (Evening)";
let khanaparaLastCheckAt = 0;
let khanaparaCheckPromise: Promise<unknown> | null = null;

function htmlToPlainText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;|&#160;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#0*39;|&apos;/gi, "'")
    .replace(/&#(\d+);/g, (_m, n) => String.fromCharCode(Number(n)))
    .replace(/\s+/g, " ")
    .trim();
}

function dateIsoToDmy(value: string): string {
  const m = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  return m ? m[3] + "/" + m[2] + "/" + m[1] : "";
}

function dateDmyToIso(value: string): string {
  const m = value.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  return m ? m[3] + "-" + m[2] + "-" + m[1] : "";
}

function normalizeResultDateIso(value: string): string {
  const raw = String(value ?? "").trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) return raw;
  return dateDmyToIso(raw.replaceAll("-", "/").replaceAll(".", "/"));
}

async function saveVerifiedResultHistory(market: string, date: string, fr: string, sr: string, source: string, sourceUpdatedAt: string | null = null) {
  if (!/^\d{2}\/\d{2}\/\d{4}$/.test(date) || !/^\d{2}$/.test(fr) || !/^\d{2}$/.test(sr)) {
    throw new Error("Only complete dated FR/SR pairs can be archived");
  }
  const resultDate = dateDmyToIso(date);
  const { data: existing, error: existingError } = await supabase.from("teer_result_history")
    .select("id,fr,sr,source").eq("market", market).eq("result_date", resultDate).maybeSingle();
  if (existingError) throw existingError;
  if (existing?.source === "admin") return { saved: false, reason: "admin_history_locked" };
  if (existing && source !== "admin" &&
      /^\d{2}$/.test(String(existing.fr ?? "")) && /^\d{2}$/.test(String(existing.sr ?? ""))) {
    return { saved: false, reason: "date_already_archived" };
  }
  const { error } = await supabase.from("teer_result_history").upsert({
    market, result_date: resultDate, fr, sr, source, source_updated_at: sourceUpdatedAt
  }, { onConflict: "market,result_date" });
  if (error) throw error;
  return { saved: true, repaired_incomplete: Boolean(existing) };
}


function extractGroundsModifiedAt(html: string, resultDateIso: string): string | null {
  const jsonLd = html.match(/"dateModified"\s*:\s*"([^"]+)"/i)?.[1] ?? "";
  const meta = html.match(/<meta[^>]+(?:property|name)=["'](?:article:modified_time|last-modified)["'][^>]+content=["']([^"']+)["']/i)?.[1] ??
    html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["'](?:article:modified_time|last-modified)["']/i)?.[1] ?? "";
  const raw = [jsonLd, meta].find(v => /T\d{2}:\d{2}/i.test(v)) ?? "";
  if (!raw) return null;
  const parsed = new Date(raw);
  if (!Number.isFinite(parsed.getTime())) return null;
  const localDate = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Kolkata", year: "numeric", month: "2-digit", day: "2-digit"
  }).format(parsed);
  return localDate === resultDateIso ? parsed.toISOString() : null;
}
async function fetchGroundsMarketPreview(market: string, url: string, headingName: "Shillong" | "Khanapara") {
  const response = await fetch(url, { method: "GET", headers: {
    "User-Agent": "TeerOnlineResultSync/1.0 (+source verification)",
    "Accept": "text/html,application/xhtml+xml", "Cache-Control": "no-cache"
  }});
  if (!response.ok) throw new Error("Source website returned HTTP " + response.status);
  const html = await response.text();
  if (!html || html.length < 1000) throw new Error("Source page content was empty or incomplete");
  const plain = htmlToPlainText(html);
  const heading = new RegExp(headingName + "\\s+Teer\\s+Result\\s*[-–:]?\\s*(\\d{2}[./-]\\d{2}[./-]\\d{4})", "i");
  const headingMatch = plain.match(heading);
  const pageDateRaw = headingMatch?.[1] ?? "";
  const pageDate = pageDateRaw.replaceAll(".", "/").replaceAll("-", "/");
  const dateParts = pageDate.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  const resultDateIso = dateParts ? dateParts[3] + "-" + dateParts[2] + "-" + dateParts[1] : "";
  const sectionStart = plain.toLowerCase().indexOf((headingName + " Teer Result").toLowerCase());
  const section = sectionStart >= 0 ? plain.slice(sectionStart, sectionStart + 900) : "";
  const rounds = section.match(/F\/R\s*\([^)]*\)\s*\|\s*S\/R\s*\([^)]*\)\s+(\d{2})\s*\|\s*(\d{2})/i);
  const fr = rounds?.[1] ?? "";
  const sr = rounds?.[2] ?? "";
  const sourceUpdatedAt = resultDateIso ? extractGroundsModifiedAt(html, resultDateIso) : null;
  const awaiting = /awaiting today's result|result is not yet declared|awaiting result/i.test(section);
  if (awaiting) return { ready: false, status: "awaiting", market, page_date: pageDate, source_updated_at: sourceUpdatedAt, source_url: url };
  if (!resultDateIso || !/^\d{2}$/.test(fr) || !/^\d{2}$/.test(sr)) {
    return { ready: false, status: "not_verified", market, page_date: pageDate, source_updated_at: sourceUpdatedAt, source_url: url };
  }
  return { ready: true, status: "verified", market, fr, sr, date: pageDate, source_updated_at: sourceUpdatedAt, source_url: url };
}
async function fetchShillongGroundsPreview() {
  return await fetchGroundsMarketPreview(SHILLONG_MARKET, SHILLONG_GROUNDS_SOURCE_URL, "Shillong");
}
async function fetchKhanaparaGroundsPreview() {
  return await fetchGroundsMarketPreview(KHANAPARA_MARKET, KHANAPARA_GROUNDS_SOURCE_URL, "Khanapara");
}
async function chooseFirstVerifiedPreview<T extends { ready: boolean; status: string; source_updated_at: string | null; source_url: string; date?: string }>(
  fetchers: Array<() => Promise<T>>
): Promise<T> {
  const attempts = await Promise.all(fetchers.map(async fetcher => {
    try {
      const preview = await fetcher();
      return { ...preview, observed_at: new Date().toISOString() };
    } catch (error) {
      return { ready: false, status: "source_error", source_updated_at: null, source_url: "",
        observed_at: new Date().toISOString(), error: error instanceof Error ? error.message : String(error) } as T;
    }
  }));
  const verified = attempts.filter(item => item.ready);
  if (verified.length) {
    verified.sort((a, b) => {
      const dateA = a.date ? dateDmyToIso(a.date) : "";
      const dateB = b.date ? dateDmyToIso(b.date) : "";
      if (dateA !== dateB) return dateB.localeCompare(dateA);
      return Date.parse(a.source_updated_at || a.observed_at) - Date.parse(b.source_updated_at || b.observed_at);
    });
    return verified[0];
  }
  return (attempts.find(item => item.status === "awaiting") || attempts.find(item => item.status !== "source_error") || attempts[0]) as T;
}

type KhanaparaSourcePreview =
  | { ready: false; status: string; market: string; page_date?: string; source_update_date?: string; previous_date?: string; previous_fr?: string; previous_sr?: string; source_updated_at: string | null; source_url: string }
  | { ready: true; status: "verified"; market: string; fr: string; sr: string; date: string; source_updated_at: string | null; source_url: string };

async function fetchKhanaparaSourcePreview(): Promise<KhanaparaSourcePreview> {
  const response = await fetch(KHANAPARA_SOURCE_URL, {
    method: "GET",
    headers: {
      "User-Agent": "TeerOnlineResultSync/1.0 (+source verification)",
      "Accept": "text/html,application/xhtml+xml",
      "Cache-Control": "no-cache",
    },
  });
  if (!response.ok) throw new Error("Source website returned HTTP " + response.status);
  const html = await response.text();
  if (!html || html.length < 1000) throw new Error("Source page content was empty or incomplete");

  const plain = htmlToPlainText(html);
  const updatedMatch = plain.match(/Updated\s+(\d{4}-\d{2}-\d{2})/i);
  const pageDateMatch = plain.match(/Khanapara Teer Result Today\s+(\d{2}-\d{2}-\d{4})/i);
  const updatedIso = updatedMatch?.[1] ?? "";
  const pageDate = pageDateMatch?.[1] ?? "";
  const awaiting = /Awaiting today's result/i.test(plain.slice(0, 6000));

  const archiveStart = plain.toLowerCase().indexOf("khanapara teer previous result list");
  const archiveText = archiveStart >= 0 ? plain.slice(archiveStart) : "";
  const archiveRow = archiveText.match(/(\d{2}-\d{2}-\d{4})\s+(\d{2})\s+(\d{2})/);
  const topText = archiveStart >= 0 ? plain.slice(0, archiveStart) : plain.slice(0, 9000);
  const frMatch = topText.match(/FR\s*[·•]?\s*4:15\s*pm\s*(\d{2})/i);
  const srMatch = topText.match(/SR\s*[·•]?\s*5:00\s*pm\s*(\d{2})/i);
  const frResult = frMatch?.[1] ?? "";
  const srResult = srMatch?.[1] ?? "";

  const jsonLdModified = html.match(/"dateModified"\s*:\s*"([^"]+)"/i)?.[1] ?? "";
  const metaModified = html.match(/<meta[^>]+(?:property|name)=["'](?:article:modified_time|last-modified)["'][^>]+content=["']([^"']+)["']/i)?.[1] ??
    html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["'](?:article:modified_time|last-modified)["']/i)?.[1] ?? "";
  const candidateTimestamp = [jsonLdModified, metaModified].find((value) => /T\d{2}:\d{2}/i.test(value)) ?? "";
  const parsedTimestamp = candidateTimestamp ? new Date(candidateTimestamp) : null;
  const sourceUpdatedAt = parsedTimestamp && Number.isFinite(parsedTimestamp.getTime()) &&
    parsedTimestamp.toISOString().slice(0, 10) === updatedIso
      ? parsedTimestamp.toISOString()
      : null;

  if (awaiting) {
    return {
      ready: false, status: "awaiting", market: KHANAPARA_MARKET,
      page_date: pageDate, source_update_date: updatedIso,
      previous_date: archiveRow?.[1] ?? "", previous_fr: archiveRow?.[2] ?? "", previous_sr: archiveRow?.[3] ?? "",
      source_updated_at: sourceUpdatedAt, source_url: KHANAPARA_SOURCE_URL,
    };
  }

  if (!/^\d{2}$/.test(frResult) || !/^\d{2}$/.test(srResult) ||
      !updatedIso || !archiveRow || archiveRow[1] !== dateIsoToDmy(updatedIso) ||
      archiveRow[2] !== frResult || archiveRow[3] !== srResult) {
    return {
      ready: false, status: "not_verified", market: KHANAPARA_MARKET,
      page_date: pageDate, source_update_date: updatedIso,
      source_updated_at: sourceUpdatedAt, source_url: KHANAPARA_SOURCE_URL,
    };
  }

  return {
    ready: true, status: "verified", market: KHANAPARA_MARKET,
    fr: frResult, sr: srResult, date: dateIsoToDmy(updatedIso),
    source_updated_at: sourceUpdatedAt, source_url: KHANAPARA_SOURCE_URL,
  };
}

async function syncKhanaparaSourceIfDue(force = false) {
  if (khanaparaCheckPromise) return await khanaparaCheckPromise;
  khanaparaCheckPromise = (async () => {
    try {
      const { data: syncState, error: stateError } = await supabase.from("result_source_sync")
        .select("last_checked_at").eq("market", KHANAPARA_MARKET).maybeSingle();
      if (stateError) throw stateError;
      const lastChecked = syncState?.last_checked_at ? new Date(syncState.last_checked_at).getTime() : 0;
      if (!force && lastChecked && Date.now() - lastChecked < 60 * 1000) return null;

      const checkedAt = new Date().toISOString();
      const { error: markError } = await supabase.from("result_source_sync")
        .upsert({ market: KHANAPARA_MARKET, last_checked_at: checkedAt }, { onConflict: "market" });
      if (markError) throw markError;
      khanaparaLastCheckAt = Date.now();

      const preview = await chooseFirstVerifiedPreview([fetchKhanaparaGroundsPreview, fetchKhanaparaSourcePreview]);
      if (preview.ready !== true) {
        // If the source says today's result is still pending/holiday, preserve
        // the last verified archive row. Only repair an empty placeholder row;
        // never overwrite a real result or an admin correction.
        if (preview.status === "awaiting" &&
            /^\d{2}-\d{2}-\d{4}$/.test(preview.previous_date ?? "") &&
            /^\d{2}$/.test(preview.previous_fr ?? "") &&
            /^\d{2}$/.test(preview.previous_sr ?? "")) {
          const { data: waitingCurrent, error: waitingError } = await supabase.from("teer_results")
            .select("market,fr,sr,result_date,updated_by")
            .eq("market", KHANAPARA_MARKET).maybeSingle();
          if (waitingError) throw waitingError;
          const isPlaceholder = !waitingCurrent ||
            (waitingCurrent.fr === "**" && waitingCurrent.sr === "**");
          if (isPlaceholder && !waitingCurrent?.updated_by) {
            const { error: restoreError } = await supabase.from("teer_results").upsert({
              market: KHANAPARA_MARKET,
              fr: preview.previous_fr,
              sr: preview.previous_sr,
              result_date: preview.previous_date.replaceAll("-", "/"),
              updated_at: new Date().toISOString(),
              updated_by: null,
              source_updated_at: null,
            }, { onConflict: "market" });
            if (restoreError) throw restoreError;
            const history = await saveVerifiedResultHistory(KHANAPARA_MARKET, preview.previous_date.replaceAll("-", "/"), preview.previous_fr, preview.previous_sr, "source");
            return { ...preview, applied: true, restored_previous: true, history };
          }
        }
        return preview;
      }

      const { data: current, error: currentError } = await supabase.from("teer_results")
        .select("market,fr,sr,result_date,updated_by")
        .eq("market", KHANAPARA_MARKET).maybeSingle();
      if (currentError) throw currentError;

      const currentDateIso = current?.result_date ? normalizeResultDateIso(String(current.result_date)) : "";
      const previewDateIso = normalizeResultDateIso(preview.date);
      if (current?.updated_by && currentDateIso === previewDateIso) {
        return { ...preview, applied: false, reason: "admin_correction_locked" };
      }
      if (currentDateIso && previewDateIso && currentDateIso > previewDateIso) {
        return { ...preview, applied: false, reason: "older_source_result_ignored" };
      }
      if (currentDateIso === previewDateIso &&
          /^\d{2}$/.test(String(current?.fr ?? "")) && /^\d{2}$/.test(String(current?.sr ?? ""))) {
        return { ...preview, applied: false, reason: "first_verified_result_locked_for_date" };
      }

      const { error: saveError } = await supabase.from("teer_results").upsert({
        market: KHANAPARA_MARKET,
        fr: preview.fr,
        sr: preview.sr,
        result_date: preview.date,
        updated_at: new Date().toISOString(),
        updated_by: null,
        source_updated_at: preview.source_updated_at,
      }, { onConflict: "market" });
      if (saveError) throw saveError;
      const history = await saveVerifiedResultHistory(KHANAPARA_MARKET, preview.date, preview.fr, preview.sr, new URL(preview.source_url).hostname, preview.source_updated_at);
      return { ...preview, applied: true, history };
    } catch (error) {
      console.error("Khanapara source sync failed:", error instanceof Error ? error.message : error);
      return { ready: false, status: "source_error" };
    } finally {
      khanaparaCheckPromise = null;
    }
  })();
  return await khanaparaCheckPromise;
}

// Shillong Teer source verification. The source page's current result is accepted
// only when its FR/SR pair matches the newest archive row and the page update date.
const SHILLONG_SOURCE_URL = "https://teer-result.com/shillong-teer-result/";
const SHILLONG_GROUNDS_SOURCE_URL = "https://shillongteergrounds.in/";
const SHILLONG_MARKET = "Shillong Teer (Evening)";
let shillongLastCheckAt = 0;
let shillongCheckPromise: Promise<unknown> | null = null;

type ShillongSourcePreview =
  | { ready: false; status: string; market: string; page_date?: string; source_update_date?: string; previous_date?: string; previous_fr?: string; previous_sr?: string; source_updated_at: string | null; source_url: string }
  | { ready: true; status: "verified"; market: string; fr: string; sr: string; date: string; source_updated_at: string | null; source_url: string };

async function fetchShillongSourcePreview(): Promise<ShillongSourcePreview> {
  const response = await fetch(SHILLONG_SOURCE_URL, {
    method: "GET",
    headers: {
      "User-Agent": "TeerOnlineResultSync/1.0 (+source verification)",
      "Accept": "text/html,application/xhtml+xml",
      "Cache-Control": "no-cache",
    },
  });
  if (!response.ok) throw new Error("Source website returned HTTP " + response.status);
  const html = await response.text();
  if (!html || html.length < 1000) throw new Error("Source page content was empty or incomplete");

  const plain = htmlToPlainText(html);
  const updatedMatch = plain.match(/Updated\s+(\d{4}-\d{2}-\d{2})/i);
  const pageDateMatch = plain.match(/Shillong Teer Result Today\s+(\d{2}-\d{2}-\d{4})/i);
  const updatedIso = updatedMatch?.[1] ?? "";
  const pageDate = pageDateMatch?.[1] ?? "";
  const awaiting = /Awaiting today's result/i.test(plain.slice(0, 6000));

  const archiveStart = plain.toLowerCase().indexOf("shillong teer previous result list");
  const archiveText = archiveStart >= 0 ? plain.slice(archiveStart) : "";
  const archiveRow = archiveText.match(/(\d{2}-\d{2}-\d{4})\s+(\d{2})\s+(\d{2})/);
  const topText = archiveStart >= 0 ? plain.slice(0, archiveStart) : plain.slice(0, 9000);
  const frMatch = topText.match(/FR\s*[·•]?\s*3:45\s*pm\s*(\d{2})/i);
  const srMatch = topText.match(/SR\s*[·•]?\s*4:45\s*pm\s*(\d{2})/i);
  const frResult = frMatch?.[1] ?? "";
  const srResult = srMatch?.[1] ?? "";

  const jsonLdModified = html.match(/"dateModified"\s*:\s*"([^"]+)"/i)?.[1] ?? "";
  const metaModified = html.match(/<meta[^>]+(?:property|name)=["'](?:article:modified_time|last-modified)["'][^>]+content=["']([^"']+)["']/i)?.[1] ??
    html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["'](?:article:modified_time|last-modified)["']/i)?.[1] ?? "";
  const candidateTimestamp = [jsonLdModified, metaModified].find((value) => /T\d{2}:\d{2}/i.test(value)) ?? "";
  const parsedTimestamp = candidateTimestamp ? new Date(candidateTimestamp) : null;
  const sourceUpdatedAt = parsedTimestamp && Number.isFinite(parsedTimestamp.getTime()) &&
    parsedTimestamp.toISOString().slice(0, 10) === updatedIso
      ? parsedTimestamp.toISOString()
      : null;

  if (awaiting) {
    return {
      ready: false, status: "awaiting", market: SHILLONG_MARKET,
      page_date: pageDate, source_update_date: updatedIso,
      previous_date: archiveRow?.[1] ?? "", previous_fr: archiveRow?.[2] ?? "", previous_sr: archiveRow?.[3] ?? "",
      source_updated_at: sourceUpdatedAt, source_url: SHILLONG_SOURCE_URL,
    };
  }

  if (!/^\d{2}$/.test(frResult) || !/^\d{2}$/.test(srResult) ||
      !updatedIso || !archiveRow || archiveRow[1] !== dateIsoToDmy(updatedIso) ||
      archiveRow[2] !== frResult || archiveRow[3] !== srResult) {
    return {
      ready: false, status: "not_verified", market: SHILLONG_MARKET,
      page_date: pageDate, source_update_date: updatedIso,
      source_updated_at: sourceUpdatedAt, source_url: SHILLONG_SOURCE_URL,
    };
  }

  return {
    ready: true, status: "verified", market: SHILLONG_MARKET,
    fr: frResult, sr: srResult, date: dateIsoToDmy(updatedIso),
    source_updated_at: sourceUpdatedAt, source_url: SHILLONG_SOURCE_URL,
  };
}

async function syncShillongSourceIfDue(force = false) {
  if (shillongCheckPromise) return await shillongCheckPromise;
  shillongCheckPromise = (async () => {
    try {
      const { data: syncState, error: stateError } = await supabase.from("result_source_sync")
        .select("last_checked_at").eq("market", SHILLONG_MARKET).maybeSingle();
      if (stateError) throw stateError;
      const lastChecked = syncState?.last_checked_at ? new Date(syncState.last_checked_at).getTime() : 0;
      if (!force && lastChecked && Date.now() - lastChecked < 60 * 1000) return null;

      const checkedAt = new Date().toISOString();
      const { error: markError } = await supabase.from("result_source_sync")
        .upsert({ market: SHILLONG_MARKET, last_checked_at: checkedAt }, { onConflict: "market" });
      if (markError) throw markError;
      shillongLastCheckAt = Date.now();

      const preview = await chooseFirstVerifiedPreview([fetchShillongGroundsPreview, fetchShillongSourcePreview]);
      if (preview.ready !== true) {
        // If the source says today's result is still pending/holiday, preserve
        // the last verified archive row. Only repair an empty placeholder row;
        // never overwrite a real result or an admin correction.
        if (preview.status === "awaiting" &&
            /^\d{2}-\d{2}-\d{4}$/.test(preview.previous_date ?? "") &&
            /^\d{2}$/.test(preview.previous_fr ?? "") &&
            /^\d{2}$/.test(preview.previous_sr ?? "")) {
          const { data: waitingCurrent, error: waitingError } = await supabase.from("teer_results")
            .select("market,fr,sr,result_date,updated_by")
            .eq("market", SHILLONG_MARKET).maybeSingle();
          if (waitingError) throw waitingError;
          const isPlaceholder = !waitingCurrent ||
            (waitingCurrent.fr === "**" && waitingCurrent.sr === "**");
          if (isPlaceholder && !waitingCurrent?.updated_by) {
            const { error: restoreError } = await supabase.from("teer_results").upsert({
              market: SHILLONG_MARKET,
              fr: preview.previous_fr,
              sr: preview.previous_sr,
              result_date: preview.previous_date.replaceAll("-", "/"),
              updated_at: new Date().toISOString(),
              updated_by: null,
              source_updated_at: null,
            }, { onConflict: "market" });
            if (restoreError) throw restoreError;
            const history = await saveVerifiedResultHistory(SHILLONG_MARKET, preview.previous_date.replaceAll("-", "/"), preview.previous_fr, preview.previous_sr, "source");
            return { ...preview, applied: true, restored_previous: true, history };
          }
        }
        return preview;
      }

      const { data: current, error: currentError } = await supabase.from("teer_results")
        .select("market,fr,sr,result_date,updated_by")
        .eq("market", SHILLONG_MARKET).maybeSingle();
      if (currentError) throw currentError;

      if (current?.updated_by && current.result_date === preview.date) {
        return { ...preview, applied: false, reason: "admin_correction_locked" };
      }
      const currentDateIso = current?.result_date ? dateDmyToIso(String(current.result_date).replaceAll("-", "/")) : "";
      const previewDateIso = dateDmyToIso(preview.date);
      if (currentDateIso && previewDateIso && currentDateIso > previewDateIso) {
        return { ...preview, applied: false, reason: "older_source_result_ignored" };
      }
      if (currentDateIso === previewDateIso &&
          /^\d{2}$/.test(String(current?.fr ?? "")) && /^\d{2}$/.test(String(current?.sr ?? ""))) {
        return { ...preview, applied: false, reason: "first_verified_result_locked_for_date" };
      }

      const { error: saveError } = await supabase.from("teer_results").upsert({
        market: SHILLONG_MARKET,
        fr: preview.fr,
        sr: preview.sr,
        result_date: preview.date,
        updated_at: new Date().toISOString(),
        updated_by: null,
        source_updated_at: preview.source_updated_at,
      }, { onConflict: "market" });
      if (saveError) throw saveError;
      const history = await saveVerifiedResultHistory(SHILLONG_MARKET, preview.date, preview.fr, preview.sr, new URL(preview.source_url).hostname, preview.source_updated_at);
      return { ...preview, applied: true, history };
    } catch (error) {
      console.error("Shillong source sync failed:", error instanceof Error ? error.message : error);
      return { ready: false, status: "source_error" };
    } finally {
      shillongCheckPromise = null;
    }
  })();
  return await shillongCheckPromise;
}
Deno.serve(async (req) => {
  const origin = req.headers.get("Origin");
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(origin) });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405, origin);
  if (!SUPABASE_URL || !SERVICE_ROLE_KEY) return json({ error: "Server configuration missing" }, 500, origin);
  if (!APP_ORIGINS.includes("*") && origin && !APP_ORIGINS.includes(origin)) {
    return json({ error: "Origin not allowed" }, 403, origin);
  }

  try {
    const body = await req.json();
    const action = String(body?.action ?? "");

    // Server-side one-minute poller. The request is rate-limited by the
    // persistent result_source_sync row, so repeated public calls cannot
    // cause repeated source fetches inside the five-minute window.
    if (action === "scheduled_result_sync") {
      const sync = await syncKhanaparaSourceIfDue(false);
      const shillongSync = await syncShillongSourceIfDue(false);
      return json({ success: true, sync, shillongSync }, 200, origin);
    }

    if (action === "register") {
      const name = String(body.name ?? "").trim().slice(0, 80);
      const phone = cleanPhone(body.phone);
      const password = body.password;
      const referredBy = body.referred_by ? String(body.referred_by).trim().slice(0, 40) : null;
      if (!name || phone.length !== 10 || !validPassword(password)) {
        return json({ error: "Name, valid 10-digit phone and password (8-128 characters) are required" }, 400, origin);
      }
      const hash = await passwordHash(password);
      const created = await rpc<unknown>("api_register_user", {
        p_name: name,
        p_phone: phone,
        p_password_hash: hash,
        p_referred_by: referredBy,
      });
      const user = asOne(created as Record<string, unknown> | Record<string, unknown>[] | null);
      if (!user || !user.user_id) throw new Error("Registration did not return a user id");
      const session = await makeSession(String(user.user_id));
      return json({ user: { id: user.user_id, uid: user.uid, name, phone, vip_level: 0 }, registration_bonus: Number(user.registration_bonus ?? 0), session }, 200, origin);
    }

    if (action === "login" || action === "admin_login") {
      const phone = cleanPhone(body.phone);
      const password = body.password;
      // Accept 4+ character legacy passwords for login compatibility. New registrations
      // still require 8+ characters in the register action.
      if (phone.length !== 10 || typeof password !== "string" || password.length < 4 || password.length > 128) {
        return json({ error: "Invalid phone or password" }, 400, origin);
      }
      const found = await rpc<unknown>("api_auth_lookup", { p_phone: phone });
      const user = asOne(found as Record<string, unknown> | Record<string, unknown>[] | null);
      if (!user || typeof user.password_hash !== "string") {
        return json({ error: "Invalid phone or password" }, 401, origin);
      }
      const passwordCheck = await verifyPassword(password, user.password_hash);
      if (!passwordCheck.valid) return json({ error: "Invalid phone or password" }, 401, origin);
      if (passwordCheck.legacyBcrypt) {
        const userIdForUpgrade = user.id ?? user.user_id;
        if (userIdForUpgrade) {
          const upgradedHash = await passwordHash(password);
          const { error: upgradeError } = await supabase.from("app_users")
            .update({ password_hash: upgradedHash }).eq("id", userIdForUpgrade);
          if (upgradeError) console.error("Legacy password hash upgrade failed:", upgradeError.message);
        }
      }
      let isAdmin = false;
      if (action === "admin_login") {
        const { data, error } = await supabase.from("admin_allowlist")
          .select("phone,is_active")
          .eq("phone", phone)
          .eq("is_active", true)
          .maybeSingle();
        if (error) throw new Error("Admin authorization check failed");
        if (!data) return json({ error: "Admin access denied" }, 403, origin);
        isAdmin = true;
      }
      const userId = user.id ?? user.user_id;
      if (!userId) throw new Error("Login lookup did not return a user id");
      const session = await makeSession(String(userId));
      return json({
        user: { id: userId, uid: user.uid, name: user.name, phone: user.phone, vip_level: Number(user.vip_level ?? 0) },
        is_admin: isAdmin,
        session,
      }, 200, origin);
    }

    if (action === "me" || action === "balance" || action === "logout") {
      const user = await getSession(req);
      if (!user || !user.id) return json({ error: "Session expired. Please login again." }, 401, origin);
      if (action === "me") return json({ user }, 200, origin);
      if (action === "balance") {
        const balance = await rpc<unknown>("api_get_wallet_balance", { p_user_id: user.id });
        return json({ balance }, 200, origin);
      }
      const token = (req.headers.get("x-session-token") ?? "").trim();
      await rpc("api_revoke_session", { p_token_hash: await sha256Hex(token) });
      return json({ success: true }, 200, origin);
    }

    if (action === "place_bets") {
      const user = await getSession(req);
      if (!user || !user.id) return json({ error: "Please login again" }, 401, origin);
      const clientRefPrefix = String(body.client_ref_prefix ?? "").trim();
      const market = String(body.market ?? "").trim();
      const rawSelections = Array.isArray(body.selections) ? body.selections : [];
      if (!clientRefPrefix || clientRefPrefix.length > 90 || !market || market.length > 80 ||
          rawSelections.length < 1 || rawSelections.length > 100) {
        return json({ error: "Invalid batch bet details" }, 400, origin);
      }
      const selections = rawSelections.map((item: Record<string, unknown>) => ({
        round: String(item?.round ?? "").trim().toUpperCase(),
        round_id: item?.round_id == null ? null : Number(item.round_id),
        bet_mode: String(item?.bet_mode ?? "").trim().toUpperCase(),
        bet_number: String(item?.bet_number ?? "").trim(),
        amount: Number(item?.amount),
      }));
      let result: unknown;
      try {
        result = await rpc("api_place_bets_batch", {
          p_user_id: user.id,
          p_client_ref_prefix: clientRefPrefix,
          p_market: market,
          p_selections: selections,
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : "Bet batch could not be completed";
        console.error("Batch bet failed:", message);
        return json({ error: message.slice(0, 220) }, 400, origin);
      }
      return json({ success: true, result }, 200, origin);
    }

    if (action === "place_bet") {
      const user = await getSession(req);
      if (!user || !user.id) return json({ error: "Please login again" }, 401, origin);
      const clientRef = String(body.client_ref ?? "").trim();
      const market = String(body.market ?? "").trim();
      const round = String(body.round ?? "").trim().toUpperCase();
      const betMode = String(body.bet_mode ?? "").trim();
      const betNumber = String(body.bet_number ?? "").trim();
      const amount = Number(body.amount);
      const roundId = body.round_id == null ? null : Number(body.round_id);
      if (!clientRef || clientRef.length > 100 || !market || market.length > 80 ||
          !round || round.length > 40 || !betMode || betMode.length > 30 ||
          !/^\d{1,2}$/.test(betNumber) || !Number.isFinite(amount) || amount <= 0 || amount > 100000) {
        return json({ error: "Invalid bet details" }, 400, origin);
      }
      if (market === "Teer Play") {
        if (!Number.isSafeInteger(roundId) || roundId < 1 || !["FR", "SR"].includes(round)) {
          return json({ error: "Select a valid open Teer Play FR/SR round ID" }, 400, origin);
        }
        const result = await rpc("api_place_bet", {
          p_user_id: user.id,
          p_client_ref: clientRef,
          p_market: market,
          p_round: round,
          p_bet_mode: betMode,
          p_bet_number: betNumber,
          p_amount: amount,
          p_round_id: roundId,
        });
        return json({ success: true, result }, 200, origin);
      }
      const result = await rpc("api_place_bet", {
        p_user_id: user.id,
        p_client_ref: clientRef,
        p_market: market,
        p_round: round,
        p_bet_mode: betMode,
        p_bet_number: betNumber,
        p_amount: amount,
      });
      return json({ success: true, result }, 200, origin);
    }

    if (action === "my_bets" || action === "my_transactions" ||
        action === "my_deposit_requests" || action === "my_withdrawal_requests") {
      const user = await getSession(req);
      if (!user || !user.id) return json({ error: "Please login again" }, 401, origin);
      const limit = Math.min(100, Math.max(1, Number.isInteger(Number(body.limit)) ? Number(body.limit) : 50));
      const table = action === "my_bets" ? "bets" :
        action === "my_transactions" ? "wallet_transactions" :
        action === "my_deposit_requests" ? "deposit_requests" : "withdrawal_requests";
      const columns = action === "my_bets"
        ? "id,client_ref,market,round,round_id,bet_mode,bet_number,amount,status,payout,created_at,settled_at"
        : action === "my_transactions"
        ? "id,type,amount,status,description,created_at,ref_id"
        : action === "my_deposit_requests"
        ? "id,amount,utr,status,credited_amount,created_at,reviewed_at"
        : "id,amount,status,created_at,reviewed_at";
      const { data, error } = await supabase.from(table).select(columns)
        .eq("user_id", user.id).order("created_at", { ascending: false }).limit(limit);
      if (error) throw error;
      return json({ success: true, items: data ?? [] }, 200, origin);
    }

    if (action === "admin_settle_bet" || action === "admin_list_bets") {
      const user = await getSession(req);
      if (!user || !user.id) return json({ error: "Please login again" }, 401, origin);
      if (!(await requireAdmin(user))) return json({ error: "Admin access denied" }, 403, origin);
      if (action === "admin_settle_bet") {
        const betId = String(body.bet_id ?? "");
        const resultNumber = String(body.result_number ?? "").trim();
        if (!/^[0-9a-f-]{36}$/i.test(betId) || !/^\d{1,2}$/.test(resultNumber)) {
          return json({ error: "Valid bet_id and 1-2 digit result_number required" }, 400, origin);
        }
        const result = await rpc("api_settle_bet", {
          p_bet_id: betId,
          p_result_number: resultNumber,
        });
        return json({ success: true, result }, 200, origin);
      }
      const limit = Math.min(200, Math.max(1, Number.isInteger(Number(body.limit)) ? Number(body.limit) : 100));
      const { data, error } = await supabase.from("bets")
        .select("id,user_id,client_ref,market,round,round_id,bet_mode,bet_number,amount,status,payout,created_at,settled_at")
        .order("created_at", { ascending: false }).limit(limit);
      if (error) throw error;
      return json({ success: true, items: data ?? [] }, 200, origin);
    }

    if (action === "rounds") {
      const limit = Math.min(300, Math.max(1, Number.isInteger(Number(body.limit)) ? Number(body.limit) : 100));
      const { data, error } = await supabase.from("teer_minute_rounds")
        .select("id,result_type,starts_at,ends_at,result_number,result_source,status,published_at")
        .order("starts_at", { ascending: false }).limit(limit);
      if (error) throw error;
      return json({ success: true, items: data ?? [] }, 200, origin);
    }

    if (action === "admin_list_rounds" || action === "admin_set_round_result") {
      const admin = await getSession(req);
      if (!admin || !admin.id) return json({ error: "Please login again" }, 401, origin);
      if (!(await requireAdmin(admin))) return json({ error: "Admin access denied" }, 403, origin);
      if (action === "admin_list_rounds") {
        const limit = Math.min(300, Math.max(1, Number.isInteger(Number(body.limit)) ? Number(body.limit) : 100));
        const { data, error } = await supabase.from("teer_minute_rounds")
          .select("id,result_type,starts_at,ends_at,result_number,result_source,status,published_at")
          .order("starts_at", { ascending: false }).limit(limit);
        if (error) throw error;
        return json({ success: true, items: data ?? [] }, 200, origin);
      }
      const roundId = Number(body.round_id);
      const resultNumber = Number(body.result_number);
      if (!Number.isSafeInteger(roundId) || roundId < 1 || !Number.isInteger(resultNumber) || resultNumber < 0 || resultNumber > 99) {
        return json({ error: "Valid round_id and result_number (00-99) required" }, 400, origin);
      }
      const token = (req.headers.get("x-session-token") ?? "").trim();
      const result = await rpc("api_admin_set_teer_round_result", {
        p_admin_token_hash: await sha256Hex(token),
        p_round_id: roundId,
        p_result_number: resultNumber,
      });
      return json({ success: true, result }, 200, origin);
    }

    if (action === "public_result_history") {
      const market = String(body.market ?? "").trim();
      if (![KHANAPARA_MARKET, SHILLONG_MARKET].includes(market)) {
        return json({ error: "Unknown result market" }, 400, origin);
      }
      const page = Math.max(0, Math.min(9, Number.isInteger(Number(body.page)) ? Number(body.page) : 0));
      const pageSize = 100;
      const { data, error } = await supabase.from("teer_result_history")
        .select("id,market,result_date,fr,sr,source,created_at,source_updated_at")
        .eq("market", market).not("fr", "is", null).not("sr", "is", null).neq("fr", "**").neq("sr", "**")
        .order("result_date", { ascending: false })
        .range(page * pageSize, page * pageSize + pageSize);
      if (error) throw error;
      const items = data ?? [];
      const hasMore = items.length > pageSize;
      return json({ success: true, history: items.slice(0, pageSize), has_more: hasMore, page }, 200, origin);
    }

    if (action === "public_app_data") {
      await Promise.all([syncKhanaparaSourceIfDue(false), syncShillongSourceIfDue(false)]);

      const [{ data: results, error: resultsError }, { data: settings, error: settingsError }, { data: rounds, error: roundsError }] = await Promise.all([
        supabase.from("teer_results").select("market,fr,sr,result_date,updated_at,source_updated_at"),
        supabase.from("app_settings").select("helpline,deposit_upi,deposit_qr_image,marquee_text,market_schedules").eq("id", 1).maybeSingle(),
        supabase.from("teer_minute_rounds").select("id,result_type,starts_at,ends_at,result_number,result_source,status,published_at").order("starts_at", { ascending: false }).limit(100),
      ]);
      if (resultsError) throw resultsError;
      if (settingsError) throw settingsError;
      if (roundsError) throw roundsError;
      const resultMap: Record<string, unknown> = {};
      for (const row of results ?? []) resultMap[row.market] = { fr: row.fr ?? "**", sr: row.sr ?? "**", date: row.result_date ?? "", updated_at: row.updated_at ?? null, source_updated_at: row.source_updated_at ?? null };
      return json({ success: true, results: resultMap, settings: settings ?? {}, rounds: rounds ?? [] }, 200, origin);
    }

    if (["admin_dashboard", "admin_save_result", "admin_reset_result", "admin_save_settings", "admin_fetch_source_result"].includes(action)) {
      const admin = await getSession(req);
      if (!admin || !admin.id) return json({ error: "Please login again" }, 401, origin);
      if (!(await requireAdmin(admin))) return json({ error: "Admin access denied" }, 403, origin);

      if (action === "admin_fetch_source_result") {
        const preview = await chooseFirstVerifiedPreview([fetchKhanaparaGroundsPreview, fetchKhanaparaSourcePreview]);
        if (!preview.ready) {
          return json({ error: preview.status === "awaiting"
            ? "Website has not published today's complete FR and SR yet. Existing result will be kept."
            : "Website result did not pass date and archive verification. Existing result will be kept.",
            preview }, 409, origin);
        }
        return json({ success: true, preview }, 200, origin);
      }

      if (action === "admin_dashboard") {
        const [usersQ, walletsQ, depositsQ, withdrawalsQ, betsQ, resultsQ, settingsQ] = await Promise.all([
          supabase.from("app_users").select("id,uid,name,phone,referred_by,created_at,vip_level").order("created_at", { ascending: false }).limit(500),
          supabase.from("wallet_accounts").select("user_id,balance"),
          supabase.from("deposit_requests").select("id,user_id,amount,utr,screenshot_url,status,credited_amount,created_at,reviewed_at").order("created_at", { ascending: false }).limit(300),
          supabase.from("withdrawal_requests").select("id,user_id,amount,payout_details,status,created_at,reviewed_at").order("created_at", { ascending: false }).limit(300),
          supabase.from("bets").select("id,user_id,market,round,round_id,bet_mode,bet_number,amount,status,payout,created_at").order("created_at", { ascending: false }).limit(500),
          supabase.from("teer_results").select("market,fr,sr,result_date,updated_at,source_updated_at"),
          supabase.from("app_settings").select("helpline,deposit_upi,deposit_qr_image,marquee_text,market_schedules").eq("id", 1).maybeSingle(),
        ]);
        for (const q of [usersQ, walletsQ, depositsQ, withdrawalsQ, betsQ, resultsQ, settingsQ]) if (q.error) throw q.error;
        const balances = Object.fromEntries((walletsQ.data ?? []).map((w: any) => [w.user_id, Number(w.balance ?? 0)]));
        const users = (usersQ.data ?? []).map((u: any) => ({ ...u, balance: balances[u.id] ?? 0 }));
        const byId = Object.fromEntries(users.map((u: any) => [u.id, u]));
        const deposits = (depositsQ.data ?? []).map((d: any) => ({ ...(byId[d.user_id] ?? {}), ...d, name: byId[d.user_id]?.name ?? "User", phone: byId[d.user_id]?.phone ?? "", screenshot: d.screenshot_url ?? "" }));
        const withdrawals = (withdrawalsQ.data ?? []).map((w: any) => ({ ...(byId[w.user_id] ?? {}), ...w, name: byId[w.user_id]?.name ?? "User", phone: byId[w.user_id]?.phone ?? "", payoutType: w.payout_details?.method === "bank" ? "bank" : "upi", bankDetails: w.payout_details?.method === "bank" ? { holderName: w.payout_details.holder_name, accountNumber: w.payout_details.account_number, ifsc: w.payout_details.ifsc, bankName: w.payout_details.bank_name } : null, upi: w.payout_details?.upi ?? "" }));
        const resultMap: Record<string, unknown> = {};
        for (const row of resultsQ.data ?? []) resultMap[row.market] = { fr: row.fr ?? "**", sr: row.sr ?? "**", date: row.result_date ?? "", updated_at: row.updated_at ?? null, source_updated_at: row.source_updated_at ?? null };
        return json({ success: true, users, deposits, withdrawals, bets: betsQ.data ?? [], results: resultMap, settings: settingsQ.data ?? {} }, 200, origin);
      }

      if (action === "admin_save_result" || action === "admin_reset_result") {
        const market = String(body.market ?? "").trim().slice(0, 100);
        if (!market) return json({ error: "Market is required" }, 400, origin);
        const fr = action === "admin_reset_result" ? "**" : String(body.fr ?? "**").trim();
        const sr = action === "admin_reset_result" ? "**" : String(body.sr ?? "**").trim();
        if (!/^\*\*$|^\d{1,2}$/.test(fr) || !/^\*\*$|^\d{1,2}$/.test(sr)) return json({ error: "FR/SR must be ** or 1-2 digits" }, 400, origin);
        const indiaDateParts = new Intl.DateTimeFormat("en-GB", { timeZone: "Asia/Kolkata", day: "2-digit", month: "2-digit", year: "numeric" }).formatToParts(new Date());
        const indiaPart = (type: string) => indiaDateParts.find((part) => part.type === type)?.value ?? "";
        const indiaToday = `${indiaPart("day")}/${indiaPart("month")}/${indiaPart("year")}`;
        const resultDate = action === "admin_reset_result" ? null : String(body.result_date ?? indiaToday).trim();
        if (action === "admin_save_result" && !/^\d{2}\/\d{2}\/\d{4}$/.test(resultDate || "")) {
          return json({ error: "Result date must be DD/MM/YYYY" }, 400, origin);
        }
        const { error } = await supabase.from("teer_results").upsert({ market, fr, sr, result_date: resultDate, updated_at: new Date().toISOString(), updated_by: admin.id, source_updated_at: null }, { onConflict: "market" });
        if (error) throw error;
        if (action === "admin_save_result" && [KHANAPARA_MARKET, SHILLONG_MARKET].includes(market) &&
            /^\d{2}$/.test(fr) && /^\d{2}$/.test(sr)) {
          await saveVerifiedResultHistory(market, resultDate!, fr, sr, "admin");
        }
        const settlements: unknown[] = [];
        if (action === "admin_save_result") {
          for (const [round, resultNumber] of [["FR", fr], ["SR", sr]] as const) {
            if (!/^\d{1,2}$/.test(resultNumber)) continue;
            const { data: activeBets, error: betsError } = await supabase.from("bets").select("id")
              .eq("market", market).eq("round", round).eq("status", "active").limit(1000);
            if (betsError) throw betsError;
            for (const bet of activeBets ?? []) {
              settlements.push(await rpc("api_settle_bet", { p_bet_id: bet.id, p_result_number: resultNumber }));
            }
          }
        }
        return json({ success: true, market, fr, sr, result_date: resultDate, settled_count: settlements.length }, 200, origin);
      }

      const helpline = String(body.helpline ?? "").trim().slice(0, 40);
      const depositUpi = String(body.deposit_upi ?? "").trim().slice(0, 120);
      const depositQrImage = String(body.deposit_qr_image ?? "").trim();
      if (depositQrImage && (!/^data:image\/(png|jpeg|webp);base64,/.test(depositQrImage) || depositQrImage.length > 500000)) {
        return json({ error: "QR image must be PNG/JPG/WEBP and smaller than 350 KB" }, 400, origin);
      }
      const marqueeText = String(body.marquee_text ?? "").trim().slice(0, 1000);
      const marketSchedules = body.market_schedules && typeof body.market_schedules === "object" ? body.market_schedules : {};
      const { error } = await supabase.from("app_settings").upsert({ id: 1, helpline, deposit_upi: depositUpi, deposit_qr_image: depositQrImage || null, marquee_text: marqueeText, market_schedules: marketSchedules, updated_at: new Date().toISOString(), updated_by: admin.id }, { onConflict: "id" });
      if (error) throw error;
      return json({ success: true }, 200, origin);
    }

    if (action === "create_withdrawal") {
      const user = await getSession(req);
      if (!user || !user.id) return json({ error: "Please login again" }, 401, origin);
      const amount = Number(body.amount);
      const payoutDetails = body.payout_details;
      if (!Number.isFinite(amount) || amount < 1000 || amount > 5000 ||
          !payoutDetails || typeof payoutDetails !== "object" || Array.isArray(payoutDetails)) {
        return json({ error: "Withdrawal must be ₹1,000–₹5,000 and payout details are required" }, 400, origin);
      }
      const request = await rpc("api_create_withdrawal", {
        p_user_id: user.id,
        p_amount: amount,
        p_payout_details: payoutDetails,
      });
      return json({ success: true, request }, 200, origin);
    }

    if (action === "admin_review_deposit" || action === "admin_review_withdrawal" || action === "admin_set_vip") {
      const user = await getSession(req);
      if (!user || !user.id) return json({ error: "Please login again" }, 401, origin);
      if (!(await requireAdmin(user))) return json({ error: "Admin access denied" }, 403, origin);
      const adminPhone = cleanPhone(user.phone);

      if (action === "admin_review_deposit") {
        const depositId = String(body.deposit_id ?? "");
        const reviewAction = String(body.review_action ?? "").toLowerCase();
        if (!/^[0-9a-f-]{36}$/i.test(depositId) || !["approve", "reject"].includes(reviewAction)) {
          return json({ error: "Valid deposit_id and approve/reject action required" }, 400, origin);
        }
        const result = await rpc("api_review_deposit", {
          p_deposit_id: depositId,
          p_admin_phone: adminPhone,
          p_action: reviewAction,
        });
        return json({ success: true, result }, 200, origin);
      }

      if (action === "admin_review_withdrawal") {
        const withdrawalId = String(body.withdrawal_id ?? "");
        const reviewAction = String(body.review_action ?? "").toLowerCase();
        if (!/^[0-9a-f-]{36}$/i.test(withdrawalId) || !["approve", "reject"].includes(reviewAction)) {
          return json({ error: "Valid withdrawal_id and approve/reject action required" }, 400, origin);
        }
        const result = await rpc("api_review_withdrawal", {
          p_withdrawal_id: withdrawalId,
          p_admin_phone: adminPhone,
          p_action: reviewAction,
        });
        return json({ success: true, result }, 200, origin);
      }

      const targetUserId = String(body.user_id ?? "");
      const vipLevel = Number(body.vip_level);
      if (!/^[0-9a-f-]{36}$/i.test(targetUserId) || !Number.isInteger(vipLevel) || vipLevel < 0 || vipLevel > 2) {
        return json({ error: "Valid user_id and VIP level 0, 1 or 2 required" }, 400, origin);
      }
      const result = await rpc("api_admin_set_vip", {
        p_user_id: targetUserId,
        p_admin_phone: adminPhone,
        p_vip_level: vipLevel,
      });
      return json({ success: true, result }, 200, origin);
    }

    if (action === "deposit_request") {
      const user = await getSession(req);
      if (!user || !user.id) return json({ error: "Please login again" }, 401, origin);
      const amount = Number(body.amount);
      const paymentMethod = String(body.payment_method ?? "upi_pay");
      const utr = String(body.utr ?? "").trim();
      const screenshotUrl = body.screenshot_url ? String(body.screenshot_url) : null;
      const maxAmount = paymentMethod === "upi_pay" ? 10000 : paymentMethod === "qr_pay" ? 5000 : 0;
      if (!Number.isInteger(amount) || amount < 100 || amount > maxAmount || !/^.{6,80}$/.test(utr)) {
        return json({ error: "Invalid deposit amount, payment method or UTR" }, 400, origin);
      }
      const result = await rpc("api_create_deposit_request", {
        p_user_id: user.id,
        p_amount: amount,
        p_utr: utr,
        p_screenshot_url: screenshotUrl,
      });
      return json({ success: true, request: result }, 200, origin);
    }

    return json({ error: "Unknown action" }, 400, origin);
  } catch (error) {
    // Avoid returning SQL, hashes, credentials or internal stack details to clients.
    console.error("account-api error:", error);
    return json({ error: "Request could not be completed" }, 400, origin);
  }
});
