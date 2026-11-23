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


// OneSignal result notification outbox. The REST API key is supplied later as
// the Supabase secret ONESIGNAL_REST_API_KEY; without it, messages stay pending.
const ONESIGNAL_APP_ID = "5c602eb8-04b1-4007-8edf-936fd353fcc1";

async function queueMarketOffPushNotifications() {
  const now = new Date();
  const localParts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Kolkata", year: "numeric", month: "2-digit", day: "2-digit", weekday: "short",
  }).formatToParts(now);
  const part = (type: string) => localParts.find(p => p.type === type)?.value ?? "";
  const dateIso = part("year") + "-" + part("month") + "-" + part("day");
  const date = part("day") + "/" + part("month") + "/" + part("year");
  const dateDash = part("day") + "-" + part("month") + "-" + part("year");
  const sunday = part("weekday") === "Sun";
  const sundayOffMarkets = sunday
    ? ["Shillong Teer (Evening)", "Khanapara Teer (Evening)"]
    : [];
  let queued = 0;
  let confirmedOff = 0;

  const enqueueOff = async (market: string, reason: string) => {
    const eventKey = "market_off:" + market + ":" + dateIso;
    const { error } = await supabase.from("broadcast_notifications").insert({
      title: (market + " — OFF Today").slice(0, 80),
      message: date + " | " + reason + " " + market + " is closed today.",
      status: "pending", recipients: 0, event_key: eventKey, created_by: null,
    });
    if (error?.code === "23505") return false;
    if (error) throw error;
    queued++;
    return true;
  };
  const enqueueRoundOff = async (market: string, round: "FR" | "SR", reason: string) => {
    const eventKey = "market_round_off:" + market + ":" + dateIso + ":" + round;
    const { error } = await supabase.from("broadcast_notifications").insert({
      title: (market + " " + round + " — OFF Today").slice(0, 80),
      message: date + " | " + market + " " + round + " is OFF. " + reason,
      status: "pending", recipients: 0, event_key: eventKey, created_by: null,
    });
    if (error?.code === "23505") return false;
    if (error) throw error;
    queued++;
    return true;
  };

  for (const market of sundayOffMarkets) {
    await enqueueOff(market, "Official Sunday holiday.");
    confirmedOff++;
  }

  // Accept a non-Sunday OFF only when the exact market page explicitly says
  // OFF/holiday for today's date. Awaiting, stale dates and fetch errors are not OFF.
  const sourceChecks = [
    { market: "Shillong Morning Teer", heading: "Shillong Morning Teer Result Today", url: "https://teer-result.com/shillong-morning-teer-result/", frTime: "10:30 AM", srTime: "11:30 AM" },
    { market: "Khanapara Morning Teer", heading: "Khanapara Morning Teer Result Today", url: "https://teer-result.com/khanapara-morning-teer-result/", frTime: "10:30 AM", srTime: "11:30 AM" },
    { market: "Shillong Teer (Evening)", heading: "Shillong Teer Result Today", url: "https://teer-result.com/shillong-teer-result/", frTime: "03:15 PM", srTime: "04:15 PM" },
    { market: "Khanapara Teer (Evening)", heading: "Khanapara Teer Result Today", url: "https://teer-result.com/khanapara-teer-result/", frTime: "04:10 PM", srTime: "04:45 PM" },
    { market: "Shillong Night Teer", heading: "Shillong Night Teer Result Today", url: "https://teer-result.com/shillong-night-teer-result/", frTime: "08:30 PM", srTime: "09:30 PM" },
    { market: "Khanapara Night Teer", heading: "Khanapara Night Teer Result Today", url: "https://shillongnighteer.com/khanapara-teer-result-today/", frTime: "10:30 PM", srTime: "11:30 PM", verifyTimes: true },
  ];
  let sourceErrors = 0;
  for (const source of sourceChecks) {
    try {
      const checkKey = "off-status:" + source.market;
      const { data: state, error: stateError } = await supabase.from("result_source_sync")
        .select("last_checked_at").eq("market", checkKey).maybeSingle();
      if (stateError) throw stateError;
      const lastChecked = state?.last_checked_at ? new Date(state.last_checked_at).getTime() : 0;
      if (lastChecked && Date.now() - lastChecked < 10 * 60 * 1000) continue;
      // Do not mark a source checked until fetch + parsing succeeds.
      // Otherwise a timeout/blocked request suppresses retries for 10 minutes.
      const response = await fetch(source.url, {
        headers: {
          "User-Agent": "TeerOnlineResultSync/1.0 (+market status verification)",
          "Accept": "text/html,application/xhtml+xml",
          "Cache-Control": "no-cache",
        },
      });
      if (!response.ok) throw new Error("HTTP " + response.status);
      const html = await response.text();
      if (!html || html.length < 500) throw new Error("empty market status page");
      const plain = htmlToPlainText(html);
      const headingIndex = plain.toLowerCase().indexOf(source.heading.toLowerCase());
      // Search a wider section after the exact market heading; source sites often
      // place date, FR and SR labels in separate cards within the same market block.
      const section = headingIndex >= 0 ? plain.slice(headingIndex, headingIndex + 4200) : "";
      const normalizedSection = section.replace(/\s+/g, " ").toLowerCase();
      const hasMarketHeading = headingIndex >= 0;
      const hasSessionTimes = !source.verifyTimes || (normalizedSection.includes(source.frTime.toLowerCase()) &&
        normalizedSection.includes(source.srTime.toLowerCase()));
      const monthLong = new Intl.DateTimeFormat("en-GB", { timeZone: "Asia/Kolkata", month: "long" }).format(now);
      const monthShort = new Intl.DateTimeFormat("en-GB", { timeZone: "Asia/Kolkata", month: "short" }).format(now);
      const dateLong = part("day") + " " + monthLong + " " + part("year");
      const dateShort = part("day") + " " + monthShort + " " + part("year");
      const datePattern = [dateIso, dateDash, date, dateLong, dateShort];
      const lowerSection = section.toLowerCase();
      const hasCurrentDate = datePattern.some(value => lowerSection.includes(value.toLowerCase()));
      const explicitOff = /\b(?:off\s+today|today\s+(?:is\s+)?(?:off|a\s+holiday)|holiday\s+today|no\s+game\s+today|market\s+(?:is\s+)?closed\s+today|game\s+is\s+off\s+today|no\s+teer\s+today)\b/i.test(section);
      const roundOff = (round: "FR" | "SR") => {
        const labels = round === "FR" ? "(?:FR|F\\s*\\/\\s*R|First\\s+Round)" : "(?:SR|S\\s*\\/\\s*R|Second\\s+Round)";
        const patterns = [
          new RegExp("\\b" + labels + "\\b[^.!?]{0,100}\\bOFF\\b", "i"),
          new RegExp("\\bOFF\\b[^.!?]{0,100}\\b" + labels + "\\b", "i"),
        ];
        return patterns.some(pattern => pattern.test(normalizedSection));
      };
      const frOff = hasMarketHeading && hasSessionTimes && hasCurrentDate && roundOff("FR");
      const srOff = hasMarketHeading && hasSessionTimes && hasCurrentDate && roundOff("SR");
      if (frOff) await enqueueRoundOff(source.market, "FR", "Source-confirmed round closure.");
      if (srOff) await enqueueRoundOff(source.market, "SR", "Source-confirmed round closure.");
      if (hasMarketHeading && hasSessionTimes && hasCurrentDate && (explicitOff || (frOff && srOff))) {
        await enqueueOff(source.market, "Source-confirmed full-market holiday.");
        confirmedOff++;
      }
      // Record a successful check only after the source was fetched and parsed.
      const { error: markError } = await supabase.from("result_source_sync")
        .upsert({ market: checkKey, last_checked_at: new Date().toISOString() }, { onConflict: "market" });
      if (markError) throw markError;
    } catch (error) {
      sourceErrors++;
      console.error("Market OFF source check failed for " + source.market + ":", error instanceof Error ? error.message : error);
    }
  }
  return { checked: true, date, sunday, off: confirmedOff, queued, source_errors: sourceErrors };
}
async function queueResultRoundPushNotification(market: string, date: string, round: "FR" | "SR", value: string) {
  const eventKey = `${market}:${date}:${round}:${value}`;
  const title = `${market} ${round} Result Updated`.slice(0, 80);
  const message = `${date} | ${round}: ${value}`;
  const { error } = await supabase.from("broadcast_notifications").insert({
    title, message, status: "pending", recipients: 0, event_key: eventKey, created_by: null,
  });
  if (error?.code === "23505") return { queued: false, reason: "duplicate_event" };
  if (error) throw error;
  return { queued: true };
}

async function flushResultPushNotifications() {
  const restKey = Deno.env.get("ONESIGNAL_REST_API_KEY")?.trim();
  if (!restKey) return { configured: false, sent: 0, pending: true };

  const { data: pending, error: listError } = await supabase.from("broadcast_notifications")
    .select("id,title,message,event_key")
    .eq("status", "pending")
    .not("event_key", "is", null)
    .order("created_at", { ascending: true })
    .limit(20);
  if (listError) throw listError;

  let sent = 0;
  let failed = 0;
  for (const item of pending ?? []) {
    const { data: claimed, error: claimError } = await supabase.from("broadcast_notifications")
      .update({ status: "sending", error_message: null })
      .eq("id", item.id)
      .eq("status", "pending")
      .select("id")
      .maybeSingle();
    if (claimError) {
      console.error("Could not claim result notification:", claimError.message);
      continue;
    }
    if (!claimed) continue;

    try {
      const response = await fetch("https://api.onesignal.com/notifications", {
        method: "POST",
        headers: {
          "Authorization": `Key ${restKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          app_id: ONESIGNAL_APP_ID,
          included_segments: ["Subscribed Users"],
          headings: { en: item.title },
          contents: { en: item.message },
          name: `Teer notification ${item.event_key}`,
          android_channel_id: "478b866d-a74d-4808-91d2-6e926e3f456b",
          priority: 10,
          data: { type: item.event_key.startsWith("market_off:") ? "market_off" : "teer_result", event_key: item.event_key },
        }),
      });
      const responseText = await response.text();
      let payload: Record<string, unknown> = {};
      try { payload = responseText ? JSON.parse(responseText) : {}; } catch { /* keep response text for diagnostics */ }
      if (!response.ok) {
        const detail = String(payload.errors ?? payload.error ?? responseText ?? `HTTP ${response.status}`).slice(0, 500);
        await supabase.from("broadcast_notifications").update({
          status: "failed",
          error_message: detail,
        }).eq("id", item.id);
        failed++;
        continue;
      }

      const { error: updateError } = await supabase.from("broadcast_notifications").update({
        status: "sent",
        notification_id: typeof payload.id === "string" ? payload.id : null,
        recipients: Number.isFinite(Number(payload.recipients)) ? Number(payload.recipients) : 0,
        sent_at: new Date().toISOString(),
        error_message: null,
      }).eq("id", item.id);
      if (updateError) {
        console.error("OneSignal accepted result notification but DB receipt update failed:", updateError.message);
      } else {
        sent++;
      }
    } catch (error) {
      const detail = (error instanceof Error ? error.message : String(error)).slice(0, 500);
      await supabase.from("broadcast_notifications").update({
        status: "failed",
        error_message: detail,
      }).eq("id", item.id);
      failed++;
    }
  }
  return { configured: true, sent, failed, remaining: Math.max(0, (pending?.length ?? 0) - sent - failed) };
}

async function saveVerifiedResultHistory(market: string, date: string, fr: string, sr: string, source: "source" | "admin", sourceUpdatedAt: string | null = null) {
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



async function settleBetsForResultDate(market: string, round: "FR" | "SR", resultNumber: string, resultDate: string) {
  if (!/^\d{2}$/.test(resultNumber)) return [];
  const iso = dateDmyToIso(resultDate);
  const start = iso + "T00:00:00+05:30";
  const next = new Date(Date.parse(iso + "T00:00:00Z") + 86400000).toISOString().slice(0, 10);
  const end = next + "T00:00:00+05:30";
  const { data: activeBets, error } = await supabase.from("bets").select("id")
    .eq("market", market).eq("round", round).eq("status", "active")
    .gte("created_at", start).lt("created_at", end).limit(2000);
  if (error) throw error;
  const settled = [];
  for (const bet of activeBets ?? []) {
    settled.push(await rpc("api_settle_bet", { p_bet_id: bet.id, p_result_number: resultNumber }));
  }
  return settled;
}

async function applyVerifiedRoundResults(preview: {
  market: string; date: string; fr?: string; sr?: string; source_updated_at: string | null;
}) {
  const { data: current, error: currentError } = await supabase.from("teer_results")
    .select("market,fr,sr,result_date,updated_by,source_updated_at")
    .eq("market", preview.market).maybeSingle();
  if (currentError) throw currentError;
  if (current?.updated_by && current.result_date === preview.date) return { applied: false, reason: "admin_correction_locked" };
  if (current?.result_date && current.result_date !== preview.date) {
    const currentIso = current.result_date.includes("/") ? dateDmyToIso(current.result_date) : current.result_date;
    if (currentIso > dateDmyToIso(preview.date)) return { applied: false, reason: "older_source_date" };
  }
  const sameDate = current?.result_date === preview.date;
  const nextFr = preview.fr ?? (sameDate ? current?.fr : "**") ?? "**";
  const nextSr = preview.sr ?? (sameDate ? current?.sr : "**") ?? "**";
  const frChanged = /^[0-9]{2}$/.test(String(preview.fr ?? "")) && (!sameDate || current?.fr !== preview.fr);
  const srChanged = /^[0-9]{2}$/.test(String(preview.sr ?? "")) && (!sameDate || current?.sr !== preview.sr);
  if (!frChanged && !srChanged) return { applied: false, reason: "already_current" };
  const { error: saveError } = await supabase.from("teer_results").upsert({
    market: preview.market, fr: nextFr, sr: nextSr, result_date: preview.date,
    updated_at: new Date().toISOString(), updated_by: null,
    source_updated_at: preview.source_updated_at ?? (sameDate ? current?.source_updated_at ?? null : null),
  }, { onConflict: "market" });
  if (saveError) throw saveError;
  let history: unknown = { saved: false, reason: "waiting_for_both_rounds" };
  if (/^[0-9]{2}$/.test(String(nextFr)) && /^[0-9]{2}$/.test(String(nextSr))) {
    history = await saveVerifiedResultHistory(preview.market, preview.date, nextFr, nextSr, "source", preview.source_updated_at);
  }
  const settlements: unknown[] = [];
  if (frChanged && preview.fr) settlements.push(...await settleBetsForResultDate(preview.market, "FR", String(preview.fr), preview.date));
  if (srChanged && preview.sr) settlements.push(...await settleBetsForResultDate(preview.market, "SR", String(preview.sr), preview.date));
  const notifications: unknown[] = [];
  if (frChanged) notifications.push(await queueResultRoundPushNotification(preview.market, preview.date, "FR", String(preview.fr)));
  if (srChanged) notifications.push(await queueResultRoundPushNotification(preview.market, preview.date, "SR", String(preview.sr)));
  return { applied: true, fr_changed: frChanged, sr_changed: srChanged, settled_count: settlements.length, history, notifications };
}

type KhanaparaSourcePreview =
  | { ready: false; status: string; market: string; page_date?: string; source_update_date?: string; previous_date?: string; previous_fr?: string; previous_sr?: string; source_updated_at: string | null; source_url: string }
  | { ready: true; status: "verified"; market: string; fr?: string; sr?: string; date: string; source_updated_at: string | null; source_url: string };

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

  const hasFr = /^[0-9]{2}$/.test(frResult);
  const hasSr = /^[0-9]{2}$/.test(srResult);
  const dateVerified = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(updatedIso) && pageDate === dateIsoToDmy(updatedIso);
  const archiveIsToday = Boolean(archiveRow && archiveRow[1] === dateIsoToDmy(updatedIso));
  if (!dateVerified || (!hasFr && !hasSr) || (awaiting && !archiveIsToday) ||
      (archiveIsToday && ((hasFr && archiveRow?.[2] !== frResult) || (hasSr && archiveRow?.[3] !== srResult)))) {
    return {
      ready: false, status: awaiting && !hasFr && !hasSr ? "awaiting" : "not_verified",
      market: KHANAPARA_MARKET, page_date: pageDate, source_update_date: updatedIso,
      source_updated_at: sourceUpdatedAt, source_url: KHANAPARA_SOURCE_URL,
    };
  }
  return {
    ready: true, status: "verified", market: KHANAPARA_MARKET,
    ...(hasFr ? { fr: frResult } : {}),
    ...(hasSr ? { sr: srResult } : {}),
    date: dateIsoToDmy(updatedIso),
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

      const preview = await fetchKhanaparaSourcePreview();
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

      const applied = await applyVerifiedRoundResults({
        market: KHANAPARA_MARKET, date: preview.date,
        ...(preview.fr ? { fr: preview.fr } : {}),
        ...(preview.sr ? { sr: preview.sr } : {}),
        source_updated_at: preview.source_updated_at,
      });
      return { ...preview, ...applied };
    } catch (error) {
      console.error("Khanapara source sync failed:", error instanceof Error ? error.message : error);
      return { ready: false, status: "source_error" };
    } finally {
      khanaparaCheckPromise = null;
    }
  })();
  return await khanaparaCheckPromise;
}


// Khanapara Morning and Night are separate sessions on the ShillongTeerGrounds page.
// Never read values from the Evening result block for either session.
const KHANAPARA_SESSIONS_SOURCE_URL = "https://shillongteergrounds.in/khanapara-teer-result-today/";
const KHANAPARA_MORNING_MARKET = "Khanapara Morning Teer";
const KHANAPARA_NIGHT_MARKET = "Khanapara Night Teer";

function parseGroundDate(value: string): string {
  const match = value.match(/^(\d{2})[.\/-](\d{2})[.\/-](\d{4})$/);
  if (!match) return "";
  return match[1] + "/" + match[2] + "/" + match[3];
}

async function fetchKhanaparaSessionPreview(
  session: "morning" | "night",
): Promise<{
  ready: boolean; status: string; market: string; date?: string;
  fr?: string; sr?: string; source_updated_at: string | null; source_url: string;
}> {
  const market = session === "morning" ? KHANAPARA_MORNING_MARKET : KHANAPARA_NIGHT_MARKET;
  const response = await fetch(KHANAPARA_SESSIONS_SOURCE_URL, {
    method: "GET",
    headers: {
      "User-Agent": "TeerOnlineResultSync/1.0 (+source verification)",
      "Accept": "text/html,application/xhtml+xml",
      "Cache-Control": "no-cache",
    },
  });
  if (!response.ok) throw new Error("Khanapara sessions source returned HTTP " + response.status);
  const html = await response.text();
  if (!html || html.length < 1000) throw new Error("Khanapara sessions page was empty or incomplete");
  const plain = htmlToPlainText(html);

  const heading = session === "morning" ? "Khanapara Morning Result" : "Khanapara Night Result";
  const nextHeading = session === "morning" ? "Khanapara Night Result" : "DIRECT GROUND CONNECTED";
  const start = plain.toLowerCase().indexOf(heading.toLowerCase());
  if (start < 0) {
    return { ready: false, status: "section_missing", market, source_updated_at: null, source_url: KHANAPARA_SESSIONS_SOURCE_URL };
  }
  const endCandidate = plain.toLowerCase().indexOf(nextHeading.toLowerCase(), start + heading.length);
  const section = plain.slice(start, endCandidate >= 0 ? endCandidate : Math.min(plain.length, start + 2200));
  const dateMatch = section.match(/Khanapara (?:Morning|Night) Result\s*[-–:]\s*(\d{2}[.\/-]\d{2}[.\/-]\d{4})/i);
  const date = dateMatch ? parseGroundDate(dateMatch[1]) : "";
  const resultPattern = session === "morning"
    ? /F\/R\s*\(10:30\s*AM\)\s*\|\s*S\/R\s*\(11:30\s*AM\)\s*(\d{2})\s*\|?\s*(\d{2})?/i
    : /F\/R\s*\(10:30\s*PM\)\s*\|\s*S\/R\s*\(11:30\s*PM\)\s*(\d{2})\s*\|?\s*(\d{2})?/i;
  const values = section.match(resultPattern);
  const fr = values?.[1] && /^\d{2}$/.test(values[1]) ? values[1] : undefined;
  const sr = values?.[2] && /^\d{2}$/.test(values[2]) ? values[2] : undefined;

  // Do not accept a previous day's cached block as today's live result.
  const today = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata", day: "2-digit", month: "2-digit", year: "numeric",
  }).format(new Date());
  const dateIsToday = date === today;
  if (!dateIsToday || (!fr && !sr)) {
    return {
      ready: false, status: dateIsToday ? "awaiting" : "date_not_current",
      market, ...(date ? { date } : {}), source_updated_at: null,
      source_url: KHANAPARA_SESSIONS_SOURCE_URL,
    };
  }
  return {
    ready: true, status: "verified", market, date,
    ...(fr ? { fr } : {}), ...(sr ? { sr } : {}),
    source_updated_at: null, source_url: KHANAPARA_SESSIONS_SOURCE_URL,
  };
}

async function syncKhanaparaSessionIfDue(session: "morning" | "night") {
  const market = session === "morning" ? KHANAPARA_MORNING_MARKET : KHANAPARA_NIGHT_MARKET;
  try {
    const { data: syncState, error: stateError } = await supabase.from("result_source_sync")
      .select("last_checked_at").eq("market", market).maybeSingle();
    if (stateError) throw stateError;
    const lastChecked = syncState?.last_checked_at ? new Date(syncState.last_checked_at).getTime() : 0;
    if (lastChecked && Date.now() - lastChecked < 60 * 1000) return null;

    const checkedAt = new Date().toISOString();
    const { error: markError } = await supabase.from("result_source_sync")
      .upsert({ market, last_checked_at: checkedAt }, { onConflict: "market" });
    if (markError) throw markError;

    let primary: Awaited<ReturnType<typeof fetchKhanaparaSessionPreview>> | null = null;
    try {
      primary = await fetchKhanaparaSessionPreview(session);
      if (primary.ready) {
        const applied = await applyVerifiedRoundResults({
          market, date: primary.date!,
          ...(primary.fr ? { fr: primary.fr } : {}),
          ...(primary.sr ? { sr: primary.sr } : {}),
          source_updated_at: primary.source_updated_at,
        });
        return { ...primary, source_used: "shillongteergrounds.in", applied };
      }
    } catch (error) {
      console.error("Khanapara " + session + " primary source failed:", error instanceof Error ? error.message : error);
    }

    let secondary: Awaited<ReturnType<typeof fetchKhanaparaSecondaryPreview>> | null = null;
    try {
      secondary = await fetchKhanaparaSecondaryPreview(session);
      if (secondary.ready) {
        const applied = await applyVerifiedRoundResults({
          market, date: secondary.date!,
          ...(secondary.fr ? { fr: secondary.fr } : {}),
          ...(secondary.sr ? { sr: secondary.sr } : {}),
          source_updated_at: secondary.source_updated_at,
        });
        return { ...secondary, source_used: "teer-result.com", fallback_from: primary?.status ?? "source_error", applied };
      }
    } catch (error) {
      console.error("Khanapara " + session + " secondary source failed:", error instanceof Error ? error.message : error);
    }

    try {
      const tertiary = await fetchKhanaparaTertiaryPreview(session);
      if (tertiary.ready) {
        const applied = await applyVerifiedRoundResults({
          market, date: tertiary.date!,
          ...(tertiary.fr ? { fr: tertiary.fr } : {}),
          ...(tertiary.sr ? { sr: tertiary.sr } : {}),
          source_updated_at: tertiary.source_updated_at,
        });
        return {
          ...tertiary, source_used: "shillongteeresults.com",
          fallback_from: secondary?.status ?? primary?.status ?? "source_error", applied,
        };
      }
      return {
        ready: false, status: tertiary.status, market,
        primary_status: primary?.status ?? "source_error",
        secondary_status: secondary?.status ?? "source_error",
        tertiary_status: tertiary.status,
        tertiary_url: tertiary.source_url,
      };
    } catch (error) {
      console.error("Khanapara " + session + " tertiary source failed:", error instanceof Error ? error.message : error);
      return {
        ready: false, status: "all_sources_unavailable", market,
        primary_status: primary?.status ?? "source_error",
        secondary_status: secondary?.status ?? "source_error",
      };
    }
  } catch (error) {
    console.error("Khanapara " + session + " source sync failed:", error instanceof Error ? error.message : error);
    return { ready: false, status: "source_error", market };
  }
}


// Secondary source: teer-result.com. Morning has its own named result card.
// Night is accepted ONLY if this site publishes an explicit Khanapara Night
// card with the user's exact 10:30 PM / 11:30 PM session times.
const KHANAPARA_SECONDARY_HOME_URL = "https://teer-result.com/";

async function fetchKhanaparaSecondaryPreview(
  session: "morning" | "night",
): Promise<{
  ready: boolean; status: string; market: string; date?: string;
  fr?: string; sr?: string; source_updated_at: string | null; source_url: string;
}> {
  const market = session === "morning" ? KHANAPARA_MORNING_MARKET : KHANAPARA_NIGHT_MARKET;
  const response = await fetch(KHANAPARA_SECONDARY_HOME_URL, {
    method: "GET",
    headers: {
      "User-Agent": "TeerOnlineResultSync/1.0 (+secondary result verification)",
      "Accept": "text/html,application/xhtml+xml",
      "Cache-Control": "no-cache",
    },
  });
  if (!response.ok) throw new Error("Secondary source returned HTTP " + response.status);
  const html = await response.text();
  if (!html || html.length < 1000) throw new Error("Secondary source page was empty or incomplete");
  const plain = htmlToPlainText(html);

  const heading = session === "morning"
    ? "Khanapara Morning Result Today"
    : "Khanapara Night Result Today";
  const nextHeadings = session === "morning"
    ? ["Night Teer Result Today", "Night Teer"]
    : ["Shillong Teer Result Today", "Night Teer Result Today"];
  const start = plain.toLowerCase().indexOf(heading.toLowerCase());
  if (start < 0) {
    return { ready: false, status: "section_missing", market, source_updated_at: null, source_url: KHANAPARA_SECONDARY_HOME_URL };
  }
  let end = plain.length;
  for (const nextHeading of nextHeadings) {
    const candidate = plain.toLowerCase().indexOf(nextHeading.toLowerCase(), start + heading.length);
    if (candidate >= 0 && candidate < end) end = candidate;
  }
  const section = plain.slice(start, end);
  const dateMatch = section.match(/Khanapara (?:Morning|Night) Result Today\s+(\d{2}-\d{2}-\d{4})/i);
  const date = dateMatch ? parseGroundDate(dateMatch[1]) : "";
  const isMorning = session === "morning";
  const frTime = isMorning ? "10:30\\s*am" : "10:30\\s*pm";
  const srTime = isMorning ? "11:30\\s*am" : "11:30\\s*pm";
  const frMatch = section.match(new RegExp("FR\\s*[·•]?\\s*" + frTime + "\\s*(\\d{2})", "i"));
  const srMatch = section.match(new RegExp("SR\\s*[·•]?\\s*" + srTime + "\\s*(\\d{2})", "i"));
  const fr = frMatch?.[1] ?? "";
  const sr = srMatch?.[1] ?? "";

  const today = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata", day: "2-digit", month: "2-digit", year: "numeric",
  }).format(new Date());
  const dateIsToday = date === today;
  const awaiting = /Awaiting today's result/i.test(section);
  if (!dateIsToday || awaiting || (!/^\d{2}$/.test(fr) && !/^\d{2}$/.test(sr))) {
    return {
      ready: false,
      status: !dateIsToday ? "date_not_current" : awaiting ? "awaiting" : "result_values_missing",
      market, ...(date ? { date } : {}), source_updated_at: null,
      source_url: KHANAPARA_SECONDARY_HOME_URL,
    };
  }
  return {
    ready: true, status: "verified", market, date,
    ...( /^\d{2}$/.test(fr) ? { fr } : {}),
    ...( /^\d{2}$/.test(sr) ? { sr } : {}),
    source_updated_at: null, source_url: KHANAPARA_SECONDARY_HOME_URL,
  };
}


// Third independent listing with explicitly separated Khanapara Morning/Night cards.
// The exact Khanapara card heading and round times are required.
const KHANAPARA_TERTIARY_URL = "https://shillongteeresults.com/khanapara-teer-result-today/";

function monthNameToNumber(value: string): string {
  const months = ["january","february","march","april","may","june","july","august","september","october","november","december"];
  const index = months.indexOf(value.toLowerCase());
  return index >= 0 ? String(index + 1).padStart(2, "0") : "";
}

async function fetchKhanaparaTertiaryPreview(
  session: "morning" | "night",
): Promise<{
  ready: boolean; status: string; market: string; date?: string;
  fr?: string; sr?: string; source_updated_at: string | null; source_url: string;
}> {
  const market = session === "morning" ? KHANAPARA_MORNING_MARKET : KHANAPARA_NIGHT_MARKET;
  const response = await fetch(KHANAPARA_TERTIARY_URL, {
    method: "GET",
    headers: {
      "User-Agent": "TeerOnlineResultSync/1.0 (+independent result listing)",
      "Accept": "text/html,application/xhtml+xml",
      "Cache-Control": "no-cache",
    },
  });
  if (!response.ok) throw new Error("Third source returned HTTP " + response.status);
  const html = await response.text();
  if (!html || html.length < 1000) throw new Error("Third source page was empty or incomplete");
  const plain = htmlToPlainText(html);

  const heading = session === "morning"
    ? "Khanapara Morning Teer Result Today"
    : "Khanapara Night Teer Result Today";
  const nextHeading = session === "morning"
    ? "Khanapara Night Teer Result Today"
    : "Khanapara Night Teer Common";
  const start = plain.toLowerCase().indexOf(heading.toLowerCase());
  if (start < 0) {
    return { ready: false, status: "section_missing", market, source_updated_at: null, source_url: KHANAPARA_TERTIARY_URL };
  }
  const endCandidate = plain.toLowerCase().indexOf(nextHeading.toLowerCase(), start + heading.length);
  const section = plain.slice(start, endCandidate >= 0 ? endCandidate : Math.min(plain.length, start + 2500));

  const dateMatches = Array.from(section.matchAll(/(\d{1,2})\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})/gi));
  const dateParts = dateMatches[0];
  const date = dateParts
    ? String(dateParts[1]).padStart(2, "0") + "/" + monthNameToNumber(dateParts[2]) + "/" + dateParts[3]
    : "";

  const frMatch = session === "morning"
    ? section.match(/FR\s+10:30\s*AM\s+(\d{2})/i)
    : section.match(/FR\s+10:30\s*PM\s+(\d{2})/i);
  const srMatch = session === "morning"
    ? section.match(/SR\s+11:30\s*AM\s+(\d{2})/i)
    : section.match(/SR\s+11:30\s*PM\s+(\d{2})/i);
  const fr = frMatch?.[1] ?? "";
  const sr = srMatch?.[1] ?? "";
  const today = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata", day: "2-digit", month: "2-digit", year: "numeric",
  }).format(new Date());

  if (!date || (!/^\d{2}$/.test(fr) && !/^\d{2}$/.test(sr))) {
    return { ready: false, status: "result_values_missing", market, ...(date ? { date } : {}), source_updated_at: null, source_url: KHANAPARA_TERTIARY_URL };
  }
  if (dateDmyToIso(date) > dateDmyToIso(today)) {
    return { ready: false, status: "future_date_rejected", market, date, source_updated_at: null, source_url: KHANAPARA_TERTIARY_URL };
  }
  return {
    ready: true, status: "verified", market, date,
    ...( /^\d{2}$/.test(fr) ? { fr } : {}),
    ...( /^\d{2}$/.test(sr) ? { sr } : {}),
    source_updated_at: null, source_url: KHANAPARA_TERTIARY_URL,
  };
}

// Shillong Morning is a separate 10:30 AM / 11:30 AM market.
// Read only its named card from the user's selected ShillongTeerGrounds source.
const SHILLONG_MORNING_SOURCE_URL = "https://shillongteergrounds.in/";
const SHILLONG_MORNING_MARKET = "Shillong Morning Teer";

async function fetchShillongMorningSourcePreview(): Promise<{
  ready: boolean; status: string; market: string; date?: string;
  fr?: string; sr?: string; source_updated_at: string | null; source_url: string;
}> {
  const response = await fetch(SHILLONG_MORNING_SOURCE_URL, {
    method: "GET",
    headers: {
      "User-Agent": "TeerOnlineResultSync/1.0 (+Shillong Morning result verification)",
      "Accept": "text/html,application/xhtml+xml",
      "Cache-Control": "no-cache",
    },
  });
  if (!response.ok) throw new Error("Shillong Morning source returned HTTP " + response.status);
  const html = await response.text();
  if (!html || html.length < 1000) throw new Error("Shillong Morning source page was empty or incomplete");

  const plain = htmlToPlainText(html);
  const heading = "Shillong Morning Result";
  const start = plain.toLowerCase().indexOf(heading.toLowerCase());
  if (start < 0) {
    return { ready: false, status: "section_missing", market: SHILLONG_MORNING_MARKET, source_updated_at: null, source_url: SHILLONG_MORNING_SOURCE_URL };
  }
  const nextHeading = plain.toLowerCase().indexOf("welcome morning result", start + heading.length);
  const section = plain.slice(start, nextHeading >= 0 ? nextHeading : Math.min(plain.length, start + 1800));
  const dateMatch = section.match(/Shillong Morning Result\s*[-–:]\s*(\d{2}[.\/-]\d{2}[.\/-]\d{4})/i);
  const date = dateMatch ? parseGroundDate(dateMatch[1]) : "";
  const values = section.match(/F\/R\s*\(10:30\s*AM\)\s*\|\s*S\/R\s*\(11:30\s*AM\)\s*(\d{2}|soon|pending|awaiting|off|--|xx)\s*\|\s*(\d{2}|soon|pending|awaiting|off|--|xx)/i);
  const fr = values?.[1] && /^\d{2}$/.test(values[1]) ? values[1] : undefined;
  const sr = values?.[2] && /^\d{2}$/.test(values[2]) ? values[2] : undefined;
  const today = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata", day: "2-digit", month: "2-digit", year: "numeric",
  }).format(new Date());

  if (date !== today) {
    return { ready: false, status: date ? "date_not_current" : "date_missing", market: SHILLONG_MORNING_MARKET, ...(date ? { date } : {}), source_updated_at: null, source_url: SHILLONG_MORNING_SOURCE_URL };
  }
  if (!fr && !sr) {
    return { ready: false, status: "awaiting_or_off", market: SHILLONG_MORNING_MARKET, date, source_updated_at: null, source_url: SHILLONG_MORNING_SOURCE_URL };
  }
  return {
    ready: true, status: "verified", market: SHILLONG_MORNING_MARKET, date,
    ...(fr ? { fr } : {}), ...(sr ? { sr } : {}),
    source_updated_at: null, source_url: SHILLONG_MORNING_SOURCE_URL,
  };
}

async function syncShillongMorningIfDue(force = false) {
  const market = SHILLONG_MORNING_MARKET;
  try {
    const { data: syncState, error: stateError } = await supabase.from("result_source_sync")
      .select("last_checked_at").eq("market", market).maybeSingle();
    if (stateError) throw stateError;
    const lastChecked = syncState?.last_checked_at ? new Date(syncState.last_checked_at).getTime() : 0;
    if (!force && lastChecked && Date.now() - lastChecked < 60 * 1000) return null;

    const { error: markError } = await supabase.from("result_source_sync")
      .upsert({ market, last_checked_at: new Date().toISOString() }, { onConflict: "market" });
    if (markError) throw markError;

    const preview = await fetchShillongMorningSourcePreview();
    if (!preview.ready) return preview;
    const applied = await applyVerifiedRoundResults({
      market, date: preview.date!,
      ...(preview.fr ? { fr: preview.fr } : {}),
      ...(preview.sr ? { sr: preview.sr } : {}),
      source_updated_at: preview.source_updated_at,
    });
    return { ...preview, applied };
  } catch (error) {
    console.error("Shillong Morning source sync failed:", error instanceof Error ? error.message : error);
    return { ready: false, status: "source_error", market };
  }
}

// Shillong Night is a separate 8:30 PM / 9:30 PM market.
// Read only its dedicated result card; never mix it with the late 11:10 PM Night Teer.
const SHILLONG_NIGHT_SOURCE_URL = "https://shillongnightteer.me/shillong-night-teer-result";

async function fetchShillongNightSourcePreview(): Promise<{
  ready: boolean; status: string; market: string; date?: string;
  fr?: string; sr?: string; source_updated_at: string | null; source_url: string;
}> {
  const market = "Shillong Night Teer";
  const response = await fetch(SHILLONG_NIGHT_SOURCE_URL, {
    method: "GET",
    headers: {
      "User-Agent": "TeerOnlineResultSync/1.0 (+Shillong Night result verification)",
      "Accept": "text/html,application/xhtml+xml",
      "Cache-Control": "no-cache",
    },
  });
  if (!response.ok) throw new Error("Shillong Night source returned HTTP " + response.status);
  const html = await response.text();
  if (!html || html.length < 1000) throw new Error("Shillong Night source page was empty or incomplete");
  const plain = htmlToPlainText(html);
  const heading = "Shillong Night (8:30)";
  const start = plain.toLowerCase().indexOf(heading.toLowerCase());
  if (start < 0) {
    return { ready: false, status: "section_missing", market, source_updated_at: null, source_url: SHILLONG_NIGHT_SOURCE_URL };
  }
  const nextHeading = plain.toLowerCase().indexOf("night teer result", start + heading.length);
  const section = plain.slice(start, nextHeading >= 0 ? nextHeading : Math.min(plain.length, start + 1400));
  const dateMatch = section.match(/(\d{2})\.(\d{2})\.(\d{4})/);
  const date = dateMatch ? dateMatch[1] + "/" + dateMatch[2] + "/" + dateMatch[3] : "";
  const frMatch = section.match(/F\/R\s*\(08:30\s*PM\)\s*(\d{2})/i);
  const srMatch = section.match(/S\/R\s*\(09:30\s*PM\)\s*(\d{2})/i);
  const fr = frMatch?.[1] ?? "";
  const sr = srMatch?.[1] ?? "";
  const today = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata", day: "2-digit", month: "2-digit", year: "numeric",
  }).format(new Date());
  if (date !== today) {
    return { ready: false, status: date ? "date_not_current" : "date_missing", market, ...(date ? { date } : {}), source_updated_at: null, source_url: SHILLONG_NIGHT_SOURCE_URL };
  }
  if (!/^\d{2}$/.test(fr) && !/^\d{2}$/.test(sr)) {
    return { ready: false, status: "awaiting", market, date, source_updated_at: null, source_url: SHILLONG_NIGHT_SOURCE_URL };
  }
  return {
    ready: true, status: "verified", market, date,
    ...( /^\d{2}$/.test(fr) ? { fr } : {}),
    ...( /^\d{2}$/.test(sr) ? { sr } : {}),
    source_updated_at: null, source_url: SHILLONG_NIGHT_SOURCE_URL,
  };
}

async function syncShillongNightIfDue(force = false) {
  const market = "Shillong Night Teer";
  try {
    const { data: syncState, error: stateError } = await supabase.from("result_source_sync")
      .select("last_checked_at").eq("market", market).maybeSingle();
    if (stateError) throw stateError;
    const lastChecked = syncState?.last_checked_at ? new Date(syncState.last_checked_at).getTime() : 0;
    if (!force && lastChecked && Date.now() - lastChecked < 60 * 1000) return null;
    const { error: markError } = await supabase.from("result_source_sync")
      .upsert({ market, last_checked_at: new Date().toISOString() }, { onConflict: "market" });
    if (markError) throw markError;
    const preview = await fetchShillongNightSourcePreview();
    if (!preview.ready) return preview;
    const applied = await applyVerifiedRoundResults({
      market, date: preview.date!,
      ...(preview.fr ? { fr: preview.fr } : {}),
      ...(preview.sr ? { sr: preview.sr } : {}),
      source_updated_at: preview.source_updated_at,
    });
    return { ...preview, applied };
  } catch (error) {
    console.error("Shillong Night source sync failed:", error instanceof Error ? error.message : error);
    return { ready: false, status: "source_error", market };
  }
}

// Shillong Teer source verification. The source page's current result is accepted
// only when its FR/SR pair matches the newest archive row and the page update date.
const SHILLONG_SOURCE_URL = "https://teer-result.com/shillong-teer-result/";
const SHILLONG_MARKET = "Shillong Teer (Evening)";
let shillongLastCheckAt = 0;
let shillongCheckPromise: Promise<unknown> | null = null;

type ShillongSourcePreview =
  | { ready: false; status: string; market: string; page_date?: string; source_update_date?: string; previous_date?: string; previous_fr?: string; previous_sr?: string; source_updated_at: string | null; source_url: string }
  | { ready: true; status: "verified"; market: string; fr?: string; sr?: string; date: string; source_updated_at: string | null; source_url: string };

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

  const hasFr = /^[0-9]{2}$/.test(frResult);
  const hasSr = /^[0-9]{2}$/.test(srResult);
  const dateVerified = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(updatedIso) && pageDate === dateIsoToDmy(updatedIso);
  const archiveIsToday = Boolean(archiveRow && archiveRow[1] === dateIsoToDmy(updatedIso));
  if (!dateVerified || (!hasFr && !hasSr) || (awaiting && !archiveIsToday) ||
      (archiveIsToday && ((hasFr && archiveRow?.[2] !== frResult) || (hasSr && archiveRow?.[3] !== srResult)))) {
    return {
      ready: false, status: awaiting && !hasFr && !hasSr ? "awaiting" : "not_verified",
      market: SHILLONG_MARKET, page_date: pageDate, source_update_date: updatedIso,
      source_updated_at: sourceUpdatedAt, source_url: SHILLONG_SOURCE_URL,
    };
  }
  return {
    ready: true, status: "verified", market: SHILLONG_MARKET,
    ...(hasFr ? { fr: frResult } : {}),
    ...(hasSr ? { sr: srResult } : {}),
    date: dateIsoToDmy(updatedIso),
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

      const preview = await fetchShillongSourcePreview();
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

      const applied = await applyVerifiedRoundResults({
        market: SHILLONG_MARKET, date: preview.date,
        ...(preview.fr ? { fr: preview.fr } : {}),
        ...(preview.sr ? { sr: preview.sr } : {}),
        source_updated_at: preview.source_updated_at,
      });
      return { ...preview, ...applied };
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

    // Server-side five-minute poller. The request is rate-limited by the
    // persistent result_source_sync row, so repeated public calls cannot
    // cause repeated source fetches inside the five-minute window.
    if (action === "scheduled_result_sync") {
      const marketOffNotifications = await queueMarketOffPushNotifications();
      const sync = await syncKhanaparaSourceIfDue(false);
      const khanaparaMorningSync = await syncKhanaparaSessionIfDue("morning");
      const khanaparaNightSync = await syncKhanaparaSessionIfDue("night");
      const shillongMorningSync = await syncShillongMorningIfDue(false);
      const shillongNightSync = await syncShillongNightIfDue(false);
      const shillongSync = await syncShillongSourceIfDue(false);
      const indiaParts = new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Kolkata", year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(new Date());
      const indiaToday = `${indiaParts.find((part) => part.type === "year")?.value}-${indiaParts.find((part) => part.type === "month")?.value}-${indiaParts.find((part) => part.type === "day")?.value}`;
      const previousIndiaDate = new Date(Date.parse(indiaToday + "T00:00:00Z") - 86400000).toISOString().slice(0, 10);
      const expiredBetRefunds = await rpc("refund_unresolved_teer_bets", { p_before_date: previousIndiaDate });
      const notifications = await flushResultPushNotifications();
      return json({ success: true, marketOffNotifications, sync, khanaparaMorningSync, khanaparaNightSync, shillongMorningSync, shillongNightSync, shillongSync, expiredBetRefunds, notifications }, 200, origin);
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


    if (action === "my_referrals") {
      const user = await getSession(req);
      if (!user || !user.id) return json({ error: "Please login again" }, 401, origin);
      const { data: referred, error: referredError } = await supabase.from("app_users")
        .select("id,uid,name,phone,created_at")
        .eq("referred_by_user_id", user.id)
        .order("created_at", { ascending: false }).limit(500);
      if (referredError) throw referredError;
      const referredIds = (referred ?? []).map((row: Record<string, unknown>) => String(row.id));
      let rewards: Record<string, unknown>[] = [];
      if (referredIds.length) {
        const { data, error } = await supabase.from("referral_rewards")
          .select("referred_user_id,reward_type,amount,created_at")
          .eq("referrer_user_id", user.id).in("referred_user_id", referredIds);
        if (error) throw error;
        rewards = (data ?? []) as Record<string, unknown>[];
      }
      const friends = (referred ?? []).map((friend: Record<string, unknown>) => {
        const earned = rewards.filter(reward => reward.referred_user_id === friend.id);
        const depositReward = earned.find(reward => reward.reward_type === "deposit_100");
        const betReward = earned.find(reward => reward.reward_type === "bets_1000");
        const phone = cleanPhone(friend.phone);
        return {
          uid: friend.uid,
          name: friend.name,
          maskedPhone: phone.length === 10 ? phone.slice(0, 2) + "••••" + phone.slice(-4) : "—",
          created_at: friend.created_at,
          depositReward: depositReward ? Number(depositReward.amount) : 0,
          betReward: betReward ? Number(betReward.amount) : 0,
        };
      });
      const totalEarned = rewards.reduce((sum, reward) => sum + Number(reward.amount || 0), 0);
      return json({ success: true, referral_code: user.uid ?? "", total_referrals: friends.length, total_earned: totalEarned, friends }, 200, origin);
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
      if (![KHANAPARA_MARKET, SHILLONG_MARKET, "Shilong Morning Teer", "Khanapara Morning Teer", "Shillong Night Teer", "Khanapara Night Teer"].includes(market)) {
        return json({ error: "Unknown result market" }, 400, origin);
      }
      const page = Math.max(0, Math.min(49, Number.isInteger(Number(body.page)) ? Number(body.page) : 0));
      const pageSize = 100;
      const { data, error } = await supabase.from("teer_result_history")
        .select("id,market,result_date,fr,sr,source,created_at,source_updated_at")
        .eq("market", market).order("result_date", { ascending: false })
        .range(page * pageSize, page * pageSize + pageSize - 1);
      if (error) throw error;
      const items = data ?? [];
      const hasMore = items.length === pageSize;
      return json({ success: true, history: items.slice(0, pageSize), has_more: hasMore, page }, 200, origin);
    }

    if (action === "public_app_data") {
      await Promise.all([syncKhanaparaSourceIfDue(false), syncShillongSourceIfDue(false), syncShillongMorningIfDue(false)]);

      const indiaParts = new Intl.DateTimeFormat("en-GB", { timeZone: "Asia/Kolkata", day: "2-digit", month: "2-digit", year: "numeric" }).formatToParts(new Date());
      const part = (type: string) => indiaParts.find((item) => item.type === type)?.value ?? "";
      const todayIso = part("year") + "-" + part("month") + "-" + part("day");
      const date = part("day") + "/" + part("month") + "/" + part("year");
      const marketNames = ["Shillong Morning Teer","Khanapara Morning Teer","Shillong Teer (Evening)","Khanapara Teer (Evening)","Shillong Night Teer","Khanapara Night Teer"];
      const offKeys = marketNames.flatMap((market) => [
        "market_off:" + market + ":" + todayIso,
        "market_round_off:" + market + ":" + todayIso + ":FR",
        "market_round_off:" + market + ":" + todayIso + ":SR",
      ]);
      const [{ data: results, error: resultsError }, { data: settings, error: settingsError }, { data: rounds, error: roundsError }, { data: offRows, error: offError }] = await Promise.all([
        supabase.from("teer_results").select("market,fr,sr,result_date,updated_at,source_updated_at"),
        supabase.from("app_settings").select("helpline,deposit_upi,deposit_qr_image,marquee_text,market_schedules").eq("id", 1).maybeSingle(),
        supabase.from("teer_minute_rounds").select("id,result_type,starts_at,ends_at,result_number,result_source,status,published_at").order("starts_at", { ascending: false }).limit(100),
        supabase.from("broadcast_notifications").select("event_key").in("event_key", offKeys),
      ]);
      if (resultsError) throw resultsError;
      if (settingsError) throw settingsError;
      if (roundsError) throw roundsError;
      if (offError) throw offError;
      const resultMap: Record<string, unknown> = {};
      for (const row of results ?? []) resultMap[row.market] = { fr: row.fr ?? "**", sr: row.sr ?? "**", date: row.result_date ?? "", updated_at: row.updated_at ?? null, source_updated_at: row.source_updated_at ?? null };
      const marketOff: Record<string, boolean> = {};
      const marketRoundOff: Record<string, { FR?: boolean; SR?: boolean }> = {};
      for (const row of offRows ?? []) {
        const key = String(row.event_key ?? "");
        for (const market of marketNames) {
          if (key === "market_off:" + market + ":" + todayIso) marketOff[market] = true;
          for (const round of ["FR", "SR"] as const) {
            if (key === "market_round_off:" + market + ":" + todayIso + ":" + round) {
              marketRoundOff[market] = marketRoundOff[market] ?? {};
              marketRoundOff[market][round] = true;
            }
          }
        }
      }
      const weekday = new Intl.DateTimeFormat("en-US", { timeZone: "Asia/Kolkata", weekday: "short" }).format(new Date());
      if (weekday === "Sun") {
        marketOff["Shillong Teer (Evening)"] = true;
        marketOff["Khanapara Teer (Evening)"] = true;
      }
      return json({ success: true, date, results: resultMap, market_off: marketOff, market_round_off: marketRoundOff, settings: settings ?? {}, rounds: rounds ?? [] }, 200, origin);
    }


    if (action === "admin_send_push") {
      const admin = await getSession(req);
      if (!admin || !admin.id) return json({ error: "Please login again" }, 401, origin);
      if (!(await requireAdmin(admin))) return json({ error: "Admin access denied" }, 403, origin);
      const title = String(body.title ?? "").trim().slice(0, 80);
      const message = String(body.message ?? "").trim().slice(0, 1000);
      if (!title || !message) return json({ error: "Notification title and message are required" }, 400, origin);
      const restKey = Deno.env.get("ONESIGNAL_REST_API_KEY")?.trim();
      if (!restKey) return json({ error: "OneSignal is not configured on the server" }, 503, origin);
      const eventKey = "admin_broadcast:" + crypto.randomUUID();
      const { data: logRow, error: logError } = await supabase.from("broadcast_notifications").insert({
        title, message, status: "sending", recipients: 0, event_key: eventKey, created_by: admin.id,
      }).select("id").single();
      if (logError) throw logError;
      try {
        const response = await fetch("https://api.onesignal.com/notifications", {
          method: "POST",
          headers: { "Authorization": "Key " + restKey, "Content-Type": "application/json" },
          body: JSON.stringify({
            app_id: ONESIGNAL_APP_ID,
            included_segments: ["Subscribed Users"],
            headings: { en: title },
            contents: { en: message },
            name: "Teer Online admin broadcast " + eventKey,
            android_channel_id: "478b866d-a74d-4808-91d2-6e926e3f456b",
            priority: 10,
            data: { type: "admin_broadcast", event_key: eventKey },
          }),
        });
        const payload = await response.json().catch(() => ({}));
        const hasErrors = Array.isArray(payload.errors) ? payload.errors.length > 0 : Boolean(payload.errors);
        if (!response.ok || hasErrors) {
          const reason = String(payload.errors?.[0] || payload.errors || ("OneSignal HTTP " + response.status)).slice(0, 500);
          await supabase.from("broadcast_notifications").update({ status: "failed", error_message: reason }).eq("id", logRow.id);
          return json({ error: "OneSignal rejected the notification", details: reason }, 502, origin);
        }
        const recipients = Number(payload.recipients || 0);
        await supabase.from("broadcast_notifications").update({ status: "sent", notification_id: payload.id ?? null, recipients, sent_at: new Date().toISOString(), error_message: null }).eq("id", logRow.id);
        return json({ success: true, recipients, notification_id: payload.id ?? null, delivery: "accepted_by_onesignal" }, 200, origin);
      } catch (sendError) {
        const reason = String(sendError instanceof Error ? sendError.message : sendError).slice(0, 500);
        await supabase.from("broadcast_notifications").update({ status: "failed", error_message: reason }).eq("id", logRow.id);
        throw sendError;
      }
    }

    if (["admin_dashboard", "admin_save_result", "admin_reset_result", "admin_save_settings", "admin_fetch_source_result"].includes(action)) {
      const admin = await getSession(req);
      if (!admin || !admin.id) return json({ error: "Please login again" }, 401, origin);
      if (!(await requireAdmin(admin))) return json({ error: "Admin access denied" }, 403, origin);

      if (action === "admin_fetch_source_result") {
        const preview = await fetchKhanaparaSourcePreview();
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
            settlements.push(...await settleBetsForResultDate(market, round, resultNumber, resultDate!));
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
