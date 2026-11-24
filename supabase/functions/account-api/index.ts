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
    "Access-Control-Allow-Headers": "authorization, x-session-token, x-client-info, apikey, content-type, x-redeem-telegram-token",
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
const KHANAPARA_SOURCE_URL = "https://shillongteergrounds.in/";
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
    { market: "Shilong Morning Teer", heading: "Shillong Morning Result", url: "https://shillongteergrounds.in/", frTime: "10:30 AM", srTime: "11:30 AM", verifyTimes: true },
    { market: "Khanapara Morning Teer", heading: "Khanapara Morning Teer Result Today", url: "https://teer-result.com/khanapara-morning-teer-result/", frTime: "10:30 AM", srTime: "11:30 AM" },
    { market: "Shillong Teer (Evening)", heading: "Shillong Teer Result", url: "https://shillongteergrounds.in/", frTime: "03:15 PM", srTime: "04:15 PM", verifyTimes: true },
    { market: "Khanapara Teer (Evening)", heading: "Khanapara Teer Result", url: "https://shillongteergrounds.in/", frTime: "04:10 PM", srTime: "04:45 PM", verifyTimes: true },
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
      const nextCardHeadings = [
        "Khanapara Teer Result", "Juwai Teer Result", "Shillong Morning Result",
        "Welcome Morning Result", "Shillong Night", "Night Teer Result",
        "Khanapara Morning Teer Result", "Khanapara Night Result",
      ];
      const nextCardStarts = nextCardHeadings
        .map((heading) => plain.toLowerCase().indexOf(heading.toLowerCase(), headingIndex + source.heading.length))
        .filter((index) => index >= 0);
      const sectionEnd = nextCardStarts.length ? Math.min(...nextCardStarts) : headingIndex + 1400;
      const section = headingIndex >= 0 ? plain.slice(headingIndex, sectionEnd) : "";
      const normalizedSection = section.replace(/\s+/g, " ").toLowerCase();
      const hasMarketHeading = headingIndex >= 0;
      const hasSessionTimes = !source.verifyTimes || (normalizedSection.includes(source.frTime.toLowerCase()) &&
        normalizedSection.includes(source.srTime.toLowerCase()));
      const monthLong = new Intl.DateTimeFormat("en-GB", { timeZone: "Asia/Kolkata", month: "long" }).format(now);
      const monthShort = new Intl.DateTimeFormat("en-GB", { timeZone: "Asia/Kolkata", month: "short" }).format(now);
      const dateLong = part("day") + " " + monthLong + " " + part("year");
      const dateShort = part("day") + " " + monthShort + " " + part("year");
      const dateDot = part("day") + "." + part("month") + "." + part("year");
      const datePattern = [dateIso, dateDash, date, dateDot, dateLong, dateShort];
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

      // Shillong Evening must be marked fully OFF only by an explicit OFF/holiday
      // statement for today's dated market section. Two loosely matched round
      // labels are not enough to close the whole market.
      const isShillongEvening = source.market === "Shillong Teer (Evening)";
      const verifiedTodaySection = hasMarketHeading && hasSessionTimes && hasCurrentDate;
      const confirmedFullMarketOff = explicitOff || (!isShillongEvening && frOff && srOff);
      if (verifiedTodaySection && confirmedFullMarketOff) {
        await enqueueOff(source.market, "Source-confirmed full-market holiday.");
        confirmedOff++;
      }

      // A fresh, dated Shillong Evening section with no OFF markers invalidates
      // stale OFF flags previously stored for this same market and date.
      if (isShillongEvening && verifiedTodaySection && !explicitOff && !frOff && !srOff) {
        const staleKeys = [
          "market_off:" + source.market + ":" + dateIso,
          "market_round_off:" + source.market + ":" + dateIso + ":FR",
          "market_round_off:" + source.market + ":" + dateIso + ":SR",
        ];
        const { error: clearOffError } = await supabase.from("broadcast_notifications")
          .delete().in("event_key", staleKeys);
        if (clearOffError) throw clearOffError;
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
  const marketNames: Record<string, string> = {
    "Shilong Morning Teer": "Shillong Morning Teer",
    "Khanapara Morning Teer": "Khanapara Morning Teer",
    "Shillong Teer (Evening)": "Shillong Evening Teer",
    "Khanapara Teer (Evening)": "Khanapara Evening Teer",
    "Shillong Night Teer": "Shillong Night Teer",
    "Khanapara Night Teer": "Khanapara Night Teer",
  };
  const displayMarket = marketNames[market] ?? market;
  const title = `🎯 ${displayMarket} — ${round} Result`.slice(0, 80);
  const message = `${round} Number: ${value} 🎯 Check your wallet now!`;
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
          included_segments: ["Active Subscriptions"],
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

async function flushRefundPushNotifications() {
  const restKey = Deno.env.get("ONESIGNAL_REST_API_KEY")?.trim();
  if (!restKey) return { configured: false, sent: 0, failed: 0 };
  const { data: pending, error } = await supabase.from("user_notifications")
    .select("id,user_id,title,message")
    .is("push_sent_at", null)
    .order("created_at", { ascending: true })
    .limit(100);
  if (error) throw error;
  let sent = 0;
  let failed = 0;
  for (const item of pending ?? []) {
    try {
      const response = await fetch("https://api.onesignal.com/notifications", {
        method: "POST",
        headers: { "Authorization": `Key ${restKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          app_id: ONESIGNAL_APP_ID,
          include_aliases: { external_id: [String(item.user_id)] },
          target_channel: "push",
          headings: { en: item.title },
          contents: { en: item.message },
          name: `Personal refund notification ${item.id}`,
          data: { type: "bet_refund", notification_id: item.id }
        })
      });
      const responseText = await response.text();
      let payload: Record<string, unknown> = {};
      try { payload = responseText ? JSON.parse(responseText) : {}; } catch { /* retain response text */ }
      if (!response.ok) {
        const detail = String(payload.errors ?? payload.error ?? responseText ?? `HTTP ${response.status}`).slice(0, 500);
        await supabase.from("user_notifications").update({ push_error: detail }).eq("id", item.id);
        failed++;
        continue;
      }
      await supabase.from("user_notifications").update({ push_sent_at: new Date().toISOString(), push_error: null }).eq("id", item.id);
      sent++;
    } catch (error) {
      const detail = (error instanceof Error ? error.message : String(error)).slice(0, 500);
      await supabase.from("user_notifications").update({ push_error: detail }).eq("id", item.id);
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

function parseGroundsMarketCard(
  plain: string, market: string, heading: string, frTime: string, srTime: string,
  dynamicTimes = false,
) {
  const escapePattern = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const token = "(\\d{2}|off|soon|pending|awaiting|--|xx)";
  const lowerPlain = plain.toLowerCase();
  const headingIndex = lowerPlain.indexOf(heading.toLowerCase());
  if (headingIndex < 0) {
    return { ready: false as const, status: "live_card_not_found", market, source_updated_at: null, source_url: "https://shillongteergrounds.in/" };
  }
  const otherHeadings = [
    "Khanapara Teer Result", "Shillong Teer Result", "Shillong Morning Result",
    "Khanapara Morning Result", "Welcome Morning Result", "Shillong Night (8:30)",
    "Night Teer Result", "Khanapara Night Result",
  ].filter((value) => value.toLowerCase() !== heading.toLowerCase());
  const nextStarts = otherHeadings
    .map((value) => lowerPlain.indexOf(value.toLowerCase(), headingIndex + heading.length))
    .filter((index) => index >= 0);
  const sectionEnd = nextStarts.length ? Math.min(...nextStarts) : Math.min(plain.length, headingIndex + 1800);
  const section = plain.slice(headingIndex, sectionEnd);
  const dateMatch = section.match(new RegExp(
    escapePattern(heading) + "\\s*[-–:]\\s*(\\d{2}[.\\/-]\\d{2}[.\\/-]\\d{4})", "i",
  ));
  // Shillong Evening's displayed round times can change. Match the FR/SR
  // labels without pinning the parser to clock text; keep fixed-time matching
  // for the other markets that still use their configured source labels.
  // Ignore source clock labels: bind FR and SR by the exact named card and its displayed date.
  const rounds = new RegExp(
    "F\\/R(?:\\s*\\([^)]*\\))?[\\s\\S]{0,120}?S\\/R(?:\\s*\\([^)]*\\))?[\\s\\S]{0,80}?" +
      token + "(?:\\s*\\|\\s*|\\s+)" + token,
    "i",
  );
  const card = dateMatch && section.match(rounds)
    ? [section, dateMatch[1], ...section.match(rounds)!.slice(1)] as RegExpMatchArray
    : null;
  const sourceUrl = "https://shillongteergrounds.in/";
  if (!card) {
    return { ready: false as const, status: "live_card_not_found", market, source_updated_at: null, source_url: sourceUrl };
  }
  const date = parseGroundDate(card[1]);
  const frValue = card[2].toLowerCase();
  const srValue = card[3].toLowerCase();
  const today = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata", day: "2-digit", month: "2-digit", year: "numeric",
  }).format(new Date());
  if (date !== today) {
    return { ready: false as const, status: date ? "date_not_current" : "date_missing", market, ...(date ? { page_date: date } : {}), source_updated_at: null, source_url: sourceUrl };
  }
  if (frValue === "off" && srValue === "off") {
    return { ready: false as const, status: "off", market, page_date: date, source_updated_at: null, source_url: sourceUrl };
  }
  const fr = /^\d{2}$/.test(frValue) ? frValue : undefined;
  const sr = /^\d{2}$/.test(srValue) ? srValue : undefined;
  if (!fr || !sr) {
    return { ready: false as const, status: "awaiting_complete_same_date_pair", market, page_date: date, source_updated_at: null, source_url: sourceUrl };
  }
  return { ready: true as const, status: "verified" as const, market, date, ...(fr ? { fr } : {}), ...(sr ? { sr } : {}), source_updated_at: null, source_url: sourceUrl };
}

async function fetchGroundsMarketPreview(
  market: string, heading: string, frTime: string, srTime: string, dynamicTimes = false,
) {
  const response = await fetch("https://shillongteergrounds.in/", {
    method: "GET",
    headers: {
      "User-Agent": "TeerOnlineResultSync/1.0 (+market result verification)",
      "Accept": "text/html,application/xhtml+xml",
      "Cache-Control": "no-cache",
    },
  });
  if (!response.ok) throw new Error("ShillongTeerGrounds source returned HTTP " + response.status);
  const html = await response.text();
  if (!html || html.length < 1000) throw new Error("ShillongTeerGrounds source page was empty or incomplete");
  return parseGroundsMarketCard(htmlToPlainText(html), market, heading, frTime, srTime, dynamicTimes);
}

async function fetchKhanaparaSourcePreview(): Promise<KhanaparaSourcePreview> {
  return await fetchGroundsMarketPreview(
    KHANAPARA_MARKET, "Khanapara Teer Result", "04:10 PM", "04:45 PM",
  ) as KhanaparaSourcePreview;
}

async function syncKhanaparaSourceIfDue(force = false) {
  if (khanaparaCheckPromise) return await khanaparaCheckPromise;
  khanaparaCheckPromise = (async () => {
    try {
      const { data: syncState, error: stateError } = await supabase.from("result_source_sync")
        .select("last_checked_at").eq("market", KHANAPARA_MARKET).maybeSingle();
      if (stateError) throw stateError;
      const lastChecked = syncState?.last_checked_at ? new Date(syncState.last_checked_at).getTime() : 0;
      if (!force && lastChecked && Date.now() - lastChecked < 5 * 60 * 1000) return null;

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

const KHANAPARA_NIGHT_PREFERRED_URL = "https://shillongnighteer.com/khanapara-teer-result-today/";

async function fetchKhanaparaNightPreferredPreview(): Promise<{
  ready: boolean; status: string; market: string; date?: string;
  fr?: string; sr?: string; source_updated_at: string | null; source_url: string;
}> {
  const market = KHANAPARA_NIGHT_MARKET;
  const response = await fetch(KHANAPARA_NIGHT_PREFERRED_URL, {
    method: "GET",
    headers: {
      "User-Agent": "TeerOnlineResultSync/1.0 (+Khanapara Night result verification)",
      "Accept": "text/html,application/xhtml+xml",
      "Cache-Control": "no-cache",
    },
  });
  if (!response.ok) throw new Error("Khanapara Night source returned HTTP " + response.status);
  const html = await response.text();
  if (!html || html.length < 1000) throw new Error("Khanapara Night source page was empty or incomplete");
  const plain = htmlToPlainText(html);
  const heading = "Khanapara Night Teer Result Today";
  const start = plain.toLowerCase().lastIndexOf(heading.toLowerCase());
  if (start < 0) {
    return { ready: false, status: "section_missing", market, source_updated_at: null, source_url: KHANAPARA_NIGHT_PREFERRED_URL };
  }
  const nextHeading = plain.toLowerCase().indexOf("khanapara teer common number", start + heading.length);
  const section = plain.slice(start, nextHeading >= 0 ? nextHeading : Math.min(plain.length, start + 1800));
  const dateMatch = section.match(/(\d{1,2})\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})/i);
  const monthIndex = dateMatch ? ["january","february","march","april","may","june","july","august","september","october","november","december"].indexOf(dateMatch[2].toLowerCase()) + 1 : 0;
  const date = dateMatch ? dateMatch[1].padStart(2, "0") + "/" + String(monthIndex).padStart(2, "0") + "/" + dateMatch[3] : "";
  const frMatch = section.match(/FR\s*10:30\s*PM\s*(\d{2})/i);
  const srMatch = section.match(/SR\s*11:30\s*PM\s*(\d{2})/i);
  const fr = frMatch?.[1] ?? "";
  const sr = srMatch?.[1] ?? "";
  const today = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata", day: "2-digit", month: "2-digit", year: "numeric",
  }).format(new Date());
  if (date !== today) {
    return { ready: false, status: date ? "date_not_current" : "date_missing", market, ...(date ? { date } : {}), source_updated_at: null, source_url: KHANAPARA_NIGHT_PREFERRED_URL };
  }
  if (!/^\d{2}$/.test(fr) && !/^\d{2}$/.test(sr)) {
    return { ready: false, status: "awaiting", market, date, source_updated_at: null, source_url: KHANAPARA_NIGHT_PREFERRED_URL };
  }
  return {
    ready: true, status: "verified", market, date,
    ...( /^\d{2}$/.test(fr) ? { fr } : {}),
    ...( /^\d{2}$/.test(sr) ? { sr } : {}),
    source_updated_at: null, source_url: KHANAPARA_NIGHT_PREFERRED_URL,
  };
}

async function syncKhanaparaSessionIfDue(session: "morning" | "night") {
  const market = session === "morning" ? KHANAPARA_MORNING_MARKET : KHANAPARA_NIGHT_MARKET;
  try {
    const { data: syncState, error: stateError } = await supabase.from("result_source_sync")
      .select("last_checked_at").eq("market", market).maybeSingle();
    if (stateError) throw stateError;
    const lastChecked = syncState?.last_checked_at ? new Date(syncState.last_checked_at).getTime() : 0;
    if (lastChecked && Date.now() - lastChecked < 5 * 60 * 1000) return null;

    const checkedAt = new Date().toISOString();
    const { error: markError } = await supabase.from("result_source_sync")
      .upsert({ market, last_checked_at: checkedAt }, { onConflict: "market" });
    if (markError) throw markError;

    let primary: {
      ready: boolean; status: string; market: string; date?: string;
      fr?: string; sr?: string; source_updated_at: string | null; source_url: string;
    } | null = null;
    try {
      primary = session === "morning"
        ? await fetchKhanaparaSecondaryPreview("morning")
        : await fetchKhanaparaNightPreferredPreview();
      if (primary.ready) {
        const applied = await applyVerifiedRoundResults({
          market, date: primary.date!,
          ...(primary.fr ? { fr: primary.fr } : {}),
          ...(primary.sr ? { sr: primary.sr } : {}),
          source_updated_at: primary.source_updated_at,
        });
        return { ...primary, source_used: session === "morning" ? "teer-result.com" : "shillongnighteer.com", applied };
      }
    } catch (error) {
      console.error("Khanapara " + session + " preferred source failed:", error instanceof Error ? error.message : error);
    }

    let secondary: {
      ready: boolean; status: string; market: string; date?: string;
      fr?: string; sr?: string; source_updated_at: string | null; source_url: string;
    } | null = null;
    try {
      secondary = session === "morning"
        ? await fetchKhanaparaSessionPreview("morning")
        : await fetchKhanaparaSecondaryPreview("night");
      if (secondary.ready) {
        const applied = await applyVerifiedRoundResults({
          market, date: secondary.date!,
          ...(secondary.fr ? { fr: secondary.fr } : {}),
          ...(secondary.sr ? { sr: secondary.sr } : {}),
          source_updated_at: secondary.source_updated_at,
        });
        return {
          ...secondary,
          source_used: session === "morning" ? "shillongteergrounds.in" : "teer-result.com",
          fallback_from: primary?.status ?? "source_error",
          applied,
        };
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
        return { ...tertiary, source_used: "shillongteeresults.com", fallback_from: secondary?.status ?? primary?.status ?? "source_error", applied };
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
const SHILLONG_MORNING_MARKET = "Shilong Morning Teer";

async function fetchShillongMorningSourcePreview(): Promise<{
  ready: boolean; status: string; market: string; date?: string;
  fr?: string; sr?: string; source_updated_at: string | null; source_url: string;
}> {
  return await fetchGroundsMarketPreview(
    SHILLONG_MORNING_MARKET, "Shillong Morning Result", "10:30 AM", "11:30 AM",
  );
}

async function syncShillongMorningIfDue(force = false) {
  const market = SHILLONG_MORNING_MARKET;
  try {
    const { data: syncState, error: stateError } = await supabase.from("result_source_sync")
      .select("last_checked_at").eq("market", market).maybeSingle();
    if (stateError) throw stateError;
    const lastChecked = syncState?.last_checked_at ? new Date(syncState.last_checked_at).getTime() : 0;
    if (!force && lastChecked && Date.now() - lastChecked < 5 * 60 * 1000) return null;

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
const SHILLONG_NIGHT_SOURCE_URL = "https://teer-result.com/shillong-night-teer-result/";

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
  const lower = plain.toLowerCase();
  const heading = "Shillong Night Teer Result Today";
  const start = lower.indexOf(heading.toLowerCase());
  if (start < 0) {
    return { ready: false, status: "section_missing", market, source_updated_at: null, source_url: SHILLONG_NIGHT_SOURCE_URL };
  }

  // Keep this exact market card isolated. Never borrow a date or number from
  // another market card or from the page's previous-result/last-result area.
  const nextHeadings = [
    "Khanapara Night Teer Result Today", "Khanapara Teer Result Today",
    "Shillong Morning Teer Result Today", "Khanapara Morning Teer Result Today",
    "Shillong Teer Result Today",
  ];
  const nextStarts = nextHeadings
    .map((h) => lower.indexOf(h.toLowerCase(), start + heading.length))
    .filter((n) => n >= 0);
  const sectionEnd = nextStarts.length ? Math.min(...nextStarts) : Math.min(plain.length, start + 1200);
  const section = plain.slice(start, sectionEnd);

  // The displayed date must belong to this exact heading/card. Clock labels
  // are intentionally ignored because source-site round times can change.
  const header = section.slice(heading.length, Math.min(section.length, heading.length + 100));
  const dateMatch = header.match(/^\s*[-–:]?\s*(\d{2})[-/.](\d{2})[-/.](\d{4})/);
  const date = dateMatch ? dateMatch[1] + "/" + dateMatch[2] + "/" + dateMatch[3] : "";
  if (!date) {
    return { ready: false, status: "date_missing", market, source_updated_at: null, source_url: SHILLONG_NIGHT_SOURCE_URL };
  }

  const roundPattern = /\bFR\b(?:\s*[-·•:]\s*|\s+)(?:\([^)]*\)\s*)?(?:\d{1,2}:\d{2}\s*(?:AM|PM)\s*)?(\d{2})\b[\s\S]{0,120}?\bSR\b(?:\s*[-·•:]\s*|\s+)(?:\([^)]*\)\s*)?(?:\d{1,2}:\d{2}\s*(?:AM|PM)\s*)?(\d{2})\b/i;
  const pair = section.match(roundPattern);
  if (!pair) {
    return { ready: false, status: "awaiting_complete_same_date_pair", market, date, source_updated_at: null, source_url: SHILLONG_NIGHT_SOURCE_URL };
  }
  const pairStart = pair.index ?? 0;
  const pairText = section.slice(Math.max(0, pairStart - 50), pairStart + pair[0].length + 100);
  if (/\blast\b|previous|yesterday/i.test(pairText)) {
    return { ready: false, status: "previous_result_rejected", market, date, source_updated_at: null, source_url: SHILLONG_NIGHT_SOURCE_URL };
  }

  const today = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata", day: "2-digit", month: "2-digit", year: "numeric",
  }).format(new Date());
  if (date !== today) {
    return { ready: false, status: "date_not_current", market, date, source_updated_at: null, source_url: SHILLONG_NIGHT_SOURCE_URL };
  }
  return {
    ready: true, status: "verified", market, date,
    fr: pair[1], sr: pair[2],
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
    if (!force && lastChecked && Date.now() - lastChecked < 5 * 60 * 1000) return null;
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
const SHILLONG_SOURCE_URL = "https://shillongteergrounds.in/";
const SHILLONG_MARKET = "Shillong Teer (Evening)";
let shillongLastCheckAt = 0;
let shillongCheckPromise: Promise<unknown> | null = null;

type ShillongSourcePreview =
  | { ready: false; status: string; market: string; page_date?: string; source_update_date?: string; previous_date?: string; previous_fr?: string; previous_sr?: string; source_updated_at: string | null; source_url: string }
  | { ready: true; status: "verified"; market: string; fr?: string; sr?: string; date: string; source_updated_at: string | null; source_url: string };

async function fetchShillongSourcePreview(): Promise<ShillongSourcePreview> {
  return await fetchGroundsMarketPreview(
    SHILLONG_MARKET, "Shillong Teer Result", "", "", true,
  ) as ShillongSourcePreview;
}

async function syncShillongSourceIfDue(force = false) {
  if (shillongCheckPromise) return await shillongCheckPromise;
  shillongCheckPromise = (async () => {
    try {
      const { data: syncState, error: stateError } = await supabase.from("result_source_sync")
        .select("last_checked_at").eq("market", SHILLONG_MARKET).maybeSingle();
      if (stateError) throw stateError;
      const lastChecked = syncState?.last_checked_at ? new Date(syncState.last_checked_at).getTime() : 0;
      if (!force && lastChecked && Date.now() - lastChecked < 5 * 60 * 1000) return null;

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

async function sendRedeemCodePush(code: Record<string, unknown>) {
  const restKey = Deno.env.get("ONESIGNAL_REST_API_KEY")?.trim();
  if (!restKey) {
    await supabase.from("redeem_codes").update({ push_error: "OneSignal is not configured" }).eq("id", code.id);
    return { sent: false, reason: "OneSignal is not configured" };
  }
  const response = await fetch("https://api.onesignal.com/notifications", {
    method: "POST",
    headers: { "Authorization": "Key " + restKey, "Content-Type": "application/json" },
    body: JSON.stringify({
      app_id: ONESIGNAL_APP_ID,
      included_segments: ["Active Subscriptions"],
      headings: { en: "🎁 New Redeem Code — Teer Online" },
      contents: { en: "Redeem code " + String(code.code || "") + " is live! Claim your random ₹2–₹20 reward. Limited users only." },
      name: "Teer Online redeem code " + String(code.code || ""),
      android_channel_id: "478b866d-a74d-4808-91d2-6e926e3f456b",
      priority: 10,
      data: { type: "redeem_code", code: String(code.code || "") },
    }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.errors) {
    const reason = String(payload.errors?.[0] || payload.errors || ("OneSignal HTTP " + response.status)).slice(0, 500);
    await supabase.from("redeem_codes").update({ push_error: reason }).eq("id", code.id);
    return { sent: false, reason };
  }
  await supabase.from("redeem_codes").update({ push_sent_at: new Date().toISOString(), push_error: null }).eq("id", code.id);
  return { sent: true, recipients: Number(payload.recipients || 0) };
}

async function validateRedeemTelegramBot(token: string) {
  if (!token || token.length < 30 || token.length > 200) return null;
  const meResponse = await fetch("https://api.telegram.org/bot" + token + "/getMe");
  const me = await meResponse.json().catch(() => ({}));
  if (!meResponse.ok || !me.ok || !me.result?.id) return null;
  const memberResponse = await fetch("https://api.telegram.org/bot" + token + "/getChatMember?chat_id=%40teerofficiall&user_id=" + me.result.id);
  const member = await memberResponse.json().catch(() => ({}));
  if (!memberResponse.ok || !member.ok) return null;
  const status = member.result?.status;
  if (status !== "creator" && !(status === "administrator" && member.result?.can_post_messages !== false)) return null;
  return { id: me.result.id };
}

async function flushRedeemTelegramPosts(token: string) {
  const { data: pending, error } = await supabase.from("redeem_codes")
    .select("id,code,max_redemptions").is("telegram_posted_at", null)
    .eq("active", true).order("created_at", { ascending: true }).limit(10);
  if (error) throw error;
  let sent = 0;
  for (const item of pending || []) {
    const message = [
      "🎁✨ <b>TEER ONLINE — REDEEM REWARD</b> ✨🎁",
      "",
      "🔥 <b>COMMON REDEEM CODE</b>",
      "<code>" + String(item.code) + "</code>",
      "",
      "💰 Reward: <b>₹2 to ₹20</b> — random for each user",
      "👥 Limit: <b>First " + Number(item.max_redemptions) + " users only</b>",
      "🎯 One claim per account • First come, first served",
      "",
      "⚡ Open Teer Online → 3-dot menu → Redeem Code",
      "🌐 https://fresh-lang.github.io/teer-online-/",
      "",
      "⏳ Hurry! Code is limited and may expire.",
      "🚀 <b>TEER ONLINE OFFICIAL</b>",
    ].join("\n");
    const response = await fetch("https://api.telegram.org/bot" + token + "/sendMessage", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: "@teerofficiall", text: message, parse_mode: "HTML", disable_web_page_preview: true }),
    });
    const payload = await response.json().catch(() => ({}));
    if (response.ok && payload.ok) {
      await supabase.from("redeem_codes").update({ telegram_posted_at: new Date().toISOString(), telegram_error: null }).eq("id", item.id);
      sent++;
    } else {
      await supabase.from("redeem_codes").update({ telegram_error: String(payload.description || ("Telegram HTTP " + response.status)).slice(0, 500) }).eq("id", item.id);
    }
  }
  return { sent, checked: (pending || []).length };
}
function escapeTelegramHtml(value: unknown): string {
  return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

async function flushResultTelegramPosts(token: string) {
  const { data: pending, error } = await supabase.from("broadcast_notifications")
    .select("id,title,message,event_key")
    .is("telegram_posted_at", null)
    .not("event_key", "is", null)
    .or("event_key.ilike.*:FR:*,event_key.ilike.*:SR:*")
    .order("created_at", { ascending: true })
    .limit(50);
  if (error) throw error;

  let sent = 0;
  let failed = 0;
  for (const item of pending ?? []) {
    if (!/:(FR|SR):\d{1,2}$/i.test(String(item.event_key ?? ""))) continue;
    const { data: claimed, error: claimError } = await supabase.from("broadcast_notifications")
      .update({ telegram_error: "sending" })
      .eq("id", item.id)
      .is("telegram_posted_at", null)
      .select("id")
      .maybeSingle();
    if (claimError || !claimed) continue;

    const text = [
      "🎯 <b>TEER ONLINE — RESULT UPDATE</b>",
      "",
      "<b>" + escapeTelegramHtml(item.title) + "</b>",
      escapeTelegramHtml(item.message),
      "",
      "📲 <b>Latest APK:</b> <a href=\"https://github.com/fresh-lang/teer-online-/releases/latest/download/teer-online.apk\">Download &amp; Update Teer Online</a>",
      "🌐 <a href=\"https://fresh-lang.github.io/teer-online-/\">Open Teer Online App</a>",
    ].join("\n");
    try {
      const response = await fetch("https://api.telegram.org/bot" + token + "/sendMessage", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: "@teerofficiall", text, parse_mode: "HTML", disable_web_page_preview: true }),
      });
      const payload = await response.json().catch(() => ({}));
      if (response.ok && payload.ok) {
        await supabase.from("broadcast_notifications")
          .update({ telegram_posted_at: new Date().toISOString(), telegram_error: null })
          .eq("id", item.id);
        sent++;
      } else {
        await supabase.from("broadcast_notifications")
          .update({ telegram_error: String(payload.description || ("Telegram HTTP " + response.status)).slice(0, 500) })
          .eq("id", item.id);
        failed++;
      }
    } catch (error) {
      await supabase.from("broadcast_notifications")
        .update({ telegram_error: String(error instanceof Error ? error.message : error).slice(0, 500) })
        .eq("id", item.id);
      failed++;
    }
  }
  return { sent, failed, checked: (pending ?? []).length };
}

async function searchSupportWeb(query: string) {
  const apiKey = Deno.env.get("TAVILY_API_KEY");
  if (!apiKey) return null;
  const response = await fetch("https://api.tavily.com/search", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ api_key: apiKey, query, search_depth: "basic", max_results: 5, include_answer: true }),
  });
  if (!response.ok) throw new Error("Online search is temporarily unavailable.");
  const payload = await response.json();
  return {
    answer: String(payload.answer ?? ""),
    results: (payload.results ?? []).slice(0, 5).map((item: any) => ({
      title: String(item.title ?? "Web result"),
      content: String(item.content ?? "").slice(0, 700),
      url: String(item.url ?? ""),
    })),
  };
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
      const refundPushNotifications = await flushRefundPushNotifications();
      return json({ success: true, marketOffNotifications, sync, khanaparaMorningSync, khanaparaNightSync, shillongMorningSync, shillongNightSync, shillongSync, expiredBetRefunds, notifications, refundPushNotifications }, 200, origin);
    }


    if (action === "redeem_scheduler") {
      const botToken = String(req.headers.get("x-redeem-telegram-token") || "").trim();
      if (!(await validateRedeemTelegramBot(botToken))) return json({ error: "Redeem scheduler authentication failed" }, 403, origin);
      const parts = new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Kolkata", year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(new Date());
      const indiaDate = [parts.find(p => p.type === "year")?.value, parts.find(p => p.type === "month")?.value, parts.find(p => p.type === "day")?.value].join("-");
      const { data: settings } = await supabase.from("redeem_code_settings").select("daily_enabled").eq("id", true).maybeSingle();
      let generated: Record<string, unknown> | null = null;
      if (settings?.daily_enabled) {
        generated = await rpc<Record<string, unknown> | null>("api_generate_daily_redeem_code", {});
        if (generated?.id && !generated.push_sent_at) await sendRedeemCodePush(generated);
      }
      const telegram = await flushRedeemTelegramPosts(botToken);
      return json({ success: true, india_date: indiaDate, generated: generated?.code || null, telegram }, 200, origin);
    }
    if (action === "result_telegram_publisher") {
      const botToken = String(req.headers.get("x-redeem-telegram-token") || "").trim();
      if (!(await validateRedeemTelegramBot(botToken))) return json({ error: "Telegram publisher authentication failed" }, 403, origin);
      const telegram = await flushResultTelegramPosts(botToken);
      return json({ success: true, telegram }, 200, origin);
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
      await supabase.from("app_users").update({ last_login_at: new Date().toISOString() }).eq("id", user.id ?? user.user_id);
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

    if (action === "start_social_follow_bonus_step") {
      const user = await getSession(req);
      if (!user || !user.id) return json({ error: "Please login again" }, 401, origin);
      const platform = String(body.platform ?? "").trim().toLowerCase();
      if (platform !== "telegram" && platform !== "facebook") {
        return json({ error: "A valid social channel is required" }, 400, origin);
      }
      const result = await rpc<Record<string, unknown>>("api_start_social_follow_bonus_step", {
        p_user_id: user.id,
        p_platform: platform,
      });
      return json({ success: true, started_at: result?.started_at ?? null }, 200, origin);
    }

    if (action === "claim_social_follow_bonus") {
      const user = await getSession(req);
      if (!user || !user.id) return json({ error: "Please login again" }, 401, origin);
      const result = await rpc<Record<string, unknown>>("api_claim_social_follow_bonus", {
        p_user_id: user.id,
      });
      if (!result || typeof result !== "object") throw new Error("Bonus claim response was invalid");
      return json({
        success: result.success === true,
        already_claimed: result.already_claimed === true,
        amount: Number(result.amount ?? 0),
        balance: Number(result.balance ?? 0),
      }, 200, origin);
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


    if (action === "redeem_code_claim") {
      const user = await getSession(req);
      if (!user || !user.id) return json({ error: "Please login to redeem a code" }, 401, origin);
      const code = String(body.code ?? "").trim().toUpperCase();
      if (!/^[A-Z0-9-]{6,32}$/.test(code)) return json({ error: "Enter a valid redeem code" }, 400, origin);
      try {
        const result = await rpc("api_claim_redeem_code", { p_user_id: user.id, p_code: code });
        return json({ success: true, result }, 200, origin);
      } catch (error) {
        const message = String(error instanceof Error ? error.message : error);
        return json({ error: message.slice(0, 180) }, 409, origin);
      }
    }
    if (action === "my_notifications" || action === "mark_notifications_read" || action === "clear_my_notifications") {
      const user = await getSession(req);
      if (!user || !user.id) return json({ error: "Please login again" }, 401, origin);
      if (action === "my_notifications") {
        const limit = Math.min(100, Math.max(1, Number.isInteger(Number(body.limit)) ? Number(body.limit) : 50));
        const { data, error } = await supabase.from("user_notifications").select("id,event_key,type,title,message,created_at,read_at")
          .eq("user_id", user.id).order("created_at", { ascending: false }).limit(limit);
        if (error) throw error;
        return json({ success: true, items: data ?? [] }, 200, origin);
      }
      if (action === "mark_notifications_read") {
        const { error } = await supabase.from("user_notifications").update({ read_at: new Date().toISOString() })
          .eq("user_id", user.id).is("read_at", null);
        if (error) throw error;
        return json({ success: true }, 200, origin);
      }
      const { error } = await supabase.from("user_notifications").delete().eq("user_id", user.id);
      if (error) throw error;
      return json({ success: true }, 200, origin);
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

    if (action === "admin_today_bet_summary") {
      const user = await getSession(req);
      if (!user || !user.id) return json({ error: "Please login again" }, 401, origin);
      if (!(await requireAdmin(user))) return json({ error: "Admin access denied" }, 403, origin);
      const indiaDateParts = new Intl.DateTimeFormat("en-GB", {
        timeZone: "Asia/Kolkata", year: "numeric", month: "2-digit", day: "2-digit",
      }).formatToParts(new Date());
      const datePart = (type: string) => indiaDateParts.find((part) => part.type === type)?.value ?? "";
      const indiaDate = datePart("year") + "-" + datePart("month") + "-" + datePart("day");
      const dayStart = new Date(indiaDate + "T00:00:00+05:30").toISOString();
      const nextDate = new Date(new Date(dayStart).getTime() + 86400000).toISOString();
      const totals = new Map<string, { market: string; round: string; number: string; amount: number; bets: number }>();
      let offset = 0;
      const pageSize = 1000;
      while (true) {
        const { data, error } = await supabase.from("bets")
          .select("market,round,bet_number,amount,created_at")
          .gte("created_at", dayStart).lt("created_at", nextDate)
          .order("created_at", { ascending: false })
          .range(offset, offset + pageSize - 1);
        if (error) throw error;
        const rows = data ?? [];
        for (const bet of rows) {
          const market = String(bet.market ?? "Unknown Market");
          const round = String(bet.round ?? "").toUpperCase();
          const number = String(bet.bet_number ?? "").trim();
          const key = market + "\u0000" + round + "\u0000" + number;
          const current = totals.get(key) ?? { market, round, number, amount: 0, bets: 0 };
          current.amount += Number(bet.amount ?? 0);
          current.bets += 1;
          totals.set(key, current);
        }
        offset += rows.length;
        if (rows.length < pageSize) break;
        if (offset >= 50000) throw new Error("Today's bet count exceeds the 50,000-row report limit.");
      }
      const items = Array.from(totals.values()).sort((a, b) =>
        a.market.localeCompare(b.market) || a.round.localeCompare(b.round) ||
        b.amount - a.amount || a.number.localeCompare(b.number)
      );
      return json({
        success: true, date: indiaDate, total_amount: items.reduce((sum, item) => sum + item.amount, 0),
        total_bets: items.reduce((sum, item) => sum + item.bets, 0), items,
      }, 200, origin);
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
      await Promise.all([
        syncKhanaparaSourceIfDue(false),
        syncKhanaparaSessionIfDue("morning"),
        syncKhanaparaSessionIfDue("night"),
        syncShillongMorningIfDue(false),
        syncShillongNightIfDue(false),
        syncShillongSourceIfDue(false),
      ]);

      const indiaParts = new Intl.DateTimeFormat("en-GB", { timeZone: "Asia/Kolkata", day: "2-digit", month: "2-digit", year: "numeric" }).formatToParts(new Date());
      const part = (type: string) => indiaParts.find((item) => item.type === type)?.value ?? "";
      const todayIso = part("year") + "-" + part("month") + "-" + part("day");
      const date = part("day") + "/" + part("month") + "/" + part("year");
      const marketNames = ["Shilong Morning Teer","Khanapara Morning Teer","Shillong Teer (Evening)","Khanapara Teer (Evening)","Shillong Night Teer","Khanapara Night Teer"];
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



    if (action === "admin_redeem_codes" || action === "admin_create_redeem_code" || action === "admin_save_redeem_settings") {
      const admin = await getSession(req);
      if (!admin || !admin.id) return json({ error: "Please login again" }, 401, origin);
      if (!(await requireAdmin(admin))) return json({ error: "Admin access denied" }, 403, origin);
      if (action === "admin_redeem_codes") {
        const [codes, settings] = await Promise.all([
          supabase.from("redeem_codes").select("id,code,max_redemptions,redeemed_count,active,source,india_date,created_at,expires_at,telegram_posted_at,telegram_error,push_sent_at,push_error").order("created_at", { ascending: false }).limit(30),
          supabase.from("redeem_code_settings").select("daily_enabled,daily_limit").eq("id", true).maybeSingle(),
        ]);
        if (codes.error) throw codes.error;
        if (settings.error) throw settings.error;
        return json({ success: true, codes: codes.data || [], settings: settings.data || { daily_enabled: true, daily_limit: 100 } }, 200, origin);
      }
      if (action === "admin_save_redeem_settings") {
        const limit = Number(body.daily_limit);
        if (![100, 500].includes(limit)) return json({ error: "Choose a user limit of 100 or 500" }, 400, origin);
        const settings = await rpc("api_set_redeem_code_settings", { p_daily_enabled: body.daily_enabled !== false, p_daily_limit: limit, p_admin_id: admin.id });
        return json({ success: true, settings }, 200, origin);
      }
      const limit = Number(body.max_redemptions);
      if (![100, 500].includes(limit)) return json({ error: "Choose a user limit of 100 or 500" }, 400, origin);
      const code = await rpc("api_create_redeem_code", { p_limit: limit, p_source: "manual", p_india_date: null, p_admin_id: admin.id });
      const push = await sendRedeemCodePush(code);
      return json({ success: true, code, push }, 200, origin);
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
            included_segments: ["Active Subscriptions"],
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

      if (action === "admin_adjust_wallet") {
        const targetUserId = String(body.user_id ?? "");
        const amount = Number(body.amount);
        const direction = String(body.direction ?? "");
        const description = String(body.description ?? "").slice(0, 180);
        if (!/^[0-9a-f-]{36}$/i.test(targetUserId) || !Number.isFinite(amount) || amount <= 0 ||
            amount > 1000000 || Math.round(amount * 100) !== amount * 100 ||
            !["credit", "debit"].includes(direction)) {
          return json({ error: "Valid user, amount and wallet direction are required" }, 400, origin);
        }
        const result = await rpc<Record<string, unknown>>("admin_adjust_wallet", {
          p_user_id: targetUserId, p_amount: amount, p_direction: direction, p_description: description,
        });
        return json({ success: true, result }, 200, origin);
      }

      if (action === "admin_active_users") {
        const since = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();
        const [loginQ, betQ] = await Promise.all([
          supabase.from("app_users").select("id,uid,name,phone,last_login_at,created_at").gte("last_login_at", since).order("last_login_at", { ascending: false }).limit(500),
          supabase.from("bets").select("user_id,created_at").gte("created_at", since).order("created_at", { ascending: false }).limit(5000),
        ]);
        if (loginQ.error) throw loginQ.error;
        if (betQ.error) throw betQ.error;
        const activity = new Map<string, string>();
        for (const u of loginQ.data ?? []) if (u.last_login_at) activity.set(u.id, u.last_login_at);
        for (const bet of betQ.data ?? []) {
          const prior = activity.get(bet.user_id);
          if (!prior || new Date(bet.created_at).getTime() > new Date(prior).getTime()) activity.set(bet.user_id, bet.created_at);
        }
        const ids = Array.from(activity.keys());
        if (!ids.length) return json({ success: true, since, items: [] }, 200, origin);
        const { data: users, error: usersError } = await supabase.from("app_users")
          .select("id,uid,name,phone,last_login_at,created_at").in("id", ids);
        if (usersError) throw usersError;
        const items = (users ?? []).map((u: any) => ({ ...u, last_activity_at: activity.get(u.id) }))
          .sort((x: any, y: any) => new Date(y.last_activity_at).getTime() - new Date(x.last_activity_at).getTime());
        return json({ success: true, since, total: items.length, items }, 200, origin);
      }

      if (action === "admin_user_activity") {
        const targetUserId = String(body.user_id ?? "");
        if (!/^[0-9a-f-]{36}$/i.test(targetUserId)) return json({ error: "Valid user is required" }, 400, origin);
        const parts = new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Kolkata", year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(new Date());
        const get = (t: string) => parts.find(p => p.type === t)?.value ?? "";
        const today = get("year") + "-" + get("month") + "-" + get("day");
        const start = new Date(today + "T00:00:00+05:30").toISOString();
        const end = new Date(new Date(start).getTime() + 86400000).toISOString();
        const { data, error } = await supabase.from("bets")
          .select("id,market,round,bet_number,amount,status,payout,created_at,settled_at")
          .eq("user_id", targetUserId).gte("created_at", start).lt("created_at", end)
          .order("created_at", { ascending: false }).limit(1000);
        if (error) throw error;
        const rows = data ?? [];
        const totalAmount = rows.reduce((s: number, x: any) => s + Number(x.amount || 0), 0);
        const winAmount = rows.filter((x: any) => x.status === "won").reduce((s: number, x: any) => s + Number(x.payout || 0), 0);
        const lossAmount = rows.filter((x: any) => x.status === "lost").reduce((s: number, x: any) => s + Number(x.amount || 0), 0);
        return json({ success: true, date: today, total_bets: rows.length, total_bet_amount: totalAmount, total_win: winAmount, total_loss: lossAmount, items: rows.slice(0, 100) }, 200, origin);
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

    if (action === "get_payout_profile" || action === "save_payout_profile") {
      const user = await getSession(req);
      if (!user || !user.id) return json({ error: "Please login again" }, 401, origin);

      if (action === "get_payout_profile") {
        const { data, error } = await supabase.from("user_payout_profiles")
          .select("upi_id,bank_holder_name,bank_account_number,bank_ifsc,bank_name")
          .eq("user_id", user.id)
          .maybeSingle();
        if (error) throw error;
        return json({ success: true, profile: data ?? null }, 200, origin);
      }

      const upiId = String(body.upi_id ?? "").trim();
      const holderName = String(body.bank_holder_name ?? "").trim();
      const accountNumber = String(body.bank_account_number ?? "").trim();
      const ifsc = String(body.bank_ifsc ?? "").trim().toUpperCase();
      const bankName = String(body.bank_name ?? "").trim();

      if (upiId && !/^[A-Za-z0-9._-]{2,100}@[A-Za-z0-9.-]{2,64}$/.test(upiId)) {
        return json({ error: "Please enter a valid UPI ID" }, 400, origin);
      }
      const hasAnyBankField = Boolean(holderName || accountNumber || ifsc || bankName);
      if (hasAnyBankField) {
        if (!holderName || holderName.length > 100 ||
            !/^\d{6,20}$/.test(accountNumber) ||
            !/^[A-Z]{4}0[A-Z0-9]{6}$/.test(ifsc) ||
            bankName.length > 100) {
          return json({ error: "Enter account holder name, a valid 6–20 digit account number and valid IFSC. Bank name is optional." }, 400, origin);
        }
      }
      if (upiId.length > 100) return json({ error: "UPI ID is too long" }, 400, origin);

      const { data, error } = await supabase.from("user_payout_profiles").upsert({
        user_id: user.id,
        upi_id: upiId || null,
        bank_holder_name: holderName || null,
        bank_account_number: accountNumber || null,
        bank_ifsc: ifsc || null,
        bank_name: bankName || null,
        updated_at: new Date().toISOString(),
      }, { onConflict: "user_id" })
        .select("upi_id,bank_holder_name,bank_account_number,bank_ifsc,bank_name")
        .single();
      if (error?.code === "23505") {
        return json({
          error: "This Bank/UPI Details Is Already Registered With Another Account.",
        }, 409, origin);
      }
      if (error) throw error;
      return json({ success: true, profile: data }, 200, origin);
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

    if (action === "ai_support_chat") {
      const user = await getSession(req);
      if (!user?.id) return json({ error: "Please log in again" }, 401, origin);
      const message = String(body.message ?? "").trim().slice(0, 1000);
      if (!message) return json({ error: "Please type a message" }, 400, origin);
      const q = message.toLowerCase();
      let reply = "";
      let usageInfo: { used: number; remaining: number; resetsAt: string } | null = null;
      const isAccountHelp = /agent\s*number|my agent|agent details|withdraw|payout|deposit|utr|payment|recharge/.test(q);
      if (!isAccountHelp) {
        const { data: quotaData, error: quotaError } = await supabase.rpc("consume_ai_support_daily_use", { p_user_id: user.id });
        if (quotaError) throw quotaError;
        const quota = Array.isArray(quotaData) ? quotaData[0] : quotaData;
        if (!quota?.allowed) {
          return json({
            success: true,
            limitReached: true,
            reply: "Aapka aaj ka 5/5 free AI search aur information limit poora ho gaya hai. Kal India time 12:00 AM ke baad aapko phir 5 free searches milenge. Abhi help ke liye Agent Chat khol sakte hain.",
            usage: { used: 5, remaining: 0, resetsAt: quota?.resets_at ?? null }
          }, 200, origin);
        }
        usageInfo = { used: Number(quota.used), remaining: Number(quota.remaining), resetsAt: quota.resets_at };
      }
      if (/agent\s*number|my agent|agent details/.test(q)) {
        const { data, error } = await supabase.from("app_users").select("agent_number").eq("id", user.id).maybeSingle();
        if (error) throw error;
        reply = data?.agent_number
          ? "Your assigned Agent WhatsApp number is: " + data.agent_number + ". You can contact this number for personal help."
          : "No agent number is assigned to your account yet. Type “connect me to an agent” to send a private message to our support team.";
      } else if (/withdraw|payout/.test(q)) {
        const { data, error } = await supabase.from("withdrawal_requests").select("amount,status,created_at").eq("user_id", user.id).order("created_at", { ascending: false }).limit(5);
        if (error) throw error;
        reply = "Withdrawal help: the app accepts withdrawal requests from ₹1,000 to ₹5,000. " +
          (data?.length ? "Your latest requests:\n" + data.map((x: any) => "₹" + Number(x.amount).toFixed(2) + " — " + String(x.status) + " (" + new Date(x.created_at).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }) + ")").join("\n") : "I could not find a withdrawal request on your account yet.") +
          "\nFor manual checking, type “connect me to an agent”.";
      } else if (/deposit|utr|payment|recharge/.test(q)) {
        const { data, error } = await supabase.from("deposit_requests").select("amount,status,utr,created_at").eq("user_id", user.id).order("created_at", { ascending: false }).limit(5);
        if (error) throw error;
        reply = "Deposit help: submit the correct UTR/reference number and payment screenshot in Wallet → Deposit. " +
          (data?.length ? "Your latest deposit requests:\n" + data.map((x: any) => "₹" + Number(x.amount).toFixed(2) + " — " + String(x.status) + " (UTR: " + String(x.utr || "not available") + ")").join("\n") : "I could not find a deposit request on your account yet.") +
          "\nIf money was deducted but not credited, type “connect me to an agent” and share your UTR.";
      } else {
        const isTeerTopic = /teer|archery|assam|shillong|khanapara|fr\b|sr\b|first round|second round|guti|hit number|dream number|previous result|result history|common number|frequency|market/.test(q);
        if (!isTeerTopic) {
          reply = "I am Teer Online Support. I can help only with Assam traditional archery Teer: Shillong Teer, Khanapara Teer, FR/SR results, previous-result history, Guti frequency and traditional dream-number chart context. I do not answer unrelated company, business or general web-search questions.";
        } else {
          const knownMarkets = [
            "Shilong Morning Teer",
            "Khanapara Morning Teer",
            "Shillong Teer (Evening)",
            "Khanapara Teer (Evening)",
            "Shillong Night Teer",
            "Khanapara Night Teer",
          ];
          const asksKhanapara = /khanapara/.test(q);
          const asksShillong = /shillong|shilong/.test(q);
          let targetMarkets = knownMarkets.filter((name) => {
            const isKhanapara = name.toLowerCase().startsWith("khanapara");
            const isShillong = name.toLowerCase().startsWith("shillong") || name.toLowerCase().startsWith("shilong");
            return (!asksKhanapara && !asksShillong) || (asksKhanapara && isKhanapara) || (asksShillong && isShillong);
          });
          if (/evening/.test(q)) targetMarkets = targetMarkets.filter((name) => name.includes("(Evening)"));
          else if (/morning/.test(q)) targetMarkets = targetMarkets.filter((name) => /morning/i.test(name));
          else if (/night/.test(q)) targetMarkets = targetMarkets.filter((name) => /night/i.test(name));
          if (/dream/.test(q)) {
            reply = "Dream-number charts are traditional reference charts used by some Assam Teer players; there is no single verified or official dream-to-number mapping. I will not invent a number. Tell me the exact dream symbol (for example, snake, river or bird), and I can explain the chart-style interpretation as an unverified traditional reference—not a prediction.";
          } else {
            const { data, error } = await supabase.from("teer_result_history")
              .select("market,result_date,fr,sr")
              .in("market", targetMarkets)
              .order("result_date", { ascending: false })
              .limit(300);
            if (error) throw error;
            const rows = data ?? [];
            const marketLabel = /khanapara/.test(q) ? "Khanapara" : /shillong|shilong/.test(q) ? "Shillong" : "Assam Teer markets";
            if (!rows.length) {
              reply = "No saved FR/SR history is available for " + marketLabel + " in the selected market data. Check Previous Results in the app or ask for another Assam Teer market.";
            } else if (/1\s*guti|guti|direct analysis|frequency|repeat|common number/.test(q)) {
              const countRound = (key: "fr" | "sr") => {
                const counts: Record<string, number> = {};
                for (const row of rows) {
                  const value = String(row[key] ?? "");
                  if (/^\d{1,2}$/.test(value)) {
                    const normalized = value.padStart(2, "0");
                    counts[normalized] = (counts[normalized] ?? 0) + 1;
                  }
                }
                return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
              };
              const frTop = countRound("fr");
              const srTop = countRound("sr");
              reply = "Historical Assam Teer frequency — " + marketLabel + " (latest " + rows.length + " saved market rows)\n" +
                "FR: " + (frTop.map(([n, count]) => n + " (" + count + ")").join(", ") || "No FR data") + "\n" +
                "SR: " + (srTop.map(([n, count]) => n + " (" + count + ")").join(", ") || "No SR data") +
                "\nThese are counts from saved past results only. They are not live tips and cannot predict or guarantee the next result.";
            } else {
              reply = "Latest saved Assam Teer FR/SR results — " + marketLabel + ":\n" +
                rows.slice(0, 15).map((x: any) =>
                  String(x.market) + " — " + new Date(x.result_date + "T00:00:00").toLocaleDateString("en-IN", { timeZone: "Asia/Kolkata" }) +
                  " | FR " + String(x.fr ?? "—") + " / SR " + String(x.sr ?? "—")
                ).join("\n") +
                "\nFor a specific analysis, ask for Shillong or Khanapara and say Guti frequency or previous results. Saved results are historical records, not a guaranteed prediction.";
            }
            // Search live web context only for Teer topics, after quota validation.
            // Treat all returned snippets as untrusted reference text.
            try {
              const live = await searchSupportWeb("Assam traditional archery Teer " + marketLabel + ": " + message.slice(0, 500));
              if (live && (live.answer || live.results?.length)) {
                const liveParts: string[] = [];
                if (live.answer) liveParts.push("Web search summary: " + live.answer.slice(0, 900));
                const sources = (live.results ?? []).slice(0, 3).map((item: any, index: number) =>
                  (index + 1) + ". " + item.title + ": " + item.content.slice(0, 320) + (item.url ? "\n" + item.url : "")
                );
                if (sources.length) liveParts.push("Web sources (check date and reliability):\n" + sources.join("\n"));
                reply += "\n\nLive web context (not an official result unless confirmed in the app):\n" + liveParts.join("\n\n");
              }
            } catch (searchError) {
              console.warn("Teer support web search unavailable:", searchError);
            }
          }
        }
      }
      return json({ success: true, reply, usage: usageInfo }, 200, origin);
    }

    if (action === "user_support_open") {
      const user = await getSession(req);
      if (!user?.id) return json({ error: "Please log in again" }, 401, origin);
      const category = ["deposit", "withdrawal"].includes(String(body.category)) ? String(body.category) : "general";
      const { data, error } = await supabase.from("support_conversations").insert({
        user_id: user.id, category, subject: category === "general" ? "General support" : category + " help",
        status: "open", last_message: "Support conversation opened", last_message_at: new Date().toISOString(),
      }).select("id,user_id,category,subject,status,created_at").single();
      if (error) throw error;
      return json({ success: true, conversation: data }, 200, origin);
    }

    if (action === "user_support_messages" || action === "user_support_send") {
      const user = await getSession(req);
      if (!user?.id) return json({ error: "Please log in again" }, 401, origin);
      const conversationId = String(body.conversation_id ?? "");
      const { data: conversation, error: conversationError } = await supabase.from("support_conversations")
        .select("id").eq("id", conversationId).eq("user_id", user.id).maybeSingle();
      if (conversationError) throw conversationError;
      if (!conversation) return json({ error: "Support conversation not found" }, 404, origin);
      if (action === "user_support_messages") {
        const { data, error } = await supabase.from("support_messages").select("id,sender_role,message,created_at")
          .eq("conversation_id", conversationId).order("created_at", { ascending: true }).limit(200);
        if (error) throw error;
        return json({ success: true, messages: data ?? [] }, 200, origin);
      }
      const message = String(body.message ?? "").trim().slice(0, 2000);
      if (!message) return json({ error: "Message is required" }, 400, origin);
      const { error } = await supabase.from("support_messages").insert({ conversation_id: conversationId, sender_role: "user", sender_user_id: user.id, message });
      if (error) throw error;
      await supabase.from("support_conversations").update({ status: "open", last_message: message, last_message_at: new Date().toISOString(), updated_at: new Date().toISOString() }).eq("id", conversationId);
      return json({ success: true }, 200, origin);
    }

    if (["admin_support_list", "admin_support_messages", "admin_support_reply", "admin_assign_agent_number"].includes(action)) {
      const admin = await getSession(req);
      if (!admin?.id || !(await requireAdmin(admin))) return json({ error: "Admin access denied" }, 403, origin);
      if (action === "admin_assign_agent_number") {
        const userId = String(body.user_id ?? "");
        const agentNumber = String(body.agent_number ?? "").trim();
        if (!/^\+?[0-9]{10,15}$/.test(agentNumber)) return json({ error: "Enter a valid agent WhatsApp number" }, 400, origin);
        const { error } = await supabase.from("app_users").update({ agent_number: agentNumber }).eq("id", userId);
        if (error) throw error;
        return json({ success: true, agent_number: agentNumber }, 200, origin);
      }
      if (action === "admin_support_list") {
        const { data, error } = await supabase.from("support_conversations").select("id,user_id,category,status,last_message,last_message_at,created_at")
          .order("last_message_at", { ascending: false }).limit(100);
        if (error) throw error;
        const ids = [...new Set((data ?? []).map((x: any) => x.user_id))];
        const { data: users, error: usersError } = ids.length
          ? await supabase.from("app_users").select("id,name,phone").in("id", ids)
          : { data: [], error: null };
        if (usersError) throw usersError;
        const byId = Object.fromEntries((users ?? []).map((x: any) => [x.id, x]));
        return json({ success: true, conversations: (data ?? []).map((x: any) => ({ ...x, app_users: byId[x.user_id] ?? null })) }, 200, origin);
      }
      const conversationId = String(body.conversation_id ?? "");
      const { data: conversation, error: conversationError } = await supabase.from("support_conversations").select("id").eq("id", conversationId).maybeSingle();
      if (conversationError) throw conversationError;
      if (!conversation) return json({ error: "Support conversation not found" }, 404, origin);
      if (action === "admin_support_messages") {
        const { data, error } = await supabase.from("support_messages").select("id,sender_role,message,created_at")
          .eq("conversation_id", conversationId).order("created_at", { ascending: true }).limit(200);
        if (error) throw error;
        return json({ success: true, messages: data ?? [] }, 200, origin);
      }
      const message = String(body.message ?? "").trim().slice(0, 2000);
      if (!message) return json({ error: "Message is required" }, 400, origin);
      const { error } = await supabase.from("support_messages").insert({ conversation_id: conversationId, sender_role: "admin", sender_user_id: admin.id, message });
      if (error) throw error;
      await supabase.from("support_conversations").update({ status: "open", last_message: message, last_message_at: new Date().toISOString(), updated_at: new Date().toISOString() }).eq("id", conversationId);
      return json({ success: true }, 200, origin);
    }

    return json({ error: "Unknown action" }, 400, origin);
  } catch (error) {
    // Avoid returning SQL, hashes, credentials or internal stack details to clients.
    console.error("account-api error:", error);
    return json({ error: "Request could not be completed" }, 400, origin);
  }
});
