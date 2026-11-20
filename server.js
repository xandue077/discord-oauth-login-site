import http from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "public");
const PORT = Number(process.env.PORT ?? 3000);
const HOST = process.env.HOST ?? "0.0.0.0";
const API = "https://discord.com/api/v10";
const CLIENT_ID = process.env.DISCORD_CLIENT_ID ?? "";
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET ?? "";
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI ?? "";
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN ?? "";
const GUILD_ID = process.env.DISCORD_GUILD_ID ?? "";
const STATE_TTL_MS = 10 * 60 * 1000;

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
};

function send(res, status, body, headers = {}) {
  res.writeHead(status, { "X-Content-Type-Options": "nosniff", ...headers });
  res.end(res.req?.method === "HEAD" ? undefined : body);
}

function html(res, status, body) {
  send(res, status, body, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
}

function redirect(res, location, headers = {}) {
  send(res, 302, "", { Location: location, "Cache-Control": "no-store", ...headers });
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[char]);
}

function parseCookies(req) {
  const result = {};
  for (const part of String(req.headers.cookie ?? "").split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key) result[key] = decodeURIComponent(value);
  }
  return result;
}

function secureCookie(req) {
  return req.headers["x-forwarded-proto"] === "https" || process.env.DISCORD_SECURE_COOKIES === "1";
}

function cookieFlags(req) {
  return `Path=/; HttpOnly; SameSite=Lax${secureCookie(req) ? "; Secure" : ""}`;
}

function setCookie(res, req, name, value, maxAge = 0) {
  const age = maxAge ? `; Max-Age=${maxAge}` : "";
  res.setHeader("Set-Cookie", `${name}=${encodeURIComponent(value)}; ${cookieFlags(req)}${age}`);
}

function clearCookie(res, req, name) {
  setCookie(res, req, name, "", -1);
}

function missingConfig() {
  return [
    ["DISCORD_CLIENT_ID", CLIENT_ID],
    ["DISCORD_CLIENT_SECRET", CLIENT_SECRET],
    ["DISCORD_REDIRECT_URI", REDIRECT_URI],
    ["DISCORD_BOT_TOKEN", BOT_TOKEN],
  ].filter(([, value]) => !value).map(([key]) => key);
}

function signPayload(payload) {
  return createHmac("sha256", CLIENT_SECRET).update(payload).digest("base64url");
}

function makeState(invite) {
  const payload = Buffer.from(JSON.stringify({
    invite: invite || "",
    nonce: randomBytes(16).toString("hex"),
    exp: Date.now() + STATE_TTL_MS,
  })).toString("base64url");
  return `${payload}.${signPayload(payload)}`;
}

function readState(state) {
  const [payload, signature] = String(state ?? "").split(".");
  if (!payload || !signature) return null;
  const expected = signPayload(payload);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!data.exp || data.exp < Date.now()) return null;
    return data;
  } catch {
    return null;
  }
}

async function apiFetch(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  return { ok: response.ok, status: response.status, data };
}

function discordError(result) {
  const message = result?.data?.message || result?.data?.error || `Discord HTTP ${result?.status ?? 500}`;
  const code = result?.data?.code ? ` (code ${result.data.code})` : "";
  return `${message}${code}`;
}

function authorizeUrl(state) {
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "identify guilds.join",
    state,
    prompt: "consent",
  });
  return `https://discord.com/oauth2/authorize?${params.toString()}`;
}

async function serveStatic(res, pathname) {
  let filePath = path.resolve(ROOT, `.${pathname}`);
  if (filePath !== ROOT && !filePath.startsWith(`${ROOT}${path.sep}`)) {
    return html(res, 400, "<h1>Bad Request</h1>");
  }
  try {
    const info = await import("node:fs/promises").then((fs) => fs.stat(filePath));
    if (info.isDirectory()) filePath = path.join(filePath, "index.html");
    const data = await readFile(filePath);
    const ext = path.extname(filePath).toLowerCase();
    send(res, 200, data, {
      "Content-Type": MIME_TYPES[ext] ?? "application/octet-stream",
      "Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=300",
    });
  } catch {
    const data = await readFile(path.join(ROOT, "index.html"));
    send(res, 200, data, { "Content-Type": MIME_TYPES[".html"], "Cache-Control": "no-cache" });
  }
}

function handleLogin(req, res, url) {
  const missing = missingConfig();
  if (missing.length) {
    return html(res, 500, `<h1>Missing setup</h1><p>Set these environment variables: ${missing.map(escapeHtml).join(", ")}</p>`);
  }

  const invite = String(url.searchParams.get("invite") ?? "").trim();
  if (invite && !/^[A-Za-z0-9_-]{1,32}$/.test(invite)) {
    return redirect(res, "/?error=invalid-invite");
  }

  const state = makeState(invite);
  setCookie(res, req, "discord_oauth_state", state, 600);
  return redirect(res, authorizeUrl(state));
}

async function handleCallback(req, res, url) {
  const cookies = parseCookies(req);
  const state = String(url.searchParams.get("state") ?? "");
  const expectedState = cookies.discord_oauth_state ?? "";
  clearCookie(res, req, "discord_oauth_state");

  const stateData = readState(state);
  if (!stateData || state !== expectedState) {
    return redirect(res, "/?error=invalid-state");
  }

  const oauthError = url.searchParams.get("error");
  if (oauthError) {
    return redirect(res, `/?error=${encodeURIComponent(oauthError)}`);
  }

  const code = String(url.searchParams.get("code") ?? "");
  if (!code) {
    return redirect(res, "/?error=missing-code");
  }

  try {
    const tokenResult = await apiFetch(`${API}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
      }).toString(),
    });
    if (!tokenResult.ok) throw new Error(discordError(tokenResult));

    const userResult = await apiFetch(`${API}/users/@me`, {
      headers: { Authorization: `Bearer ${tokenResult.data.access_token}` },
    });
    if (!userResult.ok) throw new Error(discordError(userResult));

    let guildId = GUILD_ID;
    if (!guildId) {
      if (!stateData.invite) throw new Error("No invite code and DISCORD_GUILD_ID is not set");
      const inviteResult = await apiFetch(`${API}/invites/${encodeURIComponent(stateData.invite)}`, {
        headers: { Authorization: `Bot ${BOT_TOKEN}` },
      });
      if (!inviteResult.ok) throw new Error(discordError(inviteResult));
      guildId = inviteResult.data?.guild?.id;
      if (!guildId) throw new Error("Invite did not return a guild id");
    }

    const joinResult = await apiFetch(`${API}/guilds/${encodeURIComponent(guildId)}/members/${encodeURIComponent(userResult.data.id)}`, {
      method: "PUT",
      headers: {
        Authorization: `Bot ${BOT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ access_token: tokenResult.data.access_token }),
    });
    if (!joinResult.ok) throw new Error(discordError(joinResult));

    const username = `${userResult.data.username}#${String(userResult.data.discriminator ?? "0").padStart(4, "0")}`;
    const query = new URLSearchParams({
      ok: "1",
      user: username,
      guild: guildId,
      name: userResult.data.global_name ?? userResult.data.username,
    });
    return redirect(res, `/?${query.toString()}`);
  } catch (error) {
    return redirect(res, `/?error=${encodeURIComponent(error.message || "Join failed")}`);
  }
}

async function handler(req, res) {
  const method = req.method ?? "GET";
  const url = new URL(req.url ?? "/", "http://localhost");

  if (url.pathname === "/health" || url.pathname === "/api/health") {
    return send(res, 200, JSON.stringify({ ok: true, service: "discord-oauth-login-site" }), {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    });
  }

  if (method !== "GET" && method !== "HEAD") {
    return send(res, 405, "Method Not Allowed", { "Content-Type": "text/plain; charset=utf-8", Allow: "GET, HEAD" });
  }

  if (url.pathname === "/login") return handleLogin(req, res, url);
  if (url.pathname === "/callback") return handleCallback(req, res, url);
  return serveStatic(res, url.pathname);
}

if (!process.env.VERCEL) {
  http
    .createServer((req, res) => {
      handler(req, res).catch((error) => {
        send(res, 500, "Internal Server Error", { "Content-Type": "text/plain; charset=utf-8" });
        console.error(error);
      });
    })
    .listen(PORT, HOST, () => {
      console.log(`discord-oauth-login-site listening on http://${HOST}:${PORT}`);
    });
}

export default handler;
export { handler };
