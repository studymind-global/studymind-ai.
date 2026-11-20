const enc = new TextEncoder();
const ITER = 100000;
const DAY = 86400;

const AI_MODEL = "@cf/zai-org/glm-4.7-flash";
const SYSTEM_PROMPT =
  "Ты — NBSK AI, дружелюбный образовательный помощник. Помогаешь с учёбой: объясняешь темы просто, решаешь задачи пошагово. Отвечай на языке пользователя.";

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (buf) => b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: ITER }, key, 256);
}

async function makeHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await hashPassword(password, salt);
  return `pbkdf2$${ITER}$${b64(salt)}$${b64(bits)}`;
}

async function checkPassword(password, stored) {
  const parts = stored.split("$");
  if (parts.length !== 4) return false;
  const bits = new Uint8Array(await hashPassword(password, unb64(parts[2])));
  const want = unb64(parts[3]);
  if (bits.length !== want.length) return false;
  let diff = 0;
  for (let i = 0; i < bits.length; i++) diff |= bits[i] ^ want[i];
  return diff === 0;
}

async function sha256Hex(text) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function reply(data, status = 200, cookie) {
  const h = new Headers({ "Content-Type": "application/json", "Cache-Control": "no-store" });
  if (cookie) h.append("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers: h });
}

function sessionCookie(token, maxAge) {
  return `nbsk_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function readToken(request) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === "nbsk_session") return v.join("=");
  }
  return null;
}

async function currentUser(request, env) {
  const token = readToken(request);
  if (!token) return null;
  const th = await sha256Hex(token);
  const now = Math.floor(Date.now() / 1000);
  return await env.DB.prepare(
    "SELECT u.id, u.email, u.plan FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?"
  ).bind(th, now).first();
}

async function startSession(env, userId) {
  const token = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)"
  ).bind(await sha256Hex(token), userId, now + 30 * DAY, now).run();
  return sessionCookie(token, 30 * DAY);
}

async function readBody(request) {
  try {
    const b = await request.json();
    return {
      email: String(b.email || "").trim().toLowerCase(),
      password: String(b.password || ""),
    };
  } catch (e) {
    return null;
  }
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (!path.startsWith("/api/")) return env.ASSETS.fetch(request);

    if (path === "/api/health") return reply({ ok: true, service: "NBSK AI" });

    if (path === "/api/me" && request.method === "GET") {
      const user = await currentUser(request, env);
      return reply({ user: user || null });
    }

    if (path === "/api/register" && request.method === "POST") {
      const b = await readBody(request);
      if (!b) return reply({ error: "Некорректный запрос" }, 400);
      if (!EMAIL_RE.test(b.email) || b.email.length > 254) return reply({ error: "Введите настоящую почту" }, 400);
      if (b.password.length < 8 || b.password.length > 200) return reply({ error: "Пароль: от 8 до 200 символов" }, 400);
      const id = crypto.randomUUID();
      try {
        await env.DB.prepare(
          "INSERT INTO users (id, email, password_hash, plan, created_at) VALUES (?, ?, ?, 'free', ?)"
        ).bind(id, b.email, await makeHash(b.password), Math.floor(Date.now() / 1000)).run();
      } catch (e) {
        return reply({ error: "Эта почта уже зарегистрирована" }, 409);
      }
      const cookie = await startSession(env, id);
      return reply({ user: { id, email: b.email, plan: "free" } }, 201, cookie);
    }

    if (path === "/api/login" && request.method === "POST") {
      const b = await readBody(request);
      if (!b) return reply({ error: "Некорректный запрос" }, 400);
      const user = await env.DB.prepare("SELECT id, email, plan, password_hash FROM users WHERE email = ?").bind(b.email).first();
      if (!user) {
        await makeHash(b.password);
        return reply({ error: "Неверная почта или пароль" }, 401);
      }
      if (!(await checkPassword(b.password, user.password_hash))) {
        return reply({ error: "Неверная почта или пароль" }, 401);
      }
      const cookie = await startSession(env, user.id);
      return reply({ user: { id: user.id, email: user.email, plan: user.plan } }, 200, cookie);
    }

    if (path === "/api/logout" && request.method === "POST") {
      const token = readToken(request);
      if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256Hex(token)).run();
      return reply({ ok: true }, 200, sessionCookie("", 0));
    }

    if (path === "/api/chat" && request.method === "POST") {
      const user = await currentUser(request, env);
      if (!user) return reply({ error: "Войдите в аккаунт" }, 401);
      if (!env.AI) return reply({ error: "Привязка AI не подключена к Worker" }, 500);

      let body;
      try {
        body = await request.json();
      } catch (e) {
        return reply({ error: "Некорректный запрос" }, 400);
      }

      const raw = Array.isArray(body.messages) ? body.messages : [];
      const messages = raw
        .slice(-20)
        .filter((m) => m && (m.role === "user" || m.role === "assistant") && typeof m.content === "string")
        .map((m) => ({ role: m.role, content: m.content.slice(0, 4000) }));

      if (!messages.length || messages[messages.length - 1].role !== "user") {
        return reply({ error: "Нужно хотя бы одно сообщение пользователя" }, 400);
      }

      try {
        const out = await env.AI.run(AI_MODEL, {
          messages: [{ role: "system", content: SYSTEM_PROMPT }, ...messages],
          max_tokens: 1024,
        });
        return reply({ reply: out.response || "" });
      } catch (e) {
        console.error("AI error:", e && e.message);
        return reply({ error: "ИИ временно недоступен. Попробуйте позже." }, 502);
      }
    }

    return reply({ error: "Not found" }, 404);
  },
};
