
const enc = new TextEncoder();
const ITER = 100000;
const DAY = 86400;

const AI_MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";

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
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > 1000000) return false;
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: unb64(parts[2]), iterations },
    key,
    256
  ));
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
  const h = new Headers({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  if (cookie) h.append("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers: h });
}

function sessionCookie(token, maxAge) {
  return `nbsk_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function readCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

function readToken(request) { return readCookie(request, "nbsk_session"); }

function guestCookie(token, maxAge = 60 * 60 * 24 * 365) {
  return `nbsk_guest=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

async function getGuest(request, env) {
  let token = readCookie(request, "nbsk_guest");
  let fresh = false;
  if (!token || !/^[a-f0-9-]{36}$/i.test(token)) {
    token = crypto.randomUUID();
    fresh = true;
  }
  const hash = await sha256Hex(token);
  const row = await env.DB.prepare(
    "SELECT requests FROM guest_usage WHERE guest_hash = ?"
  ).bind(hash).first();
  return {
    hash,
    remaining: Math.max(0, 10 - Number(row?.requests || 0)),
    cookie: fresh ? guestCookie(token) : null
  };
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

async function sendPasswordResetEmail(env, email, token) {
  if (!env.RESEND_API_KEY || !env.MAIL_FROM || !env.APP_URL) {
    throw new Error("Не настроена отправка писем: нужны RESEND_API_KEY, MAIL_FROM и APP_URL");
  }

  const resetUrl = `${String(env.APP_URL).replace(/\/$/, "")}/?reset=${encodeURIComponent(token)}`;

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: env.MAIL_FROM,
      to: [email],
      subject: "Восстановление пароля NBSK AI",
      html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#222"><h2>Восстановление пароля NBSK AI</h2><p>Вы запросили смену пароля. Нажмите кнопку ниже, чтобы задать новый пароль.</p><p><a href="${resetUrl}" style="display:inline-block;padding:12px 20px;background:#17181c;color:#fff;text-decoration:none;border-radius:8px">Создать новый пароль</a></p><p>Ссылка действует 60 минут. Если вы не запрашивали восстановление, просто проигнорируйте это письмо.</p></div>`
    })
  });

  if (!response.ok) {
    const details = await response.text();
    console.error("RESEND error:", response.status, details.slice(0, 500));
    throw new Error("Почтовый сервис не отправил письмо");
  }
}

async function readBody(request) {
  try {
    const b = await request.json();
    return {
      email: String(b.email || "").trim().toLowerCase(),
      password: String(b.password || ""),
    };
  } catch {
    return null;
  }
}

function extractText(out) {
  if (typeof out === "string") return out.trim();
  if (!out || typeof out !== "object") return "";

  const candidates = [
    out.response,
    out.output_text,
    out.content,
    out.result?.response,
    out.result?.output_text,
    out.result?.content,
    out.choices?.[0]?.message?.content,
    out.choices?.[0]?.text,
  ];

  for (const value of candidates) {
    if (typeof value === "string" && value.trim()) return value.trim();

    if (Array.isArray(value)) {
      const joined = value
        .map((item) => typeof item === "string" ? item : item?.text || "")
        .join("")
        .trim();
      if (joined) return joined;
    }
  }

  return "";
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (!path.startsWith("/api/")) return env.ASSETS.fetch(request);

    if (path === "/api/health") return reply({ ok: true, service: "NBSK AI" });

    if (path === "/api/guest-status" && request.method === "GET") {
      try {
        const user = await currentUser(request, env);
        if (user) return reply({ authenticated: true, remaining: 10 });
        const guest = await getGuest(request, env);
        return reply({ authenticated: false, remaining: guest.remaining, limit: 10 }, 200, guest.cookie);
      } catch (e) {
        console.error("GUEST STATUS error:", e?.message || e);
        return reply({ error: "Не удалось проверить гостевой лимит" }, 500);
      }
    }

    if (path === "/api/me" && request.method === "GET") {
      try {
        const user = await currentUser(request, env);
        return reply({ user: user || null });
      } catch (e) {
        console.error("ME error:", e?.message || e);
        return reply({ error: "Ошибка проверки аккаунта" }, 500);
      }
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
        console.error("REGISTER error:", e?.message || e);
        return reply({ error: "Эта почта уже зарегистрирована или регистрация временно недоступна" }, 409);
      }

      try {
        const cookie = await startSession(env, id);
        return reply({ user: { id, email: b.email, plan: "free" } }, 201, cookie);
      } catch (e) {
        console.error("SESSION error:", e?.message || e);
        return reply({ error: "Аккаунт создан, но не удалось начать сессию" }, 500);
      }
    }

    if (path === "/api/login" && request.method === "POST") {
      const b = await readBody(request);
      if (!b) return reply({ error: "Некорректный запрос" }, 400);
      if (!b.email || !b.password) return reply({ error: "Введите почту и пароль" }, 400);

      try {
        const user = await env.DB.prepare(
          "SELECT id, email, plan, password_hash FROM users WHERE email = ?"
        ).bind(b.email).first();

        if (!user || !(await checkPassword(b.password, user.password_hash))) {
          return reply({ error: "Неверная почта или пароль" }, 401);
        }

        const cookie = await startSession(env, user.id);
        return reply({ user: { id: user.id, email: user.email, plan: user.plan } }, 200, cookie);
      } catch (e) {
        console.error("LOGIN error:", e?.message || e);
        return reply({ error: "Ошибка входа. Проверьте настройки базы данных" }, 500);
      }
    }

    if (path === "/api/forgot-password" && request.method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return reply({ error: "Некорректный запрос" }, 400);
      }

      const email = String(body.email || "").trim().toLowerCase();
      if (!EMAIL_RE.test(email) || email.length > 254) {
        return reply({ error: "Введите корректную почту" }, 400);
      }

      try {
        const user = await env.DB.prepare(
          "SELECT id, email FROM users WHERE email = ?"
        ).bind(email).first();

        // Одинаковый ответ для существующих и неизвестных адресов.
        if (user) {
          const token = [...crypto.getRandomValues(new Uint8Array(32))]
            .map(x => x.toString(16).padStart(2, "0")).join("");
          const tokenHash = await sha256Hex(token);
          const now = Math.floor(Date.now() / 1000);

          await env.DB.prepare(
            "DELETE FROM password_resets WHERE user_id = ? OR expires_at < ?"
          ).bind(user.id, now).run();

          await env.DB.prepare(
            "INSERT INTO password_resets (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)"
          ).bind(tokenHash, user.id, now + 3600, now).run();

          try {
            await sendPasswordResetEmail(env, user.email, token);
          } catch (e) {
            await env.DB.prepare(
              "DELETE FROM password_resets WHERE token_hash = ?"
            ).bind(tokenHash).run();

            console.error("FORGOT EMAIL error:", e?.message || e);
            return reply({ error: "Не удалось отправить письмо. Проверьте настройки почтового сервиса." }, 503);
          }
        }

        return reply({
          ok: true,
          message: "Если аккаунт с такой почтой существует, письмо для восстановления уже отправлено."
        });
      } catch (e) {
        console.error("FORGOT error:", e?.message || e);
        return reply({ error: "Не удалось обработать запрос. Попробуйте позже." }, 500);
      }
    }

    if (path === "/api/reset-password" && request.method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return reply({ error: "Некорректный запрос" }, 400);
      }

      const token = String(body.token || "");
      const password = String(body.password || "");

      if (!/^[a-f0-9]{64}$/i.test(token)) {
        return reply({ error: "Ссылка восстановления недействительна или устарела" }, 400);
      }
      if (password.length < 8 || password.length > 200) {
        return reply({ error: "Пароль должен содержать от 8 до 200 символов" }, 400);
      }

      try {
        const tokenHash = await sha256Hex(token);
        const now = Math.floor(Date.now() / 1000);

        const reset = await env.DB.prepare(
          "SELECT user_id FROM password_resets WHERE token_hash = ? AND expires_at > ?"
        ).bind(tokenHash, now).first();

        if (!reset) {
          return reply({ error: "Ссылка восстановления недействительна или устарела" }, 400);
        }

        await env.DB.prepare(
          "UPDATE users SET password_hash = ? WHERE id = ?"
        ).bind(await makeHash(password), reset.user_id).run();

        await env.DB.prepare(
          "DELETE FROM password_resets WHERE user_id = ?"
        ).bind(reset.user_id).run();

        await env.DB.prepare(
          "DELETE FROM sessions WHERE user_id = ?"
        ).bind(reset.user_id).run();

        return reply({
          ok: true,
          message: "Пароль успешно изменён. Теперь войдите с новым паролем."
        }, 200, sessionCookie("", 0));
      } catch (e) {
        console.error("RESET PASSWORD error:", e?.message || e);
        return reply({ error: "Не удалось изменить пароль. Попробуйте ещё раз." }, 500);
      }
    }

    if (path === "/api/logout" && request.method === "POST") {
      try {
        const token = readToken(request);
        if (token) {
          await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?")
            .bind(await sha256Hex(token)).run();
        }
        return reply({ ok: true }, 200, sessionCookie("", 0));
      } catch (e) {
        console.error("LOGOUT error:", e?.message || e);
        return reply({ error: "Не удалось завершить сессию" }, 500);
      }
    }

    if (path === "/api/chat" && request.method === "POST") {
      try {
        const user = await currentUser(request, env);
        let guest = null;

        if (!user) {
          guest = await getGuest(request, env);
          if (guest.remaining <= 0) {
            return reply({
              error: "Бесплатные 10 запросов закончились. Войдите или зарегистрируйтесь, чтобы продолжить.",
              requireAuth: true,
              remaining: 0
            }, 429, guest.cookie);
          }
        }

        if (!env.AI) return reply({ error: "Привязка AI не подключена к Worker" }, 500, guest?.cookie);

        let body;
        try {
          body = await request.json();
        } catch {
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

        if (guest) {
          const used = await env.DB.prepare(
            "INSERT INTO guest_usage (guest_hash, requests, updated_at) VALUES (?, 1, ?) ON CONFLICT(guest_hash) DO UPDATE SET requests = requests + 1, updated_at = excluded.updated_at WHERE requests < 10 RETURNING requests"
          ).bind(guest.hash, Math.floor(Date.now() / 1000)).first();

          if (!used) {
            return reply({
              error: "Бесплатные 10 запросов закончились. Войдите или зарегистрируйтесь, чтобы продолжить.",
              requireAuth: true,
              remaining: 0
            }, 429, guest.cookie);
          }

          guest.remaining = Math.max(0, 10 - Number(used.requests));
        }

        const out = await env.AI.run(AI_MODEL, {
          messages: [{ role: "system", content: SYSTEM_PROMPT }, ...messages],
          max_tokens: 1024,
        });

        const text = extractText(out);

        console.log("AI result structure:", JSON.stringify({
          model: AI_MODEL,
          resultType: typeof out,
          keys: out && typeof out === "object" ? Object.keys(out) : [],
          responseType: typeof out?.response,
          resultKeys: out?.result && typeof out.result === "object" ? Object.keys(out.result) : [],
          choicesType: typeof out?.choices,
        }));

        if (!text) {
          console.error("AI returned no extractable text");
          return reply({
            error: "Модель вернула ответ в неизвестном формате. Проверьте Cloudflare Logs.",
          }, 502);
        }

        return reply({
          reply: text,
          model: AI_MODEL,
          ...(guest ? { remaining: guest.remaining, guest: true } : {})
        }, 200, guest?.cookie);
      } catch (e) {
        const message = String(e?.message || e).slice(0, 500);
        console.error("CHAT error:", message);
        return reply({ error: "Ошибка ИИ: " + message }, 502);
      }
    }

    return reply({ error: "Not found" }, 404);
  },
};
