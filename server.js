require("dotenv").config();

const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const helmet = require("helmet");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID = "1573653820104515604";
const SITE_URL = "https://dynex-web-sitesi.enzonic.dev";
const REDIRECT_URI = `${SITE_URL}/auth/discord/callback`;

for (const key of ["CLIENT_SECRET", "SESSION_SECRET", "DATABASE_URL"]) {
  if (!process.env[key]) {
    console.error(`Eksik ortam değişkeni: ${key}`);
    process.exit(1);
  }
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  name: "dynex.sid",
  store: new PgSession({
    pool,
    tableName: "dynex_sessions",
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.use(express.static(path.join(__dirname, "public")));

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS dynex_users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      avatar TEXT,
      access_token TEXT,
      refresh_token TEXT,
      token_expires BIGINT,
      language TEXT NOT NULL DEFAULT 'tr',
      theme_color TEXT NOT NULL DEFAULT '#101827',
      premium BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS dynex_guild_settings (
      guild_id TEXT PRIMARY KEY,
      language TEXT NOT NULL DEFAULT 'tr',
      settings JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS dynex_wallets (
      user_id TEXT PRIMARY KEY REFERENCES dynex_users(id) ON DELETE CASCADE,
      balance_dnx BIGINT NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS dynex_ads (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES dynex_users(id),
      description TEXT NOT NULL,
      image_url TEXT NOT NULL,
      invite_url TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      queue_number BIGINT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS dynex_transactions (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES dynex_users(id),
      type TEXT NOT NULL,
      amount_dnx BIGINT NOT NULL,
      description TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  console.log("Dynex veritabanı hazır.");
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Discord hesabınla giriş yapmalısın."
    });
  }
  next();
}

function validLanguage(value) {
  return ["tr", "en"].includes(value);
}

async function discordRequest(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.message || "Discord isteği başarısız.");
  }

  return data;
}

async function getFreshToken(userId) {
  const result = await pool.query(
    `SELECT access_token, refresh_token, token_expires
     FROM dynex_users WHERE id=$1`,
    [userId]
  );

  const user = result.rows[0];
  if (!user) throw new Error("Kullanıcı bulunamadı.");

  if (Number(user.token_expires) > Date.now() + 60000) {
    return user.access_token;
  }

  if (!user.refresh_token) {
    throw new Error("Discord oturumu yenilenemedi. Tekrar giriş yap.");
  }

  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token: user.refresh_token
  });

  const token = await discordRequest(
    "https://discord.com/api/oauth2/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body
    }
  );

  await pool.query(
    `UPDATE dynex_users
     SET access_token=$1, refresh_token=$2, token_expires=$3
     WHERE id=$4`,
    [
      token.access_token,
      token.refresh_token,
      Date.now() + token.expires_in * 1000,
      userId
    ]
  );

  return token.access_token;
}

async function getUserGuilds(userId) {
  const token = await getFreshToken(userId);

  return discordRequest(
    "https://discord.com/api/users/@me/guilds",
    {
      headers: {
        Authorization: `Bearer ${token}`
      }
    }
  );
}

async function canManageGuild(userId, guildId) {
  const guilds = await getUserGuilds(userId);
  const guild = guilds.find(item => item.id === guildId);

  if (!guild) return false;

  const permissions = BigInt(guild.permissions || "0");

  return guild.owner || (permissions & 8n) === 8n;
}

function adminIds() {
  return (process.env.DYNEX_ADMIN_IDS || "")
    .split(",")
    .map(id => id.trim())
    .filter(Boolean);
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save(error => error ? reject(error) : resolve());
  });
}

/* DISCORD GİRİŞİ */

app.get("/auth/discord", (req, res) => {
  const state = crypto.randomBytes(32).toString("hex");
  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "identify guilds",
    state
  });

  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

app.get("/auth/discord/callback", async (req, res) => {
  try {
    if (
      !req.query.code ||
      !req.query.state ||
      req.query.state !== req.session.oauthState
    ) {
      return res.status(400).send("Discord giriş doğrulaması geçersiz.");
    }

    delete req.session.oauthState;

    const body = new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      grant_type: "authorization_code",
      code: req.query.code,
      redirect_uri: REDIRECT_URI
    });

    const token = await discordRequest(
      "https://discord.com/api/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body
      }
    );

    const profile = await discordRequest(
      "https://discord.com/api/users/@me",
      {
        headers: {
          Authorization: `Bearer ${token.access_token}`
        }
      }
    );

    await pool.query(
      `INSERT INTO dynex_users
       (id, username, avatar, access_token, refresh_token, token_expires)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (id) DO UPDATE SET
       username=EXCLUDED.username,
       avatar=EXCLUDED.avatar,
       access_token=EXCLUDED.access_token,
       refresh_token=EXCLUDED.refresh_token,
       token_expires=EXCLUDED.token_expires`,
      [
        profile.id,
        profile.username,
        profile.avatar,
        token.access_token,
        token.refresh_token,
        Date.now() + token.expires_in * 1000
      ]
    );

    await pool.query(
      `INSERT INTO dynex_wallets (user_id)
       VALUES ($1) ON CONFLICT (user_id) DO NOTHING`,
      [profile.id]
    );

    await new Promise((resolve, reject) => {
      req.session.regenerate(error => error ? reject(error) : resolve());
    });

    req.session.userId = profile.id;
    await saveSession(req);

    res.redirect("/");
  } catch (error) {
    console.error("Discord giriş hatası:", error);
    res.status(500).send("Giriş yapılamadı. Daha sonra tekrar dene.");
  }
});

/* HESAP */

app.get("/api/me", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.username, u.avatar, u.language,
              u.theme_color, u.premium,
              COALESCE(w.balance_dnx, 0) AS balance_dnx
       FROM dynex_users u
       LEFT JOIN dynex_wallets w ON w.user_id=u.id
       WHERE u.id=$1`,
      [req.session.userId]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "Hesap bulunamadı." });
    }

    res.json({
      ...result.rows[0],
      isAdmin: adminIds().includes(req.session.userId)
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Hesap bilgileri alınamadı."
    });
  }
});

/* SUNUCULAR */

app.get("/api/guilds", requireLogin, async (req, res) => {
  try {
    const guilds = await getUserGuilds(req.session.userId);

    const allowed = guilds.filter(guild => {
      const permissions = BigInt(guild.permissions || "0");
      return guild.owner || (permissions & 8n) === 8n;
    });

    let botGuildIds = new Set();

    if (process.env.BOT_TOKEN) {
      const checks = await Promise.all(
        allowed.map(async guild => {
          try {
            await discordRequest(
              `https://discord.com/api/guilds/${guild.id}`,
              {
                headers: {
                  Authorization: `Bot ${process.env.BOT_TOKEN}`
                }
              }
            );
            return guild.id;
          } catch {
            return null;
          }
        })
      );

      botGuildIds = new Set(checks.filter(Boolean));
    }

    res.json(allowed.map(guild => ({
      id: guild.id,
      name: guild.name,
      icon: guild.icon,
      botPresent: botGuildIds.has(guild.id)
    })));
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Sunucular alınamadı."
    });
  }
});

app.get("/api/guild/:id", requireLogin, async (req, res) => {
  try {
    if (!(await canManageGuild(req.session.userId, req.params.id))) {
      return res.status(403).json({
        error: "Bu sunucuyu yönetme yetkin yok."
      });
    }

    const result = await pool.query(
      "SELECT * FROM dynex_guild_settings WHERE guild_id=$1",
      [req.params.id]
    );

    res.json(result.rows[0] || {
      guild_id: req.params.id,
      language: "tr",
      settings: {}
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Sunucu ayarları alınamadı."
    });
  }
});

app.put("/api/guild/:id", requireLogin, async (req, res) => {
  try {
    if (!(await canManageGuild(req.session.userId, req.params.id))) {
      return res.status(403).json({
        error: "Yetkin bulunmuyor."
      });
    }

    const { section, values } = req.body;

    const allowed = [
      "general", "tickets", "moderation", "welcome",
      "logs", "automod", "autoroles", "autoreplies",
      "embeds", "permissions"
    ];

    if (
      !allowed.includes(section) ||
      !values ||
      typeof values !== "object" ||
      Array.isArray(values)
    ) {
      return res.status(400).json({
        error: "Geçersiz ayar."
      });
    }

    const current = await pool.query(
      "SELECT settings FROM dynex_guild_settings WHERE guild_id=$1",
      [req.params.id]
    );

    const settings = current.rows[0]?.settings || {};
    settings[section] = values;

    const language =
      section === "general" && validLanguage(values.language)
        ? values.language
        : null;

    await pool.query(
      `INSERT INTO dynex_guild_settings (guild_id, language, settings)
       VALUES ($1, COALESCE($2, 'tr'), $3)
       ON CONFLICT (guild_id) DO UPDATE SET
       language=COALESCE($2, dynex_guild_settings.language),
       settings=EXCLUDED.settings,
       updated_at=NOW()`,
      [req.params.id, language, JSON.stringify(settings)]
    );

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Ayarlar kaydedilemedi."
    });
  }
});

/* HESAP AYARLARI */

app.put("/api/account", requireLogin, async (req, res) => {
  const { language, themeColor } = req.body;

  if (language && !validLanguage(language)) {
    return res.status(400).json({ error: "Dil geçersiz." });
  }

  if (themeColor && !/^#[0-9a-fA-F]{6}$/.test(themeColor)) {
    return res.status(400).json({ error: "Renk geçersiz." });
  }

  try {
    await pool.query(
      `UPDATE dynex_users
       SET language=COALESCE($1, language),
           theme_color=COALESCE($2, theme_color)
       WHERE id=$3`,
      [language || null, themeColor || null, req.session.userId]
    );

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Ayarlar kaydedilemedi."
    });
  }
});

/* İŞLEMLER */

app.get("/api/transactions", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, type, amount_dnx, description, created_at
       FROM dynex_transactions
       WHERE user_id=$1
       ORDER BY created_at DESC LIMIT 100`,
      [req.session.userId]
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({
      error: "İşlemler alınamadı."
    });
  }
});

/* REKLAMLAR */

app.get("/api/ads", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, description, status, queue_number, created_at
       FROM dynex_ads
       WHERE user_id=$1
       ORDER BY created_at DESC`,
      [req.session.userId]
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({
      error: "Reklamlar alınamadı."
    });
  }
});

app.post("/api/ads", requireLogin, async (req, res) => {
  return res.status(503).json({
    error: "Reklam satın alma ve ödeme sistemi henüz etkinleştirilmedi."
  });
});

/* PREMIUM */

app.post("/api/premium/purchase", requireLogin, async (req, res) => {
  return res.status(503).json({
    error: "Premium ödeme sistemi henüz etkinleştirilmedi."
  });
});

app.post("/api/premium/cancel", requireLogin, async (req, res) => {
  return res.status(503).json({
    error: "Premium iptal sistemi henüz etkinleştirilmedi."
  });
});

/* ÇIKIŞ */

app.post("/auth/logout", requireLogin, (req, res) => {
  req.session.destroy(error => {
    if (error) {
      return res.status(500).json({
        error: "Çıkış yapılamadı."
      });
    }

    res.clearCookie("dynex.sid");
    res.json({ success: true });
  });
});

/* SAYFA */

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Dynex ${PORT} portunda çalışıyor.`);
    });
  })
  .catch(error => {
    console.error("Veritabanı başlatılamadı:", error);
    process.exit(1);
  });
