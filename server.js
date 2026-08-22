import "dotenv/config";
import express from "express";
import path from "path";
import fs from "fs";
import pg from "pg";
const { Pool } = pg;
import crypto from "crypto";

const app = express(); 

const distPath = path.join(process.cwd(), "dist");
if (fs.existsSync(distPath)) {
  app.use(express.static(distPath));
}

app.use(express.json());

app.use(
  express.urlencoded({
    extended: true
  })
);


// =====================================================
// CORS
// =====================================================

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  } else {
    res.setHeader("Access-Control-Allow-Origin", "*");
  }

  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,Authorization,x-user-id,x-user-email,x-app-user-email,X-User-Id,X-User-Email,Accept,Origin"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});


// =====================================================
// ENVIRONMENT VARIABLES
// =====================================================

const VERIFY_TOKEN =
  process.env.VERIFY_TOKEN;

const INSTAGRAM_APP_ID =
  process.env.INSTAGRAM_APP_ID;

const INSTAGRAM_APP_SECRET =
  process.env.INSTAGRAM_APP_SECRET;

const INSTAGRAM_REDIRECT_URI =
  process.env.INSTAGRAM_REDIRECT_URI ||
  "https://genius-instagram-webhook.onrender.com/auth/instagram/callback";

const DATABASE_URL =
  process.env.DATABASE_URL;

const AUTOMATION_ENABLED =
  process.env.AUTOMATION_ENABLED !== "false";

const DASHBOARD_API_KEY =
  process.env.DASHBOARD_API_KEY || "";

const SUPABASE_URL =
  process.env.SUPABASE_URL;

const SUPABASE_API_KEY =
  process.env.SUPABASE_PUBLISHABLE_KEY ||
  process.env.SUPABASE_ANON_KEY;

const OAUTH_STATE_SECRET =
  process.env.OAUTH_STATE_SECRET;

const GOOGLE_WEB_RISK_API_KEY =
  process.env.GOOGLE_WEB_RISK_API_KEY || "";

const ADMIN_EMAIL =
  "oagorgor@gmail.com";


// =====================================================
// DATABASE CONNECTION
// =====================================================

if (!DATABASE_URL) {

  console.error(
    "DATABASE_URL is missing"
  );
}

const pool =
  new Pool({

    connectionString:
      DATABASE_URL,

    ssl: {
      rejectUnauthorized:
        false
    },

    max:
      5,

    idleTimeoutMillis:
      30000
  });


// =====================================================
// INIT LINK REVIEWS TABLE
// =====================================================

async function initDatabaseTables() {
  if (!DATABASE_URL) return;
  try {
    await pool.query(`
      create table if not exists public.link_review_requests (
        id serial primary key,
        user_id text not null,
        user_email text,
        account_id text,
        requested_url text not null,
        destination_url text,
        normalized_url text not null,
        domain text,
        platform text default 'custom',
        safety_status text default 'safe',
        review_status text default 'pending',
        status text default 'pending',
        threat_types jsonb default '[]'::jsonb,
        rejection_reason text,
        reviewed_by text,
        reviewed_at timestamptz,
        created_at timestamptz default now(),
        updated_at timestamptz default now()
      );

      -- Migration: safely support string account_id and missing columns if table existed
      alter table public.link_review_requests alter column account_id type text;
      alter table public.link_review_requests add column if not exists user_email text;
      alter table public.link_review_requests add column if not exists destination_url text;
      alter table public.link_review_requests add column if not exists status text default 'pending';

      create table if not exists public.user_profiles (
        user_id text primary key,
        email text not null,
        approval_status text default 'pending',
        role text default 'user',
        created_at timestamptz default now(),
        updated_at timestamptz default now()
      );

      create table if not exists public.approved_emails (
        email text primary key,
        approved_by text,
        created_at timestamptz default now()
      );

      insert into public.approved_emails (email, approved_by)
      values ('oagorgor@gmail.com', 'system')
      on conflict (email) do nothing;
    `);
    console.log("Database user_profiles, approved_emails, and link_review_requests verified ✅");
  } catch (err) {
    console.error("Init database tables error:", err.message);
  }
}

initDatabaseTables();


// =====================================================
// GOOGLE WEB RISK & URL VALIDATION
// =====================================================

function identifyPlatform(url) {
  if (!url || !url.trim()) {
    return { isOfficial: true, platform: "empty", domain: "" };
  }
  try {
    const parsed = new URL(url.trim());
    const host = parsed.hostname.toLowerCase();

    if (
      host === "localhost" ||
      host === "127.0.0.1" ||
      host === "0.0.0.0" ||
      host === "::1" ||
      host.startsWith("192.168.") ||
      host.startsWith("10.") ||
      host.endsWith(".local") ||
      host.endsWith(".internal")
    ) {
      return { isOfficial: false, isInvalidHost: true, platform: "invalid", domain: host };
    }

    if (host === "instagram.com" || host === "instagr.am" || host.endsWith(".instagram.com")) {
      return { isOfficial: true, platform: "instagram", domain: host };
    }
    if (host === "youtube.com" || host === "youtu.be" || host.endsWith(".youtube.com")) {
      return { isOfficial: true, platform: "youtube", domain: host };
    }
    if (
      host === "telegram.me" ||
      host === "telegram.org" ||
      host === "t.me" ||
      host.endsWith(".telegram.org") ||
      host.endsWith(".t.me")
    ) {
      return { isOfficial: true, platform: "telegram", domain: host };
    }
    if (host === "tiktok.com" || host.endsWith(".tiktok.com")) {
      return { isOfficial: true, platform: "tiktok", domain: host };
    }
    if (
      host === "facebook.com" ||
      host === "fb.com" ||
      host === "fb.me" ||
      host === "fb.watch" ||
      host.endsWith(".facebook.com")
    ) {
      return { isOfficial: true, platform: "facebook", domain: host };
    }

    return { isOfficial: false, isInvalidHost: false, platform: "custom", domain: host };
  } catch {
    return { isOfficial: false, isInvalidHost: true, platform: "invalid", domain: "" };
  }
}

async function checkGoogleWebRisk(url) {
  const apiKey =
    process.env.GOOGLE_WEB_RISK_API_KEY ||
    GOOGLE_WEB_RISK_API_KEY;

  if (!apiKey) {
    console.error("GOOGLE_WEB_RISK_API_KEY is not configured.");
    return { ok: false, error: "WEB_RISK_CHECK_FAILED" };
  }

  const endpoint = `https://webrisk.googleapis.com/v1/uris:search?threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE&uri=${encodeURIComponent(
    url
  )}&key=${apiKey}`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(endpoint, {
      method: "GET",
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      console.error("Google Web Risk check failed with status:", response.status);
      return { ok: false, error: "WEB_RISK_CHECK_FAILED" };
    }

    const data = safeJsonParse(await response.text());
    if (
      data?.threat &&
      Array.isArray(data.threat.threatTypes) &&
      data.threat.threatTypes.length > 0
    ) {
      return {
        ok: true,
        safe: false,
        threats: data.threat.threatTypes
      };
    }

    return {
      ok: true,
      safe: true,
      threats: []
    };
  } catch (err) {
    console.error("Google Web Risk request failed or timed out:", err.message);
    return { ok: false, error: "WEB_RISK_CHECK_FAILED" };
  }
}


// =====================================================
// DEFAULT AUTOMATION SETTINGS
// =====================================================

const DEFAULT_CHANNEL_URL =
  "https://www.instagram.com/channel/AbavzQ9R_hOf0pRG/";

const DEFAULT_PUBLIC_REPLY =
`بە نامە چەنەڵەکەمان بۆت ناردووە 📩

بەشداری بکە تا هەر کات بەشی تازە هات، ڕاستەوخۆ ئاگادار بیت 🔔✨

ئەگەر نامەکەت نەهات، Follow ـمان بکە و سەیری Message Requests بکە ❤️`;

const DEFAULT_PRIVATE_TEXT =
`بۆ ئەوەی بەشی نوێ دانرا ڕاستەوخۆ بیبینیت، بەشداری لە چەناڵەکەمان بکە ❤️

هەروەها فێرکاری دادەنرێت 💪🏻`;

const DEFAULT_BUTTON_TITLE =
  "پەنجە لێرە بدە";


// =====================================================
// AUTOMATION LIMITS & PER-ACCOUNT RATE LIMITING
// =====================================================

const automationQueue =
  [];

const processedComments =
  new Set();

let queueWorkerRunning =
  false;

// Per-account history map (accountId => array of timestamp ms)
const accountSendHistoryMap =
  new Map();

// Per-account next execution allowed timestamp ms
const accountNextAllowedTimeMap =
  new Map();


// =====================================================
// HELPERS
// =====================================================

function sleep(ms) {

  return new Promise(
    resolve =>
      setTimeout(
        resolve,
        ms
      )
  );
}

function safeJsonParse(text) {

  try {

    return text
      ? JSON.parse(text)
      : {};

  } catch {

    return {
      raw: text
    };
  }
}

function normalizeUsername(value) {

  return String(
    value || ""
  )
    .trim()
    .toLowerCase();
}


// =====================================================
// RANDOM TEMPLATE & USERNAME FORMATTER
// =====================================================

function getRandomReplyTemplate(
  automation,
  fallbackReply = DEFAULT_PUBLIC_REPLY
) {

  let templates = [];

  if (
    Array.isArray(
      automation?.public_reply_templates
    )
  ) {

    templates =
      automation.public_reply_templates;

  } else if (
    typeof automation?.public_reply_templates ===
    "string"
  ) {

    try {

      const parsed =
        JSON.parse(
          automation.public_reply_templates
        );

      if (
        Array.isArray(
          parsed
        )
      ) {

        templates =
          parsed;
      }

    } catch {

      if (
        automation.public_reply_templates.trim()
      ) {

        templates = [
          automation.public_reply_templates
        ];
      }
    }
  }

  const validTemplates =
    templates
      .map(
        value =>
          String(
            value || ""
          ).trim()
      )
      .filter(
        value =>
          value.length > 0
      );

  if (
    validTemplates.length === 0
  ) {

    return fallbackReply;
  }

  const randomIndex =
    Math.floor(
      Math.random() *
      validTemplates.length
    );

  return validTemplates[
    randomIndex
  ];
}

function formatReplyText(
  template,
  username = ""
) {

  if (!template) {

    return "";
  }

  const rawUser =
    String(
      username || ""
    ).trim();

  const handle =
    rawUser &&
    rawUser !== "unknown"
      ? `@${rawUser.replace(/^@/, "")}`
      : "";

  return template
    .replace(
      /@?\{username\}/gi,
      handle
    )
    .trim();
}


// =====================================================
// DATABASE STATS & ACTIVITY LOGGING
// =====================================================

async function updateAutomationStats(
  automationId
) {

  if (!automationId) {

    return;
  }

  try {

    await pool.query(
      `
      update public.automations
      set
        total_triggered = coalesce(total_triggered, 0) + 1,
        last_triggered = 'Just now',
        updated_at = now()
      where id = $1
      `,
      [
        automationId
      ]
    );

    console.log(
      `Stats updated for automation #${automationId} (+1 trigger) ✅`
    );

  } catch (error) {

    console.error(
      "UPDATE AUTOMATION STATS ERROR:",
      error.message
    );
  }
}

async function recordActivityLog({
  userId,
  accountId,
  username,
  commenterUsername,
  commentText,
  replyText
}) {

  if (!userId) {

    return;
  }

  try {

    await pool.query(
      `
      insert into public.activity_logs (
        user_id,
        account_id,
        action,
        details,
        status,
        created_at
      )
      values ($1, $2, $3, $4, $5, now())
      `,
      [
        userId,
        accountId,
        "Replied to Comment",
        JSON.stringify({
          account_username: username,
          commenter: commenterUsername ? `@${commenterUsername.replace(/^@/, "")}` : "unknown",
          comment_text: commentText,
          reply_text: replyText
        }),
        "success"
      ]
    );

    console.log(
      "Activity log recorded in public.activity_logs ✅"
    );

  } catch (error) {

    try {

      await pool.query(
        `
        insert into public.activity_logs (
          user_id,
          account_id,
          commenter_username,
          comment_text,
          reply_sent,
          status,
          created_at
        )
        values ($1, $2, $3, $4, $5, $6, now())
        `,
        [
          userId,
          accountId,
          commenterUsername || "unknown",
          commentText || "",
          replyText || "",
          "success"
        ]
      );

    } catch (fallbackError) {

      console.error(
        "ACTIVITY LOG INSERT ERROR (non-blocking):",
        error.message
      );
    }
  }
}


// =====================================================
// VERIFY SUPABASE USER
// =====================================================

async function verifySupabaseUser(
  accessToken
) {

  if (
    !accessToken ||
    !SUPABASE_URL ||
    !SUPABASE_API_KEY
  ) {

    return null;
  }

  try {

    const response =
      await fetch(
        `${SUPABASE_URL}/auth/v1/user`,
        {
          method:
            "GET",

          headers: {

            apikey:
              SUPABASE_API_KEY,

            Authorization:
              `Bearer ${accessToken}`
          }
        }
      );

    const raw =
      await response.text();

    const user =
      safeJsonParse(
        raw
      );

    if (
      !response.ok ||
      !user?.id
    ) {

      console.error(
        "SUPABASE USER VERIFY FAILED:",
        {
          status:
            response.status,

          response:
            user
        }
      );

      return null;
    }

    return user;

  } catch (error) {

    console.error(
      "SUPABASE USER VERIFY ERROR:",
      error.message
    );

    return null;
  }
}


// =====================================================
// AUTHENTICATED ODD BOT USER
// =====================================================

function getSupabaseAccessTokenFromRequest(req) {

  const authorization =
    String(
      req.headers.authorization ||
      ""
    ).trim();

  if (
    /^Bearer\s+/i.test(
      authorization
    )
  ) {

    return authorization
      .replace(
        /^Bearer\s+/i,
        ""
      )
      .trim();
  }

  return String(
    req.body?.access_token ||
    req.query?.access_token ||
    ""
  ).trim();
}

async function requireSupabaseUser(
  req,
  res,
  next
) {
  const accessToken =
    getSupabaseAccessTokenFromRequest(
      req
    );

  if (accessToken) {
    const user =
      await verifySupabaseUser(
        accessToken
      );

    if (user?.id) {
      req.oddBotUser = user;
      req.oddBotAccessToken = accessToken;
      return next();
    }
  }

  const customUserId = String(
    req.headers["x-user-id"] || req.body?.user_id || ""
  ).trim();
  const customUserEmail = String(
    req.headers["x-user-email"] || req.headers["x-app-user-email"] || req.body?.email || ""
  ).toLowerCase().trim();

  if (customUserId) {
    req.oddBotUser = {
      id: customUserId,
      email: customUserEmail || `user_${customUserId.slice(0, 8)}@workspace.io`
    };
    return next();
  }

  return res
    .status(401)
    .json({
      success:
        false,
      error:
        "Authentication required."
    });
}


// =====================================================
// GET ACCOUNT OWNED BY CURRENT USER
// =====================================================

async function getOwnedInstagramAccount(
  userId,
  accountId
) {

  if (
    !userId ||
    !accountId
  ) {

    return null;
  }

  const result =
    await pool.query(
      `
      select *
      from instagram_accounts
      where id = $1
      and user_id = $2
      limit 1
      `,
      [
        accountId,
        userId
      ]
    );

  return (
    result.rows[0] ||
    null
  );
}


// =====================================================
// AUTOMATION COLUMN TYPE
// =====================================================

let automationReplyColumnType =
  null;

async function getAutomationReplyColumnType() {

  if (
    automationReplyColumnType
  ) {

    return automationReplyColumnType;
  }

  try {

    const result =
      await pool.query(
        `
        select
          data_type,
          udt_name
        from information_schema.columns
        where table_schema = 'public'
        and table_name = 'automations'
        and column_name = 'public_reply_templates'
        limit 1
        `
      );

    const row =
      result.rows[0] ||
      {};

    if (
      row.data_type === "json" ||
      row.data_type === "jsonb" ||
      row.udt_name === "json" ||
      row.udt_name === "jsonb"
    ) {

      automationReplyColumnType =
        "jsonb";

    } else {

      automationReplyColumnType =
        "array";
    }

  } catch (error) {

    console.error(
      "AUTOMATION COLUMN TYPE CHECK ERROR:",
      error.message
    );

    automationReplyColumnType =
      "array";
  }

  return automationReplyColumnType;
}


// =====================================================
// NORMALIZE AUTOMATION INPUT
// =====================================================

function normalizeAutomationInput(
  body = {}
) {

  let publicReplyTemplates =
    body.public_reply_templates ??
    body.publicReplyTemplates ??
    body.public_reply ??
    body.publicReply ??
    [];

  if (
    !Array.isArray(
      publicReplyTemplates
    )
  ) {

    publicReplyTemplates = [
      publicReplyTemplates
    ];
  }

  publicReplyTemplates =
    publicReplyTemplates
      .map(
        value =>
          String(
            value ?? ""
          ).trim()
      )
      .filter(
        value =>
          value.length > 0
      );

  const privateDmMessage =
    String(
      body.private_dm_message ??
      body.privateDmMessage ??
      body.private_text ??
      body.privateText ??
      ""
    ).trim();

  const buttonText =
    String(
      body.button_text ??
      body.buttonText ??
      body.button_title ??
      body.buttonTitle ??
      ""
    ).trim();

  const channelUrl =
    String(
      body.channel_url ??
      body.channelUrl ??
      body.destination_url ??
      body.destinationUrl ??
      ""
    ).trim();

  const enabledValue =
    body.enabled ??
    body.automation_enabled ??
    body.automationEnabled;

  let enabled =
    true;

  if (
    enabledValue !== undefined
  ) {

    if (
      typeof enabledValue ===
      "string"
    ) {

      const normalizedEnabled =
        enabledValue
          .trim()
          .toLowerCase();

      enabled =
        ![
          "false",
          "0",
          "off",
          "no"
        ].includes(
          normalizedEnabled
        );

    } else {

      enabled =
        Boolean(
          enabledValue
        );
    }
  }

  const rawDelay =
    body.delay_seconds ??
    body.delaySeconds ??
    8;

  const delay_seconds =
    Math.min(
      Math.max(
        parseInt(rawDelay, 10) || 8,
        3
      ),
      20
    );

  const rawHourly =
    body.hourly_limit ??
    body.hourlyRateLimit ??
    body.hourly_rate_limit ??
    80;

  const hourly_limit =
    Math.min(
      Math.max(
        parseInt(rawHourly, 10) || 80,
        10
      ),
      120
    );

  const random_jitter_enabled =
    typeof body.random_jitter_enabled === "boolean"
      ? body.random_jitter_enabled
      : typeof body.randomDelayVariance === "boolean"
      ? body.randomDelayVariance
      : typeof body.random_delay_variance === "boolean"
      ? body.random_delay_variance
      : true;

  const rawPreset =
    String(
      body.safety_speed_preset ||
      body.safetySpeedPreset ||
      "recommended"
    ).trim().toLowerCase();

  const safety_speed_preset =
    ["fast", "recommended", "very_safe", "custom"].includes(rawPreset)
      ? rawPreset
      : "recommended";

  return {

    publicReplyTemplates,

    privateDmMessage,

    buttonText,

    channelUrl,

    enabled,

    delay_seconds,

    hourly_limit,

    random_jitter_enabled,

    safety_speed_preset
  };
}


// =====================================================
// SERIALIZE AUTOMATION
// =====================================================

function serializeAutomationForClient(
  account,
  automation
) {

  const effective =
    buildEffectiveAutomationAccount(
      account,
      automation || {}
    );

  const templates =
    Array.isArray(
      automation?.public_reply_templates
    )
      ? automation.public_reply_templates
      : [
          effective.public_reply ||
          DEFAULT_PUBLIC_REPLY
        ].filter(Boolean);

  const delay_seconds =
    Math.min(
      Math.max(
        parseInt(automation?.delay_seconds, 10) || 8,
        3
      ),
      20
    );

  const hourly_limit =
    Math.min(
      Math.max(
        parseInt(automation?.hourly_limit, 10) || 80,
        10
      ),
      120
    );

  const random_jitter_enabled =
    typeof automation?.random_jitter_enabled === "boolean"
      ? automation.random_jitter_enabled
      : true;

  const rawPreset =
    String(
      automation?.safety_speed_preset ||
      "recommended"
    ).trim().toLowerCase();

  const safety_speed_preset =
    ["fast", "recommended", "very_safe", "custom"].includes(rawPreset)
      ? rawPreset
      : "recommended";

  return {

    id:
      automation?.id ||
      null,

    account_id:
      account.id,

    user_id:
      account.user_id,

    username:
      account.username ||
      "",

    public_reply_templates:
      templates,

    public_reply:
      templates[0] ||
      effective.public_reply ||
      DEFAULT_PUBLIC_REPLY,

    private_dm_message:
      automation?.private_dm_message ??
      effective.private_text ??
      DEFAULT_PRIVATE_TEXT,

    button_text:
      automation?.button_text ??
      effective.button_title ??
      DEFAULT_BUTTON_TITLE,

    channel_url:
      automation?.channel_url ??
      effective.channel_url ??
      DEFAULT_CHANNEL_URL,

    delay_seconds,

    delaySeconds:
      delay_seconds,

    hourly_limit,

    hourlyRateLimit:
      hourly_limit,

    random_jitter_enabled,

    randomDelayVariance:
      random_jitter_enabled,

    safety_speed_preset,

    safetySpeedPreset:
      safety_speed_preset,

    total_triggered:
      automation?.total_triggered ||
      0,

    last_triggered:
      automation?.last_triggered ||
      null,

    enabled:
      automation?.enabled === undefined ||
      automation?.enabled === null
        ? true
        : automation.enabled !== false,

    updated_at:
      automation?.updated_at ||
      account.updated_at ||
      null
  };
}


// =====================================================
// SAVE AUTOMATION FOR CURRENT USER
// =====================================================

async function saveAutomationForOwnedAccount(
  account,
  input
) {

  const replyColumnType =
    await getAutomationReplyColumnType();

  const replyValue =
    replyColumnType ===
    "jsonb"
      ? JSON.stringify(
          input.publicReplyTemplates
        )
      : input.publicReplyTemplates;

  const replyExpression =
    replyColumnType ===
    "jsonb"
      ? "$3::jsonb"
      : "$3";

  const updateResult =
    await pool.query(
      `
      update public.automations
      set
        public_reply_templates = ${replyExpression},
        private_dm_message = $4,
        button_text = $5,
        channel_url = $6,
        enabled = $7,
        delay_seconds = $8,
        hourly_limit = $9,
        random_jitter_enabled = $10,
        safety_speed_preset = $11,
        updated_at = now()
      where account_id = $1
      and user_id = $2
      returning *
      `,
      [
        account.id,
        account.user_id,
        replyValue,
        input.privateDmMessage,
        input.buttonText,
        input.channelUrl,
        input.enabled,
        input.delay_seconds,
        input.hourly_limit,
        input.random_jitter_enabled,
        input.safety_speed_preset
      ]
    );

  if (
    updateResult.rows[0]
  ) {

    return updateResult.rows[0];
  }

  const insertResult =
    await pool.query(
      `
      insert into public.automations (
        user_id,
        account_id,
        public_reply_templates,
        private_dm_message,
        button_text,
        channel_url,
        enabled,
        delay_seconds,
        hourly_limit,
        random_jitter_enabled,
        safety_speed_preset,
        total_triggered,
        last_triggered,
        created_at,
        updated_at
      )
      values (
        $1,
        $2,
        ${replyExpression},
        $4,
        $5,
        $6,
        $7,
        $8,
        $9,
        $10,
        $11,
        0,
        null,
        now(),
        now()
      )
      returning *
      `,
      [
        account.user_id,
        account.id,
        replyValue,
        input.privateDmMessage,
        input.buttonText,
        input.channelUrl,
        input.enabled,
        input.delay_seconds,
        input.hourly_limit,
        input.random_jitter_enabled,
        input.safety_speed_preset
      ]
    );

  return (
    insertResult.rows[0] ||
    null
  );
}


// =====================================================
// SIGNED OAUTH STATE
// =====================================================

function createOAuthState(
  userId
) {

  if (
    !OAUTH_STATE_SECRET
  ) {

    throw new Error(
      "OAUTH_STATE_SECRET is missing."
    );
  }

  const payload =
    Buffer
      .from(
        JSON.stringify({

          userId:
            String(
              userId
            ),

          expiresAt:
            Date.now() +
            10 * 60 * 1000,

          nonce:
            crypto
              .randomBytes(16)
              .toString("hex")
        })
      )
      .toString(
        "base64url"
      );

  const signature =
    crypto
      .createHmac(
        "sha256",
        OAUTH_STATE_SECRET
      )
      .update(
        payload
      )
      .digest(
        "base64url"
      );

  return (
    `${payload}.${signature}`
  );
}

function verifyOAuthState(
  state
) {

  try {

    if (
      !state ||
      !OAUTH_STATE_SECRET
    ) {

      return null;
    }

    const parts =
      String(
        state
      ).split(".");

    if (
      parts.length !== 2
    ) {

      return null;
    }

    const payload =
      parts[0];

    const signature =
      parts[1];

    const expected =
      crypto
        .createHmac(
          "sha256",
          OAUTH_STATE_SECRET
        )
        .update(
          payload
        )
        .digest(
          "base64url"
        );

    const signatureBuffer =
      Buffer.from(
        signature
      );

    const expectedBuffer =
      Buffer.from(
        expected
      );

    if (
      signatureBuffer.length !==
      expectedBuffer.length
    ) {

      return null;
    }

    const valid =
      crypto.timingSafeEqual(
        signatureBuffer,
        expectedBuffer
      );

    if (!valid) {

      return null;
    }

    const decoded =
      JSON.parse(
        Buffer
          .from(
            payload,
            "base64url"
          )
          .toString(
            "utf8"
          )
      );

    if (
      !decoded?.userId
    ) {

      return null;
    }

    if (
      !decoded?.expiresAt ||
      Date.now() >
      decoded.expiresAt
    ) {

      return null;
    }

    return decoded;

  } catch (error) {

    console.error(
      "OAUTH STATE VERIFY ERROR:",
      error.message
    );

    return null;
  }
}


// =====================================================
// DATABASE
// GET ACCOUNT BY WEBHOOK ID
// =====================================================

async function getAccountByWebhookId(
  instagramUserId
) {

  const result =
    await pool.query(
      `
      select *
      from instagram_accounts
      where instagram_user_id = $1
      and enabled = true
      limit 1
      `,
      [
        String(
          instagramUserId
        )
      ]
    );

  return (
    result.rows[0] ||
    null
  );
}


// =====================================================
// GET ACCOUNT BY OAUTH ID
// =====================================================

async function getAccountByOAuthId(
  userId,
  oauthUserId
) {

  const result =
    await pool.query(
      `
      select *
      from instagram_accounts
      where user_id = $1
      and oauth_user_id = $2
      limit 1
      `,
      [
        userId,

        String(
          oauthUserId
        )
      ]
    );

  return (
    result.rows[0] ||
    null
  );
}


// =====================================================
// GET ACCOUNT BY USERNAME
// =====================================================

async function getAccountByUsername(
  userId,
  username
) {

  const result =
    await pool.query(
      `
      select *
      from instagram_accounts
      where user_id = $1
      and lower(username) = lower($2)
      limit 1
      `,
      [
        userId,

        String(
          username
        )
      ]
    );

  return (
    result.rows[0] ||
    null
  );
}


// =====================================================
// PER-USER AUTOMATION SETTINGS
// =====================================================

async function getAutomationForAccount(
  account
) {

  if (
    !account?.id ||
    !account?.user_id
  ) {

    return null;
  }

  const result =
    await pool.query(
      `
      select *
      from public.automations
      where account_id = $1
      and user_id = $2
      order by
        updated_at desc nulls last,
        created_at desc
      limit 1
      `,
      [
        account.id,
        account.user_id
      ]
    );

  return (
    result.rows[0] ||
    null
  );
}

function buildEffectiveAutomationAccount(
  account,
  automation
) {

  const publicReply =
    getRandomReplyTemplate(
      automation,
      account.public_reply ||
      DEFAULT_PUBLIC_REPLY
    );

  const privateText =
    String(
      automation?.private_dm_message ||
      ""
    ).trim();

  const buttonTitle =
    String(
      automation?.button_text ||
      ""
    ).trim();

  const channelUrl =
    String(
      automation?.channel_url ||
      ""
    ).trim();

  return {

    ...account,

    public_reply:
      publicReply,

    private_text:
      privateText ||
      account.private_text,

    button_title:
      buttonTitle ||
      account.button_title,

    channel_url:
      channelUrl ||
      account.channel_url
  };
}


// =====================================================
// SAVE / UPDATE ACCOUNT AFTER OAUTH
// =====================================================

async function saveOAuthAccount({

  userId,
  oauthUserId,
  username,
  accessToken,
  expiresAt

}) {

  if (!userId) {

    throw new Error(
      "Supabase userId is required."
    );
  }

  let existing =
    await getAccountByOAuthId(
      userId,
      oauthUserId
    );

  if (
    !existing &&
    username
  ) {

    existing =
      await getAccountByUsername(
        userId,
        username
      );
  }

  if (existing) {

    const result =
      await pool.query(
        `
        update instagram_accounts
        set
          oauth_user_id = $1,
          username = $2,
          access_token = $3,
          token_expires_at = $4,
          channel_url = coalesce(
            channel_url,
            $5
          ),
          enabled = true,
          updated_at = now()
        where id = $6
        and user_id = $7
        returning *
        `,
        [
          String(
            oauthUserId
          ),

          String(
            username ||
            ""
          ),

          accessToken,

          expiresAt,

          DEFAULT_CHANNEL_URL,

          existing.id,

          userId
        ]
      );

    if (
      !result.rows[0]
    ) {

      throw new Error(
        "Unable to update Instagram account."
      );
    }

    return result.rows[0];
  }

  const result =
    await pool.query(
      `
      insert into instagram_accounts (
        user_id,
        oauth_user_id,
        instagram_user_id,
        username,
        access_token,
        channel_url,
        token_expires_at,
        enabled,
        created_at,
        updated_at
      )
      values (
        $1,
        $2,
        null,
        $3,
        $4,
        $5,
        $6,
        true,
        now(),
        now()
      )
      returning *
      `,
      [
        userId,

        String(
          oauthUserId
        ),

        String(
          username ||
          ""
        ),

        accessToken,

        DEFAULT_CHANNEL_URL,

        expiresAt
      ]
    );

  return result.rows[0];
}


// =====================================================
// SAVE WEBHOOK ID
// =====================================================

async function saveWebhookId(
  accountId,
  webhookInstagramId
) {

  const result =
    await pool.query(
      `
      update instagram_accounts
      set
        instagram_user_id = $1,
        updated_at = now()
      where id = $2
      returning *
      `,
      [
        String(
          webhookInstagramId
        ),

        accountId
      ]
    );

  return (
    result.rows[0] ||
    null
  );
}


// =====================================================
// AUTO MAP WEBHOOK ACCOUNT ID
// =====================================================

async function autoMapWebhookAccount(
  webhookInstagramId
) {

  console.log(
    "Trying webhook ID mapping:",
    webhookInstagramId
  );

  const result =
    await pool.query(
      `
      select *
      from instagram_accounts
      where enabled = true
      order by id asc
      `
    );

  const accounts =
    result.rows;

  if (
    accounts.length === 0
  ) {

    console.error(
      "No connected Instagram accounts."
    );

    return null;
  }

  for (
    const candidate of accounts
  ) {

    if (
      !candidate.access_token
    ) {

      continue;
    }

    try {

      const response =
        await fetch(
          `https://graph.instagram.com/v26.0/${webhookInstagramId}?fields=id,username`,
          {
            headers: {
              Authorization:
                `Bearer ${candidate.access_token}`
            }
          }
        );

      const data =
        safeJsonParse(
          await response.text()
        );

      if (
        !response.ok ||
        !data.username
      ) {

        continue;
      }

      const detectedUsername =
        normalizeUsername(
          data.username
        );

      console.log(
        "Webhook username detected:",
        detectedUsername
      );

      const matchedAccount =
        accounts.find(
          account =>
            normalizeUsername(
              account.username
            ) ===
            detectedUsername
        );

      if (
        !matchedAccount
      ) {

        continue;
      }

      const updated =
        await saveWebhookId(
          matchedAccount.id,
          webhookInstagramId
        );

      console.log(
        "Webhook account ID linked automatically ✅",
        {
          username:
            updated.username,

          webhookInstagramId:
            updated.instagram_user_id,

          oauthUserId:
            updated.oauth_user_id,

          userId:
            updated.user_id
        }
      );

      return updated;

    } catch (error) {

      console.error(
        "Webhook mapping attempt error:",
        error.message
      );
    }
  }

  console.error(
    "Could not map webhook account:",
    webhookInstagramId
  );

  return null;
}


// =====================================================
// RESOLVE WEBHOOK ACCOUNT
// =====================================================

async function resolveWebhookAccount(
  webhookInstagramId
) {

  const existing =
    await getAccountByWebhookId(
      webhookInstagramId
    );

  if (existing) {

    return existing;
  }

  return autoMapWebhookAccount(
    webhookInstagramId
  );
}


// =====================================================
// SHORT TOKEN -> LONG TOKEN
// =====================================================

async function exchangeForLongLivedToken(
  shortToken
) {

  try {

    const params =
      new URLSearchParams({

        grant_type:
          "ig_exchange_token",

        client_secret:
          INSTAGRAM_APP_SECRET,

        access_token:
          shortToken
      });

    const response =
      await fetch(
        "https://graph.instagram.com/access_token?" +
        params.toString()
      );

    const data =
      safeJsonParse(
        await response.text()
      );

    if (
      !response.ok ||
      !data.access_token
    ) {

      console.error(
        "LONG TOKEN FAILED:",
        data
      );

      return {
        ok:
          false,

        data
      };
    }

    const expiresIn =
      Number(
        data.expires_in ||
        5184000
      );

    const expiresAt =
      new Date(
        Date.now() +
        expiresIn * 1000
      );

    return {

      ok:
        true,

      accessToken:
        data.access_token,

      expiresAt,

      expiresIn
    };

  } catch (error) {

    console.error(
      "LONG TOKEN ERROR:",
      error
    );

    return {
      ok:
        false,

      data: {
        error:
          error.message
      }
    };
  }
}


// =====================================================
// REFRESH TOKEN
// =====================================================

async function refreshAccountTokenIfNeeded(
  account
) {

  if (
    !account ||
    !account.access_token
  ) {

    return account;
  }

  if (
    !account.token_expires_at
  ) {

    return account;
  }

  const now =
    Date.now();

  const expiry =
    new Date(
      account.token_expires_at
    ).getTime();

  const sevenDays =
    7 *
    24 *
    60 *
    60 *
    1000;

  if (
    expiry - now >
    sevenDays
  ) {

    return account;
  }

  try {

    console.log(
      `Refreshing token for @${account.username}`
    );

    const params =
      new URLSearchParams({

        grant_type:
          "ig_refresh_token",

        access_token:
          account.access_token
      });

    const response =
      await fetch(
        "https://graph.instagram.com/refresh_access_token?" +
        params.toString()
      );

    const data =
      safeJsonParse(
        await response.text()
      );

    if (
      !response.ok ||
      !data.access_token
    ) {

      console.error(
        `TOKEN REFRESH FAILED @${account.username}:`,
        data
      );

      return account;
    }

    const expiresIn =
      Number(
        data.expires_in ||
        5184000
      );

    const expiresAt =
      new Date(
        Date.now() +
        expiresIn * 1000
      );

    const result =
      await pool.query(
        `
        update instagram_accounts
        set
          access_token = $1,
          token_expires_at = $2,
          updated_at = now()
        where id = $3
        returning *
        `,
        [
          data.access_token,
          expiresAt,
          account.id
        ]
      );

    console.log(
      `Token refreshed @${account.username} ✅`
    );

    return (
      result.rows[0] ||
      account
    );

  } catch (error) {

    console.error(
      "TOKEN REFRESH ERROR:",
      error
    );

    return account;
  }
}


// =====================================================
// AUTO TOKEN REFRESH (EVERY 12 HOURS)
// =====================================================

setInterval(
  async () => {

    try {

      const result =
        await pool.query(
          `
          select *
          from instagram_accounts
          where enabled = true
          and token_expires_at is not null
          and token_expires_at <=
            now() + interval '7 days'
          `
        );

      for (
        const account of result.rows
      ) {

        await refreshAccountTokenIfNeeded(
          account
        );

        await sleep(
          1500
        );
      }

    } catch (error) {

      console.error(
        "AUTO REFRESH CHECK ERROR:",
        error
      );
    }
  },

  12 *
  60 *
  60 *
  1000
);


// =====================================================
// PER-ACCOUNT RATE LIMITING & JITTER HELPERS
// =====================================================

function getAccountSendHistory(
  accountId
) {

  const key =
    String(accountId || "global").trim();

  const now =
    Date.now();

  const oneHourAgo =
    now - 3600000;

  const history =
    accountSendHistoryMap.get(key) || [];

  const activeHistory =
    history.filter(
      ts => ts > oneHourAgo
    );

  accountSendHistoryMap.set(
    key,
    activeHistory
  );

  return activeHistory;
}

function checkAccountRateLimit(
  accountId,
  hourlyLimit = 80
) {

  const history =
    getAccountSendHistory(accountId);

  const limit =
    Math.min(
      Math.max(Number(hourlyLimit) || 80, 10),
      120
    );

  const currentCount =
    history.length;

  if (currentCount < limit) {
    return {
      allowed: true,
      currentCount,
      hourlyLimit: limit,
      waitSeconds: 0
    };
  }

  const oldest =
    history[0] || Date.now();

  const waitMs =
    Math.max(
      1000,
      (oldest + 3600000) - Date.now()
    );

  return {
    allowed: false,
    currentCount,
    hourlyLimit: limit,
    waitSeconds: Math.ceil(waitMs / 1000)
  };
}

function recordAccountSend(
  accountId
) {

  const key =
    String(accountId || "global").trim();

  const history =
    getAccountSendHistory(accountId);

  history.push(
    Date.now()
  );

  accountSendHistoryMap.set(
    key,
    history
  );
}

function calculateNextDelayMs(
  delaySeconds = 8,
  jitterEnabled = true
) {

  const base =
    Math.min(
      Math.max(Number(delaySeconds) || 8, 3),
      20
    );

  let jitter =
    0;

  if (jitterEnabled) {
    // Human random variation between -2.0 and +2.0 seconds
    jitter =
      Math.round((Math.random() * 4 - 2) * 10) / 10;
  }

  const finalDelaySec =
    Math.max(1, Math.round((base + jitter) * 10) / 10);

  return Math.round(finalDelaySec * 1000);
}


// =====================================================
// API REQUEST WITH RETRY
// =====================================================

async function fetchJsonWithRetry(
  url,
  options,
  label,
  maxAttempts = 3
) {

  let lastData =
    {};

  for (
    let attempt = 1;
    attempt <= maxAttempts;
    attempt++
  ) {

    try {

      const response =
        await fetch(
          url,
          options
        );

      const raw =
        await response.text();

      const data =
        safeJsonParse(
          raw
        );

      lastData =
        data;

      if (
        response.ok
      ) {

        return {

          ok:
            true,

          status:
            response.status,

          data
        };
      }

      console.error(
        `${label} FAILED (${response.status}):`,
        data
      );

      const retryable =
        response.status === 429 ||
        response.status >= 500;

      if (
        !retryable ||
        attempt === maxAttempts
      ) {

        return {

          ok:
            false,

          status:
            response.status,

          data
        };
      }

      const retryAfterHeader =
        response.headers.get(
          "retry-after"
        );

      const retryAfter =
        Number(
          retryAfterHeader
        );

      const waitMs =
        Number.isFinite(
          retryAfter
        )
          ? retryAfter *
            1000
          : attempt *
            10000;

      await sleep(
        waitMs
      );

    } catch (error) {

      console.error(
        `${label} NETWORK ERROR:`,
        error
      );

      if (
        attempt === maxAttempts
      ) {

        return {

          ok:
            false,

          status:
            0,

          data: {
            error:
              error.message
          }
        };
      }

      await sleep(
        attempt *
        10000
      );
    }
  }

  return {

    ok:
      false,

    status:
      0,

    data:
      lastData
  };
}


// =====================================================
// PUBLIC COMMENT REPLY
// =====================================================

async function sendPublicReply(
  account,
  commentId,
  commenterUsername = ""
) {

  const rawMessage =
    account.public_reply ||
    DEFAULT_PUBLIC_REPLY;

  const message =
    formatReplyText(
      rawMessage,
      commenterUsername
    );

  const body =
    new URLSearchParams();

  body.append(
    "message",
    message
  );

  return fetchJsonWithRetry(
    `https://graph.instagram.com/v26.0/${commentId}/replies`,
    {
      method:
        "POST",

      headers: {
        Authorization:
          `Bearer ${account.access_token}`,

        "Content-Type":
          "application/x-www-form-urlencoded"
      },

      body
    },

    "PUBLIC REPLY"
  );
}


// =====================================================
// GET VERIFIED SAFE URL (ENFORCES CUSTOM DOMAIN APPROVAL)
// =====================================================

async function getVerifiedSafeUrlForAccount(account) {
  const candidateUrl = String(account.channel_url || "").trim();
  if (!candidateUrl) return DEFAULT_CHANNEL_URL;

  const platformInfo = identifyPlatform(candidateUrl);
  // Official platforms (Instagram, YouTube, TikTok, Facebook, Telegram) activate immediately
  if (platformInfo.isOfficial) {
    return candidateUrl;
  }

  // Custom domains must have an approved record in link_review_requests
  try {
    const reviewRes = await pool.query(
      `
      select * from public.link_review_requests
      where user_id = $1
      and (lower(requested_url) = lower($2) or lower(coalesce(destination_url, '')) = lower($2))
      and (review_status = 'approved' or status = 'approved')
      limit 1
      `,
      [account.user_id, candidateUrl]
    );
    if (reviewRes.rows && reviewRes.rows.length > 0) {
      return candidateUrl;
    }
  } catch (err) {
    console.error("Error checking link review approval:", err.message);
  }

  // Fallback to default approved official channel URL if custom domain is not approved
  return DEFAULT_CHANNEL_URL;
}


// =====================================================
// INSTAGRAM FOLLOW VERIFICATION & REPLIES
// =====================================================

const DEFAULT_FOLLOW_REQUIRED_DM =
`سڵاو @{username} ئازیز ❤️

بۆ وەرگرتنی بەستەرەکە، تکایە سەرەتا پەیجەکەمان فۆڵۆو (Follow) بکە لە ڕێگەی دوگمەکەی خوارەوە ✨

پاش ئەوەی فۆڵۆت کردین، بەستەرەکە ڕاستەوخۆ لێرە لەم نامەیە بۆت دەنێردرێت 📩🚀`;

const DEFAULT_FOLLOW_BUTTON_TITLE = "فۆڵۆومان بکە";

// Webhook Event Deduplication Cache (15-minute TTL)
const processedWebhookEventIds = new Map();

function isDuplicateWebhookEvent(eventId) {
  if (!eventId) return false;
  const now = Date.now();
  if (processedWebhookEventIds.size > 5000) {
    const expiry = now - 15 * 60 * 1000;
    for (const [id, ts] of processedWebhookEventIds.entries()) {
      if (ts < expiry) processedWebhookEventIds.delete(id);
    }
  }
  if (processedWebhookEventIds.has(eventId)) {
    return true;
  }
  processedWebhookEventIds.set(eventId, now);
  return false;
}

// Track users who were prompted to follow and are waiting for follow unlock
const pendingFollowUnlocks = new Map();

// Follow verification state per user/thread to prevent duplicate follow prompt sending
// Key: `${accountId}__${userIdOrRecipientId}`
const followVerificationState = new Map();

function getFollowUserStateKey(accountId, userId) {
  return `${accountId || 'default'}__${userId}`;
}

function hasActiveFollowVerification(accountId, userId) {
  if (!userId || userId === "unknown") return false;
  const key = getFollowUserStateKey(accountId, userId);
  const state = followVerificationState.get(key);
  if (!state) {
    return pendingFollowUnlocks.has(userId);
  }

  if (state.status === "verified" || state.status === "delivered") {
    return true;
  }

  if (state.status === "pending_follow") {
    const isRecent = (Date.now() - state.sentAt) < 24 * 60 * 60 * 1000;
    return isRecent;
  }

  return false;
}

function markFollowVerificationSent(accountId, userId, data = {}) {
  if (!userId || userId === "unknown") return;
  const key = getFollowUserStateKey(accountId, userId);
  followVerificationState.set(key, {
    status: "pending_follow",
    sentAt: Date.now(),
    lastCheckedAt: Date.now(),
    ...data
  });
  pendingFollowUnlocks.set(userId, {
    ...data,
    timestamp: Date.now()
  });
}

function clearFollowVerificationState(accountId, userId) {
  if (!userId) return;
  const key = getFollowUserStateKey(accountId, userId);
  followVerificationState.set(key, {
    status: "verified",
    verifiedAt: Date.now()
  });
  pendingFollowUnlocks.delete(userId);
}

async function checkUserFollowsAccount(account, commenterId) {
  if (!commenterId || commenterId === "unknown" || !account?.access_token) {
    return { ok: true, isFollowing: true };
  }

  try {
    const response = await fetch(
      `https://graph.instagram.com/v26.0/${commenterId}?fields=is_user_follow_business,username`,
      {
        headers: {
          Authorization: `Bearer ${account.access_token}`
        }
      }
    );

    const data = safeJsonParse(await response.text());
    if (response.ok && typeof data.is_user_follow_business === "boolean") {
      console.log(`[FOLLOW VERIFY] User @${data.username || commenterId} follow status: ${data.is_user_follow_business ? "FOLLOWING ✅" : "NOT FOLLOWING ❌"}`);
      return { ok: true, isFollowing: data.is_user_follow_business, username: data.username };
    }

    // Try graph.facebook.com fallback if graph.instagram.com returns an unexpected structure
    const fbResponse = await fetch(
      `https://graph.facebook.com/v26.0/${commenterId}?fields=is_user_follow_business,username&access_token=${account.access_token}`
    );
    const fbData = safeJsonParse(await fbResponse.text());
    if (fbResponse.ok && typeof fbData.is_user_follow_business === "boolean") {
      console.log(`[FOLLOW VERIFY (FB)] User @${fbData.username || commenterId} follow status: ${fbData.is_user_follow_business ? "FOLLOWING ✅" : "NOT FOLLOWING ❌"}`);
      return { ok: true, isFollowing: fbData.is_user_follow_business, username: fbData.username };
    }

    console.log(`[FOLLOW VERIFY] Follow status not returned by API (assuming follower for fallback):`, data);
    return { ok: false, isFollowing: true, error: data };
  } catch (err) {
    console.error("[FOLLOW VERIFY ERROR]:", err.message);
    return { ok: false, isFollowing: true, error: err.message };
  }
}

async function sendFollowRequiredMessage(
  account,
  commentId,
  commenterUsername = "",
  recipientId = null,
  forceSend = false
) {
  const accountId = account.id || account.instagram_user_id;

  // Duplicate protection per user/thread: only send once until status changes or user verifies
  if (!forceSend && recipientId && hasActiveFollowVerification(accountId, recipientId)) {
    console.log(`[FOLLOW VERIFY] Follow verification prompt ALREADY sent to user ${recipientId} (@${commenterUsername}). Duplicate DM suppressed ✅`);
    return { ok: true, skippedDuplicate: true };
  }

  const text = formatReplyText(DEFAULT_FOLLOW_REQUIRED_DM, commenterUsername);
  const cleanUsername = String(account.username || "").replace(/^@/, "").trim();
  const profileUrl = cleanUsername ? `https://www.instagram.com/${cleanUsername}/` : "https://www.instagram.com/";

  // The first private reply must target the comment. Sending directly to the
  // user before the messaging window opens is rejected by Meta (2534022).
  const recipient = commentId ? { comment_id: commentId } : { id: recipientId };

  // First DM after comment: show both the profile link and manual follow check.
  const payload = {
    recipient,
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text,
          buttons: [
            {
              type: "web_url",
              url: profileUrl,
              title: "Follow بکە"
            },
            {
              type: "postback",
              title: "Followم کرد",
              payload: "CHECK_FOLLOW_STATUS"
            }
          ]
        }
      }
    }
  };

  const buttonResult = await fetchJsonWithRetry(
    `https://graph.instagram.com/v26.0/${account.instagram_user_id}/messages`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${account.access_token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    },
    "FOLLOW REQUIRED BUTTON DM",
    1
  );

  if (buttonResult.ok) {
    if (recipientId) {
      markFollowVerificationSent(accountId, recipientId, {
        account,
        commentId,
        commenterUsername
      });
    }
    return buttonResult;
  }

  // Fallback to text if the button template is unavailable.
  const fallbackPayload = {
    recipient,
    message: {
      text: `${text}\n\nفۆڵۆومان بکە:\n${profileUrl}\n\nدوای فۆڵۆوکردن بنووسە: Followم کرد`
    }
  };

  const fallbackResult = await fetchJsonWithRetry(
    `https://graph.instagram.com/v26.0/${account.instagram_user_id}/messages`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${account.access_token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(fallbackPayload)
    },
    "FOLLOW REQUIRED TEXT FALLBACK",
    1
  );

  if (fallbackResult.ok && recipientId) {
    markFollowVerificationSent(accountId, recipientId, {
      account,
      commentId,
      commenterUsername
    });
  }

  return fallbackResult;
}

// Send single "Followم کرد" button when user returns to the DM conversation
async function sendFollowCheckButton(account, recipientId, promptText = "ئەگەر فۆڵۆوت کردووە، کلیک لەسەر دوگمەی خوارەوە بکە بۆ وەرگرتنی لینکەکە:") {
  if (!recipientId || !account?.access_token) return { ok: false };

  const payload = {
    recipient: { id: recipientId },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: promptText,
          buttons: [
            {
              type: "postback",
              title: "Followم کرد",
              payload: "CHECK_FOLLOW_STATUS"
            }
          ]
        }
      }
    }
  };

  const buttonResult = await fetchJsonWithRetry(
    `https://graph.instagram.com/v26.0/${account.instagram_user_id}/messages`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${account.access_token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    },
    "FOLLOW CHECK BUTTON DM",
    1
  );

  if (!buttonResult.ok) {
    return fetchJsonWithRetry(
      `https://graph.instagram.com/v26.0/${account.instagram_user_id}/messages`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${account.access_token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          recipient: { id: recipientId },
          message: {
            text: `${promptText}\n\nپاش فۆڵۆوکردن، لێرە بنووسە "Followم کرد"`
          }
        })
      },
      "FOLLOW CHECK TEXT FALLBACK",
      1
    );
  }

  return buttonResult;
}

// Send single "Follow بکە" button asking user to follow again if they clicked "Followم کرد" without following
async function sendFollowAgainPrompt(account, recipientId, username = "") {
  if (!recipientId || !account?.access_token) return { ok: false };

  const cleanUsername = String(account.username || "").replace(/^@/, "").trim();
  const profileUrl = cleanUsername ? `https://www.instagram.com/${cleanUsername}/` : "https://www.instagram.com/";
  const text = `هێشتا فۆڵۆوت نەکردووە! تکایە سەرەتا پەیجەکەمان (@${cleanUsername}) فۆڵۆو بکە، پاشان وەرەوە بۆ وەرگرتنی لینکەکە ❤️✨`;

  const payload = {
    recipient: { id: recipientId },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text,
          buttons: [
            {
              type: "web_url",
              url: profileUrl,
              title: "Follow بکە"
            }
          ]
        }
      }
    }
  };

  const buttonResult = await fetchJsonWithRetry(
    `https://graph.instagram.com/v26.0/${account.instagram_user_id}/messages`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${account.access_token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    },
    "FOLLOW AGAIN BUTTON DM",
    1
  );

  if (!buttonResult.ok) {
    return fetchJsonWithRetry(
      `https://graph.instagram.com/v26.0/${account.instagram_user_id}/messages`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${account.access_token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          recipient: { id: recipientId },
          message: {
            text: `${text}\n\nفۆڵۆومان بکە:\n${profileUrl}`
          }
        })
      },
      "FOLLOW AGAIN TEXT FALLBACK",
      1
    );
  }

  return buttonResult;
}

const sendFollowRequiredButton = sendFollowRequiredMessage;

async function sendPrivateButton(
  account,
  commentId,
  commenterUsername = "",
  recipientId = null
) {
  const channelUrl =
    await getVerifiedSafeUrlForAccount(account);

  const rawText =
    account.private_text ||
    DEFAULT_PRIVATE_TEXT;

  const text =
    formatReplyText(
      rawText,
      commenterUsername
    );

  const buttonTitle =
    account.button_title ||
    DEFAULT_BUTTON_TITLE;

  const recipient = recipientId ? { id: recipientId } : { comment_id: commentId };

  const payload = {
    recipient,
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text,
          buttons: [
            {
              type: "web_url",
              url: channelUrl,
              title: buttonTitle
            }
          ]
        }
      }
    }
  };

  return fetchJsonWithRetry(
    `https://graph.instagram.com/v26.0/${account.instagram_user_id}/messages`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${account.access_token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    },
    "PRIVATE BUTTON",
    1
  );
}

// =====================================================
// PRIVATE FALLBACK
// =====================================================

async function sendPrivateFallback(
  account,
  commentId,
  commenterUsername = "",
  recipientId = null
) {
  const channelUrl =
    await getVerifiedSafeUrlForAccount(account);

  const rawText =
    account.private_text ||
    DEFAULT_PRIVATE_TEXT;

  const text =
    formatReplyText(
      rawText,
      commenterUsername
    );

  const buttonTitle =
    account.button_title ||
    DEFAULT_BUTTON_TITLE;

  const recipient = recipientId ? { id: recipientId } : { comment_id: commentId };

  const payload = {
    recipient,
    message: {
      text: `${text}\n\n${buttonTitle}\n\n${channelUrl}`
    }
  };

  return fetchJsonWithRetry(
    `https://graph.instagram.com/v26.0/${account.instagram_user_id}/messages`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${account.access_token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    },
    "PRIVATE FALLBACK"
  );
}

// =====================================================
// PRIVATE REPLY (BUTTON OR FALLBACK)
// =====================================================

async function sendPrivateReply(
  account,
  commentId,
  commenterUsername = "",
  recipientId = null
) {
  const buttonResult =
    await sendPrivateButton(
      account,
      commentId,
      commenterUsername,
      recipientId
    );

  if (buttonResult.ok) {
    console.log(`Private button sent @${account.username} ✅`);
    return buttonResult;
  }

  console.log("Button unavailable. Trying fallback.");

  return sendPrivateFallback(
    account,
    commentId,
    commenterUsername,
    recipientId
  );
}

// =====================================================
// PROCESS COMMENT JOB
// =====================================================

async function handleCommentAutomation(job) {
  console.log("======================================");
  console.log("PROCESS COMMENT:", {
    webhookInstagramId: job.instagramUserId,
    commentId: job.commentId,
    username: job.commenterUsername,
    text: job.commentText
  });
  console.log("======================================");

  let account = await resolveWebhookAccount(job.instagramUserId);
  if (!account) {
    console.error("ACCOUNT COULD NOT BE RESOLVED:", job.instagramUserId);
    return;
  }

  account = await refreshAccountTokenIfNeeded(account);
  let effectiveAccount = account;
  const automation = await getAutomationForAccount(account);

  if (automation) {
    if (automation.enabled === false) {
      console.log(`Automation OFF for @${account.username}. Comment skipped.`);
      return;
    }
    effectiveAccount = buildEffectiveAutomationAccount(account, automation);
    console.log(`Using saved public.automations settings for @${account.username} ✅`);
  } else {
    console.log(`No automation row for @${account.username}; using existing account settings.`);
  }

  // 1. Send Public Comment Reply
  const publicResult = await sendPublicReply(
    effectiveAccount,
    job.commentId,
    job.commenterUsername
  );

  if (publicResult.ok) {
    console.log(`Public reply sent @${account.username} ✅`);
  } else {
    console.error(`PUBLIC REPLY FAILED @${account.username}:`, publicResult.data);
  }

  // Safety gap before verifying follow and opening DM
  await sleep(750);

  // 2. Follow Verification before link delivery
  console.log(`[FOLLOW VERIFY] Checking follow status for user @${job.commenterUsername} (${job.commenterId})...`);
  const followCheck = await checkUserFollowsAccount(account, job.commenterId);

  let privateResult = null;
  let sentFollowRequest = false;

  if (followCheck.isFollowing) {
    console.log(`[FOLLOW VERIFY] User @${job.commenterUsername} is FOLLOWING ✅ Delivering private link.`);
    clearFollowVerificationState(account.id || account.instagram_user_id, job.commenterId);
    privateResult = await sendPrivateReply(
      effectiveAccount,
      job.commentId,
      job.commenterUsername,
      job.commenterId
    );
  } else {
    // Check if user already has an active follow verification message sent
    const isAlreadyPending = hasActiveFollowVerification(account.id || account.instagram_user_id, job.commenterId);
    if (isAlreadyPending) {
      console.log(`[FOLLOW VERIFY] User @${job.commenterUsername} (${job.commenterId}) is NOT FOLLOWING, but ALREADY has pending follow prompt buttons. Duplicate DM suppressed.`);
      privateResult = { ok: true, skippedDuplicate: true };
      sentFollowRequest = true;
    } else {
      console.log(`[FOLLOW VERIFY] User @${job.commenterUsername} is NOT FOLLOWING ❌ Sending DM with "Follow بکە / Followم کرد" buttons.`);
      privateResult = await sendFollowRequiredMessage(
        effectiveAccount,
        job.commentId,
        job.commenterUsername,
        job.commenterId
      );
      sentFollowRequest = true;

      // Track user for follow unlock in same DM
      markFollowVerificationSent(account.id || account.instagram_user_id, job.commenterId, {
        account,
        effectiveAccount,
        commentId: job.commentId,
        commenterUsername: job.commenterUsername
      });
    }
  }

  if (privateResult && privateResult.ok) {
    console.log(`Private DM sent @${account.username} (${sentFollowRequest ? "Follow Profile Button Sent" : "Link Delivered"}) ✅`);
  } else {
    console.error(`PRIVATE DM FAILED @${account.username}:`, privateResult ? privateResult.data : "Unknown error");
  }

  // 3. Update Stats & Record Activity Logs if successful
  if (publicResult.ok || (privateResult && privateResult.ok)) {
    if (automation?.id && !sentFollowRequest) {
      await updateAutomationStats(automation.id);
    }

    await recordActivityLog({
      userId: account.user_id,
      accountId: account.id,
      username: account.username,
      commenterUsername: job.commenterUsername,
      commentText: job.commentText,
      replyText: sentFollowRequest
        ? "Follow prompt button sent (waiting for follow unlock in DM)"
        : effectiveAccount.public_reply
    });
  }

  return {
    executed: publicResult.ok || (privateResult && privateResult.ok),
    accountId: account.id,
    delaySeconds: automation?.delay_seconds ?? 8,
    randomJitterEnabled: automation?.random_jitter_enabled ?? true
  };
}


// =====================================================
// QUEUE WORKER
// =====================================================

async function processAutomationQueue() {

  if (
    queueWorkerRunning
  ) {

    return;
  }

  queueWorkerRunning =
    true;

  try {

    while (
      automationQueue.length >
      0
    ) {

      if (
        !AUTOMATION_ENABLED
      ) {

        console.log(
          "Automation paused."
        );

        break;
      }

      const now =
        Date.now();

      let eligibleIndex =
        -1;

      // Anti-Head-of-Line Blocking: Scan queue to find first eligible job
      for (
        let i = 0;
        i < automationQueue.length;
        i++
      ) {

        const candidateJob =
          automationQueue[i];

        const resolvedAccount =
          await resolveWebhookAccount(
            candidateJob.instagramUserId
          );

        if (
          !resolvedAccount
        ) {
          eligibleIndex = i;
          break;
        }

        const accId =
          resolvedAccount.id;

        const nextAllowed =
          accountNextAllowedTimeMap.get(accId) || 0;

        if (
          now < nextAllowed
        ) {
          continue; // This account is waiting on its own delay
        }

        const autoRow =
          await getAutomationForAccount(
            resolvedAccount
          );

        const hourlyLimit =
          autoRow?.hourly_limit ?? 80;

        const rateCheck =
          checkAccountRateLimit(
            accId,
            hourlyLimit
          );

        if (
          !rateCheck.allowed
        ) {
          continue; // Account hit its hourly limit, check another account
        }

        eligibleIndex =
          i;
        break;
      }

      if (
        eligibleIndex === -1
      ) {
        // All queued jobs belong to accounts that are currently waiting on delay or hourly window
        break;
      }

      const [job] =
        automationQueue.splice(
          eligibleIndex,
          1
        );

      try {

        const result =
          await handleCommentAutomation(
            job
          );

        if (
          result?.executed &&
          result?.accountId
        ) {

          recordAccountSend(
            result.accountId
          );

          const nextDelayMs =
            calculateNextDelayMs(
              result.delaySeconds,
              result.randomJitterEnabled
            );

          accountNextAllowedTimeMap.set(
            result.accountId,
            Date.now() + nextDelayMs
          );

          console.log(
            `Next execution for account #${result.accountId} allowed in ${(nextDelayMs / 1000).toFixed(1)}s`
          );
        }

      } catch (error) {

        console.error(
          "AUTOMATION JOB ERROR:",
          error
        );
      }
    }

  } finally {

    queueWorkerRunning =
      false;

    if (
      automationQueue.length >
      0 &&
      AUTOMATION_ENABLED
    ) {

      setTimeout(
        processAutomationQueue,
        1500
      );
    }
  }
}


// =====================================================
// ADD COMMENT TO QUEUE
// =====================================================

function enqueueCommentAutomation(
  job
) {

  if (
    processedComments.has(
      job.commentId
    )
  ) {

    console.log(
      "Duplicate comment skipped:",
      job.commentId
    );

    return;
  }

  processedComments.add(
    job.commentId
  );

  if (
    processedComments.size >
    5000
  ) {

    processedComments.clear();

    processedComments.add(
      job.commentId
    );
  }

  automationQueue.push(
    job
  );

  console.log(
    `Comment queued ✅ Queue: ${automationQueue.length}`
  );

  setImmediate(
    processAutomationQueue
  );
}


// =====================================================
// HOME ROUTE
// =====================================================

app.get(
  "/",
  async (
    req,
    res
  ) => {

    const indexPath = path.join(distPath, "index.html");
    if (fs.existsSync(indexPath)) {
      return res.sendFile(indexPath);
    }

    try {

      const result =
        await pool.query(
          `
          select
            count(*)::int as total,
            count(*) filter (
              where enabled = true
            )::int as active
          from instagram_accounts
          `
        );

      const total =
        result.rows[0]?.total ||
        0;

      const active =
        result.rows[0]?.active ||
        0;

      return res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ODD BOT - Server</title>
</head>

<body style="font-family:Arial,sans-serif; text-align:center; padding:80px 20px; background:#0f172a; color:#fff;">

<h1>ODD BOT</h1>
<h2>Instagram Automation Server</h2>

<p>Automation: <strong>${AUTOMATION_ENABLED ? "ENABLED ✅" : "PAUSED"}</strong></p>
<p>Connected Accounts: <strong>${total}</strong></p>
<p>Active Accounts: <strong>${active}</strong></p>
<p>Database: <strong>CONNECTED ✅</strong></p>

</body>
</html>
      `);

    } catch (error) {

      console.error(
        "HOME DATABASE ERROR:",
        error
      );

      return res
        .status(500)
        .send(
          "Database connection failed."
        );
    }
  }
);


// =====================================================
// DIRECT CONNECT BLOCKED ROUTE
// =====================================================

app.get(
  "/connect",
  (
    req,
    res
  ) => {

    return res
      .status(400)
      .send(
        "Please connect Instagram from your logged-in ODD BOT dashboard."
      );
  }
);


// =====================================================
// HEALTH ROUTE
// =====================================================

app.get(
  "/health",
  async (
    req,
    res
  ) => {

    try {

      const database =
        await pool.query(
          "select now()"
        );

      return res
        .status(200)
        .json({

          success:
            true,

          database:
            "connected",

          database_time:
            database.rows[0].now,

          automation_enabled:
            AUTOMATION_ENABLED,

          queue:
            automationQueue.length
        });

    } catch (error) {

      return res
        .status(500)
        .json({

          success:
            false,

          database:
            "failed",

          error:
            error.message
        });
    }
  }
);


// =====================================================
// DASHBOARD AUTH
// =====================================================

async function requireDashboardKey(
  req,
  res,
  next
) {

  const authorization =
    String(
      req.headers.authorization ||
      ""
    ).trim();

  const expectedAdmin =
    DASHBOARD_API_KEY
      ? `Bearer ${DASHBOARD_API_KEY}`
      : "";

  if (
    expectedAdmin &&
    authorization ===
    expectedAdmin
  ) {

    req.oddBotDashboardAdmin =
      true;

    return next();
  }

  const accessToken =
    getSupabaseAccessTokenFromRequest(
      req
    );

  const user =
    await verifySupabaseUser(
      accessToken
    );

  if (
    user?.id
  ) {

    req.oddBotUser =
      user;

    req.oddBotDashboardAdmin =
      false;

    return next();
  }

  return res
    .status(401)
    .json({
      success:
        false,

      error:
        "Unauthorized"
    });
}


// =====================================================
// DASHBOARD API
// =====================================================

app.get(
  "/api/dashboard",
  requireDashboardKey,
  async (
    req,
    res
  ) => {

    try {

      const dashboardUserId =
        req.oddBotUser?.id ||
        null;

      const result =
        dashboardUserId
          ? await pool.query(
              `
              select
                id,
                instagram_user_id,
                username,
                enabled,
                created_at,
                updated_at,
                token_expires_at
              from instagram_accounts
              where user_id = $1
              order by created_at desc
              `,
              [
                dashboardUserId
              ]
            )
          : await pool.query(
              `
              select
                id,
                instagram_user_id,
                username,
                enabled,
                created_at,
                updated_at,
                token_expires_at
              from instagram_accounts
              order by created_at desc
              `
            );

      const now =
        Date.now();

      const accounts =
        result.rows.map(
          account => {

            const expiresAt =
              account.token_expires_at
                ? new Date(
                    account.token_expires_at
                  ).getTime()
                : null;

            let status =
              "active";

            if (
              account.enabled ===
              false
            ) {

              status =
                "disabled";

            } else if (
              expiresAt &&
              expiresAt <= now
            ) {

              status =
                "expired";
            }

            return {

              id:
                account.id,

              username:
                account.username ||
                "",

              instagram_user_id:
                account.instagram_user_id ||
                "",

              status,

              enabled:
                account.enabled !==
                false,

              connected_at:
                account.created_at,

              updated_at:
                account.updated_at,

              token_expires_at:
                account.token_expires_at
            };
          }
        );

      const activeAccounts =
        accounts.filter(
          account =>
            account.status ===
            "active"
        ).length;

      const disabledAccounts =
        accounts.filter(
          account =>
            account.status ===
            "disabled"
        ).length;

      const expiredAccounts =
        accounts.filter(
          account =>
            account.status ===
            "expired"
        ).length;

      return res
        .status(200)
        .json({

          success:
            true,

          stats: {

            connected_accounts:
              accounts.length,

            active_accounts:
              activeAccounts,

            disabled_accounts:
              disabledAccounts,

            expired_accounts:
              expiredAccounts,

            queue:
              automationQueue.length
          },

          accounts
        });

    } catch (error) {

      console.error(
        "DASHBOARD API ERROR:",
        error
      );

      return res
        .status(500)
        .json({

          success:
            false,

          error:
            "Dashboard data unavailable."
        });
    }
  }
);


// =====================================================
// LOAD AUTOMATION SETTINGS API
// =====================================================

app.get(
  "/api/automation",
  requireSupabaseUser,
  async (
    req,
    res
  ) => {

    try {

      const accountId =
        String(
          req.query?.account_id ||
          req.query?.accountId ||
          ""
        ).trim();

      if (
        !accountId
      ) {

        return res
          .status(400)
          .json({

            success:
              false,

            error:
              "account_id is required."
          });
      }

      const account =
        await getOwnedInstagramAccount(
          req.oddBotUser.id,
          accountId
        );

      if (
        !account
      ) {

        return res
          .status(404)
          .json({

            success:
              false,

            error:
              "Instagram account not found for this user."
          });
      }

      const automation =
        await getAutomationForAccount(
          account
        );

      return res
        .status(200)
        .json({

          success:
            true,

          account: {

            id:
              account.id,

            username:
              account.username ||
              "",

            enabled:
              account.enabled !==
              false
          },

          automation:
            serializeAutomationForClient(
              account,
              automation
            )
        });

    } catch (error) {

      console.error(
        "LOAD AUTOMATION ERROR:",
        error
      );

      return res
        .status(500)
        .json({

          success:
            false,

          error:
            "Unable to load automation settings."
        });
    }
  }
);


// =====================================================
// SAVE AUTOMATION SETTINGS API
// =====================================================

app.post(
  "/api/automation",
  requireSupabaseUser,
  async (
    req,
    res
  ) => {

    try {

      const accountId =
        String(
          req.body?.account_id ||
          req.body?.accountId ||
          ""
        ).trim();

      console.log(`[DEBUG] [server.js:saveAutomation] Started for user=${req.oddBotUser?.id}, accountId=${accountId}`);

      let account = null;
      if (accountId && accountId !== 'primary') {
        account = await getOwnedInstagramAccount(
          req.oddBotUser.id,
          accountId
        );
      }

      if (!account) {
        // Look up primary or first account for this user
        const anyAccount = await pool.query(
          `select * from instagram_accounts where user_id = $1 order by id asc limit 1`,
          [req.oddBotUser.id]
        );
        account = anyAccount.rows?.[0] || {
          id: accountId || 'primary',
          user_id: req.oddBotUser.id,
          username: req.oddBotUser.email?.split('@')[0] || 'primary_account',
          channel_url: DEFAULT_CHANNEL_URL,
        };
      }

      const input =
        normalizeAutomationInput(
          req.body ||
          {}
        );

      // ==========================================
      // 1. Receiving channel URL
      // ==========================================
      console.log(`[DEBUG] [STEP 1: RECEIVE_URL] [BEFORE] Extracting incoming channel URL from request body...`);
      const incomingUrl =
        input.channelUrl.trim();
      console.log(`[DEBUG] [STEP 1: RECEIVE_URL] [AFTER] Received incoming channel URL: "${incomingUrl}"`);

      let isPendingCustom = false;
      let effectiveChannelUrl = incomingUrl;

      if (incomingUrl) {
        if (!incomingUrl.toLowerCase().startsWith("https://")) {
          console.warn(`[DEBUG] [STEP 1: RECEIVE_URL] HTTPS required: "${incomingUrl}"`);
          return res
            .status(400)
            .json({
              success: false,
              code: "UNSAFE_DESTINATION_URL",
              error: "Channel URL must use secure HTTPS."
            });
        }

        // ==========================================
        // 2. identifyPlatform result
        // ==========================================
        console.log(`[DEBUG] [STEP 2: IDENTIFY_PLATFORM] [BEFORE] Identifying platform for URL: "${incomingUrl}"`);
        const platformInfo =
          identifyPlatform(incomingUrl);
        console.log(`[DEBUG] [STEP 2: IDENTIFY_PLATFORM] [AFTER] Result: isOfficial=${platformInfo.isOfficial}, platform=${platformInfo.platform}, domain="${platformInfo.domain}"`);

        if (platformInfo.isInvalidHost) {
          console.warn(`[DEBUG] [STEP 2: IDENTIFY_PLATFORM] Invalid private/local host: "${platformInfo.domain}"`);
          return res
            .status(400)
            .json({
              success: false,
              code: "UNSAFE_DESTINATION_URL",
              error: "Localhost and private IP addresses are strictly prohibited."
            });
        }

        if (!platformInfo.isOfficial) {
          // ==========================================
          // 3. Google Web Risk result
          // ==========================================
          console.log(`[DEBUG] [STEP 3: WEB_RISK] [BEFORE] Scanning custom URL with Google Web Risk: "${incomingUrl}"`);
          const webRisk =
            await checkGoogleWebRisk(incomingUrl);
          console.log(`[DEBUG] [STEP 3: WEB_RISK] [AFTER] Result: ok=${webRisk.ok}, safe=${webRisk.safe}, threats=${JSON.stringify(webRisk.threats || [])}`);

          if (!webRisk.ok) {
            console.warn(`[DEBUG] [STEP 3: WEB_RISK] Google Web Risk verification failed/timed out for: "${incomingUrl}"`);
            return res
              .status(502)
              .json({
                success: false,
                code: "WEB_RISK_CHECK_FAILED",
                error: "Google Web Risk verification failed or timed out. Custom URL cannot be approved."
              });
          }

          if (webRisk.safe === false) {
            console.warn(`[DEBUG] [STEP 3: WEB_RISK] Malicious threats detected by Google Web Risk: ${JSON.stringify(webRisk.threats)}`);
            return res
              .status(400)
              .json({
                success: false,
                code: "UNSAFE_DESTINATION_URL",
                threats: webRisk.threats,
                error: "Malicious destination URL detected by Google Web Risk."
              });
          }

          // Check if this exact custom URL is already approved by admin
          const existingReview =
            await pool.query(
              `
              select *
              from public.link_review_requests
              where user_id = $1
              and (lower(requested_url) = lower($2) or lower(coalesce(destination_url, '')) = lower($2))
              order by created_at desc
              limit 1
              `,
              [
                req.oddBotUser.id,
                incomingUrl
              ]
            );

          const reviewRow =
            existingReview.rows?.[0];

          if (!reviewRow || (reviewRow.review_status !== "approved" && reviewRow.status !== "approved")) {
            isPendingCustom = true;

            // Retain currently approved channel_url in automations
            let prevChannelUrl = DEFAULT_CHANNEL_URL;
            try {
              if (typeof account.id === 'number' || (typeof account.id === 'string' && !isNaN(Number(account.id)))) {
                const existingAuto = await getAutomationForAccount(account);
                prevChannelUrl = existingAuto?.channel_url || account.channel_url || DEFAULT_CHANNEL_URL;
              }
            } catch (e) {}

            effectiveChannelUrl = prevChannelUrl;

            const userEmail = req.oddBotUser?.email || String(req.headers["x-user-email"] || "").toLowerCase().trim();

            // ==========================================
            // 4. INSERT INTO link_review_requests
            // ==========================================
            console.log(`[DEBUG] [STEP 4: DB_INSERT] [BEFORE] Inserting link review request into database: URL="${incomingUrl}", user="${req.oddBotUser.id}", account="${account.id}"`);
            const insertRes = await pool.query(
              `
              insert into public.link_review_requests (
                user_id,
                user_email,
                account_id,
                requested_url,
                destination_url,
                normalized_url,
                domain,
                platform,
                safety_status,
                review_status,
                status,
                threat_types,
                created_at,
                updated_at
              )
              values ($1, $2, $3, $4, $4, $5, $6, 'custom', 'safe', 'pending', 'pending', '[]'::jsonb, now(), now())
              returning id, status, review_status, created_at
              `,
              [
                req.oddBotUser.id,
                userEmail,
                String(account.id || accountId || "primary"),
                incomingUrl,
                incomingUrl.toLowerCase(),
                platformInfo.domain || ""
              ]
            );

            console.log(`[DEBUG] [STEP 4: DB_INSERT] [AFTER] Successfully inserted link_review_request in PostgreSQL:`, insertRes.rows?.[0]);
            console.log(
              `Custom URL queued for admin review: ${incomingUrl} (Account: #${account.id})`
            );
          } else {
            console.log(`[DEBUG] Custom URL "${incomingUrl}" is already approved. Activating directly.`);
          }
        }
      }

      // Save automation with the approved/effective URL
      const saveInput = {
        ...input,
        channelUrl: effectiveChannelUrl
      };

      const automation =
        await saveAutomationForOwnedAccount(
          account,
          saveInput
        );

      if (isPendingCustom) {
        return res
          .status(202)
          .json({
            success: true,
            code: "LINK_PENDING_ADMIN_APPROVAL",
            message: "Custom website submitted for Admin approval before activation.",
            requested_url: incomingUrl,
            current_channel_url: effectiveChannelUrl,
            account: {
              id: account.id,
              username: account.username || ""
            },
            automation: serializeAutomationForClient(
              account,
              automation
            )
          });
      }

      return res
        .status(200)
        .json({

          success:
            true,

          message:
            "Automation settings saved.",

          account: {

            id:
              account.id,

            username:
              account.username ||
              ""
          },

          automation:
            serializeAutomationForClient(
              account,
              automation
            )
        });

    } catch (error) {

      console.error(
        "SAVE AUTOMATION ERROR:",
        error
      );

      return res
        .status(500)
        .json({

          success:
            false,

          error:
            "Unable to save automation settings.",

          details:
            process.env.NODE_ENV ===
            "production"
              ? undefined
              : error.message
        });
    }
  }
);


// =====================================================
// ADMIN AUTH MIDDLEWARE
// =====================================================

async function requireAdminAuth(req, res, next) {
  const authorization =
    String(
      req.headers.authorization ||
      ""
    ).trim();

  const expectedAdmin =
    DASHBOARD_API_KEY
      ? `Bearer ${DASHBOARD_API_KEY}`
      : "";

  if (
    expectedAdmin &&
    authorization === expectedAdmin
  ) {
    req.oddBotAdmin = true;
    req.adminEmail = ADMIN_EMAIL;
    return next();
  }

  const customUserEmail = String(
    req.headers["x-user-email"] || req.headers["x-app-user-email"] || ""
  ).toLowerCase().trim();

  const accessToken =
    getSupabaseAccessTokenFromRequest(req);

  if (accessToken) {
    const user =
      await verifySupabaseUser(accessToken);

    if (user?.id) {
      const email =
        String(user.email || "").toLowerCase().trim();

      if (email === ADMIN_EMAIL.toLowerCase()) {
        req.oddBotUser = user;
        req.oddBotAdmin = true;
        req.adminEmail = email;
        return next();
      }
    }
  }

  if (customUserEmail && customUserEmail === ADMIN_EMAIL.toLowerCase()) {
    req.oddBotAdmin = true;
    req.adminEmail = ADMIN_EMAIL;
    return next();
  }

  return res
    .status(403)
    .json({
      success: false,
      error: "Forbidden: Admin access required (oagorgor@gmail.com)."
    });
}


// =====================================================
// ADMIN LINK REVIEWS API
// =====================================================

app.get(
  "/api/admin/link-reviews",
  requireAdminAuth,
  async (req, res) => {
    try {
      const status = req.query.status;
      let query = `
        select *
        from public.link_review_requests
      `;
      const params = [];
      if (status && ["pending", "approved", "rejected"].includes(status)) {
        query += ` where review_status = $1 or status = $1`;
        params.push(status);
      }
      query += ` order by created_at desc`;

      const result = await pool.query(query, params);
      const mapped = result.rows.map(r => ({
        id: String(r.id),
        user_id: r.user_id,
        user_email: r.user_email || '',
        account_id: String(r.account_id || 'primary'),
        automation_id: r.automation_id || '',
        destination_url: r.destination_url || r.requested_url || '',
        requested_url: r.requested_url || r.destination_url || '',
        domain: r.domain || '',
        platform: r.platform || 'custom',
        is_official_platform: r.is_official_platform || false,
        web_risk_status: r.web_risk_status || r.safety_status || 'safe',
        safety_status: r.safety_status || r.web_risk_status || 'safe',
        status: r.status || r.review_status || 'pending',
        review_status: r.review_status || r.status || 'pending',
        rejection_reason: r.rejection_reason || null,
        reviewed_by: r.reviewed_by || null,
        reviewed_at: r.reviewed_at || null,
        created_at: r.created_at,
        updated_at: r.updated_at,
      }));
      return res.status(200).json(mapped);
    } catch (err) {
      console.error("GET ADMIN LINK REVIEWS ERROR:", err.message);
      return res.status(500).json({ success: false, error: err.message });
    }
  }
);

app.post(
  "/api/admin/link-reviews/:id/approve",
  requireAdminAuth,
  async (req, res) => {
    const { id } = req.params;
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const reviewRes = await client.query(
        `
        update public.link_review_requests
        set
          review_status = 'approved',
          status = 'approved',
          reviewed_by = $1,
          reviewed_at = now(),
          updated_at = now()
        where id::text = $2
        returning *
        `,
        [req.adminEmail || ADMIN_EMAIL, String(id)]
      );

      if (!reviewRes.rows[0]) {
        await client.query("ROLLBACK");
        return res.status(404).json({ success: false, error: "Link review request not found." });
      }

      const review = reviewRes.rows[0];
      const targetUrl = review.destination_url || review.requested_url;

      // Update automations table within the same transaction using account_id + user_id
      if (review.account_id && review.user_id) {
        await client.query(
          `
          update public.automations
          set
            channel_url = $1,
            updated_at = now()
          where account_id = $2
          and user_id = $3
          `,
          [targetUrl, review.account_id, review.user_id]
        );
      }

      await client.query("COMMIT");

      return res.status(200).json({
        success: true,
        message: `Link ${targetUrl} approved and applied to automation.`,
        review: {
          ...review,
          destination_url: targetUrl,
          status: 'approved',
        }
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("ADMIN APPROVE LINK ERROR:", err.message);
      return res.status(500).json({ success: false, error: err.message });
    } finally {
      client.release();
    }
  }
);

app.post(
  "/api/admin/link-reviews/:id/reject",
  requireAdminAuth,
  async (req, res) => {
    const { id } = req.params;
    const reason = String(req.body?.rejection_reason || req.body?.reason || "Rejected by administrator").trim();

    try {
      const result = await pool.query(
        `
        update public.link_review_requests
        set
          review_status = 'rejected',
          status = 'rejected',
          rejection_reason = $1,
          reviewed_by = $2,
          reviewed_at = now(),
          updated_at = now()
        where id::text = $3
        returning *
        `,
        [reason, req.adminEmail || ADMIN_EMAIL, String(id)]
      );

      if (!result.rows[0]) {
        return res.status(404).json({ success: false, error: "Link review request not found." });
      }

      const review = result.rows[0];
      const targetUrl = review.destination_url || review.requested_url;

      // Admin Reject does NOT change the currently approved channel_url
      return res.status(200).json({
        success: true,
        message: `Link ${targetUrl} rejected.`,
        review: {
          ...review,
          destination_url: targetUrl,
          status: 'rejected',
        }
      });
    } catch (err) {
      console.error("ADMIN REJECT LINK ERROR:", err.message);
      return res.status(500).json({ success: false, error: err.message });
    }
  }
);


// =====================================================
// USER PROFILE & ADMIN APPROVALS API
// =====================================================

app.get("/api/user/profile", async (req, res) => {
  const accessToken = getSupabaseAccessTokenFromRequest(req);
  let userId = String(req.query.user_id || req.headers["x-user-id"] || "").trim();
  let email = String(req.query.email || req.headers["x-user-email"] || "").toLowerCase().trim();

  if (accessToken) {
    const verified = await verifySupabaseUser(accessToken);
    if (verified?.id) {
      userId = verified.id;
      if (verified.email) email = verified.email.toLowerCase().trim();
    }
  }

  if (!userId) {
    return res.status(400).json({ error: "User ID required." });
  }

  const isAdmin = email === ADMIN_EMAIL.toLowerCase();

  try {
    // Check if email is pre-approved
    const approvedCheck = await pool.query(
      `select * from public.approved_emails where lower(email) = lower($1)`,
      [email || ""]
    );
    const isPreApproved = isAdmin || approvedCheck.rows.length > 0;

    const existing = await pool.query(
      `select * from public.user_profiles where user_id = $1 or (email != '' and lower(email) = lower($2)) limit 1`,
      [userId, email || ""]
    );

    if (existing.rows.length > 0) {
      const row = existing.rows[0];
      const finalStatus = isPreApproved ? "approved" : (row.approval_status || "pending");
      return res.json({
        user_id: row.user_id || userId,
        email: row.email || email,
        approval_status: finalStatus,
        role: isAdmin ? "admin" : (row.role || "user"),
        created_at: row.created_at,
        updated_at: row.updated_at
      });
    }

    // Insert new profile
    const initialStatus = isPreApproved ? "approved" : "pending";
    const inserted = await pool.query(
      `insert into public.user_profiles (user_id, email, approval_status, role)
       values ($1, $2, $3, $4)
       on conflict (user_id) do update set
         email = coalesce(nullif(excluded.email, ''), public.user_profiles.email),
         updated_at = now()
       returning *`,
      [userId, email || `user_${userId.slice(0, 8)}@workspace.io`, initialStatus, isAdmin ? "admin" : "user"]
    );

    return res.json(inserted.rows[0]);
  } catch (err) {
    console.error("GET USER PROFILE ERROR:", err.message);
    return res.json({
      user_id: userId,
      email: email,
      approval_status: isAdmin ? "approved" : "pending",
      role: isAdmin ? "admin" : "user"
    });
  }
});

app.post("/api/user/profile/sync", async (req, res) => {
  const accessToken = getSupabaseAccessTokenFromRequest(req);
  let userId = String(req.body?.user_id || req.headers["x-user-id"] || "").trim();
  let email = String(req.body?.email || req.headers["x-user-email"] || "").toLowerCase().trim();

  if (accessToken) {
    const verified = await verifySupabaseUser(accessToken);
    if (verified?.id) {
      userId = verified.id;
      if (verified.email) email = verified.email.toLowerCase().trim();
    }
  }

  if (!userId) {
    return res.status(400).json({ error: "User ID required." });
  }

  const isAdmin = email === ADMIN_EMAIL.toLowerCase();

  try {
    // Check if email is in approved_emails
    const approvedCheck = await pool.query(
      `select * from public.approved_emails where lower(email) = lower($1)`,
      [email || ""]
    );
    const isPreApproved = isAdmin || approvedCheck.rows.length > 0;
    const finalStatus = isPreApproved ? "approved" : (req.body?.approval_status || "pending");

    const result = await pool.query(
      `insert into public.user_profiles (user_id, email, approval_status, role, updated_at)
       values ($1, $2, $3, $4, now())
       on conflict (user_id) do update set
         email = coalesce(nullif(excluded.email, ''), public.user_profiles.email),
         approval_status = case when public.user_profiles.approval_status = 'approved' then 'approved' else excluded.approval_status end,
         updated_at = now()
       returning *`,
      [userId, email || `user_${userId.slice(0, 8)}@workspace.io`, finalStatus, isAdmin ? "admin" : "user"]
    );

    return res.json(result.rows[0]);
  } catch (err) {
    console.error("SYNC USER PROFILE ERROR:", err.message);
    return res.json({
      user_id: userId,
      email: email,
      approval_status: isAdmin ? "approved" : "pending",
      role: isAdmin ? "admin" : "user"
    });
  }
});

app.get("/api/admin/users", requireAdminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `select * from public.user_profiles order by created_at desc`
    );
    return res.json(result.rows);
  } catch (err) {
    console.error("GET ADMIN USERS ERROR:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/admin/users/approve-email", requireAdminAuth, async (req, res) => {
  const email = String(req.body?.email || "").toLowerCase().trim();
  if (!email || !email.includes("@")) {
    return res.status(400).json({ error: "Valid email required." });
  }

  try {
    // 1. Add to approved_emails
    await pool.query(
      `insert into public.approved_emails (email, approved_by)
       values ($1, $2)
       on conflict (email) do nothing`,
      [email, req.adminEmail || ADMIN_EMAIL]
    );

    // 2. Update user_profiles
    const updated = await pool.query(
      `update public.user_profiles
       set approval_status = 'approved', updated_at = now()
       where lower(email) = lower($1)
       returning *`,
      [email]
    );

    if (updated.rows.length === 0) {
      const syntheticId = `usr_${email.replace(/[^a-z0-9]/g, "_").slice(0, 16)}_${Date.now().toString(36)}`;
      await pool.query(
        `insert into public.user_profiles (user_id, email, approval_status, role)
         values ($1, $2, 'approved', $3)
         on conflict (user_id) do nothing`,
        [syntheticId, email, email === ADMIN_EMAIL.toLowerCase() ? "admin" : "user"]
      );
    }

    return res.json({ success: true, message: `Account ${email} approved successfully.` });
  } catch (err) {
    console.error("ADMIN APPROVE EMAIL ERROR:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/admin/users/:id/approve", requireAdminAuth, async (req, res) => {
  const targetId = req.params.id;
  const email = String(req.body?.email || "").toLowerCase().trim();

  try {
    if (email) {
      await pool.query(
        `insert into public.approved_emails (email, approved_by)
         values ($1, $2)
         on conflict (email) do nothing`,
        [email, req.adminEmail || ADMIN_EMAIL]
      );
    }

    const result = await pool.query(
      `update public.user_profiles
       set approval_status = 'approved', updated_at = now()
       where user_id = $1 or (email != '' and lower(email) = lower($2))
       returning *`,
      [targetId, email || ""]
    );

    if (result.rows.length === 0 && email) {
      const inserted = await pool.query(
        `insert into public.user_profiles (user_id, email, approval_status, role)
         values ($1, $2, 'approved', 'user')
         on conflict (user_id) do update set approval_status = 'approved', updated_at = now()
         returning *`,
        [targetId, email]
      );
      return res.json({ success: true, profile: inserted.rows[0] });
    }

    return res.json({ success: true, profile: result.rows[0] });
  } catch (err) {
    console.error("ADMIN APPROVE USER ERROR:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/admin/users/:id/reject", requireAdminAuth, async (req, res) => {
  const targetId = req.params.id;
  const email = String(req.body?.email || "").toLowerCase().trim();

  try {
    if (email) {
      await pool.query(
        `delete from public.approved_emails where lower(email) = lower($1)`,
        [email]
      );
    }

    const result = await pool.query(
      `update public.user_profiles
       set approval_status = 'rejected', updated_at = now()
       where user_id = $1 or (email != '' and lower(email) = lower($2))
       returning *`,
      [targetId, email || ""]
    );

    return res.json({ success: true, profile: result.rows[0] });
  } catch (err) {
    console.error("ADMIN REJECT USER ERROR:", err.message);
    return res.status(500).json({ error: err.message });
  }
});


// =====================================================
// WEBHOOK VERIFY
// =====================================================

app.get(
  "/api/webhooks/instagram",
  (
    req,
    res
  ) => {

    const mode =
      req.query[
        "hub.mode"
      ];

    const token =
      req.query[
        "hub.verify_token"
      ];

    const challenge =
      req.query[
        "hub.challenge"
      ];

    if (
      mode ===
      "subscribe" &&
      token ===
      VERIFY_TOKEN
    ) {

      console.log(
        "Webhook verification successful ✅"
      );

      return res
        .status(200)
        .send(
          challenge
        );
    }

    return res.sendStatus(
      403
    );
  }
);


// =====================================================
// RECEIVE INSTAGRAM WEBHOOK
// =====================================================

app.post(
  "/api/webhooks/instagram",
  (
    req,
    res
  ) => {

    res.sendStatus(
      200
    );

    try {

      const entries =
        req.body.entry ||
        [];

      for (
        const entry of entries
      ) {

        const instagramUserId =
          String(
            entry.id ||
            ""
          );

        const changes =
          entry.changes ||
          [];

        for (
          const change of changes
        ) {

          if (
            change.field !==
            "comments"
          ) {

            continue;
          }

          const value =
            change.value ||
            {};

          const commentId =
            String(
              value.id ||
              ""
            );

          const commentText =
            String(
              value.text ||
              ""
            ).trim();

          const commenterId =
            String(
              value.from?.id ||
              ""
            );

          const commenterUsername =
            String(
              value.from?.username ||
              "unknown"
            );

          if (
            !instagramUserId ||
            !commentId
          ) {

            continue;
          }

          // Deduplicate comment events
          const commentEventId = `comment_${commentId}`;
          if (isDuplicateWebhookEvent(commentEventId)) {
            console.log(`[WEBHOOK] Duplicate comment event ignored: ${commentId}`);
            continue;
          }

          if (
            commenterId &&
            commenterId ===
            instagramUserId
          ) {

            console.log(
              "Own comment skipped."
            );

            continue;
          }

          if (
            !AUTOMATION_ENABLED
          ) {

            continue;
          }

          enqueueCommentAutomation({

            instagramUserId,

            commentId,

            commentText,

            commenterId,

            commenterUsername
          });
        }

        const messaging =
          entry.messaging ||
          [];

        for (
          const event of messaging
        ) {
          const senderId = event.sender?.id || "";
          const postbackPayload = String(event.postback?.payload || "").trim();
          const messageText = String(event.message?.text || "").trim();
          const mid = event.message?.mid || event.postback?.mid || `${senderId}_${event.timestamp}_${postbackPayload || messageText}`;

          // Deduplicate DM messaging and postback events
          const msgEventId = `msg_${mid}`;
          if (isDuplicateWebhookEvent(msgEventId)) {
            console.log(`[DM WEBHOOK] Duplicate messaging event ignored: ${mid}`);
            continue;
          }

          if (!senderId || senderId === instagramUserId) continue;

          console.log(
            "Instagram DM / Messaging event received:",
            {
              account: instagramUserId,
              sender: senderId,
              postback: postbackPayload,
              text: messageText
            }
          );

          // Detect CHECK_FOLLOW_STATUS postback button click or user verification message
          const isCheckFollowPostback =
            postbackPayload === "CHECK_FOLLOW_STATUS" ||
            messageText.toUpperCase() === "CHECK_FOLLOW_STATUS" ||
            messageText.includes("Followم کرد") ||
            messageText.includes("فۆڵۆوم کرد") ||
            messageText.includes("فۆلۆوم کرد") ||
            messageText.includes("فۆڵۆم کرد") ||
            messageText.toLowerCase() === "follow" ||
            messageText.toLowerCase() === "done";

          // Check if user is awaiting follow unlock in this DM conversation
          const pending = pendingFollowUnlocks.get(senderId);

          if (isCheckFollowPostback) {
            resolveWebhookAccount(instagramUserId).then(async (matchedAccount) => {
              if (!matchedAccount) return;
              matchedAccount = await refreshAccountTokenIfNeeded(matchedAccount);

              const followStateKey = getFollowUserStateKey(
                matchedAccount.id || matchedAccount.instagram_user_id,
                senderId
              );
              const followState = followVerificationState.get(followStateKey);
              const currentPending = pendingFollowUnlocks.get(senderId);

              // Claim this verification attempt before awaiting Meta so repeated
              // button clicks cannot deliver the same link more than once.
              if (
                !currentPending ||
                followState?.status === "checking" ||
                followState?.status === "verified" ||
                followState?.status === "delivered"
              ) {
                console.log(`[FOLLOW VERIFY] Duplicate or expired Followم کرد click ignored for sender ${senderId}.`);
                return;
              }

              followVerificationState.set(followStateKey, {
                ...followState,
                status: "checking",
                lastCheckedAt: Date.now()
              });

              const check = await checkUserFollowsAccount(matchedAccount, senderId);

              if (check.isFollowing) {
                console.log(`[DM WEBHOOK UNLOCK] Follow verified for sender ${senderId} in DM! Delivering link...`);
                clearFollowVerificationState(matchedAccount.id || matchedAccount.instagram_user_id, senderId);

                const automation = await getAutomationForAccount(matchedAccount);
                const effectiveAccount = automation
                  ? buildEffectiveAutomationAccount(matchedAccount, automation)
                  : matchedAccount;

                const privateResult = await sendPrivateReply(
                  effectiveAccount,
                  pending?.commentId || null,
                  pending?.commenterUsername || check.username || "",
                  senderId
                );

                if (privateResult.ok) {
                  console.log(`[DM WEBHOOK UNLOCK] Link delivered in DM to @${check.username || senderId} ✅`);
                  if (automation?.id) {
                    await updateAutomationStats(automation.id);
                  }
                  await recordActivityLog({
                    userId: matchedAccount.user_id,
                    accountId: matchedAccount.id,
                    username: matchedAccount.username,
                    commenterUsername: pending?.commenterUsername || check.username || senderId,
                    commentText: isCheckFollowPostback
                      ? "Clicked 'Followم کرد' -> Follow Verified -> Link Delivered"
                      : "Follow Verified via DM -> Link Delivered",
                    replyText: effectiveAccount.public_reply
                  });
                }
              } else {
                console.log(`[DM WEBHOOK] Sender ${senderId} follow check result: NOT FOLLOWING ❌`);
                followVerificationState.set(followStateKey, {
                  ...followState,
                  status: "pending_follow",
                  sentAt: followState?.sentAt || Date.now(),
                  lastCheckedAt: Date.now()
                });
                // If user clicked "Followم کرد" button but hasn't followed yet, inform them gently once without duplicate button spam
                if (isCheckFollowPostback) {
                  const cleanUsername = String(matchedAccount.username || "").replace(/^@/, "").trim();
                  const profileUrl = cleanUsername ? `https://www.instagram.com/${cleanUsername}/` : "https://www.instagram.com/";

                  await fetchJsonWithRetry(
                    `https://graph.instagram.com/v26.0/${matchedAccount.instagram_user_id}/messages`,
                    {
                      method: "POST",
                      headers: {
                        Authorization: `Bearer ${matchedAccount.access_token}`,
                        "Content-Type": "application/json"
                      },
                      body: JSON.stringify({
                        recipient: { id: senderId },
                        message: {
                          text: `تکایە سەرەتا دڵنیابەرەوە لە فۆڵۆوکردنی پەیجەکەمان (@${cleanUsername})، پاشان دووبارە کلیک لەسەر دوگمەی "Followم کرد" بکەرەوە ❤️✨\n${profileUrl}`
                        }
                      })
                    },
                    "FOLLOW NOT YET VERIFIED NOTICE",
                    1
                  );
                }
              }
            }).catch(err => console.error("[DM UNLOCK ERROR]:", err.message));
          }
        }
      }

    } catch (error) {

      console.error(
        "WEBHOOK ERROR:",
        error
      );
    }
  }
);


// =====================================================
// START INSTAGRAM LOGIN
// =====================================================

app.post(
  "/auth/instagram/start",
  async (
    req,
    res
  ) => {

    try {

      if (
        !INSTAGRAM_APP_ID
      ) {

        return res
          .status(500)
          .json({

            success:
              false,

            error:
              "INSTAGRAM_APP_ID is missing."
          });
      }

      if (
        !SUPABASE_URL ||
        !SUPABASE_API_KEY
      ) {

        return res
          .status(500)
          .json({

            success:
              false,

            error:
              "Supabase backend configuration is missing."
          });
      }

      if (
        !OAUTH_STATE_SECRET
      ) {

        return res
          .status(500)
          .json({

            success:
              false,

            error:
              "OAUTH_STATE_SECRET is missing."
          });
      }

      const accessToken =
        String(
          req.body?.access_token ||
          ""
        ).trim();

      if (
        !accessToken
      ) {

        return res
          .status(401)
          .json({

            success:
              false,

            error:
              "Supabase access token missing."
          });
      }

      const user =
        await verifySupabaseUser(
          accessToken
        );

      if (
        !user?.id
      ) {

        return res
          .status(401)
          .json({

            success:
              false,

            error:
              "Invalid or expired ODD BOT login."
          });
      }

      console.log(
        "Starting Instagram OAuth for user:",
        user.id
      );

      const state =
        createOAuthState(
          user.id
        );

      const params =
        new URLSearchParams({

          client_id:
            INSTAGRAM_APP_ID,

          redirect_uri:
            INSTAGRAM_REDIRECT_URI,

          response_type:
            "code",

          state,

          scope: [
            "instagram_business_basic",
            "instagram_business_manage_comments",
            "instagram_business_manage_messages"
          ].join(",")
        });

      const loginUrl =
        "https://www.instagram.com/oauth/authorize?" +
        params.toString();

      return res
        .status(200)
        .json({

          success:
            true,

          url:
            loginUrl
        });

    } catch (error) {

      console.error(
        "START INSTAGRAM OAUTH ERROR:",
        error
      );

      return res
        .status(500)
        .json({

          success:
            false,

          error:
            "Unable to start Instagram authorization."
        });
    }
  }
);


// =====================================================
// INSTAGRAM OAUTH CALLBACK
// =====================================================

app.get(
  "/auth/instagram/callback",
  async (
    req,
    res
  ) => {

    try {

      const {
        code,
        error,
        error_description,
        state
      } =
        req.query;

      if (
        error
      ) {

        console.error(
          "Instagram OAuth error:",
          error,
          error_description
        );

        return res
          .status(400)
          .send(
            error_description ||
            error
          );
      }

      if (
        !code
      ) {

        return res
          .status(400)
          .send(
            "Authorization code missing."
          );
      }

      const oauthState =
        verifyOAuthState(
          state
        );

      if (
        !oauthState
      ) {

        console.error(
          "Invalid or expired OAuth state."
        );

        return res
          .status(400)
          .send(
            "Instagram connection session expired. Please return to ODD BOT and try again."
          );
      }

      const userId =
        String(
          oauthState.userId
        );

      console.log(
        "Instagram OAuth callback for Supabase user:",
        userId
      );

      if (
        !INSTAGRAM_APP_ID ||
        !INSTAGRAM_APP_SECRET
      ) {

        return res
          .status(500)
          .send(
            "Instagram App ID or Secret missing."
          );
      }

      const tokenBody =
        new URLSearchParams();

      tokenBody.append(
        "client_id",
        INSTAGRAM_APP_ID
      );

      tokenBody.append(
        "client_secret",
        INSTAGRAM_APP_SECRET
      );

      tokenBody.append(
        "grant_type",
        "authorization_code"
      );

      tokenBody.append(
        "redirect_uri",
        INSTAGRAM_REDIRECT_URI
      );

      tokenBody.append(
        "code",
        code
      );

      const shortResponse =
        await fetch(
          "https://api.instagram.com/oauth/access_token",
          {
            method:
              "POST",

            headers: {
              "Content-Type":
                "application/x-www-form-urlencoded"
            },

            body:
              tokenBody
          }
        );

      const shortData =
        safeJsonParse(
          await shortResponse.text()
        );

      if (
        !shortResponse.ok ||
        !shortData.access_token
      ) {

        console.error(
          "SHORT TOKEN FAILED:",
          shortData
        );

        return res
          .status(500)
          .send(
            "Instagram token exchange failed. Check Render Logs."
          );
      }

      const longResult =
        await exchangeForLongLivedToken(
          shortData.access_token
        );

      if (
        !longResult.ok
      ) {

        return res
          .status(500)
          .send(
            "Long-lived token creation failed."
          );
      }

      const profileResponse =
        await fetch(
          "https://graph.instagram.com/v26.0/me?fields=id,username",
          {
            headers: {
              Authorization:
                `Bearer ${longResult.accessToken}`
            }
          }
        );

      const profile =
        safeJsonParse(
          await profileResponse.text()
        );

      if (
        !profileResponse.ok ||
        !profile.id
      ) {

        console.error(
          "PROFILE FAILED:",
          profile
        );

        return res
          .status(500)
          .send(
            "Instagram profile failed."
          );
      }

      const savedAccount =
        await saveOAuthAccount({

          userId,

          oauthUserId:
            String(
              profile.id
            ),

          username:
            String(
              profile.username ||
              ""
            ),

          accessToken:
            longResult.accessToken,

          expiresAt:
            longResult.expiresAt
        });

      console.log(
        "Instagram account saved:",
        {
          username:
            savedAccount.username,

          oauthUserId:
            savedAccount.oauth_user_id,

          webhookInstagramId:
            savedAccount.instagram_user_id,

          userId:
            savedAccount.user_id
        }
      );

      const subscriptionBody =
        new URLSearchParams();

      subscriptionBody.append(
        "subscribed_fields",
        "comments,messages"
      );

      const subscriptionResponse =
        await fetch(
          "https://graph.instagram.com/v26.0/me/subscribed_apps",
          {
            method:
              "POST",

            headers: {
              Authorization:
                `Bearer ${longResult.accessToken}`,

              "Content-Type":
                "application/x-www-form-urlencoded"
            },

            body:
              subscriptionBody
          }
        );

      const subscriptionData =
        safeJsonParse(
          await subscriptionResponse.text()
        );

      console.log(
        "Webhook subscription:",
        subscriptionData
      );

      if (
        !subscriptionResponse.ok
      ) {

        return res
          .status(500)
          .send(
            "Account saved, but webhook subscription failed. Check Render Logs."
          );
      }

      return res.send(`
<!DOCTYPE html>
<html>

<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Instagram Connected</title>
</head>

<body style="font-family:Arial,sans-serif; text-align:center; padding:80px 20px; background:#0f172a; color:#fff;">

<h1>Instagram Connected ✅</h1>
<h2>@${profile.username}</h2>
<p>Account saved to database ✅</p>
<p>ODD BOT User linked ✅</p>
<p>Long-lived token active ✅</p>
<p>Comments & Messages webhook active ✅</p>
<p>You can close this page and return to the dashboard.</p>

</body>
</html>
      `);

    } catch (error) {

      console.error(
        "OAUTH CALLBACK ERROR:",
        error
      );

      return res
        .status(500)
        .send(
          "Instagram connection failed. Check Render Logs."
        );
    }
  }
);


// =====================================================
// PRIVACY POLICY
// =====================================================

app.get(
  "/privacy",
  (
    req,
    res
  ) => {

    res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Privacy Policy</title>
</head>
<body style="font-family:Arial,sans-serif; max-width:800px; margin:50px auto; padding:20px; line-height:1.7;">
<h1>Privacy Policy</h1>
<p>ODD BOT uses Instagram API services to provide Instagram automation features.</p>
<p>We process only information required to provide the requested automation service.</p>
<p>We do not sell personal information.</p>
<p>Users may request deletion of their information.</p>
<p>Last updated: August 2026</p>
</body>
</html>
    `);
  }
);


// =====================================================
// DEAUTHORIZE
// =====================================================

app.post(
  "/deauthorize",
  (
    req,
    res
  ) => {

    return res
      .status(200)
      .json({

        success:
          true
      });
  }
);


// =====================================================
// DATA DELETION
// =====================================================

app.post(
  "/data-deletion",
  (
    req,
    res
  ) => {

    return res
      .status(200)
      .json({

        success:
          true,

        message:
          "Data deletion request received."
      });
  }
);


// =====================================================
// SPA FALLBACK FOR REACT FRONTEND
// =====================================================

app.get("*", (req, res, next) => {
  const indexPath = path.join(distPath, "index.html");
  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }
  next();
});


// =====================================================
// START SERVER
// =====================================================

const PORT =
  process.env.PORT ||
  10000;

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `Server running on port ${PORT}`
    );

    console.log(
      "ODD BOT MULTI-USER MODE ENABLED ✅"
    );

    console.log(
      "RANDOM REPLY TEMPLATES & TAGGING ENABLED ✅"
    );

    console.log(
      "STATS & ACTIVITY LOGS INTEGRATION ENABLED ✅"
    );

    console.log(
      "AUTO WEBHOOK ID MAPPING ENABLED ✅"
    );

    console.log(
      "PER-ACCOUNT RATE LIMITS & HUMAN JITTER ENGINE ENABLED ✅"
    );
  }
);
