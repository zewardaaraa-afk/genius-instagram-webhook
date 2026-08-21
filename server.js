const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const net = require("net");

const app = express();

// =====================================================
// BODY PARSERS + RAW META WEBHOOK BODY
// =====================================================

app.use(
  express.json({
    verify: (req, res, buf) => {
      const requestPath = String(
        req.originalUrl || ""
      ).split("?")[0];

      if (requestPath === "/api/webhooks/instagram") {
        req.rawBody = Buffer.from(buf);
      }
    }
  })
);

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
    res.setHeader(
      "Access-Control-Allow-Origin",
      origin
    );

    res.setHeader(
      "Vary",
      "Origin"
    );
  }

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET,POST,OPTIONS"
  );

  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,Authorization"
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

const PUBLIC_BASE_URL =
  (
    process.env.PUBLIC_BASE_URL ||
    "https://genius-instagram-webhook.onrender.com"
  ).replace(/\/+$/, "");

const DATA_DELETION_SECRET =
  process.env.DATA_DELETION_SECRET ||
  OAUTH_STATE_SECRET ||
  INSTAGRAM_APP_SECRET;

const GOOGLE_WEB_RISK_API_KEY =
  process.env.GOOGLE_WEB_RISK_API_KEY ||
  "";

const ADMIN_EMAIL =
  String(
    process.env.ADMIN_EMAIL ||
    ""
  )
    .trim()
    .toLowerCase();

// =====================================================
// DATABASE
// =====================================================

if (!DATABASE_URL) {
  console.error(
    "DATABASE_URL is missing"
  );
}

const pool = new Pool({
  connectionString: DATABASE_URL,

  ssl: {
    rejectUnauthorized: false
  },

  max: 5,

  idleTimeoutMillis: 30000
});

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
// QUEUE + RATE LIMIT STATE
// =====================================================

const automationQueue = [];

const processedComments =
  new Set();

let queueWorkerRunning =
  false;

const accountSendHistoryMap =
  new Map();

const accountNextAllowedTimeMap =
  new Map();

// =====================================================
// BASIC HELPERS
// =====================================================

function sleep(ms) {
  return new Promise(
    resolve => setTimeout(resolve, ms)
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

function safeBufferEqual(
  first,
  second
) {
  if (
    !Buffer.isBuffer(first) ||
    !Buffer.isBuffer(second)
  ) {
    return false;
  }

  if (
    first.length !==
    second.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    first,
    second
  );
}

// =====================================================
// SAFE DESTINATION LINK VALIDATION + GOOGLE WEB RISK
// =====================================================

const OFFICIAL_DESTINATION_HOSTS =
  new Map([
    ["instagram.com", "instagram"],
    ["www.instagram.com", "instagram"],

    ["youtube.com", "youtube"],
    ["www.youtube.com", "youtube"],
    ["m.youtube.com", "youtube"],
    ["music.youtube.com", "youtube"],
    ["youtu.be", "youtube"],

    ["t.me", "telegram"],

    ["tiktok.com", "tiktok"],
    ["www.tiktok.com", "tiktok"],
    ["m.tiktok.com", "tiktok"],
    ["vm.tiktok.com", "tiktok"],
    ["vt.tiktok.com", "tiktok"],

    ["facebook.com", "facebook"],
    ["www.facebook.com", "facebook"],
    ["m.facebook.com", "facebook"],
    ["fb.watch", "facebook"]
  ]);

function normalizeHostname(value) {
  return String(
    value || ""
  )
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");
}

function isBlockedDestinationHostname(value) {
  const host =
    normalizeHostname(value)
      .replace(/^\[/, "")
      .replace(/\]$/, "");

  if (!host) {
    return true;
  }

  if (
    host === "localhost" ||
    host === "localhost.localdomain" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal")
  ) {
    return true;
  }

  // Direct IP destinations are not accepted. This also blocks
  // private, loopback, link-local and other literal IP forms.
  if (net.isIP(host)) {
    return true;
  }

  // Dotless hostnames are local/internal-style destinations.
  if (!host.includes(".")) {
    return true;
  }

  return false;
}

function validateDestinationUrl(
  value
) {
  const raw =
    String(
      value || ""
    ).trim();

  if (!raw) {
    return {
      valid: true,
      url: "",
      hostname: "",
      platform: null,
      isOfficial: true
    };
  }

  if (raw.length > 2048) {
    return {
      valid: false,
      code:
        "UNSAFE_DESTINATION_URL",
      reason:
        "URL_TOO_LONG",
      error:
        "Link is too long."
    };
  }

  let parsed;

  try {
    parsed =
      new URL(raw);
  } catch {
    return {
      valid: false,
      code:
        "UNSAFE_DESTINATION_URL",
      reason:
        "INVALID_URL_SYNTAX",
      error:
        "Invalid URL format."
    };
  }

  if (
    parsed.protocol !==
    "https:"
  ) {
    return {
      valid: false,
      code:
        "UNSAFE_DESTINATION_URL",
      reason:
        "HTTPS_REQUIRED",
      error:
        "Only secure HTTPS links are allowed."
    };
  }

  if (
    parsed.username ||
    parsed.password
  ) {
    return {
      valid: false,
      code:
        "UNSAFE_DESTINATION_URL",
      reason:
        "URL_CREDENTIALS_BLOCKED",
      error:
        "Links containing username or password are not allowed."
    };
  }

  if (
    parsed.port &&
    parsed.port !== "443"
  ) {
    return {
      valid: false,
      code:
        "UNSAFE_DESTINATION_URL",
      reason:
        "CUSTOM_PORT_BLOCKED",
      error:
        "Custom URL ports are not allowed."
    };
  }

  const hostname =
    normalizeHostname(
      parsed.hostname
    );

  if (
    isBlockedDestinationHostname(
      hostname
    )
  ) {
    return {
      valid: false,
      code:
        "UNSAFE_DESTINATION_URL",
      reason:
        "LOCAL_OR_IP_HOST_BLOCKED",
      error:
        "Local, internal or direct-IP destination hosts are not allowed."
    };
  }

  // Canonicalize a trailing-dot hostname before saving/reviewing.
  parsed.hostname =
    hostname;

  const platform =
    OFFICIAL_DESTINATION_HOSTS.get(
      hostname
    ) ||
    "custom";

  const isOfficial =
    platform !== "custom";

  const pathname =
    String(
      parsed.pathname || "/"
    )
      .trim()
      .toLowerCase();

  // Block known external redirect/share routes on otherwise-official hosts.
  if (
    (
      hostname === "facebook.com" ||
      hostname === "www.facebook.com" ||
      hostname === "m.facebook.com"
    ) &&
    (
      pathname === "/l.php" ||
      pathname.startsWith("/l.php/") ||
      pathname.startsWith("/flx/warn/")
    )
  ) {
    return {
      valid: false,
      code:
        "UNSAFE_DESTINATION_URL",
      reason:
        "EXTERNAL_REDIRECT_BLOCKED",
      error:
        "Facebook external redirect links are not allowed."
    };
  }

  if (
    (
      hostname === "youtube.com" ||
      hostname === "www.youtube.com" ||
      hostname === "m.youtube.com"
    ) &&
    (
      pathname === "/redirect" ||
      pathname.startsWith("/redirect/")
    )
  ) {
    return {
      valid: false,
      code:
        "UNSAFE_DESTINATION_URL",
      reason:
        "EXTERNAL_REDIRECT_BLOCKED",
      error:
        "YouTube external redirect links are not allowed."
    };
  }

  if (
    hostname === "t.me" &&
    (
      pathname === "/share/url" ||
      pathname.startsWith("/share/url/")
    )
  ) {
    return {
      valid: false,
      code:
        "UNSAFE_DESTINATION_URL",
      reason:
        "EXTERNAL_REDIRECT_BLOCKED",
      error:
        "Telegram external share links are not allowed."
    };
  }

  return {
    valid: true,
    url:
      parsed.toString(),
    hostname,
    platform,
    isOfficial
  };
}

async function checkGoogleWebRisk(
  normalizedUrl
) {
  if (
    !GOOGLE_WEB_RISK_API_KEY
  ) {
    return {
      ok: false,
      safe: false,
      threats: [],
      error:
        "WEB_RISK_NOT_CONFIGURED"
    };
  }

  const controller =
    new AbortController();

  const timeout =
    setTimeout(
      () => controller.abort(),
      8000
    );

  try {
    const params =
      new URLSearchParams();

    params.append(
      "threatTypes",
      "MALWARE"
    );

    params.append(
      "threatTypes",
      "SOCIAL_ENGINEERING"
    );

    params.append(
      "threatTypes",
      "UNWANTED_SOFTWARE"
    );

    params.set(
      "uri",
      normalizedUrl
    );

    params.set(
      "key",
      GOOGLE_WEB_RISK_API_KEY
    );

    const response =
      await fetch(
        "https://webrisk.googleapis.com/v1/uris:search?" +
        params.toString(),
        {
          method: "GET",
          headers: {
            Accept:
              "application/json"
          },
          signal:
            controller.signal
        }
      );

    const data =
      safeJsonParse(
        await response.text()
      );

    if (!response.ok) {
      console.error(
        "GOOGLE WEB RISK ERROR:",
        {
          status:
            response.status
        }
      );

      return {
        ok: false,
        safe: false,
        threats: [],
        error:
          "WEB_RISK_PROVIDER_ERROR"
      };
    }

    const threats =
      Array.isArray(
        data?.threat?.threatTypes
      )
        ? data.threat.threatTypes
            .map(String)
            .filter(Boolean)
        : [];

    return {
      ok: true,
      safe:
        threats.length === 0,
      threats
    };

  } catch (error) {
    const timedOut =
      error?.name ===
      "AbortError";

    console.error(
      timedOut
        ? "GOOGLE WEB RISK TIMEOUT"
        : "GOOGLE WEB RISK NETWORK ERROR:",
      timedOut
        ? ""
        : error.message
    );

    return {
      ok: false,
      safe: false,
      threats: [],
      error:
        timedOut
          ? "WEB_RISK_TIMEOUT"
          : "WEB_RISK_NETWORK_ERROR"
    };

  } finally {
    clearTimeout(timeout);
  }
}

function serializeLinkReview(
  row
) {
  if (!row) {
    return null;
  }

  return {
    ...row,

    // Compatibility aliases used by the current dashboard UI.
    destination_url:
      row.normalized_url,

    domain:
      row.hostname,

    web_risk_status:
      row.safety_status,

    status:
      row.review_status
  };
}

async function findApprovedLinkReview({
  userId,
  accountId,
  normalizedUrl
}) {
  const result =
    await pool.query(
      `
      select *
      from public.link_review_requests
      where user_id = $1
      and account_id = $2
      and normalized_url = $3
      and review_status = 'approved'
      order by
        reviewed_at desc nulls last,
        created_at desc
      limit 1
      `,
      [
        userId,
        accountId,
        normalizedUrl
      ]
    );

  return (
    result.rows[0] ||
    null
  );
}

async function upsertPendingLinkReview({
  userId,
  accountId,
  requestedUrl,
  normalizedUrl,
  hostname,
  platform
}) {
  const client =
    await pool.connect();

  try {
    await client.query(
      "begin"
    );

    // Serialize submissions for the same user's account.
    await client.query(
      `
      select pg_advisory_xact_lock(
        hashtext($1)::bigint
      )
      `,
      [
        `${userId}:${accountId}`
      ]
    );

    // A newer custom URL supersedes older pending custom URLs.
    await client.query(
      `
      update public.link_review_requests
      set
        review_status = 'rejected',
        rejection_reason =
          'Superseded by a newer submitted URL.',
        updated_at = now()
      where user_id = $1
      and account_id = $2
      and review_status = 'pending'
      and normalized_url <> $3
      `,
      [
        userId,
        accountId,
        normalizedUrl
      ]
    );

    const existing =
      await client.query(
        `
        select *
        from public.link_review_requests
        where user_id = $1
        and account_id = $2
        and normalized_url = $3
        and review_status = 'pending'
        order by created_at desc
        limit 1
        for update
        `,
        [
          userId,
          accountId,
          normalizedUrl
        ]
      );

    let row;

    if (existing.rows[0]) {
      const updated =
        await client.query(
          `
          update public.link_review_requests
          set
            requested_url = $1,
            hostname = $2,
            platform = $3,
            safety_status = 'safe',
            threat_types = '[]'::jsonb,
            rejection_reason = null,
            updated_at = now()
          where id = $4
          returning *
          `,
          [
            requestedUrl,
            hostname,
            platform,
            existing.rows[0].id
          ]
        );

      row =
        updated.rows[0];

    } else {
      const inserted =
        await client.query(
          `
          insert into public.link_review_requests (
            user_id,
            account_id,
            requested_url,
            normalized_url,
            hostname,
            platform,
            safety_status,
            threat_types,
            review_status,
            created_at,
            updated_at
          )
          values (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            'safe',
            '[]'::jsonb,
            'pending',
            now(),
            now()
          )
          returning *
          `,
          [
            userId,
            accountId,
            requestedUrl,
            normalizedUrl,
            hostname,
            platform
          ]
        );

      row =
        inserted.rows[0];
    }

    await client.query(
      "commit"
    );

    return row;

  } catch (error) {
    try {
      await client.query(
        "rollback"
      );
    } catch {}

    throw error;

  } finally {
    client.release();
  }
}

async function recordRejectedThreatLink({
  userId,
  accountId,
  requestedUrl,
  normalizedUrl,
  hostname,
  threats
}) {
  try {
    await pool.query(
      `
      insert into public.link_review_requests (
        user_id,
        account_id,
        requested_url,
        normalized_url,
        hostname,
        platform,
        safety_status,
        threat_types,
        review_status,
        rejection_reason,
        reviewed_at,
        created_at,
        updated_at
      )
      values (
        $1,
        $2,
        $3,
        $4,
        $5,
        'custom',
        'unsafe',
        $6::jsonb,
        'rejected',
        'Rejected automatically because Google Web Risk returned a known threat match.',
        now(),
        now(),
        now()
      )
      `,
      [
        userId,
        accountId,
        requestedUrl,
        normalizedUrl,
        hostname,
        JSON.stringify(
          threats || []
        )
      ]
    );
  } catch (error) {
    // Audit logging must never make an already-unsafe link become active.
    console.error(
      "UNSAFE LINK AUDIT ERROR:",
      error.message
    );
  }
}

// =====================================================
// META WEBHOOK SIGNATURE
// =====================================================

function verifyInstagramWebhookSignature(
  req
) {
  if (!INSTAGRAM_APP_SECRET) {
    return {
      ok: false,
      status: 500,
      reason:
        "INSTAGRAM_APP_SECRET is missing."
    };
  }

  if (
    !Buffer.isBuffer(
      req.rawBody
    )
  ) {
    return {
      ok: false,
      status: 400,
      reason:
        "Raw webhook body is unavailable."
    };
  }

  const signatureHeader =
    String(
      req.headers[
        "x-hub-signature-256"
      ] || ""
    ).trim();

  if (
    !/^sha256=[a-f0-9]{64}$/i.test(
      signatureHeader
    )
  ) {
    return {
      ok: false,
      status: 401,
      reason:
        "Missing or malformed X-Hub-Signature-256."
    };
  }

  const receivedSignature =
    Buffer.from(
      signatureHeader.slice(7),
      "hex"
    );

  const expectedSignature =
    crypto
      .createHmac(
        "sha256",
        INSTAGRAM_APP_SECRET
      )
      .update(
        req.rawBody
      )
      .digest();

  const valid =
    safeBufferEqual(
      receivedSignature,
      expectedSignature
    );

  return {
    ok: valid,

    status:
      valid
        ? 200
        : 403,

    reason:
      valid
        ? ""
        : "Invalid Meta webhook signature."
  };
}

function requireInstagramWebhookSignature(
  req,
  res,
  next
) {
  const result =
    verifyInstagramWebhookSignature(
      req
    );

  if (!result.ok) {
    console.error(
      "META WEBHOOK SIGNATURE REJECTED:",
      result.reason
    );

    return res
      .status(
        result.status
      )
      .json({
        success: false,

        error:
          "Webhook signature verification failed."
      });
  }

  next();
}

// =====================================================
// META SIGNED REQUEST
// =====================================================

function parseAndVerifyMetaSignedRequest(
  signedRequest
) {
  try {
    if (
      !signedRequest ||
      !INSTAGRAM_APP_SECRET
    ) {
      return null;
    }

    const parts =
      String(
        signedRequest
      ).split(".");

    if (
      parts.length !== 2
    ) {
      return null;
    }

    const encodedSignature =
      parts[0];

    const encodedPayload =
      parts[1];

    const receivedSignature =
      Buffer.from(
        encodedSignature,
        "base64url"
      );

    const expectedSignature =
      crypto
        .createHmac(
          "sha256",
          INSTAGRAM_APP_SECRET
        )
        .update(
          encodedPayload
        )
        .digest();

    if (
      !safeBufferEqual(
        receivedSignature,
        expectedSignature
      )
    ) {
      return null;
    }

    const payload =
      JSON.parse(
        Buffer
          .from(
            encodedPayload,
            "base64url"
          )
          .toString(
            "utf8"
          )
      );

    const algorithm =
      String(
        payload?.algorithm ||
        "HMAC-SHA256"
      )
        .trim()
        .toUpperCase();

    if (
      algorithm !==
      "HMAC-SHA256"
    ) {
      return null;
    }

    if (
      !payload?.user_id
    ) {
      return null;
    }

    return payload;

  } catch (error) {
    console.error(
      "META SIGNED_REQUEST VERIFY ERROR:",
      error.message
    );

    return null;
  }
}

// =====================================================
// CLEAR ACCOUNT RUNTIME STATE
// =====================================================

function clearAccountRuntimeState(
  accounts = []
) {
  const webhookIds =
    new Set();

  for (
    const account of accounts
  ) {
    if (account?.id) {
      const accountKey =
        String(
          account.id
        );

      accountSendHistoryMap.delete(
        accountKey
      );

      accountNextAllowedTimeMap.delete(
        accountKey
      );
    }

    if (
      account?.instagram_user_id
    ) {
      webhookIds.add(
        String(
          account.instagram_user_id
        )
      );
    }
  }

  for (
    let index =
      automationQueue.length - 1;

    index >= 0;

    index--
  ) {
    const queuedId =
      String(
        automationQueue[
          index
        ]?.instagramUserId ||
        ""
      );

    if (
      webhookIds.has(
        queuedId
      )
    ) {
      automationQueue.splice(
        index,
        1
      );
    }
  }
}

const clearDeletedAccountRuntimeState =
  clearAccountRuntimeState;

// =====================================================
// FULL META DATA DELETION
// =====================================================

async function deleteMetaLinkedAccountData(
  metaUserId
) {
  const normalizedMetaUserId =
    String(
      metaUserId || ""
    ).trim();

  if (!normalizedMetaUserId) {
    throw new Error(
      "Meta user_id is missing."
    );
  }

  const client =
    await pool.connect();

  let accounts = [];

  try {
    await client.query(
      "begin"
    );

    const result =
      await client.query(
        `
        select
          id,
          user_id,
          username,
          oauth_user_id,
          instagram_user_id
        from public.instagram_accounts
        where
          oauth_user_id = $1
          or instagram_user_id = $1
        for update
        `,
        [
          normalizedMetaUserId
        ]
      );

    accounts =
      result.rows;

    for (
      const account of accounts
    ) {
      await client.query(
        `
        delete from public.link_review_requests
        where account_id = $1
        and user_id = $2
        `,
        [
          account.id,
          account.user_id
        ]
      );

      await client.query(
        `
        delete from public.activity_logs
        where account_id = $1
        and user_id = $2
        `,
        [
          account.id,
          account.user_id
        ]
      );

      await client.query(
        `
        delete from public.automations
        where account_id = $1
        and user_id = $2
        `,
        [
          account.id,
          account.user_id
        ]
      );

      await client.query(
        `
        delete from public.instagram_accounts
        where id = $1
        and user_id = $2
        `,
        [
          account.id,
          account.user_id
        ]
      );
    }

    await client.query(
      "commit"
    );

  } catch (error) {
    try {
      await client.query(
        "rollback"
      );
    } catch {}

    throw error;

  } finally {
    client.release();
  }

  clearAccountRuntimeState(
    accounts
  );

  return accounts;
}

// =====================================================
// DATA DELETION CONFIRMATION
// =====================================================

function createDeletionConfirmationCode() {
  if (!DATA_DELETION_SECRET) {
    throw new Error(
      "DATA_DELETION_SECRET is unavailable."
    );
  }

  const payload =
    Buffer
      .from(
        JSON.stringify({
          version: 1,

          status:
            "completed",

          completedAt:
            new Date()
              .toISOString(),

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
        DATA_DELETION_SECRET
      )
      .update(
        payload
      )
      .digest(
        "base64url"
      );

  return `${payload}.${signature}`;
}

function verifyDeletionConfirmationCode(
  code
) {
  try {
    if (
      !code ||
      !DATA_DELETION_SECRET
    ) {
      return null;
    }

    const parts =
      String(
        code
      ).split(".");

    if (
      parts.length !== 2
    ) {
      return null;
    }

    const payload =
      parts[0];

    const received =
      Buffer.from(
        parts[1],
        "base64url"
      );

    const expected =
      crypto
        .createHmac(
          "sha256",
          DATA_DELETION_SECRET
        )
        .update(
          payload
        )
        .digest();

    if (
      !safeBufferEqual(
        received,
        expected
      )
    ) {
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
      decoded?.status !==
      "completed"
    ) {
      return null;
    }

    return decoded;

  } catch {
    return null;
  }
}

// =====================================================
// RANDOM PUBLIC REPLY
// =====================================================

function getRandomReplyTemplate(
  automation,
  fallbackReply =
    DEFAULT_PUBLIC_REPLY
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
        Array.isArray(parsed)
      ) {
        templates =
          parsed;
      }

    } catch {
      if (
        automation
          .public_reply_templates
          .trim()
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
    validTemplates.length ===
    0
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
      /@?{username}/gi,
      handle
    )
    .trim();
}

// =====================================================
// STATS
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
        total_triggered =
          coalesce(total_triggered, 0) + 1,
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

// =====================================================
// ACTIVITY LOG
// =====================================================

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
      values (
        $1,
        $2,
        $3,
        $4,
        $5,
        now()
      )
      `,
      [
        userId,
        accountId,

        "Replied to Comment",

        JSON.stringify({
          account_username:
            username,

          commenter:
            commenterUsername
              ? `@${commenterUsername.replace(/^@/, "")}`
              : "unknown",

          comment_text:
            commentText,

          reply_text:
            replyText
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
        values (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          now()
        )
        `,
        [
          userId,
          accountId,
          commenterUsername ||
            "unknown",
          commentText ||
            "",
          replyText ||
            "",
          "success"
        ]
      );

    } catch {
      console.error(
        "ACTIVITY LOG INSERT ERROR (non-blocking):",
        error.message
      );
    }
  }
}

// =====================================================
// SUPABASE AUTH
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
          method: "GET",

          headers: {
            apikey:
              SUPABASE_API_KEY,

            Authorization:
              `Bearer ${accessToken}`
          }
        }
      );

    const user =
      safeJsonParse(
        await response.text()
      );

    if (
      !response.ok ||
      !user?.id
    ) {
      console.error(
        "SUPABASE USER VERIFY FAILED:",
        {
          status:
            response.status
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

function getSupabaseAccessTokenFromRequest(
  req
) {
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

  if (!accessToken) {
    return res
      .status(401)
      .json({
        success: false,

        error:
          "Supabase access token missing."
      });
  }

  const user =
    await verifySupabaseUser(
      accessToken
    );

  if (!user?.id) {
    return res
      .status(401)
      .json({
        success: false,

        error:
          "Invalid or expired ODD BOT login."
      });
  }

  req.oddBotUser =
    user;

  req.oddBotAccessToken =
    accessToken;

  next();
}

// =====================================================
// OWNED INSTAGRAM ACCOUNT
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
      from public.instagram_accounts
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
// NORMALIZE AUTOMATION
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
      .filter(Boolean);

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
    enabledValue !==
    undefined
  ) {
    if (
      typeof enabledValue ===
      "string"
    ) {
      enabled =
        ![
          "false",
          "0",
          "off",
          "no"
        ].includes(
          enabledValue
            .trim()
            .toLowerCase()
        );

    } else {
      enabled =
        Boolean(
          enabledValue
        );
    }
  }

  const delay_seconds =
    Math.min(
      Math.max(
        parseInt(
          body.delay_seconds ??
          body.delaySeconds ??
          8,
          10
        ) || 8,
        3
      ),
      20
    );

  const hourly_limit =
    Math.min(
      Math.max(
        parseInt(
          body.hourly_limit ??
          body.hourlyRateLimit ??
          body.hourly_rate_limit ??
          80,
          10
        ) || 80,
        10
      ),
      120
    );

  const random_jitter_enabled =
    typeof body.random_jitter_enabled ===
    "boolean"
      ? body.random_jitter_enabled
      : typeof body.randomDelayVariance ===
        "boolean"
        ? body.randomDelayVariance
        : typeof body.random_delay_variance ===
          "boolean"
          ? body.random_delay_variance
          : true;

  const rawPreset =
    String(
      body.safety_speed_preset ||
      body.safetySpeedPreset ||
      "recommended"
    )
      .trim()
      .toLowerCase();

  const safety_speed_preset =
    [
      "fast",
      "recommended",
      "very_safe",
      "custom"
    ].includes(
      rawPreset
    )
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
// ACCOUNT LOOKUPS
// =====================================================

async function getAccountByWebhookId(
  instagramUserId
) {
  const result =
    await pool.query(
      `
      select *
      from public.instagram_accounts
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

async function getAccountByOAuthId(
  userId,
  oauthUserId
) {
  const result =
    await pool.query(
      `
      select *
      from public.instagram_accounts
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

async function getAccountByUsername(
  userId,
  username
) {
  const result =
    await pool.query(
      `
      select *
      from public.instagram_accounts
      where user_id = $1
      and lower(username) = lower($2)
      limit 1
      `,
      [
        userId,
        String(username)
      ]
    );

  return (
    result.rows[0] ||
    null
  );
}

// =====================================================
// GET AUTOMATION
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

  return {
    ...account,

    public_reply:
      publicReply,

    private_text:
      String(
        automation?.private_dm_message ||
        ""
      ).trim() ||
      account.private_text,

    button_title:
      String(
        automation?.button_text ||
        ""
      ).trim() ||
      account.button_title,

    channel_url:
      String(
        automation?.channel_url ||
        ""
      ).trim() ||
      account.channel_url
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
        parseInt(
          automation?.delay_seconds,
          10
        ) || 8,
        3
      ),
      20
    );

  const hourly_limit =
    Math.min(
      Math.max(
        parseInt(
          automation?.hourly_limit,
          10
        ) || 80,
        10
      ),
      120
    );

  const random_jitter_enabled =
    typeof automation?.random_jitter_enabled ===
    "boolean"
      ? automation.random_jitter_enabled
      : true;

  const rawPreset =
    String(
      automation?.safety_speed_preset ||
      "recommended"
    )
      .trim()
      .toLowerCase();

  const safety_speed_preset =
    [
      "fast",
      "recommended",
      "very_safe",
      "custom"
    ].includes(
      rawPreset
    )
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
// SAVE AUTOMATION
// =====================================================

async function saveAutomationForOwnedAccount(
  account,
  input
) {
  const replyColumnType =
    await getAutomationReplyColumnType();

  const replyValue =
    replyColumnType === "jsonb"
      ? JSON.stringify(
          input.publicReplyTemplates
        )
      : input.publicReplyTemplates;

  const replyExpression =
    replyColumnType === "jsonb"
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
// OAUTH STATE
// =====================================================

function createOAuthState(
  userId
) {
  if (!OAUTH_STATE_SECRET) {
    throw new Error(
      "OAUTH_STATE_SECRET is missing."
    );
  }

  const payload =
    Buffer
      .from(
        JSON.stringify({
          userId:
            String(userId),

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

  return `${payload}.${signature}`;
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

    const received =
      Buffer.from(
        parts[1]
      );

    const expected =
      Buffer.from(
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
          )
      );

    if (
      !safeBufferEqual(
        received,
        expected
      )
    ) {
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
      !decoded?.userId ||
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
// SAVE / UPDATE OAUTH ACCOUNT
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
        update public.instagram_accounts
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
            username || ""
          ),

          accessToken,
          expiresAt,
          DEFAULT_CHANNEL_URL,
          existing.id,
          userId
        ]
      );

    if (!result.rows[0]) {
      throw new Error(
        "Unable to update Instagram account."
      );
    }

    return result.rows[0];
  }

  const result =
    await pool.query(
      `
      insert into public.instagram_accounts (
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
          username || ""
        ),

        accessToken,
        DEFAULT_CHANNEL_URL,
        expiresAt
      ]
    );

  return result.rows[0];
}

// =====================================================
// WEBHOOK ID
// =====================================================

async function saveWebhookId(
  accountId,
  webhookInstagramId
) {
  const result =
    await pool.query(
      `
      update public.instagram_accounts
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
// AUTO MAP WEBHOOK
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
      from public.instagram_accounts
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

      const matchedAccount =
        accounts.find(
          account =>
            normalizeUsername(
              account.username
            ) ===
            detectedUsername
        );

      if (!matchedAccount) {
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
// TOKENS
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
        ok: false,
        data
      };
    }

    const expiresIn =
      Number(
        data.expires_in ||
        5184000
      );

    return {
      ok: true,

      accessToken:
        data.access_token,

      expiresAt:
        new Date(
          Date.now() +
          expiresIn * 1000
        ),

      expiresIn
    };

  } catch (error) {
    console.error(
      "LONG TOKEN ERROR:",
      error.message
    );

    return {
      ok: false,

      data: {
        error:
          error.message
      }
    };
  }
}

async function refreshAccountTokenIfNeeded(
  account
) {
  if (
    !account?.access_token ||
    !account?.token_expires_at
  ) {
    return account;
  }

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
    expiry - Date.now() >
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
        update public.instagram_accounts
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
      error.message
    );

    return account;
  }
}

// =====================================================
// AUTO TOKEN REFRESH
// =====================================================

setInterval(
  async () => {
    try {
      const result =
        await pool.query(
          `
          select *
          from public.instagram_accounts
          where enabled = true
          and access_token is not null
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
        error.message
      );
    }
  },

  12 *
  60 *
  60 *
  1000
);

// =====================================================
// RATE LIMIT
// =====================================================

function getAccountSendHistory(
  accountId
) {
  const key =
    String(
      accountId ||
      "global"
    ).trim();

  const oneHourAgo =
    Date.now() -
    3600000;

  const history =
    accountSendHistoryMap.get(
      key
    ) || [];

  const active =
    history.filter(
      timestamp =>
        timestamp >
        oneHourAgo
    );

  accountSendHistoryMap.set(
    key,
    active
  );

  return active;
}

function checkAccountRateLimit(
  accountId,
  hourlyLimit = 80
) {
  const history =
    getAccountSendHistory(
      accountId
    );

  const limit =
    Math.min(
      Math.max(
        Number(
          hourlyLimit
        ) || 80,
        10
      ),
      120
    );

  if (
    history.length <
    limit
  ) {
    return {
      allowed: true,

      currentCount:
        history.length,

      hourlyLimit:
        limit,

      waitSeconds:
        0
    };
  }

  const oldest =
    history[0] ||
    Date.now();

  const waitMs =
    Math.max(
      1000,

      oldest +
      3600000 -
      Date.now()
    );

  return {
    allowed: false,

    currentCount:
      history.length,

    hourlyLimit:
      limit,

    waitSeconds:
      Math.ceil(
        waitMs /
        1000
      )
  };
}

function recordAccountSend(
  accountId
) {
  const key =
    String(
      accountId ||
      "global"
    ).trim();

  const history =
    getAccountSendHistory(
      accountId
    );

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
      Math.max(
        Number(
          delaySeconds
        ) || 8,
        3
      ),
      20
    );

  let jitter =
    0;

  if (jitterEnabled) {
    jitter =
      Math.round(
        (
          Math.random() *
          4 -
          2
        ) *
        10
      ) /
      10;
  }

  const finalSeconds =
    Math.max(
      1,

      Math.round(
        (
          base +
          jitter
        ) *
        10
      ) /
      10
    );

  return Math.round(
    finalSeconds *
    1000
  );
}

// =====================================================
// FETCH WITH RETRY
// =====================================================

async function fetchJsonWithRetry(
  url,
  options,
  label,
  maxAttempts = 3
) {
  let lastData = {};

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

      const data =
        safeJsonParse(
          await response.text()
        );

      lastData =
        data;

      if (
        response.ok
      ) {
        return {
          ok: true,

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
          ok: false,

          status:
            response.status,

          data
        };
      }

      const retryAfter =
        Number(
          response.headers.get(
            "retry-after"
          )
        );

      await sleep(
        Number.isFinite(
          retryAfter
        )
          ? retryAfter * 1000
          : attempt * 10000
      );

    } catch (error) {
      console.error(
        `${label} NETWORK ERROR:`,
        error.message
      );

      if (
        attempt === maxAttempts
      ) {
        return {
          ok: false,

          status: 0,

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
    ok: false,
    status: 0,
    data: lastData
  };
}

// =====================================================
// PUBLIC REPLY
// =====================================================

async function sendPublicReply(
  account,
  commentId,
  commenterUsername = ""
) {
  const message =
    formatReplyText(
      account.public_reply ||
      DEFAULT_PUBLIC_REPLY,
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
      method: "POST",

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
// PRIVATE BUTTON
// =====================================================

async function sendPrivateButton(
  account,
  commentId,
  commenterUsername = ""
) {
  const text =
    formatReplyText(
      account.private_text ||
      DEFAULT_PRIVATE_TEXT,
      commenterUsername
    );

  const payload = {
    recipient: {
      comment_id:
        commentId
    },

    message: {
      attachment: {
        type:
          "template",

        payload: {
          template_type:
            "button",

          text,

          buttons: [
            {
              type:
                "web_url",

              url:
                account.channel_url ||
                DEFAULT_CHANNEL_URL,

              title:
                account.button_title ||
                DEFAULT_BUTTON_TITLE
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
        Authorization:
          `Bearer ${account.access_token}`,

        "Content-Type":
          "application/json"
      },

      body:
        JSON.stringify(
          payload
        )
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
  commenterUsername = ""
) {
  const text =
    formatReplyText(
      account.private_text ||
      DEFAULT_PRIVATE_TEXT,
      commenterUsername
    );

  const payload = {
    recipient: {
      comment_id:
        commentId
    },

    message: {
      text:
`${text}

${account.button_title || DEFAULT_BUTTON_TITLE}

${account.channel_url || DEFAULT_CHANNEL_URL}`
    }
  };

  return fetchJsonWithRetry(
    `https://graph.instagram.com/v26.0/${account.instagram_user_id}/messages`,

    {
      method: "POST",

      headers: {
        Authorization:
          `Bearer ${account.access_token}`,

        "Content-Type":
          "application/json"
      },

      body:
        JSON.stringify(
          payload
        )
    },

    "PRIVATE FALLBACK"
  );
}

// =====================================================
// PRIVATE REPLY
// =====================================================

async function sendPrivateReply(
  account,
  commentId,
  commenterUsername = ""
) {
  const result =
    await sendPrivateButton(
      account,
      commentId,
      commenterUsername
    );

  if (result.ok) {
    console.log(
      `Private button sent @${account.username} ✅`
    );

    return result;
  }

  console.log(
    "Button unavailable. Trying fallback."
  );

  return sendPrivateFallback(
    account,
    commentId,
    commenterUsername
  );
}

// =====================================================
// PROCESS COMMENT
// =====================================================

async function handleCommentAutomation(
  job
) {
  console.log(
    "======================================"
  );

  console.log(
    "PROCESS COMMENT:",
    {
      webhookInstagramId:
        job.instagramUserId,

      commentId:
        job.commentId,

      username:
        job.commenterUsername,

      text:
        job.commentText
    }
  );

  console.log(
    "======================================"
  );

  let account =
    await resolveWebhookAccount(
      job.instagramUserId
    );

  if (!account) {
    console.error(
      "ACCOUNT COULD NOT BE RESOLVED:",
      job.instagramUserId
    );

    return {
      attempted: false,
      executed: false,
      accountId: null
    };
  }

  account =
    await refreshAccountTokenIfNeeded(
      account
    );

  const automation =
    await getAutomationForAccount(
      account
    );

  if (
    automation?.enabled ===
    false
  ) {
    console.log(
      `Automation OFF for @${account.username}. Comment skipped.`
    );

    return {
      attempted: false,
      executed: false,
      accountId:
        account.id
    };
  }

  const effectiveAccount =
    automation
      ? buildEffectiveAutomationAccount(
          account,
          automation
        )
      : account;

  if (automation) {
    console.log(
      `Using saved public.automations settings for @${account.username} ✅`
    );
  }

  const publicResult =
    await sendPublicReply(
      effectiveAccount,
      job.commentId,
      job.commenterUsername
    );

  if (publicResult.ok) {
    console.log(
      `Public reply sent @${account.username} ✅`
    );

  } else {
    console.error(
      `PUBLIC REPLY FAILED @${account.username}:`,
      publicResult.data
    );
  }

  await sleep(
    750
  );

  const privateResult =
    await sendPrivateReply(
      effectiveAccount,
      job.commentId,
      job.commenterUsername
    );

  if (privateResult.ok) {
    console.log(
      `Private reply sent @${account.username} ✅`
    );

  } else {
    console.error(
      `PRIVATE REPLY FAILED @${account.username}:`,
      privateResult.data
    );
  }

  if (
    publicResult.ok ||
    privateResult.ok
  ) {
    if (
      automation?.id
    ) {
      await updateAutomationStats(
        automation.id
      );
    }

    await recordActivityLog({
      userId:
        account.user_id,

      accountId:
        account.id,

      username:
        account.username,

      commenterUsername:
        job.commenterUsername,

      commentText:
        job.commentText,

      replyText:
        effectiveAccount.public_reply
    });
  }

  return {
    attempted: true,

    executed:
      publicResult.ok ||
      privateResult.ok,

    accountId:
      account.id,

    delaySeconds:
      automation?.delay_seconds ??
      8,

    randomJitterEnabled:
      automation?.random_jitter_enabled ??
      true
  };
}

// =====================================================
// QUEUE
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

      for (
        let i = 0;
        i <
        automationQueue.length;
        i++
      ) {
        const job =
          automationQueue[i];

        const account =
          await resolveWebhookAccount(
            job.instagramUserId
          );

        if (!account) {
          eligibleIndex =
            i;

          break;
        }

        const accountKey =
          String(
            account.id
          );

        const nextAllowed =
          accountNextAllowedTimeMap.get(
            accountKey
          ) || 0;

        if (
          now <
          nextAllowed
        ) {
          continue;
        }

        const automation =
          await getAutomationForAccount(
            account
          );

        if (
          automation?.enabled ===
          false
        ) {
          eligibleIndex =
            i;

          break;
        }

        const rate =
          checkAccountRateLimit(
            accountKey,

            automation?.hourly_limit ??
            80
          );

        if (
          !rate.allowed
        ) {
          continue;
        }

        eligibleIndex =
          i;

        break;
      }

      if (
        eligibleIndex === -1
      ) {
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
          result?.attempted &&
          result?.accountId
        ) {
          const accountKey =
            String(
              result.accountId
            );

          recordAccountSend(
            accountKey
          );

          const nextDelayMs =
            calculateNextDelayMs(
              result.delaySeconds,

              result.randomJitterEnabled
            );

          accountNextAllowedTimeMap.set(
            accountKey,

            Date.now() +
            nextDelayMs
          );

          console.log(
            `Next execution for account #${result.accountId} allowed in ${(nextDelayMs / 1000).toFixed(1)}s`
          );
        }

      } catch (error) {
        console.error(
          "AUTOMATION JOB ERROR:",
          error.message
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
// HOME
// =====================================================

app.get(
  "/",
  async (
    req,
    res
  ) => {
    try {
      const result =
        await pool.query(
          `
          select
            count(*)::int as total,
            count(*) filter (
              where enabled = true
            )::int as active
          from public.instagram_accounts
          `
        );

      return res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ODD BOT</title>
</head>

<body style="font-family:Arial,sans-serif;text-align:center;padding:80px 20px;background:#0f172a;color:#fff">

<h1>ODD BOT</h1>
<h2>Instagram Automation Server</h2>

<p>
Automation:
<strong>
${AUTOMATION_ENABLED ? "ENABLED ✅" : "PAUSED"}
</strong>
</p>

<p>
Connected Accounts:
<strong>${result.rows[0]?.total || 0}</strong>
</p>

<p>
Active Accounts:
<strong>${result.rows[0]?.active || 0}</strong>
</p>

<p>
Database:
<strong>CONNECTED ✅</strong>
</p>

</body>
</html>
      `);

    } catch (error) {
      console.error(
        "HOME DATABASE ERROR:",
        error.message
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
// HEALTH
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

      return res.json({
        success: true,

        database:
          "connected",

        database_time:
          database.rows[0].now,

        automation_enabled:
          AUTOMATION_ENABLED,

        queue:
          automationQueue.length,

        web_risk_configured:
          Boolean(
            GOOGLE_WEB_RISK_API_KEY
          ),

        admin_email_configured:
          Boolean(
            ADMIN_EMAIL
          )
      });

    } catch (error) {
      return res
        .status(500)
        .json({
          success: false,

          database:
            "failed",

          error:
            error.message
        });
    }
  }
);

// =====================================================
// DIRECT CONNECT BLOCKED
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

  if (
    DASHBOARD_API_KEY &&
    authorization ===
    `Bearer ${DASHBOARD_API_KEY}`
  ) {
    req.oddBotDashboardAdmin =
      true;

    return next();
  }

  const token =
    getSupabaseAccessTokenFromRequest(
      req
    );

  const user =
    await verifySupabaseUser(
      token
    );

  if (user?.id) {
    req.oddBotUser =
      user;

    req.oddBotDashboardAdmin =
      false;

    return next();
  }

  return res
    .status(401)
    .json({
      success: false,

      error:
        "Unauthorized"
    });
}

// =====================================================
// STRICT ADMIN AUTH
// =====================================================

async function requireAdminUser(
  req,
  res,
  next
) {
  const accessToken =
    getSupabaseAccessTokenFromRequest(
      req
    );

  if (!accessToken) {
    return res
      .status(401)
      .json({
        success: false,
        error:
          "Supabase access token missing."
      });
  }

  const user =
    await verifySupabaseUser(
      accessToken
    );

  if (!user?.id) {
    return res
      .status(401)
      .json({
        success: false,
        error:
          "Invalid or expired ODD BOT login."
      });
  }

  if (!ADMIN_EMAIL) {
    console.error(
      "ADMIN_EMAIL is missing."
    );

    return res
      .status(500)
      .json({
        success: false,
        error:
          "Admin authentication is not configured."
      });
  }

  const verifiedEmail =
    String(
      user.email || ""
    )
      .trim()
      .toLowerCase();

  if (
    verifiedEmail !==
    ADMIN_EMAIL
  ) {
    return res
      .status(403)
      .json({
        success: false,
        error:
          "Admin access required."
      });
  }

  req.oddBotUser =
    user;

  req.oddBotAccessToken =
    accessToken;

  req.oddBotAdminUserId =
    user.id;

  next();
}

// =====================================================
// DASHBOARD
// =====================================================

app.get(
  "/api/dashboard",
  requireDashboardKey,
  async (
    req,
    res
  ) => {
    try {
      const userId =
        req.oddBotUser?.id ||
        null;

      const result =
        userId
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
              from public.instagram_accounts
              where user_id = $1
              order by created_at desc
              `,
              [
                userId
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
              from public.instagram_accounts
              order by created_at desc
              `
            );

      const now =
        Date.now();

      const accounts =
        result.rows.map(
          account => {
            let status =
              "active";

            if (
              account.enabled ===
              false
            ) {
              status =
                "disabled";

            } else if (
              account.token_expires_at &&
              new Date(
                account.token_expires_at
              ).getTime() <=
              now
            ) {
              status =
                "expired";
            }

            return {
              ...account,
              status
            };
          }
        );

      return res.json({
        success: true,

        stats: {
          connected_accounts:
            accounts.length,

          active_accounts:
            accounts.filter(
              account =>
                account.status ===
                "active"
            ).length,

          disabled_accounts:
            accounts.filter(
              account =>
                account.status ===
                "disabled"
            ).length,

          expired_accounts:
            accounts.filter(
              account =>
                account.status ===
                "expired"
            ).length,

          queue:
            automationQueue.length
        },

        accounts
      });

    } catch (error) {
      console.error(
        "DASHBOARD API ERROR:",
        error.message
      );

      return res
        .status(500)
        .json({
          success: false,

          error:
            "Dashboard data unavailable."
        });
    }
  }
);

// =====================================================
// LOAD AUTOMATION
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

      if (!accountId) {
        return res
          .status(400)
          .json({
            success: false,

            error:
              "account_id is required."
          });
      }

      const account =
        await getOwnedInstagramAccount(
          req.oddBotUser.id,
          accountId
        );

      if (!account) {
        return res
          .status(404)
          .json({
            success: false,

            error:
              "Instagram account not found for this user."
          });
      }

      const automation =
        await getAutomationForAccount(
          account
        );

      return res.json({
        success: true,

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
        error.message
      );

      return res
        .status(500)
        .json({
          success: false,

          error:
            "Unable to load automation settings."
        });
    }
  }
);

// =====================================================
// SAVE AUTOMATION + WEB RISK + ADMIN REVIEW
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

      if (!accountId) {
        return res
          .status(400)
          .json({
            success: false,
            error:
              "account_id is required."
          });
      }

      const account =
        await getOwnedInstagramAccount(
          req.oddBotUser.id,
          accountId
        );

      if (!account) {
        return res
          .status(404)
          .json({
            success: false,
            error:
              "Instagram account not found for this user."
          });
      }

      const input =
        normalizeAutomationInput(
          req.body
        );

      const currentAutomation =
        await getAutomationForAccount(
          account
        );

      const currentApprovedUrl =
        String(
          currentAutomation?.channel_url ||
          account.channel_url ||
          DEFAULT_CHANNEL_URL ||
          ""
        ).trim();

      const urlCheck =
        validateDestinationUrl(
          input.channelUrl
        );

      if (!urlCheck.valid) {
        console.warn(
          "UNSAFE DESTINATION URL REJECTED:",
          {
            accountId:
              account.id,
            reason:
              urlCheck.reason ||
              urlCheck.error
          }
        );

        return res
          .status(400)
          .json({
            success: false,
            code:
              "UNSAFE_DESTINATION_URL",
            reason:
              urlCheck.reason ||
              "LOCAL_VALIDATION_FAILED",
            error:
              "ئەم لینکە قبوڵ ناکرێت ❌",
            details:
              urlCheck.error
          });
      }

      // Empty destination remains compatible with existing behavior.
      if (!input.channelUrl) {
        input.channelUrl =
          "";

        const automation =
          await saveAutomationForOwnedAccount(
            account,
            input
          );

        return res.json({
          success: true,
          code:
            "LINK_APPROVED",
          message:
            "Automation settings saved.",
          automation:
            serializeAutomationForClient(
              account,
              automation
            )
        });
      }

      // Exact official hosts are allowed immediately after local validation.
      if (urlCheck.isOfficial) {
        input.channelUrl =
          urlCheck.url;

        const automation =
          await saveAutomationForOwnedAccount(
            account,
            input
          );

        return res.json({
          success: true,
          code:
            "LINK_APPROVED",
          message:
            "لینکە فەرمییەکە پەسەندکرا و Save بوو ✅",
          link_safety: {
            safe: true,
            platform:
              urlCheck.platform,
            status:
              "approved"
          },
          automation:
            serializeAutomationForClient(
              account,
              automation
            )
        });
      }

      // A custom URL already active on this account can keep being used.
      const currentUrlCheck =
        validateDestinationUrl(
          currentApprovedUrl
        );

      if (
        currentUrlCheck.valid &&
        currentUrlCheck.url &&
        currentUrlCheck.url ===
        urlCheck.url
      ) {
        input.channelUrl =
          currentApprovedUrl;

        const automation =
          await saveAutomationForOwnedAccount(
            account,
            input
          );

        return res.json({
          success: true,
          code:
            "LINK_APPROVED",
          message:
            "Automation settings saved.",
          automation:
            serializeAutomationForClient(
              account,
              automation
            )
        });
      }

      // Custom destinations must pass Google Web Risk first.
      const webRisk =
        await checkGoogleWebRisk(
          urlCheck.url
        );

      // Fail closed: provider errors never activate or queue the new URL.
      if (!webRisk.ok) {
        console.error(
          "CUSTOM LINK WEB RISK CHECK FAILED:",
          {
            accountId:
              account.id,
            reason:
              webRisk.error
          }
        );

        return res
          .status(503)
          .json({
            success: false,
            code:
              "WEB_RISK_CHECK_FAILED",
            error:
              "پشکنینی پاراستنی لینک سەرکەوتوو نەبوو. تکایە دواتر هەوڵ بدەرەوە."
          });
      }

      // A known threat match is rejected and never becomes active.
      if (!webRisk.safe) {
        await recordRejectedThreatLink({
          userId:
            req.oddBotUser.id,
          accountId:
            account.id,
          requestedUrl:
            input.channelUrl,
          normalizedUrl:
            urlCheck.url,
          hostname:
            urlCheck.hostname,
          threats:
            webRisk.threats
        });

        return res
          .status(400)
          .json({
            success: false,
            code:
              "UNSAFE_DESTINATION_URL",
            reason:
              "THREAT_DETECTED",
            error:
              "ئەم لینکە لە پشکنینی Google Web Risk ـدا threat ـی ناسراوی بۆ دۆزرایەوە ❌",
            threat_types:
              webRisk.threats
          });
      }

      // Previously approved exact custom URL may be re-used after this fresh scan.
      const approvedReview =
        await findApprovedLinkReview({
          userId:
            req.oddBotUser.id,
          accountId:
            account.id,
          normalizedUrl:
            urlCheck.url
        });

      if (approvedReview) {
        input.channelUrl =
          urlCheck.url;

        const automation =
          await saveAutomationForOwnedAccount(
            account,
            input
          );

        return res.json({
          success: true,
          code:
            "LINK_APPROVED",
          message:
            "لینکەکە پێشتر لەلایەن Admin پەسەندکراوە و Save بوو ✅",
          link_review:
            serializeLinkReview(
              approvedReview
            ),
          automation:
            serializeAutomationForClient(
              account,
              automation
            )
        });
      }

      // Web Risk returned no known threat match. Keep old active link
      // and create/reuse a pending admin review for the custom URL.
      const pendingReview =
        await upsertPendingLinkReview({
          userId:
            req.oddBotUser.id,
          accountId:
            account.id,
          requestedUrl:
            input.channelUrl,
          normalizedUrl:
            urlCheck.url,
          hostname:
            urlCheck.hostname,
          platform:
            "custom"
        });

      const safeInput = {
        ...input,
        channelUrl:
          currentApprovedUrl
      };

      const automation =
        await saveAutomationForOwnedAccount(
          account,
          safeInput
        );

      return res
        .status(202)
        .json({
          success: true,
          code:
            "LINK_PENDING_ADMIN_APPROVAL",
          message:
            "لە Google Web Risk ـدا threat ـی ناسراو نەدۆزرایەوە ✅ ئێستا لینکەکە چاوەڕێی پەسەندکردنی Admin ـە.",
          active_channel_url:
            currentApprovedUrl,
          pending_channel_url:
            urlCheck.url,
          link_review:
            serializeLinkReview(
              pendingReview
            ),
          automation:
            serializeAutomationForClient(
              account,
              automation
            )
        });

    } catch (error) {
      console.error(
        "SAVE AUTOMATION ERROR:",
        error.message
      );

      return res
        .status(500)
        .json({
          success: false,
          error:
            "Unable to save automation settings."
        });
    }
  }
);

// =====================================================
// LINK SAFETY PREVIEW FOR USER UI
// =====================================================

app.post(
  "/api/link-safety/check",
  requireSupabaseUser,
  async (
    req,
    res
  ) => {
    try {
      const rawUrl =
        String(
          req.body?.url ||
          req.body?.channel_url ||
          req.body?.channelUrl ||
          ""
        ).trim();

      const validation =
        validateDestinationUrl(
          rawUrl
        );

      if (!validation.valid) {
        return res
          .status(400)
          .json({
            valid: false,
            code:
              "UNSAFE_DESTINATION_URL",
            reason:
              validation.reason,
            error:
              validation.error
          });
      }

      if (!rawUrl) {
        return res.json({
          valid: true,
          isOfficial: true,
          platform:
            "empty",
          domain:
            "",
          status:
            "approved"
        });
      }

      if (validation.isOfficial) {
        return res.json({
          valid: true,
          isOfficial: true,
          platform:
            validation.platform,
          domain:
            validation.hostname,
          status:
            "approved",
          webRiskStatus:
            "safe"
        });
      }

      const webRisk =
        await checkGoogleWebRisk(
          validation.url
        );

      if (!webRisk.ok) {
        return res
          .status(503)
          .json({
            valid: false,
            code:
              "WEB_RISK_CHECK_FAILED",
            error:
              "Unable to verify destination URL right now."
          });
      }

      if (!webRisk.safe) {
        return res
          .status(400)
          .json({
            valid: false,
            code:
              "UNSAFE_DESTINATION_URL",
            reason:
              "THREAT_DETECTED",
            threats:
              webRisk.threats,
            status:
              "rejected",
            webRiskStatus:
              "unsafe"
          });
      }

      const previewAccountId =
        String(
          req.body?.account_id ||
          req.body?.accountId ||
          ""
        ).trim();

      let approvedReview =
        null;

      if (
        previewAccountId &&
        /^\d+$/.test(
          previewAccountId
        )
      ) {
        approvedReview =
          await findApprovedLinkReview({
            userId:
              req.oddBotUser.id,
            accountId:
              previewAccountId,
            normalizedUrl:
              validation.url
          });

      } else {
        const approvedResult =
          await pool.query(
            `
            select *
            from public.link_review_requests
            where user_id = $1
            and normalized_url = $2
            and review_status = 'approved'
            order by
              reviewed_at desc nulls last,
              created_at desc
            limit 1
            `,
            [
              req.oddBotUser.id,
              validation.url
            ]
          );

        approvedReview =
          approvedResult.rows[0] ||
          null;
      }

      return res.json({
        valid: true,
        isOfficial: false,
        platform:
          "custom",
        domain:
          validation.hostname,
        status:
          approvedReview
            ? "approved"
            : "pending",
        webRiskStatus:
          "safe",
        existingReview:
          serializeLinkReview(
            approvedReview
          )
      });

    } catch (error) {
      console.error(
        "LINK SAFETY PREVIEW ERROR:",
        error.message
      );

      return res
        .status(500)
        .json({
          valid: false,
          error:
            "Unable to check destination URL."
        });
    }
  }
);

// =====================================================
// USER LINK REVIEWS
// =====================================================

app.get(
  "/api/user/link-reviews",
  requireSupabaseUser,
  async (
    req,
    res
  ) => {
    try {
      const result =
        await pool.query(
          `
          select
            lr.*,
            ia.username
          from public.link_review_requests lr
          left join public.instagram_accounts ia
            on ia.id = lr.account_id
            and ia.user_id = lr.user_id
          where lr.user_id = $1
          order by lr.created_at desc
          `,
          [
            req.oddBotUser.id
          ]
        );

      return res.json(
        result.rows.map(
          serializeLinkReview
        )
      );

    } catch (error) {
      console.error(
        "USER LINK REVIEWS ERROR:",
        error.message
      );

      return res
        .status(500)
        .json({
          success: false,
          error:
            "Unable to load link reviews."
        });
    }
  }
);

// =====================================================
// ADMIN LINK REVIEWS
// =====================================================

app.get(
  "/api/admin/link-reviews",
  requireAdminUser,
  async (
    req,
    res
  ) => {
    try {
      const statusFilter =
        String(
          req.query?.status ||
          ""
        )
          .trim()
          .toLowerCase();

      const params = [];
      let whereSql = "";

      if (
        [
          "pending",
          "approved",
          "rejected"
        ].includes(
          statusFilter
        )
      ) {
        params.push(
          statusFilter
        );

        whereSql =
          "where lr.review_status = $1";
      }

      const result =
        await pool.query(
          `
          select
            lr.*,
            ia.username
          from public.link_review_requests lr
          left join public.instagram_accounts ia
            on ia.id = lr.account_id
            and ia.user_id = lr.user_id
          ${whereSql}
          order by lr.created_at desc
          `,
          params
        );

      return res.json(
        result.rows.map(
          serializeLinkReview
        )
      );

    } catch (error) {
      console.error(
        "ADMIN LINK REVIEWS ERROR:",
        error.message
      );

      return res
        .status(500)
        .json({
          success: false,
          error:
            "Unable to load link reviews."
        });
    }
  }
);

app.post(
  "/api/admin/link-reviews/:id/approve",
  requireAdminUser,
  async (
    req,
    res
  ) => {
    const client =
      await pool.connect();

    try {
      await client.query(
        "begin"
      );

      const reviewResult =
        await client.query(
          `
          select *
          from public.link_review_requests
          where id = $1
          for update
          `,
          [
            req.params.id
          ]
        );

      const review =
        reviewResult.rows[0];

      if (!review) {
        await client.query(
          "rollback"
        );

        return res
          .status(404)
          .json({
            success: false,
            error:
              "Link review request not found."
          });
      }

      if (
        review.review_status !==
        "pending"
      ) {
        await client.query(
          "rollback"
        );

        return res
          .status(409)
          .json({
            success: false,
            error:
              "This link review is no longer pending."
          });
      }

      const validation =
        validateDestinationUrl(
          review.normalized_url
        );

      if (
        !validation.valid ||
        !validation.url
      ) {
        const rejected =
          await client.query(
            `
            update public.link_review_requests
            set
              safety_status = 'unsafe',
              review_status = 'rejected',
              rejection_reason =
                'URL failed final local safety validation.',
              reviewed_by = $2,
              reviewed_at = now(),
              updated_at = now()
            where id = $1
            returning *
            `,
            [
              review.id,
              req.oddBotAdminUserId
            ]
          );

        await client.query(
          "commit"
        );

        return res
          .status(400)
          .json({
            success: false,
            code:
              "UNSAFE_DESTINATION_URL",
            linkReview:
              serializeLinkReview(
                rejected.rows[0]
              )
          });
      }

      // Custom URLs are scanned again at approval time.
      if (!validation.isOfficial) {
        const webRisk =
          await checkGoogleWebRisk(
            validation.url
          );

        if (!webRisk.ok) {
          await client.query(
            "rollback"
          );

          return res
            .status(503)
            .json({
              success: false,
              code:
                "WEB_RISK_CHECK_FAILED",
              error:
                "Final Google Web Risk check failed. Link remains pending."
            });
        }

        if (!webRisk.safe) {
          const rejected =
            await client.query(
              `
              update public.link_review_requests
              set
                safety_status = 'unsafe',
                threat_types = $2::jsonb,
                review_status = 'rejected',
                rejection_reason =
                  'Rejected by final Google Web Risk scan.',
                reviewed_by = $3,
                reviewed_at = now(),
                updated_at = now()
              where id = $1
              returning *
              `,
              [
                review.id,
                JSON.stringify(
                  webRisk.threats || []
                ),
                req.oddBotAdminUserId
              ]
            );

          await client.query(
            "commit"
          );

          return res
            .status(400)
            .json({
              success: false,
              code:
                "UNSAFE_DESTINATION_URL",
              threat_types:
                webRisk.threats,
              linkReview:
                serializeLinkReview(
                  rejected.rows[0]
                )
            });
        }
      }

      const accountResult =
        await client.query(
          `
          select
            id,
            user_id,
            username
          from public.instagram_accounts
          where id = $1
          and user_id = $2
          for update
          `,
          [
            review.account_id,
            review.user_id
          ]
        );

      if (!accountResult.rows[0]) {
        await client.query(
          "rollback"
        );

        return res
          .status(404)
          .json({
            success: false,
            error:
              "Associated Instagram account no longer exists."
          });
      }

      const automationResult =
        await client.query(
          `
          select id
          from public.automations
          where account_id = $1
          and user_id = $2
          order by
            updated_at desc nulls last,
            created_at desc
          limit 1
          for update
          `,
          [
            review.account_id,
            review.user_id
          ]
        );

      const automationRow =
        automationResult.rows[0];

      if (!automationRow) {
        await client.query(
          "rollback"
        );

        return res
          .status(409)
          .json({
            success: false,
            error:
              "Associated automation no longer exists."
          });
      }

      // Only channel_url changes at approval. Other automation settings stay untouched.
      await client.query(
        `
        update public.automations
        set
          channel_url = $1,
          updated_at = now()
        where id = $2
        and account_id = $3
        and user_id = $4
        `,
        [
          validation.url,
          automationRow.id,
          review.account_id,
          review.user_id
        ]
      );

      const approved =
        await client.query(
          `
          update public.link_review_requests
          set
            normalized_url = $2,
            hostname = $3,
            safety_status = 'safe',
            threat_types = '[]'::jsonb,
            review_status = 'approved',
            rejection_reason = null,
            reviewed_by = $4,
            reviewed_at = now(),
            updated_at = now()
          where id = $1
          returning *
          `,
          [
            review.id,
            validation.url,
            validation.hostname,
            req.oddBotAdminUserId
          ]
        );

      await client.query(
        "commit"
      );

      return res.json({
        success: true,
        message:
          `Link ${validation.url} has been approved.`,
        linkReview:
          serializeLinkReview(
            approved.rows[0]
          )
      });

    } catch (error) {
      try {
        await client.query(
          "rollback"
        );
      } catch {}

      console.error(
        "ADMIN LINK APPROVE ERROR:",
        error.message
      );

      return res
        .status(500)
        .json({
          success: false,
          error:
            "Unable to approve destination link."
        });

    } finally {
      client.release();
    }
  }
);

app.post(
  "/api/admin/link-reviews/:id/reject",
  requireAdminUser,
  async (
    req,
    res
  ) => {
    const client =
      await pool.connect();

    try {
      await client.query(
        "begin"
      );

      const reviewResult =
        await client.query(
          `
          select *
          from public.link_review_requests
          where id = $1
          for update
          `,
          [
            req.params.id
          ]
        );

      const review =
        reviewResult.rows[0];

      if (!review) {
        await client.query(
          "rollback"
        );

        return res
          .status(404)
          .json({
            success: false,
            error:
              "Link review request not found."
          });
      }

      if (
        review.review_status !==
        "pending"
      ) {
        await client.query(
          "rollback"
        );

        return res
          .status(409)
          .json({
            success: false,
            error:
              "This link review is no longer pending."
          });
      }

      const reason =
        String(
          req.body?.rejection_reason ||
          req.body?.reason ||
          "Rejected by administrator."
        )
          .trim()
          .slice(0, 1000);

      const rejected =
        await client.query(
          `
          update public.link_review_requests
          set
            review_status = 'rejected',
            rejection_reason = $2,
            reviewed_by = $3,
            reviewed_at = now(),
            updated_at = now()
          where id = $1
          returning *
          `,
          [
            review.id,
            reason,
            req.oddBotAdminUserId
          ]
        );

      // Deliberately do not modify public.automations.channel_url.
      await client.query(
        "commit"
      );

      return res.json({
        success: true,
        message:
          `Link ${review.normalized_url} has been rejected.`,
        linkReview:
          serializeLinkReview(
            rejected.rows[0]
          )
      });

    } catch (error) {
      try {
        await client.query(
          "rollback"
        );
      } catch {}

      console.error(
        "ADMIN LINK REJECT ERROR:",
        error.message
      );

      return res
        .status(500)
        .json({
          success: false,
          error:
            "Unable to reject destination link."
        });

    } finally {
      client.release();
    }
  }
);

// =====================================================
// DASHBOARD DISCONNECT
// Keeps automation settings for reconnect
// =====================================================

app.post(
  "/api/instagram/disconnect",
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

      if (!accountId) {
        return res
          .status(400)
          .json({
            success: false,

            error:
              "account_id is required."
          });
      }

      const account =
        await getOwnedInstagramAccount(
          req.oddBotUser.id,
          accountId
        );

      if (!account) {
        return res
          .status(404)
          .json({
            success: false,

            error:
              "Instagram account not found for this user."
          });
      }

      console.log(
        `Dashboard disconnect requested @${account.username}`
      );

      let metaUnsubscribed =
        false;

      let warning =
        null;

      // =================================================
      // REMOVE META WEBHOOK SUBSCRIPTION
      // =================================================

      if (
        account.access_token
      ) {
        try {
          const response =
            await fetch(
              "https://graph.instagram.com/v26.0/me/subscribed_apps",
              {
                method: "DELETE",

                headers: {
                  Authorization:
                    `Bearer ${account.access_token}`
                }
              }
            );

          const data =
            safeJsonParse(
              await response.text()
            );

          const errorMessage =
            String(
              data?.error?.message ||
              ""
            ).toLowerCase();

          if (
            (
              response.ok &&
              data?.success !== false
            ) ||
            errorMessage.includes(
              "not subscribed"
            )
          ) {
            metaUnsubscribed =
              true;

            console.log(
              `Meta webhook subscription removed/already removed @${account.username} ✅`
            );

          } else {
            warning =
              data;

            console.error(
              `META UNSUBSCRIBE WARNING @${account.username}:`,
              data
            );
          }

        } catch (error) {
          warning = {
            error:
              error.message
          };

          console.error(
            "META UNSUBSCRIBE NETWORK WARNING:",
            error.message
          );
        }
      }

      // =================================================
      // DISABLE LOCAL CONNECTION
      // Keep automation settings for reconnect
      // =================================================

      const result =
        await pool.query(
          `
          update public.instagram_accounts
          set
            access_token = null,
            token_expires_at = null,
            enabled = false,
            updated_at = now()
          where id = $1
          and user_id = $2
          returning *
          `,
          [
            account.id,
            req.oddBotUser.id
          ]
        );

      if (!result.rows[0]) {
        throw new Error(
          "Unable to disconnect Instagram account."
        );
      }

      clearAccountRuntimeState([
        account
      ]);

      console.log(
        `Instagram disconnected from ODD BOT @${account.username} ✅`
      );

      return res.json({
        success: true,

        account: {
          id:
            account.id,

          username:
            account.username,

          enabled:
            false
        },

        meta_unsubscribed:
          metaUnsubscribed,

        warning:
          metaUnsubscribed
            ? null
            : (
                warning ||
                "Meta unsubscribe could not be confirmed."
              ),

        message:
          `@${account.username} disconnected successfully.`
      });

    } catch (error) {
      console.error(
        "DASHBOARD DISCONNECT ERROR:",
        error.message
      );

      return res
        .status(500)
        .json({
          success: false,

          error:
            "Unable to disconnect Instagram account."
        });
    }
  }
);

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
// WEBHOOK POST
// =====================================================

app.post(
  "/api/webhooks/instagram",
  requireInstagramWebhookSignature,
  (
    req,
    res
  ) => {
    // Reply quickly to Meta.
    res.sendStatus(200);

    try {
      const entries =
        req.body.entry ||
        [];

      for (
        const entry of entries
      ) {
        const instagramUserId =
          String(
            entry.id || ""
          );

        for (
          const change of
          entry.changes ||
          []
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
              value.id || ""
            );

          const commentText =
            String(
              value.text || ""
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
            AUTOMATION_ENABLED
          ) {
            enqueueCommentAutomation({
              instagramUserId,
              commentId,
              commentText,
              commenterId,
              commenterUsername
            });
          }
        }

        for (
          const event of
          entry.messaging ||
          []
        ) {
          if (
            !event.message
          ) {
            continue;
          }

          console.log(
            "Normal Instagram DM received:",
            {
              account:
                instagramUserId,

              sender:
                event.sender?.id ||
                "",

              text:
                event.message?.text ||
                ""
            }
          );
        }
      }

    } catch (error) {
      console.error(
        "WEBHOOK ERROR:",
        error.message
      );
    }
  }
);

// =====================================================
// START INSTAGRAM OAUTH
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
            success: false,

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
            success: false,

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
            success: false,

            error:
              "OAUTH_STATE_SECRET is missing."
          });
      }

      const accessToken =
        String(
          req.body?.access_token ||
          ""
        ).trim();

      if (!accessToken) {
        return res
          .status(401)
          .json({
            success: false,

            error:
              "Supabase access token missing."
          });
      }

      const user =
        await verifySupabaseUser(
          accessToken
        );

      if (!user?.id) {
        return res
          .status(401)
          .json({
            success: false,

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

      return res.json({
        success: true,

        url:
          "https://www.instagram.com/oauth/authorize?" +
          params.toString()
      });

    } catch (error) {
      console.error(
        "START INSTAGRAM OAUTH ERROR:",
        error.message
      );

      return res
        .status(500)
        .json({
          success: false,

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

      if (error) {
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

      if (!code) {
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

      if (!oauthState) {
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
            method: "POST",

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

      if (!longResult.ok) {
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

      // Subscribe/re-subscribe webhook
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
            method: "POST",

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

      console.log(
        "Instagram Connected/Reconnected ✅",
        {
          username:
            savedAccount.username,

          accountId:
            savedAccount.id,

          enabled:
            savedAccount.enabled
        }
      );

      return res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Instagram Connected</title>
</head>

<body style="font-family:Arial,sans-serif;text-align:center;padding:80px 20px;background:#0f172a;color:#fff">

<h1>Instagram Connected ✅</h1>

<h2>@${profile.username}</h2>

<p>ODD BOT connection active ✅</p>
<p>Long-lived token active ✅</p>
<p>Webhook active ✅</p>
<p>Your saved automation settings are ready.</p>
<p>You can close this page and return to ODD BOT.</p>

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
// PRIVACY
// =====================================================

app.get(
  "/privacy",
  (
    req,
    res
  ) => {
    return res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy Policy</title>
</head>

<body style="font-family:Arial,sans-serif;max-width:800px;margin:50px auto;padding:20px;line-height:1.7">

<h1>Privacy Policy</h1>

<p>
ODD BOT uses Instagram API services to provide Instagram automation features.
</p>

<p>
We process only information required to provide the requested service.
</p>

<p>
We do not sell personal information.
</p>

<p>
Users can disconnect their Instagram account from ODD BOT at any time.
</p>

<p>
Disconnecting stops ODD BOT access without deleting the user's Instagram profile, posts, followers or messages.
</p>

<p>
Users may also request deletion of stored Instagram-related ODD BOT data.
</p>

<p>
ODD BOT validates destination links before activation. Official supported-platform links may be approved immediately; custom websites are checked for known threats and require administrator approval before activation.
</p>

<p>
Last updated: August 2026
</p>

</body>
</html>
    `);
  }
);

// =====================================================
// META DEAUTHORIZE
// =====================================================

app.post(
  "/deauthorize",
  async (
    req,
    res
  ) => {
    try {
      const payload =
        parseAndVerifyMetaSignedRequest(
          String(
            req.body?.signed_request ||
            req.query?.signed_request ||
            ""
          ).trim()
        );

      if (!payload) {
        return res
          .status(400)
          .json({
            success: false,

            error:
              "Invalid signed_request."
          });
      }

      const deleted =
        await deleteMetaLinkedAccountData(
          payload.user_id
        );

      console.log(
        "META DEAUTHORIZE COMPLETED ✅",
        {
          deletedAccounts:
            deleted.length,

          usernames:
            deleted.map(
              account =>
                account.username
            )
        }
      );

      return res.sendStatus(
        200
      );

    } catch (error) {
      console.error(
        "DEAUTHORIZE ERROR:",
        error.message
      );

      return res
        .status(500)
        .json({
          success: false,

          error:
            "Unable to process deauthorization."
        });
    }
  }
);

// =====================================================
// META DATA DELETION
// =====================================================

app.post(
  "/data-deletion",
  async (
    req,
    res
  ) => {
    try {
      const payload =
        parseAndVerifyMetaSignedRequest(
          String(
            req.body?.signed_request ||
            req.query?.signed_request ||
            ""
          ).trim()
        );

      if (!payload) {
        return res
          .status(400)
          .json({
            success: false,

            error:
              "Invalid signed_request."
          });
      }

      const deleted =
        await deleteMetaLinkedAccountData(
          payload.user_id
        );

      const confirmationCode =
        createDeletionConfirmationCode();

      console.log(
        "META DATA DELETION COMPLETED ✅",
        {
          deletedAccounts:
            deleted.length,

          usernames:
            deleted.map(
              account =>
                account.username
            )
        }
      );

      return res.json({
        url:
          `${PUBLIC_BASE_URL}/data-deletion-status?code=${encodeURIComponent(
            confirmationCode
          )}`,

        confirmation_code:
          confirmationCode
      });

    } catch (error) {
      console.error(
        "DATA DELETION ERROR:",
        error.message
      );

      return res
        .status(500)
        .json({
          success: false,

          error:
            "Unable to process data deletion request."
        });
    }
  }
);

// =====================================================
// DATA DELETION STATUS
// =====================================================

app.get(
  "/data-deletion-status",
  (
    req,
    res
  ) => {
    const confirmation =
      verifyDeletionConfirmationCode(
        String(
          req.query?.code ||
          ""
        )
      );

    if (!confirmation) {
      return res
        .status(404)
        .send(
          "Invalid deletion confirmation."
        );
    }

    return res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Deletion Completed</title>
</head>

<body style="font-family:Arial,sans-serif;text-align:center;padding:80px 20px;background:#0f172a;color:#fff">

<h1>Data Deletion Completed ✅</h1>

<p>
Your Instagram-related ODD BOT data has been deleted.
</p>

<p>
Completed:
${confirmation.completedAt}
</p>

</body>
</html>
    `);
  }
);

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

    console.log(
      "META WEBHOOK SIGNATURE VERIFICATION ENABLED ✅"
    );

    console.log(
      "META DATA DELETION & DEAUTHORIZE ENABLED ✅"
    );

    console.log(
      "DASHBOARD INSTAGRAM DISCONNECT ENABLED ✅"
    );

    console.log(
      "SAFE DESTINATION LINK VALIDATION ENABLED ✅"
    );

    console.log(
      "GOOGLE WEB RISK + ADMIN LINK REVIEW ENABLED ✅"
    );

    console.log(
      `GOOGLE WEB RISK CONFIGURED: ${
        GOOGLE_WEB_RISK_API_KEY
          ? "YES ✅"
          : "NO ❌"
      }`
    );

    console.log(
      `ADMIN EMAIL CONFIGURED: ${
        ADMIN_EMAIL
          ? "YES ✅"
          : "NO ❌"
      }`
    );
  }
);


// =====================================================
// INSTAGRAM BUSINESS LOGIN OAUTH
// =====================================================
app.get("/auth/instagram", (req, res) => {
  const appId = process.env.INSTAGRAM_APP_ID;
  const redirectUri = process.env.INSTAGRAM_REDIRECT_URI;

  if (!appId || !redirectUri) {
    return res.status(500).json({ error: "Instagram OAuth is not configured." });
  }

  const authorizationUrl = new URL("https://www.instagram.com/oauth/authorize");
  authorizationUrl.search = new URLSearchParams({
    client_id: appId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: [
      "instagram_business_basic",
      "instagram_business_manage_messages",
      "instagram_business_manage_comments"
    ].join(",")
  }).toString();

  return res.redirect(authorizationUrl.toString());
});

app.get("/auth/instagram/callback", async (req, res) => {
  const appId = process.env.INSTAGRAM_APP_ID;
  const appSecret = process.env.INSTAGRAM_APP_SECRET;
  const redirectUri = process.env.INSTAGRAM_REDIRECT_URI;
  const code = String(req.query.code || "").trim();

  if (!appId || !appSecret || !redirectUri) {
    return res.status(500).json({ error: "Instagram OAuth is not configured." });
  }

  if (!code) {
    return res.status(400).json({ error: "Missing Instagram authorization code." });
  }

  try {
    const tokenResponse = await fetch("https://api.instagram.com/oauth/access_token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: appId,
        client_secret: appSecret,
        grant_type: "authorization_code",
        redirect_uri: redirectUri,
        code
      })
    });
    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok) {
      console.error("INSTAGRAM OAUTH TOKEN EXCHANGE FAILED:", {
        status: tokenResponse.status,
        error_type: tokenData.error_type,
        error_message: tokenData.error_message
      });
      return res.status(502).json({ error: "Instagram token exchange failed." });
    }

    return res.status(200).json({
      success: true,
      message: "Instagram account connected successfully.",
      user_id: tokenData.user_id
    });
  } catch (error) {
    console.error("INSTAGRAM OAUTH CALLBACK ERROR:", error.message);
    return res.status(502).json({ error: "Unable to complete Instagram authorization." });
  }
});
