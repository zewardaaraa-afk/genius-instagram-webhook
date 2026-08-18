const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();

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

  const origin =
    req.headers.origin;

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

  if (
    req.method === "OPTIONS"
  ) {

    return res.sendStatus(
      204
    );
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
// AUTOMATION LIMITS & RATE LIMITING
// =====================================================

const MAX_JOBS_PER_MINUTE =
  Number(
    process.env.MAX_JOBS_PER_MINUTE ||
    8
  );

const MAX_JOBS_PER_HOUR =
  Number(
    process.env.MAX_JOBS_PER_HOUR ||
    400
  );

const MIN_GAP_MS =
  Math.ceil(
    60000 /
    MAX_JOBS_PER_MINUTE
  );

const automationQueue =
  [];

const sendHistory =
  [];

const processedComments =
  new Set();

let queueWorkerRunning =
  false;


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

  if (!accessToken) {

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

  if (!user?.id) {

    return res
      .status(401)
      .json({
        success:
          false,

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

  return {

    publicReplyTemplates,

    privateDmMessage,

    buttonText,

    channelUrl,

    enabled
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
        input.enabled
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
        input.enabled
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
// RATE LIMIT CHECKING
// =====================================================

function cleanupHistory(
  now = Date.now()
) {

  while (
    sendHistory.length > 0 &&
    sendHistory[0] <=
    now - 3600000
  ) {

    sendHistory.shift();
  }
}

function getRateStatus(
  now = Date.now()
) {

  cleanupHistory(
    now
  );

  const lastMinute =
    sendHistory.filter(
      timestamp =>
        timestamp >
        now - 60000
    );

  return {

    minuteCount:
      lastMinute.length,

    hourCount:
      sendHistory.length,

    lastMinute
  };
}

function getRequiredWaitMs(
  now = Date.now()
) {

  const {
    minuteCount,
    hourCount,
    lastMinute
  } =
    getRateStatus(
      now
    );

  let waitMs =
    0;

  if (
    minuteCount >=
    MAX_JOBS_PER_MINUTE &&
    lastMinute.length > 0
  ) {

    waitMs =
      Math.max(
        waitMs,

        lastMinute[0] +
        60000 -
        now +
        250
      );
  }

  if (
    hourCount >=
    MAX_JOBS_PER_HOUR &&
    sendHistory.length > 0
  ) {

    waitMs =
      Math.max(
        waitMs,

        sendHistory[0] +
        3600000 -
        now +
        250
      );
  }

  return Math.max(
    0,
    waitMs
  );
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
// PRIVATE BUTTON
// =====================================================

async function sendPrivateButton(
  account,
  commentId,
  commenterUsername = ""
) {

  const channelUrl =
    account.channel_url ||
    DEFAULT_CHANNEL_URL;

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
                channelUrl,

              title:
                buttonTitle
            }
          ]
        }
      }
    }
  };

  return fetchJsonWithRetry(
    `https://graph.instagram.com/v26.0/${account.instagram_user_id}/messages`,
    {
      method:
        "POST",

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

  const channelUrl =
    account.channel_url ||
    DEFAULT_CHANNEL_URL;

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

  const payload = {

    recipient: {
      comment_id:
        commentId
    },

    message: {

      text: `${text}

${buttonTitle}

${channelUrl}`
    }
  };

  return fetchJsonWithRetry(
    `https://graph.instagram.com/v26.0/${account.instagram_user_id}/messages`,
    {
      method:
        "POST",

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
// PRIVATE REPLY (BUTTON OR FALLBACK)
// =====================================================

async function sendPrivateReply(
  account,
  commentId,
  commenterUsername = ""
) {

  const buttonResult =
    await sendPrivateButton(
      account,
      commentId,
      commenterUsername
    );

  if (
    buttonResult.ok
  ) {

    console.log(
      `Private button sent @${account.username} ✅`
    );

    return buttonResult;
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
// PROCESS COMMENT JOB
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

  if (
    !account
  ) {

    console.error(
      "ACCOUNT COULD NOT BE RESOLVED:",
      job.instagramUserId
    );

    return;
  }

  account =
    await refreshAccountTokenIfNeeded(
      account
    );

  let effectiveAccount =
    account;

  const automation =
    await getAutomationForAccount(
      account
    );

  if (
    automation
  ) {

    if (
      automation.enabled ===
      false
    ) {

      console.log(
        `Automation OFF for @${account.username}. Comment skipped.`
      );

      return;
    }

    effectiveAccount =
      buildEffectiveAutomationAccount(
        account,
        automation
      );

    console.log(
      `Using saved public.automations settings for @${account.username} ✅`
    );

  } else {

    console.log(
      `No automation row for @${account.username}; using existing account settings.`
    );
  }

  // 1. Send Public Comment Reply
  const publicResult =
    await sendPublicReply(
      effectiveAccount,
      job.commentId,
      job.commenterUsername
    );

  if (
    publicResult.ok
  ) {

    console.log(
      `Public reply sent @${account.username} ✅`
    );

  } else {

    console.error(
      `PUBLIC REPLY FAILED @${account.username}:`,
      publicResult.data
    );
  }

  // Safety gap before sending Private DM
  await sleep(
    750
  );

  // 2. Send Private DM
  const privateResult =
    await sendPrivateReply(
      effectiveAccount,
      job.commentId,
      job.commenterUsername
    );

  if (
    privateResult.ok
  ) {

    console.log(
      `Private reply sent @${account.username} ✅`
    );

  } else {

    console.error(
      `PRIVATE REPLY FAILED @${account.username}:`,
      privateResult.data
    );
  }

  // 3. Update Stats & Record Activity Logs if successful
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

      const waitForLimit =
        getRequiredWaitMs();

      if (
        waitForLimit >
        0
      ) {

        console.log(
          `Queue waiting ${Math.ceil(waitForLimit / 1000)} seconds`
        );

        await sleep(
          waitForLimit
        );

        continue;
      }

      const job =
        automationQueue.shift();

      sendHistory.push(
        Date.now()
      );

      try {

        await handleCommentAutomation(
          job
        );

      } catch (error) {

        console.error(
          "AUTOMATION JOB ERROR:",
          error
        );
      }

      if (
        automationQueue.length >
        0
      ) {

        await sleep(
          MIN_GAP_MS
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

      setImmediate(
        processAutomationQueue
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

      const input =
        normalizeAutomationInput(
          req.body ||
          {}
        );

      if (
        input.channelUrl &&
        !/^https?:\/\//i.test(
          input.channelUrl
        )
      ) {

        return res
          .status(400)
          .json({

            success:
              false,

            error:
              "Channel URL must start with http:// or https://"
          });
      }

      const automation =
        await saveAutomationForOwnedAccount(
          account,
          input
        );

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
      `RATE LIMIT: ${MAX_JOBS_PER_MINUTE}/minute • ${MAX_JOBS_PER_HOUR}/hour`
    );
  }
);
