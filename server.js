const express = require("express");
const { Pool } = require("pg");

const app = express();

app.use(express.json());
app.use(
  express.urlencoded({
    extended: true
  })
);


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


// Secret used only by ODD BOT backend.
// Do NOT put this secret directly in browser/frontend code.
const DASHBOARD_API_KEY =
  process.env.DASHBOARD_API_KEY || "";


// =====================================================
// DATABASE
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


const DEFAULT_PUBLIC_REPLY = `بە نامە چەنەڵەکەمان بۆت ناردووە 📩

بەشداری بکە تا هەر کات بەشی تازە هات، ڕاستەوخۆ ئاگادار بیت 🔔✨

ئەگەر نامەکەت نەهات، Follow ـمان بکە و سەیری Message Requests بکە ❤️`;


const DEFAULT_PRIVATE_TEXT = `بۆ ئەوەی بەشی نوێ دانرا ڕاستەوخۆ بیبینیت، بەشداری لە چەناڵەکەمان بکە ❤️

هەروەها فێرکاری دادەنرێت 💪🏻`;


const DEFAULT_BUTTON_TITLE =
  "پەنجە لێرە بدە";


// =====================================================
// AUTOMATION LIMITS
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
// DATABASE
// GET ACCOUNT BY OAUTH ID
// =====================================================

async function getAccountByOAuthId(
  oauthUserId
) {

  const result =
    await pool.query(
      `
      select *
      from instagram_accounts
      where oauth_user_id = $1
      limit 1
      `,
      [
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
// DATABASE
// GET ACCOUNT BY USERNAME
// =====================================================

async function getAccountByUsername(
  username
) {

  const result =
    await pool.query(
      `
      select *
      from instagram_accounts
      where lower(username) = lower($1)
      limit 1
      `,
      [
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
// SAVE / UPDATE ACCOUNT AFTER OAUTH
// =====================================================

async function saveOAuthAccount({
  oauthUserId,
  username,
  accessToken,
  expiresAt
}) {

  let existing =
    await getAccountByOAuthId(
      oauthUserId
    );


  // Old connected account may not have OAuth ID yet.
  if (
    !existing &&
    username
  ) {

    existing =
      await getAccountByUsername(
        username
      );
  }


  // =================================================
  // UPDATE EXISTING ACCOUNT
  // =================================================

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

          existing.id
        ]
      );


    return result.rows[0];
  }


  // =================================================
  // NEW ACCOUNT
  //
  // webhook instagram_user_id stays NULL first.
  // First real webhook automatically maps it.
  // =================================================

  const result =
    await pool.query(
      `
      insert into instagram_accounts (
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
        null,
        $2,
        $3,
        $4,
        $5,
        true,
        now(),
        now()
      )
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


  // Try each connected account token.
  // The correct token should be able to read its own
  // webhook Instagram account identity.

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
            updated.oauth_user_id
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
// RESOLVE ACCOUNT FOR WEBHOOK
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
// SHORT TOKEN -> LONG-LIVED TOKEN
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


    const expiresAt =
      new Date(
        Date.now() +
        expiresIn * 1000
      );


    return {

      ok: true,

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

      ok: false,

      data: {
        error:
          error.message
      }
    };
  }
}


// =====================================================
// REFRESH TOKEN WHEN NEAR EXPIRY
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


  // More than 7 days remaining.
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
// AUTO TOKEN REFRESH CHECK
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
// RATE LIMIT
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

    data:
      lastData
  };
}


// =====================================================
// PUBLIC COMMENT REPLY
// =====================================================

async function sendPublicReply(
  account,
  commentId
) {

  const message =
    account.public_reply ||
    DEFAULT_PUBLIC_REPLY;


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
  commentId
) {

  const channelUrl =
    account.channel_url ||
    DEFAULT_CHANNEL_URL;


  const text =
    account.private_text ||
    DEFAULT_PRIVATE_TEXT;


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
  commentId
) {

  const channelUrl =
    account.channel_url ||
    DEFAULT_CHANNEL_URL;


  const text =
    account.private_text ||
    DEFAULT_PRIVATE_TEXT;


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
// PRIVATE REPLY
// =====================================================

async function sendPrivateReply(
  account,
  commentId
) {

  const buttonResult =
    await sendPrivateButton(
      account,
      commentId
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
    commentId
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


  // =================================================
  // PUBLIC REPLY
  // =================================================

  const publicResult =
    await sendPublicReply(
      account,
      job.commentId
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


  await sleep(
    750
  );


  // =================================================
  // PRIVATE REPLY
  // =================================================

  const privateResult =
    await sendPrivateReply(
      account,
      job.commentId
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
// HOME
// =====================================================

app.get(
  "/",
  async (req, res) => {

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

<title>
ODD BOT
</title>

</head>


<body style="
font-family:Arial,sans-serif;
text-align:center;
padding:80px;
">


<h1>
ODD BOT
</h1>


<h2>
Instagram Automation
</h2>


<p>
Automation:
<strong>
${
  AUTOMATION_ENABLED
    ? "ENABLED ✅"
    : "PAUSED"
}
</strong>
</p>


<p>
Connected Accounts:
<strong>
${total}
</strong>
</p>


<p>
Active Accounts:
<strong>
${active}
</strong>
</p>


<p>
Database:
<strong>
CONNECTED ✅
</strong>
</p>


<p>
<a href="/connect">
Connect Instagram Account
</a>
</p>


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
// CONNECT
// =====================================================

app.get(
  "/connect",
  (req, res) => {

    return res.redirect(
      "/auth/instagram/start"
    );
  }
);


// =====================================================
// HEALTH
// =====================================================

app.get(
  "/health",
  async (req, res) => {

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
// ODD BOT DASHBOARD AUTH
// =====================================================

function requireDashboardKey(
  req,
  res,
  next
) {

  if (
    !DASHBOARD_API_KEY
  ) {

    return res
      .status(503)
      .json({

        success:
          false,

        error:
          "DASHBOARD_API_KEY is not configured."
      });
  }


  const authorization =
    String(
      req.headers.authorization ||
      ""
    );


  const expected =
    `Bearer ${DASHBOARD_API_KEY}`;


  if (
    authorization !==
    expected
  ) {

    return res
      .status(401)
      .json({

        success:
          false,

        error:
          "Unauthorized"
      });
  }


  next();
}


// =====================================================
// ODD BOT DASHBOARD API
//
// SAFE DATA ONLY.
// NEVER RETURNS ACCESS TOKEN OR PASSWORD.
// =====================================================

app.get(
  "/api/dashboard",
  requireDashboardKey,
  async (req, res) => {

    try {

      const result =
        await pool.query(
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
// WEBHOOK VERIFICATION
// =====================================================

app.get(
  "/api/webhooks/instagram",
  (req, res) => {

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
// RECEIVE WEBHOOK
// =====================================================

app.post(
  "/api/webhooks/instagram",
  (req, res) => {

    // Answer Instagram immediately.

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


        // =================================================
        // COMMENTS
        // =================================================

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


          // Don't reply to our own account.

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


        // =================================================
        // NORMAL DMs
        //
        // LOG ONLY.
        // NO NORMAL DM AUTO-REPLY.
        // =================================================

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

app.get(
  "/auth/instagram/start",
  (req, res) => {

    if (
      !INSTAGRAM_APP_ID
    ) {

      return res
        .status(500)
        .send(
          "INSTAGRAM_APP_ID is missing."
        );
    }


    const params =
      new URLSearchParams({

        client_id:
          INSTAGRAM_APP_ID,

        redirect_uri:
          INSTAGRAM_REDIRECT_URI,

        response_type:
          "code",

        scope: [

          "instagram_business_basic",

          "instagram_business_manage_comments",

          "instagram_business_manage_messages"

        ].join(",")
      });


    const loginUrl =
      "https://www.instagram.com/oauth/authorize?" +
      params.toString();


    return res.redirect(
      loginUrl
    );
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
        error_description
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


      // =================================================
      // STEP 1
      // AUTH CODE -> SHORT TOKEN
      // =================================================

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


      // =================================================
      // STEP 2
      // SHORT -> LONG-LIVED TOKEN
      // =================================================

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


      // =================================================
      // STEP 3
      // INSTAGRAM PROFILE
      // =================================================

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


      // =================================================
      // STEP 4
      // SAVE ACCOUNT
      // =================================================

      const savedAccount =
        await saveOAuthAccount({

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
            savedAccount.instagram_user_id
        }
      );


      // =================================================
      // STEP 5
      // SUBSCRIBE WEBHOOK
      // =================================================

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


      // =================================================
      // SUCCESS PAGE
      // =================================================

      return res.send(`

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width, initial-scale=1"
/>

<title>
Instagram Connected
</title>

</head>


<body style="
font-family:Arial,sans-serif;
text-align:center;
padding:80px 20px;
">


<h1>
Instagram Connected ✅
</h1>


<h2>
@${profile.username}
</h2>


<p>
Account saved to database ✅
</p>


<p>
Long-lived token active ✅
</p>


<p>
Comments webhook active ✅
</p>


<p>
Messages webhook active ✅
</p>


<p>
Webhook account ID will be linked automatically on the first comment.
</p>


<p>
You can close this page.
</p>


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
  (req, res) => {

    res.send(`

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>
Privacy Policy
</title>

</head>


<body style="
font-family:Arial,sans-serif;
max-width:800px;
margin:50px auto;
padding:20px;
line-height:1.7;
">


<h1>
Privacy Policy
</h1>


<p>
ODD BOT uses Instagram API services to provide Instagram automation features.
</p>


<p>
We process only information required to provide the requested automation service.
</p>


<p>
We do not sell personal information.
</p>


<p>
Users may request deletion of their information.
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
      "ODD BOT MULTI-ACCOUNT MODE ENABLED ✅"
    );


    console.log(
      "AUTO WEBHOOK ID MAPPING ENABLED ✅"
    );


    console.log(
      "DATABASE TOKEN STORAGE ENABLED ✅"
    );


    console.log(
      "ODD BOT DASHBOARD API ENABLED ✅"
    );


    console.log(
      `LIMIT: ${MAX_JOBS_PER_MINUTE}/minute • ${MAX_JOBS_PER_HOUR}/hour`
    );
  }
);
