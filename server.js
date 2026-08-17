const express = require("express");
const { Pool } = require("pg");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =====================================================
// ENVIRONMENT
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

// =====================================================
// DATABASE
// =====================================================

if (!DATABASE_URL) {
  console.error("DATABASE_URL is missing");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  max: 5
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
// LIMIT PROTECTION
// =====================================================

const MAX_JOBS_PER_MINUTE = 8;
const MAX_JOBS_PER_HOUR = 400;

const MIN_GAP_MS =
  Math.ceil(60000 / MAX_JOBS_PER_MINUTE);

const automationQueue = [];
const sendHistory = [];
const processedComments = new Set();

let queueWorkerRunning = false;

// =====================================================
// HELPERS
// =====================================================

function sleep(ms) {
  return new Promise(resolve =>
    setTimeout(resolve, ms)
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

// =====================================================
// DATABASE HELPERS
// =====================================================

async function saveInstagramAccount({
  instagramUserId,
  username,
  accessToken,
  channelUrl,
  tokenExpiresAt
}) {

  await pool.query(
    `
    insert into instagram_accounts (
      instagram_user_id,
      username,
      access_token,
      channel_url,
      token_expires_at,
      updated_at
    )
    values ($1, $2, $3, $4, $5, now())

    on conflict (instagram_user_id)
    do update set
      username = excluded.username,
      access_token = excluded.access_token,
      channel_url = coalesce(
        instagram_accounts.channel_url,
        excluded.channel_url
      ),
      token_expires_at = excluded.token_expires_at,
      updated_at = now()
    `,
    [
      instagramUserId,
      username,
      accessToken,
      channelUrl,
      tokenExpiresAt
    ]
  );
}

async function getInstagramAccount(
  instagramUserId
) {

  const result =
    await pool.query(
      `
      select *
      from instagram_accounts
      where instagram_user_id = $1
      limit 1
      `,
      [
        instagramUserId
      ]
    );

  return result.rows[0] || null;
}

async function updateAccountToken(
  instagramUserId,
  accessToken,
  expiresAt
) {

  await pool.query(
    `
    update instagram_accounts
    set
      access_token = $1,
      token_expires_at = $2,
      updated_at = now()
    where instagram_user_id = $3
    `,
    [
      accessToken,
      expiresAt,
      instagramUserId
    ]
  );
}

// =====================================================
// LONG-LIVED TOKEN
// =====================================================

async function exchangeForLongLivedToken(
  shortToken
) {

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
      )
  };
}

// =====================================================
// REFRESH TOKEN FOR ACCOUNT
// =====================================================

async function refreshAccountToken(
  account
) {

  if (!account?.access_token) {
    return account;
  }

  try {

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

    await updateAccountToken(
      account.instagram_user_id,
      data.access_token,
      expiresAt
    );

    account.access_token =
      data.access_token;

    account.token_expires_at =
      expiresAt;

    console.log(
      `Token refreshed for @${account.username}`
    );

    return account;

  } catch (error) {

    console.error(
      "TOKEN REFRESH ERROR:",
      error
    );

    return account;
  }
}

// =====================================================
// RATE LIMIT HELPERS
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

  cleanupHistory(now);

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
  } = getRateStatus(now);

  let waitMs = 0;

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
// META REQUEST
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

      const raw =
        await response.text();

      const data =
        safeJsonParse(raw);

      lastData = data;

      if (response.ok) {

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

      await sleep(
        attempt * 10000
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
        attempt * 10000
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
// PRIVATE FALLBACK LINK
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

  const payload = {
    recipient: {
      comment_id:
        commentId
    },
    message: {
      text: `${text}

پەنجە لێرە بدە

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

  if (buttonResult.ok) {

    return buttonResult;
  }

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

  let account =
    await getInstagramAccount(
      job.instagramUserId
    );

  if (!account) {

    console.error(
      "ACCOUNT NOT FOUND IN DATABASE:",
      job.instagramUserId
    );

    return;
  }

  account =
    await refreshAccountToken(
      account
    );

  const publicResult =
    await sendPublicReply(
      account,
      job.commentId
    );

  if (publicResult.ok) {

    console.log(
      `Public reply sent from @${account.username}`
    );

  } else {

    console.error(
      "PUBLIC REPLY FAILED:",
      publicResult.data
    );
  }

  await sleep(
    750
  );

  const privateResult =
    await sendPrivateReply(
      account,
      job.commentId
    );

  if (privateResult.ok) {

    console.log(
      `Private reply sent from @${account.username}`
    );

  } else {

    console.error(
      "PRIVATE REPLY FAILED:",
      privateResult.data
    );
  }
}

// =====================================================
// QUEUE
// =====================================================

async function processAutomationQueue() {

  if (queueWorkerRunning) {
    return;
  }

  queueWorkerRunning = true;

  try {

    while (
      automationQueue.length > 0
    ) {

      if (!AUTOMATION_ENABLED) {
        break;
      }

      const waitForLimit =
        getRequiredWaitMs();

      if (
        waitForLimit > 0
      ) {

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
        automationQueue.length > 0
      ) {

        await sleep(
          MIN_GAP_MS
        );
      }
    }

  } finally {

    queueWorkerRunning = false;

    if (
      automationQueue.length > 0 &&
      AUTOMATION_ENABLED
    ) {

      setImmediate(
        processAutomationQueue
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
          select count(*)::int
          as total
          from instagram_accounts
          `
        );

      const total =
        result.rows[0]?.total || 0;

      res.status(200).send(`

<!DOCTYPE html>

<html>

<head>
<meta charset="UTF-8">
<title>Genius Multi Account</title>
</head>

<body style="
font-family:Arial,sans-serif;
text-align:center;
padding:80px;
">

<h1>
Genius Instagram Multi-Account
</h1>

<p>
Automation:
<strong>
${AUTOMATION_ENABLED
  ? "ENABLED"
  : "PAUSED"}
</strong>
</p>

<p>
Connected Instagram Accounts:
<strong>
${total}
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

      res
        .status(500)
        .send(
          "Database connection failed."
        );
    }
  }
);

// =====================================================
// SIMPLE CONNECT LINK
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

      const db =
        await pool.query(
          "select now()"
        );

      res.status(200).json({
        success: true,
        database: "connected",
        database_time:
          db.rows[0].now,
        automation_enabled:
          AUTOMATION_ENABLED
      });

    } catch (error) {

      res.status(500).json({
        success: false,
        database: "failed",
        error:
          error.message
      });
    }
  }
);

// =====================================================
// WEBHOOK VERIFY
// =====================================================

app.get(
  "/api/webhooks/instagram",
  (req, res) => {

    const mode =
      req.query["hub.mode"];

    const token =
      req.query["hub.verify_token"];

    const challenge =
      req.query["hub.challenge"];

    if (
      mode === "subscribe" &&
      token === VERIFY_TOKEN
    ) {

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
// WEBHOOK RECEIVE
// =====================================================

app.post(
  "/api/webhooks/instagram",
  (req, res) => {

    res.sendStatus(200);

    try {

      const entries =
        req.body.entry || [];

      for (
        const entry of entries
      ) {

        const instagramUserId =
          String(
            entry.id || ""
          );

        const changes =
          entry.changes || [];

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
            change.value || {};

          const commentId =
            value.id;

          const commentText =
            (
              value.text || ""
            ).trim();

          const commenterId =
            String(
              value.from?.id ||
              ""
            );

          if (
            !commentId ||
            !instagramUserId
          ) {

            continue;
          }

          if (
            commenterId ===
            instagramUserId
          ) {

            continue;
          }

          enqueueCommentAutomation({
            instagramUserId,
            commentId,
            commentText
          });
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
// START LOGIN
// =====================================================

app.get(
  "/auth/instagram/start",
  (req, res) => {

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

    return res.redirect(
      "https://www.instagram.com/oauth/authorize?" +
      params.toString()
    );
  }
);

// =====================================================
// CALLBACK
// =====================================================

app.get(
  "/auth/instagram/callback",
  async (req, res) => {

    try {

      const {
        code,
        error,
        error_description
      } = req.query;

      if (error) {

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

      // SHORT TOKEN
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
            "Instagram token exchange failed."
          );
      }

      // LONG TOKEN
      const longResult =
        await exchangeForLongLivedToken(
          shortData.access_token
        );

      if (!longResult.ok) {

        return res
          .status(500)
          .send(
            "Long-lived token failed."
          );
      }

      // PROFILE
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

        return res
          .status(500)
          .send(
            "Instagram profile failed."
          );
      }

      // SAVE TO DB
      await saveInstagramAccount({
        instagramUserId:
          String(profile.id),
        username:
          String(
            profile.username || ""
          ),
        accessToken:
          longResult.accessToken,
        channelUrl:
          DEFAULT_CHANNEL_URL,
        tokenExpiresAt:
          longResult.expiresAt
      });

      // SUBSCRIBE WEBHOOK
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

      if (
        !subscriptionResponse.ok
      ) {

        console.error(
          "WEBHOOK SUBSCRIBE FAILED:",
          subscriptionData
        );

        return res
          .status(500)
          .send(
            "Account saved, but webhook subscription failed."
          );
      }

      return res.send(`

<!DOCTYPE html>

<html>

<head>
<meta charset="UTF-8">
<title>Instagram Connected</title>
</head>

<body style="
font-family:Arial,sans-serif;
text-align:center;
padding:80px;
">

<h1>
Instagram Connected
</h1>

<h2>
@${profile.username}
</h2>

<p>
Account saved to database.
</p>

<p>
Comments webhook active.
</p>

<p>
Messages webhook active.
</p>

<p>
You can close this page.
</p>

</body>

</html>
      `);

    } catch (error) {

      console.error(
        "CALLBACK ERROR:",
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
  (req, res) => {

    res.send(`
      <h1>Privacy Policy</h1>
      <p>
      Genius Automation uses Instagram API services.
      </p>
      <p>
      We do not sell personal information.
      </p>
    `);
  }
);

// =====================================================
// DEAUTHORIZE
// =====================================================

app.post(
  "/deauthorize",
  (req, res) => {

    res.status(200).json({
      success: true
    });
  }
);

// =====================================================
// DATA DELETION
// =====================================================

app.post(
  "/data-deletion",
  (req, res) => {

    res.status(200).json({
      success: true,
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
      "MULTI-ACCOUNT MODE ENABLED"
    );
  }
);