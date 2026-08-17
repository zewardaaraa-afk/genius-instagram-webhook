const express = require("express");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));


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

const AUTOMATION_ENABLED =
  process.env.AUTOMATION_ENABLED !== "false";


// =====================================================
// INSTAGRAM TOKEN
// =====================================================

let instagramAccessToken =
  process.env.INSTAGRAM_ACCESS_TOKEN || "";

let tokenExpiresAt = null;

let lastTokenRefreshAt = 0;

let lastRefreshAttemptAt = 0;


// =====================================================
// INSTAGRAM ACCOUNT
// =====================================================

let connectedInstagramId =
  process.env.INSTAGRAM_ACCOUNT_ID || "";

let connectedInstagramUsername =
  (
    process.env.INSTAGRAM_USERNAME ||
    "callmegenius"
  ).toLowerCase();


// =====================================================
// CHANNEL
// =====================================================

const CHANNEL_URL =
  "https://www.instagram.com/channel/AbavzQ9R_hOf0pRG/";


// =====================================================
// PUBLIC COMMENT REPLY
// =====================================================

const PUBLIC_REPLY_MESSAGE = `بە نامە چەنەڵەکەمان بۆت ناردووە 📩

بەشداری بکە تا هەر کات بەشی تازە هات، ڕاستەوخۆ ئاگادار بیت 🔔✨

ئەگەر نامەکەت نەهات، Follow ـمان بکە و سەیری Message Requests بکە ❤️`;


// =====================================================
// PRIVATE MESSAGE
// =====================================================

const PRIVATE_BUTTON_TEXT = `بۆ ئەوەی بەشی نوێ دانرا ڕاستەوخۆ بیبینیت، بەشداری لە چەناڵەکەمان بکە ❤️

هەروەها فێرکاری دادەنرێت 💪🏻`;


// =====================================================
// BUTTON
// NO EMOJI
// =====================================================

const CHANNEL_BUTTON_TITLE =
  "پەنجە لێرە بدە";


// =====================================================
// LIMIT PROTECTION
// =====================================================

const MAX_JOBS_PER_MINUTE = 8;

const MAX_JOBS_PER_HOUR = 400;

const MIN_GAP_MS =
  Math.ceil(
    60000 / MAX_JOBS_PER_MINUTE
  );

const automationQueue = [];

const sendHistory = [];

const processedComments =
  new Set();

let queueWorkerRunning = false;


// =====================================================
// HELPERS
// =====================================================

function sleep(ms) {

  return new Promise(
    resolve =>
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
// SHORT TOKEN -> LONG-LIVED TOKEN
// =====================================================

async function exchangeForLongLivedToken(
  shortLivedToken
) {

  try {

    const params =
      new URLSearchParams({

        grant_type:
          "ig_exchange_token",

        client_secret:
          INSTAGRAM_APP_SECRET,

        access_token:
          shortLivedToken
      });


    const response =
      await fetch(
        "https://graph.instagram.com/access_token?" +
          params.toString(),
        {
          method: "GET"
        }
      );


    const raw =
      await response.text();

    const data =
      safeJsonParse(raw);


    if (
      !response.ok ||
      !data.access_token
    ) {

      console.error(
        "LONG-LIVED TOKEN EXCHANGE FAILED:",
        data
      );


      return {
        ok: false,
        data
      };
    }


    instagramAccessToken =
      data.access_token;


    const expiresIn =
      Number(
        data.expires_in ||
        5184000
      );


    tokenExpiresAt =
      Date.now() +
      expiresIn * 1000;


    lastTokenRefreshAt =
      Date.now();


    console.log(
      "Long-lived Instagram token created successfully."
    );


    console.log(
      `Token lifetime: ${Math.round(expiresIn / 86400)} days`
    );


    return {
      ok: true,
      data
    };


  } catch (error) {

    console.error(
      "LONG-LIVED TOKEN ERROR:",
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
// REFRESH LONG-LIVED TOKEN
// =====================================================

async function refreshLongLivedToken(
  force = false
) {

  if (
    !instagramAccessToken
  ) {

    return false;
  }


  const now =
    Date.now();


  if (
    !force &&
    lastRefreshAttemptAt &&
    now - lastRefreshAttemptAt <
      6 * 60 * 60 * 1000
  ) {

    return true;
  }


  if (
    !force &&
    lastTokenRefreshAt &&
    now - lastTokenRefreshAt <
      24 * 60 * 60 * 1000
  ) {

    return true;
  }


  lastRefreshAttemptAt =
    now;


  try {

    const params =
      new URLSearchParams({

        grant_type:
          "ig_refresh_token",

        access_token:
          instagramAccessToken
      });


    const response =
      await fetch(
        "https://graph.instagram.com/refresh_access_token?" +
          params.toString(),
        {
          method: "GET"
        }
      );


    const raw =
      await response.text();

    const data =
      safeJsonParse(raw);


    if (
      !response.ok ||
      !data.access_token
    ) {

      console.error(
        "TOKEN REFRESH FAILED:",
        data
      );


      return false;
    }


    instagramAccessToken =
      data.access_token;


    const expiresIn =
      Number(
        data.expires_in ||
        5184000
      );


    tokenExpiresAt =
      Date.now() +
      expiresIn * 1000;


    lastTokenRefreshAt =
      Date.now();


    console.log(
      "Instagram token refreshed successfully."
    );


    console.log(
      `New token lifetime: ${Math.round(expiresIn / 86400)} days`
    );


    return true;


  } catch (error) {

    console.error(
      "TOKEN REFRESH ERROR:",
      error
    );


    return false;
  }
}


// =====================================================
// AUTO REFRESH CHECK
// =====================================================

setInterval(

  async () => {

    if (
      instagramAccessToken
    ) {

      await refreshLongLivedToken(
        false
      );
    }

  },

  6 * 60 * 60 * 1000
);


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
// META REQUEST WITH RETRY
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


      const waitMs =
        Number.isFinite(
          retryAfter
        )
          ? retryAfter * 1000
          : attempt * 10000;


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
  commentId
) {

  const body =
    new URLSearchParams();


  body.append(
    "message",
    PUBLIC_REPLY_MESSAGE
  );


  return fetchJsonWithRetry(

    `https://graph.instagram.com/v26.0/${commentId}/replies`,

    {

      method:
        "POST",

      headers: {

        Authorization:
          `Bearer ${instagramAccessToken}`,

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
  igUserId,
  commentId
) {

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

          text:
            PRIVATE_BUTTON_TEXT,

          buttons: [

            {

              type:
                "web_url",

              url:
                CHANNEL_URL,

              title:
                CHANNEL_BUTTON_TITLE
            }
          ]
        }
      }
    }
  };


  return fetchJsonWithRetry(

    `https://graph.instagram.com/v26.0/${igUserId}/messages`,

    {

      method:
        "POST",

      headers: {

        Authorization:
          `Bearer ${instagramAccessToken}`,

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
// FALLBACK PRIVATE MESSAGE
// =====================================================

async function sendPrivateLinkFallback(
  igUserId,
  commentId
) {

  const payload = {

    recipient: {

      comment_id:
        commentId
    },

    message: {

      text: `${PRIVATE_BUTTON_TEXT}

پەنجە لێرە بدە

${CHANNEL_URL}`
    }
  };


  return fetchJsonWithRetry(

    `https://graph.instagram.com/v26.0/${igUserId}/messages`,

    {

      method:
        "POST",

      headers: {

        Authorization:
          `Bearer ${instagramAccessToken}`,

        "Content-Type":
          "application/json"
      },

      body:
        JSON.stringify(
          payload
        )
    },

    "PRIVATE LINK FALLBACK"
  );
}


// =====================================================
// PRIVATE REPLY
// =====================================================

async function sendPrivateReply(
  igUserId,
  commentId
) {

  console.log(
    "Trying private channel button..."
  );


  const buttonResult =
    await sendPrivateButton(
      igUserId,
      commentId
    );


  if (
    buttonResult.ok
  ) {

    console.log(
      "Private button sent successfully."
    );


    return buttonResult;
  }


  console.log(
    "Button unavailable. Sending link fallback..."
  );


  const fallbackResult =
    await sendPrivateLinkFallback(
      igUserId,
      commentId
    );


  if (
    fallbackResult.ok
  ) {

    console.log(
      "Fallback link sent successfully."
    );

  } else {

    console.error(
      "PRIVATE REPLY FAILED:",
      fallbackResult.data
    );
  }


  return fallbackResult;
}


// =====================================================
// PROCESS COMMENT
// =====================================================

async function handleCommentAutomation(
  job
) {

  const {

    commentId,

    igUserId,

    commenterUsername,

    commentText

  } = job;


  console.log(
    "======================================"
  );


  console.log(
    "NEW AUTOMATION JOB"
  );


  console.log(
    "Username:",
    commenterUsername
  );


  console.log(
    "Comment:",
    commentText
  );


  console.log(
    "Comment ID:",
    commentId
  );


  console.log(
    "======================================"
  );


  if (
    !instagramAccessToken
  ) {

    console.error(
      "Instagram Access Token Missing."
    );


    return;
  }


  await refreshLongLivedToken(
    false
  );


  // =================================================
  // PUBLIC REPLY
  // =================================================

  const publicResult =
    await sendPublicReply(
      commentId
    );


  if (
    publicResult.ok
  ) {

    console.log(
      "Public comment reply sent."
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


  // =================================================
  // PRIVATE MESSAGE
  // =================================================

  const privateResult =
    await sendPrivateReply(
      igUserId,
      commentId
    );


  if (
    privateResult.ok
  ) {

    console.log(
      "Private message sent."
    );

  } else {

    console.error(
      "Private message failed."
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
      automationQueue.length > 0
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
        waitForLimit > 0
      ) {

        console.log(
          `Limit protection: waiting ${Math.ceil(waitForLimit / 1000)} seconds`
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
        automationQueue.length > 0
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
      automationQueue.length > 0 &&
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
      "Duplicate comment skipped."
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
    `Comment queued. Queue: ${automationQueue.length}`
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
  (req, res) => {

    res.status(200).send(`

<!DOCTYPE html>

<html>

<head>
<meta charset="UTF-8">
<title>Genius Instagram Automation</title>
</head>

<body style="
font-family:Arial,sans-serif;
text-align:center;
padding:80px;
">

<h1>
Genius Instagram Automation
</h1>

<p>
Automation:
<strong>
${
  AUTOMATION_ENABLED
    ? "ENABLED"
    : "PAUSED"
}
</strong>
</p>

<p>
Token:
<strong>
60-Day + Auto Refresh
</strong>
</p>

<p>
Public Comment:
<strong>
Auto Reply
</strong>
</p>

<p>
Private Button:
<strong>
پەنجە لێرە بدە
</strong>
</p>

<p>
Limit:
<strong>
8/minute • 400/hour
</strong>
</p>

</body>

</html>
    `);
  }
);


// =====================================================
// HEALTH
// =====================================================

app.get(
  "/health",
  (req, res) => {

    res.status(200).json({

      success:
        true,

      server:
        "running",

      automation_enabled:
        AUTOMATION_ENABLED,

      instagram_token_loaded:
        Boolean(
          instagramAccessToken
        ),

      token_expires_at:
        tokenExpiresAt
          ? new Date(
              tokenExpiresAt
            ).toISOString()
          : "unknown",

      instagram_account:
        connectedInstagramUsername
    });
  }
);


// =====================================================
// QUEUE STATUS
// =====================================================

app.get(
  "/queue-status",
  (req, res) => {

    const {
      minuteCount,
      hourCount
    } = getRateStatus();


    res.status(200).json({

      automation_enabled:
        AUTOMATION_ENABLED,

      queued_comments:
        automationQueue.length,

      processed_last_minute:
        minuteCount,

      processed_last_hour:
        hourCount,

      limits: {

        per_minute:
          MAX_JOBS_PER_MINUTE,

        per_hour:
          MAX_JOBS_PER_HOUR
      }
    });
  }
);


// =====================================================
// WEBHOOK VERIFICATION
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

      console.log(
        "Webhook Verified."
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
  (req, res) => {

    res.sendStatus(
      200
    );


    console.log(
      "Instagram Webhook Received."
    );


    try {

      const entries =
        req.body.entry || [];


      for (
        const entry of entries
      ) {


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


          const commenterUsername =
            String(
              value.from?.username ||
              "unknown"
            );


          const igUserId =
            String(
              entry.id ||
              connectedInstagramId ||
              ""
            );


          if (
            !commentId ||
            !igUserId
          ) {

            console.log(
              "Missing comment/account ID."
            );


            continue;
          }


          // =================================================
          // LOOP PROTECTION
          // =================================================

          const isOwnUsername =
            commenterUsername
              .toLowerCase() ===
            connectedInstagramUsername;


          const isOwnId =
            commenterId ===
            igUserId;


          const isOurReply =
            commentText ===
            PUBLIC_REPLY_MESSAGE;


          if (
            isOwnUsername ||
            isOwnId ||
            isOurReply
          ) {

            console.log(
              "Own comment/reply skipped."
            );


            continue;
          }


          if (
            !AUTOMATION_ENABLED
          ) {

            continue;
          }


          enqueueCommentAutomation({

            commentId,

            commentText,

            commenterId,

            commenterUsername,

            igUserId
          });
        }


        // =================================================
        // NORMAL DMs
        // LOG ONLY
        // =================================================

        const messaging =
          entry.messaging || [];


        for (
          const event of messaging
        ) {

          if (
            !event.message
          ) {

            continue;
          }


          console.log(
            "Normal Instagram DM:",
            {

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


    console.log(
      "Starting Instagram Login..."
    );


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

  async (req, res) => {

    try {

      const {
        code,
        error,
        error_description
      } = req.query;


      if (
        error
      ) {

        console.error(
          "Instagram OAuth Error:",
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
            "Instagram App ID or App Secret missing."
          );
      }


      // =================================================
      // STEP 1:
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


      const shortRaw =
        await shortResponse.text();


      const shortData =
        safeJsonParse(
          shortRaw
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


      console.log(
        "Short-Lived Token Received."
      );


      // =================================================
      // STEP 2:
      // SHORT TOKEN -> LONG-LIVED TOKEN
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
            "Could not create long-lived Instagram token. Check Render Logs."
          );
      }


      // =================================================
      // PROFILE
      // =================================================

      const profileResponse =
        await fetch(

          "https://graph.instagram.com/v26.0/me?fields=id,username",

          {

            headers: {

              Authorization:
                `Bearer ${instagramAccessToken}`
            }
          }
        );


      const profile =
        safeJsonParse(
          await profileResponse.text()
        );


      if (
        !profileResponse.ok
      ) {

        console.error(
          "PROFILE REQUEST FAILED:",
          profile
        );


        return res
          .status(500)
          .send(
            "Instagram profile request failed."
          );
      }


      connectedInstagramId =
        String(
          profile.id ||
          ""
        );


      connectedInstagramUsername =
        String(
          profile.username ||
          "callmegenius"
        ).toLowerCase();


      console.log(
        "Connected Instagram:",
        profile.username
      );


      // =================================================
      // SUBSCRIBE COMMENTS + MESSAGES
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
                `Bearer ${instagramAccessToken}`,

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
        "Webhook Subscription:",
        subscriptionData
      );


      if (
        !subscriptionResponse.ok
      ) {

        return res
          .status(500)
          .send(
            "Instagram connected, but webhook subscription failed."
          );
      }


      // =================================================
      // SUCCESS
      // =================================================

      return res.send(`

<!DOCTYPE html>

<html>

<head>
<meta charset="UTF-8">
<title>Genius Automation</title>
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
Long-Lived Token: Active
</p>

<p>
Auto Refresh: Active
</p>

<p>
Comments Webhook: Active
</p>

<p>
Messages Webhook: Active
</p>

<p>
Automation:
<strong>
${
  AUTOMATION_ENABLED
    ? "ENABLED"
    : "PAUSED"
}
</strong>
</p>

<p>
Private Button:
<strong>
پەنجە لێرە بدە
</strong>
</p>

<p>
Limit:
<strong>
8/minute • 400/hour
</strong>
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
// PRIVACY
// =====================================================

app.get(
  "/privacy",
  (req, res) => {

    res.send(`

<!DOCTYPE html>

<html>

<head>
<meta charset="UTF-8">
<title>Privacy Policy</title>
</head>

<body style="
font-family:Arial,sans-serif;
max-width:800px;
margin:50px auto;
line-height:1.7;
padding:20px;
">

<h1>
Privacy Policy
</h1>

<p>
Genius Automation uses Instagram API services to provide Instagram automation.
</p>

<p>
We process only information required to operate the automation service.
</p>

<p>
We do not sell personal information.
</p>

<p>
Users may request deletion of their data.
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
  (req, res) => {

    return res
      .status(200)
      .json({
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
      "AUTOMATION:",
      AUTOMATION_ENABLED
        ? "ENABLED"
        : "PAUSED"
    );


    console.log(
      "TOKEN: LONG-LIVED + AUTO REFRESH"
    );


    console.log(
      "BUTTON: پەنجە لێرە بدە"
    );


    console.log(
      `LIMIT: ${MAX_JOBS_PER_MINUTE}/minute • ${MAX_JOBS_PER_HOUR}/hour`
    );
  }
);
