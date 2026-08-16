const express = require("express");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =====================================================
// ENVIRONMENT VARIABLES
// =====================================================

const VERIFY_TOKEN = process.env.VERIFY_TOKEN;

const INSTAGRAM_APP_ID =
  process.env.INSTAGRAM_APP_ID;

const INSTAGRAM_APP_SECRET =
  process.env.INSTAGRAM_APP_SECRET;

const INSTAGRAM_REDIRECT_URI =
  process.env.INSTAGRAM_REDIRECT_URI ||
  "https://genius-instagram-webhook.onrender.com/auth/instagram/callback";

const AUTOMATION_ENABLED =
  process.env.AUTOMATION_ENABLED !== "false";

let instagramAccessToken =
  process.env.INSTAGRAM_ACCESS_TOKEN || "";

let connectedInstagramId =
  process.env.INSTAGRAM_ACCOUNT_ID || "";

let connectedInstagramUsername =
  (
    process.env.INSTAGRAM_USERNAME ||
    "callmegenius"
  ).toLowerCase();


// =====================================================
// INSTAGRAM CHANNEL
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
// PRIVATE MESSAGE BEFORE BUTTON
// =====================================================

const PRIVATE_BUTTON_TEXT = `بۆ ئەوەی بەشی نوێ دانرا ڕاستەوخۆ بیبینیت، بەشداری لە چەناڵەکەمان بکە ❤️

هەروەها فێرکاری دادەنرێت 💪🏻`;


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

let queueWorkerRunning =
  false;


// =====================================================
// HELPERS
// =====================================================

function sleep(ms) {

  return new Promise(
    resolve =>
      setTimeout(resolve, ms)
  );
}


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


  // -----------------------------
  // MINUTE LIMIT
  // -----------------------------

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


  // -----------------------------
  // HOUR LIMIT
  // -----------------------------

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
// FETCH JSON WITH RETRY
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


      let data = {};


      try {

        data =
          raw
            ? JSON.parse(raw)
            : {};

      } catch {

        data = {
          raw
        };
      }


      lastData = data;


      // SUCCESS
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


      const retryAfterSeconds =
        Number(
          response.headers.get(
            "retry-after"
          )
        );


      const waitMs =
        Number.isFinite(
          retryAfterSeconds
        )
          ? retryAfterSeconds * 1000
          : attempt * 10000;


      console.log(
        `${label}: retrying in ${Math.ceil(waitMs / 1000)} seconds`
      );


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
// PRIVATE BUTTON MESSAGE
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
                "بینینی چەناڵ"
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
// FALLBACK PRIVATE LINK
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

👇
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
// BUTTON FIRST -> LINK FALLBACK
// =====================================================

async function sendPrivateReply(
  igUserId,
  commentId
) {

  console.log(
    "Trying button: بینینی چەناڵ..."
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
      "Private button sent ✅"
    );

    return buttonResult;
  }


  console.log(
    "Button not accepted. Sending link fallback..."
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
      "Private link fallback sent ✅"
    );

  } else {

    console.error(
      "PRIVATE REPLY FAILED ❌",
      fallbackResult.data
    );
  }


  return fallbackResult;
}


// =====================================================
// PROCESS ONE COMMENT
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
    "PROCESSING COMMENT"
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
      "Instagram access token missing ❌"
    );

    return;
  }


  // =================================================
  // PUBLIC COMMENT REPLY
  // =================================================

  const publicResult =
    await sendPublicReply(
      commentId
    );


  if (
    publicResult.ok
  ) {

    console.log(
      "Public comment reply sent ✅"
    );

  } else {

    console.error(
      "PUBLIC REPLY FAILED ❌",
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
      igUserId,
      commentId
    );


  if (
    privateResult.ok
  ) {

    console.log(
      "Private reply completed ✅"
    );

  } else {

    console.error(
      "Private reply failed ❌"
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


      // -----------------------------
      // AUTOMATION PAUSED
      // -----------------------------

      if (
        !AUTOMATION_ENABLED
      ) {

        console.log(
          "Automation PAUSED ⏸️"
        );

        break;
      }


      // -----------------------------
      // CHECK LIMIT
      // -----------------------------

      const waitForLimit =
        getRequiredWaitMs();


      if (
        waitForLimit > 0
      ) {

        console.log(
          `Limit protection active. Waiting ${Math.ceil(waitForLimit / 1000)} seconds.`
        );


        await sleep(
          waitForLimit
        );


        continue;
      }


      // -----------------------------
      // NEXT JOB
      // -----------------------------

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
          "Automation job error:",
          error
        );
      }


      // -----------------------------
      // GAP BETWEEN COMMENTS
      // -----------------------------

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
      "Duplicate comment skipped:",
      job.commentId
    );

    return;
  }


  processedComments.add(
    job.commentId
  );


  // Prevent unlimited memory growth

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
    `Comment queued ✅ Queue size: ${automationQueue.length}`
  );


  setImmediate(
    processAutomationQueue
  );
}


// =====================================================
// HOME PAGE
// =====================================================

app.get(
  "/",
  (req, res) => {

    res.status(200).send(`

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>
Genius Instagram Automation
</title>

</head>


<body style="
font-family:Arial,sans-serif;
text-align:center;
padding:80px;
">


<h1>
Genius Instagram Automation ✅
</h1>


<p>
Server is running.
</p>


<p>
Automation:
<strong>
${
  AUTOMATION_ENABLED
    ? "ENABLED ✅"
    : "PAUSED ⏸️"
}
</strong>
</p>


<p>
Public Comment Reply:
<strong>
ENABLED ✅
</strong>
</p>


<p>
Private Message:
<strong>
Text + بینینی چەناڵ 🔗
</strong>
</p>


<p>
Fallback:
<strong>
Text + Channel Link ✅
</strong>
</p>


<p>
Limit Protection:
<strong>
8 comments/minute • 400 comments/hour
</strong>
</p>


</body>

</html>
    `);
  }
);


// =====================================================
// HEALTH CHECK
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
      mode === "subscribe" &&
      token === VERIFY_TOKEN
    ) {

      console.log(
        "Webhook verified successfully ✅"
      );


      return res
        .status(200)
        .send(
          challenge
        );
    }


    console.log(
      "Webhook verification failed ❌"
    );


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

    // Meta receives 200 immediately

    res.sendStatus(
      200
    );


    console.log(
      "Instagram webhook received ✅"
    );


    console.log(
      JSON.stringify(
        req.body,
        null,
        2
      )
    );


    try {

      const entries =
        req.body.entry || [];


      for (
        const entry of entries
      ) {


        // =================================================
        // COMMENTS
        // =================================================

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


          const usernameLower =
            commenterUsername
              .toLowerCase();


          const igUserId =
            String(
              entry.id ||
              connectedInstagramId ||
              ""
            );


          console.log(
            "NEW COMMENT:",
            {

              commentId,

              commentText,

              commenterUsername,

              commenterId,

              igUserId
            }
          );


          // -----------------------------
          // REQUIRED IDs
          // -----------------------------

          if (
            !commentId ||
            !igUserId
          ) {

            console.log(
              "Missing comment/account ID. Skipped."
            );

            continue;
          }


          // =================================================
          // LOOP PROTECTION
          // =================================================

          const isOwnUsername =
            connectedInstagramUsername &&
            usernameLower ===
              connectedInstagramUsername;


          const isOwnId =
            commenterId &&
            commenterId ===
              String(
                igUserId
              );


          const isOurReply =
            commentText ===
              PUBLIC_REPLY_MESSAGE;


          if (
            isOwnUsername ||
            isOwnId ||
            isOurReply
          ) {

            console.log(
              "Own comment/reply skipped ✅"
            );

            continue;
          }


          // -----------------------------
          // AUTOMATION PAUSED
          // -----------------------------

          if (
            !AUTOMATION_ENABLED
          ) {

            console.log(
              "Automation paused."
            );

            continue;
          }


          // -----------------------------
          // ADD TO QUEUE
          // -----------------------------

          enqueueCommentAutomation({

            commentId,

            commentText,

            commenterId,

            commenterUsername,

            igUserId
          });
        }


        // =================================================
        // NORMAL INSTAGRAM DMs
        // LOG ONLY
        // NO AUTO REPLY
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
            "NORMAL INSTAGRAM DM:",
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
        "Instagram webhook processing error:",
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
          "INSTAGRAM_APP_ID is missing in Render."
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
      "Starting Instagram login"
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


      // -----------------------------
      // LOGIN ERROR
      // -----------------------------

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
            `Instagram login failed: ${
              error_description ||
              error
            }`
          );
      }


      // -----------------------------
      // MISSING CODE
      // -----------------------------

      if (
        !code
      ) {

        return res
          .status(400)
          .send(
            "Instagram authorization code missing."
          );
      }


      // -----------------------------
      // ENV CHECK
      // -----------------------------

      if (
        !INSTAGRAM_APP_ID ||
        !INSTAGRAM_APP_SECRET
      ) {

        return res
          .status(500)
          .send(
            "Instagram App ID or App Secret is missing in Render."
          );
      }


      // =================================================
      // TOKEN EXCHANGE
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


      const tokenResponse =
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


      const tokenRaw =
        await tokenResponse.text();


      let tokenData = {};


      try {

        tokenData =
          tokenRaw
            ? JSON.parse(tokenRaw)
            : {};

      } catch {

        tokenData = {
          raw:
            tokenRaw
        };
      }


      if (
        !tokenResponse.ok ||
        !tokenData.access_token
      ) {

        console.error(
          "Instagram token exchange failed:",
          tokenData
        );


        return res
          .status(500)
          .send(
            "Instagram token exchange failed. Check Render Logs."
          );
      }


      instagramAccessToken =
        tokenData.access_token;


      console.log(
        "Instagram access token received successfully ✅"
      );


      // =================================================
      // GET PROFILE
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


      const profileRaw =
        await profileResponse.text();


      let profile = {};


      try {

        profile =
          profileRaw
            ? JSON.parse(profileRaw)
            : {};

      } catch {

        profile = {
          raw:
            profileRaw
        };
      }


      if (
        !profileResponse.ok
      ) {

        console.error(
          "Instagram profile failed:",
          profile
        );


        return res
          .status(500)
          .send(
            "Instagram profile request failed. Check Render Logs."
          );
      }


      if (
        profile.id
      ) {

        connectedInstagramId =
          String(
            profile.id
          );
      }


      if (
        profile.username
      ) {

        connectedInstagramUsername =
          String(
            profile.username
          ).toLowerCase();
      }


      console.log(
        "Connected Instagram account:",
        profile
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


      const subscriptionRaw =
        await subscriptionResponse.text();


      let subscriptionData = {};


      try {

        subscriptionData =
          subscriptionRaw
            ? JSON.parse(subscriptionRaw)
            : {};

      } catch {

        subscriptionData = {
          raw:
            subscriptionRaw
        };
      }


      console.log(
        "Webhook subscription result:",
        subscriptionData
      );


      if (
        !subscriptionResponse.ok
      ) {

        return res
          .status(500)
          .send(`
            <h1>
              Instagram Connected ✅
            </h1>

            <p>
              But webhook subscription failed.
            </p>

            <p>
              Check Render Logs.
            </p>
          `);
      }


      // =================================================
      // SUCCESS PAGE
      // =================================================

      return res.send(`

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>
Genius Automation
</title>

</head>


<body style="
font-family:Arial,sans-serif;
text-align:center;
padding:80px;
">


<h1>
Instagram Connected ✅
</h1>


<h2>
@${
  profile.username ||
  "Instagram"
}
</h2>


<p>
Comments and Messages webhooks are subscribed.
</p>


<p>
Automation:
<strong>
${
  AUTOMATION_ENABLED
    ? "ENABLED ✅"
    : "PAUSED ⏸️"
}
</strong>
</p>


<p>
Public Comment Reply:
<strong>
ENABLED ✅
</strong>
</p>


<p>
Private Message:
<strong>
Text + بینینی چەناڵ 🔗
</strong>
</p>


<p>
Fallback:
<strong>
Text + Channel Link ✅
</strong>
</p>


<p>
Limit Protection:
<strong>
8 comments/minute • 400 comments/hour
</strong>
</p>


<p>
You can close this page.
</p>


</body>

</html>
      `);


    } catch (
      callbackError
    ) {

      console.error(
        "Instagram callback error:",
        callbackError
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
Privacy Policy - Genius Automation
</title>

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
Genius Automation uses Instagram API services to provide Instagram automation features.
</p>


<h2>
Information We Process
</h2>


<p>
The service may process Instagram account identifiers, comments, messages and related interaction information required to operate the requested features.
</p>


<h2>
How Information Is Used
</h2>


<p>
Information is used only to provide Instagram automation functionality.
</p>


<h2>
Data Sharing
</h2>


<p>
We do not sell personal information.
</p>


<h2>
Data Retention
</h2>


<p>
Information is retained only as long as necessary to provide the service.
</p>


<h2>
Data Deletion
</h2>


<p>
Users may request deletion of their data by contacting the application owner.
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

    console.log(
      "Instagram deauthorization request received."
    );


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
  (req, res) => {

    console.log(
      "Instagram data deletion request received."
    );


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
        ? "ENABLED ✅"
        : "PAUSED ⏸️"
    );


    console.log(
      `LIMIT PROTECTION: ${MAX_JOBS_PER_MINUTE}/minute, ${MAX_JOBS_PER_HOUR}/hour`
    );


    console.log(
      "PUBLIC COMMENT REPLY: ENABLED ✅"
    );


    console.log(
      "PRIVATE MESSAGE: TEXT + بینینی چەناڵ ✅"
    );
  }
);
