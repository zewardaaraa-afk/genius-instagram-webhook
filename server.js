const express = require("express");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =====================================================
// ENVIRONMENT VARIABLES
// =====================================================

const VERIFY_TOKEN = process.env.VERIFY_TOKEN;

const INSTAGRAM_APP_ID = process.env.INSTAGRAM_APP_ID;
const INSTAGRAM_APP_SECRET = process.env.INSTAGRAM_APP_SECRET;

const INSTAGRAM_REDIRECT_URI =
  process.env.INSTAGRAM_REDIRECT_URI ||
  "https://genius-instagram-webhook.onrender.com/auth/instagram/callback";

// false = automation paused
// anything else / unset = enabled
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
// MESSAGES
// =====================================================

const PUBLIC_REPLY_MESSAGE =
  "سوپاس بۆ کۆمێنتەکەت ❤️ بە نامە چەنەڵەکەمان بۆت ناردووە 📩 بەشداری بکە تا هەر کات بەشی تازە هات، ڕاستەوخۆ ئاگادار بیت 🔔✨";


const PRIVATE_DM_MESSAGE = `بۆ ئەوەی بەشی نوێ کە دانرا ڕاستەوخۆ بیبینیت ❤️
بەشداری لە چەنەڵەکەمان بکە تا هیچ بەشێکت لەدەست نەچێت 🔔

هەروەها فێرکاری دادەنرێت 💪🏻

👇 چەنەڵەکەمان:
https://www.instagram.com/channel/AbavzQ9R_hOf0pRG/`;


// =====================================================
// LIMIT PROTECTION
// =====================================================

// Our own safe limits.
// These are intentionally lower than Meta's hard limit.

const MAX_JOBS_PER_MINUTE = 8;
const MAX_JOBS_PER_HOUR = 400;

// 60 seconds / 8 = 7.5 seconds
const MIN_GAP_MS =
  Math.ceil(60000 / MAX_JOBS_PER_MINUTE);


// Queue
const automationQueue = [];

// Time history of sent automation jobs
const sendHistory = [];

// Avoid duplicate webhook processing
const processedComments = new Set();

let queueWorkerRunning = false;


// =====================================================
// HELPERS
// =====================================================

const sleep = (ms) =>
  new Promise(resolve =>
    setTimeout(resolve, ms)
  );


function cleanupHistory(now = Date.now()) {

  while (
    sendHistory.length &&
    sendHistory[0] <= now - 3600000
  ) {
    sendHistory.shift();
  }
}


function getRateStatus(now = Date.now()) {

  cleanupHistory(now);

  const lastMinute =
    sendHistory.filter(
      timestamp =>
        timestamp > now - 60000
    );

  return {
    minuteCount: lastMinute.length,
    hourCount: sendHistory.length,
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


  // Minute protection
  if (
    minuteCount >= MAX_JOBS_PER_MINUTE &&
    lastMinute.length
  ) {

    waitMs = Math.max(
      waitMs,
      lastMinute[0] +
        60000 -
        now +
        250
    );
  }


  // Hour protection
  if (
    hourCount >= MAX_JOBS_PER_HOUR &&
    sendHistory.length
  ) {

    waitMs = Math.max(
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

  let lastData = null;


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


      let data;

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
      if (response.ok) {

        return {
          ok: true,
          status: response.status,
          data
        };
      }


      // Retry only rate-limit / server errors
      const retryable =
        response.status === 429 ||
        response.status >= 500;


      console.error(
        `${label} failed (${response.status}):`,
        data
      );


      if (
        !retryable ||
        attempt === maxAttempts
      ) {

        return {
          ok: false,
          status: response.status,
          data
        };
      }


      const retryAfterSeconds =
        Number(
          response.headers.get(
            "retry-after"
          )
        );


      const fallbackDelay =
        attempt * 10000;


      const waitMs =
        Number.isFinite(
          retryAfterSeconds
        )
          ? retryAfterSeconds * 1000
          : fallbackDelay;


      console.log(
        `${label}: retrying in ${Math.ceil(waitMs / 1000)} seconds`
      );


      await sleep(waitMs);


    } catch (error) {

      console.error(
        `${label} network error:`,
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
      lastData || {}
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
      method: "POST",

      headers: {

        Authorization:
          `Bearer ${instagramAccessToken}`,

        "Content-Type":
          "application/x-www-form-urlencoded"
      },

      body
    },

    "Public reply"
  );
}


// =====================================================
// PRIVATE DM TO COMMENTER
// =====================================================

async function sendPrivateReply(
  igUserId,
  commentId
) {

  return fetchJsonWithRetry(

    `https://graph.instagram.com/v26.0/${igUserId}/messages`,

    {
      method: "POST",

      headers: {

        Authorization:
          `Bearer ${instagramAccessToken}`,

        "Content-Type":
          "application/json"
      },

      body:
        JSON.stringify({

          recipient: {
            comment_id:
              commentId
          },

          message: {
            text:
              PRIVATE_DM_MESSAGE
          }
        })
    },

    "Private reply"
  );
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
    "PROCESSING QUEUED COMMENT"
  );

  console.log(
    "Comment ID:",
    commentId
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
    "======================================"
  );


  if (
    !instagramAccessToken
  ) {

    console.error(
      "Instagram access token is not loaded. Job skipped."
    );

    return;
  }


  // ---------------------------------
  // PUBLIC REPLY
  // ---------------------------------

  const publicResult =
    await sendPublicReply(
      commentId
    );


  console.log(
    "Public reply result:",
    publicResult.data
  );


  // Small gap between Meta requests
  await sleep(750);


  // ---------------------------------
  // PRIVATE DM
  // ---------------------------------

  const privateResult =
    await sendPrivateReply(
      igUserId,
      commentId
    );


  console.log(
    "Private reply result:",
    privateResult.data
  );
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


  queueWorkerRunning = true;


  try {

    while (
      automationQueue.length > 0
    ) {


      // ---------------------------------
      // PAUSE
      // ---------------------------------

      if (
        !AUTOMATION_ENABLED
      ) {

        console.log(
          "Automation PAUSED. Queue stopped."
        );

        break;
      }


      // ---------------------------------
      // CHECK LIMIT
      // ---------------------------------

      const waitForLimit =
        getRequiredWaitMs();


      if (
        waitForLimit > 0
      ) {

        console.log(
          `Rate protection active. Waiting ${Math.ceil(waitForLimit / 1000)} seconds.`
        );


        await sleep(
          waitForLimit
        );


        continue;
      }


      // ---------------------------------
      // GET NEXT COMMENT
      // ---------------------------------

      const job =
        automationQueue.shift();


      // Count this automation job
      sendHistory.push(
        Date.now()
      );


      try {

        await handleCommentAutomation(
          job
        );

      } catch (error) {

        console.error(
          "Queued job failed:",
          error
        );
      }


      // Keep safe gap
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


    // New job arrived while worker stopped
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

  // Duplicate protection
  if (
    processedComments.has(
      job.commentId
    )
  ) {

    console.log(
      "Duplicate webhook skipped:",
      job.commentId
    );

    return;
  }


  processedComments.add(
    job.commentId
  );


  // Prevent memory getting too large
  if (
    processedComments.size > 5000
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
    `Comment queued. Queue size: ${automationQueue.length}`
  );


  setImmediate(
    processAutomationQueue
  );
}


// =====================================================
// HOME
// =====================================================

app.get("/", (req, res) => {

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
          Protection:
          8 comments/minute •
          400 comments/hour
        </p>

      </body>

    </html>
  `);
});


// =====================================================
// HEALTH CHECK
// =====================================================

app.get(
  "/health",
  (req, res) => {

    res.status(200).json({

      success: true,

      server:
        "running",

      automation_enabled:
        AUTOMATION_ENABLED,

      instagram_token_loaded:
        Boolean(
          instagramAccessToken
        )
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
// META WEBHOOK VERIFICATION
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
        "Webhook verified successfully!"
      );


      return res
        .status(200)
        .send(
          challenge
        );
    }


    console.log(
      "Webhook verification failed."
    );


    return res
      .sendStatus(403);
  }
);


// =====================================================
// RECEIVE INSTAGRAM WEBHOOK
// =====================================================

app.post(
  "/api/webhooks/instagram",
  (req, res) => {

    // Meta gets 200 immediately
    res.sendStatus(200);


    console.log(
      "Instagram webhook received!"
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
        const entry
        of entries
      ) {


        // ---------------------------------
        // COMMENTS
        // ---------------------------------

        const changes =
          entry.changes || [];


        for (
          const change
          of changes
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


          // Missing IDs
          if (
            !commentId ||
            !igUserId
          ) {

            console.log(
              "Missing ID. Skipped."
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
            connectedInstagramId &&
            commenterId &&
            commenterId ===
              String(
                connectedInstagramId
              );


          const isOurReplyText =
            commentText ===
            PUBLIC_REPLY_MESSAGE;


          if (
            isOwnUsername ||
            isOwnId ||
            isOurReplyText
          ) {

            console.log(
              "Own/reply comment skipped to prevent loop."
            );

            continue;
          }


          // PAUSED
          if (
            !AUTOMATION_ENABLED
          ) {

            console.log(
              "Automation PAUSED. Comment logged only."
            );

            continue;
          }


          // QUEUE IT
          enqueueCommentAutomation({

            commentId,

            commentText,

            commenterId,

            commenterUsername,

            igUserId
          });
        }


        // ---------------------------------
        // NORMAL DM LOGGING
        // NO AUTO CHAT REPLY
        // ---------------------------------

        const messaging =
          entry.messaging || [];


        for (
          const event
          of messaging
        ) {

          if (
            !event.message
          ) {
            continue;
          }


          console.log(
            "INSTAGRAM DM RECEIVED:",
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


      if (error) {

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


      if (!code) {

        return res
          .status(400)
          .send(
            "Instagram authorization code missing."
          );
      }


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


      // ---------------------------------
      // TOKEN EXCHANGE
      // ---------------------------------

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


      const tokenData =
        await tokenResponse.json();


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
        "Instagram access token received successfully."
      );


      // ---------------------------------
      // PROFILE
      // ---------------------------------

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
        await profileResponse.json();


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


      // ---------------------------------
      // SUBSCRIBE WEBHOOKS
      // ---------------------------------

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
        await subscriptionResponse.json();


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


      // ---------------------------------
      // SUCCESS
      // ---------------------------------

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
              Protection:
              8 comments/minute •
              400 comments/hour
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
            Last updated:
            August 2026
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

    console.log(
      "Instagram data deletion request received."
    );


    return res
      .status(200)
      .json({

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
      "AUTOMATION STATUS:",
      AUTOMATION_ENABLED
        ? "ENABLED"
        : "PAUSED"
    );


    console.log(
      `LIMIT PROTECTION: ${MAX_JOBS_PER_MINUTE}/minute, ${MAX_JOBS_PER_HOUR}/hour`
    );
  }
);
