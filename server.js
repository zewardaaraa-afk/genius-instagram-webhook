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

// If AUTOMATION_ENABLED is not set, automation is ON.
// To pause everything later, set AUTOMATION_ENABLED=false in Render.
const AUTOMATION_ENABLED =
  process.env.AUTOMATION_ENABLED !== "false";

// Token can come from Render env, or from a fresh Instagram login.
let instagramAccessToken =
  process.env.INSTAGRAM_ACCESS_TOKEN || "";

// Prevent duplicate processing of the same comment
const processedComments = new Set();


// =====================================================
// HOME
// =====================================================

app.get("/", (req, res) => {
  res.status(200).send(`
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="UTF-8">
        <title>Genius Instagram Automation</title>
      </head>

      <body style="
        font-family: Arial, sans-serif;
        text-align: center;
        padding: 80px;
      ">
        <h1>Genius Instagram Automation ✅</h1>

        <p>Server is running.</p>

        <p>
          Automation:
          <strong>
            ${AUTOMATION_ENABLED ? "ENABLED ✅" : "PAUSED ⏸️"}
          </strong>
        </p>
      </body>
    </html>
  `);
});


// =====================================================
// HEALTH CHECK
// =====================================================

app.get("/health", (req, res) => {
  res.status(200).json({
    success: true,
    server: "running",
    automation_enabled: AUTOMATION_ENABLED,
    instagram_token_loaded: Boolean(instagramAccessToken)
  });
});


// =====================================================
// META WEBHOOK VERIFICATION
// =====================================================

app.get("/api/webhooks/instagram", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (
    mode === "subscribe" &&
    token === VERIFY_TOKEN
  ) {
    console.log("Webhook verified successfully!");

    return res
      .status(200)
      .send(challenge);
  }

  console.log("Webhook verification failed.");

  return res.sendStatus(403);
});


// =====================================================
// RECEIVE INSTAGRAM WEBHOOK
// =====================================================

app.post("/api/webhooks/instagram", async (req, res) => {
  // Meta should receive HTTP 200 immediately
  res.sendStatus(200);

  console.log("======================================");
  console.log("Instagram webhook received!");
  console.log(JSON.stringify(req.body, null, 2));
  console.log("======================================");

  try {
    const entries = req.body.entry || [];

    for (const entry of entries) {
      const changes = entry.changes || [];

      for (const change of changes) {
        // We only want Instagram comment events
        if (change.field !== "comments") {
          continue;
        }

        const value = change.value || {};

        const commentId = value.id;
        const commentText =
          (value.text || "").trim();

        const commenterId =
          value.from?.id || "";

        const commenterUsername =
          value.from?.username || "unknown";

        // Professional Instagram account ID
        const igUserId = entry.id;

        console.log("--------------------------------------");
        console.log("NEW COMMENT");
        console.log("Comment ID:", commentId);
        console.log("Comment text:", commentText);
        console.log("Username:", commenterUsername);
        console.log("Commenter ID:", commenterId);
        console.log("IG Account ID:", igUserId);
        console.log("--------------------------------------");


        // =================================================
        // BASIC CHECKS
        // =================================================

        if (!commentId) {
          console.log("No comment ID. Skipped.");
          continue;
        }

        // Prevent processing same webhook more than once
        if (processedComments.has(commentId)) {
          console.log(
            "Comment already processed. Skipped:",
            commentId
          );

          continue;
        }

        processedComments.add(commentId);

        // Keep memory from growing forever
        if (processedComments.size > 1000) {
          processedComments.clear();
        }


        // Do not reply to comments created by our own account
        if (
          commenterId &&
          igUserId &&
          String(commenterId) === String(igUserId)
        ) {
          console.log(
            "Own Instagram comment detected. Skipped."
          );

          continue;
        }


        // Pause switch
        if (!AUTOMATION_ENABLED) {
          console.log(
            "Automation is PAUSED. Nothing sent."
          );

          continue;
        }


        if (!instagramAccessToken) {
          console.error(
            "Instagram access token is not loaded."
          );

          console.error(
            "Reconnect Instagram or add INSTAGRAM_ACCESS_TOKEN in Render."
          );

          continue;
        }


        // =================================================
        // PUBLIC COMMENT REPLY
        // =================================================

        const publicReplyMessage =
          "سوپاس بۆ کۆمێنتەکەت ❤️ بە نامە چەنەڵەکەمان بۆت ناردووە 📩 بەشداری بکە تا هەر کات بەشی تازە هات، ڕاستەوخۆ ئاگادار بیت 🔔✨";

        try {
          const replyBody =
            new URLSearchParams();

          replyBody.append(
            "message",
            publicReplyMessage
          );

          const replyResponse =
            await fetch(
              `https://graph.instagram.com/v26.0/${commentId}/replies`,
              {
                method: "POST",

                headers: {
                  Authorization:
                    `Bearer ${instagramAccessToken}`,
                  "Content-Type":
                    "application/x-www-form-urlencoded"
                },

                body: replyBody
              }
            );

          const replyData =
            await replyResponse.json();

          console.log(
            "Public comment reply result:",
            replyData
          );

          if (!replyResponse.ok) {
            console.error(
              "PUBLIC REPLY FAILED:",
              replyData
            );
          } else {
            console.log(
              "Public comment reply sent ✅"
            );
          }

        } catch (replyError) {
          console.error(
            "Public comment reply error:",
            replyError
          );
        }


        // =================================================
        // PRIVATE DM TO COMMENTER
        // =================================================

       const privateMessage = `بۆ ئەوەی بەشی نوێ کە دانرا ڕاستەوخۆ بیبینیت ❤️
بەشداری لە چەنەڵەکەمان بکە تا هیچ بەشێکت لەدەست نەچێت 🔔

هەروەها فێرکاری دادەنرێت 💪🏻

👇 چەنەڵەکەمان:
https://www.instagram.com/channel/AbavzQ9R_hOf0pRG/`;
        try {
          const dmResponse =
            await fetch(
              `https://graph.instagram.com/v26.0/${igUserId}/messages`,
              {
                method: "POST",

                headers: {
                  Authorization:
                    `Bearer ${instagramAccessToken}`,
                  "Content-Type":
                    "application/json"
                },

                body: JSON.stringify({
                  recipient: {
                    comment_id: commentId
                  },

                  message: {
                    text: privateMessage
                  }
                })
              }
            );

          const dmData =
            await dmResponse.json();

          console.log(
            "Private DM result:",
            dmData
          );

          if (!dmResponse.ok) {
            console.error(
              "PRIVATE DM FAILED:",
              dmData
            );
          } else {
            console.log(
              "Private DM sent ✅"
            );
          }

        } catch (dmError) {
          console.error(
            "Private DM error:",
            dmError
          );
        }
      }
    }


    // =================================================
    // LOG NORMAL INSTAGRAM DMs
    // NO AUTOMATIC CHAT REPLY
    // =================================================

    for (const entry of entries) {
      const messaging =
        entry.messaging || [];

      for (const event of messaging) {
        if (!event.message) {
          continue;
        }

        const senderId =
          event.sender?.id || "";

        const messageText =
          event.message?.text || "";

        console.log("--------------------------------------");
        console.log("INSTAGRAM DM RECEIVED");
        console.log("Sender:", senderId);
        console.log("Message:", messageText);
        console.log("--------------------------------------");

        // IMPORTANT:
        // We are NOT automatically replying
        // to normal incoming DMs here.
      }
    }

  } catch (error) {
    console.error(
      "Instagram webhook processing error:",
      error
    );
  }
});


// =====================================================
// START INSTAGRAM LOGIN
// =====================================================

app.get("/auth/instagram/start", (req, res) => {
  if (!INSTAGRAM_APP_ID) {
    return res
      .status(500)
      .send(
        "INSTAGRAM_APP_ID is missing in Render."
      );
  }

  const params =
    new URLSearchParams({
      client_id: INSTAGRAM_APP_ID,

      redirect_uri:
        INSTAGRAM_REDIRECT_URI,

      response_type: "code",

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


  return res.redirect(loginUrl);
});


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


      // Instagram login error
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
              error_description || error
            }`
          );
      }


      // Missing code
      if (!code) {
        return res
          .status(400)
          .send(
            "Instagram authorization code missing."
          );
      }


      // Missing app config
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
      // EXCHANGE AUTHORIZATION CODE FOR TOKEN
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
            method: "POST",

            headers: {
              "Content-Type":
                "application/x-www-form-urlencoded"
            },

            body: tokenBody
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


      // =================================================
      // GET CONNECTED INSTAGRAM PROFILE
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
        await profileResponse.json();


      console.log(
        "Connected Instagram account:",
        profile
      );


      // =================================================
      // SUBSCRIBE INSTAGRAM ACCOUNT TO WEBHOOKS
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
            method: "POST",

            headers: {
              Authorization:
                `Bearer ${instagramAccessToken}`,
              "Content-Type":
                "application/x-www-form-urlencoded"
            },

            body: subscriptionBody
          }
        );


      const subscriptionData =
        await subscriptionResponse.json();


      console.log(
        "Webhook subscription result:",
        subscriptionData
      );


      if (!subscriptionResponse.ok) {
        return res
          .status(500)
          .send(`
            <h1>Instagram Connected ✅</h1>

            <p>
              But webhook subscription failed.
            </p>

            <p>
              Check Render Logs.
            </p>
          `);
      }


      // =================================================
      // SUCCESS
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
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 80px;
          ">

            <h1>
              Instagram Connected ✅
            </h1>

            <h2>
              @${profile.username || "Instagram"}
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
              You can close this page.
            </p>

          </body>
        </html>
      `);

    } catch (callbackError) {
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

app.get("/privacy", (req, res) => {
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
        font-family: Arial, sans-serif;
        max-width: 800px;
        margin: 50px auto;
        line-height: 1.7;
        padding: 20px;
      ">

        <h1>
          Privacy Policy
        </h1>

        <p>
          Genius Automation uses Instagram API
          services to provide Instagram automation
          features.
        </p>

        <h2>
          Information We Process
        </h2>

        <p>
          The service may process Instagram account
          identifiers, comments, messages and related
          interaction information required to operate
          the requested features.
        </p>

        <h2>
          How Information Is Used
        </h2>

        <p>
          Information is used only to provide
          Instagram automation functionality.
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
          Information is retained only as long as
          necessary to provide the service.
        </p>

        <h2>
          Data Deletion
        </h2>

        <p>
          Users may request deletion of their data
          by contacting the application owner.
        </p>

        <p>
          Last updated: August 2026
        </p>

      </body>
    </html>
  `);
});


// =====================================================
// DEAUTHORIZE
// =====================================================

app.post("/deauthorize", (req, res) => {
  console.log(
    "Instagram deauthorization request received."
  );

  return res.status(200).json({
    success: true
  });
});


// =====================================================
// DATA DELETION
// =====================================================

app.post("/data-deletion", (req, res) => {
  console.log(
    "Instagram data deletion request received."
  );

  return res.status(200).json({
    success: true,
    message:
      "Data deletion request received."
  });
});


// =====================================================
// START SERVER
// =====================================================

const PORT =
  process.env.PORT || 10000;


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
  }
);
