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

// IMPORTANT:
// Automation is OFF by default.
// Nothing will reply to comments or send DMs.
const AUTOMATION_ENABLED =
  process.env.AUTOMATION_ENABLED === "true";

// Temporary token in memory after Instagram login.
// We are NOT using it to send any messages right now.
let instagramAccessToken =
  process.env.INSTAGRAM_ACCESS_TOKEN || "";


// =====================================================
// HOME
// =====================================================

app.get("/", (req, res) => {
  res.status(200).send(`
    <html>
      <head>
        <meta charset="UTF-8" />
        <title>Genius Instagram Automation</title>
      </head>

      <body style="
        font-family: Arial, sans-serif;
        text-align: center;
        padding: 80px;
      ">
        <h1>Genius Instagram Automation ✅</h1>
        <p>Server is running.</p>
        <p>Automation replies are currently paused ⏸️</p>
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
    automation_enabled: AUTOMATION_ENABLED
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
// RECEIVE INSTAGRAM WEBHOOK EVENTS
// =====================================================

app.post("/api/webhooks/instagram", (req, res) => {

  // Meta should receive 200 immediately.
  res.sendStatus(200);

  console.log("======================================");
  console.log("Instagram webhook received!");
  console.log("======================================");

  console.log(
    JSON.stringify(req.body, null, 2)
  );

  try {

    const entries = req.body.entry || [];

    for (const entry of entries) {

      // -----------------------------------------------
      // COMMENT EVENTS
      // -----------------------------------------------

      const changes = entry.changes || [];

      for (const change of changes) {

        if (change.field === "comments") {

          const value = change.value || {};

          const commentId = value.id || "";
          const commentText =
            (value.text || "").trim();

          const username =
            value.from?.username || "unknown";

          console.log("---------- COMMENT ----------");
          console.log("Comment ID:", commentId);
          console.log("Username:", username);
          console.log("Comment text:", commentText);
          console.log("-----------------------------");

          // ⛔ PAUSED
          // NO COMMENT REPLY
          // NO PRIVATE REPLY
          // NO DM

          console.log(
            "Automation paused - no reply sent."
          );
        }
      }


      // -----------------------------------------------
      // DM / MESSAGE EVENTS
      // -----------------------------------------------

      const messaging = entry.messaging || [];

      for (const event of messaging) {

        if (event.message) {

          const senderId =
            event.sender?.id || "";

          const messageText =
            event.message?.text || "";

          console.log("----------- DM --------------");
          console.log("Sender ID:", senderId);
          console.log("Message:", messageText);
          console.log("-----------------------------");

          // ⛔ PAUSED
          // NO DM REPLY
          // NO CHAT REPLY

          console.log(
            "Automation paused - no DM reply sent."
          );
        }
      }
    }

  } catch (error) {

    console.error(
      "Webhook processing error:",
      error
    );
  }
});


// =====================================================
// START INSTAGRAM BUSINESS LOGIN
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


      // -----------------------------------------------
      // INSTAGRAM RETURNED ERROR
      // -----------------------------------------------

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


      // -----------------------------------------------
      // NO AUTHORIZATION CODE
      // -----------------------------------------------

      if (!code) {

        return res
          .status(400)
          .send(
            "Instagram authorization code missing."
          );
      }


      // -----------------------------------------------
      // CHECK ENV VARIABLES
      // -----------------------------------------------

      if (
        !INSTAGRAM_APP_ID ||
        !INSTAGRAM_APP_SECRET
      ) {

        return res
          .status(500)
          .send(
            "Instagram App ID or App Secret missing in Render."
          );
      }


      // -----------------------------------------------
      // EXCHANGE CODE FOR ACCESS TOKEN
      // -----------------------------------------------

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
          "Token exchange failed:",
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


      // -----------------------------------------------
      // GET CONNECTED INSTAGRAM ACCOUNT
      // -----------------------------------------------

      const profileResponse =
        await fetch(
          "https://graph.instagram.com/v26.0/me?fields=id,username&access_token=" +
          encodeURIComponent(
            instagramAccessToken
          )
        );


      const profile =
        await profileResponse.json();


      console.log(
        "Connected Instagram account:",
        profile
      );


      // -----------------------------------------------
      // SUBSCRIBE ACCOUNT TO WEBHOOKS
      // -----------------------------------------------

      const subscriptionBody =
        new URLSearchParams();

      subscriptionBody.append(
        "subscribed_fields",
        "comments,messages"
      );

      subscriptionBody.append(
        "access_token",
        instagramAccessToken
      );


      const subscriptionResponse =
        await fetch(
          "https://graph.instagram.com/v26.0/me/subscribed_apps",
          {
            method: "POST",

            headers: {
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
              Webhook subscription failed.
            </p>

            <p>
              Check Render Logs.
            </p>
          `);
      }


      // -----------------------------------------------
      // SUCCESS PAGE
      // -----------------------------------------------

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
              Automation replies are currently PAUSED ⏸️
            </p>

            <p>
              No automatic DM or comment reply will be sent.
            </p>

          </body>

        </html>
      `);

    } catch (error) {

      console.error(
        "Instagram callback error:",
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

app.get("/privacy", (req, res) => {

  res.send(`
    <!DOCTYPE html>

    <html>

      <head>
        <meta charset="UTF-8">
        <title>Privacy Policy</title>
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
          Genius Automation uses Instagram API services
          to provide Instagram automation features.
        </p>

        <h2>
          Information We Process
        </h2>

        <p>
          The service may process Instagram account
          identifiers, comments, messages and interaction
          information needed to operate the service.
        </p>

        <h2>
          Data Usage
        </h2>

        <p>
          Information is used only to operate the
          requested Instagram features.
        </p>

        <h2>
          Data Sharing
        </h2>

        <p>
          We do not sell personal information.
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
