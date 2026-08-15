const express = require("express");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =========================
// Environment Variables
// =========================
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;

const INSTAGRAM_APP_ID = process.env.INSTAGRAM_APP_ID;
const INSTAGRAM_APP_SECRET = process.env.INSTAGRAM_APP_SECRET;

const INSTAGRAM_REDIRECT_URI =
  process.env.INSTAGRAM_REDIRECT_URI ||
  "https://genius-instagram-webhook.onrender.com/auth/instagram/callback";

// Keep current token if you already have one in Render
let instagramAccessToken =
  process.env.INSTAGRAM_ACCESS_TOKEN || "";


// =========================
// HOME
// =========================
app.get("/", (req, res) => {
  res.send("Genius Instagram Webhook is running!");
});


// =========================
// META WEBHOOK VERIFICATION
// =========================
app.get("/api/webhooks/instagram", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === VERIFY_TOKEN) {
    console.log("Webhook verified successfully");
    return res.status(200).send(challenge);
  }

  return res.sendStatus(403);
});


// =========================
// RECEIVE INSTAGRAM WEBHOOKS
// =========================
app.post("/api/webhooks/instagram", (req, res) => {
  console.log("Instagram webhook received!");
  console.log(JSON.stringify(req.body, null, 2));

  // Always answer Meta quickly
  res.sendStatus(200);
});


// =========================
// START INSTAGRAM LOGIN
// =========================
app.get("/auth/instagram/start", (req, res) => {

  if (!INSTAGRAM_APP_ID) {
    return res
      .status(500)
      .send("INSTAGRAM_APP_ID is missing in Render.");
  }

  const params = new URLSearchParams({
    client_id: INSTAGRAM_APP_ID,
    redirect_uri: INSTAGRAM_REDIRECT_URI,
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

  console.log("Starting Instagram login");

  return res.redirect(loginUrl);
});


// =========================
// INSTAGRAM OAUTH CALLBACK
// =========================
app.get("/auth/instagram/callback", async (req, res) => {
  try {

    const { code, error, error_description } = req.query;

    if (error) {
      console.error("Instagram OAuth error:", error, error_description);

      return res.status(400).send(
        `Instagram login failed: ${error_description || error}`
      );
    }

    if (!code) {
      return res.status(400).send("Instagram authorization code missing.");
    }

    if (!INSTAGRAM_APP_ID || !INSTAGRAM_APP_SECRET) {
      return res
        .status(500)
        .send("Instagram App ID or App Secret missing in Render.");
    }


    // =========================
    // Exchange code for token
    // =========================
    const tokenBody = new URLSearchParams();

    tokenBody.append("client_id", INSTAGRAM_APP_ID);
    tokenBody.append("client_secret", INSTAGRAM_APP_SECRET);
    tokenBody.append("grant_type", "authorization_code");
    tokenBody.append("redirect_uri", INSTAGRAM_REDIRECT_URI);
    tokenBody.append("code", code);


    const tokenResponse = await fetch(
      "https://api.instagram.com/oauth/access_token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: tokenBody
      }
    );


    const tokenData = await tokenResponse.json();


    if (!tokenResponse.ok || !tokenData.access_token) {
      console.error("Token exchange failed:", tokenData);

      return res.status(500).send(
        "Instagram token exchange failed. Check Render logs."
      );
    }


    instagramAccessToken = tokenData.access_token;

    console.log(
      "Instagram access token received successfully."
    );


    // =========================
    // Get Instagram account
    // =========================
    const profileResponse = await fetch(
      "https://graph.instagram.com/v26.0/me?fields=id,username&access_token=" +
        encodeURIComponent(instagramAccessToken)
    );

    const profile = await profileResponse.json();

    console.log("Connected Instagram account:", profile);


    // =========================
    // Subscribe account to
    // comments + messages
    // =========================
    const subscriptionBody = new URLSearchParams();

    subscriptionBody.append(
      "subscribed_fields",
      "comments,messages"
    );

    subscriptionBody.append(
      "access_token",
      instagramAccessToken
    );


    const subscriptionResponse = await fetch(
      "https://graph.instagram.com/v26.0/me/subscribed_apps",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
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
      return res.status(500).send(`
        <h1>Instagram login succeeded ✅</h1>
        <p>But webhook subscription failed.</p>
        <p>Check Render Logs.</p>
      `);
    }


    // =========================
    // SUCCESS
    // =========================
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

        <h1>Instagram Connected ✅</h1>

        <h2>
          @${profile.username || "Instagram account"}
        </h2>

        <p>
          Comments and Messages webhooks are now subscribed.
        </p>

        <p>
          You can close this page.
        </p>

      </body>
      </html>
    `);

  } catch (error) {

    console.error("Instagram callback error:", error);

    return res.status(500).send(
      "Instagram connection failed. Check Render Logs."
    );
  }
});


// =========================
// PRIVACY POLICY
// =========================
app.get("/privacy", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Privacy Policy - Genius Automation</title>
    </head>

    <body style="
      font-family:Arial,sans-serif;
      max-width:800px;
      margin:40px auto;
      line-height:1.6;
    ">

      <h1>Privacy Policy</h1>

      <p>
        Genius Automation uses Instagram API services
        to provide messaging, comment management,
        and automation features.
      </p>

      <h2>Information We Process</h2>

      <p>
        We may process Instagram account identifiers,
        messages, comments, and related interaction data
        only as required to provide the requested
        automation features.
      </p>

      <h2>How We Use Information</h2>

      <p>
        Information is used only to operate and maintain
        Genius Automation and respond to Instagram
        interactions.
      </p>

      <h2>Data Sharing</h2>

      <p>
        We do not sell personal information.
      </p>

      <h2>Data Retention</h2>

      <p>
        Data is retained only as long as necessary
        to provide the service.
      </p>

      <h2>Data Deletion</h2>

      <p>
        Users may request deletion of their data
        by contacting the application owner.
      </p>

      <p>Last updated: August 2026</p>

    </body>
    </html>
  `);
});


// =========================
// START SERVER
// =========================
const PORT = process.env.PORT || 10000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
