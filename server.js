const express = require("express");

const app = express();
app.use(express.json());

const VERIFY_TOKEN = process.env.VERIFY_TOKEN;

// Meta webhook verification
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

// Receive Instagram webhook events
app.post("/api/webhooks/instagram", (req, res) => {
  console.log("Instagram webhook received:");
  console.log(JSON.stringify(req.body, null, 2));

  res.sendStatus(200);
});

app.get("/", (req, res) => {
  res.send("Genius Instagram Webhook is running");
});
app.get("/privacy", (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Privacy Policy - Genius Automation</title>
      </head>
      <body style="font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; line-height: 1.6;">
        <h1>Privacy Policy</h1>
        <p>Genius Automation uses Instagram API services to provide messaging, comment management, and automation features.</p>

        <h2>Information We Process</h2>
        <p>We may process Instagram account identifiers, messages, comments, and related interaction data only as required to provide the requested automation features.</p>

        <h2>How We Use Information</h2>
        <p>Information is used only to operate, maintain, and improve the Genius Automation service and to respond to Instagram interactions.</p>

        <h2>Data Sharing</h2>
        <p>We do not sell personal information. Data may only be shared with service providers necessary to operate the application or when required by law.</p>

        <h2>Data Retention</h2>
        <p>Data is retained only for as long as necessary to provide the service or comply with legal obligations.</p>

        <h2>Data Deletion</h2>
        <p>Users may request deletion of their data by contacting the application owner.</p>

        <h2>Contact</h2>
        <p>For privacy questions or deletion requests, contact the email address listed in the application's Meta settings.</p>

        <p>Last updated: August 2026</p>
      </body>
    </html>
  `);
});
const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
