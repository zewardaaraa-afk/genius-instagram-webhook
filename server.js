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

const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
