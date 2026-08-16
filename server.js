app.post("/api/webhooks/instagram", async (req, res) => {
  // Meta ـەکە زوو 200 وەربگرێت
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
        // تەنها comment
        if (change.field !== "comments") continue;

        const value = change.value || {};

        const commentId = value.id;
        const commentText = (value.text || "").trim();

        const commenterId =
          value.from?.id || "";

        const commenterUsername =
          value.from?.username || "unknown";

        const igUserId = entry.id;

        console.log("Comment ID:", commentId);
        console.log("Comment text:", commentText);
        console.log("Commenter:", commenterUsername);

        if (!commentId) {
          console.log("No comment ID - skipped");
          continue;
        }

        // ئەگەر reply ـی خۆمان بێت، دووبارە automation مەکە
        if (commenterId && commenterId === igUserId) {
          console.log("Own comment - skipped");
          continue;
        }

        // ئەگەر automation pause ـە
        if (!AUTOMATION_ENABLED) {
          console.log("Automation PAUSED - nothing sent");
          continue;
        }

        if (!instagramAccessToken) {
          console.error("Instagram access token missing");
          continue;
        }

        // =================================================
        // 1. PUBLIC COMMENT REPLY
        // =================================================

        const publicReply =
          "سوپاس بۆ کۆمێنتەکەت ❤️ بە نامە چەنەڵەکەمان بۆت ناردووە 📩 بەشداری بکە تا کاتێک بەشی تازە هات، ڕاستەوخۆ ئاگادار بیت 🔔";

        try {
          const replyBody = new URLSearchParams();

          replyBody.append(
            "message",
            publicReply
          );

          replyBody.append(
            "access_token",
            instagramAccessToken
          );

          const replyResponse = await fetch(
            `https://graph.instagram.com/v26.0/${commentId}/replies`,
            {
              method: "POST",
              body: replyBody
            }
          );

          const replyData =
            await replyResponse.json();

          console.log(
            "Comment reply result:",
            replyData
          );

          if (!replyResponse.ok) {
            console.error(
              "Comment reply failed:",
              replyData
            );
          }

        } catch (error) {
          console.error(
            "Comment reply error:",
            error
          );
        }

        // =================================================
        // 2. PRIVATE DM
        // =================================================

        const dmMessage = `بۆ ئەوەی بەشی نوێ کە دانرا ڕاستەوخۆ بیبینیت ❤️
بەشداری لە چەنەڵەکەمان بکە تا هیچ بەشێکت لەدەست نەچێت 🔔

هەروەها فێرکاری دادەنرێت 💪🏻

https://www.instagram.com/channel/AbavzQ9R_hOf0pRG/`;

        try {
          const dmResponse = await fetch(
            `https://graph.instagram.com/v26.0/${igUserId}/messages?access_token=${encodeURIComponent(
              instagramAccessToken
            )}`,
            {
              method: "POST",

              headers: {
                "Content-Type": "application/json"
              },

              body: JSON.stringify({
                recipient: {
                  comment_id: commentId
                },

                message: {
                  text: dmMessage
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
              "Private DM failed:",
              dmData
            );
          }

        } catch (error) {
          console.error(
            "Private DM error:",
            error
          );
        }
      }
    }
  } catch (error) {
    console.error(
      "Instagram automation error:",
      error
    );
  }
});
