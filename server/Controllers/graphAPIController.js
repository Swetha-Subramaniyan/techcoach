const getConnection = require("../Models/database");
const crypto = require("crypto");
const axios = require("axios");
const {
  createChannelSubscription,
  getTeamsChannelReply,
  sendChannelAdaptiveCard,
  getChannelMessage,
  getGraphToken,
} = require("../Services/teamsGraphService");

const getRows = (result) => {
  if (Array.isArray(result) && Array.isArray(result[0])) {
    return result[0];
  }

  return Array.isArray(result) ? result : [];
};

const registerTeamsChannel = async (req, res) => {
  let conn;

  try {
    const { groupId, webhookUrl, teamId, channelId } = req.body;

    if (!groupId || !teamId || !channelId || !webhookUrl) {
      return res.status(400).json({
        message: "Group ID, webhook URL, Team ID and Channel ID are required",
      });
    }

    conn = await getConnection();

    const groupQuery = `
      SELECT id
      FROM techcoach_lite.techcoach_groups
      WHERE id = ?
    `;

    const groups = await conn.query(groupQuery, [groupId]);

    if (!Array.isArray(groups) || groups.length === 0) {
      return res.status(404).json({
        message: "Decision Circle not found",
      });
    }

    const subscription = await createChannelSubscription(teamId, channelId);

    const updateQuery = `
      UPDATE techcoach_lite.techcoach_groups
      SET
        teams_webhook_url = ?,
        teams_team_id = ?,
        teams_channel_id = ?,
        teams_subscription_id = ?,
        teams_subscription_expiry = ?
      WHERE id = ?
    `;

    const expiryDate = new Date(subscription.expirationDateTime);

    const mysqlExpiry = expiryDate.toISOString().slice(0, 19).replace("T", " ");

    await conn.query(updateQuery, [
      webhookUrl,
      teamId,
      channelId,
      subscription.id,
      mysqlExpiry,
      groupId,
    ]);

    return res.status(200).json({
      message: "Teams channel registered successfully",
      subscriptionId: subscription.id,
      expiry: subscription.expirationDateTime,
    });
  } catch (error) {
    console.error(
      "Teams subscription registration failed:",
      error.response?.data || error,
    );

    return res.status(500).json({
      message: "Failed to register Teams channel",
    });
  } finally {
    if (conn) conn.release();
  }
};

const saveTeamsMessageMapping = async (
  conn,
  groupId,
  decisionId,
  teamId,
  channelId,
  messageId,
) => {
  await conn.query(
    `INSERT INTO techcoach_lite.techcoach_teams_message_mapping
    (
      group_id,
      decision_id,
      teams_team_id,
      teams_channel_id,
      teams_message_id
    )
    VALUES (?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE
      decision_id = VALUES(decision_id)`,
    [groupId, decisionId, teamId, channelId, messageId],
  );
};

const saveTeamsMessageAsConversation = async (
  conn,
  groupId,
  decisionId,
  comment,
  groupMember,
  parentCommentId = null
) => {
  const result = await conn.query(
    `INSERT INTO techcoach_lite.techcoach_conversations
    (groupId, groupMember, comment, decisionId, parentCommentId)
    VALUES (?, ?, ?, ?, ?)`,
    [groupId, groupMember, comment, decisionId, parentCommentId]
  );

  return result.insertId;
};

const getTeamsUserDetails = async (teamsUserId) => {
  const token = await getGraphToken();

  const response = await axios.get(
    `https://graph.microsoft.com/v1.0/users/${teamsUserId}?$select=id,displayName,mail,userPrincipalName`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    },
  );

  return response.data;
};

const teamsCallback = async (req, res) => {
  const validationToken = req.query.validationToken;

  if (validationToken) {
    return res
      .status(200)
      .set("Content-Type", "text/plain")
      .send(validationToken);
  }

  res.sendStatus(202);

  let conn;

  try {
    conn = await getConnection();

    const notifications = req.body?.value || [];

    for (const notification of notifications) {
      try {
        if (notification.clientState !== process.env.TEAMS_CLIENT_STATE) {
          console.error("Invalid Teams clientState");
          continue;
        }

        if (notification.changeType !== "created") continue;

        const resource = notification.resource || "";

        const channelMatch = resource.match(
          /teams\(['/]?([^')/]+)['/]?\)\/channels\(['/]?([^')/]+)['/]?\)/i,
        );

        if (!channelMatch) {
          console.log("Unable to extract channel details:", resource);
          continue;
        }

        const teamId = channelMatch[1];
        const channelId = channelMatch[2];

        const replyMatch = resource.match(
          /messages\(['/]?([^')/]+)['/]?\)\/replies\(['/]?([^')/]+)['/]?\)/i,
        );

        if (replyMatch) {
          const parentMessageId = replyMatch[1];
          const replyMessageId = replyMatch[2];

          const mappingResult = await conn.query(
            `SELECT group_id, decision_id, conversation_id
     FROM techcoach_lite.techcoach_teams_message_mapping
     WHERE teams_message_id = ?
       AND teams_team_id = ?
       AND teams_channel_id = ?
     LIMIT 1`,
            [parentMessageId, teamId, channelId],
          );

          const mapping = getRows(mappingResult);

          if (!mapping.length) {
            console.error("No Decision Coach mapping found:", parentMessageId);
            continue;
          }

          const { group_id, decision_id, conversation_id } = mapping[0];

          const reply = await getTeamsChannelReply(
            teamId,
            channelId,
            parentMessageId,
            replyMessageId,
          );

          const comment = await getTeamsMessageText(reply);

          if (!comment) {
            console.log("Reply has no text. Skipping:", replyMessageId);
            continue;
          }

          const teamsUserId = reply.from?.user?.id;

          if (!teamsUserId) {
            console.error("Teams sender ID not found:", replyMessageId);
            continue;
          }

          const teamsUser = await getTeamsUserDetails(teamsUserId);

          const senderEmail = (
            teamsUser.mail ||
            teamsUser.userPrincipalName ||
            ""
          )
            .trim()
            .toLowerCase();

          if (!senderEmail) {
            console.error("Teams sender email not found:", teamsUserId);
            continue;
          }

          console.log("Teams sender:", {
            teamsUserId,
            senderEmail,
            displayName: teamsUser.displayName,
          });

          const userResult = await conn.query(
            `SELECT user_id
   FROM techcoach_lite.techcoach_users
   WHERE LOWER(email) = ?
   LIMIT 1`,
            [senderEmail],
          );

          const users = getRows(userResult);

          if (!users.length) {
            console.error(
              "No Decision Coach user found for Teams email:",
              senderEmail,
            );
            continue;
          }

          const groupMember = users[0].user_id;

          await saveTeamsMessageAsConversation(
            conn,
            group_id,
            decision_id,
            comment,
            groupMember,
            conversation_id
          );

          continue;
        }

        const rootMatch = resource.match(/messages\(['/]?([^')/]+)['/]?\)$/i);

        if (rootMatch) {
          const messageId = rootMatch[1];

          const rootMessage = await getChannelMessage(
            teamId,
            channelId,
            messageId,
          );

          const messageContent = JSON.stringify(rootMessage);

          const mappingMatch = messageContent.match(
            /DC_MAPPING_ID:(\d+):(\d+)/,
          );

          if (!mappingMatch) {
            console.log("Not a Decision Coach message:", messageId);
            continue;
          }

          const groupId = mappingMatch[1];
          const decisionId = mappingMatch[2];

          const existingMappingResult = await conn.query(
            `SELECT id
     FROM techcoach_lite.techcoach_teams_message_mapping
     WHERE teams_message_id = ?
       AND teams_team_id = ?
       AND teams_channel_id = ?
     LIMIT 1`,
            [messageId, teamId, channelId],
          );

          if (getRows(existingMappingResult).length > 0) {
            console.log("Teams message already mapped:", messageId);
            continue;
          }

          const decisionResult = await conn.query(
            `SELECT user_id, decision_name
     FROM techcoach_lite.techcoach_decision
     WHERE decision_id = ?
     LIMIT 1`,
            [decisionId],
          );

          const decisions = getRows(decisionResult);

          if (!decisions.length) {
            console.error("Decision not found:", decisionId);
            continue;
          }

          const groupMember = decisions[0].user_id;

          const comment = await getTeamsMessageText(rootMessage);

          await saveTeamsMessageAsConversation(
            conn,
            groupId,
            decisionId,
            comment,
            groupMember,
            null
          );

          await saveTeamsMessageMapping(
            conn,
            groupId,
            decisionId,
            teamId,
            channelId,
            messageId,
          );
        }
      } catch (error) {
        console.error(
          "Failed to process individual Teams reply:",
          error.response?.data || error.message,
        );
      }
    }
  } catch (error) {
    console.error("Teams callback processing error:", error);
  } finally {
    if (conn) conn.release();
  }
};


const getTeamsMessageText = async (message) => {
  let content = message?.body?.content || "";

  const mentions = message?.mentions || [];

  for (const mention of mentions) {
    const displayName = mention?.mentionText;
    const teamsUserId = mention?.mentioned?.user?.id;

    if (!displayName || !teamsUserId) continue;

    try {
      const teamsUser = await getTeamsUserDetails(teamsUserId);

      const email = (
        teamsUser.mail ||
        teamsUser.userPrincipalName ||
        ""
      ).trim().toLowerCase();

      if (email) {
        const escapedName = displayName.replace(
          /[.*+?^${}()|[\]\\]/g,
          "\\$&"
        );

        content = content.replace(
          new RegExp(`<at[^>]*>\\s*${escapedName}\\s*</at>`, "i"),
          `@${email}`
        );
      }
    } catch (error) {
      console.error("Mention user lookup failed:", error.message);
    }
  }

  return content
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n")
    .replace(/<[^>]*>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .trim();
};


const sendDecisionCardToChannel = async (req, res) => {
  let conn;

  try {
    const { groupId, decisionId, adaptiveCard } = req.body;

    if (!groupId || !decisionId || !adaptiveCard) {
      return res.status(400).json({
        message: "Group ID, Decision ID and Adaptive Card are required",
      });
    }

    conn = await getConnection();

    const groupResult = await conn.query(
      `SELECT
          id,
          teams_team_id,
          teams_channel_id
       FROM techcoach_lite.techcoach_groups
       WHERE id = ?
       LIMIT 1`,
      [groupId],
    );

    const groups = getRows(groupResult);

    if (!groups.length) {
      return res.status(404).json({
        message: "Decision Circle not found",
      });
    }

    const group = groups[0];

    if (!group.teams_team_id || !group.teams_channel_id) {
      return res.status(400).json({
        message: "Teams channel is not registered",
      });
    }

    const teamsMessage = await sendChannelAdaptiveCard(
      group.teams_team_id,
      group.teams_channel_id,
      adaptiveCard,
    );

    if (!teamsMessage?.id) {
      throw new Error("Teams did not return a message ID");
    }

    await conn.query(
      `INSERT INTO techcoach_lite.techcoach_teams_message_mapping
       (
         group_id,
         decision_id,
         teams_team_id,
         teams_channel_id,
         teams_message_id
       )
       VALUES (?, ?, ?, ?, ?)`,
      [
        groupId,
        decisionId,
        group.teams_team_id,
        group.teams_channel_id,
        teamsMessage.id,
      ],
    );

    return res.status(200).json({
      message: "Adaptive Card posted and mapped successfully",
      teamsMessageId: teamsMessage.id,
    });
  } catch (error) {
    console.error(
      "Failed to post Teams Adaptive Card:",
      error.response?.data || error.message,
    );

    return res.status(500).json({
      message: "Failed to post Adaptive Card",
    });
  } finally {
    if (conn) conn.release();
  }
};

module.exports = {
  registerTeamsChannel,
  teamsCallback,
  sendDecisionCardToChannel,
};
