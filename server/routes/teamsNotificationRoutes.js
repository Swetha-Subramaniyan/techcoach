const express = require('express');
const router = express.Router();
const { sendDecisionCardToUser, sendCommentNotificationToMembers , sendChannelAdaptiveCard } = require('../Services/teamsGraphService');
const getConnection = require('../Models/database');


router.post('/notify', async (req, res) => {
  try {
    const { recipientEmail, ...cardPayload } = req.body;

    if (!recipientEmail) {
      return res.status(400).json({ error: 'recipientEmail is required' });
    }

    await sendDecisionCardToUser(recipientEmail, cardPayload);

    return res.status(200).json({ success: true, message: 'Teams message delivered' });
  } catch (error) {
    console.error('Teams delivery error:', error.response?.data || error.message);
    return res.status(500).json({
      error: 'Failed to deliver Teams notification',
      details: error.response?.data || error.message
    });
  }
});

router.post('/notify-comment', async (req, res) => {
  try {
    const {
      recipientEmails,    
      commenterEmail,     
      circleType,         
      circleName,
      decisionName,
      decisionId,
      commentText,
      isReply = false,
      actionUrl,          
    } = req.body;

    if (!Array.isArray(recipientEmails) || recipientEmails.length === 0) {
      return res.status(400).json({ error: 'recipientEmails is required' });
    }

    const payload = {
      action: isReply ? 'REPLY' : 'COMMENT',
      actionColor: 'Accent',
      decisionName: decisionName || 'Untitled Decision',
      details: commentText || '',
      updatedBy: commenterEmail || 'Circle Member',
      dueDate: 'N/A',
      takenDate: 'N/A',
      tags: circleName ? `${circleType?.replace('_', ' ')} · ${circleName}` : (circleType || 'N/A'),
      reasons: 'N/A',
      decisionId: decisionId ? String(decisionId) : 'N/A',
      actionUrl,
    };

    console.log("payload", payload)

    const result = await sendCommentNotificationToMembers(
      recipientEmails,
      payload,
      commenterEmail,
    );

    return res.status(200).json({ success: true, ...result });
  } catch (error) {
    console.error('Teams comment notify error:', error.response?.data || error.message);
    return res.status(500).json({
      error: 'Failed to notify members',
      details: error.response?.data || error.message,
    });
  }
});

router.post("/notify-channel-decision", async (req, res) => {
  let conn;

  try {
    const { groupId, decisionId, adaptiveCard } = req.body;

    if (!groupId || !decisionId || !adaptiveCard) {
      return res.status(400).json({
        error: "groupId, decisionId and adaptiveCard are required",
      });
    }

    conn = await getConnection();

    // Get the registered Teams channel for this Decision Circle
    const groupResult = await conn.query(
      `SELECT id, teams_team_id, teams_channel_id
       FROM techcoach_lite.techcoach_groups
       WHERE id = ?`,
      [groupId]
    );

    const groups = Array.isArray(groupResult?.[0])
      ? groupResult[0]
      : groupResult;

    const group = groups?.[0];

    if (!group?.teams_team_id || !group?.teams_channel_id) {
      return res.status(404).json({
        error: "Teams channel is not registered for this Decision Circle",
      });
    }

    // Post the Adaptive Card directly to the Teams channel
    const teamsMessage = await sendChannelAdaptiveCard(
      group.teams_team_id,
      group.teams_channel_id,
      adaptiveCard
    );

    const teamsMessageId = teamsMessage?.id;

    if (!teamsMessageId) {
      throw new Error("Microsoft Graph did not return a Teams message ID");
    }

    // Save the mapping needed by the Teams reply callback
    await conn.query(
      `INSERT INTO techcoach_lite.techcoach_teams_message_mapping
       (group_id, decision_id, teams_team_id, teams_channel_id,
        teams_message_id, created_at)
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [
        group.id,
        decisionId,
        group.teams_team_id,
        group.teams_channel_id,
        teamsMessageId,
      ]
    );

    return res.status(200).json({
      success: true,
      message: "Teams channel notification delivered",
      teamsMessageId,
    });

  } catch (error) {
    console.error(
      "Teams channel notification error:",
      error.response?.data || error.message
    );

    return res.status(500).json({
      error: "Failed to send Teams channel notification",
      details: error.response?.data || error.message,
    });

  } finally {
    if (conn) conn.release();
  }
});

module.exports = router;