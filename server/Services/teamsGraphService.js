const axios = require("axios");
const { ClientSecretCredential } = require("@azure/identity");

const TENANT_ID = process.env.MICROSOFT_TENANT_ID;
const CLIENT_ID = process.env.MICROSOFT_CLIENT_ID;
const CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET;
const SYSTEM_USER = process.env.TEAMS_SYSTEM_EMAIL;
const SYSTEM_PASSWORD = process.env.TEAMS_SYSTEM_PASSWORD;

async function getDelegatedToken() {
  const tokenUrl = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`;
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    scope: "https://graph.microsoft.com/.default",
    grant_type: "password",
    username: SYSTEM_USER,
    password: SYSTEM_PASSWORD,
  });

  const res = await axios.post(tokenUrl, params.toString(), {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
  return res.data.access_token;
}

async function sendDecisionCardToUser(
  targetEmailOrPayload,
  cardPayload = {},
  preFetchedToken = null,
) {
  let targetEmail;
  let payload;

  if (
    typeof targetEmailOrPayload === "object" &&
    targetEmailOrPayload !== null
  ) {
    targetEmail = targetEmailOrPayload.recipientEmail;
    payload = targetEmailOrPayload;
  } else {
    targetEmail = targetEmailOrPayload;
    payload = cardPayload;
  }

  if (!targetEmail || typeof targetEmail !== "string") {
    throw new Error(
      `Invalid targetEmail: received ${JSON.stringify(targetEmail)}`,
    );
  }

  const token = preFetchedToken || (await getDelegatedToken());
  const headers = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };

  const userRes = await axios.get(
    `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(targetEmail.trim())}`,
    { headers },
  );
  const targetUserId = userRes.data.id;

  const meRes = await axios.get("https://graph.microsoft.com/v1.0/me", {
    headers,
  });
  const myUserId = meRes.data.id;

  const chatRes = await axios.post(
    "https://graph.microsoft.com/v1.0/chats",
    {
      chatType: "oneOnOne",
      members: [
        {
          "@odata.type": "#microsoft.graph.aadUserConversationMember",
          roles: ["owner"],
          "user@odata.bind": `https://graph.microsoft.com/v1.0/users('${myUserId}')`,
        },
        {
          "@odata.type": "#microsoft.graph.aadUserConversationMember",
          roles: ["owner"],
          "user@odata.bind": `https://graph.microsoft.com/v1.0/users('${targetUserId}')`,
        },
      ],
    },
    { headers },
  );

  const chatId = chatRes.data.id;

  const isComment = payload.action === "COMMENT" || payload.action === "REPLY";

  const facts = isComment
    ? [
        { title: "Commented By:", value: payload.updatedBy || "Circle Member" },
        { title: "Circle:", value: payload.tags || "N/A" },
      ]
    : [
        {
          title: "Action By:",
          value: payload.updatedBy || "Decision Coach User",
        },
        { title: "Due Date:", value: payload.dueDate || "N/A" },
        { title: "Status / Taken:", value: payload.takenDate || "Pending" },
        { title: "Tags:", value: payload.tags || "None" },
        { title: "Key Reason:", value: payload.reasons || "None" },
      ];

  const adaptiveCardStructure = {
    $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
    type: "AdaptiveCard",
    version: "1.4",
    body: [
      {
        type: "Container",
        style: "emphasis",
        items: [
          {
            type: "ColumnSet",
            columns: [
              {
                type: "Column",
                width: "stretch",
                items: [
                  {
                    type: "TextBlock",
                    text: "DECISION COACH",
                    size: "Small",
                    weight: "Bolder",
                    color: "Accent",
                  },
                  {
                    type: "TextBlock",
                    text: payload.decisionName || "Untitled Decision",
                    size: "Large",
                    weight: "Bolder",
                    wrap: true,
                  },
                ],
              },
              {
                type: "Column",
                width: "auto",
                items: [
                  {
                    type: "TextBlock",
                    text: payload.action || "NOTIFICATION",
                    color: payload.actionColor || "Default",
                    weight: "Bolder",
                    size: "Medium",
                    horizontalAlignment: "Right",
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        type: "Container",
        items: [
          {
            type: "TextBlock",
            text: isComment ? `"${payload.details}"` : payload.details,
            wrap: true,
            isSubtle: false,
            weight: isComment ? "Bolder" : "Default",
            spacing: "Medium",
          },
          {
            type: "FactSet",
            spacing: "Medium",
            facts: facts,
          },
        ],
      },
    ],
  };

  await axios.post(
    `https://graph.microsoft.com/v1.0/chats/${chatId}/messages`,
    {
      body: {
        contentType: "html",
        content: '<attachment id="decisionCard"></attachment>',
      },
      attachments: [
        {
          id: "decisionCard",
          contentType: "application/vnd.microsoft.card.adaptive",
          content: JSON.stringify(adaptiveCardStructure),
        },
      ],
    },
    { headers },
  );
}

async function sendCommentNotificationToMembers(
  recipientEmails,
  payload,
  excludeEmail = null,
) {
  const unique = [
    ...new Set(
      (recipientEmails || [])
        .filter(Boolean)
        .map((e) => e.trim().toLowerCase()),
    ),
  ].filter((e) => e !== (excludeEmail || "").trim().toLowerCase());

  if (unique.length === 0) return { sent: 0, failed: [] };

  const token = await getDelegatedToken();

  const results = await Promise.allSettled(
    unique.map((email) => sendDecisionCardToUser(email, payload, token)),
  );

  const failed = results
    .map((r, i) =>
      r.status === "rejected"
        ? { email: unique[i], error: r.reason?.message }
        : null,
    )
    .filter(Boolean);

  console.log(
    `[Teams] comment notify: ${unique.length - failed.length}/${unique.length} delivered`,
  );
  return { sent: unique.length - failed.length, failed };
}

const credential = new ClientSecretCredential(
  process.env.MICROSOFT_TENANT_ID,
  process.env.MICROSOFT_CLIENT_ID,
  process.env.MICROSOFT_CLIENT_SECRET,
);

const getGraphToken = async () => {
  const token = await credential.getToken(
    "https://graph.microsoft.com/.default",
  );

  return token.token;
};

const graphRequest = async (method, url, data = null) => {
  const token = await getGraphToken();

  const response = await axios({
    method,
    url: `https://graph.microsoft.com/v1.0${url}`,
    data,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });
  return response.data;
};

const getSubscriptions = async () => {
  return graphRequest("GET", "/subscriptions");
};

const createChannelSubscription = async (teamId, channelId) => {
  const expirationDateTime = new Date(
    Date.now() + 60 * 60 * 1000,
  ).toISOString();

  const result = await getSubscriptions();

  return graphRequest("POST", "/subscriptions", {
    changeType: "created",
    notificationUrl: process.env.TEAMS_CALLBACK_URL,
    resource: `/teams/${teamId}/channels/${channelId}/messages`,
    expirationDateTime,
    clientState: process.env.TEAMS_CLIENT_STATE,
  });
};

const getChannelMessage = async (teamId, channelId, messageId) => {
  return graphRequest(
    "GET",
    `/teams/${teamId}/channels/${channelId}/messages/${messageId}`,
  );
};


const renewChannelSubscription = async (subscriptionId) => {
  const accessToken = await getGraphToken();

  const newExpiry = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000);

  const response = await axios.patch(
    `https://graph.microsoft.com/v1.0/subscriptions/${subscriptionId}`,
    {
      expirationDateTime: newExpiry.toISOString(),
    },
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
    }
  );

  return response.data;
};


const getTeamsChannelReply = async (
  teamId,
  channelId,
  parentMessageId,
  replyMessageId
) => {
  const accessToken = await getGraphToken();

  const url =
    `https://graph.microsoft.com/v1.0/teams/${teamId}` +
    `/channels/${channelId}` +
    `/messages/${parentMessageId}` +
    `/replies/${replyMessageId}`;

  const response = await axios.get(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  return response.data;
};



const sendChannelAdaptiveCard = async (
  teamId,
  channelId,
  adaptiveCard
) => {
  return graphRequest(
    "POST",
    `/teams/${teamId}/channels/${channelId}/messages`,
    {
      body: {
        contentType: "html",
        content: '<attachment id="decisionCard"></attachment>',
      },
      attachments: [
        {
          id: "decisionCard",
          contentType: "application/vnd.microsoft.card.adaptive",
          content: JSON.stringify(adaptiveCard),
        },
      ],
    }
  );
};



module.exports = {
  getGraphToken,
  sendDecisionCardToUser,
  sendCommentNotificationToMembers,
  graphRequest,
  createChannelSubscription,
  getChannelMessage,
  renewChannelSubscription,
  getTeamsChannelReply,
  sendChannelAdaptiveCard
};
