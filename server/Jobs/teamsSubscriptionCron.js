
const cron = require("node-cron");
const getConnection = require("../Models/database");
const {
  renewChannelSubscription,
  createChannelSubscription,
} = require("../Services/teamsGraphService");

const renewTeamsSubscriptions = async () => {
  let conn;

  try {
    conn = await getConnection();

    const query = `
      SELECT
        id,
        group_name,
        teams_team_id,
        teams_channel_id,
        teams_subscription_id,
        teams_subscription_expiry
      FROM techcoach_lite.techcoach_groups
      WHERE teams_team_id IS NOT NULL
        AND teams_channel_id IS NOT NULL
        AND teams_webhook_url IS NOT NULL
        AND (
          teams_subscription_id IS NULL
          OR teams_subscription_expiry IS NULL
          OR teams_subscription_expiry <= DATE_ADD(
            UTC_TIMESTAMP(), INTERVAL 24 HOUR
          )
        )
    `;

    const groups = await conn.query(query);

    for (const group of groups) {
      try {
        let subscription;

        if (group.teams_subscription_id) {
          try {
            subscription = await renewChannelSubscription(
              group.teams_subscription_id
            );
          } catch (error) {
            if (error.response?.status !== 404) {
              throw error;
            }

            console.log(
              `Subscription expired for group ${group.id}. Creating new one.`
            );
          }
        }

        if (!subscription) {
          subscription = await createChannelSubscription(
            group.teams_team_id,
            group.teams_channel_id
          );
        }

        await conn.query(
          `UPDATE techcoach_lite.techcoach_groups
           SET teams_subscription_id = ?,
               teams_subscription_expiry = ?
           WHERE id = ?`,
          [
            subscription.id,
            new Date(subscription.expirationDateTime)
              .toISOString()
              .slice(0, 19)
              .replace("T", " "),
            group.id,
          ]
        );

        console.log(
          `Teams subscription renewed for group ${group.id}`
        );
      } catch (error) {
        console.error(
          `Subscription renewal failed for group ${group.id}:`,
          error.response?.data || error.message
        );
      }
    }
  } catch (error) {
    console.error("Teams subscription cron error:", error);
  } finally {
    if (conn) conn.release();
  }
};

const startTeamsSubscriptionCron = () => {
  cron.schedule("0 */6 * * *", renewTeamsSubscriptions, {
    timezone: "UTC",
  });

  console.log("Teams subscription cron started.");

  renewTeamsSubscriptions();
};

module.exports = {
  startTeamsSubscriptionCron,
  renewTeamsSubscriptions,
};
