const getConnection = require("../Models/database");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const convertStripeDate = (timestamp) => {
  if (!timestamp) return null;

  return new Date(timestamp * 1000)
    .toISOString()
    .slice(0, 19)
    .replace("T", " ");
};

const mapStripeStatus = (status) => {
  switch (status) {
    case "active":
    case "trialing":
      return "ACTIVE";

    case "past_due":
    case "unpaid":
      return "SUSPENDED";

    case "canceled":
      return "CANCELLED";

    case "incomplete":
    case "incomplete_expired":
      return "PENDING";

    default:
      return "INACTIVE";
  }
};

const saveStripeSubscription = async ({
  userId,
  subscription,
  customerId,
  lastPaymentTime = null,
}) => {
  if (!userId || !subscription?.id) {
    throw new Error("Missing userId or Stripe subscription ID");
  }

  let conn;

  try {
    conn = await getConnection();

    const status = mapStripeStatus(subscription.status);

    const subscriptionItem = subscription.items?.data?.[0];

    const cancelAtPeriodEnd = subscription.cancel_at ? 1 : 0;

    let latestInvoice = subscription.latest_invoice;

    if (typeof latestInvoice === "string") {
      latestInvoice = await stripe.invoices.retrieve(latestInvoice);
    }
    const cancellationRequestedAt = subscription.canceled_at
      ? convertStripeDate(subscription.canceled_at)
      : null;
    const hasPendingRenewalInvoice =
      latestInvoice &&
      latestInvoice.billing_reason === "subscription_cycle" &&
      ["draft", "open"].includes(latestInvoice.status);

    const periodEnd = hasPendingRenewalInvoice
      ? latestInvoice.period_end
      : subscriptionItem?.current_period_end || subscription.current_period_end;

    const nextBillingTime = periodEnd ? convertStripeDate(periodEnd) : null;

    const cancellationEffectiveAt = subscription.cancel_at
      ? convertStripeDate(subscription.cancel_at)
      : subscription.ended_at
        ? convertStripeDate(subscription.ended_at)
        : subscription.cancel_at_period_end
          ? nextBillingTime
          : null;

    await conn.query(
      `INSERT INTO techcoach_lite.user_subscription
(
  user_id,
  subscription_id,
  mode_of_payment,
  stripe_customer_id,
  status,
  next_billing_time,
  last_payment_time,
  cancel_at_period_end,
  cancellation_requested_at,
  cancellation_effective_at
)
VALUES (?, ?, 'STRIPE', ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
  subscription_id = VALUES(subscription_id),
  mode_of_payment = 'STRIPE',
  stripe_customer_id = VALUES(stripe_customer_id),
  status = VALUES(status),
  next_billing_time = VALUES(next_billing_time),
  last_payment_time = COALESCE(
    VALUES(last_payment_time),
    last_payment_time
  ),
  cancel_at_period_end = VALUES(cancel_at_period_end),
  cancellation_requested_at = COALESCE(
    VALUES(cancellation_requested_at),
    cancellation_requested_at
  ),
  cancellation_effective_at = VALUES(cancellation_effective_at)`,
      [
        userId,
        subscription.id,
        customerId || null,
        status,
        nextBillingTime,
        lastPaymentTime,
        cancelAtPeriodEnd,
        cancellationRequestedAt,
        cancellationEffectiveAt,
      ],
    );

    console.log(
      `Stripe subscription saved for user ${userId}: ${subscription.id}`,
    );
  } finally {
    if (conn) conn.release();
  }
};

module.exports = { saveStripeSubscription, convertStripeDate };
