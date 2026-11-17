const express = require("express");
const router = express.Router();
const {
  createSubscription,
  getSubscriptionDetails,
  createOneTimeOrder,
  captureOneTimeOrder,
  getClientToken,
} = require("../Services/paypalService");
const getConnection = require("../models/database");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const PRICE_IDS = {
  monthly: process.env.STRIPE_PRICE_MONTHLY || "price_1UaxuSLfSDvxyGCueinLkcd4",
  yearly: process.env.STRIPE_PRICE_YEARLY || "price_1UaxuSLfSDvxyGCuSQxLO8PR",
};

const ensureAuth = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  next();
};

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

    const periodEnd =
      subscription.current_period_end ||
      subscription.items?.data?.[0]?.current_period_end ||
      null;

    const nextBillingTime = convertStripeDate(periodEnd);

    await conn.query(
      `INSERT INTO techcoach_lite.user_subscription
      (
        user_id,
        subscription_id,
        mode_of_payment,
        stripe_customer_id,
        status,
        next_billing_time,
        last_payment_time
      )
      VALUES (?, ?, 'STRIPE', ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        subscription_id = VALUES(subscription_id),
        mode_of_payment = 'STRIPE',
        stripe_customer_id = VALUES(stripe_customer_id),
        status = VALUES(status),
        next_billing_time = VALUES(next_billing_time),
        last_payment_time = COALESCE(
          VALUES(last_payment_time),
          last_payment_time
        )`,
      [
        userId,
        subscription.id,
        customerId || null,
        status,
        nextBillingTime,
        lastPaymentTime,
      ],
    );

    console.log(
      `Stripe subscription saved for user ${userId}: ${subscription.id}`,
    );
  } finally {
    if (conn) conn.release();
  }
};

router.post("/create", ensureAuth, async (req, res) => {
  try {
    const subscription = await createSubscription(process.env.PAYPAL_PLAN_ID);

    const approvalLink = subscription.links.find(
      (link) => link.rel === "approve",
    );

    if (!approvalLink) {
      return res.status(500).json({ error: "Approval link not found" });
    }

    res.json({
      approvalUrl: approvalLink.href,
    });
  } catch (err) {
    console.error("PayPal subscription error:", err.response?.data || err);
    res.status(500).json({ error: "PayPal subscription failed" });
  }
});

router.post("/confirm", ensureAuth, async (req, res) => {
  let conn;

  try {
    const { subscriptionId } = req.body;

    const details = await getSubscriptionDetails(subscriptionId);

    if (!["ACTIVE", "APPROVAL_PENDING"].includes(details.status)) {
      return res.status(400).json({
        error: "Subscription not valid",
        status: details.status,
      });
    }

    const convertPaypalDate = (paypalDate) => {
      if (!paypalDate) return null;

      return new Date(paypalDate).toISOString().slice(0, 19).replace("T", " ");
    };

    const nextBillingTime = convertPaypalDate(
      details.billing_info?.next_billing_time,
    );

    const lastPaymentTime = convertPaypalDate(
      details.billing_info?.last_payment?.time,
    );

    conn = await getConnection();

    await conn.query(
      `INSERT INTO techcoach_lite.user_subscription
      (user_id, subscription_id, mode_of_payment, status, next_billing_time, last_payment_time)
      VALUES (?, ?,'PAYPAL', ?, ?, ?)
      ON DUPLICATE KEY UPDATE
      subscription_id = VALUES(subscription_id),
      status = VALUES(status),
      next_billing_time = VALUES(next_billing_time),
      last_payment_time = VALUES(last_payment_time)`,

      [
        req.user.id,
        subscriptionId,
        details.status,
        nextBillingTime,
        lastPaymentTime,
      ],
    );

    res.json({ success: true });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Subscription confirmation failed",
      details: error.message,
    });
  } finally {
    if (conn) conn.release();
  }
});

router.get("/status", ensureAuth, async (req, res) => {
  let conn;

  try {
    conn = await getConnection();

    const rows = await conn.query(
      `SELECT 
         status,
         subscription_id,
         last_payment_time,
         next_billing_time,
         updated_at
       FROM techcoach_lite.user_subscription
       WHERE user_id = ?
       ORDER BY updated_at DESC
       LIMIT 1`,
      [req.user.id],
    );

    if (!rows.length) {
      return res.json({
        isSubscribed: false,
        status: "INACTIVE",
      });
    }

    const sub = rows[0];

    const isSubscribed =
      sub.status === "ACTIVE" &&
      sub.next_billing_time &&
      new Date(sub.next_billing_time) > new Date();

    res.json({
      isSubscribed,
      status: sub.status,
      lastPaymentTime: sub.last_payment_time,
      nextBillingTime: sub.next_billing_time,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    if (conn) conn.release();
  }
});

router.post("/orders/create", ensureAuth, async (req, res) => {
  try {
    const orderPayload = req.body;
    const order = await createOneTimeOrder(orderPayload);
    res.json({ id: order.id });
  } catch (err) {
    console.error("Order creation error:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to create PayPal order" });
  }
});

router.post("/orders/:orderId/capture", ensureAuth, async (req, res) => {
  let conn;
  try {
    const { orderId } = req.params;
    const captureData = await captureOneTimeOrder(orderId);

    if (captureData.status === "COMPLETED") {
      conn = await getConnection();
      const nextBillingDate = new Date();
      nextBillingDate.setFullYear(nextBillingDate.getFullYear() + 1);

      const nextBillingTime = nextBillingDate
        .toISOString()
        .slice(0, 19)
        .replace("T", " ");

      const lastPaymentTime = new Date()
        .toISOString()
        .slice(0, 19)
        .replace("T", " ");

      await conn.query(
        `INSERT INTO techcoach_lite.user_subscription
        (user_id, subscription_id, mode_of_payment,status, next_billing_time, last_payment_time)
        VALUES (?, ?, 'PAYPAL', 'ACTIVE', ?, ?)
        ON DUPLICATE KEY UPDATE
        subscription_id = VALUES(subscription_id),
        status = 'ACTIVE',
        next_billing_time = VALUES(next_billing_time),
        last_payment_time = VALUES(last_payment_time)`,
        [req.user.id, `ONETIME_${orderId}`, nextBillingTime, lastPaymentTime],
      );
    }

    res.json(captureData);
  } catch (err) {
    console.error("Order capture error:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to capture payment" });
  } finally {
    if (conn) conn.release();
  }
});

router.get("/client-token", ensureAuth, async (req, res) => {
  try {
    const clientToken = await getClientToken();
    res.json({ clientToken });
  } catch (err) {
    console.error(
      "Client token generation error:",
      err.response?.data || err.message,
    );
    res.status(500).json({ error: "Failed to generate client token" });
  }
});

router.post("/create-checkout-session", ensureAuth, async (req, res) => {
  try {
    const { priceId } = req.body;

    if (!Object.values(PRICE_IDS).includes(priceId)) {
      return res.status(400).json({
        error: "Invalid priceId",
      });
    }

    const userId = String(req.user.id);
    const email = req.user.email || undefined;

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",

      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],

      customer_email: email,

      client_reference_id: userId,

      metadata: {
        userId,
      },

      subscription_data: {
        metadata: {
          userId,
        },
      },

      billing_address_collection: "auto",

      success_url: `${process.env.CLIENT_URL}/profile?stripe=success&session_id={CHECKOUT_SESSION_ID}`,

      cancel_url: `${process.env.CLIENT_URL}/profile?stripe=cancel`,
    });

    res.json({
      url: session.url,
    });
  } catch (err) {
    console.error("Stripe checkout error:", err);

    res.status(500).json({
      error: err.message,
    });
  }
});

router.get("/checkout-session/:id", ensureAuth, async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.retrieve(req.params.id, {
      expand: ["subscription"],
    });

    const userId = String(req.user.id);

    if (session.client_reference_id !== userId) {
      return res.status(403).json({
        error: "This checkout session does not belong to this user",
      });
    }

    if (
      session.status === "complete" &&
      session.payment_status === "paid" &&
      session.subscription
    ) {
      const subscription =
        typeof session.subscription === "string"
          ? await stripe.subscriptions.retrieve(session.subscription)
          : session.subscription;

      await saveStripeSubscription({
        userId,
        subscription,
        customerId: session.customer,
        lastPaymentTime: convertStripeDate(session.created),
      });
    }

    res.json({
      status: session.status,
      paymentStatus: session.payment_status,
      subscriptionStatus:
        typeof session.subscription === "object"
          ? session.subscription?.status
          : null,
      customerId: session.customer,
      subscriptionId:
        typeof session.subscription === "string"
          ? session.subscription
          : session.subscription?.id || null,
      metadata: session.metadata,
    });
  } catch (err) {
    console.error("Stripe session verification error:", err);

    res.status(500).json({
      error: err.message,
    });
  }
});

router.post("/create-portal-session", async (req, res) => {
  try {
    const { customerId } = req.body;
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: `${process.env.CLIENT_URL}/profile`,
    });
    res.json({ url: portalSession.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (request, response) => {
    const signature = request.headers["stripe-signature"];
    const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

    let event;

    try {
      event = stripe.webhooks.constructEvent(
        request.body,
        signature,
        endpointSecret,
      );
    } catch (err) {
      console.error(
        "Stripe webhook signature verification failed:",
        err.message,
      );
      return response.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      switch (event.type) {
        case "checkout.session.completed": {
          const session = event.data.object;

          const userId =
            session.client_reference_id || session.metadata?.userId;

          if (
            session.mode === "subscription" &&
            session.payment_status === "paid" &&
            session.subscription &&
            userId
          ) {
            const subscription =
              typeof session.subscription === "string"
                ? await stripe.subscriptions.retrieve(session.subscription)
                : session.subscription;

            await saveStripeSubscription({
              userId,
              subscription,
              customerId: session.customer,
              lastPaymentTime: convertStripeDate(session.created),
            });
          }

          break;
        }

        case "customer.subscription.created":
        case "customer.subscription.updated":
        case "customer.subscription.deleted": {
          const subscription = event.data.object;

          const userId = subscription.metadata?.userId;

          if (!userId) {
            console.error(
              "No userId found in Stripe subscription metadata:",
              subscription.id,
            );
            break;
          }

          await saveStripeSubscription({
            userId,
            subscription,
            customerId: subscription.customer,
          });

          break;
        }

        case "invoice.paid": {
          const invoice = event.data.object;

          const subscriptionId =
            typeof invoice.subscription === "string"
              ? invoice.subscription
              : invoice.subscription?.id;

          if (subscriptionId) {
            const subscription =
              await stripe.subscriptions.retrieve(subscriptionId);

            const userId = subscription.metadata?.userId;

            if (userId) {
              await saveStripeSubscription({
                userId,
                subscription,
                customerId: subscription.customer,
                lastPaymentTime: convertStripeDate(invoice.created),
              });
            }
          }

          break;
        }

        case "invoice.payment_failed": {
          const invoice = event.data.object;

          const subscriptionId =
            typeof invoice.subscription === "string"
              ? invoice.subscription
              : invoice.subscription?.id;

          if (subscriptionId) {
            const subscription =
              await stripe.subscriptions.retrieve(subscriptionId);

            const userId = subscription.metadata?.userId;

            if (userId) {
              await saveStripeSubscription({
                userId,
                subscription,
                customerId: subscription.customer,
              });
            }
          }

          break;
        }

        default:
          console.log(`Unhandled Stripe event: ${event.type}`);
      }

      return response.json({
        received: true,
      });
    } catch (err) {
      console.error("Stripe webhook processing error:", err);

      return response.status(500).json({
        error: "Webhook processing failed",
      });
    }
  },
);

module.exports = router;
