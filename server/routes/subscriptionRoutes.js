const express = require("express");
const router = express.Router();
const {
  createSubscription,
  getSubscriptionDetails,
  createOneTimeOrder,
  captureOneTimeOrder,
  getClientToken,
} = require("../Services/paypalService");
const getConnection = require("../Models/database");
const {
  convertStripeDate,
  saveStripeSubscription,
} = require("../utils/stripe.utils");
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
         mode_of_payment,
         last_payment_time,
         next_billing_time,
         updated_at,
         cancellation_requested_at,
         cancellation_effective_at,
         cancel_at_period_end

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

    const now = new Date();

    const cancellationEffectiveAt = sub.cancellation_effective_at
      ? new Date(sub.cancellation_effective_at)
      : null;

    const isCancellationScheduled =
      sub.status === "ACTIVE" &&
      Boolean(sub.cancel_at_period_end) &&
      cancellationEffectiveAt &&
      cancellationEffectiveAt > now;

    const isSubscribed =
      sub.status === "ACTIVE" &&
      sub.next_billing_time &&
      new Date(sub.next_billing_time) > now;

    res.json({
      isSubscribed: Boolean(isSubscribed),

      status: sub.status,

      modeOfPayment: sub.mode_of_payment,

      lastPaymentTime: sub.last_payment_time,

      nextBillingTime: sub.next_billing_time,

      cancelAtPeriodEnd: Boolean(sub.cancel_at_period_end),

      isCancellationScheduled: Boolean(isCancellationScheduled),

      cancellationRequestedAt: sub.cancellation_requested_at,

      cancellationEffectiveAt: sub.cancellation_effective_at,
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

router.post("/create-cancellation-session", ensureAuth, async (req, res) => {
  let conn;

  try {
    conn = await getConnection();

    const rows = await conn.query(
      `SELECT stripe_customer_id, subscription_id
       FROM techcoach_lite.user_subscription
       WHERE user_id = ?
         AND mode_of_payment = 'STRIPE'
       ORDER BY updated_at DESC
       LIMIT 1`,
      [req.user.id],
    );

    if (!rows.length || !rows[0].subscription_id) {
      return res.status(404).json({ error: "Subscription not found" });
    }

    const customerId = rows[0].stripe_customer_id;
    const subscriptionId = rows[0].subscription_id;

    const subscription = await stripe.subscriptions.retrieve(subscriptionId);

    const cancellationScheduled =
      subscription.cancel_at_period_end === true ||
      (subscription.cancel_at && subscription.cancel_at * 1000 > Date.now());

    if (subscription.status !== "active") {
      return res.status(400).json({
        error: "Subscription is no longer active.",
      });
    }

    if (cancellationScheduled) {
      const session = await stripe.billingPortal.sessions.create({
        customer: customerId,
        return_url: `${process.env.CLIENT_URL}/profile`,
      });

      return res.json({
        url: session.url,
        cancellationScheduled: true,
      });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: customerId,
      configuration: process.env.STRIPE_PORTAL_CONFIGURATION_ID,
      return_url: `${process.env.CLIENT_URL}/profile`,
      flow_data: {
        type: "subscription_cancel",
        subscription_cancel: {
          subscription: subscriptionId,
        },
        after_completion: {
          type: "redirect",
          redirect: {
            return_url: `${process.env.CLIENT_URL}/profile?stripe=cancelled`,
          },
        },
      },
    });

    return res.json({ url: session.url });
  } catch (err) {
    console.error("Stripe portal error:", err.message);
    console.error("Stripe request ID:", err.requestId);

    return res.status(500).json({
      error: err.message || "Unable to create Stripe portal session",
    });
  } finally {
    if (conn) conn.release();
  }
});

module.exports = router;
