const express = require("express");
const router = express.Router();
const graphAPIController = require("../Controllers/graphAPIController");
const authMiddleware = require("../utils/AuthMiddleware");
const createUserKey = require("../utils/CreateUserKey");
const {
  convertStripeDate,
  saveStripeSubscription,
} = require("../utils/stripe.utils");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

router.post("/callback", graphAPIController.teamsCallback);

router.post("/webhook", async (request, response) => {
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
    console.error("Stripe webhook signature verification failed:", err.message);
    return response.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object;

        const userId = session.client_reference_id || session.metadata?.userId;

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
      case "customer.subscription.updated": {
        const subscription = event.data.object;

        const userId = subscription.metadata?.userId;

        if (!userId) {
          console.error(
            "No userId found in subscription metadata:",
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
});

router.use(authMiddleware);
router.use(createUserKey);

router.post("/register-channel", graphAPIController.registerTeamsChannel);
router.post(
  "/send-decision-card",
  graphAPIController.sendDecisionCardToChannel,
);

module.exports = router;
