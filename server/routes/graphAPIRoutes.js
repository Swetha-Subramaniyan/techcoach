const express = require("express");
const router = express.Router();
const graphAPIController = require("../Controllers/graphAPIController");
const authMiddleware = require("../utils/AuthMiddleware");
const createUserKey = require("../utils/CreateUserKey");

router.post("/callback", graphAPIController.teamsCallback)

router.use(authMiddleware);
router.use(createUserKey);

router.post("/register-channel", graphAPIController.registerTeamsChannel);
router.post(
  "/send-decision-card",
  graphAPIController.sendDecisionCardToChannel
);

module.exports = router;