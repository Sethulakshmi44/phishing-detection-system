const express = require("express");
const router = express.Router();

const { analyzeEmailContent } = require("../controllers/emailController");

router.post("/analyze-email", analyzeEmailContent);

module.exports = router;