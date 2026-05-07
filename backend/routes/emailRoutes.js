const express = require("express");
const router = express.Router();

const { analyzeEmailContent, downloadEmailReport } = require("../controllers/emailController");

router.post("/analyze-email", analyzeEmailContent);
router.post("/download-email-report", downloadEmailReport);

module.exports = router;