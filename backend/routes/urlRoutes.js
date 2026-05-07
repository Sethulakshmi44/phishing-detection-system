const express = require("express");
const router = express.Router();
const { analyzeURL,downloadReport } = require("../controllers/urlController");

router.post("/analyze-url", analyzeURL);
router.post("/download-report", downloadReport);

module.exports = router;