const express = require("express");
const router = express.Router();
const { analyzeURL } = require("../controllers/urlController");

router.post("/analyze-url", analyzeURL);

module.exports = router;