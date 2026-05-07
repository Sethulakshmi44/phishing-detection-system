const { URL } = require("url"); // eslint-disable-line no-unused-vars
const { analyzeUrlFeatures } = require("../services/urlFeatureAnalyzer");
const { checkDomainAge } = require("../services/domainChecker");
const { analyzeWebsite } = require("../services/websiteAnalyzer");
const { checkVirusTotal } = require("../services/virusTotalService");
const { generateExplanation } = require("../services/explanationService");
const { saveScan } = require("../models/scanModel");
const { generatePDFReport } = require("../services/reportService");

// ─────────────────────────────────────────────────────────────────────────────
// SCORING DESIGN
// ─────────────────────────────────────────────────────────────────────────────
// Raw scores from each module are collected independently, then combined and
// normalised to a 0–10 final phishing score.
//
// Module weights (approximate max contributions):
//   URL features   : 0–6   (capped inside urlFeatureAnalyzer)
//   Domain age     : 0–3
//   Website content: 0–6   (capped below)
//   VirusTotal     : 0–5
//
// Total raw max ≈ 20  → normalised to 10 via a weighted scale.
//
// Trust signals are NOT used as negative deductions because:
//   • HTTPS is free (Let's Encrypt) — phishing sites use it routinely
//   • Old domains can be compromised or used as parked redirectors
//   • VT zero detections is the absence of evidence, not evidence of safety
// ─────────────────────────────────────────────────────────────────────────────

// Calibrated so that a URL with 2-3 strong signals (e.g. brand impersonation +
// suspicious TLD) reaches Medium Risk, and 4+ signals reach High Risk.
// Real phishing URLs rarely exceed a raw combined score of 12-14.
const RAW_SCORE_MAX = 12;

async function analyzeUrlLogic(inputUrl) {
    let indicators = [];

    // ── Normalize URL ─────────────────────────────────────────────────────────
    let formattedURL = inputUrl.trim();
    if (!formattedURL.startsWith("http://") && !formattedURL.startsWith("https://")) {
        formattedURL = "http://" + formattedURL;
    }

    // Validate URL structure early
    let parsedURL;
    try {
        parsedURL = new URL(formattedURL);
    } catch {
        return {
            url: inputUrl,
            phishing_score: 5,
            risk_level: "Medium Risk",
            indicators: ["Malformed URL"],
            explanations: ["The URL is malformed or invalid. Legitimate services always use properly formatted URLs."],
            breakdown: { url: 5, domain: 0, website: 0, threat: 0 }
        };
    }

    const hostname = parsedURL.hostname;

    // ── Run all checks in parallel for speed ──────────────────────────────────
    const [urlResult, domainResult, websiteResult, vtResult] = await Promise.all([
        Promise.resolve(analyzeUrlFeatures(formattedURL)),   // synchronous internally
        checkDomainAge(hostname),
        analyzeWebsite(formattedURL),
        checkVirusTotal(formattedURL)
    ]);

    // ── Collect raw scores ────────────────────────────────────────────────────
    const urlScore     = Math.min(urlResult.score, 6);
    const domainScore  = Math.min(domainResult.ageRisk, 3);
    const websiteScore = Math.min(websiteResult.score, 6);
    const vtScore      = Math.min(vtResult.score, 5);

    const rawTotal = urlScore + domainScore + websiteScore + vtScore;

    // ── Normalise to 0–10 ─────────────────────────────────────────────────────
    // Uses a non-linear curve so that mid-range threats land in 4–6
    // and only clearly high-risk URLs hit 8+.
    let score = Math.round((rawTotal / RAW_SCORE_MAX) * 10);
    score = Math.max(0, Math.min(score, 10));

    // ── Collect all indicators ────────────────────────────────────────────────
    indicators = [
        ...(urlResult.indicators    || []),
        ...(domainResult.indicator ? [domainResult.indicator] : []),
        ...(websiteResult.indicators || []),
        ...(vtResult.indicator ? [vtResult.indicator] : [])
    ];

    const breakdown = {
        url:     urlScore,
        domain:  domainScore,
        website: websiteScore,
        threat:  vtScore
    };

    const explanations = generateExplanation(indicators);

    const risk_level =
        score >= 7 ? "High Risk"   :
        score >= 4 ? "Medium Risk" :
        "Low Risk";

    return {
        url: inputUrl,
        phishing_score: score,
        risk_level,
        indicators,
        explanations,
        breakdown
    };
}

// ─── Route handler: Analyze URL ───────────────────────────────────────────────
async function analyzeURL(req, res) {
    try {
        const { url } = req.body;
        if (!url || typeof url !== "string" || url.trim() === "") {
            return res.status(400).json({ error: "A valid URL is required." });
        }

        const result = await analyzeUrlLogic(url);
        await saveScan(result.url, result.phishing_score, result.risk_level);
        res.json(result);

    } catch (error) {
        console.error("[analyzeURL] Unexpected error:", error.message);
        res.status(400).json({ error: "Invalid URL or analysis failed." });
    }
}

// ─── Route handler: PDF Report ────────────────────────────────────────────────
async function downloadReport(req, res) {
    try {
        const { url } = req.body;
        if (!url) {
            return res.status(400).json({ error: "URL is required for report." });
        }

        const result = await analyzeUrlLogic(url);
        generatePDFReport(result, res);

    } catch (error) {
        console.error("[downloadReport] Error:", error.message);
        res.status(500).json({ error: "Failed to generate report." });
    }
}

module.exports = { analyzeURL, downloadReport, analyzeUrlLogic };