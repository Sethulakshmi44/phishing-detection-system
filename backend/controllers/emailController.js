const { analyzeEmail } = require("../services/emailAnalyzer");
const { analyzeUrlLogic } = require("./urlController");
const { generatePDFReport } = require("../services/reportService");

// 🔹 Reusable logic (important)
async function analyzeEmailContentLogic(email) {

    const emailResult = await analyzeEmail(email);

    let totalScore = emailResult.score;
    let indicators = [...emailResult.indicators];
    let urlResults = [];

    if (emailResult.links && emailResult.links.length > 0) {

        for (let link of emailResult.links) {

            try {
                const urlAnalysis = await analyzeUrlLogic(link);

                totalScore += urlAnalysis.phishing_score;

                if (!indicators.includes(`Link analyzed: ${link}`)) {
                    indicators.push(`Link analyzed: ${link}`);
                }

                if (urlAnalysis.risk_level === "High Risk") {
                    indicators.push(`⚠️ Malicious link detected: ${link}`);
                }

                urlResults.push({
                    link,
                    score: urlAnalysis.phishing_score,
                    risk: urlAnalysis.risk_level
                });

            } catch (err) {
                console.error("URL scan failed for:", link);
            }
        }
    }

    totalScore = Math.min(totalScore, 10);

    let riskLevel =
        totalScore >= 6 ? "High Risk" :
        totalScore >= 3 ? "Medium Risk" :
        "Low Risk";

    return {
        phishing_score: totalScore,
        risk_level: riskLevel,
        indicators,
        linksAnalyzed: urlResults
    };
}

// 🔹 Existing API
exports.analyzeEmailContent = async (req, res) => {
    try {
        const { email } = req.body;
        const result = await analyzeEmailContentLogic(email);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: "Email analysis failed" });
    }
};

// 🔹 NEW PDF API
exports.downloadEmailReport = async (req, res) => {
    console.log("📥 EMAIL PDF ROUTE HIT"); 
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ error: "Email content required" });
        }

        const result = await analyzeEmailContentLogic(email);

        generatePDFReport(result, res);

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to generate email report" });
    }
};