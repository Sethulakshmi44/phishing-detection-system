const { analyzeEmail } = require("../services/emailAnalyzer");

exports.analyzeEmailContent = async (req, res) => {

    const { email } = req.body;

    const result = await analyzeEmail(email);

    res.json({
        phishing_score: result.score,
        risk_level:
            result.score >= 6 ? "High Risk" :
            result.score >= 3 ? "Medium Risk" :
            "Low Risk",
        indicators: result.indicators
    });

};