const { URL } = require("url");
const { checkDomainAge } = require("../services/domainChecker");
const { analyzeWebsite } = require("../services/websiteAnalyzer");
const {checkVirusTotal}=require("../services/virusTotalService");
const {generateExplanation}=require("../services/explanationService");

exports.analyzeURL = async (req, res) => {

    const { url } = req.body;

    let score = 0;
    let indicators = [];

    try {

        const parsedURL = new URL(url);
        const hostname = parsedURL.hostname;

        // SUSPICIOUS TLD CHECK
        const suspiciousTLDs = ["xyz", "top", "tk", "cf", "gq", "ml"];

        const tld = hostname.split(".").pop();

        if (suspiciousTLDs.includes(tld)) {
            score += 2;
            indicators.push("Suspicious top-level domain used");
        }

        // BRAND IMPERSONATION CHECK
        const brands = {
            paypal: "paypal.com",
            amazon: "amazon.com",
            google: "google.com",
            apple: "apple.com",
            facebook: "facebook.com",
            microsoft: "microsoft.com",
            netflix: "netflix.com",
            instagram: "instagram.com"
        };

        for (let brand in brands) {

            if (hostname.includes(brand) && !hostname.endsWith(brands[brand])) {

                score += 3;
                indicators.push(`Possible impersonation of ${brand}`);
                break;

            }
        }

        // URL SHORTENER CHECK
        const shorteners = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "is.gd",
            "buff.ly"
        ];

        if (shorteners.includes(hostname)) {

            score += 3;
            indicators.push("URL shortening service used");

        }

        // URL length
        if (url.length > 75) {
            score += 2;
            indicators.push("URL is unusually long");
        }

        // @ symbol
        if (url.includes("@")) {
            score += 3;
            indicators.push("URL contains @ symbol which may hide real destination");
        }

        // HTTP instead of HTTPS
        if (parsedURL.protocol === "http:") {
            score += 2;
            indicators.push("Website not using HTTPS");
        }

        // IP address
        const ipPattern = /(\d{1,3}\.){3}\d{1,3}/;

        if (ipPattern.test(hostname)) {
            score += 3;
            indicators.push("URL uses IP address instead of domain name");
        }

        // Subdomains
        const subdomainCount = hostname.split(".").length - 2;

        if (subdomainCount > 2) {
            score += 2;
            indicators.push("URL has excessive subdomains");
        }

        // DOMAIN AGE CHECK
        const domainResult = await checkDomainAge(hostname);

        score += domainResult.ageRisk;

        if (domainResult.indicator) {
            indicators.push(domainResult.indicator);
        }

        // WEBSITE CONTENT ANALYSIS
        const websiteResult = await analyzeWebsite(url);

        score += websiteResult.score;

        indicators = indicators.concat(websiteResult.indicators);

        // VIRUSTOTAL CHECK
        const vtResult=await checkVirusTotal(url);

        score+=vtResult.score;

        if(vtResult.indicator){
            indicators.push(vtResult.indicator);
        }

        const explanations=generateExplanation(indicators);

        res.json({
        url,
        phishing_score:score,
        risk_level:
        score>=6?"High Risk":
        score>=3?"Medium Risk":
        "Low Risk",
        indicators,
        explanations
        });

    } catch (error) {

        res.status(400).json({ error: "Invalid URL" });

    }

};