const axios = require("axios");
const cheerio = require("cheerio");

async function analyzeWebsite(url) {

    let score = 0;
    let indicators = [];

    try {

        const response = await axios.get(url, { timeout: 5000 });

        const html = response.data;

        const $ = cheerio.load(html);

        // Detect login forms
        const forms = $("form");

        forms.each((i, form) => {

            const inputs = $(form).find("input");

            inputs.each((j, input) => {

                const type = $(input).attr("type");

                if (type === "password") {

                    score += 3;
                    indicators.push("Login form detected");

                }

            });

        });

        // Detect iframes
        const iframeCount = $("iframe").length;

        if (iframeCount > 0) {

            score += 2;
            indicators.push("Website contains iframe elements");

        }

        // Detect external scripts
        const scripts = $("script[src]");

        if (scripts.length > 5) {

            score += 2;
            indicators.push("Large number of external scripts");

        }

        return { score, indicators };

    } catch (error) {

        return { score: 0, indicators: [] };

    }

}

module.exports = { analyzeWebsite };