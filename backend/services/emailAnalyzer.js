const { simpleParser } = require("mailparser");

async function analyzeEmail(rawEmail) {

    let score = 0;
    let indicators = [];

    try {

        const parsed = await simpleParser(rawEmail);

        const from = parsed.from?.text || "";
        const replyTo = parsed.replyTo?.text || "";

        // Reply-To mismatch
        if (replyTo && from && replyTo !== from) {

            score += 3;
            indicators.push("Reply-To address differs from sender");

        }

        // Extract links
        const body = parsed.html || parsed.text || "";

        const urlRegex = /(https?:\/\/[^\s]+)/g;

        const links = body.match(urlRegex) || [];

        if (links.length > 3) {

            score += 2;
            indicators.push("Email contains multiple links");

        }

        // Shortened URLs
        const shorteners = ["bit.ly", "tinyurl.com", "t.co"];

        links.forEach(link => {

            for (let short of shorteners) {

                if (link.includes(short)) {

                    score += 3;
                    indicators.push("Shortened URL found in email");

                }

            }

        });

        // Fallback detection if parser fails
        const raw = rawEmail.toLowerCase();

        if(raw.includes("reply-to:") && raw.includes("from:")){

        const fromMatch = raw.match(/from:\s*(.*)/);
        const replyMatch = raw.match(/reply-to:\s*(.*)/);

        if(fromMatch && replyMatch && fromMatch[1] !== replyMatch[1]){

        score += 3;
        indicators.push("Reply-To address differs from sender");

        }

        }
        return { score, indicators };

    } catch (error) {

        return { score: 0, indicators: [] };

    }

}

module.exports = { analyzeEmail };