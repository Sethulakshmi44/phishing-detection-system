/**
 * virusTotalService.js
 *
 * Integrates with the VirusTotal API v3 to check URL reputation.
 * Requires VIRUSTOTAL_API_KEY to be set in the environment (.env file).
 *
 * Flow:
 *  1. Submit the URL for scanning (POST /urls)
 *  2. Poll the analysis report (GET /analyses/{id}) up to 3 times
 *  3. Return a risk score based on the number of engines that flagged it
 *
 * If no API key is set, skips gracefully and returns score: 0.
 */

const axios = require("axios");

const VT_BASE = "https://www.virustotal.com/api/v3";
const MAX_POLL_ATTEMPTS = 5;
const POLL_DELAY_MS = 2000;

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function checkVirusTotal(url) {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;

    if (!apiKey) {
        console.warn("[VirusTotal] VIRUSTOTAL_API_KEY not set — skipping VT check.");
        return { score: 0 };
    }

    const headers = {
        "x-apikey": apiKey,
        "Accept": "application/json"
    };

    try {
        // ── Step 1: Submit URL for scanning ──────────────────────────────────
        const submitResponse = await axios.post(
            `${VT_BASE}/urls`,
            new URLSearchParams({ url }).toString(),
            {
                headers: {
                    ...headers,
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                timeout: 10000
            }
        );

        const analysisId = submitResponse.data?.data?.id;
        if (!analysisId) {
            console.warn("[VirusTotal] No analysis ID returned from submission.");
            return { score: 0 };
        }

        // ── Step 2: Poll for results (up to MAX_POLL_ATTEMPTS times) ─────────
        for (let attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt++) {
            await sleep(POLL_DELAY_MS);

            try {
                const reportResponse = await axios.get(
                    `${VT_BASE}/analyses/${analysisId}`,
                    { headers, timeout: 10000 }
                );

                const status = reportResponse.data?.data?.attributes?.status;

                if (status === "completed") {
                    const stats = reportResponse.data.data.attributes.stats;
                    const malicious  = stats?.malicious  || 0;
                    const suspicious = stats?.suspicious || 0;
                    const total = malicious + suspicious;

                    if (malicious >= 10) {
                        return {
                            score: 5,
                            indicator: `VirusTotal: ${malicious} engines flagged as malicious`
                        };
                    } else if (malicious >= 5 || total >= 8) {
                        return {
                            score: 4,
                            indicator: `VirusTotal: ${malicious} malicious, ${suspicious} suspicious detections`
                        };
                    } else if (malicious >= 2 || total >= 3) {
                        return {
                            score: 3,
                            indicator: `VirusTotal: ${total} engines flagged this URL as suspicious`
                        };
                    } else if (malicious === 1 || total >= 1) {
                        return {
                            score: 2,
                            indicator: `VirusTotal: ${total} engine(s) flagged this URL`
                        };
                    } else {
                        return { score: 0 };
                    }
                }

                // If still queued/in-progress, wait and retry
                console.log(`[VirusTotal] Attempt ${attempt + 1}: status = ${status}, retrying...`);

            } catch (pollErr) {
                console.warn(`[VirusTotal] Poll attempt ${attempt + 1} failed:`, pollErr.message);
            }
        }

        // Analysis didn't complete in time — return neutral
        console.warn("[VirusTotal] Analysis did not complete within polling window.");
        return { score: 0 }; // Do not return an indicator on timeout to prevent false positives

    } catch (err) {
        if (err.response?.status === 401) {
            console.error("[VirusTotal] Invalid API key — check VIRUSTOTAL_API_KEY in .env");
        } else if (err.response?.status === 429) {
            console.warn("[VirusTotal] Rate limit exceeded (free tier: 4 req/min).");
        } else {
            console.error("[VirusTotal] Error:", err.message);
        }
        return { score: 0 };
    }
}

module.exports = { checkVirusTotal };