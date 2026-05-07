/**
 * websiteAnalyzer.js
 *
 * Fetches and analyzes the actual content of a webpage for phishing indicators.
 * Uses real content-analysis heuristics: brand impersonation, suspicious language,
 * form analysis, DOM structure signals, and obfuscation techniques.
 *
 * NO hardcoded URLs or domains — all logic is rule/pattern-based.
 */

const axios = require("axios");
const cheerio = require("cheerio");

// Whole-word regex cache for brand matching (avoids rebuilding on every request)
const _brandWordRegex = new Map();
function getBrandRegex(brand) {
    if (!_brandWordRegex.has(brand)) {
        // Match the brand name as a whole word (not inside another word)
        _brandWordRegex.set(brand, new RegExp('\\b' + brand.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'gi'));
    }
    return _brandWordRegex.get(brand);
}

// ─── Expanded brand list (name → canonical domain) ──────────────────────────
const BRAND_MAP = {
    "paypal":       "paypal.com",
    "google":       "google.com",
    "gmail":        "google.com",
    "amazon":       "amazon.com",
    "apple":        "apple.com",
    "icloud":       "apple.com",
    "facebook":     "facebook.com",
    "instagram":    "instagram.com",
    "microsoft":    "microsoft.com",
    "outlook":      "microsoft.com",
    "office365":    "microsoft.com",
    "netflix":      "netflix.com",
    "linkedin":     "linkedin.com",
    "dropbox":      "dropbox.com",
    "twitter":      "twitter.com",
    "whatsapp":     "whatsapp.com",
    "snapchat":     "snapchat.com",
    "yahoo":        "yahoo.com",
    "ebay":         "ebay.com",
    "chase":        "chase.com",
    "wellsfargo":   "wellsfargo.com",
    "bankofamerica":"bankofamerica.com",
    "citibank":     "citibank.com",
    "steam":        "steampowered.com",
    "coinbase":     "coinbase.com",
    "binance":      "binance.com",
    "dhl":          "dhl.com",
    "fedex":        "fedex.com",
    "ups":          "ups.com",
    "usps":         "usps.com",
    "irs":          "irs.gov",
    "walmart":      "walmart.com",
    "bestbuy":      "bestbuy.com"
};

// ─── Phishing-specific phrases (scored individually) ─────────────────────────
const PHISHING_PHRASES = [
    "verify your account",
    "confirm your identity",
    "account has been suspended",
    "your account will be closed",
    "urgent action required",
    "click here to verify",
    "click here to login",
    "unusual activity detected",
    "suspicious activity",
    "update your billing",
    "update your payment",
    "enter your password",
    "your password has expired",
    "confirm your email",
    "validate your account",
    "you have won",
    "prize winner",
    "claim your reward",
    "limited time offer",
    "your account is at risk",
    "security alert",
    "login attempt",
    "we have noticed",
    "temporarily suspended",
    "failure to verify"
];

async function analyzeWebsite(url) {
    let score = 0;
    let indicators = [];

    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();
    // Canonical domain = last two parts (e.g. google.com from www.google.com)
    const domainParts = domain.split(".");
    const canonicalDomain = domainParts.slice(-2).join(".");

    try {
        const response = await axios.get(url, {
            timeout: 7000,
            maxRedirects: 5,
            headers: {
                // Mimic a real browser to avoid bot-detection blocks
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
            }
        });

        const $ = cheerio.load(response.data);
        const rawHtml = response.data.toLowerCase();
        const pageText = $("body").text().toLowerCase();
        const pageTitle = $("title").text().toLowerCase();

        // ── 1. Brand impersonation check ─────────────────────────────────────
        // Flag if brand name appears prominently in page text/title but the
        // hosting domain is NOT the canonical brand domain.
        //
        // To avoid false positives (e.g. "irs" in footer legal text on google.com):
        //  - Use whole-word regex matching (not substring)
        //  - Require the brand name to appear in the title OR 2+ times in body text
        //  - Skip very short brand names (< 4 chars) that risk collisions
        let spoofedBrand = null;
        for (const [brand, canonicalBrandDomain] of Object.entries(BRAND_MAP)) {
            if (brand.length < 4) continue; // skip short names like "dhl", "irs", "ups"

            const onCorrectDomain = canonicalDomain === canonicalBrandDomain ||
                                    domain.endsWith("." + canonicalBrandDomain);
            if (onCorrectDomain) continue; // legitimate site — skip

            const regex = getBrandRegex(brand);
            const inTitle = regex.test(pageTitle);
            regex.lastIndex = 0; // reset stateful regex
            const bodyMatches = (pageText.match(regex) || []).length;

            // Brand appears in title OR mentioned 2+ times prominently in body
            if (inTitle || bodyMatches >= 2) {
                spoofedBrand = brand;
                break;
            }
        }
        if (spoofedBrand) {
            score += 3;
            indicators.push(`Possible brand impersonation: "${spoofedBrand}" referenced but domain is unrelated`);
        }

        // ── 2. Phishing phrase scoring ────────────────────────────────────────
        // Score each phrase individually (cap contribution at 3)
        let phraseHits = PHISHING_PHRASES.filter(phrase => pageText.includes(phrase));
        if (phraseHits.length >= 3) {
            score += 3;
            indicators.push(`Multiple phishing phrases detected (${phraseHits.length} matches)`);
        } else if (phraseHits.length >= 1) {
            score += phraseHits.length;
            indicators.push(`Phishing-related language detected: "${phraseHits[0]}"`);
        }

        // ── 3. Password / credential input form detection ─────────────────────
        const passwordInputs = $("input[type='password']").length;
        if (passwordInputs > 0) {
            score += 2;
            indicators.push("Login/credential form detected on page");
        }

        // ── 4. Form action domain mismatch ────────────────────────────────────
        let formMismatch = false;
        $("form").each((i, form) => {
            const action = $(form).attr("action");
            if (action && action.startsWith("http")) {
                try {
                    const actionHost = new URL(action).hostname.toLowerCase();
                    if (actionHost !== domain && !actionHost.endsWith("." + canonicalDomain)) {
                        formMismatch = true;
                    }
                } catch { }
            }
        });
        if (formMismatch) {
            score += 4;
            indicators.push("Form submits data to a different domain");
        }

        // ── 5. Hidden iframes (common in phishing kits) ───────────────────────
        let suspiciousIframes = 0;
        $("iframe").each((i, el) => {
            const src = $(el).attr("src") || "";
            const style = $(el).attr("style") || "";
            const width = $(el).attr("width") || "";
            const height = $(el).attr("height") || "";
            // Detect hidden or 0-size iframes with external src
            if (src && !src.startsWith("/") && (
                style.includes("display:none") || style.includes("display: none") ||
                width === "0" || height === "0" || width === "1" || height === "1"
            )) {
                suspiciousIframes++;
            }
        });
        if (suspiciousIframes > 0) {
            score += 2;
            indicators.push("Hidden iframe(s) detected (common in phishing kits)");
        }

        // ── 6. Excessive external scripts ─────────────────────────────────────
        let externalScripts = 0;
        $("script[src]").each((i, el) => {
            const src = $(el).attr("src") || "";
            if (src.startsWith("http") && !src.includes(canonicalDomain)) {
                externalScripts++;
            }
        });
        if (externalScripts >= 10) {
            score += 2;
            indicators.push(`High number of external scripts loaded (${externalScripts})`);
        }

        // ── 7. Right-click / copy disabled via JS ────────────────────────────
        // Require explicit disabling patterns — not just any contextmenu usage
        // (legitimate sites like Google use contextmenu for their own UI features)
        const rightClickDisabled =
            rawHtml.includes("disableright") ||
            rawHtml.includes("event.button==2") ||
            rawHtml.includes("oncontextmenu=\"return false\"") ||
            rawHtml.includes("oncontextmenu='return false'") ||
            (rawHtml.includes("contextmenu") &&
             rawHtml.includes("preventdefault") &&
             rawHtml.includes("return false"));
        if (rightClickDisabled) {
            score += 1;
            indicators.push("Right-click disabled (anti-inspection technique)");
        }

        // ── 8. Meta refresh redirect ──────────────────────────────────────────
        const metaRefresh = $("meta[http-equiv='refresh'], meta[http-equiv='Refresh']").length;
        if (metaRefresh > 0) {
            score += 1;
            indicators.push("Meta refresh redirect detected");
        }

        // ── 9. No favicon (phish kits often forget this) ─────────────────────
        const hasFavicon =
            $("link[rel='icon'], link[rel='shortcut icon'], link[rel='apple-touch-icon']").length > 0;
        if (!hasFavicon && passwordInputs > 0) {
            // Only flag if there's also a login form — alone it's not reliable
            score += 1;
            indicators.push("Login form present but no favicon (common in phishing kits)");
        }

        return { score, indicators };

    } catch (error) {
        if (error.code === "ENOTFOUND" || error.code === "EAI_AGAIN") {
            return {
                score: 3,
                indicators: ["Domain does not resolve (non-existent or taken down)"]
            };
        }
        if (error.code === "ECONNREFUSED" || error.code === "ETIMEDOUT") {
            return {
                score: 2,
                indicators: ["Website connection refused or timed out"]
            };
        }
        if (error.response?.status === 403 || error.response?.status === 401) {
            // Site exists but blocks automated access — neutral, don't penalize
            return { score: 0, indicators: [] };
        }
        return {
            score: 1,
            indicators: ["Website could not be accessed"]
        };
    }
}

module.exports = { analyzeWebsite };