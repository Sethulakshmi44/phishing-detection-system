/**
 * urlFeatureAnalyzer.js
 *
 * Real phishing URL heuristics based on industry and academic research.
 * Each feature contributes independently with calibrated weights.
 * NO hard-coding of specific URLs — all logic is rule/pattern-based.
 */

const { URL } = require("url");

// ─── Known brands: name → canonical TLD (for impersonation detection) ────────
const BRAND_CANONICAL = {
    "paypal":        "paypal.com",
    "google":        "google.com",
    "gmail":         "google.com",
    "amazon":        "amazon.com",
    "apple":         "apple.com",
    "icloud":        "apple.com",
    "facebook":      "facebook.com",
    "instagram":     "instagram.com",
    "microsoft":     "microsoft.com",
    "outlook":       "microsoft.com",
    "netflix":       "netflix.com",
    "linkedin":      "linkedin.com",
    "dropbox":       "dropbox.com",
    "twitter":       "twitter.com",
    "whatsapp":      "whatsapp.com",
    "snapchat":      "snapchat.com",
    "yahoo":         "yahoo.com",
    "ebay":          "ebay.com",
    "chase":         "chase.com",
    "wellsfargo":    "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "citibank":      "citibank.com",
    "steam":         "steampowered.com",
    "coinbase":      "coinbase.com",
    "binance":       "binance.com",
    "dhl":           "dhl.com",
    "fedex":         "fedex.com",
    "usps":          "usps.com",
    "irs":           "irs.gov",
    "walmart":       "walmart.com",
    "bestbuy":       "bestbuy.com",
    "netflix":       "netflix.com",
    "spotify":       "spotify.com",
    "adobe":         "adobe.com",
    "wordpress":     "wordpress.com",
    "github":        "github.com"
};

const BRAND_NAMES = Object.keys(BRAND_CANONICAL);

// ─── Suspicious TLDs heavily abused in phishing campaigns ─────────────────────
const SUSPICIOUS_TLDS = new Set([
    "tk", "ml", "ga", "cf", "gq",         // Freenom free domains
    "xyz", "top", "club", "work",          // Common phishing TLDs
    "online", "site", "website", "store",  // Generic abuse
    "info", "biz",                         // Historically abused
    "ru", "cn", "cc",                      // High-abuse country codes
    "zip", "mov"                           // New TLDs abused for phishing
]);

// ─── Known URL shorteners ──────────────────────────────────────────────────────
const URL_SHORTENERS = new Set([
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "is.gd", "buff.ly", "adf.ly", "short.link", "rebrand.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc"
]);

// ─── Levenshtein distance for typosquatting ────────────────────────────────────
function levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, (_, i) =>
        Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
    );
    for (let i = 1; i <= m; i++) {
        for (let j = 1; j <= n; j++) {
            dp[i][j] = a[i - 1] === b[j - 1]
                ? dp[i - 1][j - 1]
                : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
        }
    }
    return dp[m][n];
}

/**
 * Analyze the URL string for phishing indicators.
 * Returns additive score contributions — do NOT normalize here.
 * The controller caps and normalizes the final combined score.
 */
function analyzeUrlFeatures(rawUrl) {
    let score = 0;
    const indicators = [];

    let parsedURL;
    try {
        const formatted = /^https?:\/\//i.test(rawUrl) ? rawUrl : "http://" + rawUrl;
        parsedURL = new URL(formatted);
    } catch {
        return { score: 4, indicators: ["Malformed URL"] };
    }

    const hostname    = parsedURL.hostname.toLowerCase();
    const fullUrl     = rawUrl.toLowerCase();
    const path        = parsedURL.pathname.toLowerCase();
    const tld         = hostname.split(".").pop();
    const hostParts   = hostname.split(".");
    // Second-level domain label (e.g. "amazon" from "amazon.xyz", "paypal" from "www.paypal.com")
    const sldLabel    = hostParts.length >= 2 ? hostParts[hostParts.length - 2] : "";
    // Canonical domain = sld + tld
    const canonicalDomain = hostParts.slice(-2).join(".");
    // Subdomain parts (everything before sld.tld)
    const subdomainParts  = hostParts.slice(0, -2);

    // ── 1. IP address as hostname ─────────────────────────────────────────────
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
        score += 4;
        indicators.push("URL uses IP address instead of domain name");
    }

    // ── 2. Suspicious TLD ─────────────────────────────────────────────────────
    if (SUSPICIOUS_TLDS.has(tld)) {
        score += 2;
        indicators.push("Suspicious top-level domain used");
    }

    // ── 3. URL shortener ──────────────────────────────────────────────────────
    if (URL_SHORTENERS.has(canonicalDomain)) {
        score += 2;
        indicators.push("URL shortener detected (hides true destination)");
    }

    // ── 4. Brand name EXACTLY in SLD on wrong domain ──────────────────────────
    // e.g. amazon.xyz, paypal.tk, google.site
    // The SLD IS the brand name, but the full domain ≠ canonical brand domain.
    // This is the strongest brand-impersonation signal.
    let brandInSLD = null;
    for (const brand of BRAND_NAMES) {
        if (sldLabel === brand) {
            const canonical = BRAND_CANONICAL[brand];
            if (canonicalDomain !== canonical) {
                brandInSLD = brand;
                score += 4;
                indicators.push(`Brand name "${brand}" used as domain on non-official TLD (impersonation)`);
                break;
            }
        }
    }

    // ── 5. Brand name CONTAINED in SLD (compound impersonation) ──────────────
    // e.g. paypal-secure.com, amazon-login.net, apple-id-verify.com
    if (!brandInSLD) {
        for (const brand of BRAND_NAMES) {
            const canonical = BRAND_CANONICAL[brand];
            if (sldLabel.includes(brand) && canonicalDomain !== canonical) {
                score += 3;
                indicators.push(`Brand name "${brand}" embedded in domain label (possible impersonation)`);
                brandInSLD = brand;
                break;
            }
        }
    }

    // ── 6. Brand name in subdomain ─────────────────────────────────────────────
    // e.g. paypal.evil.com → subdomain = "paypal", sld = "evil"
    if (!brandInSLD && subdomainParts.length > 0) {
        const subStr = subdomainParts.join(".");
        for (const brand of BRAND_NAMES) {
            const canonical = BRAND_CANONICAL[brand];
            if (subStr.includes(brand) && canonicalDomain !== canonical) {
                score += 3;
                indicators.push(`Brand name "${brand}" found in subdomain (domain spoofing)`);
                brandInSLD = brand;
                break;
            }
        }
    }

    // ── 7. Typosquatting via Levenshtein ──────────────────────────────────────
    // Only check if no brand match was already found (to avoid double-counting)
    if (!brandInSLD) {
        for (const brand of BRAND_NAMES) {
            const canonical = BRAND_CANONICAL[brand];
            // Skip if it IS the canonical domain
            if (canonicalDomain === canonical) continue;
            if (sldLabel.length < 4 || brand.length < 4) continue;
            const dist = levenshtein(sldLabel, brand);
            if (dist >= 1 && dist <= 2) {
                score += 3;
                indicators.push(`Possible typosquatting of "${brand}" (very similar domain name)`);
                break;
            }
        }
    }

    // ── 8. URL length ─────────────────────────────────────────────────────────
    if (fullUrl.length > 100) {
        score += 2;
        indicators.push("Excessively long URL");
    } else if (fullUrl.length > 75) {
        score += 1;
        indicators.push("Long URL");
    }

    // ── 9. @ symbol in URL ────────────────────────────────────────────────────
    if (fullUrl.includes("@")) {
        score += 2;
        indicators.push("Contains @ symbol (browser ignores preceding content)");
    }

    // ── 10. Excessive subdomain depth ─────────────────────────────────────────
    if (hostParts.length >= 5) {
        score += 2;
        indicators.push("Excessive subdomain depth");
    } else if (hostParts.length === 4) {
        score += 1;
        indicators.push("Multiple subdomain levels");
    }

    // ── 11. Hyphens in the SLD label ──────────────────────────────────────────
    const hyphenCount = (sldLabel.match(/-/g) || []).length;
    if (hyphenCount >= 2) {
        score += 2;
        indicators.push("Multiple hyphens in domain name (common phishing pattern)");
    } else if (hyphenCount === 1) {
        score += 1;
        indicators.push("Hyphenated domain name");
    }

    // ── 12. Numeric substitution in domain (homograph) ────────────────────────
    if (!brandInSLD && /\d/.test(sldLabel) && sldLabel.length > 3) {
        score += 1;
        indicators.push("Numeric characters in domain name (possible homograph)");
    }

    // ── 13. Non-standard port ─────────────────────────────────────────────────
    const port = parsedURL.port;
    if (port && port !== "80" && port !== "443") {
        score += 2;
        indicators.push("Non-standard port in URL");
    }

    // ── 14. Redirect parameters ───────────────────────────────────────────────
    const redirectKeys = ["redirect", "url", "goto", "next", "return", "returnurl", "dest"];
    for (const key of redirectKeys) {
        if (parsedURL.searchParams.has(key)) {
            score += 1;
            indicators.push("URL contains redirect parameter (possible redirect chain)");
            break;
        }
    }

    // ── 15. Double slashes in path ────────────────────────────────────────────
    if (path.includes("//")) {
        score += 1;
        indicators.push("Double slashes in URL path (obfuscation)");
    }

    // ── 16. Excessive percent-encoding ────────────────────────────────────────
    const encodedCount = (fullUrl.match(/%[0-9a-f]{2}/gi) || []).length;
    if (encodedCount >= 5) {
        score += 2;
        indicators.push("Heavy percent-encoding in URL (obfuscation)");
    } else if (encodedCount >= 2) {
        score += 1;
        indicators.push("Percent-encoded characters in URL");
    }

    // ── 17. Sensitive path keywords ───────────────────────────────────────────
    const sensitiveWords = [
        "login", "signin", "account", "verify", "secure", "banking",
        "update", "confirm", "password", "credential", "webscr", "cmd=_login"
    ];
    const pathQuery = (path + parsedURL.search).toLowerCase();
    const sensitiveHits = sensitiveWords.filter(w => pathQuery.includes(w));
    if (sensitiveHits.length >= 2) {
        score += 2;
        indicators.push("Multiple sensitive keywords in URL path (login/verify/secure)");
    } else if (sensitiveHits.length === 1) {
        score += 1;
        indicators.push("Sensitive keyword in URL path");
    }

    return { score, indicators };
}

module.exports = { analyzeUrlFeatures };
