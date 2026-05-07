/**
 * explanationService.js
 *
 * Maps indicator strings to human-readable explanations.
 * Uses partial-match lookup so indicators with dynamic values
 * (e.g. brand names, counts) are still matched correctly.
 */

const EXPLANATIONS = [
    {
        match: "URL uses IP address",
        text: "Phishing sites often use raw IP addresses instead of domain names to avoid registration tracking and to confuse victims."
    },
    {
        match: "Suspicious top-level domain",
        text: "Certain TLDs (.tk, .ml, .xyz, .top, etc.) are offered for free or very cheaply and are disproportionately used in phishing campaigns."
    },
    {
        match: "URL shortener detected",
        text: "URL shortening services hide the true destination, which is a common phishing technique to prevent victims from seeing the real domain."
    },
    {
        match: "Excessively long URL",
        text: "Very long URLs are a strong indicator of phishing — attackers pad URLs with random tokens and parameters to obscure the true domain."
    },
    {
        match: "Long URL",
        text: "Longer-than-average URLs can be a sign of obfuscation. Legitimate sites generally use concise, readable URLs."
    },
    {
        match: "Contains @ symbol",
        text: "The '@' symbol in a URL causes browsers to ignore everything before it. Phishers use this to hide the real destination (e.g., google.com@evil.com goes to evil.com)."
    },
    {
        match: "Excessive subdomain depth",
        text: "Phishing sites create very deep subdomain chains (e.g., login.paypal.secure.verify.evil.com) to make the URL look legitimate at a glance."
    },
    {
        match: "Multiple subdomain levels",
        text: "Multiple subdomain levels can be used to embed trusted brand names while directing traffic to an attacker-controlled domain."
    },
    {
        match: "Multiple hyphens in domain",
        text: "Domains with multiple hyphens (e.g., paypal-secure-login.com) are a well-known phishing pattern used to impersonate legitimate services."
    },
    {
        match: "Hyphenated domain name",
        text: "Hyphens are commonly inserted into domain names to impersonate brands (e.g., 'paypal-verify.com' instead of 'paypal.com')."
    },
    {
        match: "found in subdomain (possible spoofing)",
        text: "Placing a trusted brand name in a subdomain (e.g., paypal.attacker.com) is a classic phishing trick — the real domain is attacker.com, not paypal.com."
    },
    {
        match: "Possible typosquatting",
        text: "The domain is suspiciously similar to a well-known brand (e.g., 'paypa1.com' vs 'paypal.com'). Attackers register near-identical domains hoping users won't notice the difference."
    },
    {
        match: "Numeric characters in domain name",
        text: "Numbers substituted for similar-looking letters (e.g., '0' for 'o', '1' for 'l') is a homograph attack technique used to impersonate brands."
    },
    {
        match: "Non-standard port",
        text: "Legitimate websites use standard ports (80/443). A non-standard port often indicates a malicious server that cannot obtain proper hosting."
    },
    {
        match: "redirect parameter",
        text: "URLs containing redirect parameters (e.g., ?url=, ?goto=) can chain victims through multiple domains, ultimately landing on a phishing page."
    },
    {
        match: "Double slashes in URL path",
        text: "Double slashes in the path component are an obfuscation technique used to confuse URL parsers and evade detection."
    },
    {
        match: "Heavy percent-encoding",
        text: "Excessive URL encoding (e.g., %70%61%79%70%61%6C) is used to obscure malicious URLs from security scanners and email filters."
    },
    {
        match: "Percent-encoded characters",
        text: "Percent-encoding in URLs can be used to hide malicious intent from security tools that don't decode before scanning."
    },
    {
        match: "Multiple sensitive keywords in URL path",
        text: "Multiple sensitive terms (login, verify, secure, account) in the URL path are strong indicators of a credential-harvesting phishing page."
    },
    {
        match: "Sensitive keyword in URL path",
        text: "Words like 'login', 'verify', or 'secure' in the URL path are often used by phishing sites to appear legitimate."
    },
    {
        match: "Malformed URL",
        text: "The URL is malformed or invalid. Legitimate services always use properly formatted URLs."
    },
    {
        match: "Possible brand impersonation",
        text: "The page references a well-known brand name but is hosted on an unrelated domain. This is the core technique of phishing — tricking users into thinking they're on a legitimate site."
    },
    {
        match: "Multiple phishing phrases detected",
        text: "The page contains numerous phrases commonly used in phishing attacks to create urgency and panic, pressuring users into acting without thinking."
    },
    {
        match: "Phishing-related language detected",
        text: "The page uses language designed to create urgency or fear (e.g., 'your account is suspended', 'verify now'). This is a hallmark of social engineering attacks."
    },
    {
        match: "Login/credential form detected",
        text: "A login form is present on this page. Combined with other signals, this is a strong indicator the page is designed to steal credentials."
    },
    {
        match: "Form submits data to a different domain",
        text: "The login form on this page sends your data to a different domain — a definitive sign of credential harvesting. Your password would go directly to attackers."
    },
    {
        match: "Hidden iframe",
        text: "Hidden iframes (invisible page embeds) are used in phishing kits to load malicious content or steal session data without the user's knowledge."
    },
    {
        match: "High number of external scripts",
        text: "Loading many external scripts can indicate a phishing kit assembling a fake page from multiple malicious sources, or tracking/logging user input."
    },
    {
        match: "Right-click disabled",
        text: "Disabling right-click is an anti-inspection technique used by phishing kits to prevent users from viewing page source or reporting the page."
    },
    {
        match: "Meta refresh redirect",
        text: "A meta refresh tag automatically redirects users to another page. This is used in multi-hop phishing chains to move victims through decoy pages."
    },
    {
        match: "Login form present but no favicon",
        text: "Phishing kit pages often forget to include a favicon. A credential-collecting form without a favicon is a common characteristic of quickly-assembled phishing pages."
    },
    {
        match: "Domain does not resolve",
        text: "The domain does not exist in DNS — it may have been taken down after being reported, or it was never a real domain."
    },
    {
        match: "Very new domain",
        text: "This domain was registered within the last 30 days. Phishing campaigns frequently use freshly-registered domains to avoid blacklists."
    },
    {
        match: "Relatively new domain",
        text: "This domain is less than 6 months old. While not conclusive alone, newly registered domains are disproportionately used in phishing."
    },
    {
        match: "VirusTotal",
        text: "VirusTotal aggregates results from 70+ antivirus engines and URL scanners. A detection here means professional security tools have flagged this URL as malicious."
    }
];

function generateExplanation(indicators) {
    return indicators.map(indicator => {
        const lowerIndicator = indicator.toLowerCase();
        for (const entry of EXPLANATIONS) {
            if (lowerIndicator.includes(entry.match.toLowerCase())) {
                return entry.text;
            }
        }
        return "This indicator suggests potentially suspicious behavior associated with phishing or social engineering.";
    });
}

module.exports = { generateExplanation };