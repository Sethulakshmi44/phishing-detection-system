/**
 * domainChecker.js
 *
 * Checks the registration age of a domain using the RDAP protocol.
 * Domain age is a reliable phishing signal — newly registered domains
 * are disproportionately used in phishing campaigns.
 *
 * Returns a risk score contribution:
 *   < 30 days old  → ageRisk: 3  (very high risk)
 *   < 180 days old → ageRisk: 2  (elevated risk)
 *   < 365 days old → ageRisk: 1  (slight risk)
 *   ≥ 365 days old → ageRisk: 0  (established, no signal either way)
 *
 * NOTE: An established domain gives 0 (neutral) — NOT a negative trust bonus.
 * Old domains can be compromised, parked, or sold. Age alone is not proof of safety.
 */

const axios = require("axios");

// RDAP servers to try in order (fallback chain)
const RDAP_SERVERS = [
    domain => `https://rdap.org/domain/${domain}`,
    domain => `https://rdap.iana.org/domain/${domain}`
];

async function checkDomainAge(domain) {
    // Strip leading "www." for RDAP lookup
    const lookupDomain = domain.replace(/^www\./, "");

    for (const serverFn of RDAP_SERVERS) {
        try {
            const response = await axios.get(serverFn(lookupDomain), {
                timeout: 5000,
                headers: { "Accept": "application/rdap+json, application/json" }
            });

            const events = response.data?.events;
            if (!Array.isArray(events)) continue;

            // Find the registration (creation) event
            const creationEvent = events.find(
                e => e.eventAction === "registration" || e.eventAction === "created"
            );

            if (!creationEvent?.eventDate) {
                return { ageRisk: 0 }; // Can't determine age — treat as neutral
            }

            const creationDate = new Date(creationEvent.eventDate);
            if (isNaN(creationDate.getTime())) {
                return { ageRisk: 0 };
            }

            const ageDays = (Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24);

            if (ageDays < 30) {
                return {
                    ageRisk: 3,
                    indicator: "Very new domain (registered < 30 days ago)"
                };
            } else if (ageDays < 180) {
                return {
                    ageRisk: 2,
                    indicator: "Relatively new domain (registered < 6 months ago)"
                };
            } else if (ageDays < 365) {
                return {
                    ageRisk: 1,
                    indicator: "Moderately new domain (registered < 1 year ago)"
                };
            } else {
                // Established domain — neutral signal, no bonus, no penalty
                return { ageRisk: 0 };
            }

        } catch (err) {
            // Try next server
            continue;
        }
    }

    // All RDAP servers failed — domain lookup inconclusive
    // Return a mild risk: we couldn't verify, which is slightly suspicious
    return {
        ageRisk: 1,
        indicator: "Domain age could not be verified (RDAP lookup failed)"
    };
}

module.exports = { checkDomainAge };