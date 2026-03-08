const axios = require("axios");

async function checkDomainAge(domain) {

    try {

        const response = await axios.get(
            `https://rdap.org/domain/${domain}`
        );

        const events = response.data.events;

        let creationDate = null;

        for (let event of events) {
            if (event.eventAction === "registration") {
                creationDate = event.eventDate;
                break;
            }
        }

        if (!creationDate) {
            return { ageRisk: 0, indicator: null };
        }

        const created = new Date(creationDate);
        const now = new Date();

        const ageDays =
            (now - created) / (1000 * 60 * 60 * 24);

        if (ageDays < 180) {

            return {
                ageRisk: 3,
                indicator: "Domain registered recently"
            };

        }

        return { ageRisk: 0, indicator: null };

    } catch (error) {

        return { ageRisk: 0, indicator: null };

    }

}

module.exports = { checkDomainAge };