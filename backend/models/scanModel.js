const db = require('../../backend/db');

const saveScan = async (url, score, risk) => {
    const query = `
        INSERT INTO scan_history (url, phishing_score, risk_level)
        VALUES ($1, $2, $3)
    `;
    await db.query(query, [url, score, risk]);
};

const getScans = async () => {
    const result = await db.query(
        "SELECT * FROM scan_history ORDER BY created_at DESC LIMIT 10"
    );
    return result.rows;
};

module.exports = { saveScan, getScans };