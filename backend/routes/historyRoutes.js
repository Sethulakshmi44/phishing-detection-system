const express = require('express');
const router = express.Router();
const { getScans } = require('../models/scanModel');

router.get('/history', async (req, res) => {
    const scans = await getScans();
    res.json(scans);
});

module.exports = router;