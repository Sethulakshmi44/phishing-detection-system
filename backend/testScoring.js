require('dotenv').config();
const { analyzeUrlLogic } = require('./controllers/urlController');

const tests = [
    // Should be HIGH RISK (≥7)
    { url: 'http://amazon.xyz',                   expect: 'High Risk' },
    { url: 'http://paypal-secure-login.tk',        expect: 'High Risk' },
    { url: 'http://192.168.1.1/login',             expect: 'High Risk' },
    { url: 'http://microsoft-support.online/verify-account', expect: 'High Risk' },
    { url: 'http://paypa1.com/signin',             expect: 'High Risk' },
    // Should be MEDIUM or HIGH RISK (≥4)
    { url: 'http://secure-login.xyz/account',      expect: 'Medium Risk+' },
    { url: 'http://bit.ly/3xAbc12',                expect: 'Medium Risk+' },
    // Should be LOW RISK (≤3)
    { url: 'https://www.google.com',               expect: 'Low Risk' },
    { url: 'https://www.amazon.com',               expect: 'Low Risk' },
    { url: 'https://www.microsoft.com',            expect: 'Low Risk' },
    { url: 'https://www.paypal.com',               expect: 'Low Risk' },
];

const PASS = '\x1b[32m✓ PASS\x1b[0m';
const FAIL = '\x1b[31m✗ FAIL\x1b[0m';

async function runTests() {
    console.log('\n=== PHISHING DETECTION ACCURACY TEST ===\n');
    let passed = 0, failed = 0;

    for (const t of tests) {
        try {
            const r = await analyzeUrlLogic(t.url);
            const score = r.phishing_score;
            const risk  = r.risk_level;

            let ok = false;
            if (t.expect === 'High Risk')     ok = score >= 7;
            else if (t.expect === 'Medium Risk+') ok = score >= 4;
            else if (t.expect === 'Low Risk') ok = score <= 3;

            if (ok) passed++;
            else failed++;

            const icon = ok ? PASS : FAIL;
            console.log(icon + ' [' + score + '/10 ' + risk + '] ' + t.url);
            if (r.indicators.length) {
                r.indicators.forEach(i => console.log('      > ' + i));
            }
        } catch(e) {
            failed++;
            console.log(FAIL + ' ERROR: ' + t.url + ' — ' + e.message);
        }
        console.log('');
    }

    console.log('=== RESULTS: ' + passed + '/' + (passed+failed) + ' passed ===\n');
}

runTests();
