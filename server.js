const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const keys = new Map(); // Temporary storage
const permanentKeys = new Map(); // Permanent storage

// Define key durations correctly
const KEY_DURATIONS = {
    "1-week": 7 * 24 * 60 * 60 * 1000,  // 7 days
    "1-month": 30 * 24 * 60 * 60 * 1000, // 30 days
    "1-year": 365 * 24 * 60 * 60 * 1000, // 1 year
    "one-time": 24 * 60 * 60 * 1000,     // 1 day
    "1-minute": 60 * 1000,               // 1 minute
    "1-second": 1 * 1000,                // 1 second
    "5-seconds": 5 * 1000                // 5 seconds
};

const UNUSED_EXPIRY = 3 * 60 * 1000; // Unused keys expire in 3 minutes
const ADMIN_SECRET = "BUHUM"; // Change this for security

function generateKey(hwid, keyType) {
    return `INF-${keyType.replace(/[^a-zA-Z0-9]/g, '').toUpperCase()}-${hwid.slice(0, 6)}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}

// Generate a key
app.post('/generate-key', (req, res) => {
    const { hwid, keyType } = req.body;

    if (!hwid || !keyType) {
        return res.status(400).json({ error: 'HWID and key type required' });
    }

    if (!(keyType in KEY_DURATIONS) && keyType !== "permanent") {
        return res.status(400).json({ error: 'Invalid key type' });
    }

    const key = generateKey(hwid, keyType);
    const now = Date.now();

    if (keyType === "permanent") {
        permanentKeys.set(hwid, { key, createdAt: now });
        return res.json({ key, expiresIn: "Never" });
    }

    const keyData = { key, hwid, keyType, createdAt: now, expiresAt: now + KEY_DURATIONS[keyType] };

    setTimeout(() => {
        if (!keyData.firstUsed) {
            keys.set(hwid, (keys.get(hwid) || []).filter(k => k.key !== key));
        }
    }, UNUSED_EXPIRY);

    if (!keys.has(hwid)) keys.set(hwid, []);
    keys.get(hwid).push(keyData);

    res.json({ key, expiresIn: KEY_DURATIONS[keyType] });
});

// Validate key
app.post('/validate-key', (req, res) => {
    const { key, hwid } = req.body;

    if (!key || !hwid) {
        return res.status(400).json({ error: 'Key and HWID required' });
    }

    if (permanentKeys.has(hwid) && permanentKeys.get(hwid).key === key) {
        return res.json({ success: true, expiresIn: "Never" });
    }

    if (keys.has(hwid)) {
        const keyData = keys.get(hwid).find(k => k.key === key);

        if (keyData) {
            if (Date.now() > keyData.expiresAt) {
                keys.set(hwid, keys.get(hwid).filter(k => k.key !== key));
                return res.status(400).json({ error: 'Key expired' });
            }

            if (!keyData.firstUsed) {
                keyData.firstUsed = Date.now();
            }

            return res.json({ success: true, expiresIn: keyData.expiresAt - Date.now() });
        }
    }

    res.status(404).json({ error: 'Invalid or expired key' });
});

// Admin route to generate permanent or timed keys manually
app.post('/admin/generate-key', (req, res) => {
    const { hwid, keyType, secret } = req.body;

    if (secret !== ADMIN_SECRET) {
        return res.status(403).json({ error: "Unauthorized" });
    }

    if (!hwid || !keyType) {
        return res.status(400).json({ error: 'HWID and key type required' });
    }

    if (!(keyType in KEY_DURATIONS) && keyType !== "permanent") {
        return res.status(400).json({ error: 'Invalid key type' });
    }

    const key = generateKey(hwid, keyType);
    const now = Date.now();

    if (keyType === "permanent") {
        permanentKeys.set(hwid, { key, createdAt: now });
        return res.json({ key, expiresIn: "Never" });
    }

    const keyData = { key, hwid, keyType, createdAt: now, expiresAt: now + KEY_DURATIONS[keyType] };
    if (!keys.has(hwid)) keys.set(hwid, []);
    keys.get(hwid).push(keyData);

    res.json({ key, expiresIn: KEY_DURATIONS[keyType] });
});

app.listen(3000, () => console.log('Key system running on port 3000'));
