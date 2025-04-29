const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const keys = new Map();
const permanentKeys = new Map();

const KEY_DURATIONS = {
    "1-w": 7 * 24 * 60 * 60 * 1000,
    "1-m": 30 * 24 * 60 * 60 * 1000,
    "1-yr": 365 * 24 * 60 * 60 * 1000,
    "one-time": 24 * 60 * 60 * 1000,
    "1-min": 60 * 1000,
    "1-s": 1 * 1000,
    "5-s": 5 * 1000
};

const UNUSED_EXPIRY = 3 * 60 * 1000;
const ADMIN_SECRET = "adi";

function generateKey(hwid, keyType) {
    return `INF-${keyType.replace(/[^a-zA-Z0-9]/g, '').toUpperCase()}-${hwid.slice(0, 6)}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}

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
            const now = Date.now();

            if (!keyData.firstUsed) {
                keyData.firstUsed = now;
                keyData.expiresAt = now + KEY_DURATIONS[keyData.keyType];
            }

            if (now > keyData.expiresAt) {
                keys.set(hwid, keys.get(hwid).filter(k => k.key !== key));
                return res.status(400).json({ error: 'Key expired' });
            }

            return res.json({ success: true, expiresIn: keyData.expiresAt - now });
        }
    }

    res.status(404).json({ error: 'Invalid or expired key' });
});

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

    setTimeout(() => {
        if (!keyData.firstUsed) {
            keys.set(hwid, (keys.get(hwid) || []).filter(k => k.key !== key));
        }
    }, UNUSED_EXPIRY);

    if (!keys.has(hwid)) keys.set(hwid, []);
    keys.get(hwid).push(keyData);

    res.json({ key, expiresIn: KEY_DURATIONS[keyType] });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Key system running on port ${PORT}`));
