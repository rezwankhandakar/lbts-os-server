/* Manual test: imgbb block হলে self-host fallback কাজ করে কি না।
   `node tests/imageUpload.manual.js` দিয়ে চালানো যায় (network লাগে না —
   axios mock করা)। */

const axios = require('axios');
const assert = require('assert');

// ── imgbb-কে ঠিক আসল block response-টাই ফেরত দিতে বলি ──
let capturedHeaders = null;
axios.post = async (url, body, cfg) => {
    capturedHeaders = cfg?.headers;
    if (url.includes('api.imgbb.com')) {
        return {
            status: 400,
            data: {
                status_code: 400,
                error: { message: 'You have been forbidden to use this website.', code: 103 },
                status_txt: 'Bad Request',
            },
        };
    }
    throw new Error('unexpected host: ' + url);
};

process.env.IMGBB_API_KEY = 'dummy-key';
process.env.PUBLIC_BASE_URL = 'https://api.example.com';

const { uploadImageResilient, getStoredImage } = require('../services/imageUpload');

// ── in-memory fake Mongo ──
const store = new Map();
const fakeDb = {
    collection: () => ({
        insertOne: async (doc) => {
            store.set(doc._id, doc);
            return { insertedId: doc._id };
        },
        findOne: async (q) => store.get(q._id) || null,
    }),
};

const logs = [];
const logger = { warn: (m, d) => logs.push([m, d]), error: () => {}, info: () => {} };

// 1x1 PNG
const png = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
    'base64'
);

(async () => {
    const out = await uploadImageResilient({
        db: fakeDb,
        req: { headers: { host: 'api.example.com' } },
        buffer: png,
        format: 'png',
        filename: 'driver.png',
        uploadedBy: 'test@lbts.app',
        logger,
    });

    console.log('result:', out);

    assert.strictEqual(out.provider, 'self-hosted', 'should fall back to self-host');
    assert.match(out.url, /^https:\/\/api\.example\.com\/images\/[a-f0-9]{32}\.png$/, 'url shape');
    assert.ok(
        out.attempts.some((a) => /code 103/.test(a.reason)),
        'imgbb block should be recorded as the reason'
    );
    assert.ok(
        /Mozilla\/5\.0/.test(capturedHeaders?.['User-Agent'] || ''),
        'browser User-Agent must be sent to imgbb'
    );

    // serve path
    const id = out.url.split('/').pop();
    const served = await getStoredImage(fakeDb, id);
    assert.ok(served && served.buffer.equals(png), 'served bytes must match uploaded bytes');
    assert.strictEqual(served.contentType, 'image/png');

    // bad id must not blow up
    assert.strictEqual(await getStoredImage(fakeDb, 'not-a-real-id'), null);
    assert.strictEqual(await getStoredImage(fakeDb, '../../etc/passwd'), null);

    console.log('\n✅ all assertions passed');
})().catch((e) => {
    console.error('❌', e);
    process.exit(1);
});