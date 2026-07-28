/* ══════════════════════════════════════════════════════════════════
   FIX #56 — Resilient image upload (Vendor / Driver / Vehicle photo)
   ──────────────────────────────────────────────────────────────────
   সমস্যা কী ছিল:
     imgbb API আমাদের server-এর request-এ 400 + code 103 ফেরত দিচ্ছিল —
       {"status_code":400,
        "error":{"message":"You have been forbidden to use this website.",
                 "code":103}}
     এটা invalid API key নয়। imgbb-র bot/abuse filter Render/Vercel-এর
     মতো datacenter IP + `axios/1.x` User-Agent দেখে request টা bot ধরে
     block করে দেয়। তাই key ঠিক থাকলেও কোনো ছবি upload হচ্ছিল না,
     আর user শুধু "Upload Failed — Image hosting service error:
     You have been forbidden to use this website." দেখত।

   এই service যা করে (উপর থেকে নিচে, আগেরটা fail করলে পরেরটা):
     1) imgbb — কিন্তু browser-এর মতো header (real User-Agent,
        Accept, Origin, Referer) সহ, এবং body হিসেবে
        x-www-form-urlencoded base64 (browser নিজে যেভাবে পাঠায়)।
        এতেই সাধারণত 103 block কেটে যায়। প্রথম attempt fail হলে
        multipart/form-data দিয়ে আরেকবার চেষ্টা করে।
     2) Cloudinary unsigned upload — শুধু CLOUDINARY_CLOUD_NAME +
        CLOUDINARY_UPLOAD_PRESET env দিলে active হয় (secret লাগে না)।
     3) Self-host — ছবি সোজা আমাদের নিজের MongoDB (`images`
        collection)-এ রেখে `/images/<id>.jpg` public URL ফেরত দেয়।
        এটা কোনো third-party-র উপর নির্ভর করে না, তাই imgbb পুরো
        বন্ধ থাকলেও upload কখনো fail করবে না।
        ⚠ Render free tier ~15 মিনিট idle থাকলে service ঘুমিয়ে পড়ে;
        তখন self-hosted ছবি load হতে cold start-এর ৩০-৫০s লাগতে পারে।
        তাই Render-এ থাকলে Cloudinary (ধাপ ২) সেট করে নেওয়াই ভালো —
        ওটা CDN, আমাদের server জেগে থাকা লাগে না। Self-host তখন
        safety net হিসেবেই থাকে।

   সব provider fail করলে যে Error throw হয় তাতে `publicMessage`
   (user-কে দেখানোর মতো) আর `attempts` (log-এর জন্য প্রতিটা
   provider-এর আসল কারণ) দুটোই থাকে।
══════════════════════════════════════════════════════════════════ */

const axios = require('axios');
const FormData = require('form-data');
const crypto = require('crypto');
const { Binary } = require('mongodb');

const IMAGES_COLLECTION = 'images';

/** ছবির magic-byte format (isRealImage-এর return) → extension / mime */
const EXT_BY_FORMAT = { jpeg: 'jpg', png: 'png', webp: 'webp' };
const MIME_BY_FORMAT = { jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp' };

/* imgbb-র bot filter এড়াতে আসল browser-এর মতো header।
   এটা "spoofing" না — আমরা user-এর হয়েই ছবি পাঠাচ্ছি, শুধু
   default `axios/1.x` UA-টাই block-এর কারণ ছিল। */
const BROWSER_HEADERS = {
    'User-Agent':
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
        '(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    Accept: 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cache-Control': 'no-cache',
    Origin: 'https://imgbb.com',
    Referer: 'https://imgbb.com/',
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** imgbb-র "তোমাকে block করেছি" ধরনের উত্তর কি না */
function isBotBlock(data) {
    const msg = data?.error?.message || '';
    const code = data?.error?.code;
    return code === 103 || /forbidden to use this website/i.test(msg);
}

/** imgbb-র "key ভুল/expired" ধরনের উত্তর কি না */
function isKeyProblem(data) {
    const msg = data?.error?.message || '';
    const code = data?.error?.code;
    return code === 100 || /invalid api|api key|api v1 key/i.test(msg);
}

/* ── Provider 1: imgbb ───────────────────────────────────────────── */

async function imgbbRequest({ key, buffer, filename, mode }) {
    const url = `https://api.imgbb.com/1/upload?key=${encodeURIComponent(key)}`;
    const base64 = buffer.toString('base64');

    if (mode === 'multipart') {
        const fd = new FormData();
        fd.append('image', base64);
        if (filename) fd.append('name', filename);
        return axios.post(url, fd, {
            headers: { ...BROWSER_HEADERS, ...fd.getHeaders() },
            timeout: 25000,
            maxBodyLength: Infinity,
            maxContentLength: Infinity,
            // status নিজে দেখব — throw করালে error body হারিয়ে যায়
            validateStatus: () => true,
        });
    }

    const body = new URLSearchParams();
    body.append('image', base64);
    if (filename) body.append('name', filename);
    return axios.post(url, body.toString(), {
        headers: {
            ...BROWSER_HEADERS,
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        timeout: 25000,
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
        validateStatus: () => true,
    });
}

async function uploadToImgbb({ buffer, filename, logger }) {
    const key = process.env.IMGBB_API_KEY;
    if (!key) return { ok: false, skipped: true, reason: 'IMGBB_API_KEY not set' };

    // urlencoded আগে (browser এভাবেই পাঠায়), fail করলে multipart
    const modes = ['urlencoded', 'multipart'];
    let lastReason = 'unknown error';

    for (let i = 0; i < modes.length; i++) {
        const mode = modes[i];
        try {
            const res = await imgbbRequest({ key, buffer, filename, mode });
            const status = res?.status;
            const data = res?.data;
            const hosted = data?.data?.url || data?.data?.display_url;

            if (status >= 200 && status < 300 && typeof hosted === 'string' && hosted) {
                return { ok: true, url: hosted, provider: `imgbb(${mode})` };
            }

            if (isKeyProblem(data)) {
                // key ভুল হলে mode বদলে লাভ নেই
                return {
                    ok: false,
                    fatal: true,
                    reason: 'IMGBB_API_KEY invalid or expired',
                };
            }
            if (isBotBlock(data)) {
                lastReason = 'imgbb bot-filter block (code 103) — server IP/User-Agent blocked';
                // multipart দিয়ে একবার চেষ্টা করা যায়, তারপর পরের provider
                if (i === modes.length - 1) return { ok: false, reason: lastReason };
                await sleep(300);
                continue;
            }

            lastReason =
                data?.error?.message ||
                `imgbb returned HTTP ${status} without a usable URL`;
        } catch (err) {
            // validateStatus থাকায় সাধারণত এখানে আসবে না, তবু network
            // error বা axios version পার্থক্যের জন্য body-টা দেখে নিই
            const data = err?.response?.data;
            if (isKeyProblem(data)) {
                return { ok: false, fatal: true, reason: 'IMGBB_API_KEY invalid or expired' };
            }
            if (isBotBlock(data)) {
                lastReason = 'imgbb bot-filter block (code 103) — server IP/User-Agent blocked';
            } else {
                lastReason =
                    err?.code === 'ECONNABORTED'
                        ? 'imgbb request timed out'
                        : data?.error?.message || err?.message || 'imgbb request failed';
            }
        }

        if (i < modes.length - 1) await sleep(400);
    }

    logger?.warn?.('imgbb upload failed', { reason: lastReason });
    return { ok: false, reason: lastReason };
}

/* ── Provider 2: Cloudinary (unsigned preset — secret লাগে না) ───── */

async function uploadToCloudinary({ buffer, format, filename }) {
    const cloud = process.env.CLOUDINARY_CLOUD_NAME;
    const preset = process.env.CLOUDINARY_UPLOAD_PRESET;
    if (!cloud || !preset) {
        return {
            ok: false,
            skipped: true,
            reason: 'CLOUDINARY_CLOUD_NAME / CLOUDINARY_UPLOAD_PRESET not set',
        };
    }

    const mime = MIME_BY_FORMAT[format] || 'image/jpeg';
    const dataUri = `data:${mime};base64,${buffer.toString('base64')}`;
    const body = new URLSearchParams();
    body.append('file', dataUri);
    body.append('upload_preset', preset);
    if (filename) body.append('public_id', filename.replace(/\.[^.]+$/, ''));

    try {
        const res = await axios.post(
            `https://api.cloudinary.com/v1_1/${encodeURIComponent(cloud)}/image/upload`,
            body.toString(),
            {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                timeout: 25000,
                maxBodyLength: Infinity,
                validateStatus: () => true,
            }
        );
        const url = res?.data?.secure_url || res?.data?.url;
        if (res.status >= 200 && res.status < 300 && typeof url === 'string' && url) {
            return { ok: true, url, provider: 'cloudinary' };
        }
        return {
            ok: false,
            reason:
                res?.data?.error?.message ||
                `cloudinary returned HTTP ${res?.status}`,
        };
    } catch (err) {
        return { ok: false, reason: err?.message || 'cloudinary request failed' };
    }
}

/* ── Provider 3: Self-host (নিজের MongoDB) ───────────────────────── */

/**
 * Request থেকে public base URL বের করে।
 * PUBLIC_BASE_URL env থাকলে সেটাই ব্যবহার করে (recommended — domain
 * বদলালেও পুরনো link ভাঙে না)। নাহলে proxy header থেকে বানায়।
 */
function resolveBaseUrl(req) {
    const fromEnv = process.env.PUBLIC_BASE_URL || process.env.SERVER_URL;
    if (fromEnv) return String(fromEnv).replace(/\/+$/, '');
    const proto =
        (req?.headers?.['x-forwarded-proto'] || '').split(',')[0].trim() ||
        req?.protocol ||
        'https';
    const host =
        (req?.headers?.['x-forwarded-host'] || '').split(',')[0].trim() ||
        req?.headers?.host ||
        '';
    return host ? `${proto}://${host}` : '';
}

async function uploadSelfHosted({ db, req, buffer, format, filename, uploadedBy }) {
    if (process.env.IMAGE_SELF_HOST === 'off') {
        return { ok: false, skipped: true, reason: 'self-host disabled (IMAGE_SELF_HOST=off)' };
    }
    if (!db) return { ok: false, skipped: true, reason: 'no DB handle for self-host' };

    const base = resolveBaseUrl(req);
    if (!base) return { ok: false, reason: 'could not resolve public base URL for self-host' };

    const ext = EXT_BY_FORMAT[format] || 'jpg';
    try {
        // ObjectId predictable (timestamp + counter) — public URL-এ সেটা
        // দিলে অন্যের ছবি guess করা সম্ভব। তাই 128-bit random id।
        const doc = {
            _id: crypto.randomBytes(16).toString('hex'),
            data: new Binary(buffer),
            contentType: MIME_BY_FORMAT[format] || 'image/jpeg',
            ext,
            size: buffer.length,
            originalName: filename || null,
            uploadedBy: uploadedBy || null,
            createdAt: new Date(),
        };
        const result = await db.collection(IMAGES_COLLECTION).insertOne(doc);
        const id = result.insertedId;
        if (!id) return { ok: false, reason: 'self-host insert returned no id' };
        return { ok: true, url: `${base}/images/${id}.${ext}`, provider: 'self-hosted' };
    } catch (err) {
        return { ok: false, reason: err?.message || 'self-host save failed' };
    }
}

/** `/images/:id` route-এর জন্য — ছবির doc ফেরত দেয় (না পেলে null) */
async function getStoredImage(db, rawId) {
    // `abc123.jpg` → `abc123`; শুধু hex id-ই বৈধ (injection-proof)
    const id = String(rawId || '').replace(/\.[a-z0-9]+$/i, '');
    if (!/^[a-f0-9]{32}$/.test(id)) return null;
    const doc = await db.collection(IMAGES_COLLECTION).findOne({ _id: id });
    if (!doc) return null;
    const buf = doc.data?.buffer
        ? Buffer.from(doc.data.buffer)
        : Buffer.isBuffer(doc.data)
            ? doc.data
            : null;
    if (!buf) return null;
    return { buffer: buf, contentType: doc.contentType || 'image/jpeg' };
}

/* ── Orchestrator ────────────────────────────────────────────────── */

/**
 * Provider chain ধরে ছবি upload করে।
 * সফল: { url, provider, attempts }
 * ব্যর্থ: throw Error (err.publicMessage + err.attempts সহ)
 */
async function uploadImageResilient({ db, req, buffer, format, filename, uploadedBy, logger }) {
    const attempts = [];

    const providers = [
        () => uploadToImgbb({ buffer, filename, logger }),
        () => uploadToCloudinary({ buffer, format, filename }),
        () => uploadSelfHosted({ db, req, buffer, format, filename, uploadedBy }),
    ];

    for (const run of providers) {
        let outcome;
        try {
            outcome = await run();
        } catch (err) {
            outcome = { ok: false, reason: err?.message || 'provider threw' };
        }

        if (outcome?.ok && outcome.url) {
            if (attempts.length) {
                // আগের provider fail করেছিল — কোনটা কেন, log-এ থাকা দরকার
                logger?.warn?.('Image upload fell back to another provider', {
                    used: outcome.provider,
                    failed: attempts,
                });
            }
            return { url: outcome.url, provider: outcome.provider, attempts };
        }

        // fatal মানে শুধু "এই provider-কে আর retry করে লাভ নেই"
        // (যেমন invalid key) — chain কিন্তু থামে না, পরের provider চলবে,
        // তাই imgbb পুরো অচল থাকলেও ছবি self-host-এ save হয়ে যাবে।
        attempts.push({
            provider: outcome?.provider || undefined,
            reason: outcome?.reason || 'unknown',
            skipped: !!outcome?.skipped,
            fatal: !!outcome?.fatal,
        });
    }

    const err = new Error('All image providers failed');
    err.attempts = attempts;
    const keyIssue = attempts.some((a) => /IMGBB_API_KEY invalid/i.test(a.reason || ''));
    err.publicMessage = keyIssue
        ? 'Image hosting API key is invalid or expired — contact admin to update IMGBB_API_KEY'
        : 'Could not save the image right now. Please try again in a moment.';
    throw err;
}

/** Admin diagnostics — কোন provider configured আছে */
function describeProviders() {
    return {
        imgbb: !!process.env.IMGBB_API_KEY,
        cloudinary: !!(process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_UPLOAD_PRESET),
        selfHosted: process.env.IMAGE_SELF_HOST !== 'off',
        publicBaseUrl: process.env.PUBLIC_BASE_URL || process.env.SERVER_URL || '(derived from request)',
    };
}

module.exports = {
    IMAGES_COLLECTION,
    uploadImageResilient,
    getStoredImage,
    describeProviders,
    resolveBaseUrl,
    EXT_BY_FORMAT,
    MIME_BY_FORMAT,
};