// ═══════════════════════════════════════════════════════════════════
//  LBTS-OS — MongoDB-backed Rate Limiter (FIX #51)
// ═══════════════════════════════════════════════════════════════════
//
//  সমস্যা: express-rate-limit in-memory store ব্যবহার করে। Vercel
//  serverless-এ প্রতিটা function instance-এর নিজস্ব memory — instance
//  বদলালে/cold-start হলে counter শূন্য হয়ে যায়, ফলে limit আসলে কাজ
//  করে না (attacker সহজেই bypass করতে পারে)।
//
//  সমাধান: fixed-window counter MongoDB-তে রাখা। সব instance একই
//  counter দেখে। `rate_limits` collection-এ TTL index থাকায় পুরনো
//  window-এর ডকুমেন্ট নিজে নিজে মুছে যায়।
//
//  ডিজাইন নোট:
//  - Fail-open: limiter নিজে fail করলে (DB hiccup) request আটকায় না —
//    availability > perfect limiting। In-memory limiter first line
//    হিসেবে আগেই বসানো থাকে।
//  - শুধু sensitive endpoint-এ ব্যবহার করুন (/jwt, /register, /upload,
//    /parse-address) — প্রতি request-এ একটা অতিরিক্ত DB write হয়,
//    তাই global limiter হিসেবে ব্যবহার করবেন না।
// ═══════════════════════════════════════════════════════════════════

/**
 * @param {Object}   opts
 * @param {Function} opts.getDb     async () => db  (index.js এর connectDB)
 * @param {Object}   opts.logger    logger with warn/error
 * @param {string}   opts.name      limiter name, e.g. 'auth'
 * @param {number}   opts.windowMs  window length in ms
 * @param {number}   opts.max       max requests per window per IP
 * @param {string}   opts.message   429 response message
 */
function createMongoRateLimit({ getDb, logger, name, windowMs, max, message }) {
    let indexEnsured = false;

    return async function mongoRateLimit(req, res, next) {
        try {
            const db = await getDb();
            const col = db.collection('rate_limits');

            // Index তৈরি idempotent — প্রথম call-এ একবার fire-and-forget
            if (!indexEnsured) {
                indexEnsured = true;
                col.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }).catch(() => { });
                col.createIndex({ key: 1 }, { unique: true }).catch(() => { });
            }

            const ip =
                (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
                req.socket?.remoteAddress ||
                'unknown';

            const windowStart = Math.floor(Date.now() / windowMs);
            const key = `${name}:${ip}:${windowStart}`;

            const doc = await col.findOneAndUpdate(
                { key },
                {
                    $inc: { count: 1 },
                    // TTL: window শেষ হওয়ার ১ মিনিট পরে ডকুমেন্ট মুছে যাবে
                    $setOnInsert: { expiresAt: new Date((windowStart + 1) * windowMs + 60 * 1000) },
                },
                { upsert: true, returnDocument: 'after' }
            );

            const count = doc?.count ?? doc?.value?.count ?? 1;
            if (count > max) {
                return res.status(429).send({ success: false, message });
            }
            return next();
        } catch (err) {
            // Fail-open — limiter ভাঙলে service ভাঙবে না
            logger?.warn?.('Mongo rate limiter failed (failing open)', {
                name, error: err?.message,
            });
            return next();
        }
    };
}

module.exports = { createMongoRateLimit };