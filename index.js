const dns = require("dns");
dns.setServers(["8.8.8.8", "8.8.4.4"]);

require("dotenv").config();

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

// ── Firebase Admin SDK (for secure ID token verification) ──
const { initFirebaseAdmin, verifyFirebaseIdToken } = require('./config/firebaseAdmin');
initFirebaseAdmin();

// ── Gemini AI Address Parser ──
const { parseAddressHybrid } = require('./services/hybridAddressParser');

const app = express();
const port = process.env.PORT || 3000;

const multer = require('multer');
const FormData = require('form-data');
const axios = require('axios');
const helmet = require('helmet');

// ═══════════════════════════════════════════════════════════════════
// FIX #49 — Pure helpers extracted to utils/helpers.js (testable, de-monolith step 1)
// FIX #50 — Server-side authoritative rate resolver (services/rateResolver.js)
// FIX #51 — Mongo-backed serverless-safe rate limiter (utils/mongoRateLimit.js)
// ═══════════════════════════════════════════════════════════════════
const {
    escapeRegex,
    isRealImage,
    getDhakaCurrentMonthYear,
    getDhakaMonthRange,
} = require('./utils/helpers');
const { resolveAuthoritativeRate } = require('./services/rateResolver');
const { createMongoRateLimit } = require('./utils/mongoRateLimit');
// FIX #55 — Client থেকে নতুন product/model যোগ করার feature।
// rate_entries collection-এ custom row রাখে, baseline rateTable.js এর
// উপরে overlay হয়। বিস্তারিত: services/customRateStore.js
const {
    COLLECTION: RATE_ENTRIES_COLLECTION,
    LOCATION_KEYS: RATE_LOCATION_KEYS,
    ensureCustomRates,
    loadCustomRates,
    invalidateCustomRates,
    getRateTablePayload,
    getBaselineTables,
} = require('./services/customRateStore');

const multerUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = ['image/jpeg', 'image/png', 'image/webp'];
        if (allowed.includes(file.mimetype)) {
            cb(null, true);
        } else {
            // Code দিলে global error handler এটাকে 400 + পরিষ্কার message
            // হিসেবে পাঠাতে পারে — আগে generic 500 "Internal Server Error"
            // যেত (phone-এর HEIC ছবিই সবচেয়ে common case)।
            const err = new Error('Only JPEG, PNG, WEBP allowed');
            err.code = 'INVALID_FILE_TYPE';
            cb(err);
        }
    }
});

// FIX #30 — Magic-byte image validation → moved to utils/helpers.js (isRealImage)

const { body, param, query, validationResult } = require('express-validator');

const validate = (validations) => async (req, res, next) => {
    await Promise.all(validations.map(v => v.run(req)));
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).send({
            success: false,
            message: 'Validation failed',
            errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
        });
    }
    next();
};

// ── Simple Logger ──────────────────────────────────────────────────
const logger = {
    info: (msg, data = {}) => console.log(JSON.stringify({
        level: "info", msg, ...data, time: new Date().toISOString()
    })),
    error: (msg, err = {}) => console.error(JSON.stringify({
        level: "error", msg,
        error: err?.message || String(err),
        stack: err?.stack,
        time: new Date().toISOString()
    })),
    warn: (msg, data = {}) => console.warn(JSON.stringify({
        level: "warn", msg, ...data, time: new Date().toISOString()
    })),
};

// ═══════════════════════════════════════════════════════════════════
// FIX #48 — Audit Log Helper (used for all delete/sensitive-edit operations)
// ═══════════════════════════════════════════════════════════════════
// Records who did what, when, and why. 365-day TTL index in setupIndexes.
// Returns inserted doc id or null if logging failed (never throws — audit
// failure must not block the primary operation).
async function recordAudit({ db, action, collectionName, documentId, oldDoc, newDoc, reason, req }) {
    try {
        const auditCol = db.collection('audit_logs');
        const entry = {
            action,                    // e.g., 'DELETE_CHALLAN', 'EDIT_DELIVERY', 'BULK_DELETE_GATEPASS'
            collectionName,
            documentId,
            ...(oldDoc ? { deletedDocument: oldDoc } : {}),
            ...(newDoc ? { updatedDocument: newDoc } : {}),
            reason: reason || '',
            performedBy: {
                email: req?.user?.email || 'unknown',
                role: req?.user?.role || 'unknown',
            },
            performedAt: new Date(),
            ipAddress: req?.headers?.['x-forwarded-for'] || req?.socket?.remoteAddress || 'unknown',
        };
        const result = await auditCol.insertOne(entry);
        return result.insertedId;
    } catch (err) {
        logger.error('Audit log insert failed', err);
        return null;
    }
}
// ═══════════════════════════════════════════════════════════════════
// FIX #29 — Asia/Dhaka Timezone Helpers
// ═══════════════════════════════════════════════════════════════════
// Server runs UTC (Vercel), users work in Dhaka time (UTC+6).
// `new Date(year, month-1, 1)` creates in server TZ — wrong for queries.
// These helpers produce UTC Date objects that correspond exactly to
// Dhaka month boundaries.
// Helpers moved to utils/helpers.js (getDhakaCurrentMonthYear, getDhakaMonthRange)

// ── Rate Limiters ──────────────────────────────────────────────────
// FIX #20 — Three-tier rate limiting:
//   1. Global: 1000 req / 15 min / IP (generous but blocks DDoS)
//   2. Auth: 20 req / 15 min / IP (protects /jwt login attempts)
//   3. Upload: 30 req / 15 min / IP (protects /upload-image from abuse)
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false },
    message: { success: false, message: 'Too many requests from this IP, please try again later' }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false },
    message: { success: false, message: 'Too many login attempts, please try again after 15 minutes' }
});

const uploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false },
    message: { success: false, message: 'Too many upload requests, please slow down' }
});

// ── AI Rate Limiter ──
const aiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 15,
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false },
    message: { success: false, message: 'Too many AI requests, please wait a moment' }
});

// ═══════════════════════════════════════════════════════════════════
// FIX #51 — Serverless-safe rate limiters (MongoDB-backed)
// ═══════════════════════════════════════════════════════════════════
// express-rate-limit-এর in-memory counter Vercel-এর প্রতিটা instance-এ
// আলাদা — cold start-এ শূন্য হয়ে যায়, তাই আসল সুরক্ষা দেয় না।
// এই limiter-গুলো counter MongoDB-তে রাখে (সব instance shared)।
// In-memory limiter গুলো first-line হিসেবে থেকেই যাচ্ছে (সস্তা,
// একই instance-এ burst আটকায়)। connectDB নিচে function declaration
// হিসেবে আছে (hoisted) এবং getDb শুধু request time-এ call হয় — safe।
const mongoAuthLimiter = createMongoRateLimit({
    getDb: (...a) => connectDB(...a), logger, name: 'auth',
    windowMs: 15 * 60 * 1000, max: 20,
    message: 'Too many login attempts, please try again after 15 minutes',
});
const mongoUploadLimiter = createMongoRateLimit({
    getDb: (...a) => connectDB(...a), logger, name: 'upload',
    windowMs: 15 * 60 * 1000, max: 30,
    message: 'Too many upload requests, please slow down',
});
const mongoAiLimiter = createMongoRateLimit({
    getDb: (...a) => connectDB(...a), logger, name: 'ai',
    windowMs: 60 * 1000, max: 15,
    message: 'Too many AI requests, please wait a moment',
});

// ── CORS ───────────────────────────────────────────────────────────
const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : ['http://localhost:5173'];

// FIX #19 — Fail fast if production without proper CORS
if (process.env.NODE_ENV === 'production' && !process.env.ALLOWED_ORIGINS) {
    logger.warn('ALLOWED_ORIGINS not set in production — only localhost:5173 allowed. Set it on Vercel.');
}

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error(`CORS blocked: ${origin}`));
        }
    },
    credentials: true
}));

// ── Security Headers ───────────────────────────────────────────────
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
}));

app.use(express.json({ limit: '2mb' }));

// FIX #20 — Apply global rate limit to ALL routes (exempts health check)
app.use((req, res, next) => {
    if (req.path === '/' || req.path === '/warmup') return next(); // skip health + warmup
    return globalLimiter(req, res, next);
});

// ── Environment Validation (Fail Fast on Startup) ──────────────────
const REQUIRED_ENV = ['DB_USER', 'DB_PASS', 'JWT_SECRET'];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length > 0) {
    throw new Error(
        `Missing required environment variables: ${missingEnv.join(', ')}. ` +
        `Please set them in .env file or Vercel dashboard.`
    );
}

// ── MongoDB Connection (Serverless-Optimized) ──────────────────────
// FIX #52 — Cluster host আর hardcoded নয়; DB_HOST env দিয়ে override করা যায়
// (fallback পুরনো মান — deploy-এ কিছু ভাঙবে না)
const DB_HOST = process.env.DB_HOST || 'cluster0.fu1n5ti.mongodb.net';
const uri = `mongodb+srv://${encodeURIComponent(process.env.DB_USER)}:${encodeURIComponent(process.env.DB_PASS)}@${DB_HOST}/?retryWrites=true&w=majority&appName=LBTS-OS`;

let cachedConnection = null;
let connectionPromise = null;
let lastPingTime = 0;
const PING_CACHE_MS = 60 * 1000; // FIX: ping interval 60s — connection alive থাকলে ping skip

async function getConnection() {
    // If already connected, reuse (ping only if stale)
    if (cachedConnection) {
        const now = Date.now();
        if (now - lastPingTime < PING_CACHE_MS) {
            return cachedConnection;
        }
        try {
            await cachedConnection.client.db('admin').command({ ping: 1 });
            lastPingTime = now;
            return cachedConnection;
        } catch (err) {
            logger.warn('Cached MongoDB connection unhealthy, reconnecting', {
                error: err.message
            });
            cachedConnection.client.close().catch(() => { });
            cachedConnection = null;
            connectionPromise = null;
            lastPingTime = 0;
        }
    }

    if (connectionPromise) {
        return connectionPromise;
    }

    connectionPromise = (async () => {
        const client = new MongoClient(uri, {
            serverApi: {
                version: ServerApiVersion.v1,
                strict: false,
                deprecationErrors: true,
            },
            // ── FIX: Cold Start & Connection Warmup ──────────────────────
            // আগে: minPoolSize=0, maxIdleTimeMS=10000
            //   → Vercel function sleep হলে connection মরে যেত
            //   → পরের request-এ reconnect → 3-5s cold start
            // এখন: minPoolSize=1 → সবসময় ১টা connection জীবিত থাকে
            //       maxIdleTimeMS=60000 → 60s idle-এও connection টিকে থাকে
            //       heartbeatFrequencyMS=10000 → MongoDB server alive রাখে
            maxPoolSize: 5,           // 10-12 user, 5 concurrent যথেষ্ট
            minPoolSize: 1,           // সবসময় ১টা connection warm থাকবে
            maxIdleTimeMS: 60000,     // 60s idle-এও মরবে না (আগে 10s)
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
            connectTimeoutMS: 10000,
            waitQueueTimeoutMS: 5000,
            heartbeatFrequencyMS: 10000, // server alive রাখে, stale connection ধরে
            retryWrites: true,
            retryReads: true,
        });

        try {
            await client.connect();
            const db = client.db('LBTS-OS-DB');
            logger.info('MongoDB Connected', { poolSize: 5, minPool: 1, appName: 'LBTS-OS' });
            cachedConnection = { client, db };
            lastPingTime = Date.now();
            return cachedConnection;
        } catch (err) {
            logger.error('MongoDB Connection failed', err);
            throw err;
        }
    })();

    try {
        return await connectionPromise;
    } catch (err) {
        connectionPromise = null;
        throw err;
    }
}

async function connectDB() {
    const { db } = await getConnection();
    // FIX #55 — custom rate overrides cache warm রাখা।
    // ৬০s TTL; fresh থাকলে কোনো DB hit হয় না, stale হলে background refresh।
    // কখনো throw করে না, তাই কোনো route এতে ভাঙবে না।
    await ensureCustomRates(db);
    return db;
}

// ── Graceful shutdown ──────────────────────────────────────────────
const gracefulShutdown = async (signal) => {
    logger.info(`${signal} received, closing MongoDB connection`);
    if (cachedConnection?.client) {
        try {
            await cachedConnection.client.close();
            logger.info('MongoDB connection closed cleanly');
        } catch (err) {
            logger.error('Error closing MongoDB', err);
        }
    }
    process.exit(0);
};
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ═══════════════════════════════════════════════════════════════════
// Auth Middlewares
// ═══════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════
// FIX #53 — Fresh role/status check (stale-JWT hole বন্ধ)
// ═══════════════════════════════════════════════════════════════════
// সমস্যা: role + status JWT-এর ভেতরে বেক করা ছিল আর token ৭ দিন বৈধ
// থাকত। কাউকে block/demote করলেও সে পুরনো token দিয়ে ৭ দিন পর্যন্ত
// আগের role-এ কাজ চালাতে পারত।
//
// সমাধান: প্রতিটা authenticated request-এ DB থেকে টাটকা role/status
// পড়া হয় (৬০ সেকেন্ডের in-memory cache সহ, যাতে প্রতি request-এ DB
// hit না লাগে)। ফলে block/role-change সর্বোচ্চ ৬০ সেকেন্ডের মধ্যে
// কার্যকর হয়। DB সাময়িক down থাকলে token-এর claim-এ fallback করি
// (fail-open) — না হলে DB hiccup-এ সবাই logout হয়ে যেত।
const FRESH_USER_TTL_MS = 60 * 1000;
const freshUserCache = new Map(); // email -> { claims, at }

function bustFreshUserCache(email) {
    if (email) freshUserCache.delete(email);
}

async function getFreshUserClaims(email) {
    const hit = freshUserCache.get(email);
    if (hit && Date.now() - hit.at < FRESH_USER_TTL_MS) return hit.claims;

    const db = await connectDB();
    const doc = await db.collection('users').findOne(
        { email },
        { projection: { role: 1, status: 1, vendorName: 1 } }
    );
    // doc === null মানে user DB থেকে delete হয়ে গেছে → claims: null
    const claims = doc
        ? {
            role: doc.role || 'user',
            status: doc.status || 'pending',
            ...(doc.vendorName ? { vendorName: doc.vendorName } : {}),
        }
        : null;

    freshUserCache.set(email, { claims, at: Date.now() });
    if (freshUserCache.size > 5000) freshUserCache.clear(); // memory guard
    return claims;
}

async function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send({ success: false, message: 'Unauthorized: No token provided' });
    }

    const token = authHeader.split(' ')[1];

    let decoded;
    try {
        decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).send({ success: false, message: 'Unauthorized: Invalid or expired token' });
    }

    req.user = decoded;

    // ── FIX #53: DB থেকে টাটকা role/status overlay ──
    try {
        const fresh = await getFreshUserClaims(decoded.email);
        if (fresh === null) {
            // User deleted from DB — token আর বৈধ নয়
            return res.status(401).send({ success: false, message: 'Unauthorized: Account no longer exists' });
        }
        req.user = {
            ...decoded,
            role: fresh.role,
            status: fresh.status,
            ...(fresh.vendorName ? { vendorName: fresh.vendorName } : {}),
        };
    } catch (err) {
        // DB hiccup — token claims-এ fallback, কিন্তু log রাখি
        logger.warn('Fresh role check failed — falling back to token claims', { error: err?.message });
    }

    next();
}

// FIX #5 — Require approved status (blocks pending/rejected users)
function verifyApproved(req, res, next) {
    if (req.user?.status !== 'approved') {
        return res.status(403).send({ success: false, message: 'Forbidden: Account not approved' });
    }
    next();
}

// FIX #5 — Role-based middleware factory
function verifyRole(...allowedRoles) {
    return (req, res, next) => {
        if (req.user?.status !== 'approved') {
            return res.status(403).send({ success: false, message: 'Forbidden: Account not approved' });
        }
        if (!allowedRoles.includes(req.user?.role)) {
            return res.status(403).send({
                success: false,
                message: `Forbidden: Requires role ${allowedRoles.join(' or ')}`
            });
        }
        next();
    };
}

function verifyAdmin(req, res, next) {
    if (req.user?.role !== 'admin' || req.user?.status !== 'approved') {
        return res.status(403).send({ success: false, message: 'Forbidden: Admins only' });
    }
    next();
}

// Non-vendor approved users (for pages vendor can't access)
function verifyNonVendor(req, res, next) {
    if (req.user?.status !== 'approved') {
        return res.status(403).send({ success: false, message: 'Forbidden: Account not approved' });
    }
    if (req.user?.role === 'vendor') {
        return res.status(403).send({ success: false, message: 'Forbidden: Vendor role not allowed here' });
    }
    next();
}

// ═══════════════════════════════════════════════════════════════════
// FIX #54 — Stale claimToken auto-release
// ═══════════════════════════════════════════════════════════════════
// সমস্যা: delivery create / trip-add flow-তে challan-এ claimToken বসিয়ে
// কাজ করা হয়। Vercel function যদি claim-এর পরে কিন্তু finalize/rollback-এর
// আগে timeout/crash করে, claimToken চিরকাল লেগে থাকত — ওই challan দিয়ে
// আর কখনো delivery করা যেত না (বারবার 409 CONCURRENT_DELIVERY)।
//
// সমাধান: প্রতিবার claim করার আগে, target challan-গুলোর মধ্যে যেগুলোর
// claim ২ মিনিটের বেশি পুরনো (Vercel maxDuration 60s — তাই ২ মিনিট মানেই
// ওই request মরে গেছে), সেগুলোর claim ছেড়ে দেওয়া হয়। ফলে user আবার
// চেষ্টা করলেই আটকে থাকা challan নিজে নিজে মুক্ত হয়ে যায়।
const STALE_CLAIM_MS = 2 * 60 * 1000;

async function releaseStaleClaims(challanCollection, challanIds) {
    try {
        const cutoff = new Date(Date.now() - STALE_CLAIM_MS);
        const r = await challanCollection.updateMany(
            {
                _id: { $in: challanIds },
                claimToken: { $exists: true },
                claimedAt: { $lt: cutoff },
            },
            { $unset: { claimToken: "", claimedAt: "" } }
        );
        if (r.modifiedCount > 0) {
            logger.warn('Released stale challan claims (crashed request cleanup)', {
                count: r.modifiedCount,
            });
        }
    } catch (err) {
        // Cleanup fail করলে মূল flow আটকাবে না — পরের চেষ্টায় আবার হবে
        logger.error('Stale claim release failed', err);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Leftover split — partial delivery support
// ═══════════════════════════════════════════════════════════════════
// CreateDelivery-র edit modal বা Trip-Details-এর Edit-Challan modal থেকে
// কোনো product row remove করলে বা quantity কমালে (৫ → ২), বাদ পড়া অংশটা
// (৩ pcs) হারিয়ে না গিয়ে একটা আলাদা "leftover" challan হিসেবে challans
// collection-এ ঢোকে — status: "pending", তাই All-Challan-এ আবার next
// delivery-র জন্য available থাকে।
//
// Link fields:
//   - challan doc:  splitFromChallanId = original challan-এর _id (string)
//   - product row:  sourceProductId    = original product-এর _id
//     (bulk-trip-do propagation + merge-dedupe এই দুটো দিয়েই match করে)
//
// tripDo: original product-এ Trip Do আগেই বসানো থাকলে leftover product-ও
// সেটা inherit করে; পরে বসালে bulk-trip-do propagation ফাঁকা গুলো fill
// করে — দুই ক্ষেত্রেই All-Gate-Pass-এর pending qty হিসেব ঠিক থাকে।

/** old vs new products তুলনা করে বাদ-পড়া/কমে-যাওয়া অংশ বের করা (match by _id) */
function computeLeftoverProducts(oldProducts, newProducts) {
    const nextById = new Map(
        (newProducts || []).filter(p => p && p._id).map(p => [String(p._id), p])
    );
    const leftovers = [];
    for (const op of (oldProducts || [])) {
        const oldQty = Number(op?.quantity) || 0;
        if (oldQty <= 0 || !String(op?.productName || '').trim()) continue;
        const np = op._id ? nextById.get(String(op._id)) : null;
        const newQty = np ? (Number(np.quantity) || 0) : 0;
        const diff = oldQty - newQty;
        if (diff > 0) {
            leftovers.push({
                productName: op.productName || '',
                model: op.model || '',
                quantity: diff,
                ...(op.capacity ? { capacity: op.capacity } : {}),
                ...(op.rate !== undefined && op.rate !== null ? { rate: op.rate } : {}),
                ...(typeof op.tripDo === 'string' && op.tripDo.trim() ? { tripDo: op.tripDo.trim() } : {}),
                sourceProductId: String(op._id || ''),
            });
        }
    }
    return leftovers;
}

/**
 * Leftover challan তৈরি (বা একই source-এর আগের pending leftover-এ merge)।
 * @returns { created, merged, quantity, challanId }
 */
async function spawnLeftoverChallan(db, { sourceChallanId, sourceInfo, leftoverProducts, createdBy }) {
    const challanCollection = db.collection('challans');
    const items = (leftoverProducts || [])
        .map(p => ({ ...p, quantity: Number(p.quantity) || 0 }))
        .filter(p => p.quantity > 0 && String(p.productName || '').trim());
    if (items.length === 0) return { created: false, merged: false, quantity: 0, challanId: null };

    const norm = (s) => String(s ?? '').toLowerCase().replace(/[^a-z0-9\u0980-\u09FF]/g, '');
    const totalQty = items.reduce((s, p) => s + p.quantity, 0);
    const now = new Date();

    // একই challan থেকে বারবার কমালে আলাদা আলাদা doc না বানিয়ে
    // আগের still-pending leftover-এ qty যোগ হয় — All-Challan পরিষ্কার থাকে।
    const existing = await challanCollection.findOne({
        splitFromChallanId: String(sourceChallanId),
        status: 'pending',
        claimToken: { $exists: false }, // dispatch চলমান থাকলে নতুন doc-ই বানাই
    });
    if (existing) {
        const products = Array.isArray(existing.products) ? existing.products.map(p => ({ ...p })) : [];
        for (const p of items) {
            const idx = products.findIndex(ep =>
                (p.sourceProductId && String(ep.sourceProductId || '') === String(p.sourceProductId)) ||
                (norm(ep.productName) === norm(p.productName) && norm(ep.model) === norm(p.model))
            );
            if (idx >= 0) {
                products[idx] = {
                    ...products[idx],
                    quantity: (Number(products[idx].quantity) || 0) + p.quantity,
                    ...(p.tripDo && !String(products[idx].tripDo || '').trim() ? { tripDo: p.tripDo } : {}),
                };
            } else {
                products.push({ _id: new ObjectId().toString(), ...p });
            }
        }
        await challanCollection.updateOne(
            { _id: existing._id },
            { $set: { products, lastUpdatedAt: now, lastUpdatedBy: createdBy || 'system' } }
        );
        return { created: false, merged: true, quantity: totalQty, challanId: String(existing._id) };
    }

    const doc = {
        customerName: sourceInfo?.customerName || '',
        receiverNumber: sourceInfo?.receiverNumber || '',
        zone: sourceInfo?.zone || '',
        address: sourceInfo?.address || '',
        thana: sourceInfo?.thana || '',
        district: sourceInfo?.district || '',
        ...(sourceInfo?.location ? { location: sourceInfo.location } : {}),
        ...(sourceInfo?.remarks ? { remarks: sourceInfo.remarks } : {}),
        ...(sourceInfo?.csd ? { csd: sourceInfo.csd } : {}),
        ...(sourceInfo?.unit ? { unit: sourceInfo.unit } : {}),
        products: items.map(p => ({ _id: new ObjectId().toString(), ...p })),
        status: 'pending',
        splitFromChallanId: String(sourceChallanId),
        splitAt: now,
        createdAt: now,
        createdBy: createdBy || 'system',
    };
    const r = await challanCollection.insertOne(doc);
    return { created: true, merged: false, quantity: totalQty, challanId: String(r.insertedId) };
}

// ── ObjectId Validation Helper ─────────────────────────────────────
function isValidObjectId(id) {
    return ObjectId.isValid(id) && String(new ObjectId(id)) === id;
}

function validateObjectId(paramName = 'id') {
    return (req, res, next) => {
        const id = req.params[paramName];
        if (!isValidObjectId(id)) {
            return res.status(400).send({
                success: false,
                message: `Invalid ID format: ${paramName}`
            });
        }
        next();
    };
}

// ── Health Check ───────────────────────────────────────────────────
app.get('/', (req, res) => {
    res.send('LBTS-OS Server is running ✅');
});

// ── Warmup endpoint ────────────────────────────────────────────────
// FIX: Vercel serverless cold start এড়াতে client থেকে প্রতি 4 মিনিটে
// এই endpoint ping করলে function warm থাকবে + MongoDB connection জীবিত থাকবে
// Client-এ: setInterval(() => fetch(`${API_URL}/warmup`), 4 * 60 * 1000)
// (শুধু user logged-in থাকলে চলবে — AuthProvider-এ রাখো)
app.get('/warmup', async (req, res) => {
    try {
        const start = Date.now();
        await connectDB(); // connection alive আছে কিনা confirm করো
        res.send({
            ok: true,
            message: 'warm',
            dbLatencyMs: Date.now() - start,
            ts: new Date().toISOString(),
        });
    } catch (err) {
        logger.error('Warmup failed', err);
        res.status(503).send({ ok: false, message: 'db unavailable' });
    }
});

// ── Image Upload ───────────────────────────────────────────────────
app.post('/upload-image', uploadLimiter, mongoUploadLimiter, multerUpload.single('image'), async (req, res) => {
    try {
        // Firebase ID token অথবা App JWT — দুটোই accept করো
        const authHeader = req.headers.authorization;
        if (!authHeader?.startsWith('Bearer ')) {
            return res.status(401).send({ success: false, message: 'Unauthorized' });
        }
        const token = authHeader.split(' ')[1];

        // আগে App JWT try করো, fail হলে Firebase ID token try করো
        let userEmail = null;
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            userEmail = decoded.email;
        } catch {
            const verification = await verifyFirebaseIdToken(token);
            if (!verification.valid) {
                return res.status(401).send({ success: false, message: 'Invalid token' });
            }
            userEmail = verification.email;
        }
        req.user = { email: userEmail };

        if (!req.file) {
            return res.status(400).send({ success: false, message: 'No image provided' });
        }

        const realFormat = isRealImage(req.file.buffer);
        if (!realFormat) {
            logger.warn('Fake image upload blocked', {
                user: req.user?.email,
                claimed: req.file.mimetype,
                size: req.file.size,
            });
            return res.status(400).send({
                success: false,
                message: 'File is not a valid JPEG, PNG, or WEBP image'
            });
        }

        if (!process.env.IMGBB_API_KEY) {
            logger.error('IMGBB_API_KEY missing');
            return res.status(500).send({ success: false, message: 'Image service not configured' });
        }

        const formData = new FormData();
        formData.append('image', req.file.buffer.toString('base64'));

        const response = await axios.post(
            `https://api.imgbb.com/1/upload?key=${process.env.IMGBB_API_KEY}`,
            formData,
            { headers: formData.getHeaders(), timeout: 20000 }
        );

        const url = response?.data?.data?.url;
        if (!url || typeof url !== 'string') {
            logger.error('ImgBB response invalid', { responseData: response?.data });
            return res.status(502).send({ success: false, message: 'Image service returned invalid response' });
        }

        res.send({ success: true, url });
    } catch (err) {
        /* imgbb-side failure আলাদা করে চেনা — আগে সব ক্ষেত্রেই
           generic "Image upload failed" (500) যেত, log-এও বোঝা যেত না
           imgbb key invalid নাকি timeout নাকি অন্য কিছু। */
        const imgbbStatus = err?.response?.status;
        const imgbbData = err?.response?.data;
        logger.error('Image upload failed', {
            message: err?.message,
            code: err?.code,
            imgbbStatus,
            imgbbError: imgbbData?.error || imgbbData,
            user: req.user?.email,
        });
        if (err?.code === 'ECONNABORTED') {
            return res.status(504).send({ success: false, message: 'Image hosting service timed out — please try again' });
        }
        if (imgbbStatus) {
            // imgbb নিজে error দিয়েছে (invalid/expired API key হলে 400 আসে)
            const detail = imgbbData?.error?.message || '';
            const keyIssue = /key/i.test(detail);
            return res.status(502).send({
                success: false,
                message: keyIssue
                    ? 'Image hosting API key is invalid or expired — contact admin to update IMGBB_API_KEY'
                    : `Image hosting service error${detail ? `: ${detail}` : ''}`,
            });
        }
        res.status(500).send({ success: false, message: 'Image upload failed' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// /jwt — Issue Application JWT after Firebase ID Token Verification
// ═══════════════════════════════════════════════════════════════════
// ── FIX #50c / #55 — Rate table read endpoint ──────────────────────
// baseline table (constants/rateTable.js) + rate_entries collection-এর
// custom row — দুটো merge করে পাঠায়। Client boot-এ একবার এটা fetch করে
// নিজের rateMatcher-এ overlay করে, ফলে নতুন যোগ করা product/model
// সাথে সাথেই challan/delivery সব জায়গায় কাজ করে।
app.get('/rate-table', verifyToken, verifyApproved, async (req, res) => {
    try {
        const db = await connectDB();
        await loadCustomRates(db);            // সবসময় টাটকা copy পাঠাই
        res.send({ success: true, ...getRateTablePayload() });
    } catch (err) {
        logger.error('Rate table fetch failed', err);
        // Baseline অন্তত পাঠাই — client তখন শুধু নিজের static copy ব্যবহার করবে
        const base = getBaselineTables();
        res.status(200).send({
            success: true,
            degraded: true,
            custom: { withModel: [], withoutModel: [] },
            withModel: base.withModel,
            withoutModel: base.withoutModel,
        });
    }
});

// ═══════════════════════════════════════════════════════════════════
// FIX #55 — Product / Model Rate Entries (client থেকে নতুন product add)
// ═══════════════════════════════════════════════════════════════════
// আগে নতুন unique product model যোগ করতে withModelData.js +
// withoutModelData.js + constants/rateTable.js হাতে edit করে redeploy
// করতে হতো। এখন admin/manager UI থেকেই row যোগ/edit/delete করতে পারে।
//
// Doc shape:
//   {
//     type:     'with-model' | 'without-model',
//     product:  'Refrigerator',
//     model:    '7A1'          // with-model হলে required, নাহলে ''
//     capacity: 'Gross 50-150 Litre' | ''   // without-model এ optional
//     rates:    { 'ISD': 650, 'OSD-Metro': 950, 'OSD-Thana': 1150 },
//     active:   true,
//     note:     '',
//     createdBy, createdAt, updatedBy, updatedAt
//   }
//
// ⚠ Rate সরাসরি bill-এর হিসাবে যায়, তাই সব write audit log-এ ওঠে।

const RATE_ENTRY_TYPES = ['with-model', 'without-model'];

/** body → validated doc fields (throw করে message নিয়ে) */
function parseRateEntryBody(body) {
    const type = String(body?.type || '').trim();
    if (!RATE_ENTRY_TYPES.includes(type)) {
        throw new Error("type must be 'with-model' or 'without-model'");
    }

    const product = String(body?.product || '').trim();
    if (product.length < 2) throw new Error('Product name must be at least 2 characters');
    if (product.length > 80) throw new Error('Product name is too long (max 80)');

    let model = String(body?.model || '').trim();
    if (type === 'with-model') {
        // Model string substring-match এ ব্যবহার হয় — ১ অক্ষরের model
        // প্রায় সব model string-এ মিলে যাবে, তাই ২ অক্ষর minimum।
        if (model.length < 2) throw new Error('Model must be at least 2 characters (substring match হয়)');
        if (model.length > 60) throw new Error('Model is too long (max 60)');
    } else {
        model = '';
    }

    const capacity = String(body?.capacity || '').trim();
    if (capacity.length > 80) throw new Error('Capacity is too long (max 80)');

    const rawRates = body?.rates || {};
    const rates = {};
    for (const key of RATE_LOCATION_KEYS) {
        const n = Number(rawRates[key]);
        if (!Number.isFinite(n) || n < 0 || n > 1000000) {
            throw new Error(`Invalid rate for ${key} (0 – 1,000,000 এর মধ্যে হতে হবে)`);
        }
        rates[key] = Math.round(n);
    }

    const note = String(body?.note || '').trim().slice(0, 300);
    const active = body?.active === undefined ? true : !!body.active;

    return { type, product, model, capacity, rates, note, active };
}

/** একই product + model + capacity আগে থেকেই আছে কি না */
async function findDuplicateRateEntry(col, { type, product, model, capacity }, excludeId) {
    const ci = (s) => new RegExp(`^${escapeRegex(s)}$`, 'i');
    const query = {
        type,
        product: ci(product),
        model: model ? ci(model) : { $in: ['', null] },
        capacity: capacity ? ci(capacity) : { $in: ['', null] },
    };
    if (excludeId) query._id = { $ne: new ObjectId(excludeId) };
    return col.findOne(query);
}

// ── LIST ───────────────────────────────────────────────────────────
// Custom entries (default) — includeBaseline=1 দিলে built-in table-ও আসে
app.get('/rate-entries', verifyToken, verifyRole('admin', 'manager', 'ceo'), async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection(RATE_ENTRIES_COLLECTION);

        const filter = {};
        if (RATE_ENTRY_TYPES.includes(req.query.type)) filter.type = req.query.type;
        if (req.query.search) {
            const rx = new RegExp(escapeRegex(String(req.query.search).trim()), 'i');
            filter.$or = [{ product: rx }, { model: rx }, { capacity: rx }];
        }

        const data = await col.find(filter).sort({ createdAt: -1 }).toArray();

        const payload = { success: true, data, count: data.length };
        if (req.query.includeBaseline === '1') {
            payload.baseline = getBaselineTables();
        }
        res.send(payload);
    } catch (err) {
        logger.error('Rate entries fetch failed', err);
        res.status(500).send({ success: false, message: 'Failed to fetch rate entries' });
    }
});

// ── CREATE ─────────────────────────────────────────────────────────
app.post('/rate-entries', verifyToken, verifyRole('admin', 'manager'), async (req, res) => {
    try {
        let fields;
        try {
            fields = parseRateEntryBody(req.body);
        } catch (e) {
            return res.status(400).send({ success: false, message: e.message });
        }

        const db = await connectDB();
        const col = db.collection(RATE_ENTRIES_COLLECTION);

        const dup = await findDuplicateRateEntry(col, fields);
        if (dup) {
            return res.status(409).send({
                success: false,
                message: 'এই product + model + capacity combination আগেই যোগ করা আছে',
                existingId: String(dup._id),
            });
        }

        const doc = {
            ...fields,
            createdBy: req.user?.email || 'unknown',
            createdAt: new Date(),
            updatedBy: null,
            updatedAt: null,
        };

        const result = await col.insertOne(doc);
        invalidateCustomRates();

        await recordAudit({
            db,
            action: 'CREATE_RATE_ENTRY',
            collectionName: RATE_ENTRIES_COLLECTION,
            documentId: String(result.insertedId),
            newDoc: doc,
            reason: fields.note,
            req,
        });

        logger.info('Rate entry created', {
            by: doc.createdBy, product: doc.product, model: doc.model, type: doc.type,
        });

        res.send({ success: true, insertedId: result.insertedId, data: { ...doc, _id: result.insertedId } });
    } catch (err) {
        logger.error('Rate entry create failed', err);
        res.status(500).send({ success: false, message: 'Failed to create rate entry' });
    }
});

// ── UPDATE ─────────────────────────────────────────────────────────
app.patch('/rate-entries/:id', verifyToken, verifyRole('admin', 'manager'), validateObjectId('id'), async (req, res) => {
    try {
        let fields;
        try {
            fields = parseRateEntryBody(req.body);
        } catch (e) {
            return res.status(400).send({ success: false, message: e.message });
        }

        const db = await connectDB();
        const col = db.collection(RATE_ENTRIES_COLLECTION);
        const _id = new ObjectId(req.params.id);

        const oldDoc = await col.findOne({ _id });
        if (!oldDoc) {
            return res.status(404).send({ success: false, message: 'Rate entry not found' });
        }

        const dup = await findDuplicateRateEntry(col, fields, req.params.id);
        if (dup) {
            return res.status(409).send({
                success: false,
                message: 'অন্য একটা entry-তে একই product + model + capacity আছে',
                existingId: String(dup._id),
            });
        }

        const update = {
            ...fields,
            updatedBy: req.user?.email || 'unknown',
            updatedAt: new Date(),
        };

        await col.updateOne({ _id }, { $set: update });
        invalidateCustomRates();

        await recordAudit({
            db,
            action: 'EDIT_RATE_ENTRY',
            collectionName: RATE_ENTRIES_COLLECTION,
            documentId: req.params.id,
            oldDoc,
            newDoc: { ...oldDoc, ...update },
            reason: req.body?.reason || fields.note,
            req,
        });

        res.send({ success: true, data: { ...oldDoc, ...update } });
    } catch (err) {
        logger.error('Rate entry update failed', err);
        res.status(500).send({ success: false, message: 'Failed to update rate entry' });
    }
});

// ── DELETE ─────────────────────────────────────────────────────────
app.delete('/rate-entries/:id', verifyToken, verifyRole('admin', 'manager'), validateObjectId('id'), async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection(RATE_ENTRIES_COLLECTION);
        const _id = new ObjectId(req.params.id);

        const oldDoc = await col.findOne({ _id });
        if (!oldDoc) {
            return res.status(404).send({ success: false, message: 'Rate entry not found' });
        }

        await col.deleteOne({ _id });
        invalidateCustomRates();

        await recordAudit({
            db,
            action: 'DELETE_RATE_ENTRY',
            collectionName: RATE_ENTRIES_COLLECTION,
            documentId: req.params.id,
            oldDoc,
            reason: req.body?.reason || req.query?.reason || '',
            req,
        });

        logger.warn('Rate entry deleted', {
            by: req.user?.email, product: oldDoc.product, model: oldDoc.model,
        });

        res.send({ success: true, message: 'Rate entry deleted' });
    } catch (err) {
        logger.error('Rate entry delete failed', err);
        res.status(500).send({ success: false, message: 'Failed to delete rate entry' });
    }
});

app.post('/jwt', authLimiter, mongoAuthLimiter, async (req, res) => {
    try {
        let idToken = req.body?.idToken;
        if (!idToken) {
            const authHeader = req.headers.authorization;
            if (authHeader?.startsWith('Bearer ')) {
                idToken = authHeader.split(' ')[1];
            }
        }

        if (!idToken) {
            return res.status(400).send({
                success: false,
                message: 'Firebase ID token required',
                code: 'missing-token',
            });
        }

        const verification = await verifyFirebaseIdToken(idToken);

        if (!verification.valid) {
            logger.warn('Firebase ID token verification failed', {
                error: verification.error,
                message: verification.message,
                ip: req.headers['x-forwarded-for'] || req.socket?.remoteAddress,
            });

            const isExpired = verification.error === 'auth/id-token-expired';
            return res.status(401).send({
                success: false,
                message: isExpired
                    ? 'Session expired. Please refresh to continue.'
                    : 'Invalid session. Please log in again.',
                code: verification.error,
            });
        }

        const email = verification.email;

        if (!email) {
            return res.status(400).send({
                success: false,
                message: 'No email in Firebase session',
                code: 'no-email',
            });
        }

        // FIX #47 — Email verification enforcement
        // Users must verify their email before they can get an app JWT.
        // Exception: admins (once promoted) can bypass this check.
        const db = await connectDB();
        const userCollection = db.collection('users');
        const user = await userCollection.findOne({ email });

        // Allow login if email is verified OR user is already admin (safety net)
        const isEmailVerified = verification.emailVerified === true;
        const isAdminBypass = user?.role === 'admin' && user?.emailVerifyBypass === true;

        if (!isEmailVerified && !isAdminBypass) {
            logger.warn('Login blocked — email not verified', { email });
            return res.status(403).send({
                success: false,
                code: 'EMAIL_NOT_VERIFIED',
                message: 'Please verify your email address before logging in. Check your inbox for a verification link.',
                email,
            });
        }

        // Mark email as verified in our DB (for audit/UI use)
        if (user && !user.emailVerified && isEmailVerified) {
            await userCollection.updateOne(
                { _id: user._id },
                { $set: { emailVerified: true, emailVerifiedAt: new Date() } }
            );
        }

        const payload = {
            uid: verification.uid,
            email,
            role: user?.role || 'user',
            status: user?.status || 'pending',
            emailVerified: isEmailVerified,
            ...(user?.vendorName ? { vendorName: user.vendorName } : {}),
        };

        // FIX #53b — 7d → 1d. Client-এর useAxiosSecure 401 পেলে Firebase দিয়ে
        // নিজেই silently নতুন JWT নেয়, তাই user-এর কিছু টের পাওয়ার কথা না।
        // ছোট মেয়াদ = চুরি হওয়া token-এর ক্ষতির window-ও ছোট।
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' });

        res.send({
            success: true,
            token,
            user: {
                email,
                role: payload.role,
                status: payload.status,
                uid: payload.uid,
                emailVerified: isEmailVerified,
                ...(payload.vendorName ? { vendorName: payload.vendorName } : {}),
            },
        });
    } catch (err) {
        logger.error('JWT issuance failed', err);
        res.status(500).send({ success: false, message: 'Token generation failed' });
    }
});

// ── Quick token validity check (no DB hit) ────────────────────────
// Useful for client to check token is still valid without making a real request.
app.get('/verify-token', verifyToken, (req, res) => {
    res.send({
        success: true,
        valid: true,
        user: {
            email: req.user?.email,
            role: req.user?.role,
            status: req.user?.status,
            uid: req.user?.uid,
            ...(req.user?.vendorName ? { vendorName: req.user.vendorName } : {}),
        },
    });
});

// ═══════════════════════════════════════════════════════════════════
// Users
// ═══════════════════════════════════════════════════════════════════

// ── Registration endpoint ──────────────────────────────────────────
// Accepts a Firebase ID token (not an app JWT) so the client never needs
// to call /jwt during registration. This removes the isNewRegistration
// bypass entirely — /jwt now always requires a verified email.
//
// Security properties:
//  - Firebase ID token is cryptographically verified server-side
//  - Email comes from the verified token, never from request body
//  - Account must be < 5 minutes old (prevents abusing this endpoint
//    after a user deletes their own DB record to bypass email verification)
app.post('/register', authLimiter, mongoAuthLimiter, async (req, res) => {
    try {
        const { idToken, displayName, photoURL } = req.body;

        if (!idToken) {
            return res.status(400).send({ success: false, message: 'Firebase ID token required' });
        }
        if (!displayName || typeof displayName !== 'string' || !displayName.trim()) {
            return res.status(400).send({ success: false, message: 'displayName required' });
        }

        const verification = await verifyFirebaseIdToken(idToken);
        if (!verification.valid) {
            return res.status(401).send({ success: false, message: 'Invalid Firebase token', code: verification.error });
        }

        const { email, uid, issuedAt } = verification;
        if (!email) {
            return res.status(400).send({ success: false, message: 'No email in Firebase token' });
        }

        // Reject if the Firebase account is older than 5 minutes — this endpoint
        // is only for brand-new signups, not for bypassing email verification later.
        const accountAgeMs = Date.now() - new Date(issuedAt).getTime();
        if (accountAgeMs > 5 * 60 * 1000) {
            return res.status(403).send({
                success: false,
                code: 'NOT_NEW_ACCOUNT',
                message: 'This endpoint is only for new registrations.',
            });
        }

        const db = await connectDB();
        const userCollection = db.collection('users');
        const exists = await userCollection.findOne({ email });
        if (exists) {
            return res.send({ success: true, alreadyExists: true, message: 'User already exists' });
        }

        const newUser = {
            email,
            displayName: displayName.trim(),
            photoURL: typeof photoURL === 'string' ? photoURL : '',
            role: 'user',
            status: 'pending',
            firebaseUid: uid,
            createdAt: new Date(),
        };
        const result = await userCollection.insertOne(newUser);
        res.send({ success: true, alreadyExists: false, insertedId: result.insertedId });
    } catch (err) {
        logger.error('Registration failed', err);
        res.status(500).send({ success: false, message: 'Registration failed' });
    }
});

// FIX #16 — Require valid JWT (user must have completed /jwt flow).
// Email taken from JWT (verified server-side), NOT from request body → spoof-proof.
app.post('/users', verifyToken, async (req, res) => {
    try {
        // Email comes from verified JWT — set during /jwt after Firebase verification
        const verifiedEmail = req.user?.email;
        if (!verifiedEmail) {
            return res.status(401).send({ success: false, message: 'Unauthorized: no email in token' });
        }

        const { displayName, photoURL } = req.body;
        if (!displayName || typeof displayName !== 'string' || !displayName.trim()) {
            return res.status(400).send({ success: false, message: 'displayName required' });
        }

        const db = await connectDB();
        const userCollection = db.collection('users');
        const exists = await userCollection.findOne({ email: verifiedEmail });
        if (exists) {
            // FIX #2 — Return structured success so client knows what happened
            return res.send({
                success: true,
                alreadyExists: true,
                message: 'User already exists',
                user: { email: exists.email, role: exists.role, status: exists.status },
            });
        }

        const newUser = {
            email: verifiedEmail,
            displayName: displayName.trim(),
            photoURL: typeof photoURL === 'string' ? photoURL : '',
            role: 'user',
            status: 'pending',
            firebaseUid: req.user?.uid || null,
            createdAt: new Date(),
        };
        const result = await userCollection.insertOne(newUser);
        res.send({
            success: true,
            alreadyExists: false,
            insertedId: result.insertedId,
            user: { email: newUser.email, role: newUser.role, status: newUser.status },
        });
    } catch (err) {
        logger.error('Failed to add user', err);
        res.status(500).send({ success: false, message: 'Failed to add user' });
    }
});

app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const db = await connectDB();
        const userCollection = db.collection('users');
        const result = await userCollection.find().sort({ createdAt: -1 }).toArray();
        res.send(result);
    } catch (err) {
        logger.error('Failed to fetch users', err);
        res.status(500).send({ success: false, message: 'Failed to fetch users' });
    }
});

app.get('/users/:email/role', verifyToken, async (req, res) => {
    try {
        const db = await connectDB();
        const userCollection = db.collection('users');
        // Only allow user to fetch their own, OR admin to fetch any
        if (req.user?.email !== req.params.email && req.user?.role !== 'admin') {
            return res.status(403).send({ success: false, message: 'Forbidden' });
        }
        const user = await userCollection.findOne({ email: req.params.email });
        if (!user) return res.status(404).send({ success: false, message: 'User not found' });
        res.send({
            role: user.role,
            status: user.status,
            vendorName: user.vendorName || null,
        });
    } catch (err) {
        logger.error('Failed to fetch user role', err);
        res.status(500).send({ success: false, message: 'Failed to fetch user role' });
    }
});

app.patch('/users/role/:id', verifyToken, verifyAdmin, validateObjectId('id'), validate([
    param('id').isMongoId().withMessage('Invalid user ID'),
    body('role').isIn(['admin', 'manager', 'operator', 'user', 'ceo', 'vendor']).withMessage('Invalid role'),
    body('vendorName').optional().trim(),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const userCollection = db.collection('users');
        const { role, vendorName } = req.body;
        const setDoc = { role };
        if (role === 'vendor' && vendorName) {
            setDoc.vendorName = vendorName.trim();
        } else if (role !== 'vendor') {
            // Non-vendor role হলে vendorName clear করো
            await userCollection.updateOne(
                { _id: new ObjectId(req.params.id) },
                { $unset: { vendorName: "" } }
            );
        }
        const result = await userCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: setDoc }
        );
        // FIX #53 — role change এই instance-এ সাথে সাথে কার্যকর হোক
        const changedUser = await userCollection.findOne(
            { _id: new ObjectId(req.params.id) }, { projection: { email: 1 } }
        );
        bustFreshUserCache(changedUser?.email);
        res.send(result);
    } catch (err) {
        logger.error('Failed to update role', err);
        res.status(500).send({ success: false, message: 'Failed to update role' });
    }
});

app.patch('/users/status/:id', verifyToken, verifyAdmin, validateObjectId('id'), validate([
    param('id').isMongoId().withMessage('Invalid user ID'),
    body('status').isIn(['approved', 'pending', 'rejected']).withMessage('Invalid status'),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const userCollection = db.collection('users');
        const { status } = req.body;
        const result = await userCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { status } }
        );
        // FIX #53 — block/approve এই instance-এ সাথে সাথে কার্যকর হোক
        const changedUser = await userCollection.findOne(
            { _id: new ObjectId(req.params.id) }, { projection: { email: 1 } }
        );
        bustFreshUserCache(changedUser?.email);
        res.send(result);
    } catch (err) {
        logger.error('Failed to update status', err);
        res.status(500).send({ success: false, message: 'Failed to update status' });
    }
});

// Profile update — user updates their own displayName / photoURL in MongoDB.
// Email and role are immutable here; those go through admin routes.
app.patch('/users/profile', verifyToken, validate([
    body('displayName').optional().trim().notEmpty().withMessage('displayName cannot be empty'),
    body('photoURL').optional().isURL().withMessage('photoURL must be a valid URL'),
]), async (req, res) => {
    try {
        const email = req.user?.email;
        if (!email) return res.status(401).send({ success: false, message: 'Unauthorized' });

        const { displayName, photoURL } = req.body;
        const updates = {};
        if (displayName) updates.displayName = displayName.trim();
        if (typeof photoURL === 'string') updates.photoURL = photoURL;

        if (Object.keys(updates).length === 0) {
            return res.status(400).send({ success: false, message: 'Nothing to update' });
        }

        updates.updatedAt = new Date();

        const db = await connectDB();
        const result = await db.collection('users').updateOne({ email }, { $set: updates });
        if (result.matchedCount === 0) {
            return res.status(404).send({ success: false, message: 'User not found' });
        }

        res.send({ success: true, updated: updates });
    } catch (err) {
        logger.error('Failed to update profile', err);
        res.status(500).send({ success: false, message: 'Failed to update profile' });
    }
});

// Self-delete — used only during registration rollback when post-create steps fail.
// Allows a newly created user to remove their own DB record before Firebase account
// is also deleted. No admin required — token ownership proves identity.
app.delete('/users/self', verifyToken, async (req, res) => {
    try {
        const email = req.user?.email;
        if (!email) return res.status(401).send({ success: false, message: 'Unauthorized' });

        const db = await connectDB();
        const userCollection = db.collection('users');
        const result = await userCollection.deleteOne({ email });
        res.send({ success: true, deleted: result.deletedCount === 1 });
    } catch (err) {
        logger.error('Failed to self-delete user', err);
        res.status(500).send({ success: false, message: 'Failed to delete user' });
    }
});

app.delete('/users/:id', verifyToken, verifyAdmin, validateObjectId('id'), validate([
    param('id').isMongoId().withMessage('Invalid user ID'),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const userCollection = db.collection('users');
        const doc = await userCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).send({ success: false, message: 'User not found' });

        // FIX #48 — Audit log
        await recordAudit({
            db, req,
            action: "DELETE_USER",
            collectionName: "users",
            documentId: doc._id,
            oldDoc: doc,
            reason: req.body?.reason?.trim() || "",
        });

        const result = await userCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 1) {
            res.send({ success: true, message: 'User deleted successfully' });
        } else {
            res.status(404).send({ success: false, message: 'User not found' });
        }
    } catch (err) {
        logger.error('Failed to delete user', err);
        res.status(500).send({ success: false, message: 'Failed to delete user' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// Gate Pass — FIX #5: verifyNonVendor applied (vendor can't touch gatepass)
// ═══════════════════════════════════════════════════════════════════

app.post('/gate-pass', verifyToken, verifyRole('admin', 'manager', 'operator'), validate([
    body('tripDo').trim().notEmpty().withMessage('Trip Do required'),
    body('tripDate').isISO8601().withMessage('Valid date required'),
    body('customerName').trim().notEmpty().withMessage('Customer name required'),
    body('csd').trim().notEmpty().withMessage('CSD required'),
    body('unit').trim().notEmpty().withMessage('Unit required'),
    body('vehicleNo').trim().notEmpty().withMessage('Vehicle number required'),
    body('zone').trim().notEmpty().withMessage('Zone required'),
    body('products').isArray({ min: 1 }).withMessage('At least one product required'),
    body('products.*.productName').trim().notEmpty().withMessage('Product name required'),
    body('products.*.model').trim().notEmpty().withMessage('Model required'),
    body('products.*.quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const gatePassCollection = db.collection('gate-pass');
        const gatePass = req.body;
        if (gatePass.products && Array.isArray(gatePass.products)) {
            gatePass.products = gatePass.products.map(p => ({
                _id: new ObjectId().toString(),
                productName: p.productName,
                model: p.model,
                quantity: Number(p.quantity)
            }));
        }
        gatePass.createdAt = new Date();
        gatePass.createdBy = req.user?.email || 'unknown';
        // Date string থেকে সরাসরি parse — server timezone-এ month পিছলে
        // যাওয়ার bug fix (new Date('YYYY-MM-DD').getMonth() negative-offset
        // TZ-এ আগের month দিত, gate pass ভুল month-এ পড়ত)
        const [tpY, tpM] = String(gatePass.tripDate).slice(0, 10).split('-').map(Number);
        gatePass.tripMonth = tpM;
        gatePass.tripYear = tpY;
        const result = await gatePassCollection.insertOne(gatePass);
        // Invalidate dashboard cache so summary updates immediately
        invalidateDashboardCache(gatePass.tripMonth, gatePass.tripYear);
        res.send({ success: true, insertedId: result.insertedId });
    } catch (err) {
        logger.error('Failed to add gate pass', err);
        res.status(500).send({ success: false, message: 'Failed to add gate pass' });
    }
});

app.get("/gate-pass", verifyToken, verifyNonVendor, async (req, res) => {
    try {
        const db = await connectDB();
        const gatePassCollection = db.collection('gate-pass');
        let month = parseInt(req.query.month);
        let year = parseInt(req.query.year);
        // FIX #3 — escape regex input
        const search = escapeRegex(req.query.search || "");
        let query = {};

        if (search) {
            // Global search — পুরো collection, limit 500
            query.$or = [
                { tripDo: { $regex: search, $options: "i" } },
                { customerName: { $regex: search, $options: "i" } },
                { csd: { $regex: search, $options: "i" } },
                { unit: { $regex: search, $options: "i" } },
                { vehicleNo: { $regex: search, $options: "i" } },
                { zone: { $regex: search, $options: "i" } },
                { "products.productName": { $regex: search, $options: "i" } },
                { "products.model": { $regex: search, $options: "i" } },
            ];
            const data = await gatePassCollection.find(query).sort({ createdAt: -1 }).limit(500).toArray();
            return res.send({ data, pagination: { total: data.length } });
        }

        // FIX — ?limit=N (month ছাড়া): সর্বশেষ N টা pass, month-boundary
        // নির্বিশেষে। আগে limit ignore হয়ে পুরো current month আসত, আর
        // মাসের শুরুতে (শেষ pass আগের মাসে হলে) "Recently Added" খালি দেখাত।
        const recentLimit = parseInt(req.query.limit) || 0;
        if (recentLimit > 0 && !req.query.month) {
            const data = await gatePassCollection.find({})
                .sort({ createdAt: -1 })
                .limit(Math.min(recentLimit, 50))
                .toArray();
            return res.send({ data, pagination: { total: data.length } });
        }

        // Month query — no limit, index আছে তাই fast
        if (!month || !year) {
            const _dt = getDhakaCurrentMonthYear();
            month = _dt.month;
            year = _dt.year;
        }
        query.tripMonth = month;
        query.tripYear = year;
        const data = await gatePassCollection.find(query).sort({ createdAt: -1 }).toArray();
        res.send({ data, pagination: { total: data.length } });
    } catch (err) {
        logger.error('Failed to fetch gate passes', err);
        res.status(500).send({ success: false, message: "Failed to fetch gate passes" });
    }
});

// ─────────────────────────────────────────────────────────────────────
//  POST /gate-pass/by-trip-do
//  Body: { tripDos: ["4681835", ...] }
//  All-Challan page-এর "GP Match" column এটা ব্যবহার করে — challan
//  product-এ বসানো Trip Do গুলোর against কোন gate pass আছে সেটা এক
//  request-এ এনে client-side fuzzy verify (customer + model) করা হয়।
//  /challans/by-trip-do-র আয়না; শুধু matching-এ দরকারি field গুলো যায়।
// ─────────────────────────────────────────────────────────────────────
app.post("/gate-pass/by-trip-do", verifyToken, verifyNonVendor, async (req, res) => {
    try {
        const { tripDos } = req.body || {};
        if (!Array.isArray(tripDos) || tripDos.length === 0) {
            return res.send({ success: true, data: [] });
        }
        const clean = [...new Set(
            tripDos.map(t => String(t ?? "").trim()).filter(Boolean)
        )].slice(0, 3000);
        if (clean.length === 0) return res.send({ success: true, data: [] });

        const db = await connectDB();
        const data = await db.collection('gate-pass').find(
            { tripDo: { $in: clean } },
            { projection: {
                tripDo: 1, customerName: 1, csd: 1, unit: 1, tripDate: 1,
                "products._id": 1, "products.productName": 1,
                "products.model": 1, "products.quantity": 1,
            } }
        ).limit(5000).toArray();
        res.send({ success: true, data });
    } catch (err) {
        logger.error("gate-pass by-trip-do fetch failed", err);
        res.status(500).send({ success: false, message: "Failed to fetch gate passes" });
    }
});

app.patch('/gate-pass/:id', verifyToken, verifyRole('admin', 'manager', 'operator'), validateObjectId('id'), validate([
    param('id').isMongoId().withMessage('Invalid gate pass ID'),
    body('customerName').trim().notEmpty().withMessage('Customer name required'),
    body('tripDate').isISO8601().withMessage('Valid date required'),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const gatePassCollection = db.collection('gate-pass');
        const { tripDo, tripDate, customerName, csd, unit, vehicleNo, zone, currentUser } = req.body;
        await gatePassCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            {
                $set: {
                    tripDo, tripDate, customerName, csd, unit, vehicleNo, zone, currentUser,
                    tripMonth: new Date(tripDate).getMonth() + 1,
                    tripYear: new Date(tripDate).getFullYear(),
                    lastUpdatedBy: req.user?.email || 'unknown',
                    lastUpdatedAt: new Date(),
                }
            }
        );
        const updatedGatePass = await gatePassCollection.findOne({ _id: new ObjectId(req.params.id) });
        // Invalidate dashboard cache so summary updates immediately
    invalidateDashboardCache(updatedGatePass?.tripMonth, updatedGatePass?.tripYear);
        res.send({ success: true, data: updatedGatePass });
    } catch (err) {
        logger.error('Failed to update gate pass', err);
        res.status(500).send({ success: false, message: "Failed to update gate pass" });
    }
});

app.put('/gate-pass/:gatePassId/product/:productId', verifyToken, verifyRole('admin', 'manager', 'operator'), validateObjectId('gatePassId'), validate([
    param('gatePassId').isMongoId().withMessage('Invalid gate pass ID'),
    body('productName').trim().notEmpty().withMessage('Product name required'),
    body('model').trim().notEmpty().withMessage('Model required'),
    body('quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const gatePassCollection = db.collection('gate-pass');
        const { gatePassId, productId } = req.params;
        const { productName, model, quantity } = req.body;
        const result = await gatePassCollection.updateOne(
            { _id: new ObjectId(gatePassId), "products._id": productId },
            {
                $set: {
                    "products.$.productName": productName,
                    "products.$.model": model,
                    "products.$.quantity": Number(quantity)
                }
            }
        );
        if (result.matchedCount === 0)
            return res.status(404).send({ success: false, message: "Product not found" });
        const updatedGatePass = await gatePassCollection.findOne({ _id: new ObjectId(gatePassId) });
        // Invalidate dashboard cache so unit breakdown updates immediately
    invalidateDashboardCache(updatedGatePass?.tripMonth, updatedGatePass?.tripYear);
        res.send({ success: true, data: updatedGatePass });
    } catch (err) {
        logger.error('Failed to update product', err);
        res.status(500).send({ success: false, message: "Failed to update product" });
    }
});

// FIX #5 — Only admin/manager can delete gate pass (was: any authenticated user)
app.delete('/gate-pass/:id', verifyToken, verifyRole('admin', 'manager', 'operator'), validateObjectId('id'), validate([
    param('id').isMongoId().withMessage('Invalid ID'),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const gatePassCollection = db.collection('gate-pass');
        const doc = await gatePassCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).send({ success: false, message: "Gate Pass not found" });

        // FIX #48 — Audit log
        await recordAudit({
            db, req,
            action: "DELETE_GATEPASS",
            collectionName: "gate-pass",
            documentId: doc._id,
            oldDoc: doc,
            reason: req.body?.reason?.trim() || "",
        });

        await gatePassCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        // Invalidate dashboard cache so summary updates immediately
    invalidateDashboardCache(doc.tripMonth, doc.tripYear);
        res.send({ success: true, message: "Gate Pass deleted successfully" });
    } catch (err) {
        logger.error('Failed to delete gate pass', err);
        res.status(500).send({ success: false, message: "Failed to delete gate pass" });
    }
});

// ── Autocomplete ───────────────────────────────────────────────────
// ── Autocomplete field → index mapping ──────────────────────────────
// Text index কোন collection-এ কোন field cover করে:
//   challans    text index: customerName, address, receiverNumber, zone, thana, district
//   gate-pass   text index: tripDo, customerName, csd, unit, vehicleNo, zone
// productName / model — nested products array, text index support নেই MongoDB-তে
//   → এগুলোর জন্য individual field index (products.productName, products.model) দিয়ে regex
//
// Strategy:
//   1. Text-indexed fields  → $text + $search (fastest, index-only scan)
//   2. products.* fields    → $match regex on indexed nested field + $unwind
//   3. Fallback             → regex on individual field index (still fast with index)

// কোন field কোন collection-এ text index-এ আছে
const TEXT_INDEXED = {
    challan: new Set(['customerName', 'address', 'receiverNumber', 'zone', 'thana', 'district']),
    gatepass: new Set(['tripDo', 'customerName', 'csd', 'vehicleNo', 'zone']),
};

app.get("/autocomplete", verifyToken, verifyNonVendor, async (req, res) => {
    try {
        const db = await connectDB();
        const gatePassCollection = db.collection('gate-pass');
        const challanCollection = db.collection('challans');
        const { field, collection } = req.query;
        const rawSearch = (req.query.search || "").trim();

        if (!rawSearch) return res.send([]);

        // Whitelist — injection protection
        const ALLOWED_FIELDS = [
            'tripDo', 'customerName', 'csd', 'unit', 'vehicleNo', 'zone',
            'productName', 'model', 'address', 'receiverNumber', 'thana', 'district'
        ];
        if (!ALLOWED_FIELDS.includes(field)) {
            return res.status(400).send({ success: false, message: 'Invalid field' });
        }

        const isChallan = collection === "challan";
        const targetCollection = isChallan ? challanCollection : gatePassCollection;
        const collKey = isChallan ? 'challan' : 'gatepass';
        const isTextIndexed = TEXT_INDEXED[collKey]?.has(field);
        const isProductField = field === 'productName' || field === 'model';

        let pipeline = [];

        if (isProductField) {
            // ── products.* — nested field, individual index দিয়ে regex ──
            // Index: challans→products.model, challans→(no productName index, regex scan)
            // $match আগে করো তারপর $unwind → collection scan কমে
            const safeSearch = escapeRegex(rawSearch);
            pipeline = [
                { $match: { [`products.${field}`]: { $regex: safeSearch, $options: 'i' } } },
                { $unwind: '$products' },
                { $match: { [`products.${field}`]: { $regex: safeSearch, $options: 'i' } } },
                { $group: { _id: `$products.${field}` } },
                { $project: { _id: 0, value: '$_id' } },
                { $limit: 5 },
            ];
        } else if (isTextIndexed) {
            // ── Text index → $text + $search (fastest) ──
            // MongoDB text search prefix match নেই — তাই regex fallback দিয়ে filter করো
            // $text দিয়ে candidate set ছোট করো, তারপর regex দিয়ে prefix match করো
            const safeSearch = escapeRegex(rawSearch);
            pipeline = [
                {
                    $match: {
                        $and: [
                            { $text: { $search: rawSearch } },                              // text index scan
                            { [field]: { $regex: safeSearch, $options: 'i' } },            // prefix filter
                        ]
                    }
                },
                { $group: { _id: `$${field}` } },
                { $project: { _id: 0, value: '$_id' } },
                { $limit: 5 },
            ];
        } else {
            // ── Fallback: individual field index দিয়ে regex ──
            // (vehicleNo, tripDo etc যেগুলো text index-এ নেই কিন্তু own index আছে)
            const safeSearch = escapeRegex(rawSearch);
            pipeline = [
                { $match: { [field]: { $regex: safeSearch, $options: 'i' } } },
                { $group: { _id: `$${field}` } },
                { $project: { _id: 0, value: '$_id' } },
                { $limit: 5 },
            ];
        }

        const result = await targetCollection.aggregate(pipeline).toArray();
        res.send(result);
    } catch (err) {
        logger.error('Autocomplete failed', err);
        res.status(500).send({ success: false, message: "Autocomplete failed" });
    }
});

// ═══════════════════════════════════════════════════════════════════
// Challan
// ═══════════════════════════════════════════════════════════════════

app.post("/challan", verifyToken, verifyNonVendor, validate([
    body('customerName').trim().notEmpty().withMessage('Customer name required'),
    body('address').trim().notEmpty().withMessage('Address required'),
    body('receiverNumber').trim().notEmpty().withMessage('Receiver number required'),
    body('zone').trim().notEmpty().withMessage('Zone required'),
    body('products').isArray({ min: 1 }).withMessage('At least one product required'),
    body('products.*.productName').trim().notEmpty().withMessage('Product name required'),
    body('products.*.model').trim().notEmpty().withMessage('Model required'),
    body('products.*.quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
    // capacity (string) and rate (number) are optional — auto-resolved by
    // the client from with-model / without-model lookup tables.  When the
    // client couldn't resolve a rate yet (e.g. without-model product whose
    // capacity must be picked on the Delivered page), capacity/rate are
    // sent as "" / 0 and the Delivered-page editor sets them later.
    body('products.*.capacity').optional({ checkFalsy: false }).isString(),
    body('products.*.rate').optional({ checkFalsy: false }).isNumeric(),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const challanCollection = db.collection('challans');
        const challan = req.body;
        if (challan.products && Array.isArray(challan.products)) {
            challan.products = challan.products.map(p => {
                // FIX #50 — rate আর client থেকে বিশ্বাস করা হয় না; server
                // নিজের rate table থেকে resolve করে। Client-এর মান শুধু
                // cross-check + tamper-log-এর জন্য।
                const guarded = resolveAuthoritativeRate({
                    productName: p.productName,
                    model: p.model,
                    location: challan.location || null,
                    capacity: p.capacity,
                    clientRate: p.rate,
                    logger,
                    context: 'POST /challan',
                    userEmail: req.user?.email,
                });
                return {
                    _id: new ObjectId().toString(),
                    productName: p.productName,
                    model: p.model,
                    quantity: Number(p.quantity),
                    capacity: guarded.capacity,
                    rate: guarded.rate,
                };
            });
        }
        challan.createdAt = new Date();
        challan.createdBy = req.user?.email || 'unknown';
        const result = await challanCollection.insertOne(challan);
        res.send({ success: true, insertedId: result.insertedId });
    } catch (err) {
        logger.error('Failed to add challan', err);
        res.status(500).send({ success: false, message: "Failed to add challan" });
    }
});

app.get("/challan/recent", verifyToken, verifyNonVendor, async (req, res) => {
    try {
        const db = await connectDB();
        const challanCollection = db.collection('challans');
        const result = await challanCollection.find().sort({ createdAt: -1 }).limit(1).toArray();
        res.send({ data: result });
    } catch (err) {
        logger.error('Failed to fetch recent challan', err);
        res.status(500).send({ success: false, message: "Failed to fetch recent challan" });
    }
});

// ═══════════════════════════════════════════════════════════════════
//  PATCH: index.js  /parse-address endpoint  (server, v2)
//  ───────────────────────────────────────────────────────────────────
//  Apply these THREE changes to your existing index.js:
//
//   (1) Change the require() at the top of the file.
//   (2) Inside POST /parse-address: REMOVE the `existingThanas` /
//       `approvedThanas` DB lookup. It's not used anymore — the AI now
//       gets the canonical thana→district mapping from
//       bangladeshThanaData.js.
//   (3) Change the parseAddressHybrid() call to pass the mapping.
//
//  (Optional) Add a small /gemini-status route to inspect key pool health.
// ═══════════════════════════════════════════════════════════════════


// ─────────────────────────────────────────────────────────────────
//  (1) Top-of-file require
// ─────────────────────────────────────────────────────────────────

// ── OLD (around line 17 of your index.js): ──
//   const { BANGLADESH_DISTRICTS } = require('./constants/bangladeshDistricts');

// ── NEW: ──
const {
    DISTRICTS_WITH_THANAS,
    BANGLADESH_DISTRICTS,
} = require('./constants/bangladeshThanaData');

// (Keep the existing line:)
//   const { parseAddressHybrid } = require('./services/hybridAddressParser');


// ─────────────────────────────────────────────────────────────────
//  (2) & (3) /parse-address endpoint — full new version
// ─────────────────────────────────────────────────────────────────

app.post('/parse-address', verifyToken, verifyNonVendor, aiLimiter, mongoAiLimiter, async (req, res) => {
    try {
        const { address } = req.body;

        if (!address || typeof address !== 'string' || address.trim().length < 3) {
            return res.status(400).send({
                success: false,
                message: 'Address must be at least 3 characters',
            });
        }

        const db = await connectDB();

        // ── Cache check (unchanged) ──
        const crypto = require('crypto');
        const cacheKey = crypto
            .createHash('sha256')
            .update(address.trim().toLowerCase())
            .digest('hex');

        const cacheCollection = db.collection('address_cache');
        const cached = await cacheCollection.findOne({ _id: cacheKey });

        if (cached && cached.expiresAt > new Date()) {
            return res.send({
                success: true,
                ...cached.result,
                cached: true,
            });
        }

        // ── REMOVED: the old DB lookup for `existingThanas` / `approvedThanas`.
        //    It was pulling every user-typed thana value (including typos)
        //    out of the challans collection and feeding them back to the AI
        //    as "approved", which made the AI repeat the same wrong names.
        //
        //    The AI now gets the canonical thana→district mapping instead,
        //    and any thana that doesn't belong to its returned district is
        //    automatically dropped by the parser. ──

        // ── Call Hybrid (Gemini only — Groq removed) with the canonical mapping ──
        const result = await parseAddressHybrid(
            address,
            DISTRICTS_WITH_THANAS,
            BANGLADESH_DISTRICTS
        );

        if (!result.success) {
            return res.status(502).send(result);
        }

        // ── Save to cache (30 days TTL) ──
        const cacheDoc = {
            _id: cacheKey,
            input: address.trim(),
            result: {
                cleanAddress: result.cleanAddress,
                thana: result.thana,
                district: result.district,
                confidence: result.confidence,
                notes: result.notes,
            },
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        };

        cacheCollection.updateOne(
            { _id: cacheKey },
            { $set: cacheDoc },
            { upsert: true }
        ).catch((err) => console.error('Cache write failed', err));

        res.send({
            success: true,
            cleanAddress: result.cleanAddress,
            thana: result.thana,
            district: result.district,
            confidence: result.confidence,
            notes: result.notes,
            cached: false,
        });
    } catch (err) {
        console.error('Parse address failed', err);
        res.status(500).send({
            success: false,
            message: 'Failed to parse address',
        });
    }
});


// ─────────────────────────────────────────────────────────────────
//  (OPTIONAL) /gemini-status — inspect key pool health
//  ───────────────────────────────────────────────────────────────
//  Useful when you want to see which Gemini keys are cooled down.
//  Protect it with admin auth in production.
// ─────────────────────────────────────────────────────────────────

const { poolStatus } = require('./services/geminiAddressParser');

app.get('/gemini-status', verifyToken, (req, res) => {
    res.send({
        success: true,
        pool: poolStatus(),
        note: 'Cooldowns are in-memory only; they reset on server restart.',
    });
});
app.get("/challans", verifyToken, verifyNonVendor, async (req, res) => {
    try {
        const db = await connectDB();
        const challanCollection = db.collection('challans');
        let month = parseInt(req.query.month);
        let year = parseInt(req.query.year);
        // FIX #3 — escape all user input used in regex
        const search = escapeRegex(req.query.search || "");

        const customerFilter = escapeRegex(req.query.customer || "");
        const zoneFilter = escapeRegex(req.query.zone || "");
        const districtFilter = escapeRegex(req.query.district || "");
        const thanaFilter = escapeRegex(req.query.thana || "");
        const receiverFilter = escapeRegex(req.query.receiver || "");
        const modelFilter = escapeRegex(req.query.model || "");
        const productNameFilter = escapeRegex(req.query.productName || "");
        const dateFilter = req.query.date || "";

        let query = {};

        if (search) {
            // Global search — পুরো collection, কিন্তু limit 200 (browser fast রাখতে)
            query.$or = [
                { customerName: { $regex: search, $options: "i" } },
                { address: { $regex: search, $options: "i" } },
                { receiverNumber: { $regex: search, $options: "i" } },
                { zone: { $regex: search, $options: "i" } },
                { thana: { $regex: search, $options: "i" } },
                { district: { $regex: search, $options: "i" } },
                { "products.productName": { $regex: search, $options: "i" } },
                { "products.model": { $regex: search, $options: "i" } },
            ];
            const data = await challanCollection.find(query).sort({ createdAt: -1 }).limit(200).toArray();
            return res.send({ data, pagination: { total: data.length } });
        }

        // Month query — no limit, index আছে তাই fast
        if (!month || !year) {
            const _dt = getDhakaCurrentMonthYear();
            month = _dt.month;
            year = _dt.year;
        }
        const { startDate, endDate } = getDhakaMonthRange(year, month);
        query.createdAt = { $gte: startDate, $lt: endDate };

        if (customerFilter) query.customerName = { $regex: customerFilter, $options: "i" };
        if (zoneFilter) query.zone = { $regex: zoneFilter, $options: "i" };
        if (districtFilter) query.district = { $regex: districtFilter, $options: "i" };
        if (thanaFilter) query.thana = { $regex: thanaFilter, $options: "i" };
        if (receiverFilter) query.receiverNumber = { $regex: receiverFilter, $options: "i" };
        if (modelFilter) query["products.model"] = { $regex: modelFilter, $options: "i" };
        if (productNameFilter) query["products.productName"] = { $regex: productNameFilter, $options: "i" };
        if (dateFilter) {
            const filterDate = new Date(dateFilter);
            if (!isNaN(filterDate.getTime())) {
                const nextDay = new Date(filterDate);
                nextDay.setDate(nextDay.getDate() + 1);
                query.createdAt = { $gte: filterDate, $lt: nextDay };
            }
        }

        const data = await challanCollection.find(query).sort({ createdAt: -1 }).toArray();
        res.send({ data, pagination: { total: data.length } });
    } catch (err) {
        logger.error('Failed to fetch challans', err);
        res.status(500).send({ success: false, message: "Failed to fetch challans" });
    }
});

app.get("/challans/filter-options", verifyToken, verifyNonVendor, async (req, res) => {
    try {
        const db = await connectDB();
        const challanCollection = db.collection('challans');
        let month = parseInt(req.query.month);
        let year = parseInt(req.query.year);
        if (!month || !year) {
            const _dt = getDhakaCurrentMonthYear();
            month = _dt.month;
            year = _dt.year;
        }
        const { startDate, endDate } = getDhakaMonthRange(year, month);
        const baseQuery = { createdAt: { $gte: startDate, $lt: endDate } };
        const [result] = await challanCollection.aggregate([
            { $match: baseQuery },
            { $unwind: "$products" },
            {
                $group: {
                    _id: null,
                    customerNames: { $addToSet: "$customerName" },
                    zones: { $addToSet: "$zone" },
                    districts: { $addToSet: "$district" },
                    thanas: { $addToSet: "$thana" },
                    receivers: { $addToSet: "$receiverNumber" },
                    models: { $addToSet: "$products.model" },
                    productNames: { $addToSet: "$products.productName" },
                }
            },
            {
                $project: {
                    _id: 0,
                    customerNames: { $sortArray: { input: "$customerNames", sortBy: 1 } },
                    zones: { $sortArray: { input: "$zones", sortBy: 1 } },
                    districts: { $sortArray: { input: "$districts", sortBy: 1 } },
                    thanas: { $sortArray: { input: "$thanas", sortBy: 1 } },
                    receivers: { $sortArray: { input: "$receivers", sortBy: 1 } },
                    models: { $sortArray: { input: "$models", sortBy: 1 } },
                    productNames: { $sortArray: { input: "$productNames", sortBy: 1 } },
                }
            }
        ]).toArray();
        res.send({
            success: true,
            data: result || { customerNames: [], zones: [], districts: [], thanas: [], receivers: [], models: [], productNames: [] }
        });
    } catch (err) {
        logger.error('Failed to fetch filter options', err);
        res.status(500).send({ success: false, message: "Failed to fetch filter options" });
    }
});

// FIX #5 — Only admin/manager can delete challan
app.delete("/challan/:id", verifyToken, verifyRole('admin', 'manager', 'operator'), validateObjectId('id'), validate([
    param('id').isMongoId().withMessage('Invalid ID'),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const challanCollection = db.collection('challans');
        const doc = await challanCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).send({ success: false, message: "Challan not found" });

        // FIX #48 — Audit log the delete
        await recordAudit({
            db, req,
            action: "DELETE_CHALLAN",
            collectionName: "challans",
            documentId: doc._id,
            oldDoc: doc,
            reason: req.body?.reason?.trim() || "",
        });

        const result = await challanCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        res.send({ success: true, deletedCount: result.deletedCount });
    } catch (err) {
        logger.error('Failed to delete challan', err);
        res.status(500).send({ success: false, message: "Failed to delete challan" });
    }
});

app.patch('/challan/:id', verifyToken, verifyNonVendor, validateObjectId('id'), validate([
    param('id').isMongoId().withMessage('Invalid challan ID'),
    body('customerName').trim().notEmpty().withMessage('Customer name required'),
    body('receiverNumber').trim().notEmpty().withMessage('Receiver number required'),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const challanCollection = db.collection('challans');
        const { customerName, address, thana, district, receiverNumber, zone, location, currentUser, createdAt, updatedBy } = req.body;

        // createdAt না পাঠালে DB থেকে নাও
        let dateToUse = createdAt ? new Date(createdAt) : null;
        if (!dateToUse) {
            const existing = await challanCollection.findOne(
                { _id: new ObjectId(req.params.id) },
                { projection: { createdAt: 1 } }
            );
            dateToUse = existing?.createdAt ? new Date(existing.createdAt) : null;
        }

        const setDoc = {
            customerName, address, thana, district, receiverNumber, zone, currentUser,
            lastUpdatedBy: updatedBy || req.user?.email || 'unknown',
            lastUpdatedAt: new Date(),
        };

        // location is recomputed client-side from the (possibly edited) thana +
        // district. Only set it when supplied so a partial edit can't wipe it.
        if (typeof location === 'string') {
            setDoc.location = location;
        }

        // এখন সবসময় month/year set হবে
        if (dateToUse && !isNaN(dateToUse.getTime())) {
            setDoc.month = dateToUse.getMonth() + 1;
            setDoc.year = dateToUse.getFullYear();
        }

        await challanCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: setDoc });
        const updatedChallan = await challanCollection.findOne({ _id: new ObjectId(req.params.id) });
        res.send({ success: true, data: updatedChallan });
    } catch (err) {
        logger.error('Failed to update challan', err);
        res.status(500).send({ success: false, message: "Failed to update challan" });
    }
});

// Remarks — admin-only note on a challan, editable from BOTH the All
// Challan page and the Delivered page. See PATCH /challans/bulk-remarks
// (near the other bulk-* routes) for the actual update logic — single-row
// edits from either page just call it with a one-element `challanIds`
// array, same pattern as Trip Do.

app.put('/challan/:challanId/product/:productId', verifyToken, verifyNonVendor, validateObjectId('challanId'), validate([
    param('challanId').isMongoId().withMessage('Invalid challan ID'),
    body('productName').trim().notEmpty().withMessage('Product name required'),
    body('model').trim().notEmpty().withMessage('Model required'),
    body('quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
    // capacity + rate are optional; client sends them after looking up the
    // resolved value from with-model / without-model tables.  When the
    // user only changes (say) quantity, capacity/rate may be omitted and
    // existing values are preserved.
    body('capacity').optional({ checkFalsy: false }).isString(),
    body('rate').optional({ checkFalsy: false }).isNumeric(),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const challanCollection = db.collection('challans');
        const { challanId, productId } = req.params;
        const { productName, model, quantity, capacity, rate } = req.body;

        // Build the $set patch — only include capacity/rate when the client
        // explicitly supplied them so we don't accidentally wipe existing
        // values on a quantity-only edit.
        const setPatch = {
            "products.$.productName": productName,
            "products.$.model": model,
            "products.$.quantity": Number(quantity),
        };
        if (typeof capacity === 'string' || (rate !== undefined && rate !== null && rate !== '')) {
            // FIX #50 — client capacity/rate পাঠালে server নিজে resolve করে
            // save করে; challan doc থেকে location পড়ি।
            const parentChallan = await challanCollection.findOne(
                { _id: new ObjectId(challanId) }, { projection: { location: 1 } }
            );
            const guarded = resolveAuthoritativeRate({
                productName, model,
                location: parentChallan?.location || null,
                capacity,
                clientRate: rate,
                logger,
                context: 'PUT /challan/:id/product/:pid',
                userEmail: req.user?.email,
            });
            setPatch["products.$.capacity"] = guarded.capacity;
            setPatch["products.$.rate"] = guarded.rate;
        }

        const result = await challanCollection.updateOne(
            { _id: new ObjectId(challanId), "products._id": productId },
            { $set: setPatch }
        );
        if (result.matchedCount === 0)
            return res.status(404).send({ success: false, message: "Product not found" });
        const updatedChallan = await challanCollection.findOne({ _id: new ObjectId(challanId) });
        res.send({ success: true, data: updatedChallan });
    } catch (err) {
        logger.error('Failed to update product', err);
        res.status(500).send({ success: false, message: "Failed to update product" });
    }
});

app.delete("/challans/:challanId/product/:productId", verifyToken, verifyNonVendor, validateObjectId('challanId'), async (req, res) => {
    try {
        const db = await connectDB();
        const challanCollection = db.collection('challans');
        const { challanId, productId } = req.params;
        const result = await challanCollection.updateOne(
            { _id: new ObjectId(challanId) },
            { $pull: { products: { _id: productId } } }
        );
        if (result.modifiedCount > 0) {
            res.send({ success: true, message: "Product removed from challan" });
        } else {
            res.status(404).send({ success: false, message: "Product not found" });
        }
    } catch (err) {
        logger.error('Failed to delete product', err);
        res.status(500).send({ success: false, message: "Failed to delete product" });
    }
});

/**
 * Bulk Remarks — stamps one Remarks value onto every challan supplied.
 * Admin-only, and shared by BOTH the All Challan page and the Delivered
 * page:
 *   - a single-row edit on either page just calls this with a
 *     one-element `challanIds` array (same pattern as Trip Do)
 *   - the "Bulk Remarks" button on either page passes every distinct
 *     challanId currently visible under the active filters
 *
 * Remarks are written to the `challans` collection (source of truth,
 * shown on the All Challan page) AND mirrored onto any embedded copy in
 * `deliveries.challans[]` (what the Delivered page actually reads), so
 * editing from either page keeps both in sync. Empty string clears
 * Remarks on those challans.
 *
 * IMPORTANT: this route MUST be registered before `/challans/:id` below —
 * Express matches routes in registration order, and "bulk-remarks" would
 * otherwise match the `:id` wildcard first (and get rejected by its
 * validateObjectId check, since "bulk-remarks" isn't a Mongo ObjectId).
 */
// ─────────────────────────────────────────────────────────────────────
//  Gate Pass ↔ Challan linkage
//  ─────────────────────────────────────────────────────────────────
//  POST /challans/by-trip-do
//  Body: { tripDos: ["4681835", ...] }  (max 3000)
//  Returns minimal challan docs whose products carry any of the given
//  Trip Do numbers. AllGatePass page এটা দিয়ে current + previous
//  month-এর gate pass গুলোর delivery status compute করে (fuzzy
//  customer/model matching client-side হয়)। Month-এর সীমানা মানা হয়
//  না — জুলাইয়ের gate pass আগস্টের challan দিয়ে deliver হলেও ধরা পড়ে।
// ─────────────────────────────────────────────────────────────────────
app.post("/challans/by-trip-do", verifyToken, verifyNonVendor, async (req, res) => {
    try {
        const { tripDos } = req.body || {};
        if (!Array.isArray(tripDos) || tripDos.length === 0) {
            return res.send({ success: true, data: [] });
        }
        const clean = [...new Set(
            tripDos.map(t => String(t ?? "").trim()).filter(Boolean)
        )].slice(0, 3000);
        if (clean.length === 0) return res.send({ success: true, data: [] });

        const db = await connectDB();
        const challanCol = db.collection('challans');
        const projection = {
            customerName: 1, status: 1, csd: 1, unit: 1, tripNumber: 1,
            createdAt: 1, zone: 1, returnedFromChallanId: 1,
            "products._id": 1, "products.productName": 1, "products.model": 1,
            "products.quantity": 1, "products.tripDo": 1,
        };
        const data = await challanCol.find(
            { "products.tripDo": { $in: clean } },
            { projection }
        ).limit(5000).toArray();

        // ── Self-heal: legacy return challan-এ Trip Do backfill ─────────
        // Fix-এর আগে তৈরি return-pending / re-delivered challan-গুলোর
        // products-এ tripDo নেই, তাই উপরের query-তে ওগুলো ধরাই পড়ে না —
        // ফলে All-Gate-Pass-এ Return status কখনো আসত না। এখানে found
        // original গুলোর derived return challan খুঁজে original product
        // থেকে tripDo inherit করে DB-তে বসিয়ে দেওয়া হয় (একবারই লাগে),
        // আর এই response-এই সেগুলো যোগ হয় যাতে status সাথে সাথে আসে।
        try {
            const norm = (s) => String(s ?? "").toLowerCase().replace(/[^a-z0-9\u0980-\u09FF]/g, "");
            const originalsById = new Map(
                data.filter(d => !d.returnedFromChallanId)
                    .map(d => [String(d._id), d])
            );
            const foundIds = [...originalsById.keys()];
            if (foundIds.length) {
                // FULL products আনতে হবে — $set-এ পুরো array বসে, projected
                // subset বসালে capacity/rate হারিয়ে যেত
                const derived = await challanCol.find(
                    {
                        returnedFromChallanId: { $in: foundIds },
                        products: { $elemMatch: { tripDo: { $in: [null, ""] } } },
                    },
                    { projection: {
                        customerName: 1, status: 1, csd: 1, unit: 1, tripNumber: 1,
                        createdAt: 1, zone: 1, returnedFromChallanId: 1, products: 1,
                    } }
                ).limit(1000).toArray();

                const healOps = [];
                const cardFills = []; // deliveries return card-এও ফাঁকা tripDo fill
                for (const d of derived) {
                    const orig = originalsById.get(String(d.returnedFromChallanId));
                    if (!orig) continue;
                    let changed = false;
                    const healedPairs = []; // { cardProductId, tripDo }
                    for (const p of (d.products || [])) {
                        if (typeof p.tripDo === 'string' && p.tripDo.trim()) continue;
                        const src = (orig.products || []).find(op =>
                            (p.sourceProductId && String(op._id) === String(p.sourceProductId)) ||
                            (norm(op.productName) === norm(p.productName) && norm(op.model) === norm(p.model))
                        );
                        if (src && typeof src.tripDo === 'string' && src.tripDo.trim()) {
                            p.tripDo = src.tripDo.trim();
                            if (!p.sourceProductId) p.sourceProductId = src._id;
                            healedPairs.push({ cardProductId: String(src._id), tripDo: p.tripDo });
                            changed = true;
                        }
                    }
                    if (changed) {
                        healOps.push({
                            updateOne: {
                                filter: { _id: d._id },
                                update: { $set: {
                                    products: d.products,
                                    tripDoBackfilledAt: new Date(),
                                } },
                            }
                        });
                        // Delivered page-এর return card-ও fill হয় — card
                        // product-এর _id = original product-এর _id
                        const origId = String(d.returnedFromChallanId);
                        for (const { cardProductId, tripDo } of healedPairs) {
                            cardFills.push(
                                db.collection('deliveries').updateMany(
                                    { challans: { $elemMatch: { isReturn: true, originalChallanId: origId } } },
                                    { $set: { "challans.$[c].products.$[p].tripDo": tripDo } },
                                    { arrayFilters: [
                                        { "c.isReturn": true, "c.originalChallanId": origId },
                                        { "p._id": cardProductId, "p.tripDo": { $in: [null, ""] } },
                                    ] }
                                ).catch(() => {})
                            );
                        }
                        // এই response-এই যোগ করা হয় — শুধু requested tripDo-র
                        // product গুলোই relevant, তবু পুরো doc পাঠালে ক্ষতি নেই
                        if (!data.some(x => String(x._id) === String(d._id))) data.push(d);
                    }
                }
                if (healOps.length) await challanCol.bulkWrite(healOps, { ordered: false });
                if (cardFills.length) await Promise.all(cardFills);
            }
        } catch (healErr) {
            // Backfill best-effort — fail করলেও মূল read ভাঙবে না
            logger.error("by-trip-do return backfill failed", healErr);
        }

        res.send({ success: true, data });
    } catch (err) {
        logger.error("by-trip-do fetch failed", err);
        res.status(500).send({ success: false, message: "Failed to fetch linked challans" });
    }
});

// ─────────────────────────────────────────────────────────────────────
//  PATCH /challans/bulk-gate-sync
//  Body: { assignments: [{ challanId, csd, unit }, ...] }
//  Gate pass-এর সাথে match হওয়া challan-এ gp-এর CSD ও Unit বসায় —
//  challans collection (All-Challan page) এবং deliveries-এর embedded
//  copy (Delivered page) দুটোতেই, bulk-csd-এর মতোই। Client matching
//  করে explicit assignment পাঠায়, তাই server-side fuzzy guess নেই —
//  পুরোটা deterministic ও auditable।
// ─────────────────────────────────────────────────────────────────────
app.patch("/challans/bulk-gate-sync", verifyToken, verifyRole('admin', 'manager', 'operator'), async (req, res) => {
    try {
        const { assignments } = req.body || {};
        if (!Array.isArray(assignments) || assignments.length === 0) {
            return res.status(400).send({ success: false, message: "No assignments supplied" });
        }
        const db = await connectDB();
        const challanCollection = db.collection('challans');
        const deliveriesCollection = db.collection('deliveries');

        const syncedBy = req.user?.email || "unknown";
        const syncedAt = new Date();

        // আগে প্রতি assignment-এ ২টা করে আলাদা update fire হতো
        // (Promise.all) — শ'খানেক assignment-এ শ'দুয়েক parallel অপারেশন,
        // M0/serverless-এ connection pool/timeout-এ একটা fail করলেই পুরো
        // request 500 দিত, অথচ বাকিগুলো লিখে ফেলত (data বসে কিন্তু
        // "Gate sync failed" দেখায়)। এখন: প্রতি collection-এ ১টা করে
        // bulkWrite (ordered:false) — দ্রুত, pool-safe, আর partial
        // failure হলেও যা লেগেছে তার হিসাব দিয়ে success ফেরত যায়।
        const challanOps = [];
        const deliveryOps = [];

        for (const a of assignments.slice(0, 2000)) {
            const challanId = String(a?.challanId || "").trim();
            if (!challanId) continue;
            const csd  = String(a?.csd  ?? "").trim();
            const unit = String(a?.unit ?? "").trim();
            if (!csd && !unit) continue;

            const setChallan = { gateSyncedAt: syncedAt, gateSyncedBy: syncedBy };
            if (csd)  setChallan.csd  = csd;
            if (unit) setChallan.unit = unit;

            if (isValidObjectId(challanId)) {
                challanOps.push({
                    updateOne: {
                        filter: { _id: new ObjectId(challanId) },
                        update: { $set: setChallan },
                    }
                });
            }

            const setEmb = {};
            if (csd)  setEmb["challans.$[c].csd"]  = csd;
            if (unit) setEmb["challans.$[c].unit"] = unit;
            deliveryOps.push({
                updateMany: {
                    filter: { "challans.challanId": challanId },
                    update: { $set: setEmb },
                    arrayFilters: [{ "c.challanId": challanId }],
                }
            });
        }

        let touched = 0;
        const errors = [];
        const runBulk = async (col, ops, label) => {
            if (!ops.length) return;
            try {
                const r = await col.bulkWrite(ops, { ordered: false });
                touched += r.modifiedCount || 0;
            } catch (e) {
                // ordered:false → error হলেও বাকি op গুলো চলে; যা লেগেছে গুনি
                touched += e?.result?.modifiedCount || e?.result?.nModified || 0;
                errors.push(`${label}: ${e.message}`);
                logger.error(`bulk-gate-sync ${label} partial failure`, e);
            }
        };
        await runBulk(challanCollection, challanOps, "challans");
        await runBulk(deliveriesCollection, deliveryOps, "deliveries");

        // কিছুই না লাগলে-ই কেবল fail; আংশিক হলে success + warning।
        // engine field টা version marker — client console-এ দেখলেই বোঝা
        // যায় নতুন server code live আছে কিনা।
        if (errors.length && touched === 0) {
            return res.status(500).send({ success: false, engine: "gate-sync-v2", message: "Gate sync failed", detail: errors.join(" | "), errors });
        }
        res.send({ success: true, engine: "gate-sync-v2", touched, ...(errors.length ? { warning: "Some updates failed", errors } : {}) });
    } catch (err) {
        logger.error("bulk-gate-sync failed", err);
        // আসল error message response-এ পাঠানো হয় যাতে UI-তেই root cause
        // দেখা যায় — generic "Gate sync failed" দিয়ে debug করা যেত না
        res.status(500).send({ success: false, engine: "gate-sync-v2", message: "Gate sync failed", detail: err?.message || String(err) });
    }
});

app.patch("/challans/bulk-remarks", verifyToken, verifyRole('admin'), async (req, res) => {
    try {
        const { remarks, challanIds } = req.body || {};
        if (!Array.isArray(challanIds) || challanIds.length === 0) {
            return res.status(400).send({ success: false, message: "No challans supplied" });
        }
        const clean = String(remarks ?? "").trim();

        const db = await connectDB();
        const challanCollection = db.collection('challans');
        const deliveriesCollection = db.collection('deliveries');

        // De-duplicate ids.
        const ids = [...new Set(challanIds.filter(Boolean).map(String))];

        let touched = 0;
        const operations = [];

        for (const challanId of ids) {
            // ── 1. challans collection (source of truth — All Challan page) ──
            if (isValidObjectId(challanId)) {
                operations.push(
                    challanCollection.updateOne(
                        { _id: new ObjectId(challanId) },
                        {
                            $set: {
                                remarks: clean,
                                remarksUpdatedBy: req.user?.email || 'unknown',
                                remarksUpdatedAt: new Date(),
                            },
                        }
                    ).then(r => { touched += r.matchedCount || 0; })
                );
            }

            // ── 2. deliveries collection (embedded copy — Delivered page reads this) ──
            operations.push(
                deliveriesCollection.updateMany(
                    { "challans.challanId": challanId },
                    { $set: { "challans.$[c].remarks": clean, "challans.$[c].remarksUpdatedAt": new Date() } },
                    { arrayFilters: [{ "c.challanId": challanId }] }
                ).catch(() => { /* non-fatal — challans collection is still updated above */ })
            );
        }

        await Promise.all(operations);
        res.send({ success: true, touched, remarks: clean });
    } catch (err) {
        logger.error("Bulk Remarks update failed", err);
        res.status(500).send({ success: false, message: "Failed to update remarks" });
    }
});

// FIX (A3): Plural route — used by CreateDelivery to update challan + products together.
// আগে কোনো validation ছিল না → invalid product data inject করা যেত।
// এখন: required field + products array structure validate করি।
app.patch('/challans/:id', verifyToken, verifyNonVendor, validateObjectId('id'), validate([
    param('id').isMongoId().withMessage('Invalid challan ID'),
    body('customerName').trim().notEmpty().withMessage('Customer name required'),
    body('receiverNumber').trim().notEmpty().withMessage('Receiver number required'),
    body('products').optional().isArray().withMessage('Products must be an array'),
    body('products.*.productName').optional().trim().notEmpty().withMessage('Product name required'),
    // FIX — model খালি string হতে পারে: without-model product গুলোর
    // (rate table-এর N/M items) model থাকে না। আগের notEmpty() validation
    // এদের edit save করতে দিত না (400 "Product model required")।
    body('products.*.model').optional({ checkFalsy: false }).isString(),
    body('products.*.quantity').optional().isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
    body('products.*.capacity').optional({ checkFalsy: false }).isString(),
    body('products.*.rate').optional({ checkFalsy: false }).isNumeric(),
    body('location').optional({ checkFalsy: false }).isString(),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const challanCollection = db.collection('challans');
        const { customerName, receiverNumber, zone, address, thana, district, products, updatedBy, location, splitLeftover } = req.body;

        // FIX #50 — rate server-side resolve করার জন্য challan-এর location লাগে।
        // splitLeftover flow-তে old products + customer info-ও লাগে, তাই
        // পুরো doc-ই আনা হয় (ছোট doc, projection বাদ)।
        const existingChallan = Array.isArray(products)
            ? await challanCollection.findOne({ _id: new ObjectId(req.params.id) })
            : null;

        // FIX — thana/district edit হলে client নতুন location পাঠায়;
        // সেটাই authoritative, নাহলে পুরনো location দিয়ে ভুল rate resolve হতো।
        const effectiveLocation = (typeof location === 'string' && location.trim())
            ? location.trim()
            : (existingChallan?.location || null);

        // Sanitize products — preserve _id, coerce quantity to number.
        // capacity + rate এখন server নিজে resolve করে (client মান শুধু cross-check)।
        const sanitizedProducts = Array.isArray(products)
            ? products.map(p => {
                const guarded = resolveAuthoritativeRate({
                    productName: String(p.productName || '').trim(),
                    model: String(p.model || '').trim(),
                    location: effectiveLocation,
                    capacity: p.capacity,
                    clientRate: p.rate,
                    logger,
                    context: 'PATCH /challans/:id',
                    userEmail: req.user?.email,
                });
                return {
                    _id: p._id || new ObjectId().toString(),
                    productName: String(p.productName || '').trim(),
                    model: String(p.model || '').trim(),
                    quantity: Number(p.quantity) || 0,
                    capacity: guarded.capacity,
                    rate: guarded.rate,
                };
            })
            : undefined;

        const setDoc = {
            customerName, receiverNumber, zone, address, thana, district,
            lastUpdatedBy: updatedBy || req.user?.email || 'unknown',
            lastUpdatedAt: new Date(),
        };
        if (typeof location === 'string' && location.trim()) setDoc.location = location.trim();
        if (sanitizedProducts !== undefined) setDoc.products = sanitizedProducts;

        const result = await challanCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: setDoc }
        );
        if (result.matchedCount > 0) {
            // ── Leftover split (opt-in) ──────────────────────────────────
            // CreateDelivery / Trip-Details-এর "Add Challan" edit modal
            // splitLeftover: true পাঠায় — product row remove বা qty কমালে
            // বাদ পড়া অংশটা নতুন pending challan হয়ে All-Challan-এ থাকে,
            // পরের delivery-তে ব্যবহারের জন্য। Delivered/re-delivered
            // challan-এ এই route দিয়ে edit হয় না, তবু guard রাখা হলো।
            let leftover = null;
            if (
                splitLeftover === true &&
                sanitizedProducts !== undefined &&
                existingChallan &&
                existingChallan.status !== 'delivered' &&
                existingChallan.status !== 're-delivered'
            ) {
                try {
                    const leftoverProducts = computeLeftoverProducts(existingChallan.products, sanitizedProducts);
                    if (leftoverProducts.length > 0) {
                        leftover = await spawnLeftoverChallan(db, {
                            sourceChallanId: req.params.id,
                            sourceInfo: {
                                customerName: customerName || existingChallan.customerName,
                                receiverNumber: receiverNumber || existingChallan.receiverNumber,
                                zone: zone || existingChallan.zone,
                                address: address || existingChallan.address,
                                thana: thana || existingChallan.thana,
                                district: district || existingChallan.district,
                                location: effectiveLocation || undefined,
                                remarks: existingChallan.remarks,
                                csd: existingChallan.csd,
                                unit: existingChallan.unit,
                            },
                            leftoverProducts,
                            createdBy: updatedBy || req.user?.email || 'unknown',
                        });
                    }
                } catch (splitErr) {
                    // Best-effort — split fail করলেও মূল update সফল-ই থাকে
                    logger.error('Leftover split failed (PATCH /challans/:id)', splitErr);
                }
            }
            res.send({ success: true, message: "Challan and Products updated successfully", ...(leftover ? { leftover } : {}) });
        } else {
            res.status(404).send({ success: false, message: "Challan not found" });
        }
    } catch (err) {
        logger.error('Update failed', err);
        res.status(500).send({ success: false, message: "Update failed" });
    }
});

// ═══════════════════════════════════════════════════════════════════
// Vendors
// ═══════════════════════════════════════════════════════════════════

app.post("/vendors", verifyToken, verifyNonVendor, validate([
    body('vendorName').trim().notEmpty().withMessage('Vendor name required'),
    body('vendorPhone').trim().notEmpty().withMessage('Phone required'),
    body('vendorAddress').trim().notEmpty().withMessage('Address required'),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const vendorsCollection = db.collection('vendors');
        // FIX (A8): Whitelist instead of `...req.body` spread to prevent mass assignment.
        const { vendorName, vendorPhone, vendorAddress, vendorImg } = req.body;
        const result = await vendorsCollection.insertOne({
            vendorName: vendorName.trim(),
            vendorPhone: vendorPhone.trim(),
            vendorAddress: vendorAddress.trim(),
            vendorImg: vendorImg || null,
            vehicles: [],
            createdAt: new Date(),
            createdBy: req.user?.email || 'unknown',
        });
        res.send({ success: true, insertedId: result.insertedId });
    } catch (err) {
        logger.error('Failed to add vendor', err);
        res.status(500).send({ success: false, message: "Failed to add vendor" });
    }
});

app.get("/vendors", verifyToken, verifyApproved, async (req, res) => {
    try {
        const db = await connectDB();
        const vendorsCollection = db.collection('vendors');

        let query = {};
        if (req.user?.role === 'vendor') {
            // FIX #6 — Don't trust JWT vendorName; fetch fresh from DB
            const userCollection = db.collection('users');
            const me = await userCollection.findOne({ email: req.user.email });
            if (!me?.vendorName) return res.send([]);
            query.vendorName = { $regex: `^${escapeRegex(me.vendorName)}$`, $options: 'i' };
        }

        const result = await vendorsCollection.find(query).toArray();
        res.send(result);
    } catch (err) {
        logger.error('Failed to fetch vendors', err);
        res.status(500).send({ success: false, message: "Failed to fetch vendors" });
    }
});

// FIX #15 — Vendor role can only fetch their own vendor record
app.get("/vendors/:id", verifyToken, verifyApproved, validateObjectId('id'), async (req, res) => {
    try {
        const db = await connectDB();
        const vendorsCollection = db.collection('vendors');
        const vendor = await vendorsCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (!vendor) return res.status(404).send({ success: false, message: 'Vendor not found' });

        // Vendor role — check they own this record
        if (req.user?.role === 'vendor') {
            const userCollection = db.collection('users');
            const me = await userCollection.findOne({ email: req.user.email });
            if (!me?.vendorName || me.vendorName.toLowerCase() !== (vendor.vendorName || '').toLowerCase()) {
                return res.status(403).send({ success: false, message: 'Forbidden: Not your vendor' });
            }
        }

        res.send(vendor);
    } catch (err) {
        logger.error('Failed to fetch vendor', err);
        res.status(500).send({ success: false, message: "Failed to fetch vendor" });
    }
});

app.patch("/vendors/:id", verifyToken, verifyNonVendor, validateObjectId('id'), validate([
    param('id').isMongoId().withMessage('Invalid vendor ID'),
    body('vendorName').trim().notEmpty().withMessage('Vendor name required'),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const vendorsCollection = db.collection('vendors');
        const { vendorName, vendorImg, vendorAddress, vendorPhone } = req.body;
        const result = await vendorsCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { vendorName, vendorImg, vendorAddress, vendorPhone } }
        );
        res.send({ success: true, modifiedCount: result.modifiedCount });
    } catch (err) {
        logger.error('Failed to update vendor', err);
        res.status(500).send({ success: false, message: "Failed to update vendor" });
    }
});

app.delete("/vendors/:id", verifyToken, verifyAdmin, validateObjectId('id'), validate([
    param('id').isMongoId().withMessage('Invalid ID'),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const vendorsCollection = db.collection('vendors');
        const doc = await vendorsCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).send({ success: false, message: "Vendor not found" });

        // FIX #48 — Audit log
        await recordAudit({
            db, req,
            action: "DELETE_VENDOR",
            collectionName: "vendors",
            documentId: doc._id,
            oldDoc: doc,
            reason: req.body?.reason?.trim() || "",
        });

        const result = await vendorsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        res.send({ success: true, deletedCount: result.deletedCount });
    } catch (err) {
        logger.error('Failed to delete vendor', err);
        res.status(500).send({ success: false, message: "Failed to delete vendor" });
    }
});

// ═══════════════════════════════════════════════════════════════════
// Vehicles
// ═══════════════════════════════════════════════════════════════════

app.get("/vehicles/search", verifyToken, verifyNonVendor, async (req, res) => {
    try {
        const db = await connectDB();
        const vendorsCollection = db.collection('vendors');
        // FIX #3 — escape regex input
        const search = escapeRegex(req.query.search?.trim() || "");
        if (!search) return res.send([]);
        const result = await vendorsCollection.aggregate([
            { $unwind: "$vehicles" },
            { $match: { "vehicles.vehicleNumber": { $regex: search, $options: "i" } } },
            {
                $project: {
                    _id: 0,
                    vendorName: 1,
                    vendorPhone: 1,
                    vehicleNumber: "$vehicles.vehicleNumber",
                    driverName: "$vehicles.driverName",
                    driverPhone: "$vehicles.driverPhone",
                }
            },
            { $limit: 10 }
        ]).toArray();
        res.send(result);
    } catch (err) {
        logger.error('Vehicle search failed', err);
        res.status(500).send({ success: false, message: "Server Error" });
    }
});

app.post("/vehicles", verifyToken, verifyNonVendor, validate([
    body('vendorId').isMongoId().withMessage('Invalid vendor ID'),
    body('vehicleNumber').trim().notEmpty().withMessage('Vehicle number required'),
    body('driverName').trim().notEmpty().withMessage('Driver name required'),
    body('driverPhone').trim().notEmpty().withMessage('Driver phone required'),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const vendorsCollection = db.collection('vendors');
        const { vendorId, ...vehicleData } = req.body;

        // ── Duplicate guard: vehicleNumber unique হওয়া দরকার (case-insensitive)।
        //    Delivery planner-এর autocomplete আর trip-এর vehicleImg attach
        //    দুটোই vehicleNumber match-এর উপর চলে — duplicate থাকলে ভুল
        //    vendor/driver auto-fill হয়ে যেতে পারত।
        const vNum = String(vehicleData.vehicleNumber || '').trim();
        const dup = await vendorsCollection.findOne(
            { "vehicles.vehicleNumber": { $regex: `^${escapeRegex(vNum)}$`, $options: 'i' } },
            { projection: { vendorName: 1 } }
        );
        if (dup) {
            return res.status(409).send({
                success: false,
                message: `Vehicle "${vNum}" already exists under vendor "${dup.vendorName}"`,
            });
        }

        const result = await vendorsCollection.updateOne(
            { _id: new ObjectId(vendorId) },
            { $push: { vehicles: { _id: new ObjectId(), ...vehicleData, vehicleNumber: vNum, createdAt: new Date() } } }
        );
        if (result.modifiedCount > 0) {
            res.send({ success: true, insertedId: true });
        } else {
            res.status(404).send({ success: false, message: "Vendor not found" });
        }
    } catch (err) {
        logger.error('Failed to add vehicle', err);
        res.status(500).send({ success: false, message: "Failed to add vehicle" });
    }
});

// ── FIX: Duplicate route ছিল (line 1686 + 1747) — merged into one ──
// প্রথমটা: partial update + vehicles.$  (positional operator)
// দ্বিতীয়টা: full replace + arrayFilters (more precise, MongoDB recommended)
// Merged: partial update (undefined skip) + arrayFilters + driverImg support
app.put("/vehicles/:vendorId/:vehicleId", verifyToken, verifyNonVendor,
    validateObjectId('vendorId'),
    validateObjectId('vehicleId'),
    async (req, res) => {
        try {
            const db = await connectDB();
            const vendorsCollection = db.collection('vendors');
            const { vendorId, vehicleId } = req.params;
            const { vehicleModel, vehicleNumber, driverName, driverPhone, driverImg, vehicleImg } = req.body;

            // Partial update — undefined field পাঠালে overwrite হবে না
            const updateFields = {};
            if (vehicleModel !== undefined) updateFields["vehicles.$[elem].vehicleModel"] = vehicleModel;
            if (vehicleNumber !== undefined) updateFields["vehicles.$[elem].vehicleNumber"] = vehicleNumber;
            if (driverName !== undefined) updateFields["vehicles.$[elem].driverName"] = driverName;
            if (driverPhone !== undefined) updateFields["vehicles.$[elem].driverPhone"] = driverPhone;
            if (driverImg !== undefined) updateFields["vehicles.$[elem].driverImg"] = driverImg;
            if (vehicleImg !== undefined) updateFields["vehicles.$[elem].vehicleImg"] = vehicleImg;

            if (Object.keys(updateFields).length === 0) {
                return res.status(400).send({ success: false, message: "No fields to update" });
            }

            const result = await vendorsCollection.updateOne(
                { _id: new ObjectId(vendorId) },
                { $set: updateFields },
                { arrayFilters: [{ "elem._id": new ObjectId(vehicleId) }] }
            );

            if (result.modifiedCount > 0) {
                res.send({ success: true, modifiedCount: 1 });
            } else {
                res.status(404).send({ success: false, message: "Vehicle not found" });
            }
        } catch (err) {
            logger.error('Failed to update vehicle', err);
            res.status(500).send({ success: false, message: "Failed to update vehicle" });
        }
    }
);

app.delete("/vehicles/:vendorId/:vehicleId", verifyToken, verifyNonVendor,
    validateObjectId('vendorId'),
    validateObjectId('vehicleId'),
    async (req, res) => {
        try {
            const db = await connectDB();
            const vendorsCollection = db.collection('vendors');
            const { vendorId, vehicleId } = req.params;
            const result = await vendorsCollection.updateOne(
                { _id: new ObjectId(vendorId) },
                { $pull: { vehicles: { _id: new ObjectId(vehicleId) } } }
            );
            if (result.modifiedCount > 0) {
                res.send({ success: true, deletedCount: 1 });
            } else {
                res.status(404).send({ success: false, message: "Vehicle or Vendor not found" });
            }
        } catch (err) {
            logger.error('Failed to delete vehicle', err);
            res.status(500).send({ success: false, message: "Failed to delete vehicle" });
        }
    }
);



// ═══════════════════════════════════════════════════════════════════
// Deliveries
// ═══════════════════════════════════════════════════════════════════

app.post("/deliveries", verifyToken, verifyNonVendor, validate([
    body().isArray({ min: 1 }).withMessage('At least one delivery required'),
    body('*.vehicleNumber').trim().notEmpty().withMessage('Vehicle number required'),
    body('*.driverName').trim().notEmpty().withMessage('Driver name required'),
    body('*.customerName').trim().notEmpty().withMessage('Customer name required'),
    body('*.products').isArray({ min: 1 }).withMessage('Products required'),
]), async (req, res) => {
    const deliveries = req.body;
    if (!Array.isArray(deliveries) || deliveries.length === 0) {
        return res.status(400).send({ success: false, message: "No deliveries provided" });
    }

    const { db } = await getConnection();
    const deliveriesCollection = db.collection('deliveries');
    const challanCollection = db.collection('challans');
    const counterCollection = db.collection('counters');

    // ── FIX: Race-safe atomic claim pattern ────────────────────────
    // আগের bug: Step 2 read-then-write race — দুটো concurrent request
    //           একই challan-এর জন্য দুটো trip তৈরি করে দিতে পারত।
    // এখন: MongoDB-এর atomic updateMany ব্যবহার করে "claim" করি।
    //      `status: { $ne: 'delivered' }` filter দিয়ে updateMany করলে
    //      MongoDB শুধু সেই docs-ই update করে যেগুলো সত্যি pending।
    //      দুটো request একসাথে এলে শুধু একজনই matchedCount পাবে।
    //
    // Order:
    //   1) Atomically claim challans (set status=claiming, tripNumber=temp)
    //   2) Verify সবাই claim হয়েছে — না হলে rollback
    //   3) Counter increment + tripNumber generate
    //   4) Insert delivery doc
    //   5) Finalize challan status to 'delivered' with real tripNumber
    //   6) Fail হলে manual rollback (challan status revert + delivery delete)

    let challanIds;
    try {
        challanIds = deliveries.map(d => {
            if (typeof d.challanId === "string" && ObjectId.isValid(d.challanId)) {
                return new ObjectId(d.challanId);
            }
            throw new Error(`Invalid challanId: ${d.challanId}`);
        });
    } catch (err) {
        return res.status(400).send({ success: false, message: err.message });
    }

    // Unique check — একই request-এ duplicate challanId এলে বাতিল করো
    const uniqueIds = new Set(challanIds.map(id => id.toString()));
    if (uniqueIds.size !== challanIds.length) {
        return res.status(400).send({ success: false, message: "Duplicate challan IDs in request" });
    }

    // Temp claim token — concurrent request distinguish করতে
    const claimToken = `claim_${new ObjectId().toString()}`;
    let tripNumber = null;
    let insertedDeliveryId = null;
    let claimedSuccessfully = false;

    // ── Return-pending lookup ────────────────────────────────────────
    // Challans created from a Trip-Details "Product Return" carry
    // status "return-pending". When those are dispatched again they
    // should finalize to "re-delivered" (not "delivered") so the
    // All-Challan / Delivered pages can distinguish a first delivery
    // from a re-delivery of a returned item.
    let returnPendingIdSet = new Set();
    try {
        const preStatusDocs = await challanCollection
            .find({ _id: { $in: challanIds } })
            .project({ status: 1 })
            .toArray();
        returnPendingIdSet = new Set(
            preStatusDocs.filter(d => d.status === 'return-pending').map(d => d._id.toString())
        );
    } catch (err) {
        logger.error('Pre-claim status lookup failed', err);
    }

    try {
        // ── FIX #54: আগের কোনো crashed request-এর আটকে থাকা claim ছাড়ো ──
        await releaseStaleClaims(challanCollection, challanIds);

        // ── Step 1: Atomic claim ───────────────────────────────────────
        // শুধু সেই challan গুলোই claim হবে যেগুলো:
        //   - exist করে (matched in $in)
        //   - status delivered/re-delivered না (অথবা status field-ই নেই)
        //   - কোনো claim token attached না (অন্য concurrent request পেন্ডিং না)
        const claimResult = await challanCollection.updateMany(
            {
                _id: { $in: challanIds },
                status: { $nin: ['delivered', 're-delivered'] },
                claimToken: { $exists: false },
            },
            {
                $set: { claimToken, claimedAt: new Date() },
            }
        );
        claimedSuccessfully = true;

        // ── Step 2: Verify সবাই claim হয়েছে কিনা ───────────────────────
        if (claimResult.matchedCount !== challanIds.length) {
            // কেউ-কেউ claim হয়নি — already delivered, missing, বা race-এ অন্য request পেয়েছে
            // আমরা যা claim করেছিলাম সেগুলো release করি
            await challanCollection.updateMany(
                { _id: { $in: challanIds }, claimToken },
                { $unset: { claimToken: "", claimedAt: "" } }
            );
            claimedSuccessfully = false;

            // Diagnostic: কোন challan গুলো problem তা ক্লায়েন্টকে জানাই
            const conflictDocs = await challanCollection
                .find({ _id: { $in: challanIds } })
                .project({ customerName: 1, status: 1 })
                .toArray();

            const foundIds = new Set(conflictDocs.map(d => d._id.toString()));
            const missing = challanIds.filter(id => !foundIds.has(id.toString()));
            const alreadyDelivered = conflictDocs.filter(d => d.status === 'delivered' || d.status === 're-delivered');
            const lockedByOther = conflictDocs.filter(d => d.status !== 'delivered' && d.status !== 're-delivered'); // claim token দখলে

            if (alreadyDelivered.length > 0) {
                return res.status(400).send({
                    success: false,
                    code: 'ALREADY_DELIVERED',
                    message: `Already delivered: ${alreadyDelivered.map(c => c.customerName).join(", ")}`,
                    items: alreadyDelivered.map(c => ({ id: c._id, customerName: c.customerName })),
                });
            }
            if (missing.length > 0) {
                return res.status(404).send({
                    success: false,
                    code: 'CHALLAN_NOT_FOUND',
                    message: `Challan(s) not found: ${missing.length}`,
                    items: missing,
                });
            }
            // race condition — অন্য concurrent request claim করেছে
            return res.status(409).send({
                success: false,
                code: 'CONCURRENT_DELIVERY',
                message: 'Another delivery is being processed for these challans. Please try again.',
                items: lockedByOther.map(c => ({ id: c._id, customerName: c.customerName })),
            });
        }

        // ── Step 3: Counter increment + tripNumber ─────────────────────
        const counter = await counterCollection.findOneAndUpdate(
            { _id: "tripNumber" },
            { $inc: { seq: 1 } },
            { upsert: true, returnDocument: "after" }
        );
        const seq = counter?.seq ?? counter?.value?.seq;
        if (!seq || typeof seq !== 'number') throw new Error('Counter generation failed');
        tripNumber = `TR-${seq.toString().padStart(6, "0")}`;

        // ── Step 4: Insert delivery doc ────────────────────────────────
        const tripDocument = {
            tripNumber,
            vehicleNumber: deliveries[0].vehicleNumber,
            vendorName: deliveries[0].vendorName,
            vendorNumber: deliveries[0].vendorNumber,
            driverName: deliveries[0].driverName,
            driverNumber: deliveries[0].driverNumber,
            createdBy: deliveries[0].createdBy || req.user?.email || "unknown",
            totalChallan: deliveries.length,
            challans: deliveries.map(d => ({
                challanId: d.challanId,
                customerName: d.customerName,
                zone: d.zone,
                address: d.address,
                thana: d.thana,
                district: d.district,
                // location saved alongside the challan snapshot so the Delivered
                // page's rate-matcher fallback can resolve rates for products
                // whose capacity/rate weren't yet saved on the original challan.
                location: d.location || null,
                // Remarks — admin-only note set on the AllChallan page.
                // Snapshotted here so the Delivered page can show it
                // without needing to look the original challan back up.
                remarks: typeof d.remarks === 'string' ? d.remarks : '',
                receiverNumber: d.receiverNumber,
                // Marks this snapshot as a re-delivery of a previously
                // returned item — the Delivered page shows "Re-Delivered"
                // in the Type column for these rows.
                isReDelivery: returnPendingIdSet.has(String(d.challanId)),
                products: (d.products || []).map(p => {
                    // FIX #50 — snapshot-এ rate server-resolved মান পায়;
                    // client মান শুধু cross-check।
                    const guarded = resolveAuthoritativeRate({
                        productName: p.productName,
                        model: p.model,
                        location: d.location || null,
                        capacity: p.capacity,
                        clientRate: p.rate,
                        logger,
                        context: 'POST /deliveries',
                        userEmail: req.user?.email,
                    });
                    return {
                        _id: p._id || new ObjectId().toString(),
                        productName: p.productName,
                        model: p.model,
                        quantity: Number(p.quantity),
                        capacity: guarded.capacity,
                        rate: guarded.rate,
                        // Trip Do — All-Challan page-এ dispatch-এর আগেই set করা
                        // থাকতে পারে; remarks-এর মতোই snapshot-এ carry হয়, নাহলে
                        // Delivered page-এ গিয়ে হারিয়ে যেত (sync gap)।
                        ...(typeof p.tripDo === 'string' && p.tripDo.trim() ? { tripDo: p.tripDo.trim() } : {}),
                    };
                })
            })),
            createdAt: new Date()
        };
        const result = await deliveriesCollection.insertOne(tripDocument);
        insertedDeliveryId = result.insertedId;

        // ── Step 5: Finalize challan status (claim → delivered / re-delivered) ───────
        // claimToken filter দিয়ে নিশ্চিত করি যে শুধু আমাদের claim করা docs-ই update হবে.
        // Challans that were "return-pending" finalize to "re-delivered";
        // everything else finalizes to the normal "delivered".
        const returnPendingChallanIds = challanIds.filter(id => returnPendingIdSet.has(id.toString()));
        const regularChallanIds = challanIds.filter(id => !returnPendingIdSet.has(id.toString()));

        let finalizedCount = 0;
        if (regularChallanIds.length > 0) {
            const r = await challanCollection.updateMany(
                { _id: { $in: regularChallanIds }, claimToken },
                {
                    $set: { status: "delivered", tripNumber },
                    $unset: { claimToken: "", claimedAt: "" },
                }
            );
            finalizedCount += r.matchedCount;
        }
        if (returnPendingChallanIds.length > 0) {
            const r = await challanCollection.updateMany(
                { _id: { $in: returnPendingChallanIds }, claimToken },
                {
                    $set: { status: "re-delivered", tripNumber },
                    $unset: { claimToken: "", claimedAt: "" },
                }
            );
            finalizedCount += r.matchedCount;
        }

        if (finalizedCount !== challanIds.length) {
            // সাধারণত এটা hit হবে না (claim আমাদের লক ছিল), কিন্তু safety
            throw new Error('Failed to finalize all challans');
        }

        return res.send({
            success: true,
            insertedId: result.insertedId,
            tripNumber,
            totalChallan: deliveries.length
        });

    } catch (err) {
        logger.error("Delivery failed", err, { tripNumber, claimToken });

        // ── Manual Rollback ──────────────────────────────────────────
        // Step 4/5 fail হলে: claim release + delivery delete
        if (insertedDeliveryId) {
            try {
                await deliveriesCollection.deleteOne({ _id: insertedDeliveryId });
            } catch (rollbackErr) {
                logger.error('Delivery doc rollback FAILED', { tripNumber, rollbackErr });
            }
        }
        if (claimedSuccessfully) {
            try {
                await challanCollection.updateMany(
                    { _id: { $in: challanIds }, claimToken },
                    {
                        $unset: { claimToken: "", claimedAt: "", tripNumber: "" },
                        // status delivered হয়ে গেলেও revert — কিন্তু শুধু আমাদের tripNumber হলে
                        // (অন্য কারো success-কে ভাঙব না)
                    }
                );
                // status revert আলাদা — শুধু আমাদের trip-এর জন্য।
                // যেসব challan return-pending ছিল, সেগুলো আবার
                // return-pending-এ ফিরবে; বাকিগুলো plain pending-এ।
                if (tripNumber) {
                    const revertReturnPendingIds = challanIds.filter(id => returnPendingIdSet.has(id.toString()));
                    const revertRegularIds = challanIds.filter(id => !returnPendingIdSet.has(id.toString()));
                    if (revertRegularIds.length > 0) {
                        await challanCollection.updateMany(
                            { _id: { $in: revertRegularIds }, tripNumber },
                            { $set: { status: "pending" }, $unset: { tripNumber: "" } }
                        );
                    }
                    if (revertReturnPendingIds.length > 0) {
                        await challanCollection.updateMany(
                            { _id: { $in: revertReturnPendingIds }, tripNumber },
                            { $set: { status: "return-pending" }, $unset: { tripNumber: "" } }
                        );
                    }
                }
                logger.info('Delivery rollback successful', { tripNumber });
            } catch (rollbackErr) {
                logger.error('Challan rollback FAILED — manual fix needed', { tripNumber, claimToken, rollbackErr });
            }
        }

        // FIX #55 — internal error details client-কে leak করা হয় না
        return res.status(500).send({
            success: false,
            message: "Delivery failed. Please try again.",
        });
    }
});

app.get("/deliveries", verifyToken, verifyApproved, async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        let month = parseInt(req.query.month);
        let year = parseInt(req.query.year);
        // FIX #3 — escape regex
        const search = escapeRegex(req.query.search || "");
        let query = {};
        const isVendor = req.user?.role === 'vendor';
        // Trip-level note is admin/manager/operator-only. Vendors must
        // never receive it in the API response — strip it at the query
        // level (not just hidden client-side) so a direct API call from
        // a vendor account can't see it either.
        const projection = isVendor ? { tripNote: 0, tripNoteUpdatedAt: 0, tripNoteUpdatedBy: 0 } : undefined;

        // Attach vehicleImg (from vendor vehicles, matched by vehicleNumber) so
        // list pages can show a vehicle photo. Trip docs store only the number.
        const attachVehicleImg = async (rows) => {
            try {
                const numbers = [...new Set(rows.map(r => (r.vehicleNumber || "").trim().toLowerCase()).filter(Boolean))];
                if (numbers.length === 0) return rows;
                const vendorsCol = db.collection('vendors');
                const vendorDocs = await vendorsCol.find(
                    {}, { projection: { "vehicles.vehicleNumber": 1, "vehicles.vehicleImg": 1 } }
                ).toArray();
                const imgMap = new Map();
                for (const vd of vendorDocs) {
                    for (const v of (vd.vehicles || [])) {
                        const key = (v.vehicleNumber || "").trim().toLowerCase();
                        if (key && v.vehicleImg && !imgMap.has(key)) imgMap.set(key, v.vehicleImg);
                    }
                }
                return rows.map(r => {
                    const key = (r.vehicleNumber || "").trim().toLowerCase();
                    return imgMap.has(key) ? { ...r, vehicleImg: imgMap.get(key) } : r;
                });
            } catch (e) {
                logger.error("attachVehicleImg (deliveries) failed", e);
                return rows;
            }
        };

        if (search) {
            // Global search — পুরো collection, limit 500
            query.$or = [
                { tripNumber: { $regex: search, $options: "i" } },
                { vendorName: { $regex: search, $options: "i" } },
                { driverName: { $regex: search, $options: "i" } },
                { vehicleNumber: { $regex: search, $options: "i" } },
                { "challans.customerName": { $regex: search, $options: "i" } },
                { "challans.zone": { $regex: search, $options: "i" } },
                { "challans.address": { $regex: search, $options: "i" } },
                { "challans.receiverNumber": { $regex: search, $options: "i" } },
                { "challans.district": { $regex: search, $options: "i" } },
                { "challans.thana": { $regex: search, $options: "i" } },
                { "challans.products.productName": { $regex: search, $options: "i" } },
                { "challans.products.model": { $regex: search, $options: "i" } },
            ];

            // Vendor filter — search এও apply হবে
            if (isVendor) {
                const userCollection = db.collection('users');
                const me = await userCollection.findOne({ email: req.user.email });
                if (!me?.vendorName) return res.send({ success: true, data: [], pagination: { total: 0 } });
                query.vendorName = { $regex: `^${escapeRegex(me.vendorName)}$`, $options: 'i' };
            }

            let data = await deliveriesCollection.find(query, { projection }).sort({ createdAt: -1 }).limit(500).toArray();
            data = await attachVehicleImg(data);
            return res.send({ success: true, data, pagination: { total: data.length } });
        }

        // Month query — no limit, index আছে তাই fast
        if (!month || !year) {
            const _dt = getDhakaCurrentMonthYear();
            month = _dt.month;
            year = _dt.year;
        }
        const { startDate, endDate } = getDhakaMonthRange(year, month);
        query.createdAt = { $gte: startDate, $lt: endDate };

        // FIX #15 — Vendor can only see their trips (double-check via DB)
        if (isVendor) {
            const userCollection = db.collection('users');
            const me = await userCollection.findOne({ email: req.user.email });
            if (!me?.vendorName) return res.send({ success: true, data: [], pagination: { total: 0 } });
            query.vendorName = { $regex: `^${escapeRegex(me.vendorName)}$`, $options: 'i' };
        }

        let data = await deliveriesCollection.find(query, { projection }).sort({ createdAt: -1 }).toArray();
        data = await attachVehicleImg(data);
        res.send({ success: true, data, pagination: { total: data.length } });
    } catch (err) {
        logger.error('Failed to fetch deliveries', err);
        res.status(500).send({ success: false, message: "Failed to fetch deliveries" });
    }
});

/* ── GET /deliveries/single/:tripId ──────────────────────────────────
   Fetch ONE trip by its _id — used by the Trip Details page (/trip/:id).
   আগে client-কে trip খুঁজতে ৬ মাসের সব deliveries download করতে হতো
   (up to 6 requests, হাজার হাজার doc) — এখন এক query-তেই কাজ হয়।
   Path-এ "/single/" রাখা হয়েছে যাতে "/deliveries/bulk-export"-এর মতো
   static route-এর সাথে conflict না হয়।
   Security: same rules as GET /deliveries —
     • vendor হলে শুধু নিজের vendorName-এর trip দেখতে পারবে
     • vendor-দের response থেকে tripNote strip হয়
   vehicleImg-ও attach হয় (list page-এর মতোই)। */
app.get("/deliveries/single/:tripId", verifyToken, verifyApproved, validateObjectId('tripId'), async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        const isVendor = req.user?.role === 'vendor';
        const projection = isVendor ? { tripNote: 0, tripNoteUpdatedAt: 0, tripNoteUpdatedBy: 0 } : undefined;

        const trip = await deliveriesCollection.findOne(
            { _id: new ObjectId(req.params.tripId) },
            projection ? { projection } : undefined
        );
        if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });

        // Vendor ownership check — নিজের trip না হলে 404 (existence leak এড়াতে 403 নয়)
        if (isVendor) {
            const me = await db.collection('users').findOne({ email: req.user.email });
            const mine = me?.vendorName &&
                String(trip.vendorName || "").trim().toLowerCase() === String(me.vendorName).trim().toLowerCase();
            if (!mine) return res.status(404).send({ success: false, message: "Trip not found" });
        }

        // vehicleImg attach (vendors collection থেকে, vehicleNumber match করে)
        try {
            const key = (trip.vehicleNumber || "").trim().toLowerCase();
            if (key) {
                const vendorDoc = await db.collection('vendors').findOne(
                    { "vehicles.vehicleNumber": { $regex: `^${escapeRegex(trip.vehicleNumber.trim())}$`, $options: 'i' } },
                    { projection: { "vehicles.vehicleNumber": 1, "vehicles.vehicleImg": 1 } }
                );
                const v = (vendorDoc?.vehicles || []).find(x => (x.vehicleNumber || "").trim().toLowerCase() === key && x.vehicleImg);
                if (v) trip.vehicleImg = v.vehicleImg;
            }
        } catch (e) { logger.error("attachVehicleImg (single trip) failed", e); }

        res.send({ success: true, data: trip });
    } catch (err) {
        logger.error('Failed to fetch single trip', err);
        res.status(500).send({ success: false, message: "Failed to fetch trip" });
    }
});

app.patch("/deliveries/confirm", verifyToken, verifyNonVendor, async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        const { tripNumber, challanId, status, note, operator } = req.body;
        const result = await deliveriesCollection.updateOne(
            { tripNumber, "challans.challanId": String(challanId) },
            {
                $set: {
                    "challans.$.deliveryStatus": status,
                    "challans.$.operatorNote": note || "",
                    "challans.$.confirmedBy": operator,
                    "challans.$.confirmedAt": new Date()
                }
            }
        );
        res.send({ success: true, modifiedCount: result.modifiedCount });
    } catch (err) {
        logger.error('Confirm failed', err);
        res.status(500).send({ success: false, message: "Confirm failed" });
    }
});

app.patch("/deliveries/challan-return", verifyToken, verifyNonVendor, async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        const { tripNumber, challanId, status, operator } = req.body;
        const result = await deliveriesCollection.updateOne(
            { tripNumber, "challans.challanId": String(challanId) },
            {
                $set: {
                    "challans.$.challanReturnStatus": status,
                    "challans.$.challanReturnedAt": new Date(),
                    "challans.$.challanReceivedBy": operator
                }
            }
        );
        res.send({ success: true, modifiedCount: result.modifiedCount });
    } catch (err) {
        logger.error('Challan return update failed', err);
        res.status(500).send({ success: false, message: "Challan return update failed" });
    }
});

app.patch("/deliveries/:tripId/challan/:challanId", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        const { tripId, challanId } = req.params;
        const { customerName, address, thana, district, receiverNumber, zone, location, updatedBy } = req.body;

        // Build the $set patch.  `location` is recomputed client-side from the
        // (possibly edited) thana + district and sent along so the Delivered
        // page's Location column + downstream rate resolution stay in sync.
        // Only set it when the client actually supplied a value so a partial
        // edit can't accidentally wipe an existing location.
        const setPatch = {
            "challans.$.customerName": customerName,
            "challans.$.address": address,
            "challans.$.thana": thana,
            "challans.$.district": district,
            "challans.$.receiverNumber": receiverNumber,
            "challans.$.zone": zone,
            lastUpdatedBy: updatedBy || req.user?.email || null,
            lastUpdatedAt: new Date(),
        };
        if (typeof location === 'string') {
            setPatch["challans.$.location"] = location;
        }

        const result = await deliveriesCollection.updateOne(
            { _id: new ObjectId(tripId), "challans.challanId": challanId },
            { $set: setPatch }
        );
        if (result.matchedCount === 0)
            return res.status(404).send({ success: false, message: "Challan not found in trip" });

        const updated = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
        res.send({ success: true, data: updated });
    } catch (err) {
        logger.error("Edit trip challan failed", err);
        res.status(500).send({ success: false, message: "Failed to update challan" });
    }
});

app.patch("/deliveries/:tripId/challan/:challanId/product/:productId", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        const { tripId, challanId, productId } = req.params;
        const { productName, model, quantity, capacity, rate, updatedBy, splitLeftover } = req.body;

        const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
        if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });

        // FIX (A12): Defensive — challans/products undefined হলে .findIndex throws
        if (!Array.isArray(trip.challans)) {
            return res.status(400).send({ success: false, message: "Trip has no challans" });
        }
        const challanIndex = trip.challans.findIndex(c => c.challanId === challanId);
        if (challanIndex === -1) return res.status(404).send({ success: false, message: "Challan not found" });

        const challanProducts = trip.challans[challanIndex].products;
        if (!Array.isArray(challanProducts)) {
            return res.status(400).send({ success: false, message: "Challan has no products" });
        }
        const productIndex = challanProducts.findIndex(p => p._id === productId);
        if (productIndex === -1) return res.status(404).send({ success: false, message: "Product not found" });

        const updateField = `challans.${challanIndex}.products.${productIndex}`;
        const setPatch = {
            [`${updateField}.productName`]: productName,
            [`${updateField}.model`]: model,
            [`${updateField}.quantity`]: Number(quantity),
            lastUpdatedBy: updatedBy || req.user?.email || null,
            lastUpdatedAt: new Date(),
        };
        // FIX #50 — capacity/rate client পাঠালে server নিজে rate table থেকে
        // resolve করে save করে; location আসে trip-এর challan snapshot থেকে।
        // Quantity-only edit-এ (capacity/rate না পাঠালে) আগের মান অক্ষত থাকে।
        if (typeof capacity === 'string' || (rate !== undefined && rate !== null && rate !== '')) {
            const guarded = resolveAuthoritativeRate({
                productName, model,
                location: trip.challans[challanIndex]?.location || null,
                capacity,
                clientRate: rate,
                logger,
                context: 'PATCH /deliveries/:t/challan/:c/product/:p',
                userEmail: req.user?.email,
            });
            setPatch[`${updateField}.capacity`] = guarded.capacity;
            setPatch[`${updateField}.rate`] = guarded.rate;
        }

        const result = await deliveriesCollection.updateOne(
            { _id: new ObjectId(tripId) },
            { $set: setPatch }
        );

        // ── Leftover split (opt-in — Trip-Details Edit-Challan modal) ──
        // quantity কমালে (৫ → ২) কমে যাওয়া অংশ (৩) নতুন pending challan
        // হয়ে All-Challan-এ ফিরে যায় — next delivery-র জন্য available।
        // পাশাপাশি canonical challans doc-এর ওই product-এর qty-ও নতুন
        // মানে নামানো হয়, নাহলে delivered qty + pending leftover মিলে
        // মোট সংখ্যা ফুলে যেত (gate-pass matching-ও ভুল হতো)।
        let leftover = null;
        if (splitLeftover === true) {
            try {
                const oldProduct = challanProducts[productIndex];
                const oldQty = Number(oldProduct?.quantity) || 0;
                const newQty = Number(quantity) || 0;
                const diff = oldQty - newQty;
                if (diff > 0) {
                    const snap = trip.challans[challanIndex];
                    leftover = await spawnLeftoverChallan(db, {
                        sourceChallanId: challanId,
                        sourceInfo: {
                            customerName: snap.customerName,
                            receiverNumber: snap.receiverNumber,
                            zone: snap.zone,
                            address: snap.address,
                            thana: snap.thana,
                            district: snap.district,
                            location: snap.location || undefined,
                            remarks: snap.remarks,
                            csd: snap.csd,
                            unit: snap.unit,
                        },
                        leftoverProducts: [{
                            productName: oldProduct.productName || productName || '',
                            model: oldProduct.model || model || '',
                            quantity: diff,
                            ...(oldProduct.capacity ? { capacity: oldProduct.capacity } : {}),
                            ...(oldProduct.rate !== undefined && oldProduct.rate !== null ? { rate: oldProduct.rate } : {}),
                            ...(typeof oldProduct.tripDo === 'string' && oldProduct.tripDo.trim() ? { tripDo: oldProduct.tripDo.trim() } : {}),
                            sourceProductId: String(oldProduct._id || productId),
                        }],
                        createdBy: updatedBy || req.user?.email || 'unknown',
                    });

                    // Canonical challans doc mirror — একই product-এর qty কমানো
                    if (isValidObjectId(challanId)) {
                        await db.collection('challans').updateOne(
                            { _id: new ObjectId(challanId) },
                            {
                                $set: {
                                    "products.$[el].quantity": newQty,
                                    lastUpdatedBy: updatedBy || req.user?.email || 'unknown',
                                    lastUpdatedAt: new Date(),
                                },
                            },
                            { arrayFilters: [{ "el._id": String(oldProduct._id || productId) }] }
                        ).catch(() => { /* best-effort */ });
                    }
                }
            } catch (splitErr) {
                logger.error('Leftover split failed (PATCH trip product)', splitErr);
            }
        }

        res.send({ success: true, modifiedCount: result.modifiedCount, ...(leftover ? { leftover } : {}) });
    } catch (err) {
        logger.error("Edit trip product failed", err);
        res.status(500).send({ success: false, message: "Failed to update product" });
    }
});

app.delete("/deliveries/:tripId/challan/:challanId/product/:productId", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        const { tripId, challanId, productId } = req.params;

        const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
        if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });

        // FIX (A12): Defensive
        if (!Array.isArray(trip.challans)) {
            return res.status(400).send({ success: false, message: "Trip has no challans" });
        }
        const challanIndex = trip.challans.findIndex(c => c.challanId === challanId);
        if (challanIndex === -1) return res.status(404).send({ success: false, message: "Challan not found" });

        const challanProducts = trip.challans[challanIndex].products;
        if (!Array.isArray(challanProducts) || challanProducts.length <= 1)
            return res.status(400).send({ success: false, message: "Cannot remove last product" });

        // Split flow-এর জন্য মুছে-যাওয়া product-টা আগে ধরে রাখি
        const removedProduct = challanProducts.find(p => String(p._id) === String(productId));

        const result = await deliveriesCollection.updateOne(
            { _id: new ObjectId(tripId) },
            { $pull: { [`challans.${challanIndex}.products`]: { _id: productId } } }
        );

        // ── Leftover split (opt-in — ?splitLeftover=1) ─────────────────
        // Trip-Details Edit-Challan modal থেকে row remove করলে সেই product
        // পুরো qty সহ নতুন pending challan হয়ে All-Challan-এ ফিরে যায়।
        // canonical challans doc থেকেও row টা সরানো হয় (delivered হিসেব
        // থেকে বাদ), যাতে delivered + pending মিলে মোট qty ঠিক থাকে।
        let leftover = null;
        const wantSplit = String(req.query?.splitLeftover || '') === '1';
        if (wantSplit && result.modifiedCount > 0 && removedProduct) {
            try {
                const snap = trip.challans[challanIndex];
                leftover = await spawnLeftoverChallan(db, {
                    sourceChallanId: challanId,
                    sourceInfo: {
                        customerName: snap.customerName,
                        receiverNumber: snap.receiverNumber,
                        zone: snap.zone,
                        address: snap.address,
                        thana: snap.thana,
                        district: snap.district,
                        location: snap.location || undefined,
                        remarks: snap.remarks,
                        csd: snap.csd,
                        unit: snap.unit,
                    },
                    leftoverProducts: [{
                        productName: removedProduct.productName || '',
                        model: removedProduct.model || '',
                        quantity: Number(removedProduct.quantity) || 0,
                        ...(removedProduct.capacity ? { capacity: removedProduct.capacity } : {}),
                        ...(removedProduct.rate !== undefined && removedProduct.rate !== null ? { rate: removedProduct.rate } : {}),
                        ...(typeof removedProduct.tripDo === 'string' && removedProduct.tripDo.trim() ? { tripDo: removedProduct.tripDo.trim() } : {}),
                        sourceProductId: String(removedProduct._id || productId),
                    }],
                    createdBy: req.user?.email || 'unknown',
                });

                // Canonical challans doc mirror — row remove (last product হলে skip)
                if (isValidObjectId(challanId)) {
                    const canon = await db.collection('challans').findOne(
                        { _id: new ObjectId(challanId) },
                        { projection: { "products._id": 1 } }
                    );
                    if (Array.isArray(canon?.products) && canon.products.length > 1 &&
                        canon.products.some(p => String(p._id) === String(productId))) {
                        await db.collection('challans').updateOne(
                            { _id: new ObjectId(challanId) },
                            {
                                $pull: { products: { _id: String(productId) } },
                                $set: { lastUpdatedBy: req.user?.email || 'unknown', lastUpdatedAt: new Date() },
                            }
                        ).catch(() => { /* best-effort */ });
                    }
                }
            } catch (splitErr) {
                logger.error('Leftover split failed (DELETE trip product)', splitErr);
            }
        }

        res.send({ success: true, modifiedCount: result.modifiedCount, ...(leftover ? { leftover } : {}) });
    } catch (err) {
        logger.error("Delete trip product failed", err);
        res.status(500).send({ success: false, message: "Failed to delete product" });
    }
});

// ─────────────────────────────────────────────────────────────────────
//  Hide a single row from the Delivered page ONLY.
//
//  "Row" on the Delivered page = one product line inside one challan
//  inside one trip (deliveries document). The SAME `deliveries`
//  documents are also read by the Trip Inventory page (and its trip
//  details modal), so we must NOT physically delete anything from the
//  document — that would remove the row from Trip Inventory too.
//
//  Instead this endpoint sets `hiddenFromDelivered: true` on just that
//  one product. The Delivered page's row-builder filters out any
//  product with this flag, so the row disappears there — while Trip
//  Inventory (which doesn't check this flag) keeps showing it exactly
//  as before.
//
//  IMPORTANT — isolation guarantee:
//    - Never touches the `challans` collection (canonical challan
//      records used by AllChallan / billing / status).
//    - Never removes anything from the `deliveries` document either —
//      it only sets a flag, so Trip Inventory / trip details are 100%
//      unaffected.
// ─────────────────────────────────────────────────────────────────────
app.patch("/deliveries/:tripId/row/:challanId/:productId/hide", verifyToken, verifyAdmin, validateObjectId('tripId'), async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        const { tripId, challanId, productId } = req.params;

        const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
        if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });

        if (!Array.isArray(trip.challans) || trip.challans.length === 0) {
            return res.status(400).send({ success: false, message: "Trip has no challans" });
        }
        const challanIndex = trip.challans.findIndex(c =>
            c.challanId === challanId || c.challanId?.toString() === challanId
        );
        if (challanIndex === -1) return res.status(404).send({ success: false, message: "Challan not found" });

        const challanProducts = Array.isArray(trip.challans[challanIndex].products) ? trip.challans[challanIndex].products : [];
        const productIndex = challanProducts.findIndex(p => p._id === productId || p._id?.toString() === productId);
        if (productIndex === -1) return res.status(404).send({ success: false, message: "Product row not found" });

        await recordAudit({
            db, req,
            action: "HIDE_DELIVERED_ROW",
            collectionName: "deliveries",
            documentId: trip._id,
            oldDoc: {
                tripNumber: trip.tripNumber,
                challanId: trip.challans[challanIndex].challanId,
                customerName: trip.challans[challanIndex].customerName,
                hiddenProduct: challanProducts[productIndex],
            },
            reason: req.body?.reason?.trim() || "",
        });

        const result = await deliveriesCollection.updateOne(
            { _id: new ObjectId(tripId) },
            { $set: { [`challans.${challanIndex}.products.${productIndex}.hiddenFromDelivered`]: true } }
        );
        res.send({ success: true, modifiedCount: result.modifiedCount });
    } catch (err) {
        logger.error("Hide delivered row failed", err);
        res.status(500).send({ success: false, message: "Failed to delete row" });
    }
});

app.post("/deliveries/:tripId/challan/:challanId/product", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        const { tripId, challanId } = req.params;
        const { productName, model, quantity, capacity, rate } = req.body;

        const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
        if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });

        const challanIndex = trip.challans.findIndex(c =>
            c.challanId === challanId || c.challanId?.toString() === challanId
        );
        if (challanIndex === -1) return res.status(404).send({ success: false, message: "Challan not found" });

        // FIX #50 — rate server-resolved; location parent challan snapshot থেকে
        const guarded = resolveAuthoritativeRate({
            productName, model,
            location: trip.challans[challanIndex]?.location || null,
            capacity,
            clientRate: rate,
            logger,
            context: 'POST /deliveries/:t/challan/:c/product',
            userEmail: req.user?.email,
        });
        const newProduct = {
            _id: new ObjectId().toString(),
            productName,
            model,
            quantity: Number(quantity),
            capacity: guarded.capacity,
            rate: guarded.rate,
        };

        await deliveriesCollection.updateOne(
            { _id: new ObjectId(tripId) },
            { $push: { [`challans.${challanIndex}.products`]: newProduct } }
        );

        // ── Canonical challans doc sync (opt-in) ───────────────────────
        // Trip-Details-এর Edit-Challan modal থেকে নতুন product add করলে
        // সেটা All-Challan-এর canonical challan record-এও যোগ হয় — একই
        // _id সহ, যাতে পরের Trip-Do / gate-sync propagation ঠিকমতো match
        // করে। Best-effort: fail করলেও trip-এ add সফল-ই থাকে।
        if (req.body?.syncChallan === true && isValidObjectId(challanId)) {
            try {
                await db.collection('challans').updateOne(
                    {
                        _id: new ObjectId(challanId),
                        // একই _id-র product আগেই থাকলে duplicate push নয়
                        "products._id": { $ne: newProduct._id },
                    },
                    {
                        $push: { products: { ...newProduct } },
                        $set: {
                            lastUpdatedBy: req.user?.email || 'unknown',
                            lastUpdatedAt: new Date(),
                        },
                    }
                );
            } catch (syncErr) {
                logger.error('Canonical challan product sync failed (POST trip product)', syncErr);
            }
        }

        res.send({ success: true, product: newProduct });
    } catch (err) {
        logger.error("Add trip product failed", err);
        res.status(500).send({ success: false, message: "Failed to add product" });
    }
});

// ─────────────────────────────────────────────────────────────────────
//  Bulk Trip Do assignment
//  ─────────────────────────────────────────────────────────────────
//  Used by the Delivered page to stamp the same `tripDo` value onto
//  many products at once (e.g. user filters down to a set of rows and
//  enters one DO number that applies to all of them).
//
//  Body shape:
//    {
//      tripDo: "4681835",
//      targets: [
//        { challanId, productId },
//        { challanId, productId },
//        ...
//      ]
//    }
//
//  Writes to BOTH collections so the Delivered page (reads `deliveries`)
//  and the canonical challan record (reads `challans`) stay in sync.
//  Empty / null `tripDo` is allowed — it CLEARS the field.
// ─────────────────────────────────────────────────────────────────────
app.patch("/deliveries/bulk-trip-do", verifyToken, verifyRole('admin'), async (req, res) => {
    try {
        const { tripDo, targets } = req.body || {};
        if (!Array.isArray(targets) || targets.length === 0) {
            return res.status(400).send({ success: false, message: "No targets supplied" });
        }
        const clean = String(tripDo ?? "").trim();
        const writeValue = clean.length ? clean : null; // null → unset

        const db = await connectDB();
        const challanCollection = db.collection('challans');
        const deliveriesCollection = db.collection('deliveries');

        // Group targets by challanId for efficient updates
        const byChallan = new Map();
        for (const t of targets) {
            if (!t?.challanId || !t?.productId) continue;
            if (!byChallan.has(t.challanId)) byChallan.set(t.challanId, []);
            byChallan.get(t.challanId).push(t.productId);
        }

        let touched = 0;
        const operations = [];

        for (const [challanId, productIds] of byChallan.entries()) {
            // ── 1. Update challans collection ──
            // Use arrayFilters to update many products in one shot.
            // Return rows use a synthetic challanId like
            // `return_<originalChallanId>_<timestamp>` which is NOT a valid
            // Mongo ObjectId — `new ObjectId(challanId)` would throw for
            // those and abort the whole request (see bulk-csd for the same
            // guard). The canonical `challans` collection only ever holds
            // real (non-return) challans, so just skip step 1 for those.
            if (isValidObjectId(challanId)) {
                operations.push(
                    challanCollection.updateOne(
                        { _id: new ObjectId(challanId) },
                        writeValue === null
                            ? { $unset: { "products.$[el].tripDo": "" } }
                            : { $set: { "products.$[el].tripDo": writeValue } },
                        { arrayFilters: [{ "el._id": { $in: productIds } }] }
                    ).then(r => { touched += r.modifiedCount || 0; })
                );
            }

            // ── 2. Update deliveries collection (embedded copy) ──
            // Same productIds may appear inside any trip's challans[].products.
            // arrayFilters on nested arrays is supported by MongoDB.
            // This is the source of truth for the Delivered page and works
            // for both normal and return rows (matches by string challanId).
            operations.push(
                deliveriesCollection.updateMany(
                    { "challans.challanId": challanId },
                    writeValue === null
                        ? { $unset: { "challans.$[c].products.$[p].tripDo": "" } }
                        : { $set: { "challans.$[c].products.$[p].tripDo": writeValue } },
                    {
                        arrayFilters: [
                            { "c.challanId": challanId },
                            { "p._id": { $in: productIds } },
                        ],
                    }
                ).then(r => { touched += r.modifiedCount || 0; })
            );
        }

        // ── 3. Return-artifact propagation ─────────────────────────────
        // Trip Do বসানোর আগে Return হোক বা Return হওয়ার পর Trip Do বসানো
        // হোক না কেন — return product-এর Trip Do সবসময় re-deliverable
        // "return-pending" challan (challans collection)-এও পৌঁছাতে হবে,
        // কারণ All-Gate-Pass-এর matching ওই collection-ই পড়ে। Return
        // rows-এর synthetic challanId `return_<origId>_<ts>` step 1-এ
        // skip হয়, তাই এখানে আলাদা করে stamp করা হয়:
        //   3a. Return row target → ওই origChallan থেকে জন্মানো pending
        //       challan-এ set/clear (admin সরাসরি return row-এ লিখেছে)
        //   3b. Normal row target → তার return card (deliveries) এবং
        //       derived pending challan-এ শুধু ফাঁকা tripDo গুলো fill হয়
        //       (admin অন্য DO বসিয়ে থাকলে overwrite হয় না; clear
        //       propagate হয় না)
        const RETURN_ID_RE = /^return_(.+)_\d+$/;
        const returnTargets = [];
        const normalTargets = [];
        for (const [challanId, productIds] of byChallan.entries()) {
            const m = RETURN_ID_RE.exec(challanId);
            if (m) returnTargets.push({ origId: m[1], returnChallanId: challanId, productIds });
            else if (isValidObjectId(challanId)) normalTargets.push({ challanId, productIds });
        }

        const tripDoWrite = writeValue === null
            ? { $unset: { "products.$[el].tripDo": "" } }
            : { $set: { "products.$[el].tripDo": writeValue } };
        // model ফাঁকা/missing দুটোই match করাতে
        const modelCond = (model) => (model ? model : { $in: [null, ""] });

        if (returnTargets.length) {
            // Legacy pending challans-এ sourceProductId নেই — name/model
            // fallback-এর জন্য return card-এর products লাগে (এক query-তে)
            const rcIds = returnTargets.map(t => t.returnChallanId);
            const tripsWithCards = await deliveriesCollection.find(
                { "challans.challanId": { $in: rcIds } },
                { projection: { "challans.challanId": 1, "challans.isReturn": 1, "challans.products": 1 } }
            ).toArray();
            const cardMap = new Map(); // returnChallanId → products[]
            for (const t of tripsWithCards) for (const c of (t.challans || [])) {
                if (c.isReturn && rcIds.includes(c.challanId)) cardMap.set(c.challanId, c.products || []);
            }

            for (const { origId, returnChallanId, productIds } of returnTargets) {
                const filter = { returnedFromChallanId: origId };
                // Modern docs — sourceProductId দিয়ে exact match
                operations.push(
                    challanCollection.updateMany(filter, tripDoWrite, {
                        arrayFilters: [{ "el.sourceProductId": { $in: productIds } }],
                    }).then(r => { touched += r.modifiedCount || 0; })
                );
                // Legacy docs — productName + model দিয়ে
                const namePairs = (cardMap.get(returnChallanId) || [])
                    .filter(p => productIds.includes(p._id));
                for (const p of namePairs) {
                    operations.push(
                        challanCollection.updateMany(filter, tripDoWrite, {
                            arrayFilters: [{
                                "el.sourceProductId": { $exists: false },
                                "el.productName": p.productName ?? "",
                                "el.model": modelCond(p.model),
                            }],
                        }).then(r => { touched += r.modifiedCount || 0; })
                    );
                }
            }
        }

        if (normalTargets.length) {
            const ids = normalTargets.map(t => t.challanId);
            // এক query-তে target doc গুলো — কোনটা original আর কোনটা নিজেই
            // derived return challan (returnedFromChallanId আছে) সেটা বোঝা
            // যায়; legacy name/model fallback-এর তথ্যও এখান থেকেই আসে
            const targetDocs = await challanCollection.find(
                { _id: { $in: ids.map(id => new ObjectId(id)) } },
                { projection: { returnedFromChallanId: 1, "products._id": 1, "products.sourceProductId": 1, "products.productName": 1, "products.model": 1 } }
            ).toArray();
            const docMap = new Map(targetDocs.map(d => [String(d._id), d]));
            // কোন original গুলোর derived return challan আছে (এক query)
            const derivedDocs = await challanCollection.find(
                { returnedFromChallanId: { $in: ids } },
                { projection: { returnedFromChallanId: 1 } }
            ).toArray();
            const hasDerived = new Set(derivedDocs.map(d => String(d.returnedFromChallanId)));

            // কোন original গুলোর split-leftover challan আছে (এক query) —
            // CreateDelivery / Trip-Details edit-এ product কমানো/সরানোর ফলে
            // জন্মানো pending leftover গুলো, Trip Do এদেরও পৌঁছাতে হবে
            // যাতে All-Gate-Pass এদের pending qty হিসাবে ধরে।
            const splitDocs = await challanCollection.find(
                { splitFromChallanId: { $in: ids } },
                { projection: { splitFromChallanId: 1 } }
            ).toArray();
            const hasSplit = new Set(splitDocs.map(d => String(d.splitFromChallanId)));

            const inIds = (pid, productIds) => productIds.includes(String(pid)) || productIds.includes(pid);
            const fillEmpty = { "el.tripDo": { $in: [null, ""] } };

            for (const { challanId, productIds } of normalTargets) {
                const doc = docMap.get(challanId);

                // ── CASE A: target নিজেই derived return challan (All-Challan
                // page-এর return-pending row) → deliveries-এর return card-এ
                // পুরো mirror (set এবং clear দুটোই)। এই path-টাই আগে ছিল না,
                // তাই All-Challan থেকে return product-এ Trip Do বসালে
                // Delivered page-এর return row-এ যেত না।
                if (doc?.returnedFromChallanId) {
                    const origId = String(doc.returnedFromChallanId);
                    const targeted = (doc.products || []).filter(p => inIds(p._id, productIds));
                    const cardFilter = { challans: { $elemMatch: { isReturn: true, originalChallanId: origId } } };
                    const cardWrite = writeValue === null
                        ? { $unset: { "challans.$[c].products.$[p].tripDo": "" } }
                        : { $set:   { "challans.$[c].products.$[p].tripDo": writeValue } };
                    const cFilter = { "c.isReturn": true, "c.originalChallanId": origId };
                    // Modern: pending product-এর sourceProductId = card product-এর _id
                    const srcIds = targeted.map(p => p.sourceProductId).filter(Boolean).map(String);
                    if (srcIds.length) {
                        operations.push(
                            deliveriesCollection.updateMany(cardFilter, cardWrite, {
                                arrayFilters: [cFilter, { "p._id": { $in: srcIds } }],
                            }).then(r => { touched += r.modifiedCount || 0; })
                        );
                    }
                    // Legacy: sourceProductId নেই → name/model দিয়ে card product match
                    for (const p of targeted.filter(p => !p.sourceProductId)) {
                        operations.push(
                            deliveriesCollection.updateMany(cardFilter, cardWrite, {
                                arrayFilters: [cFilter, {
                                    "p.productName": p.productName ?? "",
                                    "p.model": modelCond(p.model),
                                }],
                            }).then(r => { touched += r.modifiedCount || 0; })
                        );
                    }
                    continue; // derived target original-এর মতো আর propagate হয় না
                }

                // ── CASE B: original row → return artifacts-এ শুধু ফাঁকা
                // tripDo fill হয় (set-এর সময়; clear propagate হয় না)
                if (writeValue === null) continue;
                operations.push(
                    deliveriesCollection.updateMany(
                        { challans: { $elemMatch: { isReturn: true, originalChallanId: challanId } } },
                        { $set: { "challans.$[c].products.$[p].tripDo": writeValue } },
                        {
                            arrayFilters: [
                                { "c.isReturn": true, "c.originalChallanId": challanId },
                                { "p._id": { $in: productIds }, "p.tripDo": { $in: [null, ""] } },
                            ],
                        }
                    ).then(r => { touched += r.modifiedCount || 0; })
                );
                // ── Split-leftover propagation ──────────────────────────
                // Original product-এ Trip Do বসালে তার থেকে জন্মানো leftover
                // challan-এর ফাঁকা tripDo গুলোও fill হয় (sourceProductId
                // দিয়ে exact match; admin আলাদা DO বসিয়ে থাকলে overwrite নয়)।
                if (hasSplit.has(challanId)) {
                    operations.push(
                        challanCollection.updateMany(
                            { splitFromChallanId: challanId },
                            { $set: { "products.$[el].tripDo": writeValue } },
                            { arrayFilters: [{ "el.sourceProductId": { $in: productIds.map(String) }, ...fillEmpty }] }
                        ).then(r => { touched += r.modifiedCount || 0; })
                    );
                }

                if (!hasDerived.has(challanId)) continue;
                const filter = { returnedFromChallanId: challanId };
                operations.push(
                    challanCollection.updateMany(filter,
                        { $set: { "products.$[el].tripDo": writeValue } },
                        { arrayFilters: [{ "el.sourceProductId": { $in: productIds }, ...fillEmpty }] }
                    ).then(r => { touched += r.modifiedCount || 0; })
                );
                const namePairs = (doc?.products || [])
                    .filter(p => inIds(p._id, productIds));
                for (const p of namePairs) {
                    operations.push(
                        challanCollection.updateMany(filter,
                            { $set: { "products.$[el].tripDo": writeValue } },
                            { arrayFilters: [{
                                "el.sourceProductId": { $exists: false },
                                "el.productName": p.productName ?? "",
                                "el.model": modelCond(p.model),
                                ...fillEmpty,
                            }] }
                        ).then(r => { touched += r.modifiedCount || 0; })
                    );
                }
            }
        }

        await Promise.all(operations);
        res.send({ success: true, touched });
    } catch (err) {
        logger.error("Bulk trip-do update failed", err);
        res.status(500).send({ success: false, message: "Failed to update trip Do" });
    }
});

// ─────────────────────────────────────────────────────────────────────
//  Bulk CSD update
//  ─────────────────────────────────────────────────────────────────
//  CSD is a per-challan field (one value per challan), so unlike Trip Do
//  the targets are distinct challanIds — productId is irrelevant here.
//  Writes to the deliveries collection (the Delivered page's source of
//  truth) and best-effort to the challans collection so other views stay
//  in sync.  Empty value clears the CSD.
//
//  Body shape:  { csd: "<name>", challanIds: ["<id>", ...] }
// ─────────────────────────────────────────────────────────────────────
app.patch("/deliveries/bulk-csd", verifyToken, verifyRole('admin'), async (req, res) => {
    try {
        const { csd, challanIds } = req.body || {};
        if (!Array.isArray(challanIds) || challanIds.length === 0) {
            return res.status(400).send({ success: false, message: "No challans supplied" });
        }
        const clean = String(csd ?? "").trim();
        const writeValue = clean.length ? clean : null;   // null → unset

        const db = await connectDB();
        const challanCollection = db.collection('challans');
        const deliveriesCollection = db.collection('deliveries');

        // De-duplicate ids.
        const ids = [...new Set(challanIds.filter(Boolean).map(String))];

        let touched = 0;
        const operations = [];

        for (const challanId of ids) {
            // ── 1. deliveries collection (embedded copy — authoritative here) ──
            operations.push(
                deliveriesCollection.updateMany(
                    { "challans.challanId": challanId },
                    writeValue === null
                        ? { $unset: { "challans.$[c].csd": "" }, $set: { "challans.$[c].csdUpdatedAt": new Date() } }
                        : { $set: { "challans.$[c].csd": writeValue, "challans.$[c].csdUpdatedAt": new Date() } },
                    { arrayFilters: [{ "c.challanId": challanId }] }
                ).then(r => { touched += r.modifiedCount || 0; })
            );

            // ── 2. challans collection (best-effort, keeps other views fresh) ──
            if (isValidObjectId(challanId)) {
                operations.push(
                    challanCollection.updateOne(
                        { _id: new ObjectId(challanId) },
                        writeValue === null
                            ? { $unset: { csd: "" }, $set: { csdUpdatedAt: new Date() } }
                            : { $set: { csd: writeValue, csdUpdatedAt: new Date() } }
                    ).catch(() => { /* non-fatal — deliveries is the page's source */ })
                );
            }
        }

        await Promise.all(operations);
        res.send({ success: true, touched });
    } catch (err) {
        logger.error("Bulk CSD update failed", err);
        res.status(500).send({ success: false, message: "Failed to update CSD" });
    }
});

// NOTE: PATCH /challans/bulk-remarks lives further up the file, directly
// above `/challans/:id`, so Express matches the specific "bulk-remarks"
// path before the `:id` wildcard route can shadow it (Express matches
// routes in registration order, and "bulk-remarks" would otherwise get
// swallowed by `:id`'s validateObjectId check → 400).

// ─────────────────────────────────────────────────────────────────────
//  Split a product row by quantity
//  ─────────────────────────────────────────────────────────────────
//  Used by the Delivered page when an admin needs to assign different
//  Trip Do numbers to portions of the same qty.  Example: a row has
//  qty = 2 and the user wants to put 1 qty on one trip and 1 qty on
//  another.  The user splits the row first — the original row's qty
//  is reduced (e.g. 2 → 1) and a brand-new product entry is inserted
//  (qty = 1) carrying the same productName/model/capacity/rate but a
//  fresh _id and NO tripDo, so Trip Do can be set independently.
//
//  Body shape:
//    {
//      challanId: "<canonical challan _id>",
//      productId: "<embedded product _id>",
//      splitQty:  1     // qty to peel off into the new row
//    }
//
//  Constraints:
//    - splitQty must be a positive integer
//    - splitQty must be strictly less than the original row's qty
//      (i.e. the original always retains at least 1 qty; if you want
//      to "move all qty", just edit Trip Do on the existing row)
//
//  Writes to BOTH collections (challans + deliveries) so the embedded
//  copy on the trip and the canonical challan record stay in sync.
// ─────────────────────────────────────────────────────────────────────
app.post("/deliveries/split-product", verifyToken, verifyRole('admin'), async (req, res) => {
    try {
        const { challanId, productId, splitQty } = req.body || {};
        if (!challanId || !productId) {
            return res.status(400).send({ success: false, message: "challanId and productId required" });
        }
        const peel = Number(splitQty);
        if (!Number.isInteger(peel) || peel <= 0) {
            return res.status(400).send({ success: false, message: "splitQty must be a positive integer" });
        }

        const db = await connectDB();
        const challanCollection = db.collection('challans');
        const deliveriesCollection = db.collection('deliveries');

        // ── 1. Find the source row from the DELIVERIES collection ──
        // The Delivered page reads from `deliveries` (trips embed challans),
        // so the source of truth for what the user is looking at is the
        // embedded copy — not the canonical `challans` document (which may
        // have been deleted or never linked).  We look up by:
        //   - challans.challanId (the embedded reference field)
        //   - challans.products._id (the embedded product)
        //
        // Match on string OR ObjectId for challanId because historical data
        // may have either.
        const challanIdMatchers = [{ "challans.challanId": challanId }];
        if (isValidObjectId(challanId)) {
            challanIdMatchers.push({ "challans.challanId": new ObjectId(challanId) });
        }
        const trip = await deliveriesCollection.findOne({
            $and: [
                { $or: challanIdMatchers },
                { "challans.products._id": productId },
            ],
        });
        if (!trip) {
            return res.status(404).send({ success: false, message: "Row not found in any trip" });
        }

        // Walk the embedded challans → products to grab the source product
        let source = null;
        let embeddedChallanIdValue = null; // preserve original type for arrayFilters
        for (const c of (trip.challans || [])) {
            const cid = c?.challanId;
            const matches = cid === challanId || cid?.toString() === challanId;
            if (!matches) continue;
            const p = (c.products || []).find(pp => pp._id === productId || pp._id?.toString() === productId);
            if (p) {
                source = p;
                embeddedChallanIdValue = cid;   // could be string or ObjectId
                break;
            }
        }
        if (!source) {
            return res.status(404).send({ success: false, message: "Product not found in embedded challan" });
        }

        const originalQty = Number(source.quantity) || 0;
        if (peel >= originalQty) {
            return res.status(400).send({
                success: false,
                message: `splitQty (${peel}) must be less than current quantity (${originalQty})`,
            });
        }
        const remainingQty = originalQty - peel;

        // ── 2. Build the new product (clone source, fresh _id, no tripDo) ──
        const newProduct = { ...source };
        delete newProduct.tripDo;
        newProduct._id = new ObjectId().toString();
        newProduct.quantity = peel;
        newProduct.splitFrom = source._id;

        // ── 3. Update deliveries collection (the page's source of truth) ──
        // arrayFilters need to match the embedded challanId in its original
        // type (string or ObjectId), so we pass through `embeddedChallanIdValue`.
        const deliveriesFilter = isValidObjectId(challanId)
            ? {
                $or: [
                    { "challans.challanId": challanId },
                    { "challans.challanId": new ObjectId(challanId) },
                ]
            }
            : { "challans.challanId": challanId };

        await deliveriesCollection.updateMany(
            deliveriesFilter,
            { $set: { "challans.$[c].products.$[p].quantity": remainingQty } },
            {
                arrayFilters: [
                    { "c.challanId": embeddedChallanIdValue },
                    { "p._id": productId },
                ],
            }
        );
        await deliveriesCollection.updateMany(
            deliveriesFilter,
            { $push: { "challans.$[c].products": newProduct } },
            { arrayFilters: [{ "c.challanId": embeddedChallanIdValue }] }
        );

        // ── 4. Best-effort sync to canonical challans collection ──
        // If the canonical challan still exists, keep it in sync.  If not,
        // we don't fail — the Delivered page reads from `deliveries` anyway.
        if (isValidObjectId(challanId)) {
            try {
                const canonical = await challanCollection.findOne(
                    { _id: new ObjectId(challanId) },
                    { projection: { _id: 1, "products._id": 1 } }
                );
                if (canonical) {
                    const hasProduct = (canonical.products || []).some(
                        p => p._id === productId || p._id?.toString() === productId
                    );
                    if (hasProduct) {
                        await challanCollection.updateOne(
                            { _id: new ObjectId(challanId), "products._id": productId },
                            { $set: { "products.$.quantity": remainingQty } }
                        );
                        await challanCollection.updateOne(
                            { _id: new ObjectId(challanId) },
                            { $push: { products: newProduct } }
                        );
                    }
                }
            } catch (syncErr) {
                // Sync failure is non-fatal — log and move on.  The Delivered
                // page is already updated; an admin can reconcile later if needed.
                logger.warn?.("Canonical challan sync failed during split", { challanId, productId, err: syncErr?.message });
            }
        }

        res.send({
            success: true,
            originalProductId: productId,
            originalQuantity: remainingQty,
            newProduct,
        });
    } catch (err) {
        logger.error("Product split failed", err);
        res.status(500).send({ success: false, message: "Failed to split product" });
    }
});

// FIX #25 — When removing challan from trip, restore original challan's status
// ─────────────────────────────────────────────────────────────────────
// DELETE /deliveries/:tripId
//   Delete an ENTIRE trip from Trip Inventory. Unlike the single-challan
//   delete below, this removes the whole trip document and undoes
//   everything it did:
//     - Every real (non-return) embedded challan reverts to its
//       pre-dispatch status — "pending" normally, or "return-pending"
//       if it was a re-delivery of a previously returned item — and
//       loses its tripNumber so it's available again on All-Challan /
//       Create-Delivery.
//     - Any "Product Return" recorded on this trip created a fresh
//       "return-pending" challan for re-delivery; if that item hasn't
//       been re-delivered yet, it's removed too (deleting the trip
//       undoes the return along with everything else on it).
//   Admin/Manager only.
// ─────────────────────────────────────────────────────────────────────
app.delete("/deliveries/:tripId", verifyToken, verifyRole('admin', 'manager'), validateObjectId('tripId'), async (req, res) => {
    const { db } = await getConnection();
    const deliveriesCollection = db.collection('deliveries');
    const challanCollection = db.collection('challans');
    const { tripId } = req.params;

    try {
        const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
        if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });

        await recordAudit({
            db, req,
            action: "DELETE_TRIP",
            collectionName: "deliveries",
            documentId: trip._id,
            oldDoc: trip,
            reason: req.body?.reason?.trim() || "",
        });

        const challans = Array.isArray(trip.challans) ? trip.challans : [];

        // Revert real (non-return) challans to their pre-dispatch status.
        const regularIds = [];
        const reDeliveryIds = [];
        challans.forEach(c => {
            if (c.isReturn) return;
            if (!ObjectId.isValid(c.challanId)) return;
            (c.isReDelivery ? reDeliveryIds : regularIds).push(new ObjectId(c.challanId));
        });

        if (regularIds.length > 0) {
            await challanCollection.updateMany(
                { _id: { $in: regularIds } },
                { $set: { status: 'pending' }, $unset: { tripNumber: '' } }
            );
        }
        if (reDeliveryIds.length > 0) {
            await challanCollection.updateMany(
                { _id: { $in: reDeliveryIds } },
                { $set: { status: 'return-pending' }, $unset: { tripNumber: '' } }
            );
        }

        // Undo any Product Return recorded on this trip — remove the
        // re-deliverable challan it created, unless it's already been
        // re-delivered (status would no longer be "return-pending").
        if (trip.tripNumber) {
            await challanCollection.deleteMany({
                returnedFromTripNumber: trip.tripNumber,
                status: 'return-pending',
            });
        }

        await deliveriesCollection.deleteOne({ _id: new ObjectId(tripId) });

        res.send({ success: true, tripNumber: trip.tripNumber });
    } catch (err) {
        logger.error("Delete trip failed", err);
        res.status(500).send({ success: false, message: "Failed to delete trip" });
    }
});

app.delete("/deliveries/:tripId/challan/:challanId", verifyToken, verifyRole('admin', 'manager', 'operator'), validateObjectId('tripId'), async (req, res) => {
    const { db } = await getConnection();
    const deliveriesCollection = db.collection('deliveries');
    const challanCollection = db.collection('challans');
    const { tripId, challanId } = req.params;

    try {
        const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
        if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });
        // FIX (A12 defensive): challans field undefined হলে crash না করে handle
        if (!Array.isArray(trip.challans) || trip.challans.length === 0) {
            return res.status(400).send({ success: false, message: "Trip has no challans" });
        }
        if (trip.challans.length <= 1)
            return res.status(400).send({ success: false, message: "Cannot remove last challan from trip" });

        const targetChallan = trip.challans.find(c =>
            c.challanId === challanId || c.challanId?.toString() === challanId
        );
        if (!targetChallan)
            return res.status(404).send({ success: false, message: "Challan not found in trip" });

        // FIX (A9): Audit log the trip-challan delete (অন্য delete-এ আছে কিন্তু এটায় ছিল না)
        await recordAudit({
            db, req,
            action: "DELETE_CHALLAN_FROM_TRIP",
            collectionName: "deliveries",
            documentId: trip._id,
            oldDoc: { tripNumber: trip.tripNumber, removedChallan: targetChallan },
            reason: req.body?.reason?.trim() || "",
        });

        // ── M0 transaction → sequential writes + rollback ──────────────
        // Step 1: Trip থেকে challan বাদ দাও
        // Step 2: Original challan-কে pending করো
        // Fail হলে: trip-এ challan ফিরিয়ে দাও (rollback)
        const tripUpdateResult = await deliveriesCollection.updateOne(
            { _id: new ObjectId(tripId) },
            {
                $pull: { challans: { challanId: targetChallan.challanId } },
                $inc: { totalChallan: -1 }
            }
        );

        if (tripUpdateResult.modifiedCount === 0) {
            return res.status(404).send({ success: false, message: "Challan not found in trip" });
        }

        try {
            if (!targetChallan.isReturn && ObjectId.isValid(targetChallan.challanId)) {
                await challanCollection.updateOne(
                    { _id: new ObjectId(targetChallan.challanId) },
                    { $set: { status: 'pending' }, $unset: { tripNumber: '' } }
                );
            }
            res.send({ success: true, modifiedCount: 1 });
        } catch (challanErr) {
            // Step 2 fail → rollback step 1 (trip-এ challan ফিরিয়ে দাও)
            logger.error('Challan status revert failed, rolling back trip', challanErr);
            try {
                await deliveriesCollection.updateOne(
                    { _id: new ObjectId(tripId) },
                    {
                        $push: { challans: targetChallan },
                        $inc: { totalChallan: 1 }
                    }
                );
                logger.info('Trip rollback successful');
            } catch (rollbackErr) {
                logger.error('Trip rollback FAILED — manual fix needed', { tripId, challanId, rollbackErr });
            }
            throw challanErr;
        }
    } catch (err) {
        logger.error("Delete trip challan failed", err);
        res.status(500).send({ success: false, message: "Failed to delete challan" });
    }
});

// ─────────────────────────────────────────────────────────────────────
// POST /deliveries/:tripId/add-challans
//   Add one or more EXISTING pending challans to an ALREADY-CREATED trip.
//   Mirrors the create-delivery flow but targets an existing trip:
//     1. Atomic claim of the requested challans (race-safe, skips delivered)
//     2. Embed them in the trip.challans array + bump totalChallan
//     3. Finalize: status -> "delivered", set tripNumber, release claim
//   On failure the claim is released and the embedded challans rolled back
//   so the trip / challans never end up half-updated.
//   Body: { challans: [ { challanId, customerName, zone, address, thana,
//                         district, location, receiverNumber,
//                         products: [{ _id?, productName, model, quantity,
//                                      capacity?, rate? }] } ],
//           addedBy? }
// ─────────────────────────────────────────────────────────────────────
app.post("/deliveries/:tripId/add-challans", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
    const { db } = await getConnection();
    const deliveriesCollection = db.collection('deliveries');
    const challanCollection = db.collection('challans');
    const { tripId } = req.params;
    const { challans, addedBy } = req.body;

    if (!Array.isArray(challans) || challans.length === 0) {
        return res.status(400).send({ success: false, message: "No challans provided" });
    }

    // Resolve & validate the target challan ObjectIds.
    const challanIds = [];
    for (const c of challans) {
        if (!c.challanId || !ObjectId.isValid(c.challanId)) {
            return res.status(400).send({ success: false, message: `Invalid challan id: ${c.challanId}` });
        }
        challanIds.push(new ObjectId(c.challanId));
    }

    const claimToken = `claim_${new ObjectId().toString()}`;
    let claimedSuccessfully = false;
    let embedded = false;
    let embeddedIds = [];
    // Rollback + finalize-এ লাগে, তাই try block-এর বাইরে declare
    let returnPendingIdSet = new Set();
    let tripNumberForRollback = null;

    try {
        const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
        if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });
        tripNumberForRollback = trip.tripNumber || null;

        // Guard: don't add a challan that's already embedded in this trip.
        const existingIds = new Set((trip.challans || []).map(c => String(c.challanId)));
        const dupes = challans.filter(c => existingIds.has(String(c.challanId)));
        if (dupes.length > 0) {
            return res.status(409).send({
                success: false,
                message: `Already in this trip: ${dupes.map(c => c.customerName || c.challanId).join(", ")}`,
            });
        }

        // ── Return-pending lookup ──────────────────────────────────────
        // মূল POST /deliveries route-এর মতোই: Trip-Details-এর "Product
        // Return" থেকে জন্মানো challan-এর status "return-pending" থাকে।
        // Existing trip-এ add করে dispatch করলেও সেগুলো "delivered" নয়,
        // "re-delivered" হিসেবে finalize হতে হবে — নাহলে All-Challan /
        // Delivered page-এ প্রথম delivery আর re-delivery আলাদা করা যায় না
        // (আর gate-pass-এর net delivered হিসাবও ভুল হয়ে যায়)।
        try {
            const preStatusDocs = await challanCollection
                .find({ _id: { $in: challanIds } })
                .project({ status: 1 })
                .toArray();
            returnPendingIdSet = new Set(
                preStatusDocs.filter(d => d.status === 'return-pending').map(d => d._id.toString())
            );
        } catch (err) {
            logger.error('Pre-claim status lookup failed (add-challans)', err);
        }

        // ── FIX #54: আগের কোনো crashed request-এর আটকে থাকা claim ছাড়ো ──
        await releaseStaleClaims(challanCollection, challanIds);

        // ── Step 1: Atomic claim (only pending, unclaimed challans) ──
        // Main route-এর মতোই re-delivered-ও exclude — একবার re-deliver
        // হয়ে যাওয়া challan আবার add করা যাবে না।
        const claimResult = await challanCollection.updateMany(
            { _id: { $in: challanIds }, status: { $nin: ['delivered', 're-delivered'] }, claimToken: { $exists: false } },
            { $set: { claimToken, claimedAt: new Date() } }
        );
        claimedSuccessfully = true;

        if (claimResult.matchedCount !== challanIds.length) {
            // Release whatever we claimed and report the conflicting ones.
            await challanCollection.updateMany(
                { _id: { $in: challanIds }, claimToken },
                { $unset: { claimToken: "", claimedAt: "" } }
            );
            claimedSuccessfully = false;
            const conflictDocs = await challanCollection
                .find({ _id: { $in: challanIds } })
                .project({ customerName: 1, status: 1 }).toArray();
            const alreadyDelivered = conflictDocs.filter(d => d.status === 'delivered' || d.status === 're-delivered');
            const msg = alreadyDelivered.length > 0
                ? `Already delivered: ${alreadyDelivered.map(c => c.customerName).join(", ")}`
                : "Some challans could not be claimed (in another active dispatch). Try again.";
            return res.status(409).send({ success: false, message: msg });
        }

        // ── Step 2: Build embedded snapshots & push into the trip ──
        const embeddedChallans = challans.map(d => ({
            challanId: String(d.challanId),
            customerName: d.customerName,
            zone: d.zone,
            address: d.address,
            thana: d.thana,
            district: d.district,
            location: d.location || null,
            // Remarks — same snapshot behaviour as the main create-delivery
            // route above.
            remarks: typeof d.remarks === 'string' ? d.remarks : '',
            receiverNumber: d.receiverNumber,
            // Re-delivery marker — Delivered page-এর Type column-এ
            // "Re-Delivered" দেখাতে (main create-delivery route-এর মতোই)
            isReDelivery: returnPendingIdSet.has(String(d.challanId)),
            products: (d.products || []).map(p => {
                // FIX #50 — server-resolved rate, client মান শুধু cross-check
                const guarded = resolveAuthoritativeRate({
                    productName: p.productName,
                    model: p.model,
                    location: d.location || null,
                    capacity: p.capacity,
                    clientRate: p.rate,
                    logger,
                    context: 'POST /deliveries/:tripId/challans (embed)',
                    userEmail: req.user?.email,
                });
                return {
                    _id: p._id || new ObjectId().toString(),
                    productName: p.productName,
                    model: p.model,
                    quantity: Number(p.quantity),
                    capacity: guarded.capacity,
                    rate: guarded.rate,
                    // Trip Do carry — main route-এর মতোই: dispatch-এর আগে
                    // বসানো থাকলে snapshot-এও যায়, নাহলে Delivered page-এ
                    // গিয়ে হারিয়ে যেত (sync gap)।
                    ...(typeof p.tripDo === 'string' && p.tripDo.trim() ? { tripDo: p.tripDo.trim() } : {}),
                };
            }),
        }));
        embeddedIds = embeddedChallans.map(c => c.challanId);

        const pushResult = await deliveriesCollection.updateOne(
            { _id: new ObjectId(tripId) },
            {
                $push: { challans: { $each: embeddedChallans } },
                $inc: { totalChallan: embeddedChallans.length },
                $set: { lastUpdatedBy: addedBy || req.user?.email || null, lastUpdatedAt: new Date() },
            }
        );
        if (pushResult.modifiedCount === 0) throw new Error("Failed to embed challans into trip");
        embedded = true;

        // ── Step 3: Finalize challan status ────────────────────────────
        // Main create-delivery route-এর মতোই: return-pending challan
        // "re-delivered" হয়, বাকিরা "delivered"। আগে সবাইকে "delivered"
        // করা হতো — তাতে existing trip-এ add করা return product-এর
        // status ভুল দেখাত।
        const returnPendingChallanIds = challanIds.filter(id => returnPendingIdSet.has(id.toString()));
        const regularChallanIds = challanIds.filter(id => !returnPendingIdSet.has(id.toString()));

        let finalizedCount = 0;
        if (regularChallanIds.length > 0) {
            const r = await challanCollection.updateMany(
                { _id: { $in: regularChallanIds }, claimToken },
                {
                    $set: { status: "delivered", tripNumber: trip.tripNumber },
                    $unset: { claimToken: "", claimedAt: "" },
                }
            );
            finalizedCount += r.matchedCount;
        }
        if (returnPendingChallanIds.length > 0) {
            const r = await challanCollection.updateMany(
                { _id: { $in: returnPendingChallanIds }, claimToken },
                {
                    $set: { status: "re-delivered", tripNumber: trip.tripNumber },
                    $unset: { claimToken: "", claimedAt: "" },
                }
            );
            finalizedCount += r.matchedCount;
        }
        if (finalizedCount !== challanIds.length) {
            throw new Error("Failed to finalize all challans");
        }

        return res.send({
            success: true,
            tripNumber: trip.tripNumber,
            added: embeddedChallans.length,
            addedChallans: embeddedChallans,
        });
    } catch (err) {
        logger.error("Add challans to trip failed", err, { tripId });
        // ── Rollback ──
        try {
            if (embedded && embeddedIds.length > 0) {
                await deliveriesCollection.updateOne(
                    { _id: new ObjectId(tripId) },
                    {
                        $pull: { challans: { challanId: { $in: embeddedIds } } },
                        $inc: { totalChallan: -embeddedIds.length },
                    }
                );
            }
            if (claimedSuccessfully) {
                await challanCollection.updateMany(
                    { _id: { $in: challanIds }, claimToken },
                    { $unset: { claimToken: "", claimedAt: "" } }
                );
                // Finalize আংশিক হয়ে গিয়ে থাকলে (claimToken আর নেই, status
                // বসে গেছে) সেগুলোকে আগের অবস্থায় ফেরানো হয় — শুধু এই
                // request-এর challan + এই trip-এর tripNumber match করলে।
                // Return-pending থেকে আসা গুলো আবার return-pending-এ,
                // বাকিরা plain pending-এ ফিরবে (main route-এর মতোই)।
                if (tripNumberForRollback) {
                    const revertReturnIds  = challanIds.filter(id => returnPendingIdSet.has(id.toString()));
                    const revertRegularIds = challanIds.filter(id => !returnPendingIdSet.has(id.toString()));
                    if (revertRegularIds.length > 0) {
                        await challanCollection.updateMany(
                            { _id: { $in: revertRegularIds }, tripNumber: tripNumberForRollback, status: "delivered" },
                            { $set: { status: "pending" }, $unset: { tripNumber: "" } }
                        );
                    }
                    if (revertReturnIds.length > 0) {
                        await challanCollection.updateMany(
                            { _id: { $in: revertReturnIds }, tripNumber: tripNumberForRollback, status: "re-delivered" },
                            { $set: { status: "return-pending" }, $unset: { tripNumber: "" } }
                        );
                    }
                }
            }
        } catch (rollbackErr) {
            logger.error("Add-challans rollback FAILED — manual fix needed", { tripId, rollbackErr });
        }
        return res.status(500).send({ success: false, message: err.message || "Failed to add challans" });
    }
});

app.patch("/deliveries/:tripId/trip-info", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        const { tripId } = req.params;
        const { vehicleNumber, vendorName, vendorNumber, driverName, driverNumber, updatedBy } = req.body;

        const result = await deliveriesCollection.updateOne(
            { _id: new ObjectId(tripId) },
            {
                $set: {
                    vehicleNumber, vendorName, vendorNumber, driverName, driverNumber,
                    lastUpdatedBy: updatedBy || req.user?.email || null,
                    lastUpdatedAt: new Date(),
                }
            }
        );
        if (result.matchedCount === 0)
            return res.status(404).send({ success: false, message: "Trip not found" });

        const updated = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
        res.send({ success: true, data: updated });
    } catch (err) {
        logger.error("Edit trip info failed", err);
        res.status(500).send({ success: false, message: "Failed to update trip info" });
    }
});

// ═══════════════════════════════════════════════════════════════════
// FIX #58 — Product Return: edit sync + removal
// ═══════════════════════════════════════════════════════════════════
// Return issue করলে ৩ জায়গায় data বসে:
//   (a) original challan snapshot-এ returnedProducts mark
//   (b) trip-এর ভেতরে একটা embedded return card (isReturn: true)
//   (c) challans collection-এ একটা re-deliverable "return-pending" challan
//
// আগের সমস্যা:
//   - Edit করলে শুধু (a) আপডেট হতো — (b) আর (c) পুরনো quantity নিয়ে
//     বসে থাকত (out of sync)
//   - Return remove করার কোনো পথই ছিল না (client-ও আটকাতো, route-ও নেই)
//
// এখন: PATCH তিনটাই sync করে; DELETE (নিচে) তিনটাই undo করে।
app.patch("/deliveries/:tripId/challan/:challanId/return", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        const challanCollection = db.collection('challans');
        const { tripId, challanId } = req.params;
        const { returnedProducts, returnNote, updatedBy } = req.body;

        // খালি list মানে return তুলে নেওয়া — সেটার জন্য DELETE route
        if (!Array.isArray(returnedProducts) || returnedProducts.length === 0) {
            return res.status(400).send({
                success: false,
                message: "No return items — use Remove Return to clear this return",
            });
        }

        const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
        if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });

        const originalSnapshot = (trip.challans || []).find(
            c => c.challanId === challanId && !c.isReturn
        );
        if (!originalSnapshot) {
            return res.status(404).send({ success: false, message: "Challan not found" });
        }

        // Trip Do resolve — return card-এ admin আগে নিজে Trip Do বসিয়ে
        // থাকলে সেটাই থাকবে; নাহলে original product-এর Trip Do (থাকলে)।
        // Edit-এ products rebuild হয়, তাই এটা না রাখলে Trip Do মুছে যেত।
        const existingReturnCard = (trip.challans || []).find(
            c => c.isReturn && c.originalChallanId === challanId
        );
        // Canonical challan doc fallback — Trip Do শুধু challans
        // collection-এ থাকলেও যেন return-এ সেটা যায়
        let canonTripDoProducts = [];
        if (isValidObjectId(challanId)) {
            try {
                const canon = await challanCollection.findOne(
                    { _id: new ObjectId(challanId) },
                    { projection: { "products._id": 1, "products.tripDo": 1 } }
                );
                canonTripDoProducts = canon?.products || [];
            } catch (_) { /* best-effort */ }
        }
        const resolveTripDo = (p) => {
            const fromCard = existingReturnCard?.products?.find(ep => ep._id === p._id)?.tripDo;
            if (typeof fromCard === 'string' && fromCard.trim()) return fromCard.trim();
            const fromOrig = originalSnapshot.products?.find(op => op._id === p._id)?.tripDo;
            if (typeof fromOrig === 'string' && fromOrig.trim()) return fromOrig.trim();
            const fromCanon = canonTripDoProducts.find(op => String(op._id) === String(p._id))?.tripDo;
            if (typeof fromCanon === 'string' && fromCanon.trim()) return fromCanon.trim();
            return null;
        };

        // (b) embedded return card-এর products — quantity = returnQty
        const returnCardProducts = returnedProducts.map(p => {
            const tripDo = resolveTripDo(p);
            return {
                _id: p._id || new ObjectId().toString(),
                productName: p.productName,
                model: p.model,
                quantity: Number(p.returnQty || p.quantity) || 0,
                ...(tripDo ? { tripDo } : {}),
            };
        });

        await deliveriesCollection.bulkWrite([
            // (a) original snapshot-এ return mark আপডেট
            {
                updateOne: {
                    filter: { _id: new ObjectId(tripId), "challans.challanId": challanId },
                    update: {
                        $set: {
                            "challans.$.returnedProducts": returnedProducts,
                            "challans.$.returnNote": returnNote || "",
                            "challans.$.returnedAt": new Date(),
                            lastUpdatedBy: updatedBy || req.user?.email || null,
                            lastUpdatedAt: new Date(),
                        }
                    }
                }
            },
            // (b) embedded return card sync (থাকলে)
            {
                updateOne: {
                    filter: { _id: new ObjectId(tripId) },
                    update: {
                        $set: {
                            "challans.$[ret].products": returnCardProducts,
                            "challans.$[ret].returnNote": returnNote || "",
                        }
                    },
                    arrayFilters: [{ "ret.isReturn": true, "ret.originalChallanId": challanId }],
                }
            }
        ], { ordered: true });

        // (c) re-deliverable pending challan sync — শুধু যদি এখনো
        // dispatch না হয়ে থাকে (status return-pending, কেউ claim করেনি)।
        // capacity/rate original snapshot থেকে copy (creation-এর মতোই)।
        const pendingProducts = returnedProducts.map(p => {
            const orig = originalSnapshot.products?.find(op => op._id === p._id) || {};
            const tripDo = resolveTripDo(p);
            return {
                _id: new ObjectId().toString(),
                sourceProductId: p._id || null,
                productName: p.productName,
                model: p.model,
                quantity: Number(p.returnQty || p.quantity) || 0,
                capacity: typeof orig.capacity === 'string' ? orig.capacity : '',
                rate: Number(orig.rate) || 0,
                ...(tripDo ? { tripDo } : {}),
            };
        });
        const pendingSync = await challanCollection.updateOne(
            {
                returnedFromChallanId: challanId,
                returnedFromTripNumber: trip.tripNumber || null,
                status: 'return-pending',
                claimToken: { $exists: false },
            },
            {
                $set: {
                    products: pendingProducts,
                    lastUpdatedBy: updatedBy || req.user?.email || null,
                    lastUpdatedAt: new Date(),
                }
            }
        );

        res.send({
            success: true,
            pendingChallanSynced: pendingSync.matchedCount > 0,
        });
    } catch (err) {
        logger.error("Return update failed", err);
        res.status(500).send({ success: false, message: "Failed to update return" });
    }
});

// ── FIX #58b — Return সম্পূর্ণ remove ──────────────────────────────
// তিন জায়গার data-ই undo হয়। Idempotent — আগেরবার আধাআধি fail করলে
// আবার call করলেই বাকিটা পরিষ্কার হয়ে যায়।
// Safety: return item ইতিমধ্যে re-deliver হয়ে গেলে remove block হয়।
app.delete("/deliveries/:tripId/challan/:challanId/return", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        const challanCollection = db.collection('challans');
        const { tripId, challanId } = req.params;

        const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
        if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });

        const originalSnapshot = (trip.challans || []).find(
            c => c.challanId === challanId && !c.isReturn
        );
        if (!originalSnapshot) {
            return res.status(404).send({ success: false, message: "Challan not found" });
        }

        // (c) pending re-deliverable challan-গুলোর অবস্থা check
        const pendingFilter = {
            returnedFromChallanId: challanId,
            returnedFromTripNumber: trip.tripNumber || null,
        };
        const pendings = await challanCollection.find(pendingFilter).toArray();

        const dispatched = pendings.find(p => p.status !== 'return-pending');
        if (dispatched) {
            return res.status(409).send({
                success: false,
                message: "Return item already re-delivered in another trip — remove that delivery first",
            });
        }
        const beingClaimed = pendings.find(p => p.claimToken);
        if (beingClaimed) {
            return res.status(409).send({
                success: false,
                message: "Return item is being dispatched right now — try again in a moment",
            });
        }

        const embeddedReturns = (trip.challans || []).filter(
            c => c.isReturn && c.originalChallanId === challanId
        );

        // Step 1: trip cleanup — (b) return card সরাও + (a) mark unset
        await deliveriesCollection.bulkWrite([
            {
                updateOne: {
                    filter: { _id: new ObjectId(tripId) },
                    update: {
                        $pull: { challans: { isReturn: true, originalChallanId: challanId } },
                        ...(embeddedReturns.length > 0
                            ? { $inc: { totalChallan: -embeddedReturns.length } }
                            : {}),
                    }
                }
            },
            {
                updateOne: {
                    filter: { _id: new ObjectId(tripId), "challans.challanId": challanId },
                    update: {
                        $unset: {
                            "challans.$.returnedProducts": "",
                            "challans.$.returnNote": "",
                            "challans.$.returnedAt": "",
                        },
                        $set: {
                            lastUpdatedBy: req.user?.email || null,
                            lastUpdatedAt: new Date(),
                        }
                    }
                }
            }
        ], { ordered: true });

        // Step 2: (c) pending challan delete (এখনো pending + unclaimed গুলোই)
        let removedPending = 0;
        if (pendings.length > 0) {
            const del = await challanCollection.deleteMany({
                ...pendingFilter,
                status: 'return-pending',
                claimToken: { $exists: false },
            });
            removedPending = del.deletedCount || 0;
        }

        // Audit trail — কে কখন return মুছল
        await recordAudit({
            db,
            action: 'REMOVE_RETURN',
            collectionName: 'deliveries',
            documentId: tripId,
            oldDoc: {
                challanId,
                customerName: originalSnapshot.customerName || '',
                returnedProducts: originalSnapshot.returnedProducts || [],
                returnNote: originalSnapshot.returnNote || '',
                removedReturnCards: embeddedReturns.length,
                removedPendingChallans: removedPending,
            },
            reason: 'Product return removed from Trip Details',
            req,
        });

        res.send({
            success: true,
            removedReturnCards: embeddedReturns.length,
            removedPendingChallans: removedPending,
        });
    } catch (err) {
        logger.error("Return remove failed", err);
        res.status(500).send({ success: false, message: "Failed to remove return" });
    }
});

app.patch("/deliveries/:tripId/challan/:challanId/note", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        const { tripId, challanId } = req.params;
        const { note, updatedBy } = req.body;

        const result = await deliveriesCollection.updateOne(
            { _id: new ObjectId(tripId), "challans.challanId": challanId },
            {
                $set: {
                    "challans.$.note": note, "challans.$.noteUpdatedAt": new Date(),
                    lastUpdatedBy: updatedBy || req.user?.email || null,
                    lastUpdatedAt: new Date(),
                }
            }
        );
        if (result.matchedCount === 0)
            return res.status(404).send({ success: false, message: "Challan not found" });
        res.send({ success: true });
    } catch (err) {
        logger.error("Note update failed", err);
        res.status(500).send({ success: false, message: "Failed to update note" });
    }
});

// PATCH /deliveries/:tripId/note
//   Trip-level note (one note per whole trip, separate from the
//   per-challan note above). Used by the Trip Details page so an
//   admin/manager/operator can jot down something about the trip as a
//   whole (e.g. "driver delayed", "double-checked with customer").
//
//   Vendor visibility: vendors must NEVER see this note. The note is
//   written/read only through NON_VENDOR-gated routes on the client
//   (Trip Details page, behind the same guard as everything else in
//   this file's /deliveries:tripId... family), and — as a second,
//   server-side layer of protection — GET /deliveries strips this
//   field out of the response whenever the requester's role is
//   'vendor', so even a direct API call from a vendor account never
//   receives the note's contents.
app.patch("/deliveries/:tripId/note", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        const { tripId } = req.params;
        const { note, updatedBy } = req.body;

        const result = await deliveriesCollection.updateOne(
            { _id: new ObjectId(tripId) },
            {
                $set: {
                    tripNote: (note ?? "").toString(),
                    tripNoteUpdatedAt: new Date(),
                    tripNoteUpdatedBy: updatedBy || req.user?.email || null,
                    lastUpdatedBy: updatedBy || req.user?.email || null,
                    lastUpdatedAt: new Date(),
                }
            }
        );
        if (result.matchedCount === 0)
            return res.status(404).send({ success: false, message: "Trip not found" });
        res.send({ success: true });
    } catch (err) {
        logger.error("Trip note update failed", err);
        res.status(500).send({ success: false, message: "Failed to update trip note" });
    }
});

// PATCH /deliveries/:tripId/challan/:challanId/csd
// Update the per-challan CSD field directly from the Delivered page.
// CSD is a challan-level attribute (not per-product), so we match the
// embedded challan by its challanId and $set the field. Mirrors the
// /note endpoint above.
app.patch("/deliveries/:tripId/challan/:challanId/csd", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        const { tripId, challanId } = req.params;
        const { csd, updatedBy } = req.body;
        const clean = (csd ?? "").toString().trim();

        const result = await deliveriesCollection.updateOne(
            { _id: new ObjectId(tripId), "challans.challanId": challanId },
            {
                $set: {
                    "challans.$.csd": clean, "challans.$.csdUpdatedAt": new Date(),
                    lastUpdatedBy: updatedBy || req.user?.email || null,
                    lastUpdatedAt: new Date(),
                }
            }
        );
        if (result.matchedCount === 0)
            return res.status(404).send({ success: false, message: "Challan not found" });
        res.send({ success: true });
    } catch (err) {
        logger.error("CSD update failed", err);
        res.status(500).send({ success: false, message: "Failed to update CSD" });
    }
});

app.post("/deliveries/:tripId/return-challan", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
    const { client, db } = await getConnection();
    const deliveriesCollection = db.collection('deliveries');
    const challanCollection = db.collection('challans');
    const { tripId } = req.params;
    const {
        originalChallanId, customerName, zone, address,
        thana, district, receiverNumber,
        returnedProducts, returnNote,
    } = req.body;

    const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
    if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });

    // Original embedded challan snapshot — needed BOTH for the return
    // card and the re-deliverable challan below (tripDo / capacity / rate
    // are copied from here). Trip Do আগে বসানো থাকলে return-এর সাথে
    // সাথে সেটা return card + re-deliverable challan-এ চলে যায়, ফলে
    // All-Gate-Pass-এর Trip Do matching-এ Return status ধরা পড়ে।
    const originalChallanSnapshot = (trip.challans || []).find(c => c.challanId === originalChallanId);

    // Fallback source — canonical challan doc (challans collection)।
    // Trip Do কখনো কখনো শুধু ওখানে থাকে (যেমন trip তৈরির client payload-এ
    // tripDo না এলে embedded copy-তে থাকে না)। দুই জায়গা মিলিয়ে দেখা হয়,
    // যাতে Trip Do বসানো থাকলে return-pending challan-এ সেটা যাবেই।
    let canonicalProducts = [];
    if (isValidObjectId(originalChallanId)) {
        try {
            const canon = await challanCollection.findOne(
                { _id: new ObjectId(originalChallanId) },
                { projection: { "products._id": 1, "products.tripDo": 1 } }
            );
            canonicalProducts = canon?.products || [];
        } catch (_) { /* fallback best-effort */ }
    }
    const findOrigProduct = (pid) => {
        const snap  = originalChallanSnapshot?.products?.find(op => op._id === pid) || {};
        if (typeof snap.tripDo === 'string' && snap.tripDo.trim()) return snap;
        const canon = canonicalProducts.find(op => String(op._id) === String(pid));
        return (canon && typeof canon.tripDo === 'string' && canon.tripDo.trim())
            ? { ...snap, tripDo: canon.tripDo }
            : snap;
    };

    const returnChallan = {
        challanId: `return_${originalChallanId}_${Date.now()}`,
        isReturn: true,
        originalChallanId,
        customerName,
        zone,
        address,
        thana,
        district,
        receiverNumber,
        products: (returnedProducts || []).map(p => {
            const orig = findOrigProduct(p._id);
            return {
                _id: p._id || new ObjectId().toString(),
                productName: p.productName,
                model: p.model,
                quantity: Number(p.returnQty || p.quantity),
                // original product-এ Trip Do থাকলে return card-ও সেটা বহন করে
                ...(typeof orig.tripDo === 'string' && orig.tripDo.trim()
                    ? { tripDo: orig.tripDo.trim() } : {}),
            };
        }),
        returnNote: returnNote || "",
        returnedAt: new Date(),
        deliveryStatus: "return",
        challanReturnStatus: null,
    };

    // ── Re-deliverable challan ───────────────────────────────────────
    // A returned product needs to go back out for re-delivery. We create
    // a brand-new document in the `challans` collection (status
    // "return-pending") that behaves exactly like a normal pending
    // challan on All-Challan / Create-Delivery, except it carries a
    // "Return-Pending" status badge and, once dispatched again, is
    // finalized to "re-delivered" instead of "delivered" (see POST
    // /deliveries). capacity/rate are copied from the original challan's
    // matching product snapshot (embedded on the trip) so Rate/Amount
    // stay consistent when this item is re-delivered. tripDo is copied
    // too (থাকলে) so the All-Gate-Pass matching picks this challan up as
    // "return-pending" for the same DO. sourceProductId points back to
    // the original product _id so a later Trip Do entry on the Delivered
    // page can find and stamp this row as well.
    const newPendingChallan = {
        customerName, zone, address, thana, district, receiverNumber,
        location: originalChallanSnapshot?.location || null,
        remarks: originalChallanSnapshot?.remarks || "",
        products: (returnedProducts || []).map(p => {
            const orig = findOrigProduct(p._id);
            return {
                _id: new ObjectId().toString(),
                sourceProductId: p._id || null,
                productName: p.productName,
                model: p.model,
                quantity: Number(p.returnQty || p.quantity),
                capacity: typeof orig.capacity === 'string' ? orig.capacity : '',
                rate: Number(orig.rate) || 0,
                ...(typeof orig.tripDo === 'string' && orig.tripDo.trim()
                    ? { tripDo: orig.tripDo.trim() } : {}),
            };
        }),
        status: "return-pending",
        returnedFromTripNumber: trip.tripNumber || null,
        returnedFromChallanId: originalChallanId,
        createdAt: new Date(),
        createdBy: req.user?.email || 'unknown',
    };

    // ── FIX: ২টো update একই delivery document-এ ($_id same) ────────
    // আগে: transaction দিয়ে ২টা আলাদা updateOne (M0-তে fail হতো)
    // এখন: bulkWrite দিয়ে একটা atomic operation — transaction-ই দরকার নেই
    //   bulkWrite ordered=true → প্রথমটা fail হলে দ্বিতীয়টা চলে না
    try {
        // নতুন re-deliverable challan সবার আগে insert করি — এটা fail করলে
        // trip document touch-ই করব না।
        await challanCollection.insertOne(newPendingChallan);

        await deliveriesCollection.bulkWrite([
            // ১ম: return challan যোগ করো
            {
                updateOne: {
                    filter: { _id: new ObjectId(tripId) },
                    update: {
                        $push: { challans: returnChallan },
                        $inc: { totalChallan: 1 }
                    }
                }
            },
            // ২য়: original challan-এ returnedProducts mark করো
            {
                updateOne: {
                    filter: { _id: new ObjectId(tripId), "challans.challanId": originalChallanId },
                    update: {
                        $set: {
                            "challans.$.returnedProducts": returnedProducts,
                            "challans.$.returnNote": returnNote || "",
                            "challans.$.returnedAt": new Date(),
                            lastUpdatedBy: req.user?.email || null,
                            lastUpdatedAt: new Date(),
                        }
                    }
                }
            }
        ], { ordered: true }); // ordered=true → atomic sequence

        res.send({ success: true, returnChallan, newPendingChallan });
    } catch (err) {
        logger.error("Return challan add failed", err);
        res.status(500).send({ success: false, message: "Failed to add return challan" });
    }
});

// ═══════════════════════════════════════════════════════════════════
// Car Rent
// ═══════════════════════════════════════════════════════════════════

app.get("/car-rents", verifyToken, verifyRole('admin', 'manager', 'ceo', 'vendor'), async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        let month = parseInt(req.query.month);
        let year = parseInt(req.query.year);
        const search = escapeRegex(req.query.search || "");

        // Build a vehicleNumber → vehicleImg map from vendor vehicles so the
        // Car-Rent list can show a vehicle photo (trip docs only store the
        // vehicleNumber, not the image). Case-insensitive keys.
        const attachVehicleImg = async (rows) => {
            try {
                const numbers = [...new Set(rows.map(r => (r.vehicleNumber || "").trim().toLowerCase()).filter(Boolean))];
                if (numbers.length === 0) return rows;
                const vendorsCol = db.collection('vendors');
                const vendorDocs = await vendorsCol.find(
                    {}, { projection: { "vehicles.vehicleNumber": 1, "vehicles.vehicleImg": 1 } }
                ).toArray();
                const imgMap = new Map();
                for (const vd of vendorDocs) {
                    for (const v of (vd.vehicles || [])) {
                        const key = (v.vehicleNumber || "").trim().toLowerCase();
                        if (key && v.vehicleImg && !imgMap.has(key)) imgMap.set(key, v.vehicleImg);
                    }
                }
                return rows.map(r => {
                    const key = (r.vehicleNumber || "").trim().toLowerCase();
                    return imgMap.has(key) ? { ...r, vehicleImg: imgMap.get(key) } : r;
                });
            } catch (e) {
                logger.error("attachVehicleImg failed", e);
                return rows;
            }
        };

        let query = {};
        const isVendor = req.user?.role === "vendor";
        // Same trip documents are shared with /deliveries — the trip-level
        // note must stay hidden from vendors here too. See the matching
        // comment on GET /deliveries.
        const projection = isVendor ? { tripNote: 0, tripNoteUpdatedAt: 0, tripNoteUpdatedBy: 0 } : undefined;

        if (search) {
            // Global search — পুরো collection, limit 500
            query.$or = [
                { tripNumber: { $regex: search, $options: "i" } },
                { vendorName: { $regex: search, $options: "i" } },
                { driverName: { $regex: search, $options: "i" } },
                { vehicleNumber: { $regex: search, $options: "i" } },
            ];

            if (isVendor) {
                const userCollection = db.collection('users');
                const me = await userCollection.findOne({ email: req.user.email });
                if (!me?.vendorName) return res.send({ success: true, data: [], pagination: { total: 0 } });
                query.vendorName = { $regex: `^${escapeRegex(me.vendorName)}$`, $options: "i" };
            }

            let data = await deliveriesCollection.find(query, { projection }).sort({ createdAt: -1 }).limit(500).toArray();
            data = await attachVehicleImg(data);
            return res.send({ success: true, data, pagination: { total: data.length } });
        }

        // Month query — no limit, index আছে তাই fast
        if (!month || !year) {
            const _dt = getDhakaCurrentMonthYear();
            month = _dt.month;
            year = _dt.year;
        }
        const { startDate, endDate } = getDhakaMonthRange(year, month);
        query.createdAt = { $gte: startDate, $lt: endDate };

        // FIX #6 — Fetch fresh vendorName from DB (JWT could be stale)
        if (isVendor) {
            const userCollection = db.collection('users');
            const me = await userCollection.findOne({ email: req.user.email });
            if (!me?.vendorName) return res.send({ success: true, data: [], pagination: { total: 0 } });
            query.vendorName = { $regex: `^${escapeRegex(me.vendorName)}$`, $options: "i" };
        }

        let data = await deliveriesCollection.find(query, { projection }).sort({ createdAt: -1 }).toArray();
        data = await attachVehicleImg(data);
        res.send({ success: true, data, pagination: { total: data.length } });
    } catch (err) {
        logger.error("Car rent fetch failed", err);
        res.status(500).send({ success: false, message: "Failed to fetch car rents" });
    }
});

// ══ Bill Summary — Rent + Lebor tracking per month ══════════════
// GET /bill-summary?month=4&year=2025
// Returns: per-vendor bill breakdown + payment status
app.get("/bill-summary", verifyToken, verifyRole('admin', 'manager', 'ceo'), async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');

        let month = parseInt(req.query.month);
        let year = parseInt(req.query.year);
        if (!month || !year) {
            const _dt = getDhakaCurrentMonthYear();
            month = _dt.month; year = _dt.year;
        }
        const { startDate, endDate } = getDhakaMonthRange(year, month);

        const trips = await deliveriesCollection.find(
            { createdAt: { $gte: startDate, $lt: endDate } },
            {
                projection: {
                    tripNumber: 1, vendorName: 1, vendorNumber: 1, driverName: 1,
                    challans: 1, rent: 1, leborBill: 1, advance: 1, rentPaid: 1, rentPaidAmount: 1,
                    leborPaid: 1, leborPaidAmount: 1, createdAt: 1
                }
            }
        ).sort({ createdAt: -1 }).toArray();

        // Group by vendor
        const vendorMap = new Map();
        for (const trip of trips) {
            const key = (trip.vendorName || 'Unknown').trim();
            if (!vendorMap.has(key)) {
                vendorMap.set(key, {
                    vendorName: key,
                    vendorNumber: trip.vendorNumber || null,
                    trips: [],
                    totalRent: 0, totalLebor: 0, totalAdvance: 0,
                    totalPics: 0,
                    rentPaidAmount: 0, leborPaidAmount: 0,
                });
            }
            const v = vendorMap.get(key);
            const normalChallans = (trip.challans || []).filter(c => !c.isReturn);
            const pics = normalChallans.reduce((s, c) =>
                s + (c.products || []).reduce((ps, p) => ps + Number(p.quantity || 0), 0), 0);

            // Product summary per trip
            const prodMap = {};
            normalChallans.forEach(c => (c.products || []).forEach(p => {
                if (!prodMap[p.productName]) prodMap[p.productName] = 0;
                prodMap[p.productName] += Number(p.quantity || 0);
            }));

            v.trips.push({
                _id: trip._id,
                tripNumber: trip.tripNumber,
                createdAt: trip.createdAt,
                pics,
                products: Object.entries(prodMap).map(([name, qty]) => ({ name, qty })),
                rent: trip.rent ?? null,
                leborBill: trip.leborBill ?? null,
                advance: trip.advance ?? null,
                rentPaid: trip.rentPaid || false,
                rentPaidAmount: trip.rentPaidAmount ?? null,
                leborPaid: trip.leborPaid || false,
                leborPaidAmount: trip.leborPaidAmount ?? null,
            });

            v.totalPics += pics;
            v.totalRent += Number(trip.rent || 0);
            v.totalLebor += Number(trip.leborBill || 0);
            v.totalAdvance += Number(trip.advance || 0);
            v.rentPaidAmount += Number(trip.rentPaidAmount || 0);
            v.leborPaidAmount += Number(trip.leborPaidAmount || 0);
        }

        const vendors = Array.from(vendorMap.values()).map(v => ({
            ...v,
            rentDue: Math.max(0, v.totalRent - v.rentPaidAmount),
            leborDue: Math.max(0, v.totalLebor - v.leborPaidAmount),
        }));

        const summary = {
            month, year,
            totalTrips: trips.length,
            totalRent: vendors.reduce((s, v) => s + v.totalRent, 0),
            totalLebor: vendors.reduce((s, v) => s + v.totalLebor, 0),
            totalRentDue: vendors.reduce((s, v) => s + v.rentDue, 0),
            totalLeborDue: vendors.reduce((s, v) => s + v.leborDue, 0),
        };

        res.send({ success: true, vendors, summary });
    } catch (err) {
        logger.error('Bill summary failed', err);
        res.status(500).send({ success: false, message: 'Failed to fetch bill summary' });
    }
});

// PATCH /bill-summary/:tripId/payment — mark rent or lebor as paid
app.patch("/bill-summary/:tripId/payment", verifyToken, verifyRole('admin', 'manager', 'ceo'),
    validateObjectId('tripId'), async (req, res) => {
        try {
            const db = await connectDB();
            const col = db.collection('deliveries');
            const { type, paidAmount, paidBy } = req.body; // type: 'rent' | 'lebor'
            if (!['rent', 'lebor'].includes(type)) {
                return res.status(400).send({ success: false, message: 'type must be rent or lebor' });
            }
            const setFields = type === 'rent'
                ? { rentPaid: true, rentPaidAmount: Number(paidAmount), rentPaidBy: paidBy, rentPaidAt: new Date() }
                : { leborPaid: true, leborPaidAmount: Number(paidAmount), leborPaidBy: paidBy, leborPaidAt: new Date() };

            const result = await col.updateOne({ _id: new ObjectId(req.params.tripId) }, { $set: setFields });
            if (result.matchedCount === 0) return res.status(404).send({ success: false, message: 'Trip not found' });
            res.send({ success: true });
        } catch (err) {
            logger.error('Payment update failed', err);
            res.status(500).send({ success: false, message: 'Failed to update payment' });
        }
    });

// FIX #5 — Only finance roles can edit car rent money
app.patch("/car-rents/:tripId", verifyToken, verifyRole('admin', 'manager', 'ceo'), validateObjectId('tripId'), async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        const { rent, leborBill, updatedBy } = req.body;

        // Validate numeric
        if (rent != null && (typeof rent !== 'number' || rent < 0)) {
            return res.status(400).send({ success: false, message: 'rent must be non-negative number' });
        }
        if (leborBill != null && (typeof leborBill !== 'number' || leborBill < 0)) {
            return res.status(400).send({ success: false, message: 'leborBill must be non-negative number' });
        }

        const result = await deliveriesCollection.updateOne(
            { _id: new ObjectId(req.params.tripId) },
            {
                $set: {
                    rent, leborBill,
                    rentSavedBy: updatedBy || req.user?.email || null,
                    rentSavedAt: new Date(),
                }
            }
        );
        if (result.matchedCount === 0)
            return res.status(404).send({ success: false, message: "Trip not found" });
        const updated = await deliveriesCollection.findOne({ _id: new ObjectId(req.params.tripId) });
        res.send({ success: true, data: updated });
    } catch (err) {
        logger.error("Car rent update failed", err);
        res.status(500).send({ success: false, message: "Failed to update" });
    }
});

// FIX #5 — Only finance roles can edit advance
app.patch("/deliveries/:tripId/advance", verifyToken, verifyRole('admin', 'manager', 'ceo', 'operator'), validateObjectId('tripId'), async (req, res) => {
    try {
        const db = await connectDB();
        const deliveriesCollection = db.collection('deliveries');
        const { advance, updatedBy } = req.body;

        if (advance != null && (typeof advance !== 'number' || advance < 0)) {
            return res.status(400).send({ success: false, message: 'advance must be non-negative number' });
        }

        const result = await deliveriesCollection.updateOne(
            { _id: new ObjectId(req.params.tripId) },
            {
                $set: {
                    advance: advance !== undefined ? Number(advance) : null,
                    advanceSavedBy: updatedBy || req.user?.email || null,
                    advanceSavedAt: new Date(),
                }
            }
        );
        if (result.matchedCount === 0)
            return res.status(404).send({ success: false, message: "Trip not found" });

        const updated = await deliveriesCollection.findOne({ _id: new ObjectId(req.params.tripId) });
        res.send({ success: true, data: updated });
    } catch (err) {
        logger.error("Advance update failed", err);
        res.status(500).send({ success: false, message: "Failed to update advance" });
    }
});

// ═══════════════════════════════════════════════════════════════════
// Accounts — FIX #4 (amount sign validation) + FIX #5 (finance roles only)
// ═══════════════════════════════════════════════════════════════════

app.post("/accounts", verifyToken, verifyRole('admin', 'manager', 'ceo'), validate([
    body("type").isIn([
        "income", "expense", "vendor_payment",
        "auto_advance", "manual_advance", "advance_adjust", "carry_forward"
    ]).withMessage("Invalid type"),
    body("amount").isFloat().withMessage("Amount must be a number"),
    body("date").isISO8601().withMessage("Valid date required"),
    body("description").trim().notEmpty().withMessage("Description required"),
]), async (req, res) => {
    try {
        const { type, description, amount, date, note, vendorName, recipientName, month: bodyMonth, year: bodyYear } = req.body;
        const amt = Number(amount);

        // FIX #4 — Sign validation per type (prevent negative balance hacking)
        if (type === 'advance_adjust' || type === 'carry_forward') {
            // advance_adjust + carry_forward — can be negative
            if (Number.isNaN(amt)) {
                return res.status(400).send({ success: false, message: 'Invalid amount' });
            }
        } else {
            // income, expense, vendor_payment, auto_advance, manual_advance — must be > 0
            if (Number.isNaN(amt) || amt <= 0) {
                return res.status(400).send({
                    success: false,
                    message: `${type} amount must be a positive number`,
                });
            }
        }

        const db = await connectDB();
        const col = db.collection("accounts");

        // ── Ledger month/year নির্ধারণ ──────────────────────────────
        // Client explicit month/year পাঠালে (যেমন: Accounts dashboard-এ
        // previous month select করা অবস্থায় Pay Vendor) সেটাই ledger
        // month হবে — date field তখন শুধু "কবে টাকা দেওয়া হলো" তার record।
        // month/year না পাঠালে আগের মতো date থেকে বের হবে — তবে এখন
        // string থেকে সরাসরি parse, তাই server timezone-এ month পিছলে
        // যাওয়ার bug আর নেই (আগে new Date('YYYY-MM-DD').getMonth()
        // negative-offset timezone-এ আগের month দিত)।
        const [dYear, dMonth] = String(date).slice(0, 10).split('-').map(Number);
        let ledgerMonth = parseInt(bodyMonth);
        let ledgerYear = parseInt(bodyYear);
        if (!ledgerMonth || ledgerMonth < 1 || ledgerMonth > 12 || !ledgerYear || ledgerYear < 2000 || ledgerYear > 2100) {
            ledgerMonth = dMonth;
            ledgerYear = dYear;
        }

        const doc = {
            type,
            description: description.trim(),
            amount: amt,
            date,
            note: note?.trim() || "",
            vendorName: vendorName?.trim() || "",
            recipientName: recipientName?.trim() || "",
            month: ledgerMonth,
            year: ledgerYear,
            createdBy: req.user?.email || "unknown",
            createdAt: new Date(),
        };
        const result = await col.insertOne(doc);
        res.send({ success: true, insertedId: result.insertedId, data: { ...doc, _id: result.insertedId } });
    } catch (err) {
        logger.error("Account tx insert failed", err);
        res.status(500).send({ success: false, message: "Failed to add transaction" });
    }
});

app.get("/accounts", verifyToken, verifyRole('admin', 'manager', 'ceo'), async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection("accounts");
        let month = parseInt(req.query.month);
        let year = parseInt(req.query.year);
        if (!month || !year) {
            const _dt = getDhakaCurrentMonthYear();
            month = _dt.month;
            year = _dt.year;
        }
        const data = await col.find({ month, year }).sort({ date: -1, createdAt: -1 }).toArray();
        res.send({ success: true, data });
    } catch (err) {
        logger.error("Account tx fetch failed", err);
        res.status(500).send({ success: false, message: "Failed to fetch transactions" });
    }
});

app.delete("/accounts/:id", verifyToken, verifyRole('admin', 'manager', 'ceo'), validateObjectId("id"), async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection("accounts");

        const doc = await col.findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).send({ success: false, message: "Transaction not found" });
        if (doc.type === "auto_advance") {
            return res.status(403).send({ success: false, message: "Auto transactions cannot be deleted" });
        }

        const reason = req.body?.reason?.trim() || "";
        await recordAudit({
            db, req,
            action: "DELETE_TRANSACTION",
            collectionName: "accounts",
            documentId: doc._id,
            oldDoc: doc,
            reason,
        });

        await col.deleteOne({ _id: new ObjectId(req.params.id) });
        logger.info("Account tx deleted with audit log", { id: req.params.id, by: req.user?.email });
        res.send({ success: true });
    } catch (err) {
        logger.error("Account tx delete failed", err);
        res.status(500).send({ success: false, message: "Failed to delete transaction" });
    }
});

// manager delete করতে পারে (DELETE /accounts) — তাই audit log-ও দেখতে
// পারা দরকার। আগে শুধু admin/ceo ছিল বলে manager-এর কাছে 403 যেত আর
// Deleted tab খালি দেখাত।
app.get("/audit-logs", verifyToken, verifyRole('admin', 'manager', 'ceo'), async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection("audit_logs");
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(100, parseInt(req.query.limit) || 50);
        const skip = (page - 1) * limit;

        const filter = {};
        if (req.query.action) filter.action = req.query.action;
        if (req.query.performedBy) {
            filter["performedBy.email"] = { $regex: escapeRegex(req.query.performedBy), $options: "i" };
        }

        const [data, total] = await Promise.all([
            col.find(filter).sort({ performedAt: -1 }).skip(skip).limit(limit).toArray(),
            col.countDocuments(filter),
        ]);
        res.send({ success: true, data, total, page, limit });
    } catch (err) {
        logger.error("Audit log fetch failed", err);
        res.status(500).send({ success: false, message: "Failed to fetch audit logs" });
    }
});

// Restore flow: manager /accounts-এ restore POST করতে পারে, কিন্তু এই
// PATCH-এ 403 পেত — ফলে tx restore হয়ে যেত অথচ log-এ "Restored" mark
// হতো না (double-restore এর ঝুঁকি)। এখন consistent।
app.patch("/audit-logs/:id/restored", verifyToken, verifyRole('admin', 'manager', 'ceo'), validateObjectId("id"), async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection("audit_logs");
        const { restoredDocumentId } = req.body;
        const result = await col.updateOne(
            { _id: new ObjectId(req.params.id) },
            {
                $set: {
                    isRestored: true,
                    restoredAt: new Date(),
                    restoredBy: { email: req.user?.email || "unknown", role: req.user?.role || "unknown" },
                    restoredDocumentId: restoredDocumentId || null,
                }
            }
        );
        if (result.matchedCount === 0)
            return res.status(404).send({ success: false, message: "Audit log not found" });
        res.send({ success: true });
    } catch (err) {
        logger.error("Audit log restore mark failed", err);
        res.status(500).send({ success: false, message: "Failed to mark as restored" });
    }
});

// ═══════════════════════════════════════════════════════════════════
// FIX #49 — Bulk Operations
// ═══════════════════════════════════════════════════════════════════
// Max 500 items per request to prevent abuse.
// All bulk operations audit-log the batch operation.

const BULK_LIMIT = 500;

/**
 * Bulk delete challans
 * Body: { ids: ["...", "..."], reason: "..." }
 */
app.post('/challans/bulk-delete', verifyToken, verifyRole('admin', 'manager'), async (req, res) => {
    try {
        const { ids, reason } = req.body;
        if (!Array.isArray(ids) || ids.length === 0) {
            return res.status(400).send({ success: false, message: 'ids array required' });
        }
        if (ids.length > BULK_LIMIT) {
            return res.status(400).send({ success: false, message: `Max ${BULK_LIMIT} items per request` });
        }
        const validIds = ids.filter(id => isValidObjectId(id)).map(id => new ObjectId(id));
        if (validIds.length === 0) {
            return res.status(400).send({ success: false, message: 'No valid IDs provided' });
        }

        const db = await connectDB();
        const col = db.collection('challans');

        // Fetch docs before delete for audit
        const docs = await col.find({ _id: { $in: validIds } }).toArray();

        await recordAudit({
            db, req,
            action: "BULK_DELETE_CHALLAN",
            collectionName: "challans",
            documentId: null,
            oldDoc: { count: docs.length, items: docs.map(d => ({ _id: d._id, customerName: d.customerName })) },
            reason: reason?.trim() || "",
        });

        const result = await col.deleteMany({ _id: { $in: validIds } });
        logger.info("Bulk challan delete", { count: result.deletedCount, by: req.user?.email });
        res.send({ success: true, deletedCount: result.deletedCount });
    } catch (err) {
        logger.error('Bulk challan delete failed', err);
        res.status(500).send({ success: false, message: "Bulk delete failed" });
    }
});

/**
 * Bulk delete gate passes
 */
app.post('/gate-pass/bulk-delete', verifyToken, verifyRole('admin', 'manager'), async (req, res) => {
    try {
        const { ids, reason } = req.body;
        if (!Array.isArray(ids) || ids.length === 0) {
            return res.status(400).send({ success: false, message: 'ids array required' });
        }
        if (ids.length > BULK_LIMIT) {
            return res.status(400).send({ success: false, message: `Max ${BULK_LIMIT} items per request` });
        }
        const validIds = ids.filter(id => isValidObjectId(id)).map(id => new ObjectId(id));
        if (validIds.length === 0) {
            return res.status(400).send({ success: false, message: 'No valid IDs provided' });
        }

        const db = await connectDB();
        const col = db.collection('gate-pass');
        const docs = await col.find({ _id: { $in: validIds } }).toArray();

        await recordAudit({
            db, req,
            action: "BULK_DELETE_GATEPASS",
            collectionName: "gate-pass",
            documentId: null,
            oldDoc: { count: docs.length, items: docs.map(d => ({ _id: d._id, tripDo: d.tripDo, customerName: d.customerName })) },
            reason: reason?.trim() || "",
        });

        const result = await col.deleteMany({ _id: { $in: validIds } });
        logger.info("Bulk gate-pass delete", { count: result.deletedCount, by: req.user?.email });
        res.send({ success: true, deletedCount: result.deletedCount });
    } catch (err) {
        logger.error('Bulk gate-pass delete failed', err);
        res.status(500).send({ success: false, message: "Bulk delete failed" });
    }
});

/**
 * Bulk export — fetch all matching records for Excel/PDF generation (client-side).
 * Supports same filters as list endpoints.
 * No pagination (up to 10000 records max).
 */
app.get('/challans/bulk-export', verifyToken, verifyNonVendor, async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection('challans');
        let month = parseInt(req.query.month);
        let year = parseInt(req.query.year);
        const search = escapeRegex(req.query.search || "");

        let query = {};
        if (search) {
            query.$or = [
                { customerName: { $regex: search, $options: "i" } },
                { receiverNumber: { $regex: search, $options: "i" } },
                { zone: { $regex: search, $options: "i" } },
            ];
        } else {
            if (!month || !year) {
                const _dt = getDhakaCurrentMonthYear();
                month = _dt.month;
                year = _dt.year;
            }
            const { startDate, endDate } = getDhakaMonthRange(year, month);
            query.createdAt = { $gte: startDate, $lt: endDate };
        }

        const data = await col.find(query).sort({ createdAt: -1 }).limit(10000).toArray();
        res.send({ success: true, data, count: data.length });
    } catch (err) {
        logger.error('Bulk export failed', err);
        res.status(500).send({ success: false, message: "Export failed" });
    }
});

app.get('/gate-pass/bulk-export', verifyToken, verifyNonVendor, async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection('gate-pass');
        let month = parseInt(req.query.month);
        let year = parseInt(req.query.year);
        const search = escapeRegex(req.query.search || "");

        let query = {};
        if (search) {
            query.$or = [
                { tripDo: { $regex: search, $options: "i" } },
                { customerName: { $regex: search, $options: "i" } },
                { vehicleNo: { $regex: search, $options: "i" } },
            ];
        } else {
            if (!month || !year) {
                const _dt = getDhakaCurrentMonthYear();
                month = _dt.month;
                year = _dt.year;
            }
            query.tripMonth = month;
            query.tripYear = year;
        }

        const data = await col.find(query).sort({ createdAt: -1 }).limit(10000).toArray();
        res.send({ success: true, data, count: data.length });
    } catch (err) {
        logger.error('Bulk export failed', err);
        res.status(500).send({ success: false, message: "Export failed" });
    }
});

app.get('/deliveries/bulk-export', verifyToken, verifyApproved, async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection('deliveries');
        let month = parseInt(req.query.month);
        let year = parseInt(req.query.year);
        if (!month || !year) {
            const _dt = getDhakaCurrentMonthYear();
            month = _dt.month;
            year = _dt.year;
        }
        const { startDate, endDate } = getDhakaMonthRange(year, month);
        let query = { createdAt: { $gte: startDate, $lt: endDate } };

        // Vendor isolation
        if (req.user?.role === 'vendor') {
            const userCollection = db.collection('users');
            const me = await userCollection.findOne({ email: req.user.email });
            if (!me?.vendorName) return res.send({ success: true, data: [], count: 0 });
            query.vendorName = { $regex: `^${escapeRegex(me.vendorName)}$`, $options: 'i' };
        }

        const data = await col.find(query).sort({ createdAt: -1 }).limit(10000).toArray();
        res.send({ success: true, data, count: data.length });
    } catch (err) {
        logger.error('Bulk export failed', err);
        res.status(500).send({ success: false, message: "Export failed" });
    }
});

app.get('/accounts/bulk-export', verifyToken, verifyRole('admin', 'manager', 'ceo'), async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection('accounts');
        let month = parseInt(req.query.month);
        let year = parseInt(req.query.year);
        if (!month || !year) {
            const _dt = getDhakaCurrentMonthYear();
            month = _dt.month;
            year = _dt.year;
        }
        const data = await col.find({ month, year }).sort({ date: -1 }).limit(10000).toArray();
        res.send({ success: true, data, count: data.length });
    } catch (err) {
        logger.error('Accounts export failed', err);
        res.status(500).send({ success: false, message: "Export failed" });
    }
});

// ── Advance PAY (supports partial payment) ──
// Body: { payAmount }  -> increments paidAmount, clamped to [0, amount].
//   status is derived from paidAmount vs amount: unpaid / partial / paid.
// Backward-compatible: { status: "paid" | "unpaid" } still works
//   ("paid" => paidAmount = amount, "unpaid" => paidAmount = 0).
app.patch("/accounts/:id/status", verifyToken, verifyRole('admin', 'manager', 'ceo'), validateObjectId("id"), async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection("accounts");

        const adv = await col.findOne({ _id: new ObjectId(req.params.id), type: "manual_advance" });
        if (!adv)
            return res.status(404).send({ success: false, message: "Advance not found" });

        const total   = Number(adv.amount) || 0;
        const curPaid = Number(adv.paidAmount) || 0;

        let newPaid;

        if (req.body.payAmount !== undefined) {
            // Partial / additional payment — increment by payAmount.
            const pay = Number(req.body.payAmount);
            if (Number.isNaN(pay) || pay <= 0)
                return res.status(400).send({ success: false, message: "Pay amount must be a positive number" });
            newPaid = curPaid + pay;
        } else if (req.body.setPaidAmount !== undefined) {
            // Set absolute paid amount (used for edits / corrections).
            const set = Number(req.body.setPaidAmount);
            if (Number.isNaN(set) || set < 0)
                return res.status(400).send({ success: false, message: "Paid amount must be a non-negative number" });
            newPaid = set;
        } else if (req.body.status !== undefined) {
            // Legacy toggle — full paid or reset to unpaid.
            if (!["paid", "unpaid"].includes(req.body.status))
                return res.status(400).send({ success: false, message: "Invalid status" });
            newPaid = req.body.status === "paid" ? total : 0;
        } else {
            return res.status(400).send({ success: false, message: "payAmount, setPaidAmount or status required" });
        }

        // Clamp to [0, total]
        newPaid = Math.max(0, Math.min(total, newPaid));

        const status = newPaid >= total && total > 0 ? "paid"
            : newPaid > 0 ? "partial"
            : "unpaid";

        await col.updateOne(
            { _id: adv._id },
            { $set: { paidAmount: newPaid, status, statusUpdatedAt: new Date(), statusUpdatedBy: req.user?.email || null } }
        );
        const updated = await col.findOne({ _id: adv._id });
        res.send({ success: true, data: updated });
    } catch (err) {
        logger.error("Advance payment update failed", err);
        res.status(500).send({ success: false, message: "Failed to update advance" });
    }
});

// ═══════════════════════════════════════════════════════════════════
// Dashboard Stats
// ═══════════════════════════════════════════════════════════════════
// FIX #27 — Simple in-memory cache for dashboard stats (5 min TTL).
// Stats aggregate 15+ queries; caching saves M0 tier load.
// Cache key includes month/year but NOT user role (data is same for all roles).
const dashboardCache = new Map();
const DASHBOARD_CACHE_TTL_MS = 5 * 60 * 1000; // 5 min

function getCachedDashboard(key) {
    const entry = dashboardCache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.ts > DASHBOARD_CACHE_TTL_MS) {
        dashboardCache.delete(key);
        return null;
    }
    return entry.data;
}
function setCachedDashboard(key, data) {
    // Prevent unbounded growth — drop oldest if > 50 entries
    if (dashboardCache.size >= 50) {
        const firstKey = dashboardCache.keys().next().value;
        dashboardCache.delete(firstKey);
    }
    dashboardCache.set(key, { ts: Date.now(), data });
}


// Invalidate a specific month-year cache entry after gate-pass mutations
function invalidateDashboardCache(month, year) {
    if (month && year) {
        dashboardCache.delete(`${month}-${year}`);
    }
}

// FIX (A13): verifyApproved যোগ — pending/rejected user-দের access বন্ধ
app.get("/dashboard-stats", verifyToken, verifyApproved, async (req, res) => {
    try {
        const db = await connectDB();
        // FIX #28 — Accept optional month/year query params; default to current Dhaka month
        let month = parseInt(req.query.month);
        let year = parseInt(req.query.year);
        if (!month || !year || month < 1 || month > 12) {
            const _dt = getDhakaCurrentMonthYear();
            month = _dt.month;
            year = _dt.year;
        }

        // Try cache first
        // FIX #61 — ?fresh=1 দিলে cache bypass (Dashboard-এর ↻ Refresh button)।
        // টাটকা হিসাব হয়ে আবার cache-এ বসে যায় — পরের ৫ মিনিট বাকিরা
        // সেই টাটকা data-ই পাবে।
        const cacheKey = `${month}-${year}`;
        const wantFresh = req.query.fresh === '1' || req.query.fresh === 'true';
        if (!wantFresh) {
            const cached = getCachedDashboard(cacheKey);
            if (cached) {
                return res.send({ success: true, data: cached, cached: true });
            }
        }

        const { startDate: monthStart, endDate: monthEnd } = getDhakaMonthRange(year, month);

        // FIX #59 — গত মাসের সাথে তুলনার জন্য previous month range
        const prevMonth = month === 1 ? 12 : month - 1;
        const prevYear = month === 1 ? year - 1 : year;
        const { startDate: prevStart, endDate: prevEnd } = getDhakaMonthRange(prevYear, prevMonth);

        // ── FIX: ১৫টি query একসাথে → M0-তে timeout হওয়ার সম্ভাবনা ছিল
        // এখন ৩টি batch-এ ভাগ — প্রতি batch-এ ৫টি করে query
        // Batch 1: lightweight counts + accounts (দ্রুত শেষ হয়, index-only)
        // Batch 2: medium aggregations (challan status, zone, gatepass unit)
        // Batch 3: heavy double-unwind aggregations (শেষে)
        // প্রতিটি batch sequential — M0 একসাথে কম চাপ পাবে

        // ── Batch 1: Counts + accounts (fast, index hits) ──────────────
        const [
            gpMonthCount, gpTotalCount,
            challanTotalCount,
            tripMonthCount, tripTotalCount, activeTripCount,
            vendorCount, userCount,
            accountsTxs, carRentThisMonth,
            prevChallanCount, prevTripCount, challanMonthCount, prevGpCount,
            lastTripArr,
        ] = await Promise.all([
            db.collection('gate-pass').countDocuments({ tripMonth: month, tripYear: year }),
            db.collection('gate-pass').countDocuments(),

            db.collection('challans').countDocuments(),

            db.collection('deliveries').countDocuments({ createdAt: { $gte: monthStart, $lt: monthEnd } }),
            db.collection('deliveries').countDocuments(),
            db.collection('deliveries').countDocuments({
                $or: [{ status: { $exists: false } }, { status: { $in: ['pending', 'in_progress'] } }]
            }),

            db.collection('vendors').countDocuments(),
            db.collection('users').countDocuments(),

            db.collection('accounts').find({ month, year }).toArray(),
            db.collection('deliveries').find(
                { createdAt: { $gte: monthStart, $lt: monthEnd } },
                { projection: { advance: 1 } }
            ).toArray(),

            // FIX #59 — trend: গত মাসের challan + trip সংখ্যা
            db.collection('challans').countDocuments({ createdAt: { $gte: prevStart, $lt: prevEnd } }),
            db.collection('deliveries').countDocuments({ createdAt: { $gte: prevStart, $lt: prevEnd } }),
            db.collection('challans').countDocuments({ createdAt: { $gte: monthStart, $lt: monthEnd } }),
            db.collection('gate-pass').countDocuments({ tripMonth: prevMonth, tripYear: prevYear }),

            // Dashboard "Active" badge-এ সর্বশেষ trip number দেখানোর জন্য
            db.collection('deliveries')
                .find({ tripNumber: { $exists: true, $ne: null } }, { projection: { tripNumber: 1 } })
                .sort({ createdAt: -1 })
                .limit(1)
                .toArray(),
        ]);

        // ── Batch 2: Medium aggregations (challan status, zone, gatepass) ──
        const [
            challanStatusAgg, topDeliveryPoints, gpFacetAgg, vendorFacetAgg,
        ] = await Promise.all([
            db.collection('challans').aggregate([
                { $match: { createdAt: { $gte: monthStart, $lt: monthEnd } } },
                { $group: { _id: '$status', count: { $sum: 1 } } },
            ]).toArray(),
            db.collection('challans').aggregate([
                { $match: { createdAt: { $gte: monthStart, $lt: monthEnd } } },
                { $group: { _id: '$zone', count: { $sum: 1 } } },
                { $sort: { count: -1 } },
                { $limit: 5 },
            ]).toArray(),
            db.collection('gate-pass').aggregate([
                { $match: { tripMonth: month, tripYear: year } },
                { $unwind: '$products' },
                {
                    $facet: {
                        units: [
                            {
                                $group: {
                                    _id: { $toUpper: '$unit' },
                                    qty: { $sum: '$products.quantity' },
                                    passCount: { $addToSet: '$_id' },
                                }
                            },
                            { $addFields: { passCount: { $size: '$passCount' } } },
                            { $sort: { qty: -1 } },
                            { $limit: 10 },
                        ],
                        // FIX #60 — এ মাসে মোট কত PCS ঢুকল (warehouse header-এর জন্য)
                        totals: [
                            { $group: { _id: null, qty: { $sum: '$products.quantity' } } },
                        ],
                    }
                },
            ]).toArray(),
            // FIX #59 — এ মাসের top vendor + মোট challan-সংখ্যা এক pass-এ
            db.collection('deliveries').aggregate([
                { $match: { createdAt: { $gte: monthStart, $lt: monthEnd } } },
                {
                    $facet: {
                        topVendors: [
                            { $group: { _id: '$vendorName', trips: { $sum: 1 }, challans: { $sum: { $ifNull: ['$totalChallan', 0] } } } },
                            { $sort: { trips: -1 } },
                            { $limit: 5 },
                        ],
                        totals: [
                            { $group: { _id: null, challans: { $sum: { $ifNull: ['$totalChallan', 0] } } } },
                        ],
                    }
                },
            ]).toArray(),
        ]);

        // ── Batch 3: Heavy unwind aggregations — $facet দিয়ে এক pass-এ
        //    top products + মোট PCS + (deliveries-তে) return পরিসংখ্যান ──
        const [
            challanFacetArr, deliveryFacetArr,
        ] = await Promise.all([
            db.collection('challans').aggregate([
                { $match: { createdAt: { $gte: monthStart, $lt: monthEnd } } },
                { $unwind: '$products' },
                {
                    $facet: {
                        top: [
                            { $group: { _id: '$products.productName', qty: { $sum: '$products.quantity' } } },
                            { $sort: { qty: -1 } },
                            { $limit: 8 },
                        ],
                        totals: [
                            { $group: { _id: null, qty: { $sum: '$products.quantity' } } },
                        ],
                        // Delivery Progress-এ challan-সংখ্যার বদলে product qty (PCS)
                        // দেখানোর জন্য status-ভিত্তিক PCS breakdown
                        statusPcs: [
                            { $group: { _id: { $ifNull: ['$status', 'pending'] }, qty: { $sum: '$products.quantity' } } },
                        ],
                    }
                },
            ]).toArray(),
            db.collection('deliveries').aggregate([
                { $match: { createdAt: { $gte: monthStart, $lt: monthEnd } } },
                { $unwind: '$challans' },
                {
                    $facet: {
                        // Return card বাদ দিয়ে আসল delivered products
                        top: [
                            { $match: { 'challans.isReturn': { $ne: true } } },
                            { $unwind: '$challans.products' },
                            { $group: { _id: '$challans.products.productName', qty: { $sum: '$challans.products.quantity' } } },
                            { $sort: { qty: -1 } },
                            { $limit: 8 },
                        ],
                        totals: [
                            { $match: { 'challans.isReturn': { $ne: true } } },
                            { $unwind: '$challans.products' },
                            { $group: { _id: null, qty: { $sum: '$challans.products.quantity' } } },
                        ],
                        // FIX #59 — এ মাসে কয়টা return হলো, কত PCS
                        returns: [
                            { $match: { 'challans.isReturn': true } },
                            { $unwind: '$challans.products' },
                            {
                                $group: {
                                    _id: null,
                                    qty: { $sum: '$challans.products.quantity' },
                                    cards: { $addToSet: '$challans.challanId' },
                                }
                            },
                            { $addFields: { cards: { $size: '$cards' } } },
                        ],
                    }
                },
            ]).toArray(),
        ]);

        const challanFacet = challanFacetArr[0] || {};
        const deliveryFacet = deliveryFacetArr[0] || {};
        const vendorFacet = vendorFacetAgg[0] || {};
        const gpFacet = gpFacetAgg[0] || {};
        const gpUnitAgg = gpFacet.units || [];
        const challanProductAgg = challanFacet.top || [];
        const deliveryProductAgg = deliveryFacet.top || [];

        const csMap = {};
        challanStatusAgg.forEach(s => { csMap[s._id || 'pending'] = s.count; });

        // Status-ভিত্তিক PCS map (Delivery Progress-এর qty ভিউয়ের জন্য)
        const cpMap = {};
        (challanFacet.statusPcs || []).forEach(s => { cpMap[s._id || 'pending'] = s.qty; });

        const n = (v) => (v != null ? Number(v) : 0);
        const income = accountsTxs.filter(t => t.type === 'income').reduce((s, t) => s + n(t.amount), 0);
        const expense = accountsTxs.filter(t => t.type === 'expense').reduce((s, t) => s + n(t.amount), 0);
        const vendorPayment = accountsTxs.filter(t => t.type === 'vendor_payment').reduce((s, t) => s + n(t.amount), 0);
        const manualAdv = accountsTxs.filter(t => t.type === 'manual_advance').reduce((s, t) => s + n(t.amount), 0);
        const autoAdv = carRentThisMonth.reduce((s, t) => s + n(t.advance), 0);
        const totalExpense = expense + vendorPayment + manualAdv + autoAdv;
        const netBalance = income - totalExpense;

        const statsData = {
            currentMonth: month,
            currentYear: year,
            gatePass: {
                totalCount: gpTotalCount,
                monthCount: gpMonthCount,
                prevMonthCount: prevGpCount,               // FIX #60 — trend
                totalPcs: gpFacet.totals?.[0]?.qty || 0,   // FIX #60 — মোট PCS
                unitBreakdown: gpUnitAgg,
            },
            challan: {
                totalCount: challanTotalCount,
                monthTotal: challanMonthCount,
                // Status breakdown — সব status আলাদা করে (আগে re-delivered /
                // return-pending বাদ পড়ত, হিসাব মিলত না)
                delivered: (csMap['delivered'] || 0) + (csMap['re-delivered'] || 0),
                pending: csMap['pending'] || 0,
                returnPending: csMap['return-pending'] || 0,
                returned: csMap['returned'] || 0,
                prevMonthTotal: prevChallanCount,          // FIX #59 — trend
                totalPcs: challanFacet.totals?.[0]?.qty || 0,
                // Product qty (PCS) অনুযায়ী status breakdown
                deliveredPcs: (cpMap['delivered'] || 0) + (cpMap['re-delivered'] || 0),
                pendingPcs: cpMap['pending'] || 0,
                returnPendingPcs: cpMap['return-pending'] || 0,
                returnedPcs: cpMap['returned'] || 0,
                productBreakdown: challanProductAgg,
            },
            trip: {
                totalCount: tripTotalCount,
                monthCount: tripMonthCount,
                activeCount: activeTripCount,
                lastTripNumber: lastTripArr?.[0]?.tripNumber || null, // সর্বশেষ trip

                prevMonthCount: prevTripCount,             // FIX #59 — trend
                monthChallans: vendorFacet.totals?.[0]?.challans || 0,
                deliveredPcs: deliveryFacet.totals?.[0]?.qty || 0,
                returnCards: deliveryFacet.returns?.[0]?.cards || 0,
                returnPcs: deliveryFacet.returns?.[0]?.qty || 0,
                topVendors: vendorFacet.topVendors || [],
                productBreakdown: deliveryProductAgg,
            },
            vendor: { totalCount: vendorCount },
            user: { totalCount: userCount },
            accounts: { income, totalExpense, netBalance, vendorPayment, autoAdv, manualAdv },
            topDeliveryPoints,
        };

        // FIX #27 — Cache result for 5 min
        setCachedDashboard(cacheKey, statsData);

        res.send({ success: true, data: statsData, cached: false });
    } catch (err) {
        logger.error("Dashboard stats failed", err);
        res.status(500).send({ success: false, message: "Failed to fetch stats" });
    }
});

// ═══════════════════════════════════════════════════════════════════
// Walton Bill Tracker — Manual bill issue & payment tracking
// Collection: walton-bills
// ═══════════════════════════════════════════════════════════════════

// GET /walton-bills?month=4&year=2025&type=main|lebor
app.get("/walton-bills", verifyToken, verifyRole('admin', 'manager', 'ceo'), async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection('walton-bills');
        const month = parseInt(req.query.month) || new Date().getMonth() + 1;
        const year = parseInt(req.query.year) || new Date().getFullYear();
        const type = req.query.type; // 'main' | 'lebor' | undefined (all)

        const query = { month, year };
        if (type) query.type = type;

        const bills = await col.find(query).sort({ createdAt: -1 }).toArray();
        res.send({ success: true, data: bills });
    } catch (err) {
        logger.error('Walton bills fetch failed', err);
        res.status(500).send({ success: false, message: 'Failed to fetch bills' });
    }
});

// POST /walton-bills — create new bill issue
// FIX (A5): Added validation + defensive item parsing — invalid item.model
//           আগে .trim() throw করত (TypeError → 500)
app.post("/walton-bills", verifyToken, verifyRole('admin', 'manager', 'ceo'), validate([
    body('month').isInt({ min: 1, max: 12 }).withMessage('Valid month (1-12) required'),
    body('year').isInt({ min: 2000, max: 3000 }).withMessage('Valid year required'),
    body('type').isIn(['main', 'lebor']).withMessage('Type must be main or lebor'),
    body('items').isArray({ min: 1 }).withMessage('At least one item required'),
    body('items.*.model').trim().notEmpty().withMessage('Item model required'),
    body('items.*.pics').optional().isInt({ min: 0 }).withMessage('Pics must be non-negative integer'),
    body('items.*.amount').isFloat({ min: 0 }).withMessage('Amount must be non-negative'),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection('walton-bills');
        const { month, year, type, items, note } = req.body;

        // Safe item processing — String() coerce করি যাতে .trim() never fails
        const sanitizedItems = items.map(i => ({
            model: String(i.model || '').trim(),
            pics: Number(i.pics) || 0,
            amount: Number(i.amount) || 0,
        }));
        const totalAmount = sanitizedItems.reduce((s, i) => s + i.amount, 0);

        const doc = {
            month: Number(month), year: Number(year), type,
            items: sanitizedItems,
            totalAmount,
            note: note || '',
            payments: [],           // [{ amount, date, note, by }]
            totalPaid: 0,
            status: 'unpaid',       // unpaid | partial | paid
            issuedBy: req.user?.email || 'unknown',
            createdAt: new Date(),
            updatedAt: new Date(),
        };

        const result = await col.insertOne(doc);
        res.send({ success: true, insertedId: result.insertedId, data: { ...doc, _id: result.insertedId } });
    } catch (err) {
        logger.error('Walton bill create failed', err);
        res.status(500).send({ success: false, message: 'Failed to create bill' });
    }
});

// PATCH /walton-bills/:id — edit an existing bill's items/note.
// Recomputes totalAmount + status (payments/totalPaid are untouched —
// use the /payment endpoints for those). Model/pics/amount validated
// the same way as bill creation.
app.patch("/walton-bills/:id", verifyToken, verifyRole('admin', 'manager', 'ceo'), validateObjectId('id'), validate([
    body('items').isArray({ min: 1 }).withMessage('At least one item required'),
    body('items.*.model').trim().notEmpty().withMessage('Item model required'),
    body('items.*.pics').optional().isInt({ min: 0 }).withMessage('Pics must be non-negative integer'),
    body('items.*.amount').isFloat({ min: 0 }).withMessage('Amount must be non-negative'),
]), async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection('walton-bills');
        const bill = await col.findOne({ _id: new ObjectId(req.params.id) });
        if (!bill) return res.status(404).send({ success: false, message: 'Bill not found' });

        const { items, note } = req.body;
        const sanitizedItems = items.map(i => ({
            model: String(i.model || '').trim(),
            pics: Number(i.pics) || 0,
            amount: Number(i.amount) || 0,
        }));
        const totalAmount = sanitizedItems.reduce((s, i) => s + i.amount, 0);

        // Re-derive status against the (possibly changed) total — payments
        // themselves aren't touched by an item edit.
        const currentTotalPaid = Number(bill.totalPaid) || 0;
        const newStatus = totalAmount > 0 && currentTotalPaid >= totalAmount
            ? 'paid'
            : currentTotalPaid > 0 ? 'partial' : 'unpaid';

        await col.updateOne(
            { _id: new ObjectId(req.params.id) },
            {
                $set: {
                    items: sanitizedItems,
                    totalAmount,
                    note: note ?? bill.note ?? '',
                    status: newStatus,
                    updatedAt: new Date(),
                    lastEditedBy: req.user?.email || 'unknown',
                }
            }
        );
        const updated = await col.findOne({ _id: new ObjectId(req.params.id) });
        res.send({ success: true, data: updated });
    } catch (err) {
        logger.error('Walton bill edit failed', err);
        res.status(500).send({ success: false, message: 'Failed to edit bill' });
    }
});

// PATCH /walton-bills/:id/payment — add a payment
app.patch("/walton-bills/:id/payment", verifyToken, verifyRole('admin', 'manager', 'ceo'), validateObjectId('id'), async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection('walton-bills');
        const { amount, note, date } = req.body;

        if (!amount || isNaN(amount) || Number(amount) <= 0) {
            return res.status(400).send({ success: false, message: 'Valid amount required' });
        }

        const bill = await col.findOne({ _id: new ObjectId(req.params.id) });
        if (!bill) return res.status(404).send({ success: false, message: 'Bill not found' });

        const payment = { amount: Number(amount), note: note || '', date: date || new Date().toISOString(), by: req.user?.email || 'unknown', addedAt: new Date() };
        // FIX (A7): legacy bill-এ totalPaid/totalAmount undefined হলে NaN হয়ে যেত
        const currentTotalPaid = Number(bill.totalPaid) || 0;
        const currentTotalAmount = Number(bill.totalAmount) || 0;
        const newTotalPaid = currentTotalPaid + payment.amount;
        const newStatus = newTotalPaid >= currentTotalAmount ? 'paid' : newTotalPaid > 0 ? 'partial' : 'unpaid';

        await col.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $push: { payments: payment }, $set: { totalPaid: newTotalPaid, status: newStatus, updatedAt: new Date() } }
        );
        const updated = await col.findOne({ _id: new ObjectId(req.params.id) });
        res.send({ success: true, data: updated });
    } catch (err) {
        logger.error('Payment add failed', err);
        res.status(500).send({ success: false, message: 'Failed to add payment' });
    }
});

// DELETE /walton-bills/:id — delete a bill
app.delete("/walton-bills/:id", verifyToken, verifyRole('admin', 'manager', 'ceo'), validateObjectId('id'), async (req, res) => {
    try {
        const db = await connectDB();
        const result = await db.collection('walton-bills').deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0) return res.status(404).send({ success: false, message: 'Bill not found' });
        res.send({ success: true });
    } catch (err) {
        logger.error('Bill delete failed', err);
        res.status(500).send({ success: false, message: 'Failed to delete bill' });
    }
});

// DELETE /walton-bills/:id/payment/:idx — delete a specific payment
app.delete("/walton-bills/:id/payment/:idx", verifyToken, verifyRole('admin', 'manager', 'ceo'), validateObjectId('id'), async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection('walton-bills');
        const bill = await col.findOne({ _id: new ObjectId(req.params.id) });
        if (!bill) return res.status(404).send({ success: false, message: 'Bill not found' });

        // FIX (A6): legacy bill-এ payments field না থাকলে .length throw করত
        const payments = Array.isArray(bill.payments) ? bill.payments : [];
        const idx = parseInt(req.params.idx);
        if (isNaN(idx) || idx < 0 || idx >= payments.length) {
            return res.status(400).send({ success: false, message: 'Invalid payment index' });
        }
        const removedAmt = Number(payments[idx]?.amount) || 0;
        const newPayments = payments.filter((_, i) => i !== idx);
        const currentTotalPaid = Number(bill.totalPaid) || 0;
        const currentTotalAmount = Number(bill.totalAmount) || 0;
        const newTotalPaid = currentTotalPaid - removedAmt;
        const newStatus = newTotalPaid >= currentTotalAmount ? 'paid' : newTotalPaid > 0 ? 'partial' : 'unpaid';

        await col.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { payments: newPayments, totalPaid: newTotalPaid, status: newStatus, updatedAt: new Date() } }
        );
        const updated = await col.findOne({ _id: new ObjectId(req.params.id) });
        res.send({ success: true, data: updated });
    } catch (err) {
        logger.error('Payment delete failed', err);
        res.status(500).send({ success: false, message: 'Failed to delete payment' });
    }
});


// ═══════════════════════════════════════════════════════════════════
// Challan Floor/Carrying entry — for Labor Bill tracking
// PATCH /deliveries/:tripId/challan/:challanId/floor-carrying
// ═══════════════════════════════════════════════════════════════════
app.patch("/deliveries/:tripId/challan/:challanId/floor-carrying",
    verifyToken, verifyNonVendor, validateObjectId('tripId'),
    async (req, res) => {
        try {
            const db = await connectDB();
            const col = db.collection('deliveries');
            const { floor, carrying, note } = req.body;
            // floor: number 1-15 | null, carrying: string | null
            const setFields = {};
            if (floor !== undefined) setFields["challans.$.floor"] = floor;
            if (carrying !== undefined) setFields["challans.$.carrying"] = carrying;
            if (note !== undefined) setFields["challans.$.note"] = note;
            if (Object.keys(setFields).length === 0)
                return res.status(400).send({ success: false, message: 'No fields provided' });

            const result = await col.updateOne(
                { _id: new ObjectId(req.params.tripId), "challans.challanId": req.params.challanId },
                { $set: setFields }
            );
            if (result.matchedCount === 0)
                return res.status(404).send({ success: false, message: 'Trip or challan not found' });
            const updated = await col.findOne({ _id: new ObjectId(req.params.tripId) });
            res.send({ success: true, data: updated });
        } catch (err) {
            logger.error('Floor/carrying update failed', err);
            res.status(500).send({ success: false, message: 'Failed to update' });
        }
    });

// PATCH /deliveries/:tripId/challan/:challanId/status — update rtn/note status
app.patch("/deliveries/:tripId/challan/:challanId/status",
    verifyToken, verifyNonVendor, validateObjectId('tripId'),
    async (req, res) => {
        try {
            const db = await connectDB();
            const col = db.collection('deliveries');
            const { deliveryStatus, challanReturnStatus, note, returnNote } = req.body;
            const setFields = {};
            if (deliveryStatus !== undefined) setFields["challans.$.deliveryStatus"] = deliveryStatus;
            if (challanReturnStatus !== undefined) setFields["challans.$.challanReturnStatus"] = challanReturnStatus;
            if (note !== undefined) setFields["challans.$.note"] = note;
            if (returnNote !== undefined) setFields["challans.$.returnNote"] = returnNote;
            if (!Object.keys(setFields).length)
                return res.status(400).send({ success: false, message: 'No fields' });

            const result = await col.updateOne(
                { _id: new ObjectId(req.params.tripId), "challans.challanId": req.params.challanId },
                { $set: setFields }
            );
            if (result.matchedCount === 0)
                return res.status(404).send({ success: false, message: 'Not found' });
            const updated = await col.findOne({ _id: new ObjectId(req.params.tripId) });
            res.send({ success: true, data: updated });
        } catch (err) {
            logger.error('Challan status update failed', err);
            res.status(500).send({ success: false, message: 'Failed to update status' });
        }
    });

// GET /labor-bill?month=4&year=2025 — challans with floor or carrying entry
// SECURITY FIX — আগে শুধু verifyToken ছিল: যেকোনো logged-in user
// (vendor, এমনকি unapproved account-ও) customer phone/address সহ
// labor data দেখতে পারত। Client route-এর মতোই role-gate করা হলো।
app.get("/labor-bill", verifyToken, verifyRole('admin', 'manager', 'ceo', 'operator'), async (req, res) => {
    try {
        const db = await connectDB();
        const col = db.collection('deliveries');
        let month = parseInt(req.query.month);
        let year = parseInt(req.query.year);
        if (!month || !year) {
            const _dt = getDhakaCurrentMonthYear();
            month = _dt.month; year = _dt.year;
        }
        const { startDate, endDate } = getDhakaMonthRange(year, month);
        const trips = await col.find(
            { createdAt: { $gte: startDate, $lt: endDate } },
            { projection: { tripNumber: 1, challans: 1, createdAt: 1 } }
        ).sort({ createdAt: -1 }).toArray();

        // Extract only challans that have floor or carrying set
        const rows = [];
        trips.forEach(trip => {
            (trip.challans || []).filter(c => !c.isReturn && (c.floor || c.carrying)).forEach(c => {
                rows.push({
                    tripId: trip._id,
                    tripNumber: trip.tripNumber,
                    createdAt: trip.createdAt,
                    challanId: c.challanId,
                    customerName: c.customerName,
                    zone: c.zone,
                    address: c.address,
                    district: c.district,
                    thana: c.thana,
                    receiverNumber: c.receiverNumber,
                    products: c.products || [],
                    floor: c.floor ?? null,
                    carrying: c.carrying || null,
                    note: c.note || null,
                });
            });
        });
        res.send({ success: true, data: rows, month, year });
    } catch (err) {
        logger.error('Labor bill fetch failed', err);
        res.status(500).send({ success: false, message: 'Failed' });
    }
});

// ── Global Error Handler ───────────────────────────────────────────
// FIX: এই handler অবশ্যই সব route registration-এর পরে থাকতে হবে।
// Express শুধু এর আগে register হওয়া route গুলোর error catch করে — পরের
// route গুলো default HTML error page-এ fall through করে যায়।
app.use((err, req, res, next) => {
    logger.error("Unhandled error", err);
    // CORS error
    if (err.message?.startsWith('CORS blocked')) {
        return res.status(403).send({ success: false, message: err.message });
    }
    // Multer file size error
    if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).send({ success: false, message: 'File too large (max 5MB)' });
    }
    // Multer fileFilter rejection (HEIC / অন্য format)
    if (err.code === 'INVALID_FILE_TYPE') {
        return res.status(400).send({
            success: false,
            message: 'Only JPEG, PNG or WEBP images are allowed — phone HEIC photos must be converted to JPEG first'
        });
    }
    res.status(500).send({ success: false, message: "Internal Server Error" });
});

// ── Start Server ───────────────────────────────────────────────────
if (process.env.NODE_ENV !== "production" && !process.env.VERCEL) {
    app.listen(port, () => {
        logger.info(`Server running`, { port });
    });
}

module.exports = app;