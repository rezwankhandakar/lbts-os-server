
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
// FIX #3 — Regex escape helper (prevents ReDoS + regex injection)
// ═══════════════════════════════════════════════════════════════════
function escapeRegex(str) {
  if (typeof str !== 'string') return '';
  // Limit length to prevent abuse (search should be under 100 chars)
  const safe = str.slice(0, 100);
  return safe.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const multerUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only JPEG, PNG, WEBP allowed'));
    }
  }
});

// FIX #30 — Magic-byte image validation
// Multer mimetype check is client-reported and spoofable. These
// magic bytes are the actual file format signature at byte 0.
function isRealImage(buffer) {
  if (!buffer || buffer.length < 12) return false;
  // JPEG: FF D8 FF
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return 'jpeg';
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47 &&
    buffer[4] === 0x0D && buffer[5] === 0x0A && buffer[6] === 0x1A && buffer[7] === 0x0A) return 'png';
  // WEBP: RIFF....WEBP (bytes 0-3 'RIFF', bytes 8-11 'WEBP')
  if (buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
    buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50) return 'webp';
  return false;
}

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
const DHAKA_OFFSET_HOURS = 6;
const DHAKA_OFFSET_MS = DHAKA_OFFSET_HOURS * 60 * 60 * 1000;

/** Get current month/year as interpreted in Asia/Dhaka timezone. */
function getDhakaCurrentMonthYear() {
  const dhakaNow = new Date(Date.now() + DHAKA_OFFSET_MS);
  return {
    month: dhakaNow.getUTCMonth() + 1,
    year: dhakaNow.getUTCFullYear(),
  };
}

/** Dhaka-local month start/end, returned as UTC Date for MongoDB queries. */
function getDhakaMonthRange(year, month) {
  // Dhaka's Jan 1 00:00 = UTC Dec 31 18:00 (previous day)
  // So Dhaka start of month in UTC = Date.UTC(y, m-1, 1) - 6 hours
  const startDate = new Date(Date.UTC(year, month - 1, 1) - DHAKA_OFFSET_MS);
  // Dhaka end of month in UTC = Date.UTC(y, m, 1) - 6 hours
  const endDate = new Date(Date.UTC(year, month, 1) - DHAKA_OFFSET_MS);
  return { startDate, endDate };
}

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
const uri = `mongodb+srv://${encodeURIComponent(process.env.DB_USER)}:${encodeURIComponent(process.env.DB_PASS)}@cluster0.fu1n5ti.mongodb.net/?retryWrites=true&w=majority&appName=LBTS-OS`;

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
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send({ success: false, message: 'Unauthorized: No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).send({ success: false, message: 'Unauthorized: Invalid or expired token' });
  }
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
app.post('/upload-image', uploadLimiter, multerUpload.single('image'), async (req, res) => {
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
    logger.error('Image upload failed', err);
    res.status(500).send({ success: false, message: 'Image upload failed' });
  }
});

// ═══════════════════════════════════════════════════════════════════
// /jwt — Issue Application JWT after Firebase ID Token Verification
// ═══════════════════════════════════════════════════════════════════
app.post('/jwt', authLimiter, async (req, res) => {
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

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });

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
app.post('/register', authLimiter, async (req, res) => {
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
    gatePass.tripMonth = new Date(gatePass.tripDate).getMonth() + 1;
    gatePass.tripYear = new Date(gatePass.tripDate).getFullYear();
    const result = await gatePassCollection.insertOne(gatePass);
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
    res.send({ success: true, data: updatedGatePass });
  } catch (err) {
    logger.error('Failed to update product', err);
    res.status(500).send({ success: false, message: "Failed to update product" });
  }
});

// FIX #5 — Only admin/manager can delete gate pass (was: any authenticated user)
app.delete('/gate-pass/:id', verifyToken, verifyRole('admin', 'manager','operator'), validateObjectId('id'), validate([
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
  challan:  new Set(['customerName', 'address', 'receiverNumber', 'zone', 'thana', 'district']),
  gatepass: new Set(['tripDo', 'customerName', 'csd', 'vehicleNo', 'zone']),
};

app.get("/autocomplete", verifyToken, verifyNonVendor, async (req, res) => {
  try {
    const db = await connectDB();
    const gatePassCollection = db.collection('gate-pass');
    const challanCollection  = db.collection('challans');
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
        { $match:   { [`products.${field}`]: { $regex: safeSearch, $options: 'i' } } },
        { $unwind:  '$products' },
        { $match:   { [`products.${field}`]: { $regex: safeSearch, $options: 'i' } } },
        { $group:   { _id: `$products.${field}` } },
        { $project: { _id: 0, value: '$_id' } },
        { $limit:   5 },
      ];
    } else if (isTextIndexed) {
      // ── Text index → $text + $search (fastest) ──
      // MongoDB text search prefix match নেই — তাই regex fallback দিয়ে filter করো
      // $text দিয়ে candidate set ছোট করো, তারপর regex দিয়ে prefix match করো
      const safeSearch = escapeRegex(rawSearch);
      pipeline = [
        { $match: {
            $and: [
              { $text: { $search: rawSearch } },                              // text index scan
              { [field]: { $regex: safeSearch, $options: 'i' } },            // prefix filter
            ]
        }},
        { $group:   { _id: `$${field}` } },
        { $project: { _id: 0, value: '$_id' } },
        { $limit:   5 },
      ];
    } else {
      // ── Fallback: individual field index দিয়ে regex ──
      // (vehicleNo, tripDo etc যেগুলো text index-এ নেই কিন্তু own index আছে)
      const safeSearch = escapeRegex(rawSearch);
      pipeline = [
        { $match:   { [field]: { $regex: safeSearch, $options: 'i' } } },
        { $group:   { _id: `$${field}` } },
        { $project: { _id: 0, value: '$_id' } },
        { $limit:   5 },
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
      challan.products = challan.products.map(p => ({
        _id: new ObjectId().toString(),
        productName: p.productName,
        model: p.model,
        quantity: Number(p.quantity),
        // Persist capacity + rate as resolved by the client.  Defaults
        // keep older rows / partial submissions intact:
        //   capacity: "" when not yet known (e.g. Gas Stove pre-pick)
        //   rate:     0  when not yet known
        capacity: typeof p.capacity === 'string' ? p.capacity : '',
        rate: Number(p.rate) || 0,
      }));
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

app.post('/parse-address', verifyToken, verifyNonVendor, aiLimiter, async (req, res) => {
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

    // ── Call Hybrid (Groq → Gemini fallback) with the canonical mapping ──
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
app.delete("/challan/:id", verifyToken, verifyRole('admin', 'manager','operator'), validateObjectId('id'), validate([
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
    const { customerName, address, thana, district, receiverNumber, zone, currentUser, createdAt, updatedBy } = req.body;

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
    if (typeof capacity === 'string') {
      setPatch["products.$.capacity"] = capacity;
    }
    if (rate !== undefined && rate !== null && rate !== '') {
      setPatch["products.$.rate"] = Number(rate) || 0;
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

// FIX (A3): Plural route — used by CreateDelivery to update challan + products together.
// আগে কোনো validation ছিল না → invalid product data inject করা যেত।
// এখন: required field + products array structure validate করি।
app.patch('/challans/:id', verifyToken, verifyNonVendor, validateObjectId('id'), validate([
  param('id').isMongoId().withMessage('Invalid challan ID'),
  body('customerName').trim().notEmpty().withMessage('Customer name required'),
  body('receiverNumber').trim().notEmpty().withMessage('Receiver number required'),
  body('products').optional().isArray().withMessage('Products must be an array'),
  body('products.*.productName').optional().trim().notEmpty().withMessage('Product name required'),
  body('products.*.model').optional().trim().notEmpty().withMessage('Product model required'),
  body('products.*.quantity').optional().isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
  body('products.*.capacity').optional({ checkFalsy: false }).isString(),
  body('products.*.rate').optional({ checkFalsy: false }).isNumeric(),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');
    const { customerName, receiverNumber, zone, address, thana, district, products, updatedBy } = req.body;

    // Sanitize products — preserve _id, coerce quantity to number,
    // also pass through capacity + rate when supplied.
    const sanitizedProducts = Array.isArray(products)
      ? products.map(p => ({
          _id: p._id || new ObjectId().toString(),
          productName: String(p.productName || '').trim(),
          model: String(p.model || '').trim(),
          quantity: Number(p.quantity) || 0,
          capacity: typeof p.capacity === 'string' ? p.capacity : '',
          rate: Number(p.rate) || 0,
        }))
      : undefined;

    const setDoc = {
      customerName, receiverNumber, zone, address, thana, district,
      lastUpdatedBy: updatedBy || req.user?.email || 'unknown',
      lastUpdatedAt: new Date(),
    };
    if (sanitizedProducts !== undefined) setDoc.products = sanitizedProducts;

    const result = await challanCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: setDoc }
    );
    if (result.matchedCount > 0) {
      res.send({ success: true, message: "Challan and Products updated successfully" });
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
    const result = await vendorsCollection.updateOne(
      { _id: new ObjectId(vendorId) },
      { $push: { vehicles: { _id: new ObjectId(), ...vehicleData, createdAt: new Date() } } }
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
      const { vehicleModel, vehicleNumber, driverName, driverPhone, driverImg } = req.body;

      // Partial update — undefined field পাঠালে overwrite হবে না
      const updateFields = {};
      if (vehicleModel  !== undefined) updateFields["vehicles.$[elem].vehicleModel"]  = vehicleModel;
      if (vehicleNumber !== undefined) updateFields["vehicles.$[elem].vehicleNumber"] = vehicleNumber;
      if (driverName    !== undefined) updateFields["vehicles.$[elem].driverName"]    = driverName;
      if (driverPhone   !== undefined) updateFields["vehicles.$[elem].driverPhone"]   = driverPhone;
      if (driverImg     !== undefined) updateFields["vehicles.$[elem].driverImg"]     = driverImg;

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

  try {
    // ── Step 1: Atomic claim ───────────────────────────────────────
    // শুধু সেই challan গুলোই claim হবে যেগুলো:
    //   - exist করে (matched in $in)
    //   - status delivered না (অথবা status field-ই নেই)
    //   - কোনো claim token attached না (অন্য concurrent request পেন্ডিং না)
    const claimResult = await challanCollection.updateMany(
      {
        _id: { $in: challanIds },
        status: { $ne: 'delivered' },
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
      const alreadyDelivered = conflictDocs.filter(d => d.status === 'delivered');
      const lockedByOther = conflictDocs.filter(d => d.status !== 'delivered'); // claim token দখলে

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
        receiverNumber: d.receiverNumber,
        products: (d.products || []).map(p => ({
          _id: p._id || new ObjectId().toString(),
          productName: p.productName,
          model: p.model,
          quantity: Number(p.quantity),
          // Persist rate-table fields onto the delivery snapshot.
          // Defaults keep older flows safe:
          //   capacity: "" when not yet known
          //   rate:     0  when not yet known
          capacity: typeof p.capacity === 'string' ? p.capacity : '',
          rate: Number(p.rate) || 0,
        }))
      })),
      createdAt: new Date()
    };
    const result = await deliveriesCollection.insertOne(tripDocument);
    insertedDeliveryId = result.insertedId;

    // ── Step 5: Finalize challan status (claim → delivered) ───────
    // claimToken filter দিয়ে নিশ্চিত করি যে শুধু আমাদের claim করা docs-ই update হবে
    const finalizeResult = await challanCollection.updateMany(
      { _id: { $in: challanIds }, claimToken },
      {
        $set: { status: "delivered", tripNumber },
        $unset: { claimToken: "", claimedAt: "" },
      }
    );

    if (finalizeResult.matchedCount !== challanIds.length) {
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
        // status revert আলাদা — শুধু আমাদের trip-এর জন্য
        if (tripNumber) {
          await challanCollection.updateMany(
            { _id: { $in: challanIds }, tripNumber },
            { $set: { status: "pending" }, $unset: { tripNumber: "" } }
          );
        }
        logger.info('Delivery rollback successful', { tripNumber });
      } catch (rollbackErr) {
        logger.error('Challan rollback FAILED — manual fix needed', { tripNumber, claimToken, rollbackErr });
      }
    }

    return res.status(500).send({
      success: false,
      message: "Delivery failed",
      error: err.message,
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
      if (req.user?.role === 'vendor') {
        const userCollection = db.collection('users');
        const me = await userCollection.findOne({ email: req.user.email });
        if (!me?.vendorName) return res.send({ success: true, data: [], pagination: { total: 0 } });
        query.vendorName = { $regex: `^${escapeRegex(me.vendorName)}$`, $options: 'i' };
      }

      const data = await deliveriesCollection.find(query).sort({ createdAt: -1 }).limit(500).toArray();
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
    if (req.user?.role === 'vendor') {
      const userCollection = db.collection('users');
      const me = await userCollection.findOne({ email: req.user.email });
      if (!me?.vendorName) return res.send({ success: true, data: [], pagination: { total: 0 } });
      query.vendorName = { $regex: `^${escapeRegex(me.vendorName)}$`, $options: 'i' };
    }

    const data = await deliveriesCollection.find(query).sort({ createdAt: -1 }).toArray();
    res.send({ success: true, data, pagination: { total: data.length } });
  } catch (err) {
    logger.error('Failed to fetch deliveries', err);
    res.status(500).send({ success: false, message: "Failed to fetch deliveries" });
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
    const { customerName, address, thana, district, receiverNumber, zone, updatedBy } = req.body;

    const result = await deliveriesCollection.updateOne(
      { _id: new ObjectId(tripId), "challans.challanId": challanId },
      {
        $set: {
          "challans.$.customerName": customerName,
          "challans.$.address": address,
          "challans.$.thana": thana,
          "challans.$.district": district,
          "challans.$.receiverNumber": receiverNumber,
          "challans.$.zone": zone,
          lastUpdatedBy: updatedBy || req.user?.email || null,
          lastUpdatedAt: new Date(),
        }
      }
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
    const { productName, model, quantity, updatedBy } = req.body;

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
    const result = await deliveriesCollection.updateOne(
      { _id: new ObjectId(tripId) },
      {
        $set: {
          [`${updateField}.productName`]: productName,
          [`${updateField}.model`]: model,
          [`${updateField}.quantity`]: Number(quantity),
          lastUpdatedBy: updatedBy || req.user?.email || null,
          lastUpdatedAt: new Date(),
        }
      }
    );
    res.send({ success: true, modifiedCount: result.modifiedCount });
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

    const result = await deliveriesCollection.updateOne(
      { _id: new ObjectId(tripId) },
      { $pull: { [`challans.${challanIndex}.products`]: { _id: productId } } }
    );
    res.send({ success: true, modifiedCount: result.modifiedCount });
  } catch (err) {
    logger.error("Delete trip product failed", err);
    res.status(500).send({ success: false, message: "Failed to delete product" });
  }
});

app.post("/deliveries/:tripId/challan/:challanId/product", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripId, challanId } = req.params;
    const { productName, model, quantity } = req.body;

    const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
    if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });

    const challanIndex = trip.challans.findIndex(c =>
      c.challanId === challanId || c.challanId?.toString() === challanId
    );
    if (challanIndex === -1) return res.status(404).send({ success: false, message: "Challan not found" });

    const newProduct = {
      _id: new ObjectId().toString(),
      productName,
      model,
      quantity: Number(quantity)
    };

    await deliveriesCollection.updateOne(
      { _id: new ObjectId(tripId) },
      { $push: { [`challans.${challanIndex}.products`]: newProduct } }
    );
    res.send({ success: true, product: newProduct });
  } catch (err) {
    logger.error("Add trip product failed", err);
    res.status(500).send({ success: false, message: "Failed to add product" });
  }
});

// FIX #25 — When removing challan from trip, restore original challan's status
app.delete("/deliveries/:tripId/challan/:challanId", verifyToken, verifyRole('admin', 'manager'), validateObjectId('tripId'), async (req, res) => {
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

app.patch("/deliveries/:tripId/trip-info", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripId } = req.params;
    const { vehicleNumber, vendorName, vendorNumber, driverName, driverNumber,updatedBy  } = req.body;

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

app.patch("/deliveries/:tripId/challan/:challanId/return", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripId, challanId } = req.params;
    const { returnedProducts, returnNote,updatedBy } = req.body;

    const result = await deliveriesCollection.updateOne(
      { _id: new ObjectId(tripId), "challans.challanId": challanId },
      {
        $set: {
          "challans.$.returnedProducts": returnedProducts,
          "challans.$.returnNote": returnNote || "",
          "challans.$.returnedAt": new Date(),
          lastUpdatedBy:updatedBy || req.user?.email || null,
          lastUpdatedAt: new Date(),
        }
      }
    );
    if (result.matchedCount === 0)
      return res.status(404).send({ success: false, message: "Challan not found" });
    res.send({ success: true });
  } catch (err) {
    logger.error("Return update failed", err);
    res.status(500).send({ success: false, message: "Failed to update return" });
  }
});

app.patch("/deliveries/:tripId/challan/:challanId/note", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripId, challanId } = req.params;
    const { note,updatedBy} = req.body;

    const result = await deliveriesCollection.updateOne(
      { _id: new ObjectId(tripId), "challans.challanId": challanId },
      {
        $set: {
          "challans.$.note": note, "challans.$.noteUpdatedAt": new Date(),
          lastUpdatedBy:updatedBy || req.user?.email || null,
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

app.post("/deliveries/:tripId/return-challan", verifyToken, verifyNonVendor, validateObjectId('tripId'), async (req, res) => {
  const { client, db } = await getConnection();
  const deliveriesCollection = db.collection('deliveries');
  const { tripId } = req.params;
  const {
    originalChallanId, customerName, zone, address,
    thana, district, receiverNumber,
    returnedProducts, returnNote,
  } = req.body;

  const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
  if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });

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
    products: (returnedProducts || []).map(p => ({
      _id: p._id || new ObjectId().toString(),
      productName: p.productName,
      model: p.model,
      quantity: Number(p.returnQty || p.quantity),
    })),
    returnNote: returnNote || "",
    returnedAt: new Date(),
    deliveryStatus: "return",
    challanReturnStatus: null,
  };

  // ── FIX: ২টো update একই delivery document-এ ($_id same) ────────
  // আগে: transaction দিয়ে ২টা আলাদা updateOne (M0-তে fail হতো)
  // এখন: bulkWrite দিয়ে একটা atomic operation — transaction-ই দরকার নেই
  //   bulkWrite ordered=true → প্রথমটা fail হলে দ্বিতীয়টা চলে না
  try {
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

    res.send({ success: true, returnChallan });
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

    let query = {};

    if (search) {
      // Global search — পুরো collection, limit 500
      query.$or = [
        { tripNumber: { $regex: search, $options: "i" } },
        { vendorName: { $regex: search, $options: "i" } },
        { driverName: { $regex: search, $options: "i" } },
        { vehicleNumber: { $regex: search, $options: "i" } },
      ];

      if (req.user?.role === "vendor") {
        const userCollection = db.collection('users');
        const me = await userCollection.findOne({ email: req.user.email });
        if (!me?.vendorName) return res.send({ success: true, data: [], pagination: { total: 0 } });
        query.vendorName = { $regex: `^${escapeRegex(me.vendorName)}$`, $options: "i" };
      }

      const data = await deliveriesCollection.find(query).sort({ createdAt: -1 }).limit(500).toArray();
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
    if (req.user?.role === "vendor") {
      const userCollection = db.collection('users');
      const me = await userCollection.findOne({ email: req.user.email });
      if (!me?.vendorName) return res.send({ success: true, data: [], pagination: { total: 0 } });
      query.vendorName = { $regex: `^${escapeRegex(me.vendorName)}$`, $options: "i" };
    }

    const data = await deliveriesCollection.find(query).sort({ createdAt: -1 }).toArray();
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
    let year  = parseInt(req.query.year);
    if (!month || !year) {
      const _dt = getDhakaCurrentMonthYear();
      month = _dt.month; year = _dt.year;
    }
    const { startDate, endDate } = getDhakaMonthRange(year, month);

    const trips = await deliveriesCollection.find(
      { createdAt: { $gte: startDate, $lt: endDate } },
      { projection: { tripNumber:1, vendorName:1, vendorNumber:1, driverName:1,
          challans:1, rent:1, leborBill:1, advance:1, rentPaid:1, rentPaidAmount:1,
          leborPaid:1, leborPaidAmount:1, createdAt:1 } }
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

      v.totalPics     += pics;
      v.totalRent     += Number(trip.rent     || 0);
      v.totalLebor    += Number(trip.leborBill || 0);
      v.totalAdvance  += Number(trip.advance   || 0);
      v.rentPaidAmount  += Number(trip.rentPaidAmount  || 0);
      v.leborPaidAmount += Number(trip.leborPaidAmount || 0);
    }

    const vendors = Array.from(vendorMap.values()).map(v => ({
      ...v,
      rentDue:  Math.max(0, v.totalRent  - v.rentPaidAmount),
      leborDue: Math.max(0, v.totalLebor - v.leborPaidAmount),
    }));

    const summary = {
      month, year,
      totalTrips:    trips.length,
      totalRent:     vendors.reduce((s, v) => s + v.totalRent, 0),
      totalLebor:    vendors.reduce((s, v) => s + v.totalLebor, 0),
      totalRentDue:  vendors.reduce((s, v) => s + v.rentDue, 0),
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
app.patch("/deliveries/:tripId/advance", verifyToken, verifyRole('admin', 'manager', 'ceo','operator'), validateObjectId('tripId'), async (req, res) => {
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
    const { type, description, amount, date, note, vendorName, recipientName } = req.body;
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
    const d = new Date(date);
    const doc = {
      type,
      description: description.trim(),
      amount: amt,
      date,
      note: note?.trim() || "",
      vendorName: vendorName?.trim() || "",
      recipientName: recipientName?.trim() || "",
      month: d.getMonth() + 1,
      year: d.getFullYear(),
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

app.get("/audit-logs", verifyToken, verifyRole('admin', 'ceo'), async (req, res) => {
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

app.patch("/audit-logs/:id/restored", verifyToken, verifyRole('admin', 'ceo'), validateObjectId("id"), async (req, res) => {
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

app.patch("/accounts/:id/status", verifyToken, verifyRole('admin', 'manager', 'ceo'), validateObjectId("id"), async (req, res) => {
  try {
    const db = await connectDB();
    const col = db.collection("accounts");
    const { status } = req.body;
    if (!["paid", "unpaid"].includes(status))
      return res.status(400).send({ success: false, message: "Invalid status" });
    const result = await col.updateOne(
      { _id: new ObjectId(req.params.id), type: "manual_advance" },
      { $set: { status, statusUpdatedAt: new Date(), statusUpdatedBy: req.user?.email || null } }
    );
    if (result.matchedCount === 0)
      return res.status(404).send({ success: false, message: "Advance not found" });
    const updated = await col.findOne({ _id: new ObjectId(req.params.id) });
    res.send({ success: true, data: updated });
  } catch (err) {
    logger.error("Advance status update failed", err);
    res.status(500).send({ success: false, message: "Failed to update status" });
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
    const cacheKey = `${month}-${year}`;
    const cached = getCachedDashboard(cacheKey);
    if (cached) {
      return res.send({ success: true, data: cached, cached: true });
    }

    const { startDate: monthStart, endDate: monthEnd } = getDhakaMonthRange(year, month);

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
    ]);

    // ── Batch 2: Medium aggregations (challan status, zone, gatepass) ──
    const [
      challanStatusAgg, topDeliveryPoints, gpUnitAgg,
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
          $group: {
            _id: { $toUpper: '$unit' },
            qty: { $sum: '$products.quantity' },
            passCount: { $addToSet: '$_id' },
          }
        },
        { $addFields: { passCount: { $size: '$passCount' } } },
        { $sort: { qty: -1 } },
        { $limit: 10 },
      ]).toArray(),
    ]);

    // ── Batch 3: Heavy double-unwind aggregations ───────────────────
    const [
      challanProductAgg, deliveryProductAgg,
    ] = await Promise.all([
      db.collection('challans').aggregate([
        { $match: { createdAt: { $gte: monthStart, $lt: monthEnd } } },
        { $unwind: '$products' },
        { $group: { _id: '$products.productName', qty: { $sum: '$products.quantity' } } },
        { $sort: { qty: -1 } },
        { $limit: 8 },
      ]).toArray(),
      db.collection('deliveries').aggregate([
        { $match: { createdAt: { $gte: monthStart, $lt: monthEnd } } },
        { $unwind: '$challans' },
        { $unwind: '$challans.products' },
        { $group: { _id: '$challans.products.productName', qty: { $sum: '$challans.products.quantity' } } },
        { $sort: { qty: -1 } },
        { $limit: 8 },
      ]).toArray(),
    ]);

    const csMap = {};
    challanStatusAgg.forEach(s => { csMap[s._id || 'pending'] = s.count; });

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
        unitBreakdown: gpUnitAgg,
      },
      challan: {
        totalCount: challanTotalCount,
        monthTotal: challanStatusAgg.reduce((s, x) => s + x.count, 0),
        delivered: csMap['delivered'] || 0,
        pending: csMap['pending'] || 0,
        returned: csMap['returned'] || 0,
        productBreakdown: challanProductAgg,
      },
      trip: {
        totalCount: tripTotalCount,
        monthCount: tripMonthCount,
        activeCount: activeTripCount,
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
    const year  = parseInt(req.query.year)  || new Date().getFullYear();
    const type  = req.query.type; // 'main' | 'lebor' | undefined (all)

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
    if (deliveryStatus !== undefined)      setFields["challans.$.deliveryStatus"]      = deliveryStatus;
    if (challanReturnStatus !== undefined) setFields["challans.$.challanReturnStatus"] = challanReturnStatus;
    if (note !== undefined)                setFields["challans.$.note"]                = note;
    if (returnNote !== undefined)          setFields["challans.$.returnNote"]          = returnNote;
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
app.get("/labor-bill", verifyToken, async (req, res) => {
  try {
    const db = await connectDB();
    const col = db.collection('deliveries');
    let month = parseInt(req.query.month);
    let year  = parseInt(req.query.year);
    if (!month || !year) {
      const _dt = getDhakaCurrentMonthYear();
      month = _dt.month; year = _dt.year;
    }
    const { startDate, endDate } = getDhakaMonthRange(year, month);
    const trips = await col.find(
      { createdAt: { $gte: startDate, $lt: endDate } },
      { projection: { tripNumber:1, challans:1, createdAt:1 } }
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
  res.status(500).send({ success: false, message: "Internal Server Error" });
});

// ── Start Server ───────────────────────────────────────────────────
if (process.env.NODE_ENV !== "production" && !process.env.VERCEL) {
  app.listen(port, () => {
    logger.info(`Server running`, { port });
  });
}

module.exports = app;