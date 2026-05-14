// ═══════════════════════════════════════════════════════════════════
//  STEP 1: এই import গুলো index.js-এর উপরের অংশে (অন্য require-এর পাশে) যোগ করুন
// ═══════════════════════════════════════════════════════════════════

const { parseAddressWithGemini } = require('./services/geminiAddressParser');
const { BANGLADESH_DISTRICTS } = require('./constants/bangladeshDistricts');


// ═══════════════════════════════════════════════════════════════════
//  STEP 2: এই rate limiter অন্য rate limiter-গুলোর পাশে যোগ করুন
//  (line ~182, uploadLimiter এর নিচে)
// ═══════════════════════════════════════════════════════════════════

const aiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 15, // 15 AI calls per minute per IP (matches Gemini free tier)
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false },
  message: { success: false, message: 'Too many AI requests, please wait a moment' }
});


// ═══════════════════════════════════════════════════════════════════
//  STEP 3: এই endpoint টা challan-related endpoints-এর কাছাকাছি যোগ করুন
//  (line ~1225, /challan/recent endpoint-এর পরে ভালো জায়গা)
// ═══════════════════════════════════════════════════════════════════

/**
 * POST /parse-address
 * Body: { address: "raw user-pasted address" }
 *
 * Uses Gemini AI to extract structured thana/district from messy address text.
 * Supports Bangla, English, mixed, and legacy font input.
 */
app.post('/parse-address', verifyToken, verifyNonVendor, aiLimiter, async (req, res) => {
  try {
    const { address } = req.body;

    if (!address || typeof address !== 'string' || address.trim().length < 3) {
      return res.status(400).send({
        success: false,
        message: 'Address must be at least 3 characters',
      });
    }

    // ── Step A: Get existing thanas from DB (for context) ──
    const db = await connectDB();
    const challanCollection = db.collection('challans');

    // Pull distinct thanas that already exist in our system
    // Limit to 200 to keep prompt size reasonable
    const existingThanas = await challanCollection
      .distinct('thana', { thana: { $exists: true, $ne: null, $ne: '' } });

    const approvedThanas = existingThanas
      .filter(t => typeof t === 'string' && t.trim().length > 0)
      .map(t => t.trim())
      .slice(0, 200);

    // ── Step B: Check cache first (saves API calls for repeat addresses) ──
    const crypto = require('crypto');
    const cacheKey = crypto
      .createHash('sha256')
      .update(address.trim().toLowerCase())
      .digest('hex');

    const cacheCollection = db.collection('address_cache');
    const cached = await cacheCollection.findOne({ _id: cacheKey });

    if (cached && cached.expiresAt > new Date()) {
      logger.info?.('Address cache HIT', { cacheKey: cacheKey.substring(0, 8) });
      return res.send({
        success: true,
        ...cached.result,
        cached: true,
      });
    }

    // ── Step C: Call Gemini ──
    const result = await parseAddressWithGemini(
      address,
      approvedThanas,
      BANGLADESH_DISTRICTS
    );

    if (!result.success) {
      return res.status(502).send(result);
    }

    // ── Step D: Save to cache (30 days TTL) ──
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
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    };

    // Upsert (don't fail request if cache write fails)
    cacheCollection.updateOne(
      { _id: cacheKey },
      { $set: cacheDoc },
      { upsert: true }
    ).catch(err => logger.error?.('Cache write failed', err));

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
    logger.error?.('Parse address failed', err);
    res.status(500).send({
      success: false,
      message: 'Failed to parse address',
    });
  }
});