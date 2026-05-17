/**
 * ═══════════════════════════════════════════════════════════════════
 *  LBTS-OS — Gemini Address Parser (STRICT v2 + MULTI-KEY ROTATION)
 * ═══════════════════════════════════════════════════════════════════
 *
 *  POLICY: Same strict no-guessing rules as Groq. Never returns a
 *  fabricated thana. If uncertain → thana: null.
 *
 *  MULTI-KEY ROTATION:
 *  ────────────────────────────────────────────────────────────────
 *  Set up to 6 Gemini API keys in .env:
 *      GEMINI_API_KEY=AIza...        (key 1, default)
 *      GEMINI_API_KEY_2=AIza...
 *      GEMINI_API_KEY_3=AIza...
 *      GEMINI_API_KEY_4=AIza...
 *      GEMINI_API_KEY_5=AIza...
 *      GEMINI_API_KEY_6=AIza...
 *
 *  When a key hits its daily/per-minute limit (HTTP 429) or is rejected
 *  (HTTP 403), the parser AUTOMATICALLY rotates to the next available
 *  key for THIS request. The cooled-down key is then put on a short
 *  cooldown (default 60 minutes) so we don't keep hitting it.
 *
 *  Cooldowns are in-memory only — restart the server and all keys reset.
 *  This is intentional: we don't want stale cooldown state across deploys.
 * ═══════════════════════════════════════════════════════════════════
 */

const axios = require('axios');
const {
  isValidThanaForDistrict,
  canonicaliseThana,
  canonicaliseDistrict,
} = require('../constants/bangladeshThanaData');

const GEMINI_MODEL = 'gemini-2.5-flash';
const GEMINI_BASE = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;

// ═══════════════════════════════════════════════════════════════════
//  KEY POOL — read once at module load, then rotate at runtime.
// ═══════════════════════════════════════════════════════════════════

/**
 * Read all configured Gemini keys from process.env.
 * Order: GEMINI_API_KEY, GEMINI_API_KEY_2, GEMINI_API_KEY_3, ...
 *
 * Returns an array of { name, value, cooldownUntil } objects. cooldownUntil
 * is the epoch-ms timestamp after which the key can be tried again.
 */
function loadKeyPool() {
  const keys = [];
  const primary = process.env.GEMINI_API_KEY;
  if (primary) keys.push({ name: 'GEMINI_API_KEY', value: primary, cooldownUntil: 0 });
  for (let i = 2; i <= 10; i++) {
    const v = process.env[`GEMINI_API_KEY_${i}`];
    if (v) keys.push({ name: `GEMINI_API_KEY_${i}`, value: v, cooldownUntil: 0 });
  }
  return keys;
}

// Singleton pool — module-level state. Mutated as keys hit cooldowns.
const KEY_POOL = loadKeyPool();

// How long to cool a key down after a 429/403 (in milliseconds).
const COOLDOWN_RATELIMIT_MS = 60 * 60 * 1000;   // 1 hour for rate-limit
const COOLDOWN_AUTH_MS      = 24 * 60 * 60 * 1000; // 24 hours for auth-fail

/**
 * Get the next available key (not on cooldown). Returns null if all are
 * cooled down or none configured.
 */
function pickAvailableKey() {
  const now = Date.now();
  for (const k of KEY_POOL) {
    if (k.cooldownUntil <= now) return k;
  }
  return null;
}

/** Put a specific key on cooldown. */
function coolDownKey(key, reason) {
  const ms = reason === 'auth' ? COOLDOWN_AUTH_MS : COOLDOWN_RATELIMIT_MS;
  key.cooldownUntil = Date.now() + ms;
  console.warn(`[Gemini] Key "${key.name}" cooled down for ${ms / 60000} min (reason: ${reason})`);
}

/** Pretty status of the pool (useful for health endpoints). */
function poolStatus() {
  const now = Date.now();
  return KEY_POOL.map((k) => ({
    name: k.name,
    available: k.cooldownUntil <= now,
    cooldownRemainingMin: Math.max(0, Math.round((k.cooldownUntil - now) / 60000)),
  }));
}

// ═══════════════════════════════════════════════════════════════════
//  JSON extraction
// ═══════════════════════════════════════════════════════════════════

function extractJSON(text) {
  if (!text) return null;
  try { return JSON.parse(text.trim()); } catch {}
  try {
    const cleaned = text.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim();
    return JSON.parse(cleaned);
  } catch {}
  try {
    const match = text.match(/\{[\s\S]*\}/);
    if (match) return JSON.parse(match[0]);
  } catch {}
  try {
    const start = text.indexOf('{');
    const end = text.lastIndexOf('}');
    if (start !== -1 && end > start) return JSON.parse(text.substring(start, end + 1));
  } catch {}
  return null;
}

// ═══════════════════════════════════════════════════════════════════
//  Lazy Sadar guess detector (same as Groq parser)
// ═══════════════════════════════════════════════════════════════════

function isLazySadarGuess(address, thana, district) {
  if (!thana || !district) return false;
  const addrLower = address.toLowerCase();
  const thanaLower = thana.toLowerCase();
  const districtLower = district.toLowerCase();
  const thanaWords = thanaLower.split(/\s+/);
  for (const w of thanaWords) {
    if (w.length >= 4 && addrLower.includes(w)) return false;
  }
  const looksLikeSadar = /sadar$/i.test(thana) ||
                        /^kotwali/i.test(thana) ||
                        thanaLower.startsWith(districtLower);
  return looksLikeSadar;
}

// ═══════════════════════════════════════════════════════════════════
//  Low-level HTTP call with auto-rotation
// ═══════════════════════════════════════════════════════════════════

/**
 * Make a Gemini API call. Automatically rotates to next available key
 * on 429/403 and retries (up to all keys in the pool). Returns the
 * axios response data on success, or throws on final failure.
 */
async function geminiCall(body, opts = {}) {
  if (KEY_POOL.length === 0) {
    const err = new Error('No Gemini API keys configured');
    err.code = 'no-api-key';
    throw err;
  }

  const attempts = [];
  let lastError = null;

  // Try each available key once
  for (let i = 0; i < KEY_POOL.length; i++) {
    const key = pickAvailableKey();
    if (!key) {
      const err = new Error('All Gemini keys are cooled down');
      err.code = 'all-cooled-down';
      err.poolStatus = poolStatus();
      throw err;
    }

    try {
      const response = await axios.post(
        `${GEMINI_BASE}?key=${key.value}`,
        body,
        {
          timeout: opts.timeout || 15000,
          headers: { 'Content-Type': 'application/json' },
        }
      );
      attempts.push({ key: key.name, status: 'ok' });
      console.log(`[Gemini] Success with key "${key.name}" (attempts: ${attempts.length})`);
      return response.data;
    } catch (err) {
      const status = err.response?.status;
      attempts.push({ key: key.name, status });
      lastError = err;

      if (status === 429) {
        coolDownKey(key, 'ratelimit');
        // Try next key
        continue;
      }
      if (status === 403) {
        coolDownKey(key, 'auth');
        continue;
      }
      // Any other error — don't rotate, just throw
      throw err;
    }
  }

  // Exhausted all keys
  const err = new Error('All Gemini keys exhausted');
  err.code = 'all-exhausted';
  err.attempts = attempts;
  err.lastError = lastError?.message;
  throw err;
}

// ═══════════════════════════════════════════════════════════════════
//  Step 1: web-grounded context lookup
// ═══════════════════════════════════════════════════════════════════

async function searchAddressContext(rawAddress) {
  const prompt = `Find the exact thana (upazila) and district in Bangladesh for this address:

"${rawAddress}"

Search the web. Provide:
1. Which thana this address belongs to (use null if you cannot find a real thana)
2. Which district this address belongs to
3. Brief explanation

Use English names. Be concise. If you cannot find a specific thana, say so — do NOT guess.`;

  try {
    const data = await geminiCall(
      {
        contents: [{ parts: [{ text: prompt }] }],
        tools: [{ google_search: {} }],
        generationConfig: { temperature: 0.2, maxOutputTokens: 800 },
      },
      { timeout: 20000 }
    );
    return data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
  } catch (err) {
    console.error('[Gemini Search] Failed:', err.message, err.code);
    return '';
  }
}

// ═══════════════════════════════════════════════════════════════════
//  Step 2: structured extraction with mapping
// ═══════════════════════════════════════════════════════════════════

async function extractStructured(rawAddress, searchContext, thanaDistrictMap, approvedDistricts) {
  let mappingText = '';
  if (thanaDistrictMap && typeof thanaDistrictMap === 'object') {
    const lines = [];
    for (const [district, thanas] of Object.entries(thanaDistrictMap)) {
      if (Array.isArray(thanas) && thanas.length > 0) {
        lines.push(`${district}: ${thanas.join(', ')}`);
      }
    }
    mappingText = lines.join('\n');
  }

  const prompt = `You are a STRICT Bangladesh address parser.

ORIGINAL ADDRESS:
"""
${rawAddress}
"""

${searchContext ? `WEB SEARCH RESULTS:
"""
${searchContext}
"""

Use the search results to identify thana and district. If the search
results do not clearly identify the thana, return null for thana — do NOT
guess based on the district.

` : ''}═══════════════════════════════════════════════════
⚠️ CRITICAL RULES — READ CAREFULLY
═══════════════════════════════════════════════════

1. NEVER GUESS A THANA. If the address (and search results) do NOT clearly
   contain a real thana name, set "thana" to null. NEVER substitute the
   district's Sadar thana as a guess.

2. NEVER use the district's name as the thana.

3. The THANA returned MUST be listed under the matching DISTRICT below.
   Use the EXACT spelling shown for that district.

4. Decode Bangla and legacy fonts (SutonnyMJ, Bhanga, Bijoy ANSI).
   Transliterate using canonical spellings:
     • ফুলপুর → "Fulpur" (NOT "Phulpur")
     • শ্যামপুর → "Shyampur"
     • ভাটারা → "Bhatara"

5. Well-known bazar / area mappings (these are NOT guesses):
     • "Madhobdi" / "Madhabdi"  → "Narsingdi Sadar", Narsingdi
     • "Bashundhara R/A"        → "Bhatara",         Dhaka
     • "Agrabad"                → "Double Mooring",  Chattogram
     • "Mohakhali"              → "Banani",          Dhaka
     • "Maijdee" / "Maijdi"     → "Sudharam",        Noakhali
     • "Chowmuhani"             → "Begumganj",       Noakhali
     • "GEC" / "Nasirabad"      → "Panchlaish",      Chattogram

6. If you cannot determine the thana, output null. null is the CORRECT
   answer when uncertain. NEVER fabricate to be helpful.

═══════════════════════════════════════════════════
APPROVED DISTRICTS:
${approvedDistricts.join(', ')}

${mappingText ? `THANA → DISTRICT MAPPING:
${mappingText}

` : ''}═══════════════════════════════════════════════════

Confidence:
- "high": Both fields clearly identified in address or search results.
- "medium": One field clear, other from well-known area name.
- "low": Significant guessing → use null for uncertain fields.

Return ONLY valid JSON:
{"cleanAddress":"...","thana":"... or null","district":"... or null","confidence":"high|medium|low","notes":"..."}`;

  const data = await geminiCall(
    {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.05,
        maxOutputTokens: 1024,
        responseMimeType: 'application/json',
        responseSchema: {
          type: 'object',
          properties: {
            cleanAddress: { type: 'string' },
            thana: { type: 'string', nullable: true },
            district: { type: 'string', nullable: true },
            confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
            notes: { type: 'string' },
          },
          required: ['cleanAddress', 'confidence'],
        },
      },
    },
    { timeout: 15000 }
  );

  const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  console.log('[Gemini Parse]', {
    input: rawAddress.substring(0, 50),
    hasSearch: !!searchContext,
    raw: text?.substring(0, 200),
  });

  if (!text) return null;
  return extractJSON(text);
}

// ═══════════════════════════════════════════════════════════════════
//  Main parser
// ═══════════════════════════════════════════════════════════════════

async function parseAddressWithGemini(
  rawAddress,
  thanaDistrictMap = {},
  approvedDistricts = []
) {
  if (KEY_POOL.length === 0) {
    return {
      success: false,
      error: 'no-api-key',
      message: 'No GEMINI_API_KEY* configured in environment',
    };
  }
  if (!rawAddress || typeof rawAddress !== 'string' || rawAddress.trim().length < 3) {
    return { success: false, error: 'invalid-input', message: 'Address too short' };
  }

  const truncated = rawAddress.trim().substring(0, 1000);

  try {
    const searchContext = await searchAddressContext(truncated);
    const parsed = await extractStructured(truncated, searchContext, thanaDistrictMap, approvedDistricts);

    if (!parsed || typeof parsed.cleanAddress !== 'string') {
      return { success: false, error: 'parse-failed', message: 'Could not parse Gemini response' };
    }

    let thana = parsed.thana && parsed.thana !== 'null' ? String(parsed.thana).trim() : null;
    let district = parsed.district && parsed.district !== 'null' ? String(parsed.district).trim() : null;
    let confidence = ['high', 'medium', 'low'].includes(parsed.confidence) ? parsed.confidence : 'low';
    let notes = String(parsed.notes || '').substring(0, 200);

    if (district) {
      const canon = canonicaliseDistrict(district);
      if (canon) district = canon;
    }
    if (thana && district) {
      const canon = canonicaliseThana(thana, district);
      if (canon) thana = canon;
    }

    // Validation Layer 1: invalid combination
    if (thana && district && !isValidThanaForDistrict(thana, district)) {
      console.warn('[Gemini Parse] Invalid thana/district — dropping thana:', { thana, district });
      notes = `Dropped invalid "${thana}" for ${district}. ${notes}`.substring(0, 200);
      thana = null;
      confidence = 'low';
    }

    // Validation Layer 2: lazy Sadar guess
    if (thana && district && isLazySadarGuess(rawAddress, thana, district)) {
      console.warn('[Gemini Parse] Lazy Sadar guess — dropping thana:', { thana, district });
      notes = `Dropped lazy Sadar guess "${thana}" (not in address). ${notes}`.substring(0, 200);
      thana = null;
      confidence = 'low';
    }

    return {
      success: true,
      cleanAddress: parsed.cleanAddress.trim(),
      thana,
      district,
      confidence,
      notes,
      provider: 'gemini',
      groundedWithSearch: !!searchContext,
    };
  } catch (err) {
    console.error('[Gemini Parse] Error:', err.message, err.code, err.attempts);
    if (err.code === 'all-exhausted' || err.code === 'all-cooled-down') {
      return {
        success: false,
        error: 'all-keys-exhausted',
        message: 'All Gemini keys hit rate limits or are cooled down. Try later.',
        poolStatus: poolStatus(),
      };
    }
    if (err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT') {
      return { success: false, error: 'timeout', message: 'Gemini timed out' };
    }
    return { success: false, error: 'unknown', message: err.message };
  }
}

module.exports = { parseAddressWithGemini, poolStatus };