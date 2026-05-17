/**
 * ═══════════════════════════════════════════════════════════════════
 *  LBTS-OS — Groq Address Parser (STRICT v2)
 * ═══════════════════════════════════════════════════════════════════
 *
 *  POLICY: NEVER return a thana the AI guessed.
 *  ────────────────────────────────────────────────────────────────
 *  If Groq cannot identify the thana from the address text, it MUST
 *  return null for thana. The system prompt and validation enforce
 *  this. Common mistakes (returning the district's Sadar thana when
 *  no real thana is in the address) are detected and dropped.
 *
 *  The Hybrid parser will then fall through to Gemini.
 * ═══════════════════════════════════════════════════════════════════
 */

const axios = require('axios');
const {
  isValidThanaForDistrict,
  canonicaliseThana,
  canonicaliseDistrict,
  DISTRICTS_WITH_THANAS,
} = require('../constants/bangladeshThanaData');

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_MODEL = 'llama-3.3-70b-versatile';

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
  return null;
}

/**
 * Detect if AI returned a "lazy Sadar" — i.e. the address doesn't mention
 * any real thana, but the AI returned the district's Sadar thana as a guess.
 * We drop those.
 *
 * Heuristic: if the returned thana is "<District> Sadar" or "Kotwali" or
 * matches the district name itself, AND the address text does NOT contain
 * any token that looks like that thana — it's a guess. Drop it.
 */
function isLazySadarGuess(address, thana, district) {
  if (!thana || !district) return false;
  const addrLower = address.toLowerCase();
  const thanaLower = thana.toLowerCase();
  const districtLower = district.toLowerCase();

  // Check if address mentions the thana itself
  const thanaWords = thanaLower.split(/\s+/);
  for (const w of thanaWords) {
    if (w.length >= 4 && addrLower.includes(w)) return false; // thana name is in address
  }

  // Lazy patterns: "<District> Sadar", "Kotwali", or thana name == district name
  const looksLikeSadar = /sadar$/i.test(thana) ||
                        /^kotwali/i.test(thana) ||
                        thanaLower.startsWith(districtLower);
  return looksLikeSadar;
}

function buildPrompt(rawAddress, thanaDistrictMap, approvedDistricts) {
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

  return `You are a STRICT Bangladesh address parser.

ORIGINAL ADDRESS:
"""
${rawAddress}
"""

═══════════════════════════════════════════════════
⚠️ CRITICAL RULES — READ CAREFULLY BEFORE ANSWERING
═══════════════════════════════════════════════════

1. NEVER GUESS A THANA. If the address text does NOT clearly contain a real
   thana name (or a well-known bazar/area that you know maps to a specific
   thana), set "thana" to null. NEVER substitute the district's Sadar thana
   as a guess.

2. NEVER use the district's name as the thana. If you can only identify the
   district, return:
       { "thana": null, "district": "<DistrictName>", ... }

3. The THANA returned MUST be listed under the matching DISTRICT below.
   Use the EXACT spelling shown for that district.

4. Bangla → English transliteration is OK. Examples:
     • "মিরপুর" → "Mirpur"
     • "ঢাকা" → "Dhaka"
     • "ফুলপুর" → "Fulpur"   (NOT "Phulpur" — use the canonical spelling)

5. Common bazar / area mappings (these are NOT guesses — these are KNOWN):
     • "Madhobdi" / "Madhabdi"  → thana: "Narsingdi Sadar", district: "Narsingdi"
     • "Bashundhara R/A"        → thana: "Bhatara",         district: "Dhaka"
     • "Agrabad"                → thana: "Double Mooring",  district: "Chattogram"
     • "Mohakhali"              → thana: "Banani",          district: "Dhaka"
     • "Maijdee" / "Maijdi"     → thana: "Sudharam",        district: "Noakhali"
     • "Chowmuhani"             → thana: "Begumganj",       district: "Noakhali"
     • "GEC" / "Nasirabad"      → thana: "Panchlaish",      district: "Chattogram"

6. If the address is unclear, output null for whichever field you cannot
   determine. NEVER fabricate. NEVER fill in "to be helpful". null is the
   correct answer when uncertain.

7. Clean the address (fix spacing, correct spelling of thana/district names
   to match the approved spellings below).

═══════════════════════════════════════════════════
APPROVED DISTRICTS:
${approvedDistricts.join(', ')}

${mappingText ? `THANA → DISTRICT MAPPING (thana name MUST come from the matching district):
${mappingText}

` : ''}═══════════════════════════════════════════════════

Confidence levels:
- "high": Both thana and district CLEARLY in the address, exact text match.
- "medium": One field clear, other inferred from a well-known bazar/area name.
- "low": Significant guessing. In this case use null for uncertain fields.

Return ONLY valid JSON:
{"cleanAddress":"...","thana":"... or null","district":"... or null","confidence":"high|medium|low","notes":"brief note explaining what you found and what you set to null"}`;
}

async function parseAddressWithGroq(
  rawAddress,
  thanaDistrictMap = {},
  approvedDistricts = []
) {
  if (!process.env.GROQ_API_KEY) {
    return { success: false, error: 'no-api-key', message: 'GROQ_API_KEY not set' };
  }
  if (!rawAddress || typeof rawAddress !== 'string' || rawAddress.trim().length < 3) {
    return { success: false, error: 'invalid-input', message: 'Address too short' };
  }

  const truncated = rawAddress.trim().substring(0, 1000);
  const prompt = buildPrompt(truncated, thanaDistrictMap, approvedDistricts);

  try {
    const response = await axios.post(
      GROQ_URL,
      {
        model: GROQ_MODEL,
        messages: [
          {
            role: 'system',
            content:
              'You are a STRICT Bangladesh address parsing expert. ' +
              'You NEVER guess a thana — if the address does not clearly contain a real thana name, ' +
              'you return null for the thana field. You NEVER use the district name or its Sadar thana ' +
              'as a substitute. Return valid JSON only.',
          },
          { role: 'user', content: prompt },
        ],
        temperature: 0.05,
        max_tokens: 800,
        response_format: { type: 'json_object' },
      },
      {
        timeout: 10000,
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
        },
      }
    );

    const text = response.data?.choices?.[0]?.message?.content;
    console.log('[Groq Parse]', { input: truncated.substring(0, 50), raw: text?.substring(0, 200) });

    if (!text) {
      return { success: false, error: 'empty-response', message: 'Empty Groq response' };
    }

    const parsed = extractJSON(text);
    if (!parsed || typeof parsed.cleanAddress !== 'string') {
      return { success: false, error: 'parse-failed', message: 'Could not parse Groq response' };
    }

    let thana = parsed.thana && parsed.thana !== 'null' ? String(parsed.thana).trim() : null;
    let district = parsed.district && parsed.district !== 'null' ? String(parsed.district).trim() : null;
    let confidence = ['high', 'medium', 'low'].includes(parsed.confidence) ? parsed.confidence : 'low';
    let notes = String(parsed.notes || '').substring(0, 200);

    // ── Canonicalise casing ──
    if (district) {
      const canon = canonicaliseDistrict(district);
      if (canon) district = canon;
    }
    if (thana && district) {
      const canon = canonicaliseThana(thana, district);
      if (canon) thana = canon;
    }

    // ── Validation Layer 1: thana must exist in district ──
    if (thana && district && !isValidThanaForDistrict(thana, district)) {
      console.warn('[Groq Parse] Invalid thana/district — dropping thana:', { thana, district });
      notes = `Dropped invalid "${thana}" for ${district}. ${notes}`.substring(0, 200);
      thana = null;
      confidence = 'low';
    }

    // ── Validation Layer 2: lazy Sadar guess detection ──
    if (thana && district && isLazySadarGuess(rawAddress, thana, district)) {
      console.warn('[Groq Parse] Lazy Sadar guess detected — dropping thana:', { thana, district });
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
      provider: 'groq',
    };
  } catch (err) {
    console.error('[Groq Parse] Error:', err.message, err.response?.data);
    if (err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT') {
      return { success: false, error: 'timeout', message: 'Groq request timed out' };
    }
    if (err.response?.status === 429) {
      return { success: false, error: 'rate-limit', message: 'Groq rate limit exceeded' };
    }
    if (err.response?.status === 401) {
      return { success: false, error: 'auth-failed', message: 'Invalid Groq API key' };
    }
    if (err.response?.status === 400) {
      return {
        success: false,
        error: 'bad-request',
        message: 'Bad request to Groq',
        details: err.response?.data?.error?.message,
      };
    }
    return { success: false, error: 'unknown', message: err.message };
  }
}

module.exports = { parseAddressWithGroq };