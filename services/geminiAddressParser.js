/** geminiAddressParser.js Server site file 
 * ═══════════════════════════════════════════════════════════════════
 *  LBTS-OS — Gemini Address Parser (Fallback with Web Search)
 * ═══════════════════════════════════════════════════════════════════
 *
 *  PURPOSE:
 *  Fallback parser when Groq cannot detect thana/district.
 *  Uses Google Search grounding to find specific businesses/landmarks.
 *
 *  ENV: GEMINI_API_KEY=AIza... (from https://aistudio.google.com/apikey)
 *
 *  STRENGTHS: Web search, specific business detection
 *  WEAKNESSES: Slower (3-8 sec), lower rate limit (15/min, 1500/day)
 *
 *  USAGE: Called only when Groq returns low confidence + missing fields
 * ═══════════════════════════════════════════════════════════════════
 */

const axios = require('axios');

const GEMINI_MODEL = 'gemini-2.5-flash';
const GEMINI_URL = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;

// ─────────────────────────────────────────────────────────────────
//  JSON extraction with multiple strategies
// ─────────────────────────────────────────────────────────────────
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
    if (start !== -1 && end > start) {
      return JSON.parse(text.substring(start, end + 1));
    }
  } catch {}
  return null;
}

// ─────────────────────────────────────────────────────────────────
//  Step 1: Search the web for address context
// ─────────────────────────────────────────────────────────────────
async function searchAddressContext(rawAddress) {
  const prompt = `Find the exact thana (upazila) and district in Bangladesh for this address:

"${rawAddress}"

Search the web. Provide:
1. Which thana this address belongs to
2. Which district this address belongs to
3. Brief explanation

Be concise. Use English names. If unsure, say so clearly.`;

  try {
    const response = await axios.post(
      `${GEMINI_URL}?key=${process.env.GEMINI_API_KEY}`,
      {
        contents: [{ parts: [{ text: prompt }] }],
        tools: [{ google_search: {} }],
        generationConfig: { temperature: 0.2, maxOutputTokens: 800 },
      },
      { timeout: 20000, headers: { 'Content-Type': 'application/json' } }
    );
    return response.data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
  } catch (err) {
    console.error('[Gemini Search] Failed:', err.message);
    return '';
  }
}

// ─────────────────────────────────────────────────────────────────
//  Step 2: Structured extraction with search context
// ─────────────────────────────────────────────────────────────────
async function extractStructured(rawAddress, searchContext, approvedThanas, approvedDistricts) {
  const prompt = `You are a Bangladesh address parser.

ORIGINAL ADDRESS:
"""
${rawAddress}
"""

${searchContext ? `WEB SEARCH RESULTS:
"""
${searchContext}
"""

Use the search results above to identify thana and district.

` : ''}INSTRUCTIONS:
1. Convert Bangla text to English (মিরপুর → Mirpur).
2. Decode legacy fonts (SutonnyMJ, Bhanga, Bijoy) if present.
3. Identify THANA and DISTRICT.
4. Clean the address format.
5. Correct spelling.

APPROVED DISTRICTS:
${approvedDistricts.join(', ')}

${approvedThanas.length > 0 ? `KNOWN THANAS:\n${approvedThanas.join(', ')}\n` : ''}

Confidence:
- "high": Both fields clearly identified
- "medium": One clear, other inferred
- "low": Guessing → use null for uncertain fields

Return ONLY valid JSON:
{"cleanAddress":"...","thana":"... or null","district":"... or null","confidence":"high|medium|low","notes":"..."}`;

  const response = await axios.post(
    `${GEMINI_URL}?key=${process.env.GEMINI_API_KEY}`,
    {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.1,
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
    { timeout: 15000, headers: { 'Content-Type': 'application/json' } }
  );

  const text = response.data?.candidates?.[0]?.content?.parts?.[0]?.text;
  console.log('[Gemini Parse]', {
    input: rawAddress.substring(0, 50),
    hasSearch: !!searchContext,
    raw: text?.substring(0, 200),
  });

  if (!text) return null;
  return extractJSON(text);
}

// ─────────────────────────────────────────────────────────────────
//  Main parser (with web search)
// ─────────────────────────────────────────────────────────────────
async function parseAddressWithGemini(rawAddress, approvedThanas = [], approvedDistricts = []) {
  if (!process.env.GEMINI_API_KEY) {
    return { success: false, error: 'no-api-key', message: 'GEMINI_API_KEY not set' };
  }

  if (!rawAddress || typeof rawAddress !== 'string' || rawAddress.trim().length < 3) {
    return { success: false, error: 'invalid-input', message: 'Address too short' };
  }

  const truncated = rawAddress.trim().substring(0, 1000);

  try {
    // Always search the web for fallback addresses (we only get here when Groq failed)
    const searchContext = await searchAddressContext(truncated);
    const parsed = await extractStructured(truncated, searchContext, approvedThanas, approvedDistricts);

    if (!parsed || typeof parsed.cleanAddress !== 'string') {
      return {
        success: false,
        error: 'parse-failed',
        message: 'Could not parse Gemini response',
      };
    }

    return {
      success: true,
      cleanAddress: parsed.cleanAddress.trim(),
      thana: parsed.thana && parsed.thana !== 'null' ? String(parsed.thana).trim() : null,
      district: parsed.district && parsed.district !== 'null' ? String(parsed.district).trim() : null,
      confidence: ['high', 'medium', 'low'].includes(parsed.confidence) ? parsed.confidence : 'low',
      notes: String(parsed.notes || '').substring(0, 200),
      provider: 'gemini',
      groundedWithSearch: !!searchContext,
    };

  } catch (err) {
    console.error('[Gemini Parse] Error:', err.message, err.response?.data);

    if (err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT') {
      return { success: false, error: 'timeout', message: 'Gemini timed out' };
    }
    if (err.response?.status === 429) {
      return { success: false, error: 'rate-limit', message: 'Gemini rate limit' };
    }
    if (err.response?.status === 403) {
      return { success: false, error: 'auth-failed', message: 'Gemini API key invalid' };
    }
    return { success: false, error: 'unknown', message: err.message };
  }
}

module.exports = { parseAddressWithGemini };