/**
 * ═══════════════════════════════════════════════════════════════════
 *  LBTS-OS — Groq Address Parser
 * ═══════════════════════════════════════════════════════════════════
 *
 *  PURPOSE:
 *  Fast structured extraction using Groq (Llama 3.3 70B).
 *  Used as PRIMARY parser — handles most addresses in <1 sec.
 *
 *  ENV: GROQ_API_KEY=gsk_... (from https://console.groq.com)
 *
 *  LIMITS:
 *  - Free tier: 30 req/min, 14,400 req/day
 *  - JSON mode: native (uses `response_format: json_object`)
 *
 *  STRENGTHS: Fast, high quota, good for clear addresses
 *  WEAKNESSES: No web search → cannot find specific small businesses
 * ═══════════════════════════════════════════════════════════════════
 */

const axios = require('axios');

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_MODEL = 'llama-3.3-70b-versatile'; // Best for structured extraction

// ─────────────────────────────────────────────────────────────────
//  Robust JSON extraction
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
  return null;
}

// ─────────────────────────────────────────────────────────────────
//  Build prompt
// ─────────────────────────────────────────────────────────────────
function buildPrompt(rawAddress, approvedThanas, approvedDistricts) {
  return `You are a Bangladesh address parser. Extract structured data from delivery addresses.

ORIGINAL ADDRESS:
"""
${rawAddress}
"""

INSTRUCTIONS:
1. Convert Bangla text to English transliteration (মিরপুর → Mirpur, ঢাকা → Dhaka).
2. If text is in legacy Bangla fonts (SutonnyMJ, Bhanga, Bijoy ANSI), decode and transliterate.
3. Identify THANA (upazila/sub-district) and DISTRICT (zila).
4. Clean the address: format consistently, fix spacing.
5. Correct spelling mistakes for thana/district names.

APPROVED DISTRICTS (use these EXACT spellings):
${approvedDistricts.join(', ')}

${approvedThanas.length > 0 ? `KNOWN THANAS in our system (prefer these, but use valid BD thana names if needed):\n${approvedThanas.join(', ')}\n` : ''}

Confidence levels:
- "high": Both thana and district clearly identified or strongly inferable
- "medium": One field clear, other inferred from context
- "low": Significant guessing → use null for uncertain fields

CRITICAL: Return ONLY valid JSON with these exact field names:
{"cleanAddress":"...","thana":"... or null","district":"... or null","confidence":"high|medium|low","notes":"brief note"}`;
}

// ─────────────────────────────────────────────────────────────────
//  Main parser
// ─────────────────────────────────────────────────────────────────
async function parseAddressWithGroq(rawAddress, approvedThanas = [], approvedDistricts = []) {
  if (!process.env.GROQ_API_KEY) {
    return {
      success: false,
      error: 'no-api-key',
      message: 'GROQ_API_KEY not set',
    };
  }

  if (!rawAddress || typeof rawAddress !== 'string' || rawAddress.trim().length < 3) {
    return {
      success: false,
      error: 'invalid-input',
      message: 'Address too short',
    };
  }

  const truncated = rawAddress.trim().substring(0, 1000);
  const prompt = buildPrompt(truncated, approvedThanas, approvedDistricts);

  try {
    const response = await axios.post(
      GROQ_URL,
      {
        model: GROQ_MODEL,
        messages: [
          {
            role: 'system',
            content: 'You are a Bangladesh address parsing expert. Always respond with valid JSON only.',
          },
          { role: 'user', content: prompt },
        ],
        temperature: 0.1,
        max_tokens: 800,
        response_format: { type: 'json_object' }, // ← Forces JSON
      },
      {
        timeout: 10000,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
        },
      }
    );

    const text = response.data?.choices?.[0]?.message?.content;

    console.log('[Groq Parse]', {
      input: truncated.substring(0, 50),
      raw: text?.substring(0, 200),
    });

    if (!text) {
      return { success: false, error: 'empty-response', message: 'Empty Groq response' };
    }

    const parsed = extractJSON(text);

    if (!parsed || typeof parsed.cleanAddress !== 'string') {
      return {
        success: false,
        error: 'parse-failed',
        message: 'Could not parse Groq response',
      };
    }

    return {
      success: true,
      cleanAddress: parsed.cleanAddress.trim(),
      thana: parsed.thana && parsed.thana !== 'null' ? String(parsed.thana).trim() : null,
      district: parsed.district && parsed.district !== 'null' ? String(parsed.district).trim() : null,
      confidence: ['high', 'medium', 'low'].includes(parsed.confidence) ? parsed.confidence : 'low',
      notes: String(parsed.notes || '').substring(0, 200),
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