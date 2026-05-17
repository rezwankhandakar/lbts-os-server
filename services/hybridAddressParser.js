/**
 * ═══════════════════════════════════════════════════════════════════
 *  LBTS-OS — Hybrid Address Parser (STRICT v2)
 * ═══════════════════════════════════════════════════════════════════
 *
 *  STRATEGY:
 *   1. Try Groq first (fast, high quota, no web search).
 *   2. If Groq returns null thana → fallback to Gemini (with web search).
 *   3. Pick whichever result has the highest confidence + most fields.
 *
 *  POLICY (per user requirement):
 *   • Local matcher (client-side) already returned null/null/null OR
 *     a perfectly confident match — we only get here when local failed.
 *   • Groq sets thana=null when uncertain → triggers Gemini.
 *   • Gemini sets thana=null when uncertain → that's the final answer.
 *   • NEVER guess. NEVER fill in district's Sadar as a placeholder.
 *
 *  Gemini has built-in multi-key rotation (up to 6 keys).
 * ═══════════════════════════════════════════════════════════════════
 */

const { parseAddressWithGroq } = require('./groqAddressParser');
const { parseAddressWithGemini } = require('./geminiAddressParser');

/**
 * Decide whether to invoke Gemini after Groq's response.
 * Rule: only skip Gemini if Groq returned a CONFIDENT (high) result with
 * BOTH thana AND district. Anything else → Gemini gets a chance.
 */
function shouldFallbackToGemini(groqResult) {
  if (!groqResult.success) return true;
  if (!groqResult.thana || !groqResult.district) return true;
  if (groqResult.confidence !== 'high') return true;
  return false;
}

/**
 * Score a result for comparison. Higher = better.
 *   • confidence weighted heavily (high=3, medium=2, low=1)
 *   • +1 for each non-null field (thana, district)
 *   • having a thana counts double (since that's the harder field)
 */
function scoreResult(r) {
  if (!r || !r.success) return -1;
  const confScore = { high: 30, medium: 20, low: 10 }[r.confidence] || 0;
  const fieldScore = (r.thana ? 2 : 0) + (r.district ? 1 : 0);
  return confScore + fieldScore;
}

function pickBetter(a, b) {
  if (!a?.success && !b?.success) return a || b;
  if (!a?.success) return b;
  if (!b?.success) return a;
  return scoreResult(b) > scoreResult(a) ? b : a;
}

/**
 * @param {string}   rawAddress
 * @param {object}   thanaDistrictMap  DISTRICTS_WITH_THANAS object
 * @param {string[]} approvedDistricts flat list of 64 districts
 */
async function parseAddressHybrid(rawAddress, thanaDistrictMap = {}, approvedDistricts = []) {
  // ── Step 1: Groq (fast path) ──
  const groqResult = await parseAddressWithGroq(rawAddress, thanaDistrictMap, approvedDistricts);

  console.log('[Hybrid] Groq:', {
    success: groqResult.success,
    confidence: groqResult.confidence,
    thana: groqResult.thana,
    district: groqResult.district,
  });

  if (!shouldFallbackToGemini(groqResult)) {
    return groqResult;
  }

  // ── Step 2: Gemini (with web search + multi-key rotation) ──
  console.log('[Hybrid] Falling back to Gemini (Groq incomplete)');
  const geminiResult = await parseAddressWithGemini(rawAddress, thanaDistrictMap, approvedDistricts);

  console.log('[Hybrid] Gemini:', {
    success: geminiResult.success,
    confidence: geminiResult.confidence,
    thana: geminiResult.thana,
    district: geminiResult.district,
  });

  const finalResult = pickBetter(groqResult, geminiResult);

  console.log('[Hybrid] Final:', {
    provider: finalResult.provider,
    confidence: finalResult.confidence,
    thana: finalResult.thana,
    district: finalResult.district,
  });

  return finalResult;
}

module.exports = { parseAddressHybrid };