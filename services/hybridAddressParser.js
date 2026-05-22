/**
 * ═══════════════════════════════════════════════════════════════════
 *  LBTS-OS — Hybrid Address Parser (STRICT v3 — Gemini only)
 * ═══════════════════════════════════════════════════════════════════
 *
 *  STRATEGY (updated):
 *   • Local matcher (client-side) runs FIRST. If it returns a
 *     confident thana + district match, the request never reaches
 *     this server-side parser.
 *   • Otherwise, fall back to Gemini directly. Groq has been removed
 *     from the chain (per user request) — Gemini handles everything.
 *
 *  POLICY:
 *   • NEVER guess. NEVER fill in district's Sadar as a placeholder.
 *   • Gemini sets thana=null when uncertain → that's the final answer.
 *
 *  Gemini has built-in multi-key rotation (up to 10 keys).
 * ═══════════════════════════════════════════════════════════════════
 */

const { parseAddressWithGemini } = require('./geminiAddressParser');

/**
 * @param {string}   rawAddress
 * @param {object}   thanaDistrictMap  DISTRICTS_WITH_THANAS object
 * @param {string[]} approvedDistricts flat list of 64 districts
 */
async function parseAddressHybrid(rawAddress, thanaDistrictMap = {}, approvedDistricts = []) {
  // ── Gemini (with web search + multi-key rotation) ──
  const geminiResult = await parseAddressWithGemini(
    rawAddress,
    thanaDistrictMap,
    approvedDistricts
  );

  console.log('[Hybrid] Gemini:', {
    success: geminiResult.success,
    confidence: geminiResult.confidence,
    thana: geminiResult.thana,
    district: geminiResult.district,
  });

  return geminiResult;
}

module.exports = { parseAddressHybrid };