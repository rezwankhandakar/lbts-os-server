/**
 * ═══════════════════════════════════════════════════════════════════
 *  LBTS-OS — Hybrid Address Parser (Groq + Gemini)
 * ═══════════════════════════════════════════════════════════════════
 *
 *  STRATEGY:
 *  1. Try Groq first (fast, high quota, no web search)
 *  2. If Groq returns LOW confidence AND missing thana/district AND
 *     address might benefit from web search → fallback to Gemini
 *  3. Pick the better result
 *
 *  COST OPTIMIZATION:
 *  - 80% addresses solved by Groq alone (1 fast call, ~0.5 sec)
 *  - 20% addresses fallback to Gemini with web search (~5 sec, 2 calls)
 *
 *  Provider used is returned in `provider` field of response.
 * ═══════════════════════════════════════════════════════════════════
 */

const { parseAddressWithGroq } = require('./groqAddressParser');
const { parseAddressWithGemini } = require('./geminiAddressParser');

// ─────────────────────────────────────────────────────────────────
//  Heuristic: should we try Gemini fallback?
// ─────────────────────────────────────────────────────────────────
function shouldFallbackToGemini(groqResult, rawAddress) {
  // Groq failed entirely → try Gemini
  if (!groqResult.success) return true;

  // Groq returned low confidence + missing fields → maybe Gemini can do better
  if (groqResult.confidence === 'low' && (!groqResult.thana || !groqResult.district)) {
    return true;
  }

  // Address has only district but no thana, and confidence is medium → try Gemini for thana
  if (groqResult.confidence === 'medium' && !groqResult.thana) {
    return true;
  }

  return false;
}

// ─────────────────────────────────────────────────────────────────
//  Pick the better result between two providers
// ─────────────────────────────────────────────────────────────────
function pickBetter(a, b) {
  if (!a.success && !b.success) return a; // both failed, return first
  if (!a.success) return b;
  if (!b.success) return a;

  const confScore = { high: 3, medium: 2, low: 1 };
  const fieldsScore = (r) => (r.thana ? 1 : 0) + (r.district ? 1 : 0);

  const scoreA = (confScore[a.confidence] || 0) * 10 + fieldsScore(a);
  const scoreB = (confScore[b.confidence] || 0) * 10 + fieldsScore(b);

  return scoreB > scoreA ? b : a;
}

// ─────────────────────────────────────────────────────────────────
//  Main hybrid parser
// ─────────────────────────────────────────────────────────────────
async function parseAddressHybrid(rawAddress, approvedThanas = [], approvedDistricts = []) {
  // ── Step 1: Try Groq first (fast path) ──
  const groqResult = await parseAddressWithGroq(rawAddress, approvedThanas, approvedDistricts);

  console.log('[Hybrid] Groq result:', {
    success: groqResult.success,
    confidence: groqResult.confidence,
    thana: groqResult.thana,
    district: groqResult.district,
  });

  // ── Step 2: Decide on fallback ──
  if (!shouldFallbackToGemini(groqResult, rawAddress)) {
    // Groq was good enough — return immediately
    return groqResult;
  }

  // ── Step 3: Fallback to Gemini with web search ──
  console.log('[Hybrid] Falling back to Gemini with web search');
  const geminiResult = await parseAddressWithGemini(rawAddress, approvedThanas, approvedDistricts);

  console.log('[Hybrid] Gemini result:', {
    success: geminiResult.success,
    confidence: geminiResult.confidence,
    thana: geminiResult.thana,
    district: geminiResult.district,
  });

  // ── Step 4: Pick the better one ──
  const finalResult = pickBetter(groqResult, geminiResult);

  console.log('[Hybrid] Final:', {
    provider: finalResult.provider,
    confidence: finalResult.confidence,
  });

  return finalResult;
}

module.exports = { parseAddressHybrid };