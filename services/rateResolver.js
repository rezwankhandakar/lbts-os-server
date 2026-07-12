// ═══════════════════════════════════════════════════════════════════
//  LBTS-OS — Server-side Rate Resolver
// ═══════════════════════════════════════════════════════════════════
//
//  WHY THIS EXISTS (FIX #50):
//  আগে server client-পাঠানো `rate` মানকে অন্ধভাবে বিশ্বাস করত —
//  `rate: Number(p.rate) || 0`। যেকোনো logged-in user API দিয়ে
//  ইচ্ছামতো rate পাঠিয়ে bill-এর হিসাব বদলাতে পারত।
//
//  এখন: rate সবসময় server-এর নিজস্ব rate table থেকে resolve হয়
//  (client-এর rateMatcher.js-এর হুবহু একই algorithm)। Client-পাঠানো
//  rate শুধু cross-check-এর জন্য ব্যবহার হয়:
//    - Server resolve করতে পারলে → server-এর মানই save হয় (authoritative)
//    - Server resolve করতে না পারলে → 0 save হয়; client nonzero
//      পাঠালে tamper-warning log হয়
//
//  ROLLOUT SAFETY:
//    env RATE_GUARD_MODE=warn দিলে enforce না করে শুধু log করবে
//    (পুরনো data/edge-case ধরার জন্য প্রথম কয়েকদিন warn-এ চালাতে পারেন)।
//    Default: enforce
// ═══════════════════════════════════════════════════════════════════

const { WITH_MODEL_DATA, WITHOUT_MODEL_DATA } = require('../constants/rateTable');

const LOCATION_KEYS = ['ISD', 'OSD-Metro', 'OSD-Thana'];

const norm = (s) => (s == null ? '' : String(s).trim().toLowerCase());

const includesCI = (big, small) => {
    const b = norm(big);
    const s = norm(small);
    return !!s && b.includes(s);
};

// Client-এর productMatches-এর হুবহু port — দুই দিকেই substring match।
const productMatches = (typed, candidate) => {
    const a = norm(typed);
    const b = norm(candidate);
    if (!a || !b) return false;
    if (a === b) return true;
    if (a.length >= 3 && b.includes(a)) return true;
    if (b.length >= 3 && a.includes(b)) return true;
    return false;
};

/**
 * Client rateMatcher.findRate()-এর server-side twin।
 * @return {{ capacity: string, rate: number, source: string, needsCapacity: boolean }}
 */
function findRate({ productName, model, location, capacity }) {
    const empty = { capacity: '', rate: 0, source: 'none', needsCapacity: false };

    if (!productName || !location || !LOCATION_KEYS.includes(location)) {
        return empty;
    }

    // ── 1. WITH-MODEL first (more specific) ──
    if (model) {
        for (const row of WITH_MODEL_DATA) {
            if (!productMatches(productName, row.product)) continue;
            if (!includesCI(model, row.model)) continue;
            return {
                capacity: row.capacity || '',
                rate: Number(row[location]) || 0,
                source: 'with-model',
                needsCapacity: false,
            };
        }
    }

    // ── 2. WITHOUT-MODEL ──
    const rows = WITHOUT_MODEL_DATA.filter((row) => productMatches(productName, row.product));
    if (rows.length === 0) return empty;

    if (capacity && String(capacity).trim()) {
        const exact = rows.find((r) => norm(r.capacity) === norm(capacity));
        if (exact) {
            return {
                capacity: exact.capacity || '',
                rate: Number(exact[location]) || 0,
                source: 'without-model',
                needsCapacity: false,
            };
        }
        return { capacity: '', rate: 0, source: 'without-model', needsCapacity: rows.length > 1 };
    }

    if (rows.length === 1) {
        const r = rows[0];
        return {
            capacity: r.capacity || '',
            rate: Number(r[location]) || 0,
            source: 'without-model',
            needsCapacity: false,
        };
    }

    return { capacity: '', rate: 0, source: 'without-model', needsCapacity: true };
}

/**
 * Authoritative rate resolution — সব write-path এ ব্যবহার করুন।
 *
 * @param {Object} args
 * @param {string}  args.productName
 * @param {string}  args.model
 * @param {string}  args.location      "ISD" | "OSD-Metro" | "OSD-Thana" | null
 * @param {string}  args.capacity      client-supplied capacity (optional)
 * @param {number}  args.clientRate    client-supplied rate (cross-check only)
 * @param {Object}  [args.logger]      optional logger for tamper warnings
 * @param {string}  [args.context]     route name for the log line
 * @param {string}  [args.userEmail]   who sent the request
 *
 * @return {{ capacity: string, rate: number, source: string, tampered: boolean }}
 */
function resolveAuthoritativeRate({
    productName, model, location, capacity, clientRate,
    logger, context = '', userEmail = '',
}) {
    const mode = (process.env.RATE_GUARD_MODE || 'enforce').toLowerCase();
    const clientNum = Number(clientRate) || 0;

    const resolved = findRate({ productName, model, location, capacity });

    // ── Case 1: server resolve করতে পেরেছে ──
    if (resolved.rate > 0) {
        const tampered = clientNum !== 0 && clientNum !== resolved.rate;
        if (tampered && logger) {
            logger.warn('RATE GUARD: client rate mismatch — server value used', {
                context, userEmail, productName, model, location, capacity,
                clientRate: clientNum, serverRate: resolved.rate,
            });
        }
        if (mode === 'warn' && tampered) {
            // Warn-only mode: client value save হবে, শুধু log
            return { capacity: resolved.capacity, rate: clientNum, source: resolved.source, tampered };
        }
        return { capacity: resolved.capacity, rate: resolved.rate, source: resolved.source, tampered };
    }

    // ── Case 2: server resolve করতে পারেনি (table-এ নেই / location নেই /
    //           capacity এখনো pick হয়নি) ──
    // বৈধ client-ও এই ক্ষেত্রে 0 পাঠায় (একই table থেকে হিসাব করে)।
    // Nonzero এলে সেটা হয় table drift, নয়তো tampering — log করি।
    const tampered = clientNum !== 0;
    if (tampered && logger) {
        logger.warn('RATE GUARD: unresolvable product got nonzero client rate', {
            context, userEmail, productName, model, location, capacity,
            clientRate: clientNum, mode,
        });
    }
    if (mode === 'warn') {
        return { capacity: typeof capacity === 'string' ? capacity : '', rate: clientNum, source: 'unverified', tampered };
    }
    return { capacity: typeof capacity === 'string' ? capacity : '', rate: 0, source: resolved.source, tampered };
}

module.exports = { findRate, resolveAuthoritativeRate, LOCATION_KEYS };