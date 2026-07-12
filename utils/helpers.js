// ═══════════════════════════════════════════════════════════════════
//  LBTS-OS — Pure helper functions (extracted from index.js)
// ═══════════════════════════════════════════════════════════════════
//  এই ফাইলে কোনো DB/network dependency নেই — শুধু pure functions,
//  তাই `node --test` দিয়ে সহজে test করা যায় (tests/helpers.test.js)।
// ═══════════════════════════════════════════════════════════════════

// ── FIX #3 — Regex escape helper (prevents ReDoS + regex injection) ──
function escapeRegex(str) {
    if (typeof str !== 'string') return '';
    // Limit length to prevent abuse (search should be under 100 chars)
    const safe = str.slice(0, 100);
    return safe.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ── FIX #30 — Magic-byte image validation ──
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

// ═══════════════════════════════════════════════════════════════════
// FIX #29 — Asia/Dhaka Timezone Helpers
// ═══════════════════════════════════════════════════════════════════
// Server runs UTC (Vercel), users work in Dhaka time (UTC+6).
const DHAKA_OFFSET_HOURS = 6;
const DHAKA_OFFSET_MS = DHAKA_OFFSET_HOURS * 60 * 60 * 1000;

/** Get current month/year as interpreted in Asia/Dhaka timezone. */
function getDhakaCurrentMonthYear(now = Date.now()) {
    const dhakaNow = new Date(now + DHAKA_OFFSET_MS);
    return {
        month: dhakaNow.getUTCMonth() + 1,
        year: dhakaNow.getUTCFullYear(),
    };
}

/** Dhaka-local month start/end, returned as UTC Date for MongoDB queries. */
function getDhakaMonthRange(year, month) {
    const startDate = new Date(Date.UTC(year, month - 1, 1) - DHAKA_OFFSET_MS);
    const endDate = new Date(Date.UTC(year, month, 1) - DHAKA_OFFSET_MS);
    return { startDate, endDate };
}

module.exports = {
    escapeRegex,
    isRealImage,
    getDhakaCurrentMonthYear,
    getDhakaMonthRange,
    DHAKA_OFFSET_MS,
};