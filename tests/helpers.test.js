// ═══════════════════════════════════════════════════════════════════
//  Tests — utils/helpers.js  (run: npm test)
// ═══════════════════════════════════════════════════════════════════
const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
    escapeRegex,
    isRealImage,
    getDhakaCurrentMonthYear,
    getDhakaMonthRange,
} = require('../utils/helpers');

// ── escapeRegex ────────────────────────────────────────────────────
test('escapeRegex escapes all regex metacharacters', () => {
    assert.equal(escapeRegex('a.b*c+d?'), 'a\\.b\\*c\\+d\\?');
    assert.equal(escapeRegex('(x)|[y]{z}^$\\'), '\\(x\\)\\|\\[y\\]\\{z\\}\\^\\$\\\\');
});

test('escapeRegex handles non-strings and caps length at 100', () => {
    assert.equal(escapeRegex(null), '');
    assert.equal(escapeRegex(undefined), '');
    assert.equal(escapeRegex(12345), '');
    const long = 'a'.repeat(500);
    assert.equal(escapeRegex(long).length, 100);
});

test('escapeRegex output is safe to feed to new RegExp', () => {
    const nasty = '(((((((.*+?';
    assert.doesNotThrow(() => new RegExp(escapeRegex(nasty)));
});

// ── isRealImage (magic bytes) ──────────────────────────────────────
test('isRealImage detects JPEG / PNG / WEBP by magic bytes', () => {
    const jpeg = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0, 0, 0, 0, 0]);
    const png = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0]);
    const webp = Buffer.from([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50]);
    assert.equal(isRealImage(jpeg), 'jpeg');
    assert.equal(isRealImage(png), 'png');
    assert.equal(isRealImage(webp), 'webp');
});

test('isRealImage rejects spoofed/mislabeled files', () => {
    const fakeExe = Buffer.from('MZ......this is not an image....');
    const tiny = Buffer.from([0xFF, 0xD8]);
    assert.equal(isRealImage(fakeExe), false);
    assert.equal(isRealImage(tiny), false);      // < 12 bytes
    assert.equal(isRealImage(null), false);
});

// ── Dhaka timezone helpers ─────────────────────────────────────────
test('getDhakaMonthRange: Jan 2026 Dhaka month = UTC Dec 31 18:00 → Jan 31 18:00', () => {
    const { startDate, endDate } = getDhakaMonthRange(2026, 1);
    assert.equal(startDate.toISOString(), '2025-12-31T18:00:00.000Z');
    assert.equal(endDate.toISOString(), '2026-01-31T18:00:00.000Z');
});

test('getDhakaCurrentMonthYear rolls to next month at Dhaka midnight', () => {
    // UTC 2026-06-30 19:00 == Dhaka 2026-07-01 01:00 → July in Dhaka
    const utcLateJune = Date.UTC(2026, 5, 30, 19, 0, 0);
    const r = getDhakaCurrentMonthYear(utcLateJune);
    assert.deepEqual(r, { month: 7, year: 2026 });

    // UTC 2026-06-30 17:00 == Dhaka 2026-06-30 23:00 → still June
    const utcEarlier = Date.UTC(2026, 5, 30, 17, 0, 0);
    assert.deepEqual(getDhakaCurrentMonthYear(utcEarlier), { month: 6, year: 2026 });
});