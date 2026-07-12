// ═══════════════════════════════════════════════════════════════════
//  Tests — services/rateResolver.js  (run: npm test)
//  টাকার হিসাবের মূল logic — regression এখানে ধরা পড়বে।
// ═══════════════════════════════════════════════════════════════════
const { test, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const { findRate, resolveAuthoritativeRate } = require('../services/rateResolver');

beforeEach(() => { delete process.env.RATE_GUARD_MODE; });

// ── findRate: with-model matching ──────────────────────────────────
test('with-model: model substring match resolves capacity + rate', () => {
    // "WFA-2A3-GDEL-XX" contains "2A3" → Refrigerator Gross 151-285 Litre
    const r = findRate({
        productName: 'Refrigerator',
        model: 'WFA-2A3-GDEL-XX',
        location: 'OSD-Metro',
    });
    assert.equal(r.source, 'with-model');
    assert.equal(r.capacity, 'Gross 151-285 Litre');
    assert.equal(r.rate, 1450);
});

test('with-model: case-insensitive product + model match', () => {
    const r = findRate({ productName: 'refrigerator ', model: 'xx-1b5-yy', location: 'ISD' });
    assert.equal(r.rate, 650);
});

// ── findRate: without-model matching ───────────────────────────────
test('without-model: single-row product resolves by name + location', () => {
    const r = findRate({ productName: 'Ceiling Fan', model: '', location: 'OSD-Thana' });
    assert.equal(r.source, 'without-model');
    assert.equal(r.rate, 145);
});

test('without-model: multi-capacity product needs a capacity pick', () => {
    const noCap = findRate({ productName: 'Gas Stove', model: '', location: 'ISD' });
    assert.equal(noCap.rate, 0);
    assert.equal(noCap.needsCapacity, true);

    const withCap = findRate({ productName: 'Gas Stove', model: '', location: 'ISD', capacity: 'Double' });
    assert.equal(withCap.rate, 132);
    assert.equal(withCap.needsCapacity, false);
});

test('unknown product / invalid location → empty result', () => {
    assert.equal(findRate({ productName: 'Spaceship', model: '', location: 'ISD' }).rate, 0);
    assert.equal(findRate({ productName: 'Ceiling Fan', model: '', location: 'Mars' }).rate, 0);
});

// ── resolveAuthoritativeRate: the security guard ───────────────────
test('guard: server-resolvable product → server rate wins over tampered client rate', () => {
    const r = resolveAuthoritativeRate({
        productName: 'Refrigerator', model: '2A3', location: 'ISD',
        clientRate: 99999, // tampered
    });
    assert.equal(r.rate, 950);      // server value, NOT 99999
    assert.equal(r.tampered, true);
});

test('guard: honest client rate matches server → no tamper flag', () => {
    const r = resolveAuthoritativeRate({
        productName: 'Refrigerator', model: '2A3', location: 'ISD',
        clientRate: 950,
    });
    assert.equal(r.rate, 950);
    assert.equal(r.tampered, false);
});

test('guard: unresolvable product + nonzero client rate → clamped to 0 (enforce mode)', () => {
    const r = resolveAuthoritativeRate({
        productName: 'Unknown Gadget', model: '', location: 'ISD',
        clientRate: 5000,
    });
    assert.equal(r.rate, 0);
    assert.equal(r.tampered, true);
});

test('guard: unresolved-yet product with client rate 0 → clean pass-through', () => {
    // Gas Stove capacity এখনো pick হয়নি — বৈধ client-ও 0 পাঠায়
    const r = resolveAuthoritativeRate({
        productName: 'Gas Stove', model: '', location: 'ISD',
        clientRate: 0,
    });
    assert.equal(r.rate, 0);
    assert.equal(r.tampered, false);
});

test('guard: RATE_GUARD_MODE=warn keeps client value but flags tamper', () => {
    process.env.RATE_GUARD_MODE = 'warn';
    const r = resolveAuthoritativeRate({
        productName: 'Refrigerator', model: '2A3', location: 'ISD',
        clientRate: 99999,
    });
    assert.equal(r.rate, 99999);    // warn mode: save হয় কিন্তু log হয়
    assert.equal(r.tampered, true);
});

test('guard: no location → rate clamps to 0 unless client also sent 0', () => {
    const clean = resolveAuthoritativeRate({
        productName: 'Refrigerator', model: '2A3', location: null, clientRate: 0,
    });
    assert.equal(clean.rate, 0);
    assert.equal(clean.tampered, false);

    const dirty = resolveAuthoritativeRate({
        productName: 'Refrigerator', model: '2A3', location: null, clientRate: 777,
    });
    assert.equal(dirty.rate, 0);
    assert.equal(dirty.tampered, true);
});