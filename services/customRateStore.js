// ═══════════════════════════════════════════════════════════════════
//  LBTS-OS — Custom Rate Store (DB-backed product/model overrides)
// ═══════════════════════════════════════════════════════════════════
//
//  কেন এটা আছে:
//  আগে নতুন product/model যোগ করতে হলে client-এর withModelData.js +
//  withoutModelData.js আর server-এর constants/rateTable.js — তিন
//  জায়গায় হাতে code লিখে redeploy করতে হতো।
//
//  এখন: `rate_entries` collection-এ admin UI থেকে row যোগ হয়।
//  constants/rateTable.js এখনো baseline (built-in) table হিসেবে থাকে —
//  কিছুই delete করা হয়নি, তাই পুরনো behaviour অটুট। DB-র row গুলো
//  baseline-এর **আগে** বসে, তাই একই product+model দিয়ে নতুন row
//  বানালে সেটা baseline rate কে override করে।
//
//  Caching: serverless (Vercel) instance-এ ৬০ সেকেন্ডের in-memory
//  cache। প্রথম load await হয়, তারপর stale হলে background-এ refresh
//  (request latency বাড়ে না)। Admin add/edit/delete করলে ওই instance-এ
//  সাথে সাথে invalidate হয়, বাকি instance সর্বোচ্চ ৬০s এ ধরে ফেলে।
// ═══════════════════════════════════════════════════════════════════

const {
    WITH_MODEL_DATA,
    WITH_MODEL_PRODUCTS,
    WITH_MODEL_MODELS_BY_PRODUCT,
    WITHOUT_MODEL_DATA,
    WITHOUT_MODEL_PRODUCTS,
    WITHOUT_MODEL_CAPACITY_BY_PRODUCT,
} = require('../constants/rateTable');

const COLLECTION = 'rate_entries';
const CACHE_TTL_MS = 60 * 1000;
const LOCATION_KEYS = ['ISD', 'OSD-Metro', 'OSD-Thana'];

const norm = (s) => (s == null ? '' : String(s).trim().toLowerCase());

// ── In-memory cache ────────────────────────────────────────────────
let cache = {
    withModel: [],
    withoutModel: [],
    loadedAt: 0,
    version: 0,
    ready: false,
};
let inflight = null;

// Merged (custom + baseline) memoised by cache.version so findRate()
// একটা loop-এ হাজারবার call হলেও array বারবার তৈরি হয় না।
let merged = null;
let mergedVersion = -1;

/** Mongo doc → matcher row shape (rateTable.js এর row-এর হুবহু আকার) */
function docToRow(doc) {
    const rates = doc.rates || {};
    const row = {
        product: String(doc.product || '').trim(),
        capacity: doc.capacity ? String(doc.capacity).trim() : null,
        _custom: true,
        _id: String(doc._id),
    };
    if (doc.type === 'with-model') {
        row.model = String(doc.model || '').trim();
    }
    for (const k of LOCATION_KEYS) row[k] = Number(rates[k]) || 0;
    return row;
}

/** DB থেকে active custom rows পড়ে cache ভরে */
async function loadCustomRates(db, { force = false } = {}) {
    if (!force && cache.ready && Date.now() - cache.loadedAt < CACHE_TTL_MS) {
        return cache;
    }
    if (inflight) return inflight;

    inflight = (async () => {
        const docs = await db
            .collection(COLLECTION)
            .find({ active: { $ne: false } })
            .sort({ createdAt: 1 })
            .toArray();

        const withModel = [];
        const withoutModel = [];

        for (const d of docs) {
            const row = docToRow(d);
            if (!row.product) continue;
            if (d.type === 'with-model') {
                if (row.model) withModel.push(row);
            } else {
                withoutModel.push(row);
            }
        }

        // লম্বা model string আগে — substring match এ বেশি নির্দিষ্টটা জিতবে
        // (যেমন "WWM-ATV90" আর "ATV9" দুটোই থাকলে লম্বাটা আগে দেখা হবে)।
        withModel.sort((a, b) => b.model.length - a.model.length);

        cache = {
            withModel,
            withoutModel,
            loadedAt: Date.now(),
            version: cache.version + 1,
            ready: true,
        };
        return cache;
    })();

    try {
        return await inflight;
    } finally {
        inflight = null;
    }
}

/**
 * প্রতি request-এ সস্তায় call করার জন্য — connectDB() থেকে ডাকা হয়।
 * প্রথমবার await করে, পরে stale হলে background refresh। কখনো throw করে না,
 * কারণ rate override পড়তে না পারলেও baseline table দিয়ে কাজ চলবে।
 */
async function ensureCustomRates(db) {
    try {
        const fresh = cache.ready && Date.now() - cache.loadedAt < CACHE_TTL_MS;
        if (fresh) return;
        if (cache.ready) {
            // stale — background refresh, request আটকাবে না
            loadCustomRates(db).catch(() => { });
            return;
        }
        await loadCustomRates(db);
    } catch (err) {
        // silent — baseline table দিয়েই resolve হবে
    }
}

/** Admin write-এর পর সাথে সাথে cache ফেলে দেওয়া */
function invalidateCustomRates() {
    cache = { ...cache, loadedAt: 0, ready: false };
    merged = null;
    mergedVersion = -1;
}

/** rateResolver.findRate() এর জন্য merged table (custom আগে, baseline পরে) */
function getMergedTables() {
    if (mergedVersion !== cache.version || !merged) {
        merged = {
            withModel: [...cache.withModel, ...WITH_MODEL_DATA],
            withoutModel: [...cache.withoutModel, ...WITHOUT_MODEL_DATA],
        };
        mergedVersion = cache.version;
    }
    return merged;
}

/** case-insensitive dedupe রেখে product name list বানানো */
function mergeNames(baseNames, extraNames) {
    const seen = new Set(baseNames.map(norm));
    const out = [...baseNames];
    for (const n of extraNames) {
        const name = String(n || '').trim();
        if (!name || seen.has(norm(name))) continue;
        seen.add(norm(name));
        out.push(name);
    }
    return out;
}

/**
 * GET /rate-table এর payload — client এটা fetch করে নিজের static copy-র
 * উপরে overlay করে। `custom` list দিয়েই client-এর rateMatcher merge করে,
 * আর `withModel`/`withoutModel` full merged view (debug / future use)।
 */
function getRateTablePayload() {
    const m = getMergedTables();

    const customWithModelProducts = cache.withModel.map((r) => r.product);
    const customWithoutModelProducts = cache.withoutModel.map((r) => r.product);

    // capacity variants — baseline map + custom row থেকে derive করা
    const capacityByProduct = {};
    for (const [k, v] of Object.entries(WITHOUT_MODEL_CAPACITY_BY_PRODUCT)) {
        capacityByProduct[k] = [...v];
    }
    for (const row of cache.withoutModel) {
        if (!row.capacity) continue;
        const key =
            Object.keys(capacityByProduct).find((k) => norm(k) === norm(row.product)) ||
            row.product;
        if (!capacityByProduct[key]) capacityByProduct[key] = [];
        if (!capacityByProduct[key].some((c) => norm(c) === norm(row.capacity))) {
            capacityByProduct[key].push(row.capacity);
        }
    }

    // model list per product — baseline map + custom model গুলো
    const modelsByProduct = {};
    for (const [k, v] of Object.entries(WITH_MODEL_MODELS_BY_PRODUCT)) {
        modelsByProduct[k] = [...v];
    }
    for (const row of cache.withModel) {
        const key =
            Object.keys(modelsByProduct).find((k) => norm(k) === norm(row.product)) ||
            row.product;
        if (!modelsByProduct[key]) modelsByProduct[key] = [];
        if (!modelsByProduct[key].some((mm) => norm(mm) === norm(row.model))) {
            modelsByProduct[key].push(row.model);
        }
    }

    return {
        // client-এর overlay এর জন্য (এটাই আসল কাজের অংশ)
        custom: {
            withModel: cache.withModel,
            withoutModel: cache.withoutModel,
        },
        // full merged view
        withModel: m.withModel,
        withoutModel: m.withoutModel,
        withModelProducts: mergeNames(WITH_MODEL_PRODUCTS, customWithModelProducts),
        withoutModelProducts: mergeNames(WITHOUT_MODEL_PRODUCTS, customWithoutModelProducts),
        capacityByProduct,
        modelsByProduct,
        meta: {
            customCount: cache.withModel.length + cache.withoutModel.length,
            baselineCount: WITH_MODEL_DATA.length + WITHOUT_MODEL_DATA.length,
            cachedAt: cache.loadedAt ? new Date(cache.loadedAt).toISOString() : null,
        },
    };
}

/** baseline table (read-only view — admin UI-তে দেখানোর জন্য) */
function getBaselineTables() {
    return {
        withModel: WITH_MODEL_DATA,
        withoutModel: WITHOUT_MODEL_DATA,
    };
}

module.exports = {
    COLLECTION,
    LOCATION_KEYS,
    loadCustomRates,
    ensureCustomRates,
    invalidateCustomRates,
    getMergedTables,
    getRateTablePayload,
    getBaselineTables,
};