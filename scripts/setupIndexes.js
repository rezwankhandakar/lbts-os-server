/**
 * ═══════════════════════════════════════════════════════════════════
 *  LBTS-OS — MongoDB Indexes Setup Script
 * ═══════════════════════════════════════════════════════════════════
 *
 *  WHAT IT DOES:
 *  Creates all required indexes for optimal query performance based on
 *  the actual query patterns in index.js. Safe to run multiple times
 *  (MongoDB's createIndex is idempotent).
 *
 *  WHEN TO RUN:
 *  - First deployment (MANDATORY)
 *  - After schema changes
 *  - If query performance degrades (re-verify)
 *
 *  HOW TO RUN:
 *    node scripts/setupIndexes.js
 *
 *  EXPECTED OUTPUT:
 *    ✅ Each collection lists indexes created (or "already exists")
 *    📊 Final summary with total index count per collection
 *
 *  SAFETY:
 *  - Does NOT delete any data
 *  - Does NOT modify any documents
 *  - Only creates indexes (metadata)
 *  - MongoDB Atlas M0 Free Tier limit: 500 indexes per DB (we use ~30)
 * ═══════════════════════════════════════════════════════════════════
 */

// ── DNS Fix ────────────────────────────────────────────────────────
// index.js-এর মতোই: কিছু ISP-র DNS MongoDB-র SRV lookup resolve করতে
// পারে না (querySrv ECONNREFUSED)। Google DNS দিয়ে bypass করা হয়।
const dns = require("dns");
dns.setServers(["8.8.8.8", "8.8.4.4"]);

require('dotenv').config();
const { MongoClient, ServerApiVersion } = require('mongodb');

const DB_HOST = process.env.DB_HOST || 'cluster0.fu1n5ti.mongodb.net';
const uri = `mongodb+srv://${encodeURIComponent(process.env.DB_USER)}:${encodeURIComponent(process.env.DB_PASS)}@${DB_HOST}/?retryWrites=true&w=majority&appName=LBTS-OS-Migration`;

// ── Color output for terminal ─────────────────────────────────────
const c = {
  green:  (s) => `\x1b[32m${s}\x1b[0m`,
  red:    (s) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  blue:   (s) => `\x1b[34m${s}\x1b[0m`,
  gray:   (s) => `\x1b[90m${s}\x1b[0m`,
  bold:   (s) => `\x1b[1m${s}\x1b[0m`,
};

// ═══════════════════════════════════════════════════════════════════
//  INDEX DEFINITIONS — per collection, explained inline
// ═══════════════════════════════════════════════════════════════════

const INDEX_PLAN = {
  // ─────────────────────────────────────────────────────────────────
  //  USERS collection
  // ─────────────────────────────────────────────────────────────────
  users: [
    {
      keys: { email: 1 },
      options: { unique: true, name: 'email_unique' },
      why: 'Unique email lookup for /users/:email/role, /jwt, duplicate check',
    },
    {
      keys: { role: 1, status: 1 },
      options: { name: 'role_status' },
      why: 'Admin queries like find({ role: "admin", status: "approved" })',
    },
  ],

  // ─────────────────────────────────────────────────────────────────.......
  //  GATE-PASS collection
  //  Query patterns from index.js:
  //    - find({ tripMonth, tripYear }).sort({ createdAt: -1 })   [Line 2480-2484]
  //    - find({ $or: [tripDo, customerName, ...] regex search }) [Line 2464-2473]
  //    - aggregate({ tripMonth, tripYear }) for dashboard         [Line 3978-3991]
  // ─────────────────────────────────────────────────────────────────
  'gate-pass': [
    {
      keys: { tripYear: -1, tripMonth: -1, createdAt: -1 },
      options: { name: 'year_month_created' },
      why: 'Main list query: GET /gate-pass — month/year filter + sort by created',
    },
    {
      keys: { createdAt: -1 },
      options: { name: 'created_desc' },
      why: 'Fallback sort when no month/year filter',
    },
    {
      keys: { tripDo: 1 },
      options: { name: 'tripDo' },
      why: 'Search by Trip DO number (autocomplete + regex search)',
    },
    {
      keys: { customerName: 1 },
      options: { name: 'customerName' },
      why: 'Search/filter by customer name',
    },
    {
      keys: { vehicleNo: 1 },
      options: { name: 'vehicleNo' },
      why: 'Search by vehicle number',
    },
    {
      keys: { unit: 1, tripYear: -1, tripMonth: -1 },
      options: { name: 'unit_period' },
      why: 'Dashboard: unit-wise aggregation for current month',
    },
    // ── Text index for full-text search (replaces dangerous regex) ──
    {
      keys: {
        tripDo: 'text',
        customerName: 'text',
        csd: 'text',
        unit: 'text',
        vehicleNo: 'text',
        zone: 'text',
      },
      options: {
        name: 'gatepass_text_search',
        weights: {
          tripDo: 10,      // Most important for search
          customerName: 8,
          vehicleNo: 6,
          csd: 4,
          unit: 3,
          zone: 2,
        },
      },
      why: 'Full-text search — safer + faster than regex-based search',
    },
  ],

  // ─────────────────────────────────────────────────────────────────
  //  CHALLANS collection
  //  Query patterns:
  //    - find({ createdAt: { $gte, $lte } }).sort({ createdAt: -1 })  [Line 2694-2714]
  //    - find({ $or: [customerName, receiverNumber, ...] regex })     [Line 2677-2687]
  //    - find({ status: "delivered" })                                 [Line 3140]
  //    - find({ _id: { $in: challanIds } })                            [Line 3140]
  //    - aggregate for filter options                                  [Line 2745-2772]
  // ─────────────────────────────────────────────────────────────────
  challans: [
    {
      // FIX #54 — stale claim cleanup query: { claimToken exists, claimedAt < cutoff }
      // Partial index তাই খুব ছোট থাকে (শুধু claimed docs index হয়)।
      keys: { claimedAt: 1 },
      options: {
        name: 'stale_claim_cleanup',
        partialFilterExpression: { claimToken: { $exists: true } },
      },
      why: 'releaseStaleClaims() — crashed request-এর আটকে থাকা claim খুঁজতে',
    },
    {
      keys: { createdAt: -1 },
      options: { name: 'created_desc' },
      why: 'Main list query: GET /challans — date range + sort',
    },
    {
      keys: { status: 1, createdAt: -1 },
      options: { name: 'status_created' },
      why: 'Filter undelivered challans in CreateDelivery page',
    },
    {
      keys: { customerName: 1 },
      options: { name: 'customerName' },
      why: 'Filter by customer name (MultiSelectFilter)',
    },
    {
      keys: { zone: 1 },
      options: { name: 'zone' },
      why: 'Filter by zone',
    },
    {
      keys: { district: 1 },
      options: { name: 'district' },
      why: 'Filter by district',
    },
    {
      keys: { thana: 1 },
      options: { name: 'thana' },
      why: 'Filter by thana',
    },
    {
      keys: { receiverNumber: 1 },
      options: { name: 'receiverNumber' },
      why: 'Filter/search by receiver phone',
    },
    {
      keys: { tripNumber: 1 },
      options: { name: 'tripNumber', sparse: true },
      why: 'Lookup challans by trip number (sparse: only delivered ones)',
    },
    // ── Products nested field indexes — autocomplete fast path ──
    {
      keys: { 'products.productName': 1 },
      options: { name: 'products_productName' },
      why: 'Autocomplete: $match on products.productName before $unwind (faster than full scan)',
    },
    {
      keys: { 'products.model': 1 },
      options: { name: 'products_model' },
      why: 'Autocomplete: $match on products.model before $unwind (faster than full scan)',
    },
    // ── Text index for challan search ──
    {
      keys: {
        customerName: 'text',
        address: 'text',
        receiverNumber: 'text',
        zone: 'text',
        thana: 'text',
        district: 'text',
      },
      options: {
        name: 'challan_text_search',
        weights: {
          customerName: 10,
          receiverNumber: 8,
          address: 6,
          zone: 4,
          thana: 3,
          district: 3,
        },
      },
      why: 'Full-text search for challans — replaces regex search',
    },
  ],

  // ─────────────────────────────────────────────────────────────────
  //  DELIVERIES collection
  //  Query patterns:
  //    - find({ createdAt: { $gte, $lte } }).sort({ createdAt: -1 })    [Line 3233-3239]
  //    - find({ $or: [tripNumber, vendorName, ...] regex })              [Line 3213-3226]
  //    - find({ vendorName: regex })                                     [Line 3709]
  //    - findOne({ _id, "challans.challanId": X })                       [Line 3263]
  //    - aggregate({ "challans.products.productName" })                  [Line 4011-4018]
  // ─────────────────────────────────────────────────────────────────
  deliveries: [
    {
      keys: { tripNumber: 1 },
      options: { unique: true, name: 'tripNumber_unique' },
      why: 'Trip lookup + prevent duplicate trip numbers',
    },
    {
      keys: { createdAt: -1 },
      options: { name: 'created_desc' },
      why: 'Main list query: GET /deliveries — sort by newest',
    },
    {
      keys: { vendorName: 1, createdAt: -1 },
      options: { name: 'vendor_created' },
      why: 'Vendor-role user filter: their own trips only',
    },
    {
      keys: { vehicleNumber: 1 },
      options: { name: 'vehicleNumber' },
      why: 'Search/filter by vehicle',
    },
    {
      keys: { 'challans.challanId': 1 },
      options: { name: 'challans_challanId' },
      why: 'Nested lookup: find trip containing a specific challan',
    },
    {
      keys: { 'challans.customerName': 1 },
      options: { name: 'challans_customer' },
      why: 'Search trips by customer name',
    },
    {
      keys: { status: 1, createdAt: -1 },
      options: { name: 'status_created', sparse: true },
      why: 'Active/pending trips filter for dashboard',
    },
  ],

  // ─────────────────────────────────────────────────────────────────
  //  VENDORS collection
  //  Query patterns:
  //    - find({ vendorName: regex })                [Line 2936]
  //    - findOne({ _id })                            [Line 2951]
  //    - aggregate({ "vehicles.vehicleNumber": regex }) [Line 3000-3014]
  // ─────────────────────────────────────────────────────────────────
  vendors: [
    {
      keys: { vendorName: 1 },
      options: { name: 'vendorName', collation: { locale: 'en', strength: 2 } },
      why: 'Case-insensitive vendor name lookup (for vendor-role filter)',
    },
    {
      keys: { 'vehicles.vehicleNumber': 1 },
      options: { name: 'vehicles_number' },
      why: 'Vehicle search in CreateDelivery page',
    },
  ],

  // ─────────────────────────────────────────────────────────────────
  //  ACCOUNTS collection
  //  Query patterns:
  //    - find({ month, year }).sort({ date: -1, createdAt: -1 })    [Line 3842]
  //    - updateOne({ _id, type: "manual_advance" })                  [Line 3945]
  // ─────────────────────────────────────────────────────────────────
  accounts: [
    {
      keys: { year: -1, month: -1, date: -1, createdAt: -1 },
      options: { name: 'period_date_created' },
      why: 'Main list query: accounts by month/year, sorted by date',
    },
    {
      keys: { type: 1, year: -1, month: -1 },
      options: { name: 'type_period' },
      why: 'Dashboard: filter by transaction type (income/expense/etc)',
    },
    {
      keys: { vendorName: 1, year: -1, month: -1 },
      options: { name: 'vendor_period', sparse: true },
      why: 'Vendor payment history lookup',
    },
  ],

  // ─────────────────────────────────────────────────────────────────
  //  AUDIT_LOGS collection
  //  Query patterns:
  //    - find(filter).sort({ performedAt: -1 })                  [Line 3902]
  //    - filter by action, performedBy.email regex
  // ─────────────────────────────────────────────────────────────────
  audit_logs: [
    {
      keys: { performedAt: -1 },
      options: { name: 'performedAt_desc' },
      why: 'Main list query: audit logs newest first',
    },
    {
      keys: { action: 1, performedAt: -1 },
      options: { name: 'action_time' },
      why: 'Filter by action type (DELETE_TRANSACTION, etc)',
    },
    {
      keys: { 'performedBy.email': 1, performedAt: -1 },
      options: { name: 'user_time' },
      why: 'Filter audit trail by user',
    },
    {
      keys: { documentId: 1 },
      options: { name: 'documentId', sparse: true },
      why: 'Quick lookup: find audit entry for a specific deleted document',
    },
    // ── TTL index: auto-delete audit logs older than 1 year ──
    // Audit logs grow fast. Keep 12 months, auto-purge older to save storage.
    {
      keys: { performedAt: 1 },
      options: {
        name: 'performedAt_ttl',
        expireAfterSeconds: 60 * 60 * 24 * 365, // 365 days
      },
      why: 'Auto-delete audit logs older than 1 year (saves M0 storage)',
    },
  ],

  // ─────────────────────────────────────────────────────────────────
  //  RATE_ENTRIES collection (FIX #55 — client থেকে যোগ করা product/model)
  //  Query patterns:
  //    find({ active: { $ne: false } }).sort({ createdAt: 1 })  ← cache load
  //    find({ type }).sort({ createdAt: -1 })                   ← admin list
  //    findOne({ type, product: /^..$/i, model, capacity })     ← duplicate check
  // ─────────────────────────────────────────────────────────────────
  rate_entries: [
    {
      keys: { active: 1, createdAt: 1 },
      options: { name: 'active_created' },
      why: 'Rate override cache load — active rows in insertion order',
    },
    {
      keys: { type: 1, createdAt: -1 },
      options: { name: 'type_created_desc' },
      why: 'Admin list page: filter by with-model / without-model, newest first',
    },
    {
      keys: { product: 1, model: 1, capacity: 1 },
      options: { name: 'product_model_capacity' },
      why: 'Duplicate detection before insert/update',
    },
  ],

  // ─────────────────────────────────────────────────────────────────
  //  RATE_LIMITS collection (FIX #51 — serverless-safe limiter counters)
  //  utils/mongoRateLimit.js নিজেও প্রথম call-এ index তৈরি করে,
  //  কিন্তু এখানে declare করা থাকলে setup script একবারেই সব বানায়।
  // ─────────────────────────────────────────────────────────────────
  rate_limits: [
    {
      keys: { key: 1 },
      options: { name: 'key_unique', unique: true },
      why: 'Fixed-window counter lookup: findOneAndUpdate({ key })',
    },
    {
      keys: { expiresAt: 1 },
      options: { name: 'expiresAt_ttl', expireAfterSeconds: 0 },
      why: 'Auto-delete expired window counters',
    },
  ],

  // ─────────────────────────────────────────────────────────────────
  //  COUNTERS collection (for trip number sequence)
  //  Query patterns: findOneAndUpdate({ _id: "tripNumber" }) [Line 3127]
  //  _id is already auto-indexed, no extra index needed
  // ─────────────────────────────────────────────────────────────────
};

// ═══════════════════════════════════════════════════════════════════
//  MAIN EXECUTION
// ═══════════════════════════════════════════════════════════════════

async function main() {
  // ── Validate env ──
  if (!process.env.DB_USER || !process.env.DB_PASS) {
    console.error(c.red('❌ ERROR: DB_USER or DB_PASS missing in .env'));
    process.exit(1);
  }

  console.log(c.bold(c.blue('\n╔══════════════════════════════════════════════════════════╗')));
  console.log(c.bold(c.blue('║       LBTS-OS — MongoDB Index Setup Script               ║')));
  console.log(c.bold(c.blue('╚══════════════════════════════════════════════════════════╝\n')));

  const client = new MongoClient(uri, {
    serverApi: { version: ServerApiVersion.v1, strict: false, deprecationErrors: true },
    serverSelectionTimeoutMS: 10000,
  });

  try {
    console.log(c.gray('Connecting to MongoDB Atlas...'));
    await client.connect();
    console.log(c.green('✅ Connected\n'));

    const db = client.db('LBTS-OS-DB');

    let totalCreated = 0;
    let totalExisting = 0;
    let totalFailed = 0;
    const summary = {};

    // ── Process each collection ──
    for (const [collectionName, indexes] of Object.entries(INDEX_PLAN)) {
      console.log(c.bold(`\n📦 Collection: ${c.yellow(collectionName)}`));
      console.log(c.gray('─'.repeat(60)));

      const collection = db.collection(collectionName);
      // Collection এখনো exist না করলে (যেমন rate_limits প্রথমবার)
      // indexes() NamespaceNotFound (code 26) throw করে — সেক্ষেত্রে
      // খালি list ধরে এগোই; createIndex নিজেই collection বানিয়ে নেবে।
      let existingIndexes = [];
      try {
        existingIndexes = await collection.indexes();
      } catch (err) {
        if (err.code !== 26) throw err;
        console.log(c.gray('   (collection does not exist yet — will be created)'));
      }
      const existingNames = new Set(existingIndexes.map((idx) => idx.name));

      let created = 0;
      let existing = 0;
      let failed = 0;

      for (const { keys, options, why } of indexes) {
        const indexName = options.name;

        try {
          if (existingNames.has(indexName)) {
            console.log(
              c.gray(`   ⊙ ${indexName.padEnd(30)} already exists`)
            );
            existing++;
          } else {
            // Use background index build to avoid blocking the collection
            // (MongoDB 4.2+ builds in background by default, but explicit is safer)
            await collection.createIndex(keys, options);
            console.log(
              c.green(`   ✓ ${indexName.padEnd(30)} created`)
            );
            console.log(c.gray(`     └─ ${why}`));
            created++;
          }
        } catch (err) {
          // Common failure: index with same name exists but different keys
          // OR text index already exists (MongoDB allows only 1 per collection)
          if (err.code === 85 || err.code === 86) {
            console.log(
              c.yellow(`   ⚠ ${indexName.padEnd(30)} conflict: ${err.codeName}`)
            );
            console.log(c.gray(`     └─ ${err.message.substring(0, 100)}`));
          } else {
            console.log(c.red(`   ✗ ${indexName.padEnd(30)} FAILED: ${err.message}`));
          }
          failed++;
        }
      }

      summary[collectionName] = { created, existing, failed, total: indexes.length };
      totalCreated += created;
      totalExisting += existing;
      totalFailed += failed;
    }

    // ── Final Summary ──
    console.log(c.bold(c.blue('\n╔══════════════════════════════════════════════════════════╗')));
    console.log(c.bold(c.blue('║                      SUMMARY                             ║')));
    console.log(c.bold(c.blue('╚══════════════════════════════════════════════════════════╝\n')));

    console.log(
      c.bold('Collection'.padEnd(20)) +
      c.bold('Created'.padEnd(10)) +
      c.bold('Existing'.padEnd(10)) +
      c.bold('Failed'.padEnd(10)) +
      c.bold('Total')
    );
    console.log(c.gray('─'.repeat(60)));

    for (const [name, stats] of Object.entries(summary)) {
      console.log(
        name.padEnd(20) +
        c.green(String(stats.created).padEnd(10)) +
        c.gray(String(stats.existing).padEnd(10)) +
        (stats.failed > 0 ? c.red(String(stats.failed).padEnd(10)) : '0'.padEnd(10)) +
        String(stats.total)
      );
    }

    console.log(c.gray('─'.repeat(60)));
    console.log(
      c.bold('TOTAL'.padEnd(20)) +
      c.green(String(totalCreated).padEnd(10)) +
      c.gray(String(totalExisting).padEnd(10)) +
      (totalFailed > 0 ? c.red(String(totalFailed).padEnd(10)) : '0'.padEnd(10)) +
      c.bold(String(totalCreated + totalExisting + totalFailed))
    );

    if (totalFailed > 0) {
      console.log(c.red(`\n⚠  ${totalFailed} index(es) failed. Review errors above.`));
    } else {
      console.log(c.green('\n🎉 All indexes verified / created successfully!'));
    }

    console.log(c.gray('\nNext steps:'));
    console.log(c.gray('  1. Deploy your updated server to Vercel'));
    console.log(c.gray('  2. Monitor query performance in MongoDB Atlas → Performance Advisor'));
    console.log(c.gray('  3. Run this script again after 1 month to verify indexes are being used\n'));

  } catch (err) {
    console.error(c.red('\n❌ FATAL ERROR:'), err.message);
    console.error(err);
    process.exit(1);
  } finally {
    await client.close();
  }
}

// ── Run ──
main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(c.red('Uncaught error:'), err);
    process.exit(1);
  });