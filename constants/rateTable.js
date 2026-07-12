// ═══════════════════════════════════════════════════════════════
//  LBTS-OS SERVER — Authoritative Rate Table (single source of truth)
//  ⚠ client/src/utils/withModelData.js + withoutModelData.js এর সাথে
//    sync রাখতে হবে। Rate বদলালে দুই জায়গাতেই বদলান (অথবা client-কে
//    GET /rate-table endpoint থেকে fetch করান — endpoint যোগ করা আছে)।
// ═══════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════════════
// With-Model Rate Data — auto-generated from With_Model.xlsx
// ────────────────────────────────────────────────────────────────────────
// Structure: each entry maps product + model + location → capacity + rate
// Match strategy: model এর substring (e.g. WFA-2A3-GDEL এ "2A3" থাকলে match)
// Location keys: ISD, OSD-Metro, OSD-Thana
// ════════════════════════════════════════════════════════════════════════

const WITH_MODEL_DATA = [
  { product: "Refrigerator", model: "JET", capacity: "Gross 50-150 Litre", "ISD": 650, "OSD-Metro": 950, "OSD-Thana": 1150 },
  { product: "Refrigerator", model: "TE0", capacity: "Gross 50-150 Litre", "ISD": 650, "OSD-Metro": 950, "OSD-Thana": 1150 },
  { product: "Refrigerator", model: "1X1", capacity: "Gross 50-150 Litre", "ISD": 650, "OSD-Metro": 950, "OSD-Thana": 1150 },
  { product: "Refrigerator", model: "TG2", capacity: "Gross 50-150 Litre", "ISD": 650, "OSD-Metro": 950, "OSD-Thana": 1150 },
  { product: "Refrigerator", model: "TN3", capacity: "Gross 50-150 Litre", "ISD": 650, "OSD-Metro": 950, "OSD-Thana": 1150 },
  { product: "Refrigerator", model: "1B5", capacity: "Gross 50-150 Litre", "ISD": 650, "OSD-Metro": 950, "OSD-Thana": 1150 },
  { product: "Refrigerator", model: "1D5", capacity: "Gross 50-150 Litre", "ISD": 650, "OSD-Metro": 950, "OSD-Thana": 1150 },
   { product: "Refrigerator", model: "1B6", capacity: "Gross 50-150 Litre", "ISD": 650, "OSD-Metro": 950, "OSD-Thana": 1150 },

  { product: "Refrigerator", model: "1N3", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "1G7", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "1H5", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "1D4", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "1F3", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "1G0", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "1N5", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2B4", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2F0", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2T5", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2E5", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2A3", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2B0", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2B5", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2D4", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2A8", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2B3", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2B6", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2E0", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2X1", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2A7", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2F1", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2G2", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2G0", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2E4", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2H2", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },
  { product: "Refrigerator", model: "2A0", capacity: "Gross 151-285 Litre", "ISD": 950, "OSD-Metro": 1450, "OSD-Thana": 1680 },


  { product: "Refrigerator", model: "2N5", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3J0", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3A7", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3D8", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3F5", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3X7", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3A2", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3B0", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3C3", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3E8", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3X9", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3D7", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3G0", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3H6", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3D3", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3B5", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3C4", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "4C0", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "4D0", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },
  { product: "Refrigerator", model: "3X8", capacity: "Gross 286-460 Litre", "ISD": 1100, "OSD-Metro": 1700, "OSD-Thana": 1900 },

  { product: "Refrigerator", model: "5F3", capacity: "Gross 461-800 Litre", "ISD": 1400, "OSD-Metro": 2100, "OSD-Thana": 2500 },
  { product: "Refrigerator", model: "5A2", capacity: "Gross 461-800 Litre", "ISD": 1400, "OSD-Metro": 2100, "OSD-Thana": 2500 },
  { product: "Refrigerator", model: "5B6", capacity: "Gross 461-800 Litre", "ISD": 1400, "OSD-Metro": 2100, "OSD-Thana": 2500 },
  { product: "Refrigerator", model: "5E5", capacity: "Gross 461-800 Litre", "ISD": 1400, "OSD-Metro": 2100, "OSD-Thana": 2500 },
  { product: "Refrigerator", model: "5H5", capacity: "Gross 461-800 Litre", "ISD": 1400, "OSD-Metro": 2100, "OSD-Thana": 2500 },
  { product: "Refrigerator", model: "6A9", capacity: "Gross 461-800 Litre", "ISD": 1400, "OSD-Metro": 2100, "OSD-Thana": 2500 },
  { product: "Refrigerator", model: "6D6", capacity: "Gross 461-800 Litre", "ISD": 1400, "OSD-Metro": 2100, "OSD-Thana": 2500 },
  { product: "Refrigerator", model: "6E2", capacity: "Gross 461-800 Litre", "ISD": 1400, "OSD-Metro": 2100, "OSD-Thana": 2500 },
  { product: "Refrigerator", model: "6F0", capacity: "Gross 461-800 Litre", "ISD": 1400, "OSD-Metro": 2100, "OSD-Thana": 2500 },
  { product: "Refrigerator", model: "5F0", capacity: "Gross 461-800 Litre", "ISD": 1400, "OSD-Metro": 2100, "OSD-Thana": 2500 },
  { product: "Refrigerator", model: "5A5", capacity: "Gross 461-800 Litre", "ISD": 1400, "OSD-Metro": 2100, "OSD-Thana": 2500 },

  { product: "Air Conditioner", model: "09", capacity: "Split AC: up to 1.5 Ton", "ISD": 905, "OSD-Metro": 1206, "OSD-Thana": 1508 },
  { product: "Air Conditioner", model: "12", capacity: "Split AC: up to 1.5 Ton", "ISD": 905, "OSD-Metro": 1206, "OSD-Thana": 1508 },
  { product: "Air Conditioner", model: "18", capacity: "Split AC: up to 1.5 Ton", "ISD": 905, "OSD-Metro": 1206, "OSD-Thana": 1508 },

  { product: "Air Conditioner", model: "24", capacity: "Split AC: 2-2.5 Ton", "ISD": 1056, "OSD-Metro": 1357, "OSD-Thana": 1810 },
  { product: "Air Conditioner", model: "30", capacity: "Split AC: 2-2.5 Ton", "ISD": 1056, "OSD-Metro": 1357, "OSD-Thana": 1810 },

  { product: "Air Conditioner", model: "36", capacity: "Split AC: 3 Ton", "ISD": 1357, "OSD-Metro": 1810, "OSD-Thana": 2413 },
  { product: "Air Conditioner", model: "42", capacity: "Split AC: 3 Ton", "ISD": 1357, "OSD-Metro": 1810, "OSD-Thana": 2413 },

  { product: "Air Conditioner", model: "48", capacity: "Split AC: 4-5Ton", "ISD": 1508, "OSD-Metro": 1960, "OSD-Thana": 2714 },
  { product: "Air Conditioner", model: "60", capacity: "Split AC: 4-5Ton", "ISD": 1508, "OSD-Metro": 1960, "OSD-Thana": 2714 },
 
  { product: "Television", model: "24", capacity: "Up to 43 Inch", "ISD": 420, "OSD-Metro": 540, "OSD-Thana": 720 },
  { product: "Television", model: "32", capacity: "Up to 43 Inch", "ISD": 420, "OSD-Metro": 540, "OSD-Thana": 720 },
  { product: "Television", model: "40", capacity: "Up to 43 Inch", "ISD": 420, "OSD-Metro": 540, "OSD-Thana": 720 },
  { product: "Television", model: "43", capacity: "Up to 43 Inch", "ISD": 420, "OSD-Metro": 540, "OSD-Thana": 720 },

  { product: "Television", model: "50", capacity: "44-55 Inch", "ISD": 540, "OSD-Metro": 900, "OSD-Thana": 1080 },
  { product: "Television", model: "55", capacity: "44-55 Inch", "ISD": 540, "OSD-Metro": 900, "OSD-Thana": 1080 },
 
  { product: "Oven", model: "20", capacity: "Up to 30 Litre", "ISD": 180, "OSD-Metro": 216, "OSD-Thana": 240 },
  { product: "Oven", model: "23", capacity: "Up to 30 Litre", "ISD": 180, "OSD-Metro": 216, "OSD-Thana": 240 },
  { product: "Oven", model: "25", capacity: "Up to 30 Litre", "ISD": 180, "OSD-Metro": 216, "OSD-Thana": 240 },
  { product: "Oven", model: "26", capacity: "Up to 30 Litre", "ISD": 180, "OSD-Metro": 216, "OSD-Thana": 240 },
  { product: "Oven", model: "28", capacity: "Up to 30 Litre", "ISD": 180, "OSD-Metro": 216, "OSD-Thana": 240 },
  { product: "Oven", model: "30", capacity: "Up to 30 Litre", "ISD": 180, "OSD-Metro": 216, "OSD-Thana": 240 },

  { product: "Washing Machine", model: "WWM-SWG60N", capacity: "Up to kg", "ISD": 300, "OSD-Metro": 420, "OSD-Thana": 480 },
  { product: "Washing Machine", model: "WWM-SWG80", capacity: "Up to kg", "ISD": 300, "OSD-Metro": 420, "OSD-Thana": 480 },

  { product: "Washing Machine", model: "WWM-TWG80", capacity: "21 to 40 kg", "ISD": 420, "OSD-Metro": 600, "OSD-Thana": 720 },
  { product: "Washing Machine", model: "WWM-TWG90M", capacity: "21 to 40 kg", "ISD": 420, "OSD-Metro": 600, "OSD-Thana": 720 },
  { product: "Washing Machine", model: "WWM-TWG100P", capacity: "21 to 40 kg", "ISD": 420, "OSD-Metro": 600, "OSD-Thana": 720 },
  { product: "Washing Machine", model: "WWM-TWG100PL", capacity: "21 to 40 kg", "ISD": 420, "OSD-Metro": 600, "OSD-Thana": 720 },
  { product: "Washing Machine", model: "WWM-TWG110", capacity: "21 to 40 kg", "ISD": 420, "OSD-Metro": 600, "OSD-Thana": 720 },
  { product: "Washing Machine", model: "WWM-TWP110DP", capacity: "21 to 40 kg kg", "ISD": 420, "OSD-Metro": 600, "OSD-Thana": 720 },
  { product: "Washing Machine", model: "WWM-TTP60", capacity: "21 to 40 kg", "ISD": 420, "OSD-Metro": 600, "OSD-Thana": 720 },
  { product: "Washing Machine", model: "WWM-TTM70", capacity: "21 to 40 kg", "ISD": 420, "OSD-Metro": 600, "OSD-Thana": 720 },
  { product: "Washing Machine", model: "WWM-TSM80", capacity: "21 to 40 kg", "ISD": 420, "OSD-Metro": 600, "OSD-Thana": 720 },
  { product: "Washing Machine", model: "WWM-ATP70", capacity: "21 to 40 kg", "ISD": 420, "OSD-Metro": 600, "OSD-Thana": 720 },
  { product: "Washing Machine", model: "WWM-Q60", capacity: "21 to 40 kg", "ISD": 420, "OSD-Metro": 600, "OSD-Thana": 720 },
  { product: "Washing Machine", model: "WWM-Q70", capacity: "21 to 40 kg", "ISD": 420, "OSD-Metro": 600, "OSD-Thana": 720 },
  { product: "Washing Machine", model: "WWM-Q80", capacity: "21 to 40 kg", "ISD": 420, "OSD-Metro": 600, "OSD-Thana": 720 },
  { product: "Washing Machine", model: "WWM-ATV70", capacity: "21 to 40 kg", "ISD": 420, "OSD-Metro": 600, "OSD-Thana": 720 },
  { product: "Washing Machine", model: "WWM-ATV80", capacity: "21 to 40 kg", "ISD": 420, "OSD-Metro": 600, "OSD-Thana": 720 },
  { product: "Washing Machine", model: "WWM-ATV90", capacity: "21 to 40 kg", "ISD": 420, "OSD-Metro": 600, "OSD-Thana": 720 },

  { product: "Washing Machine", model: "WWM-AFM60", capacity: "More than 40 kg", "ISD": 600, "OSD-Metro": 840, "OSD-Thana": 1080 },
  { product: "Washing Machine", model: "WWM-AFM70", capacity: "More than 40 kg", "ISD": 600, "OSD-Metro": 840, "OSD-Thana": 1080 },
  { product: "Washing Machine", model: "WWM-AFM90", capacity: "More than 40 kg", "ISD": 600, "OSD-Metro": 840, "OSD-Thana": 1080 },
  { product: "Washing Machine", model: "WWM-AFT80W", capacity: "More than 40 kg", "ISD": 600, "OSD-Metro": 840, "OSD-Thana": 1080 },
  { product: "Washing Machine", model: "WWM-AFC90W", capacity: "More than 40 kg", "ISD": 600, "OSD-Metro": 840, "OSD-Thana": 1080 },
];

// Unique product names — used for product-name typeahead suggestions
const WITH_MODEL_PRODUCTS = [
  "Refrigerator",
  "Air Conditioner",
  "Television",
  "Oven",
  "Washing Machine",
];

// All available model strings grouped by product — for model field suggestion
const WITH_MODEL_MODELS_BY_PRODUCT = {
  "Refrigerator": ["JET", "1X1", "TG2", "TN3", "1B5", "1D5", "1N3", "1G7", "1H5", "1B6", "1D4", "1F3", "1G0", "1N5", "2B4", "2F0", "2T5", "2E5", "2A3", "2B0", "2B5", "2D4", "2A8", "2B3", "2B6", "2E0", "2X1", "2A7", "2F1", "2G2", "2G0", "2E4", "2H2", "2N5", "3J0", "3A7", "3D8", "3F5", "3X7", "3A2", "3B0", "3C3", "3E8", "3X9", "3D7", "3G0", "3H6", "3D3", "3B5", "3C4", "4C0", "4D0", "5F3", "5A2", "5B6", "5E5", "5H5", "6A9", "6D6", "6E2", "6F0"],
  "Air Conditioner": ["12", "18", "24", "30", "36", "42", "48", "60"],
  "Television": ["24", "32", "40", "43", "50", "55", "65"],
  "Oven": ["20", "23", "25", "26", "28", "30"],
  "Washing Machine": ["WWM-SWG60N", "WWM-SWG80", "WWM-TWG80", "WWM-TWG90M", "WWM-TWG100P", "WWM-TWG100PL", "WWM-TWG110", "WWM-TWP110DP", "WWM-TTP60", "WWM-TTM70", "WWM-TSM80", "WWM-ATP70", "WWM-Q60", "WWM-Q70", "WWM-Q80", "WWM-ATV70", "WWM-ATV80", "WWM-ATV90", "WWM-AFM60", "WWM-AFM70", "WWM-AFM90", "WWM-AFT80W", "WWM-AFC90W"],
};

// ════════════════════════════════════════════════════════════════════════
// Without-Model Rate Data — auto-generated from Without_Model.xlsx
// ────────────────────────────────────────────────────────────────────────
// Items here do NOT need a model match — product name + location is enough.
// A few items have a capacity variant (Gas Stove single/Double, Air Cooler,
// Weight Machine).  For those, capacity is selected manually on the Delivered
// page, then rate is looked up by product + capacity + location.
// ════════════════════════════════════════════════════════════════════════

const WITHOUT_MODEL_DATA = [
  { product: "Pedal Stand Fan", capacity: null, "ISD": 145, "OSD-Metro": 180, "OSD-Thana": 180 },
  { product: "Wall Fan", capacity: null, "ISD": 95, "OSD-Metro": 120, "OSD-Thana": 155 },
  { product: "Table Fan", capacity: null, "ISD": 95, "OSD-Metro": 120, "OSD-Thana": 155 },
  { product: "Non Recharagable", capacity: null, "ISD": 95, "OSD-Metro": 120, "OSD-Thana": 155 },
  { product: "Rechargable", capacity: null, "ISD": 95, "OSD-Metro": 120, "OSD-Thana": 155 },
  { product: "Ceiling Fan", capacity: null, "ISD": 90, "OSD-Metro": 120, "OSD-Thana": 145 },
  { product: "Tornado Fan", capacity: null, "ISD": 90, "OSD-Metro": 120, "OSD-Thana": 145 },
  { product: "Exhaust Fan", capacity: null, "ISD": 40, "OSD-Metro": 50, "OSD-Thana": 50 },
  { product: "Bulb", capacity: null, "ISD": 60, "OSD-Metro": 70, "OSD-Thana": 80 },
  { product: "Light", capacity: null, "ISD": 60, "OSD-Metro": 70, "OSD-Thana": 80 },
  { product: "Infrared Cooker", capacity: null, "ISD": 96, "OSD-Metro": 120, "OSD-Thana": 144 },
  { product: "Induction Cooker", capacity: null, "ISD": 96, "OSD-Metro": 120, "OSD-Thana": 144 },
  { product: "Gas Stove", capacity: "single", "ISD": 96, "OSD-Metro": 120, "OSD-Thana": 144 },
  { product: "Gas Stove", capacity: "Double", "ISD": 132, "OSD-Metro": 168, "OSD-Thana": 180 },
  { product: "Weight Machine", capacity: "Upto 40Kg", "ISD": 78, "OSD-Metro": 108, "OSD-Thana": 120 },
  { product: "Coffee Maker", capacity: null, "ISD": 70, "OSD-Metro": 80, "OSD-Thana": 90 },
  { product: "Toasters", capacity: null, "ISD": 65, "OSD-Metro": 70, "OSD-Thana": 80 },
  { product: "Sandwich Maker", capacity: null, "ISD": 65, "OSD-Metro": 70, "OSD-Thana": 80 },
  { product: "Rice Cooker", capacity: null, "ISD": 70, "OSD-Metro": 80, "OSD-Thana": 90 },
  { product: "Pressure cooker", capacity: null, "ISD": 70, "OSD-Metro": 80, "OSD-Thana": 90 },
  { product: "Kitchen Hood", capacity: null, "ISD": 350, "OSD-Metro": 450, "OSD-Thana": 550 },
  { product: "Room heater", capacity: null, "ISD": 350, "OSD-Metro": 450, "OSD-Thana": 550 },

  { product: "Gyser", capacity: null, "ISD": 240, "OSD-Metro": 300, "OSD-Thana": 336 },
  { product: "Vacuum Cleaner", capacity: null, "ISD": 240, "OSD-Metro": 300, "OSD-Thana": 336 },
  { product: "Air Cooler", capacity: "11-18 Litre", "ISD": 180, "OSD-Metro": 240, "OSD-Thana": 300 },
  { product: "Air Cooler", capacity: "19-30 Litre", "ISD": 216, "OSD-Metro": 300, "OSD-Thana": 384 },
  { product: "Hair Dryer", capacity: null, "ISD": 60, "OSD-Metro": 70, "OSD-Thana": 80 },
  { product: "Hair Styler", capacity: null, "ISD": 60, "OSD-Metro": 70, "OSD-Thana": 80 },
  { product: "Shaver", capacity: null, "ISD": 60, "OSD-Metro": 70, "OSD-Thana": 80 },
  { product: "Trimmer", capacity: null, "ISD": 60, "OSD-Metro": 70, "OSD-Thana": 80 },
  { product: "Grooming Kit", capacity: null, "ISD": 60, "OSD-Metro": 70, "OSD-Thana": 80 },
  { product: "Blender", capacity: null, "ISD": 90, "OSD-Metro": 114, "OSD-Thana": 120 },
  { product: "Juicer", capacity: null, "ISD": 90, "OSD-Metro": 114, "OSD-Thana": 120 },
  { product: "Grinder", capacity: null, "ISD": 90, "OSD-Metro": 114, "OSD-Thana": 120 },
];

// Unique product names — used for product-name typeahead suggestions
const WITHOUT_MODEL_PRODUCTS = [
  "Pedal Stand Fan",
  "Wall Fan",
  "Table Fan",
  "Non Recharagable",
  "Rechargable",
  "Ceiling Fan",
  "Tornado Fan",
  "Exhaust Fan",
  "Bulb",
  "Light",
  "Infrared Cooker",
  "Induction Cooker",
  "Gas Stove",
  "Weight Machine",
  "Coffee Maker",
  "Toasters",
  "Sandwich Maker",
  "Rice Cooker",
  "Pressure cooker",
  "Kitchen Hood",
  "Room heater",
  "Gyser",
  "Vacuum Cleaner",
  "Air Cooler",
  "Hair Dryer",
  "Hair Styler",
  "Shaver",
  "Trimmer",
  "Grooming Kit",
  "Blender",
  "Juicer",
  "Grinder"
];

// Products that have selectable capacity variants (no model, but capacity matters).
// Used on the Delivered page to show a capacity-suggestion list.
const WITHOUT_MODEL_CAPACITY_BY_PRODUCT = {
  "Gas Stove": ["single", "Double"],
  "Weight Machine": ["Upto 40Kg"],
  "Air Cooler": ["11-18 Litre", "19-30 Litre"],
};

module.exports = { WITH_MODEL_DATA, WITH_MODEL_PRODUCTS, WITH_MODEL_MODELS_BY_PRODUCT, WITHOUT_MODEL_DATA, WITHOUT_MODEL_PRODUCTS, WITHOUT_MODEL_CAPACITY_BY_PRODUCT };