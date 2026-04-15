

require("dotenv").config();
 
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
 
const app = express();
const port = process.env.PORT || 3000;
 
const multer = require('multer');
const FormData = require('form-data');
const axios = require('axios');
const helmet = require('helmet');
 
const multerUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only JPEG, PNG, WEBP allowed'));
    }
  }
});
 
const { body, param, query, validationResult } = require('express-validator');
 
const validate = (validations) => async (req, res, next) => {
  await Promise.all(validations.map(v => v.run(req)));
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).send({
      success: false,
      message: 'Validation failed',
      errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
    });
  }
  next();
};
 
// ── Simple Logger ──────────────────────────────────────────────────
const logger = {
  info: (msg, data = {}) => console.log(JSON.stringify({
    level: "info", msg, ...data, time: new Date().toISOString()
  })),
  error: (msg, err = {}) => console.error(JSON.stringify({
    level: "error", msg,
    error: err?.message || String(err),
    stack: err?.stack,
    time: new Date().toISOString()
  })),
  warn: (msg, data = {}) => console.warn(JSON.stringify({
    level: "warn", msg, ...data, time: new Date().toISOString()
  })),
};
 
// ── Rate Limiters ──────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false },
  message: { success: false, message: 'Too many login attempts, please try again after 15 minutes' }
});
 
// ── CORS ───────────────────────────────────────────────────────────
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : ['http://localhost:5173'];
 
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS blocked: ${origin}`));
    }
  },
  credentials: true
}));
 
// ── Security Headers ───────────────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }, // imgbb image load এর জন্য
}));
 
app.use(express.json());
 
// ── MongoDB ────────────────────────────────────────────────────────
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.fu1n5ti.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
 
let cachedClient = null;
let cachedDb = null;
 
async function connectDB() {
  if (cachedDb) return cachedDb;
 
  if (cachedClient) {
    cachedDb = cachedClient.db('LBTS-OS-DB');
    return cachedDb;
  }
 
  cachedClient = new MongoClient(uri, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    },
    maxPoolSize: 10,
    minPoolSize: 1,
    maxIdleTimeMS: 30000,
    serverSelectionTimeoutMS: 10000,
    socketTimeoutMS: 45000,
    connectTimeoutMS: 10000,
  });
 
  await cachedClient.connect();
  cachedDb = cachedClient.db('LBTS-OS-DB');
  logger.info("MongoDB Connected");
  return cachedDb;
}
 
// ── JWT Verify Middleware ──────────────────────────────────────────
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
 
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send({ message: 'Unauthorized: No token provided' });
  }
 
  const token = authHeader.split(' ')[1];
 
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).send({ message: 'Unauthorized: Invalid or expired token' });
  }
}
 
// ── Admin only middleware ──────────────────────────────────────────
function verifyAdmin(req, res, next) {
  if (req.user?.role !== 'admin' || req.user?.status !== 'approved') {
    return res.status(403).send({ message: 'Forbidden: Admins only' });
  }
  next();
}
 
 
// ── ObjectId Validation Helper ─────────────────────────────────────
function isValidObjectId(id) {
  return ObjectId.isValid(id) && String(new ObjectId(id)) === id;
}
 
function validateObjectId(paramName = 'id') {
  return (req, res, next) => {
    const id = req.params[paramName];
    if (!isValidObjectId(id)) {
      return res.status(400).send({
        success: false,
        message: `Invalid ID format: ${paramName}`
      });
    }
    next();
  };
}
 
// ── Health Check ───────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.send('LBTS-OS Server is running ✅');
});
 
// ── Image Upload ───────────────────────────────────────────────────
app.post('/upload-image', verifyToken, multerUpload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).send({ success: false, message: 'No image provided' });
    }
 
    const formData = new FormData();
    formData.append('image', req.file.buffer.toString('base64'));
 
    const response = await axios.post(
      `https://api.imgbb.com/1/upload?key=${process.env.IMGBB_API_KEY}`,
      formData,
      { headers: formData.getHeaders() }
    );
 
    res.send({ success: true, url: response.data.data.url });
  } catch (err) {
    logger.error("Image upload failed", err);
    res.status(500).send({ success: false, message: 'Image upload failed' });
  }
});
 
// ── JWT Token Issue ────────────────────────────────────────────────
app.post('/jwt', authLimiter, validate([
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const userCollection = db.collection('users');
    const { email } = req.body;
 
    if (!email) return res.status(400).send({ message: 'Email required' });
 
    const user = await userCollection.findOne({ email });
    const payload = {
      email,
      role: user?.role || 'user',
      status: user?.status || 'pending',
    };
 
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
    res.send({ token });
  } catch (err) {
    logger.error("Token generation failed", err);
    res.status(500).send({ message: 'Token generation failed' });
  }
});
 
// ── Users ──────────────────────────────────────────────────────────────────────
 
// ── Users ──────────────────────────────────────────────────────────────────────
 
app.post('/users', authLimiter, validate([
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('displayName').trim().notEmpty().withMessage('Name required'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const userCollection = db.collection('users');
    const user = req.body;
    const exists = await userCollection.findOne({ email: user.email });
    if (exists) return res.send({ message: 'User already exists' });
    user.role = 'user';
    user.status = 'pending';
    const result = await userCollection.insertOne(user);
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: 'Failed to add user' });
  }
});
 
app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const db = await connectDB();
    const userCollection = db.collection('users');
    const result = await userCollection.find().toArray();
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: 'Failed to fetch users' });
  }
});
 
app.get('/users/:email/role', verifyToken, async (req, res) => {
  try {
    const db = await connectDB();
    const userCollection = db.collection('users');
    const user = await userCollection.findOne({ email: req.params.email });
    if (!user) return res.status(404).send({ message: 'User not found' });
    res.send({ role: user.role, status: user.status });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: 'Failed to fetch user role' });
  }
});
 
// app.patch('/users/role/:id', verifyToken, verifyAdmin, validateObjectId('id'), validate([
//   param('id').isMongoId().withMessage('Invalid user ID'),
//   body('role').isIn(['admin', 'manager', 'operator', 'user', 'ceo','vendor']).withMessage('Invalid role'),
// ]), async (req, res) => {
//   try {
//     const db = await connectDB();
//     const userCollection = db.collection('users');
//     const { role } = req.body;
//     const result = await userCollection.updateOne(
//       { _id: new ObjectId(req.params.id) },
//       { $set: { role } }
//     );
//     res.send(result);
//   } catch (err) {
//     console.error(err);
//     res.status(500).send({ message: 'Failed to update role' });
//   }
// });
 
app.patch('/users/role/:id', verifyToken, verifyAdmin, validateObjectId('id'), validate([
  param('id').isMongoId().withMessage('Invalid user ID'),
  body('role').isIn(['admin', 'manager', 'operator', 'user', 'ceo','vendor']).withMessage('Invalid role'),
  body('vendorName').optional().trim(),  // ← ADD
]), async (req, res) => {
  try {
    const db = await connectDB();
    const userCollection = db.collection('users');
    const { role, vendorName } = req.body;  // ← vendorName নাও
    const setDoc = { role };
    if (role === 'vendor' && vendorName) setDoc.vendorName = vendorName;  // ← vendor হলে save করো
    const result = await userCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: setDoc }
    );
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: 'Failed to update role' });
  }
});

app.patch('/users/status/:id', verifyToken, verifyAdmin, validateObjectId('id'), validate([
  param('id').isMongoId().withMessage('Invalid user ID'),
  body('status').isIn(['approved', 'pending', 'rejected']).withMessage('Invalid status'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const userCollection = db.collection('users');
    const { status } = req.body;
    const result = await userCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status } }
    );
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: 'Failed to update status' });
  }
});
 
app.delete('/users/:id', verifyToken, verifyAdmin, validateObjectId('id'), validate([
  param('id').isMongoId().withMessage('Invalid user ID'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const userCollection = db.collection('users');
    const result = await userCollection.deleteOne({ _id: new ObjectId(req.params.id) });
    if (result.deletedCount === 1) {
      res.send({ success: true, message: 'User deleted successfully' });
    } else {
      res.status(404).send({ success: false, message: 'User not found' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: 'Failed to delete user' });
  }
});
 
// ── Gate Pass ──────────────────────────────────────────────────────────────────
 
app.post('/gate-pass', verifyToken, validate([
  body('tripDo').trim().notEmpty().withMessage('Trip Do required'),
  body('tripDate').isISO8601().withMessage('Valid date required'),
  body('customerName').trim().notEmpty().withMessage('Customer name required'),
  body('csd').trim().notEmpty().withMessage('CSD required'),
  body('vehicleNo').trim().notEmpty().withMessage('Vehicle number required'),
  body('zone').trim().notEmpty().withMessage('Zone required'),
  body('products').isArray({ min: 1 }).withMessage('At least one product required'),
  body('products.*.productName').trim().notEmpty().withMessage('Product name required'),
  body('products.*.model').trim().notEmpty().withMessage('Model required'),
  body('products.*.quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const gatePassCollection = db.collection('gate-pass');
    const gatePass = req.body;
    if (gatePass.products && Array.isArray(gatePass.products)) {
      gatePass.products = gatePass.products.map(p => ({
        _id: new ObjectId().toString(),
        productName: p.productName,
        model: p.model,
        quantity: Number(p.quantity)
      }));
    }
    gatePass.createdAt = new Date();
    gatePass.tripMonth = new Date(gatePass.tripDate).getMonth() + 1;
    gatePass.tripYear = new Date(gatePass.tripDate).getFullYear();
    const result = await gatePassCollection.insertOne(gatePass);
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: 'Failed to add gate pass' });
  }
});
 
app.get("/gate-pass", verifyToken, async (req, res) => {
  try {
    const db = await connectDB();
    const gatePassCollection = db.collection('gate-pass');
    let month = parseInt(req.query.month);
    let year = parseInt(req.query.year);
    const search = req.query.search || "";
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;
    let query = {};
    if (search) {
      query.$or = [
        { tripDo: { $regex: search, $options: "i" } },
        { customerName: { $regex: search, $options: "i" } },
        { csd: { $regex: search, $options: "i" } },
        { unit: { $regex: search, $options: "i" } },
        { vehicleNo: { $regex: search, $options: "i" } },
        { zone: { $regex: search, $options: "i" } },
        { "products.productName": { $regex: search, $options: "i" } },
        { "products.model": { $regex: search, $options: "i" } },
      ];
    } else {
      if (!month || !year) {
        const now = new Date();
        month = now.getMonth() + 1;
        year = now.getFullYear();
      }
      query.tripMonth = month;
      query.tripYear = year;
    }
    const [data, total] = await Promise.all([
      gatePassCollection.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
      gatePassCollection.countDocuments(query),
    ]);
    res.send({
      data,
      pagination: {
        total, page, limit,
        totalPages: Math.ceil(total / limit),
        hasNextPage: page < Math.ceil(total / limit),
        hasPrevPage: page > 1,
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch gate passes" });
  }
});
 
app.patch('/gate-pass/:id', verifyToken, validateObjectId('id'), validate([
  param('id').isMongoId().withMessage('Invalid gate pass ID'),
  body('customerName').trim().notEmpty().withMessage('Customer name required'),
  body('tripDate').isISO8601().withMessage('Valid date required'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const gatePassCollection = db.collection('gate-pass');
    const { tripDo, tripDate, customerName, csd, unit, vehicleNo, zone, currentUser } = req.body;
    await gatePassCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      {
        $set: {
          tripDo, tripDate, customerName, csd, unit, vehicleNo, zone, currentUser,
          tripMonth: new Date(tripDate).getMonth() + 1,
          tripYear: new Date(tripDate).getFullYear()
        }
      }
    );
    const updatedGatePass = await gatePassCollection.findOne({ _id: new ObjectId(req.params.id) });
    res.send({ success: true, data: updatedGatePass });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to update gate pass" });
  }
});
 
app.put('/gate-pass/:gatePassId/product/:productId', verifyToken, validateObjectId('gatePassId'), validate([
  param('gatePassId').isMongoId().withMessage('Invalid gate pass ID'),
  body('productName').trim().notEmpty().withMessage('Product name required'),
  body('model').trim().notEmpty().withMessage('Model required'),
  body('quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const gatePassCollection = db.collection('gate-pass');
    const { gatePassId, productId } = req.params;
    const { productName, model, quantity } = req.body;
    const result = await gatePassCollection.updateOne(
      { _id: new ObjectId(gatePassId), "products._id": productId },
      {
        $set: {
          "products.$.productName": productName,
          "products.$.model": model,
          "products.$.quantity": Number(quantity)
        }
      }
    );
    if (result.matchedCount === 0)
      return res.status(404).send({ success: false, message: "Product not found" });
    const updatedGatePass = await gatePassCollection.findOne({ _id: new ObjectId(gatePassId) });
    res.send({ success: true, data: updatedGatePass });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to update product" });
  }
});
 
app.delete('/gate-pass/:id', verifyToken, validateObjectId('id'), validate([
  param('id').isMongoId().withMessage('Invalid ID'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const gatePassCollection = db.collection('gate-pass');
    const result = await gatePassCollection.deleteOne({ _id: new ObjectId(req.params.id) });
    if (result.deletedCount === 0)
      return res.status(404).send({ success: false, message: "Gate Pass not found" });
    res.send({ success: true, message: "Gate Pass deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to delete gate pass" });
  }
});
 
// ── Autocomplete ───────────────────────────────────────────────────────────────
 
app.get("/autocomplete", verifyToken, async (req, res) => {
  try {
    const db = await connectDB();
    const gatePassCollection = db.collection('gate-pass');
    const challanCollection = db.collection('challans');
    const { field, search, collection } = req.query;
    const targetCollection = collection === "challan" ? challanCollection : gatePassCollection;
    let pipeline = [];
    if (field === "productName" || field === "model") {
      pipeline = [
        { $unwind: "$products" },
        { $match: { [`products.${field}`]: { $regex: search || "", $options: "i" } } },
        { $group: { _id: `$products.${field}` } },
        { $project: { _id: 0, value: "$_id" } },
        { $limit: 5 },
      ];
    } else {
      pipeline = [
        { $match: { [field]: { $regex: search || "", $options: "i" } } },
        { $group: { _id: `$${field}` } },
        { $project: { _id: 0, value: "$_id" } },
        { $limit: 5 },
      ];
    }
    const result = await targetCollection.aggregate(pipeline).toArray();
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Autocomplete failed" });
  }
});
 
// ── Challan ────────────────────────────────────────────────────────────────────
 
app.post("/challan", verifyToken, validate([
  body('customerName').trim().notEmpty().withMessage('Customer name required'),
  body('address').trim().notEmpty().withMessage('Address required'),
  body('receiverNumber').trim().notEmpty().withMessage('Receiver number required'),
  body('zone').trim().notEmpty().withMessage('Zone required'),
  body('products').isArray({ min: 1 }).withMessage('At least one product required'),
  body('products.*.productName').trim().notEmpty().withMessage('Product name required'),
  body('products.*.model').trim().notEmpty().withMessage('Model required'),
  body('products.*.quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');
    const challan = req.body;
    if (challan.products && Array.isArray(challan.products)) {
      challan.products = challan.products.map(p => ({
        _id: new ObjectId().toString(),
        productName: p.productName,
        model: p.model,
        quantity: Number(p.quantity)
      }));
    }
    challan.createdAt = new Date();
    const result = await challanCollection.insertOne(challan);
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to add challan" });
  }
});
 
app.get("/challan/recent", verifyToken, async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');
    const result = await challanCollection.find().sort({ createdAt: -1 }).limit(1).toArray();
    res.send({ data: result });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch recent challan" });
  }
});
 
app.get("/challans", verifyToken, async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');
    let month = parseInt(req.query.month);
    let year = parseInt(req.query.year);
    const search = req.query.search || "";
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;
 
    // ── Server-side column filters ─────────────────────────────────
    const customerFilter = req.query.customer || "";
    const zoneFilter = req.query.zone || "";
    const districtFilter = req.query.district || "";
    const thanaFilter = req.query.thana || "";
    const receiverFilter = req.query.receiver || "";
    const modelFilter = req.query.model || "";
    const productNameFilter = req.query.productName || "";
    const dateFilter = req.query.date || "";
 
    let query = {};
    if (search) {
      query.$or = [
        { customerName: { $regex: search, $options: "i" } },
        { address: { $regex: search, $options: "i" } },
        { receiverNumber: { $regex: search, $options: "i" } },
        { zone: { $regex: search, $options: "i" } },
        { thana: { $regex: search, $options: "i" } },
        { district: { $regex: search, $options: "i" } },
        { "products.productName": { $regex: search, $options: "i" } },
        { "products.model": { $regex: search, $options: "i" } },
      ];
    } else {
      if (!month || !year) {
        const now = new Date();
        month = now.getMonth() + 1;
        year = now.getFullYear();
      }
      const startDate = new Date(year, month - 1, 1);
      const endDate = new Date(year, month, 0, 23, 59, 59);
      query.createdAt = { $gte: startDate, $lte: endDate };
    }
    if (customerFilter) query.customerName = { $regex: customerFilter, $options: "i" };
    if (zoneFilter) query.zone = { $regex: zoneFilter, $options: "i" };
    if (districtFilter) query.district = { $regex: districtFilter, $options: "i" };
    if (thanaFilter) query.thana = { $regex: thanaFilter, $options: "i" };
    if (receiverFilter) query.receiverNumber = { $regex: receiverFilter, $options: "i" };
    if (modelFilter) query["products.model"] = { $regex: modelFilter, $options: "i" };
    if (productNameFilter) query["products.productName"] = { $regex: productNameFilter, $options: "i" };
    if (dateFilter) {
      const filterDate = new Date(dateFilter);
      const nextDay = new Date(dateFilter);
      nextDay.setDate(nextDay.getDate() + 1);
      query.createdAt = { $gte: filterDate, $lt: nextDay };
    }
 
    const [data, total] = await Promise.all([
      challanCollection.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
      challanCollection.countDocuments(query),
    ]);
    res.send({
      data,
      pagination: {
        total, page, limit,
        totalPages: Math.ceil(total / limit),
        hasNextPage: page < Math.ceil(total / limit),
        hasPrevPage: page > 1,
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch challans" });
  }
});
 
app.get("/challans/filter-options", verifyToken, async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');
    let month = parseInt(req.query.month);
    let year = parseInt(req.query.year);
    if (!month || !year) {
      const now = new Date();
      month = now.getMonth() + 1;
      year = now.getFullYear();
    }
    const startDate = new Date(year, month - 1, 1);
    const endDate = new Date(year, month, 0, 23, 59, 59);
    const baseQuery = { createdAt: { $gte: startDate, $lte: endDate } };
    const [result] = await challanCollection.aggregate([
      { $match: baseQuery },
      { $unwind: "$products" },
      {
        $group: {
          _id: null,
          customerNames: { $addToSet: "$customerName" },
          zones: { $addToSet: "$zone" },
          districts: { $addToSet: "$district" },
          thanas: { $addToSet: "$thana" },
          receivers: { $addToSet: "$receiverNumber" },
          models: { $addToSet: "$products.model" },
          productNames: { $addToSet: "$products.productName" },
        }
      },
      {
        $project: {
          _id: 0,
          customerNames: { $sortArray: { input: "$customerNames", sortBy: 1 } },
          zones: { $sortArray: { input: "$zones", sortBy: 1 } },
          districts: { $sortArray: { input: "$districts", sortBy: 1 } },
          thanas: { $sortArray: { input: "$thanas", sortBy: 1 } },
          receivers: { $sortArray: { input: "$receivers", sortBy: 1 } },
          models: { $sortArray: { input: "$models", sortBy: 1 } },
          productNames: { $sortArray: { input: "$productNames", sortBy: 1 } },
        }
      }
    ]).toArray();
    res.send({
      success: true,
      data: result || { customerNames: [], zones: [], districts: [], thanas: [], receivers: [], models: [], productNames: [] }
    });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch filter options" });
  }
});
 
app.delete("/challan/:id", verifyToken, validateObjectId('id'), validate([
  param('id').isMongoId().withMessage('Invalid ID'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');
    const result = await challanCollection.deleteOne({ _id: new ObjectId(req.params.id) });
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to delete challan" });
  }
});
 
app.patch('/challan/:id', verifyToken, validateObjectId('id'), validate([
  param('id').isMongoId().withMessage('Invalid challan ID'),
  body('customerName').trim().notEmpty().withMessage('Customer name required'),
  body('receiverNumber').trim().notEmpty().withMessage('Receiver number required'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');
    const { customerName, address, thana, district, receiverNumber, zone, currentUser, createdAt } = req.body;
    const setDoc = { customerName, address, thana, district, receiverNumber, zone, currentUser };
    if (createdAt) {
      setDoc.month = new Date(createdAt).getMonth() + 1;
      setDoc.year = new Date(createdAt).getFullYear();
    }
    await challanCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: setDoc });
    const updatedChallan = await challanCollection.findOne({ _id: new ObjectId(req.params.id) });
    res.send({ success: true, data: updatedChallan });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to update challan" });
  }
});
 
 
app.put('/challan/:challanId/product/:productId', verifyToken, validateObjectId('challanId'), validate([
  param('challanId').isMongoId().withMessage('Invalid challan ID'),
  body('productName').trim().notEmpty().withMessage('Product name required'),
  body('model').trim().notEmpty().withMessage('Model required'),
  body('quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');
    const { challanId, productId } = req.params;
    const { productName, model, quantity } = req.body;
    const result = await challanCollection.updateOne(
      { _id: new ObjectId(challanId), "products._id": productId },
      {
        $set: {
          "products.$.productName": productName,
          "products.$.model": model,
          "products.$.quantity": Number(quantity)
        }
      }
    );
    if (result.matchedCount === 0)
      return res.status(404).send({ success: false, message: "Product not found" });
    const updatedChallan = await challanCollection.findOne({ _id: new ObjectId(challanId) });
    res.send({ success: true, data: updatedChallan });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to update product" });
  }
});
 
 
app.delete("/challans/:challanId/product/:productId", verifyToken, validateObjectId('challanId'), async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');
    const { challanId, productId } = req.params;
    const result = await challanCollection.updateOne(
      { _id: new ObjectId(challanId) },
      { $pull: { products: { _id: productId } } }
    );
    if (result.modifiedCount > 0) {
      res.send({ success: true, message: "Product removed from challan" });
    } else {
      res.status(404).send({ success: false, message: "Product not found" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to delete product" });
  }
});
 
app.patch('/challans/:id', verifyToken, validateObjectId('id'), async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');
    const { customerName, receiverNumber, zone, address, thana, district, products } = req.body;
    const result = await challanCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { customerName, receiverNumber, zone, address, thana, district, products } }
    );
    if (result.matchedCount > 0) {
      res.send({ success: true, message: "Challan and Products updated successfully" });
    } else {
      res.status(404).send({ success: false, message: "Challan not found" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Update failed" });
  }
});
 
// ── Vendors ────────────────────────────────────────────────────────────────────
 
app.post("/vendors", verifyToken, validate([
  body('vendorName').trim().notEmpty().withMessage('Vendor name required'),
  body('vendorPhone').trim().notEmpty().withMessage('Phone required'),
  body('vendorAddress').trim().notEmpty().withMessage('Address required'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const vendorsCollection = db.collection('vendors');
    const result = await vendorsCollection.insertOne({
      ...req.body,
      vehicles: [],
      createdAt: new Date(),
    });
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to add vendor" });
  }
});
 
// app.get("/vendors", verifyToken, async (req, res) => {
//   try {
//     const db = await connectDB();
//     const vendorsCollection = db.collection('vendors');
//     const result = await vendorsCollection.find().toArray();
//     res.send(result);
//   } catch (err) {
//     console.error(err);
//     res.status(500).send({ message: "Failed to fetch vendors" });
//   }
// });
 
app.get("/vendors", verifyToken, async (req, res) => {
  try {
    const db = await connectDB();
    const vendorsCollection = db.collection('vendors');
    
    // vendor role হলে শুধু নিজের vendor দেখাবে
    let query = {};
    if (req.user?.role === 'vendor') {
      if (!req.user?.vendorName) return res.send([]);
      query.vendorName = { $regex: `^${req.user.vendorName}$`, $options: 'i' };
    }
    
    const result = await vendorsCollection.find(query).toArray();
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch vendors" });
  }
});

app.get("/vendors/:id", verifyToken, validateObjectId('id'), async (req, res) => {
  try {
    const db = await connectDB();
    const vendorsCollection = db.collection('vendors');
    const vendor = await vendorsCollection.findOne({ _id: new ObjectId(req.params.id) });
    res.send(vendor);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch vendor" });
  }
});
 
app.patch("/vendors/:id", verifyToken, validateObjectId('id'), validate([
  param('id').isMongoId().withMessage('Invalid vendor ID'),
  body('vendorName').trim().notEmpty().withMessage('Vendor name required'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const vendorsCollection = db.collection('vendors');
    const { vendorName, vendorImg, vendorAddress, vendorPhone } = req.body;
    const result = await vendorsCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { vendorName, vendorImg, vendorAddress, vendorPhone } }
    );
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to update vendor" });
  }
});
 
app.delete("/vendors/:id", verifyToken, verifyAdmin, validateObjectId('id'), validate([
  param('id').isMongoId().withMessage('Invalid ID'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const vendorsCollection = db.collection('vendors');
    const result = await vendorsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to delete vendor" });
  }
});
 
// ── Vehicles ───────────────────────────────────────────────────────────────────
 
app.get("/vehicles/search", verifyToken, async (req, res) => {
  try {
    const db = await connectDB();
    const vendorsCollection = db.collection('vendors');
    const search = req.query.search?.trim();
    if (!search) return res.send([]);
    const result = await vendorsCollection.aggregate([
      { $unwind: "$vehicles" },
      { $match: { "vehicles.vehicleNumber": { $regex: search, $options: "i" } } },
      {
        $project: {
          _id: 0,
          vendorName: 1,
          vendorPhone: 1,
          vehicleNumber: "$vehicles.vehicleNumber",
          driverName: "$vehicles.driverName",
          driverPhone: "$vehicles.driverPhone",
        }
      },
      { $limit: 10 }
    ]).toArray();
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Server Error" });
  }
});
 
app.post("/vehicles", verifyToken, validate([
  body('vendorId').isMongoId().withMessage('Invalid vendor ID'),
  body('vehicleNumber').trim().notEmpty().withMessage('Vehicle number required'),
  body('driverName').trim().notEmpty().withMessage('Driver name required'),
  body('driverPhone').trim().notEmpty().withMessage('Driver phone required'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const vendorsCollection = db.collection('vendors');
    const { vendorId, ...vehicleData } = req.body;
    const result = await vendorsCollection.updateOne(
      { _id: new ObjectId(vendorId) },
      { $push: { vehicles: { _id: new ObjectId(), ...vehicleData, createdAt: new Date() } } }
    );
    if (result.modifiedCount > 0) {
      res.send({ insertedId: true });
    } else {
      res.status(404).send({ error: "Vendor not found" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).send({ error: "Failed to add vehicle" });
  }
});
 
app.delete("/vehicles/:vendorId/:vehicleId", verifyToken,
  validateObjectId('vendorId'),
  validateObjectId('vehicleId'),
  async (req, res) => {
    try {
      const db = await connectDB();
      const vendorsCollection = db.collection('vendors');
      const { vendorId, vehicleId } = req.params;
      const result = await vendorsCollection.updateOne(
        { _id: new ObjectId(vendorId) },
        { $pull: { vehicles: { _id: new ObjectId(vehicleId) } } }
      );
      if (result.modifiedCount > 0) {
        res.send({ deletedCount: 1 });
      } else {
        res.status(404).send({ error: "Vehicle or Vendor not found" });
      }
    } catch (err) {
      console.error(err);
      res.status(500).send({ error: "Failed to delete vehicle" });
    }
  }
);
 
app.put("/vehicles/:vendorId/:vehicleId", verifyToken,
  validateObjectId('vendorId'),
  validateObjectId('vehicleId'),
  async (req, res) => {
    try {
      const db = await connectDB();
      const vendorsCollection = db.collection('vendors');
      const { vendorId, vehicleId } = req.params;
      const updatedData = req.body;
      const result = await vendorsCollection.updateOne(
        { _id: new ObjectId(vendorId) },
        {
          $set: {
            "vehicles.$[elem].vehicleNumber": updatedData.vehicleNumber,
            "vehicles.$[elem].vehicleModel": updatedData.vehicleModel,
            "vehicles.$[elem].driverName": updatedData.driverName,
            "vehicles.$[elem].driverPhone": updatedData.driverPhone,
          }
        },
        { arrayFilters: [{ "elem._id": new ObjectId(vehicleId) }] }
      );
      if (result.modifiedCount > 0) {
        res.send({ modifiedCount: 1 });
      } else {
        res.status(404).send({ error: "Nothing updated" });
      }
    } catch (err) {
      console.error(err);
      res.status(500).send({ error: "Failed to update vehicle" });
    }
  }
);
 
// ── Deliveries ─────────────────────────────────────────────────────────────────
 
app.post("/deliveries", verifyToken, validate([
  body().isArray({ min: 1 }).withMessage('At least one delivery required'),
  body('*.vehicleNumber').trim().notEmpty().withMessage('Vehicle number required'),
  body('*.driverName').trim().notEmpty().withMessage('Driver name required'),
  body('*.customerName').trim().notEmpty().withMessage('Customer name required'),
  body('*.products').isArray({ min: 1 }).withMessage('Products required'),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const challanCollection = db.collection('challans');
    const counterCollection = db.collection('counters');
    const deliveries = req.body;
    if (!Array.isArray(deliveries) || deliveries.length === 0) {
      return res.status(400).send({ success: false, message: "No deliveries provided" });
    }
    const session = cachedClient.startSession();
    let tripNumber;
    let result;
    try {
      await session.withTransaction(async () => {
        const counter = await counterCollection.findOneAndUpdate(
          { _id: "tripNumber" },
          { $inc: { seq: 1 } },
          { upsert: true, returnDocument: "after", session }
        );
        const seq = counter?.seq ?? counter?.value?.seq ?? 1;
        tripNumber = `TR-${seq.toString().padStart(6, "0")}`;
 
        const challanIds = deliveries.map(d =>
          typeof d.challanId === "string" ? new ObjectId(d.challanId) : d.challanId
        );
 
        // ── Already delivered check ────────────────────────────────
        const alreadyDelivered = await challanCollection.find(
          { _id: { $in: challanIds }, status: "delivered" },
          { session }
        ).toArray();
 
        if (alreadyDelivered.length > 0) {
          const names = alreadyDelivered.map(c => c.customerName).join(", ");
          throw new Error(`Already delivered: ${names}`);
        }
        // ──────────────────────────────────────────────────────────
 
        const tripDocument = {
          tripNumber,
          vehicleNumber: deliveries[0].vehicleNumber,
          vendorName: deliveries[0].vendorName,
          vendorNumber: deliveries[0].vendorNumber,
          driverName: deliveries[0].driverName,
          driverNumber: deliveries[0].driverNumber,
          createdBy: deliveries[0].createdBy || "unknown",
          totalChallan: deliveries.length,
          challans: deliveries.map(d => ({
            challanId: d.challanId,
            customerName: d.customerName,
            zone: d.zone,
            address: d.address,
            thana: d.thana,
            district: d.district,
            receiverNumber: d.receiverNumber,
            products: (d.products || []).map(p => ({
              _id: p._id || new ObjectId().toString(),
              productName: p.productName,
              model: p.model,
              quantity: Number(p.quantity)
            }))
          })),
          createdAt: new Date()
        };
 
        result = await deliveriesCollection.insertOne(tripDocument, { session });
        await challanCollection.updateMany(
          { _id: { $in: challanIds } },
          { $set: { status: "delivered", tripNumber } },
          { session }
        );
      });
      res.send({ success: true, insertedId: result.insertedId, tripNumber, totalChallan: deliveries.length });
    } finally {
      await session.endSession();
    }
  } catch (err) {
    logger.error("Delivery failed", err);
    // already delivered error টা আলাদাভাবে handle করো
    if (err.message?.startsWith("Already delivered:")) {
      return res.status(400).send({ success: false, message: err.message });
    }
    res.status(500).send({ success: false, message: "Delivery failed", error: err.message });
  }
});
 
 
app.get("/deliveries", verifyToken, async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    let month = parseInt(req.query.month);
    let year = parseInt(req.query.year);
    const search = req.query.search || "";
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;
    let query = {};
 
    if (search) {
      query.$or = [
        { tripNumber:                        { $regex: search, $options: "i" } },
        { vendorName:                        { $regex: search, $options: "i" } },
        { driverName:                        { $regex: search, $options: "i" } },
        { vehicleNumber:                     { $regex: search, $options: "i" } },
        { "challans.customerName":           { $regex: search, $options: "i" } },
        { "challans.zone":                   { $regex: search, $options: "i" } },
        { "challans.address":                { $regex: search, $options: "i" } },
        { "challans.receiverNumber":         { $regex: search, $options: "i" } },
        { "challans.district":               { $regex: search, $options: "i" } },
        { "challans.thana":                  { $regex: search, $options: "i" } },
        { "challans.products.productName":   { $regex: search, $options: "i" } },
        { "challans.products.model":         { $regex: search, $options: "i" } },
      ];
    } else {
      if (!month || !year) {
        const now = new Date();
        month = now.getMonth() + 1;
        year = now.getFullYear();
      }
      const startDate = new Date(year, month - 1, 1);
      const endDate = new Date(year, month, 0, 23, 59, 59, 999);
      query.createdAt = { $gte: startDate, $lte: endDate };
    }
 
    const [data, total] = await Promise.all([
      deliveriesCollection.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
      deliveriesCollection.countDocuments(query),
    ]);
 
    res.send({
      success: true, data,
      pagination: {
        total, page, limit,
        totalPages: Math.ceil(total / limit),
        hasNextPage: page < Math.ceil(total / limit),
        hasPrevPage: page > 1,
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).send({ success: false, message: "Failed to fetch deliveries" });
  }
});
 
app.patch("/deliveries/confirm", verifyToken, async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripNumber, challanId, status, note, operator } = req.body;
    const result = await deliveriesCollection.updateOne(
      { tripNumber, "challans.challanId": String(challanId) },
      {
        $set: {
          "challans.$.deliveryStatus": status,
          "challans.$.operatorNote": note || "",
          "challans.$.confirmedBy": operator,
          "challans.$.confirmedAt": new Date()
        }
      }
    );
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Confirm failed" });
  }
});
 
app.patch("/deliveries/challan-return", verifyToken, async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripNumber, challanId, status, operator } = req.body;
    const result = await deliveriesCollection.updateOne(
      { tripNumber, "challans.challanId": String(challanId) },
      {
        $set: {
          "challans.$.challanReturnStatus": status,
          "challans.$.challanReturnedAt": new Date(),
          "challans.$.challanReceivedBy": operator
        }
      }
    );
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Challan return update failed" });
  }
});
 
 
// ── Edit full challan info inside a trip ───────────────────────────
app.patch("/deliveries/:tripId/challan/:challanId", verifyToken, validateObjectId('tripId'), async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripId, challanId } = req.params;
    const { customerName, address, thana, district, receiverNumber, zone, updatedBy } = req.body; // ← updatedBy নাও
 
    const result = await deliveriesCollection.updateOne(
      { _id: new ObjectId(tripId), "challans.challanId": challanId },
      {
        $set: {
          "challans.$.customerName":   customerName,
          "challans.$.address":        address,
          "challans.$.thana":          thana,
          "challans.$.district":       district,
          "challans.$.receiverNumber": receiverNumber,
          "challans.$.zone":           zone,
          lastUpdatedBy: updatedBy || null, // ← নতুন
          lastUpdatedAt: new Date(),         // ← নতুন
        }
      }
    );
    if (result.matchedCount === 0)
      return res.status(404).send({ success: false, message: "Challan not found in trip" });
 
    const updated = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
    res.send({ success: true, data: updated }); // ← data return করো
  } catch (err) {
    logger.error("Edit trip challan failed", err);
    res.status(500).send({ message: "Failed to update challan" });
  }
});
 
// ── Edit a product inside a trip's challan ─────────────────────────
app.patch("/deliveries/:tripId/challan/:challanId/product/:productId", verifyToken, validateObjectId('tripId'), async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripId, challanId, productId } = req.params;
    const { productName, model, quantity } = req.body;
 
    // Fetch the trip, find challan index, update product in that challan
    const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
    if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });
 
    const challanIndex = trip.challans.findIndex(c => c.challanId === challanId);
    if (challanIndex === -1) return res.status(404).send({ success: false, message: "Challan not found" });
 
    const productIndex = trip.challans[challanIndex].products.findIndex(p => p._id === productId);
    if (productIndex === -1) return res.status(404).send({ success: false, message: "Product not found" });
 
    const updateField = `challans.${challanIndex}.products.${productIndex}`;
    const result = await deliveriesCollection.updateOne(
      { _id: new ObjectId(tripId) },
      { $set: {
        [`${updateField}.productName`]: productName,
        [`${updateField}.model`]:       model,
        [`${updateField}.quantity`]:    Number(quantity),
      }}
    );
    res.send({ success: true, modifiedCount: result.modifiedCount });
  } catch (err) {
    logger.error("Edit trip product failed", err);
    res.status(500).send({ message: "Failed to update product" });
  }
});
 
// ── Delete a product inside a trip's challan ───────────────────────
app.delete("/deliveries/:tripId/challan/:challanId/product/:productId", verifyToken, validateObjectId('tripId'), async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripId, challanId, productId } = req.params;
 
    const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
    if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });
 
    const challanIndex = trip.challans.findIndex(c => c.challanId === challanId);
    if (challanIndex === -1) return res.status(404).send({ success: false, message: "Challan not found" });
 
    if (trip.challans[challanIndex].products.length <= 1)
      return res.status(400).send({ success: false, message: "Cannot remove last product" });
 
    const result = await deliveriesCollection.updateOne(
      { _id: new ObjectId(tripId) },
      { $pull: { [`challans.${challanIndex}.products`]: { _id: productId } } }
    );
    res.send({ success: true, modifiedCount: result.modifiedCount });
  } catch (err) {
    logger.error("Delete trip product failed", err);
    res.status(500).send({ message: "Failed to delete product" });
  }
});
 
// ── Add a product to a trip's challan ─────────────────────────────
app.post("/deliveries/:tripId/challan/:challanId/product", verifyToken, validateObjectId('tripId'), async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripId, challanId } = req.params;
    const { productName, model, quantity } = req.body;
 
    const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
    if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });
 
    const challanIndex = trip.challans.findIndex(c =>
      c.challanId === challanId || c.challanId?.toString() === challanId
    );
    if (challanIndex === -1) return res.status(404).send({ success: false, message: "Challan not found" });
 
    const newProduct = {
      _id: new ObjectId().toString(),
      productName,
      model,
      quantity: Number(quantity)
    };
 
    await deliveriesCollection.updateOne(
      { _id: new ObjectId(tripId) },
      { $push: { [`challans.${challanIndex}.products`]: newProduct } }
    );
    res.send({ success: true, product: newProduct });
  } catch (err) {
    logger.error("Add trip product failed", err);
    res.status(500).send({ message: "Failed to add product" });
  }
});
 
// ── Delete a full challan from a trip ─────────────────────────────
app.delete("/deliveries/:tripId/challan/:challanId", verifyToken, validateObjectId('tripId'), async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripId, challanId } = req.params;
 
    const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
    if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });
    if (trip.challans.length <= 1)
      return res.status(400).send({ success: false, message: "Cannot remove last challan from trip" });
 
    // challan টা আসলে DB তে কোন format এ আছে সেটা দেখো
    const targetChallan = trip.challans.find(c => 
      c.challanId === challanId || c.challanId?.toString() === challanId
    );
    if (!targetChallan)
      return res.status(404).send({ success: false, message: "Challan not found in trip" });
 
    const result = await deliveriesCollection.updateOne(
      { _id: new ObjectId(tripId) },
      {
        $pull: { challans: { challanId: targetChallan.challanId } },
        $inc: { totalChallan: -1 }
      }
    );
    res.send({ success: true, modifiedCount: result.modifiedCount });
  } catch (err) {
    logger.error("Delete trip challan failed", err);
    res.status(500).send({ message: "Failed to delete challan" });
  }
});
 
// ── Edit trip vehicle/driver/vendor info ───────────────────────────
app.patch("/deliveries/:tripId/trip-info", verifyToken, validateObjectId('tripId'), async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripId } = req.params;
    const { vehicleNumber, vendorName, vendorNumber, driverName, driverNumber, updatedBy } = req.body;
 
    const result = await deliveriesCollection.updateOne(
      { _id: new ObjectId(tripId) },
      {
        $set: {
          vehicleNumber, vendorName, vendorNumber, driverName, driverNumber,
          lastUpdatedBy: updatedBy || null,  // ← trip info updater
          lastUpdatedAt: new Date(),
          // advanceSavedBy touch করছে না
        }
      }
    );
    if (result.matchedCount === 0)
      return res.status(404).send({ success: false, message: "Trip not found" });
 
    // ← data return করো, frontend এটা serverData হিসেবে পাবে
    const updated = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
    res.send({ success: true, data: updated });
  } catch (err) {
    logger.error("Edit trip info failed", err);
    res.status(500).send({ message: "Failed to update trip info" });
  }
});
 
 
// ── Add/Update return products for a challan ───────────────────────
app.patch("/deliveries/:tripId/challan/:challanId/return", verifyToken, validateObjectId('tripId'), async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripId, challanId } = req.params;
    const { returnedProducts, returnNote,updatedBy  } = req.body;
    // returnedProducts: [{ _id, productName, model, returnQty }]
 
    const result = await deliveriesCollection.updateOne(
      { _id: new ObjectId(tripId), "challans.challanId": challanId },
      {
        $set: {
          "challans.$.returnedProducts": returnedProducts,
          "challans.$.returnNote":       returnNote || "",
          "challans.$.returnedAt":       new Date(),
          lastUpdatedBy: updatedBy || null, // ← নতুন
      lastUpdatedAt: new Date(),
        }
      }
    );
    if (result.matchedCount === 0)
      return res.status(404).send({ success: false, message: "Challan not found" });
    res.send({ success: true });
  } catch (err) {
    logger.error("Return update failed", err);
    res.status(500).send({ message: "Failed to update return" });
  }
});
 
// ── Add/Update note for a challan ──────────────────────────────────
app.patch("/deliveries/:tripId/challan/:challanId/note", verifyToken, validateObjectId('tripId'), async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripId, challanId } = req.params;
    const { note,updatedBy  } = req.body;
 
    const result = await deliveriesCollection.updateOne(
      { _id: new ObjectId(tripId), "challans.challanId": challanId },
      { $set: { "challans.$.note": note, "challans.$.noteUpdatedAt": new Date(),
            lastUpdatedBy: updatedBy || null, // ← নতুন
      lastUpdatedAt: new Date(),
       } }
    );
    if (result.matchedCount === 0)
      return res.status(404).send({ success: false, message: "Challan not found" });
    res.send({ success: true });
  } catch (err) {
    logger.error("Note update failed", err);
    res.status(500).send({ message: "Failed to update note" });
  }
});
 
// ── Add return challan to trip ─────────────────────────────────────
app.post("/deliveries/:tripId/return-challan", verifyToken, validateObjectId('tripId'), async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripId } = req.params;
    const { 
  originalChallanId, customerName, zone, address, 
  thana, district, receiverNumber, 
  returnedProducts, returnNote,
  updatedBy  
} = req.body;
    const trip = await deliveriesCollection.findOne({ _id: new ObjectId(tripId) });
    if (!trip) return res.status(404).send({ success: false, message: "Trip not found" });
 
    // Return challan object
    const returnChallan = {
      challanId:        `return_${originalChallanId}_${Date.now()}`,
      isReturn:         true,
      originalChallanId,
      customerName,
      zone,
      address,
      thana,
      district,
      receiverNumber,
      products:         returnedProducts.map(p => ({
        _id:         p._id || new ObjectId().toString(),
        productName: p.productName,
        model:       p.model,
        quantity:    Number(p.returnQty || p.quantity),
      })),
      returnNote:       returnNote || "",
      returnedAt:       new Date(),
      deliveryStatus:   "return",
      challanReturnStatus: null,
    };
 
    await deliveriesCollection.updateOne(
      { _id: new ObjectId(tripId) },
      {
        $push: { challans: returnChallan },
        $inc:  { totalChallan: 1 }
      }
    );
 
    // Also update original challan's returnedProducts
    await deliveriesCollection.updateOne(
      { _id: new ObjectId(tripId), "challans.challanId": originalChallanId },
      {
        $set: {
          "challans.$.returnedProducts": returnedProducts,
          "challans.$.returnNote":       returnNote || "",
          "challans.$.returnedAt":       new Date(),
          lastUpdatedBy: updatedBy || null, // ← নতুন
  lastUpdatedAt: new Date(),
        }
      }
    );
 
    res.send({ success: true, returnChallan });
  } catch (err) {
    logger.error("Return challan add failed", err);
    res.status(500).send({ message: "Failed to add return challan" });
  }
});
 
// ── Car Rent ───────────────────────────────────────────────────────────────────
 
// app.get("/car-rents", verifyToken, async (req, res) => {
//   try {
//     const db = await connectDB();
//     const deliveriesCollection = db.collection('deliveries');
//     let month = parseInt(req.query.month);
//     let year  = parseInt(req.query.year);
//     const search = req.query.search || "";
//     const page  = parseInt(req.query.page)  || 1;
//     const limit = parseInt(req.query.limit) || 50;
//     const skip  = (page - 1) * limit;
 
//     let query = {};
//     if (search) {
//       query.$or = [
//         { tripNumber:    { $regex: search, $options: "i" } },
//         { vendorName:    { $regex: search, $options: "i" } },
//         { driverName:    { $regex: search, $options: "i" } },
//         { vehicleNumber: { $regex: search, $options: "i" } },
//       ];
//     } else {
//       if (!month || !year) {
//         const now = new Date();
//         month = now.getMonth() + 1;
//         year  = now.getFullYear();
//       }
//       const startDate = new Date(year, month - 1, 1);
//       const endDate   = new Date(year, month, 0, 23, 59, 59, 999);
//       query.createdAt = { $gte: startDate, $lte: endDate };
//     }
 
//     const [data, total] = await Promise.all([
//       deliveriesCollection.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
//       deliveriesCollection.countDocuments(query),
//     ]);
 
//     res.send({
//       success: true, data,
//       pagination: { total, page, limit,
//         totalPages: Math.ceil(total / limit),
//         hasNextPage: page < Math.ceil(total / limit),
//         hasPrevPage: page > 1,
//       }
//     });
//   } catch (err) {
//     logger.error("Car rent fetch failed", err);
//     res.status(500).send({ success: false, message: "Failed to fetch car rents" });
//   }
// });
 
app.get("/car-rents", verifyToken, async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    let month = parseInt(req.query.month);
    let year  = parseInt(req.query.year);
    const search = req.query.search || "";
    const page  = parseInt(req.query.page)  || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip  = (page - 1) * limit;

    let query = {};

    if (search) {
      query.$or = [
        { tripNumber:    { $regex: search, $options: "i" } },
        { vendorName:    { $regex: search, $options: "i" } },
        { driverName:    { $regex: search, $options: "i" } },
        { vehicleNumber: { $regex: search, $options: "i" } },
      ];
    } else {
      if (!month || !year) {
        const now = new Date();
        month = now.getMonth() + 1;
        year  = now.getFullYear();
      }
      const startDate = new Date(year, month - 1, 1);
      const endDate   = new Date(year, month, 0, 23, 59, 59, 999);
      query.createdAt = { $gte: startDate, $lte: endDate };
    }

    // vendor role হলে শুধু নিজের vendorName এর trips দেখাবে
    if (req.user?.role === "vendor") {
      if (!req.user?.vendorName) {
        return res.send({
          success: true, data: [],
          pagination: { total: 0, page, limit, totalPages: 0, hasNextPage: false, hasPrevPage: false },
        });
      }
      query.vendorName = { $regex: `^${req.user.vendorName}$`, $options: "i" };
    }

    const [data, total] = await Promise.all([
      deliveriesCollection.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
      deliveriesCollection.countDocuments(query),
    ]);

    res.send({
      success: true, data,
      pagination: {
        total, page, limit,
        totalPages: Math.ceil(total / limit),
        hasNextPage: page < Math.ceil(total / limit),
        hasPrevPage: page > 1,
      }
    });
  } catch (err) {
    logger.error("Car rent fetch failed", err);
    res.status(500).send({ success: false, message: "Failed to fetch car rents" });
  }
});

// ── Update rent & leborBill for a trip ─────────────────────────────
app.patch("/car-rents/:tripId", verifyToken, validateObjectId('tripId'), async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { rent, leborBill,updatedBy  } = req.body;
    const result = await deliveriesCollection.updateOne(
      { _id: new ObjectId(req.params.tripId) },
      { $set: { rent, leborBill,
        rentSavedBy: updatedBy || null,
       } }
    );
    if (result.matchedCount === 0)
      return res.status(404).send({ success: false, message: "Trip not found" });
    const updated = await deliveriesCollection.findOne({ _id: new ObjectId(req.params.tripId) });
    res.send({ success: true, data: updated });
  } catch (err) {
    logger.error("Car rent update failed", err);
    res.status(500).send({ message: "Failed to update" });
  }
});
 
 
// ── Update advance amount for a trip ──────────────────────────────
app.patch("/deliveries/:tripId/advance", verifyToken, validateObjectId('tripId'), async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { advance, updatedBy } = req.body;
 
    const result = await deliveriesCollection.updateOne(
      { _id: new ObjectId(req.params.tripId) },
      {
        $set: {
          advance: advance !== undefined ? Number(advance) : null,
          advanceSavedBy: updatedBy || null,  // ← শুধু এটাই
          // lastUpdatedBy touch করছে না!
        }
      }
    );
    if (result.matchedCount === 0)
      return res.status(404).send({ success: false, message: "Trip not found" });
 
    const updated = await deliveriesCollection.findOne({ _id: new ObjectId(req.params.tripId) });
    res.send({ success: true, data: updated });
  } catch (err) {
    logger.error("Advance update failed", err);
    res.status(500).send({ message: "Failed to update advance" });
  }
});
// ── Accounts ───────────────────────────────────────────────────────
//
//  collection: accounts
//  document shape:
//  {
//    type:        "income" | "expense" | "vendor_payment" | "auto_advance"
//    description: string
//    amount:      number
//    date:        string  (YYYY-MM-DD)
//    note:        string  (optional)
//    vendorName:  string  (vendor_payment only)
//    month:       number
//    year:        number
//    createdBy:   string
//    createdAt:   Date
//  }
 
app.post("/accounts", verifyToken, validate([
  body("type").isIn(["income","expense","vendor_payment","auto_advance","manual_advance","advance_adjust","carry_forward"]).withMessage("Invalid type"),
  body("amount").isFloat().withMessage("Amount must be a number"), // advance_adjust negative হতে পারে
  body("date").isISO8601().withMessage("Valid date required"),
  body("description").trim().notEmpty().withMessage("Description required"),
]), async (req, res) => {
  try {
    const db = await connectDB();
    const col = db.collection("accounts");
    const { type, description, amount, date, note, vendorName, recipientName } = req.body;
    const d = new Date(date);
    const doc = {
      type,
      description: description.trim(),
      amount: Number(amount),
      date,
      note: note?.trim() || "",
      vendorName: vendorName?.trim() || "",
      recipientName: recipientName?.trim() || "",
      month: d.getMonth() + 1,
      year:  d.getFullYear(),
      createdBy: req.user?.email || "unknown",
      createdAt: new Date(),
    };
    const result = await col.insertOne(doc);
    res.send({ success: true, insertedId: result.insertedId, data: { ...doc, _id: result.insertedId } });
  } catch (err) {
    logger.error("Account tx insert failed", err);
    res.status(500).send({ message: "Failed to add transaction" });
  }
});
 
app.get("/accounts", verifyToken, async (req, res) => {
  try {
    const db = await connectDB();
    const col = db.collection("accounts");
    let month = parseInt(req.query.month);
    let year  = parseInt(req.query.year);
    if (!month || !year) {
      const now = new Date();
      month = now.getMonth() + 1;
      year  = now.getFullYear();
    }
    const data = await col.find({ month, year }).sort({ date: -1, createdAt: -1 }).toArray();
    res.send({ success: true, data });
  } catch (err) {
    logger.error("Account tx fetch failed", err);
    res.status(500).send({ message: "Failed to fetch transactions" });
  }
});
 
app.delete("/accounts/:id", verifyToken, validateObjectId("id"), async (req, res) => {
  try {
    const db = await connectDB();
    const col = db.collection("accounts");
    const auditCol = db.collection("audit_logs");
 
    const doc = await col.findOne({ _id: new ObjectId(req.params.id) });
    if (!doc) return res.status(404).send({ success: false, message: "Transaction not found" });
    if (doc.type === "auto_advance") return res.status(403).send({ success: false, message: "Auto transactions cannot be deleted" });
 
    // ── Delete reason (optional — frontend থেকে পাঠাতে পারবে)
    const reason = req.body?.reason?.trim() || "";
 
    // ── Audit log save করো delete করার আগে
    await auditCol.insertOne({
      action: "DELETE_TRANSACTION",
      collectionName: "accounts",
      documentId: doc._id,
      deletedDocument: doc,          // পুরো document টা save করো
      reason,
      performedBy: {
        email: req.user?.email || "unknown",
        role:  req.user?.role  || "unknown",
      },
      performedAt: new Date(),
      ipAddress: req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown",
    });
 
    await col.deleteOne({ _id: new ObjectId(req.params.id) });
    logger.info("Account tx deleted with audit log", { id: req.params.id, by: req.user?.email });
    res.send({ success: true });
  } catch (err) {
    logger.error("Account tx delete failed", err);
    res.status(500).send({ message: "Failed to delete transaction" });
  }
});
 
// ── Get Audit Logs ─────────────────────────────────────────────────
app.get("/audit-logs", verifyToken, async (req, res) => {
  try {
    const db = await connectDB();
    const col = db.collection("audit_logs");
    const page  = Math.max(1, parseInt(req.query.page)  || 1);
    const limit = Math.min(100, parseInt(req.query.limit) || 50);
    const skip  = (page - 1) * limit;
 
    // Filter options
    const filter = {};
    if (req.query.action)      filter.action       = req.query.action;
    if (req.query.performedBy) filter["performedBy.email"] = { $regex: req.query.performedBy, $options: "i" };
 
    const [data, total] = await Promise.all([
      col.find(filter).sort({ performedAt: -1 }).skip(skip).limit(limit).toArray(),
      col.countDocuments(filter),
    ]);
    res.send({ success: true, data, total, page, limit });
  } catch (err) {
    logger.error("Audit log fetch failed", err);
    res.status(500).send({ message: "Failed to fetch audit logs" });
  }
});
 
// ── Mark audit log entry as restored ──────────────────────────────
app.patch("/audit-logs/:id/restored", verifyToken, validateObjectId("id"), async (req, res) => {
  try {
    const db = await connectDB();
    const col = db.collection("audit_logs");
    const { restoredDocumentId } = req.body; // নতুন insert হওয়া document এর _id
    const result = await col.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: {
        isRestored: true,
        restoredAt: new Date(),
        restoredBy: { email: req.user?.email || "unknown", role: req.user?.role || "unknown" },
        restoredDocumentId: restoredDocumentId || null,
      }}
    );
    if (result.matchedCount === 0)
      return res.status(404).send({ success: false, message: "Audit log not found" });
    res.send({ success: true });
  } catch (err) {
    logger.error("Audit log restore mark failed", err);
    res.status(500).send({ message: "Failed to mark as restored" });
  }
});
 
// ── Mark manual advance as paid/unpaid ────────────────────────────
app.patch("/accounts/:id/status", verifyToken, validateObjectId("id"), async (req, res) => {
  try {
    const db = await connectDB();
    const col = db.collection("accounts");
    const { status } = req.body; // "paid" | "unpaid"
    if (!["paid","unpaid"].includes(status))
      return res.status(400).send({ success: false, message: "Invalid status" });
    const result = await col.updateOne(
      { _id: new ObjectId(req.params.id), type: "manual_advance" },
      { $set: { status, statusUpdatedAt: new Date() } }
    );
    if (result.matchedCount === 0)
      return res.status(404).send({ success: false, message: "Advance not found" });
    const updated = await col.findOne({ _id: new ObjectId(req.params.id) });
    res.send({ success: true, data: updated });
  } catch (err) {
    logger.error("Advance status update failed", err);
    res.status(500).send({ message: "Failed to update status" });
  }
});
 
// ── Dashboard Stats ────────────────────────────────────────────────
app.get("/dashboard-stats", verifyToken, async (req, res) => {
  try {
    const db = await connectDB();
    const now = new Date();
    const month = now.getMonth() + 1;
    const year  = now.getFullYear();
    const monthStart = new Date(year, month - 1, 1);
    const monthEnd   = new Date(year, month, 1);

    const [
      gpUnitAgg, gpMonthCount, gpTotalCount,
      challanProductAgg, challanStatusAgg, challanTotalCount,
      deliveryProductAgg, tripMonthCount, tripTotalCount, activeTripCount,
      vendorCount, userCount,
      accountsTxs, carRentThisMonth,
      topDeliveryPoints,
    ] = await Promise.all([

      // Gate Pass: unit-wise total qty এই মাসে (unit = top-level field, e.g. "WFR")
      db.collection('gate-pass').aggregate([
        { $match: { tripMonth: month, tripYear: year } },
        { $unwind: '$products' },
        {
          $group: {
            _id: '$unit',
            qty: { $sum: '$products.quantity' },
            passCount: { $addToSet: '$_id' },
          }
        },
        { $addFields: { passCount: { $size: '$passCount' } } },
        { $sort: { qty: -1 } },
        { $limit: 10 },
      ]).toArray(),
      db.collection('gate-pass').countDocuments({ tripMonth: month, tripYear: year }),
      db.collection('gate-pass').countDocuments(),

      // Challan: productName-wise qty এই মাসে
      db.collection('challans').aggregate([
        { $match: { createdAt: { $gte: monthStart, $lt: monthEnd } } },
        { $unwind: '$products' },
        { $group: { _id: '$products.productName', qty: { $sum: '$products.quantity' } } },
        { $sort: { qty: -1 } },
        { $limit: 8 },
      ]).toArray(),
      // Challan status breakdown
      db.collection('challans').aggregate([
        { $match: { createdAt: { $gte: monthStart, $lt: monthEnd } } },
        { $group: { _id: '$status', count: { $sum: 1 } } },
      ]).toArray(),
      db.collection('challans').countDocuments(),

      // Delivery: productName-wise qty এই মাসে
      db.collection('deliveries').aggregate([
        { $match: { createdAt: { $gte: monthStart, $lt: monthEnd } } },
        { $unwind: '$challans' },
        { $unwind: '$challans.products' },
        { $group: { _id: '$challans.products.productName', qty: { $sum: '$challans.products.quantity' } } },
        { $sort: { qty: -1 } },
        { $limit: 8 },
      ]).toArray(),
      db.collection('deliveries').countDocuments({ createdAt: { $gte: monthStart, $lt: monthEnd } }),
      db.collection('deliveries').countDocuments(),
      db.collection('deliveries').countDocuments({
        $or: [{ status: { $exists: false } }, { status: { $in: ['pending', 'in_progress'] } }]
      }),

      db.collection('vendors').countDocuments(),
      db.collection('users').countDocuments(),

      // Accounts এই মাসের
      db.collection('accounts').find({ month, year }).toArray(),
      // Car rent এই মাসের (advance জন্য)
      db.collection('deliveries').find(
        { createdAt: { $gte: monthStart, $lt: monthEnd } },
        { projection: { advance: 1 } }
      ).toArray(),

      // Top delivery zones/points এই মাসে (challan zone-wise count)
      db.collection('challans').aggregate([
        { $match: { createdAt: { $gte: monthStart, $lt: monthEnd } } },
        { $group: { _id: '$zone', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 5 },
      ]).toArray(),
    ]);

    // Challan status map
    const csMap = {};
    challanStatusAgg.forEach(s => { csMap[s._id || 'pending'] = s.count; });

    // Accounts summary
    const n = (v) => (v != null ? Number(v) : 0);
    const income        = accountsTxs.filter(t => t.type === 'income').reduce((s,t) => s + n(t.amount), 0);
    const expense       = accountsTxs.filter(t => t.type === 'expense').reduce((s,t) => s + n(t.amount), 0);
    const vendorPayment = accountsTxs.filter(t => t.type === 'vendor_payment').reduce((s,t) => s + n(t.amount), 0);
    const manualAdv     = accountsTxs.filter(t => t.type === 'manual_advance').reduce((s,t) => s + n(t.amount), 0);
    const autoAdv       = carRentThisMonth.reduce((s,t) => s + n(t.advance), 0);
    const totalExpense  = expense + vendorPayment + manualAdv + autoAdv;
    const netBalance    = income - totalExpense;

    res.send({
      success: true,
      data: {
        currentMonth: month,
        currentYear:  year,
        gatePass: {
          totalCount:    gpTotalCount,
          monthCount:    gpMonthCount,
          unitBreakdown: gpUnitAgg,   // [{ _id: 'WFR', qty: 230, passCount: 5 }, ...]
        },
        challan: {
          totalCount:       challanTotalCount,
          monthTotal:       challanStatusAgg.reduce((s,x) => s + x.count, 0),
          delivered:        csMap['delivered'] || 0,
          pending:          csMap['pending']   || 0,
          returned:         csMap['returned']  || 0,
          productBreakdown: challanProductAgg,
        },
        trip: {
          totalCount:       tripTotalCount,
          monthCount:       tripMonthCount,
          activeCount:      activeTripCount,
          productBreakdown: deliveryProductAgg,
        },
        vendor: { totalCount: vendorCount },
        user:   { totalCount: userCount },
        accounts: { income, totalExpense, netBalance, vendorPayment, autoAdv, manualAdv },
        topDeliveryPoints,
      }
    });
  } catch (err) {
    logger.error("Dashboard stats failed", err);
    res.status(500).send({ message: "Failed to fetch stats" });
  }
});
 
 
// ── Global Error Handler ───────────────────────────────────────────
app.use((err, req, res, next) => {
  logger.error("Unhandled error", err);
  res.status(500).send({ message: "Internal Server Error" });
});
 
// ── Start Server ───────────────────────────────────────────────────
if (process.env.NODE_ENV !== "production") {
  app.listen(port, () => {
    logger.info(`Server running`, { port });
  });
}
 
module.exports = app;