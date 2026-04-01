require("dotenv").config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

// ── Environment Variable Validation ───────────────────────────────────────────
const requiredEnvVars = ['DB_USER', 'DB_PASS', 'ALLOWED_ORIGINS'];
const missingVars = requiredEnvVars.filter(v => !process.env[v]);
if (missingVars.length > 0) {
  console.error(`❌ Missing required environment variables: ${missingVars.join(', ')}`);
  process.exit(1);
}

const app = express();
const port = process.env.PORT || 3000;

// ── Security Middleware ────────────────────────────────────────────────────────
app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});
app.use(limiter);

// ── CORS ───────────────────────────────────────────────────────────────────────
const allowedOrigins = process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim());

app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ── Helpers ────────────────────────────────────────────────────────────────────
const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const isValidObjectId = (id) => {
  try {
    return ObjectId.isValid(id) && new ObjectId(id).toString() === id;
  } catch {
    return false;
  }
};

// ── MongoDB (Vercel-safe singleton) ────────────────────────────────────────────
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.fu1n5ti.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

let client;
let db;

function getClient() {
  if (!client) {
    client = new MongoClient(uri, {
      serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
      },
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
  }
  return client;
}

async function connectDB() {
  if (db) return db;
  const c = getClient();
  await c.connect();
  db = c.db('LBTS-OS-DB');
  console.log("✅ MongoDB Connected");
  return db;
}

// ── Health Check ───────────────────────────────────────────────────────────────

app.get('/', (req, res) => {
  res.send({ status: 'ok', message: 'LBTS-OS Server is running ✅' });
});

// ── Users ──────────────────────────────────────────────────────────────────────

app.post('/users', async (req, res) => {
  try {
    const db = await connectDB();
    const userCollection = db.collection('users');

    const user = req.body;
    if (!user.email || !user.name) {
      return res.status(400).send({ message: 'Email and name are required' });
    }

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

app.get('/users', async (req, res) => {
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

app.get('/users/:email/role', async (req, res) => {
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

app.patch('/users/role/:id', async (req, res) => {
  try {
    const db = await connectDB();
    const userCollection = db.collection('users');
    const { role } = req.body;

    const allowedRoles = ['user', 'operator', 'manager', 'admin'];
    if (!role || !allowedRoles.includes(role)) {
      return res.status(400).send({ message: 'Invalid role value' });
    }

    if (!isValidObjectId(req.params.id)) {
      return res.status(400).send({ message: 'Invalid user ID' });
    }

    const result = await userCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { role } }
    );
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: 'Failed to update role' });
  }
});

app.patch('/users/status/:id', async (req, res) => {
  try {
    const db = await connectDB();
    const userCollection = db.collection('users');
    const { status } = req.body;

    const allowedStatuses = ['pending', 'approved', 'rejected'];
    if (!status || !allowedStatuses.includes(status)) {
      return res.status(400).send({ message: 'Invalid status value' });
    }

    if (!isValidObjectId(req.params.id)) {
      return res.status(400).send({ message: 'Invalid user ID' });
    }

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

app.delete('/users/:id', async (req, res) => {
  try {
    const db = await connectDB();
    const userCollection = db.collection('users');

    if (!isValidObjectId(req.params.id)) {
      return res.status(400).send({ message: 'Invalid user ID' });
    }

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

app.post('/gate-pass', async (req, res) => {
  try {
    const db = await connectDB();
    const gatePassCollection = db.collection('gate-pass');
    const gatePass = req.body;

    if (!gatePass.tripDo || !gatePass.tripDate) {
      return res.status(400).send({ message: 'tripDo and tripDate are required' });
    }

    if (gatePass.products && Array.isArray(gatePass.products)) {
      if (gatePass.products.length > 100) {
        return res.status(400).send({ message: 'Too many products (max 100)' });
      }
      gatePass.products = gatePass.products.map(p => ({
        _id: new ObjectId().toString(),
        productName: String(p.productName || '').slice(0, 200),
        model: String(p.model || '').slice(0, 200),
        quantity: Math.max(0, Number(p.quantity) || 0)
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

app.get("/gate-pass", async (req, res) => {
  try {
    const db = await connectDB();
    const gatePassCollection = db.collection('gate-pass');

    let month = parseInt(req.query.month);
    let year = parseInt(req.query.year);
    const search = escapeRegex((req.query.search || "").trim().slice(0, 100));
    let query = {};

    if (search) {
      query.$or = [
        { tripDo: { $regex: search, $options: "i" } },
        { customerName: { $regex: search, $options: "i" } },
        { csd: { $regex: search, $options: "i" } },
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

    const data = await gatePassCollection.find(query).sort({ createdAt: -1 }).toArray();
    res.send({ data });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch gate passes" });
  }
});

app.patch('/gate-pass/:id', async (req, res) => {
  try {
    const db = await connectDB();
    const gatePassCollection = db.collection('gate-pass');

    if (!isValidObjectId(req.params.id)) {
      return res.status(400).send({ message: 'Invalid ID' });
    }

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

app.put('/gate-pass/:gatePassId/product/:productId', async (req, res) => {
  try {
    const db = await connectDB();
    const gatePassCollection = db.collection('gate-pass');
    const { gatePassId, productId } = req.params;
    const { productName, model, quantity } = req.body;

    if (!isValidObjectId(gatePassId)) {
      return res.status(400).send({ message: 'Invalid gate pass ID' });
    }

    const result = await gatePassCollection.updateOne(
      { _id: new ObjectId(gatePassId), "products._id": productId },
      {
        $set: {
          "products.$.productName": String(productName || '').slice(0, 200),
          "products.$.model": String(model || '').slice(0, 200),
          "products.$.quantity": Math.max(0, Number(quantity) || 0)
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

app.delete('/gate-pass/:id', async (req, res) => {
  try {
    const db = await connectDB();
    const gatePassCollection = db.collection('gate-pass');

    if (!isValidObjectId(req.params.id)) {
      return res.status(400).send({ message: 'Invalid ID' });
    }

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

app.get("/autocomplete", async (req, res) => {
  try {
    const db = await connectDB();
    const gatePassCollection = db.collection('gate-pass');
    const challanCollection = db.collection('challans');

    const { field, collection } = req.query;
    const search = escapeRegex((req.query.search || "").slice(0, 100));
    const targetCollection = collection === "challan" ? challanCollection : gatePassCollection;

    if (!field) {
      return res.status(400).send({ message: 'field is required' });
    }

    let pipeline = [];

    if (field === "productName" || field === "model") {
      pipeline = [
        { $unwind: "$products" },
        { $match: { [`products.${field}`]: { $regex: search, $options: "i" } } },
        { $group: { _id: `$products.${field}` } },
        { $project: { _id: 0, value: "$_id" } },
        { $limit: 5 },
      ];
    } else {
      pipeline = [
        { $match: { [field]: { $regex: search, $options: "i" } } },
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

app.post("/challan", async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');
    const challan = req.body;

    if (!challan.customerName) {
      return res.status(400).send({ message: 'customerName is required' });
    }

    if (challan.products && Array.isArray(challan.products)) {
      if (challan.products.length > 100) {
        return res.status(400).send({ message: 'Too many products (max 100)' });
      }
      challan.products = challan.products.map(p => ({
        _id: new ObjectId().toString(),
        productName: String(p.productName || '').slice(0, 200),
        model: String(p.model || '').slice(0, 200),
        quantity: Math.max(0, Number(p.quantity) || 0)
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

app.get("/challan/recent", async (req, res) => {
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

app.get("/challans", async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');

    let month = parseInt(req.query.month);
    let year = parseInt(req.query.year);
    const search = escapeRegex((req.query.search || "").trim().slice(0, 100));
    let query = {};

    if (search) {
      query.$or = [
        { customerName: { $regex: search, $options: "i" } },
        { address: { $regex: search, $options: "i" } },
        { receiverNumber: { $regex: search, $options: "i" } },
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
      const startDate = new Date(year, month - 1, 1);
      const endDate = new Date(year, month, 0, 23, 59, 59);
      query.createdAt = { $gte: startDate, $lte: endDate };
    }

    const data = await challanCollection.find(query).sort({ createdAt: -1 }).toArray();
    res.send({ data });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch challans" });
  }
});

app.delete("/challan/:id", async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');

    if (!isValidObjectId(req.params.id)) {
      return res.status(400).send({ message: 'Invalid ID' });
    }

    const result = await challanCollection.deleteOne({ _id: new ObjectId(req.params.id) });
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to delete challan" });
  }
});

app.patch('/challan/:id', async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');

    if (!isValidObjectId(req.params.id)) {
      return res.status(400).send({ message: 'Invalid ID' });
    }

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

app.put('/challan/:challanId/product/:productId', async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');
    const { challanId, productId } = req.params;
    const { productName, model, quantity } = req.body;

    if (!isValidObjectId(challanId)) {
      return res.status(400).send({ message: 'Invalid challan ID' });
    }

    const result = await challanCollection.updateOne(
      { _id: new ObjectId(challanId), "products._id": productId },
      {
        $set: {
          "products.$.productName": String(productName || '').slice(0, 200),
          "products.$.model": String(model || '').slice(0, 200),
          "products.$.quantity": Math.max(0, Number(quantity) || 0)
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

app.delete("/challans/:challanId/product/:productId", async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');
    const { challanId, productId } = req.params;

    if (!isValidObjectId(challanId)) {
      return res.status(400).send({ message: 'Invalid challan ID' });
    }

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

app.patch('/challans/:id', async (req, res) => {
  try {
    const db = await connectDB();
    const challanCollection = db.collection('challans');

    if (!isValidObjectId(req.params.id)) {
      return res.status(400).send({ message: 'Invalid ID' });
    }

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

app.post("/vendors", async (req, res) => {
  try {
    const db = await connectDB();
    const vendorsCollection = db.collection('vendors');
    const { vendorName, vendorImg, vendorAddress, vendorPhone } = req.body;

    if (!vendorName) {
      return res.status(400).send({ message: 'vendorName is required' });
    }

    const result = await vendorsCollection.insertOne({
      vendorName: String(vendorName).slice(0, 200),
      vendorImg: vendorImg || '',
      vendorAddress: String(vendorAddress || '').slice(0, 500),
      vendorPhone: String(vendorPhone || '').slice(0, 20),
      vehicles: [],
      createdAt: new Date(),
    });
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to add vendor" });
  }
});

app.get("/vendors", async (req, res) => {
  try {
    const db = await connectDB();
    const vendorsCollection = db.collection('vendors');
    const result = await vendorsCollection.find().toArray();
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch vendors" });
  }
});

app.get("/vendors/:id", async (req, res) => {
  try {
    const db = await connectDB();
    const vendorsCollection = db.collection('vendors');

    if (!isValidObjectId(req.params.id)) {
      return res.status(400).send({ message: 'Invalid vendor ID' });
    }

    const vendor = await vendorsCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!vendor) return res.status(404).send({ message: 'Vendor not found' });
    res.send(vendor);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch vendor" });
  }
});

app.patch("/vendors/:id", async (req, res) => {
  try {
    const db = await connectDB();
    const vendorsCollection = db.collection('vendors');

    if (!isValidObjectId(req.params.id)) {
      return res.status(400).send({ message: 'Invalid vendor ID' });
    }

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

app.delete("/vendors/:id", async (req, res) => {
  try {
    const db = await connectDB();
    const vendorsCollection = db.collection('vendors');

    if (!isValidObjectId(req.params.id)) {
      return res.status(400).send({ message: 'Invalid vendor ID' });
    }

    const result = await vendorsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to delete vendor" });
  }
});

// ── Vehicles ───────────────────────────────────────────────────────────────────

// ✅ /vehicles/search — MUST be BEFORE /vehicles/:vendorId/:vehicleId
app.get("/vehicles/search", async (req, res) => {
  try {
    const db = await connectDB();
    const vendorsCollection = db.collection('vendors');
    const rawSearch = req.query.search?.trim();
    if (!rawSearch) return res.send([]);

    const search = escapeRegex(rawSearch.slice(0, 50));

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

app.post("/vehicles", async (req, res) => {
  try {
    const db = await connectDB();
    const vendorsCollection = db.collection('vendors');
    const { vendorId, ...vehicleData } = req.body;

    if (!isValidObjectId(vendorId)) {
      return res.status(400).send({ message: 'Invalid vendor ID' });
    }

    const result = await vendorsCollection.updateOne(
      { _id: new ObjectId(vendorId) },
      {
        $push: {
          vehicles: { _id: new ObjectId(), ...vehicleData, createdAt: new Date() }
        }
      }
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

app.delete("/vehicles/:vendorId/:vehicleId", async (req, res) => {
  try {
    const db = await connectDB();
    const vendorsCollection = db.collection('vendors');
    const { vendorId, vehicleId } = req.params;

    if (!isValidObjectId(vendorId) || !isValidObjectId(vehicleId)) {
      return res.status(400).send({ message: 'Invalid ID' });
    }

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
});

app.put("/vehicles/:vendorId/:vehicleId", async (req, res) => {
  try {
    const db = await connectDB();
    const vendorsCollection = db.collection('vendors');
    const { vendorId, vehicleId } = req.params;
    const updatedData = req.body;

    if (!isValidObjectId(vendorId) || !isValidObjectId(vehicleId)) {
      return res.status(400).send({ message: 'Invalid ID' });
    }

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
});

// ── Deliveries ─────────────────────────────────────────────────────────────────

app.post("/deliveries", async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const challanCollection = db.collection('challans');
    const counterCollection = db.collection('counters');

    const deliveries = req.body;

    if (!Array.isArray(deliveries) || deliveries.length === 0) {
      return res.status(400).send({ success: false, message: "No deliveries provided" });
    }

    if (deliveries.length > 200) {
      return res.status(400).send({ success: false, message: "Too many deliveries (max 200)" });
    }

    const counter = await counterCollection.findOneAndUpdate(
      { _id: "tripNumber" },
      { $inc: { seq: 1 } },
      { upsert: true, returnDocument: "after" }
    );

    const seq = counter?.seq ?? counter?.value?.seq ?? 1;
    const tripNumber = `TR-${seq.toString().padStart(6, "0")}`;

    const challanIds = deliveries.map(d =>
      typeof d.challanId === "string" ? new ObjectId(d.challanId) : d.challanId
    );

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
        products: d.products
      })),
      createdAt: new Date()
    };

    const result = await deliveriesCollection.insertOne(tripDocument);

    const updateResult = await challanCollection.updateMany(
      { _id: { $in: challanIds } },
      { $set: { status: "delivered", tripNumber } }
    );

    res.send({
      success: true,
      insertedId: result.insertedId,
      updatedCount: updateResult.modifiedCount,
      tripNumber,
      totalChallan: deliveries.length
    });
  } catch (err) {
    console.error("Delivery Error:", err);
    res.status(500).send({ success: false, message: "Delivery failed", error: err.message });
  }
});

app.get("/deliveries", async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const deliveries = await deliveriesCollection.find().sort({ createdAt: -1 }).toArray();
    res.send({ success: true, data: deliveries });
  } catch (err) {
    console.error(err);
    res.status(500).send({ success: false, message: "Failed to fetch deliveries" });
  }
});

app.patch("/deliveries/confirm", async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripNumber, challanId, status, note, operator } = req.body;

    if (!tripNumber || !challanId || !status) {
      return res.status(400).send({ message: 'tripNumber, challanId, and status are required' });
    }

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

app.patch("/deliveries/challan-return", async (req, res) => {
  try {
    const db = await connectDB();
    const deliveriesCollection = db.collection('deliveries');
    const { tripNumber, challanId, status, operator } = req.body;

    if (!tripNumber || !challanId || !status) {
      return res.status(400).send({ message: 'tripNumber, challanId, and status are required' });
    }

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

// ── Global Error Handler ───────────────────────────────────────────────────────

app.use((err, req, res, next) => {
  console.error("💥 Unhandled Error:", err.message);
  res.status(500).send({ message: "Internal Server Error" });
});

// ── Start Server ───────────────────────────────────────────────────────────────

if (process.env.NODE_ENV !== "production") {
  app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);
  });
}

module.exports = app;
