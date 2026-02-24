require ("dotenv").config();
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');


const app = express();
const port = process.env.PORT || 3000;

// middleware//
app.use(cors());
app.use(express.json());

//mondoDB Uri// 
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.fu1n5ti.mongodb.net/myDB?retryWrites=true&w=majority`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

app.get('/', (req, res) => {
  res.send('LBTS-OS Server is running');
});

async function run() {
  try {
    await client.connect();

    const db= client.db('LBTS-OS-DB')
    const userCollection = db.collection('users')
    const gatePassCollection = db.collection('gate-pass')
//.........................All API................................//


//  Add user//
    app.post('/users', async (req,res)=>{
        const user = req.body;
        user.role= 'user';
        user.status= 'pending'
        const result = await userCollection.insertOne(user)
        res.send(result)
    })

    //Get all users//
app.get('/users', async (req, res) => {
  const result = await userCollection.find().toArray();
  res.send(result);
});


    // Get role & status of single user
    app.get('/users/:email/role', async (req,res)=>{
      const email = req.params.email;
      try {
        const user = await userCollection.findOne({ email });
        if(!user) return res.status(404).send({ message: 'User not found' });
        res.send({ role: user.role, status: user.status });
      } catch(err) {
        console.error(err);
        res.status(500).send({ message: 'Failed to fetch user role' });
      }
    });

//role update//
app.patch('/users/role/:id', async (req, res) => {
  const id = req.params.id;
  const { role } = req.body;

  const result = await userCollection.updateOne(
    { _id: new ObjectId(id) },
    { $set: { role } }
  );

  res.send(result);
});


//status update api//
app.patch('/users/status/:id', async (req, res) => {
  const id = req.params.id;
  const { status } = req.body;

  const result = await userCollection.updateOne(
    { _id: new ObjectId(id) },
    { $set: { status } }
  );

  res.send(result);
});


// Delete user by ID
app.delete('/users/:id', async (req, res) => {
  try {
    const id = req.params.id;

    // MongoDB ObjectId import করা লাগবে
    const result = await userCollection.deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 1) {
      res.send({ success: true, message: 'User deleted successfully' });
    } else {
      res.status(404).send({ success: false, message: 'User not found' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).send({ success: false, message: 'Failed to delete user' });
  }
});

//add gate pass//
app.post('/gate-pass', async (req, res) => {
  try {
    const gatePass = req.body;

    // ⭐ products এ unique _id add
    if (gatePass.products && Array.isArray(gatePass.products)) {
      gatePass.products = gatePass.products.map(p => ({
        _id: new ObjectId().toString(),   // string id (React friendly)
        productName: p.productName,
        model: p.model,
        quantity: Number(p.quantity)
      }));
    }

    // ⭐ extra fields auto set (optional but recommended)
    gatePass.createdAt = new Date();
    gatePass.tripMonth = new Date(gatePass.tripDate).getMonth() + 1;
    gatePass.tripYear = new Date(gatePass.tripDate).getFullYear();

    const result = await gatePassCollection.insertOne(gatePass);
    res.send(result);

  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Failed to add gate pass' });
  }
});

// GET /gate-pass//
app.get("/gate-pass", async (req, res) => {
  try {
    let month = parseInt(req.query.month);
    let year = parseInt(req.query.year);
    const search = req.query.search || "";

    let query = {};

    // 🔎 search থাকলে full DB search
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
    } 
    
    // 📅 search না থাকলে month filter
    else {
      if (!month || !year) {
        const now = new Date();
        month = now.getMonth() + 1;
        year = now.getFullYear();
      }

      query.tripMonth = month;
      query.tripYear = year;
    }

    const data = await gatePassCollection
      .find(query)
      .sort({ createdAt: -1 })
      .toArray();

    res.send({ data });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch gate passes" });
  }
});

// Update a gate pass//
app.patch('/gate-pass/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const { tripDo, tripDate, customerName, csd, vehicleNo, zone } = req.body;

    const updateDoc = {
      $set: {
        tripDo,
        tripDate,
        customerName,
        csd,
        vehicleNo,
        zone,
        tripMonth: new Date(tripDate).getMonth() + 1,
        tripYear: new Date(tripDate).getFullYear()
      }
    };

    const result = await gatePassCollection.updateOne(
      { _id: new ObjectId(id) },
      updateDoc
    );

    const updatedGatePass = await gatePassCollection.findOne({ _id: new ObjectId(id) });

    res.send({ success: true, data: updatedGatePass });

  } catch (err) {
    console.error(err);
    res.status(500).send({ success: false, message: "Failed to update gate pass" });
  }
});

// Update a gate pass Single Proguct//
app.put('/gate-pass/:gatePassId/product/:productId', async (req, res) => {
  try {
    const { gatePassId, productId } = req.params;
    const { productName, model, quantity } = req.body;

    const result = await gatePassCollection.updateOne(
      {
        _id: new ObjectId(gatePassId),
        "products._id": productId   // ⚡ match specific product
      },
      {
        $set: {
          "products.$.productName": productName,
          "products.$.model": model,
          "products.$.quantity": Number(quantity)
        }
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ success: false, message: "Product not found" });
    }

    const updatedGatePass = await gatePassCollection.findOne({ _id: new ObjectId(gatePassId) });

    res.send({ success: true, data: updatedGatePass });

  } catch (err) {
    console.error(err);
    res.status(500).send({ success: false, message: "Failed to update product" });
  }
});

// Delete a gate pass by ID
app.delete('/gate-pass/:id', async (req, res) => {
  try {
    const id = req.params.id;

    const result = await gatePassCollection.deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res.status(404).send({ success: false, message: "Gate Pass not found" });
    }

    res.send({ success: true, message: "Gate Pass deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).send({ success: false, message: "Failed to delete gate pass" });
  }
});


// 🔍 Generic autocomplete Search character from gate-pass collection API
app.get("/autocomplete", async (req, res) => {
  try {
    const { field, search } = req.query;

    let pipeline = [];

    // ⭐ product & model nested field
    if (field === "productName" || field === "model") {
      pipeline = [
        { $unwind: "$products" },
        {
          $match: {
            [`products.${field}`]: { $regex: search || "", $options: "i" }
          }
        },
        {
          $group: {
            _id: `$products.${field}`
          }
        },
        {
          $project: {
            _id: 0,
            value: "$_id"
          }
        },
        { $limit: 5 }
      ];
    }

    // ⭐ normal field
    else {
      pipeline = [
        {
          $match: {
            [field]: { $regex: search || "", $options: "i" }
          }
        },
        {
          $group: {
            _id: `$${field}`
          }
        },
        {
          $project: {
            _id: 0,
            value: "$_id"
          }
        },
        { $limit: 5 }
      ];
    }

    const result = await gatePassCollection.aggregate(pipeline).toArray();
    res.send(result);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Autocomplete failed" });
  }
});

    console.log("✅ MongoDB connected successfully");
  } catch (err) {
    console.error("MongoDB connection failed:", err);
  }
}

run();

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
