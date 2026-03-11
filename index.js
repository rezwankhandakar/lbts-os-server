require("dotenv").config();
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

    const db = client.db('LBTS-OS-DB')
    const userCollection = db.collection('users')
    const gatePassCollection = db.collection('gate-pass')
    const challanCollection = db.collection('challans')
    const vendorsCollection = db.collection('vendors')
    const deliveriesCollection = db.collection('deliveries')
    const counterCollection = db.collection('counters');
    //.........................All API................................//


    //  Add user//
    app.post('/users', async (req, res) => {
      const user = req.body;
      user.role = 'user';
      user.status = 'pending'
      const result = await userCollection.insertOne(user)
      res.send(result)
    })

    //Get all users//
    app.get('/users', async (req, res) => {
      const result = await userCollection.find().toArray();
      res.send(result);
    });


    // Get role & status of single user
    app.get('/users/:email/role', async (req, res) => {
      const email = req.params.email;
      try {
        const user = await userCollection.findOne({ email });
        if (!user) return res.status(404).send({ message: 'User not found' });
        res.send({ role: user.role, status: user.status });
      } catch (err) {
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

    //Gate Related API//

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
        const { tripDo, tripDate, customerName, csd, unit, vehicleNo, zone, currentUser } = req.body;

        const updateDoc = {
          $set: {
            tripDo,
            tripDate,
            customerName,
            csd,
            unit,
            vehicleNo,
            zone,
            currentUser,
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
        const { field, search, collection } = req.query;

        // ⭐ collection select
        let targetCollection;

        if (collection === "challan") {
          targetCollection = challanCollection;
        } else {
          targetCollection = gatePassCollection; // default
        }

        let pipeline = [];

        // nested product/model
        if (field === "productName" || field === "model") {
          pipeline = [
            { $unwind: "$products" },
            {
              $match: {
                [`products.${field}`]: {
                  $regex: search || "",
                  $options: "i",
                },
              },
            },
            {
              $group: {
                _id: `$products.${field}`,
              },
            },
            {
              $project: {
                _id: 0,
                value: "$_id",
              },
            },
            { $limit: 5 },
          ];
        } else {
          pipeline = [
            {
              $match: {
                [field]: { $regex: search || "", $options: "i" },
              },
            },
            {
              $group: { _id: `$${field}` },
            },
            {
              $project: {
                _id: 0,
                value: "$_id",
              },
            },
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


    //Challan Related API//
    app.post("/challan", async (req, res) => {
      try {
        const challan = req.body;

        // ✅ products এ string _id add
        if (challan.products && Array.isArray(challan.products)) {
          challan.products = challan.products.map(p => ({
            _id: new ObjectId().toString(),   // string id (React friendly)
            productName: p.productName,
            model: p.model,
            quantity: Number(p.quantity)
          }));
        }

        challan.createdAt = new Date();

        const result = await challanCollection.insertOne(challan);
        res.send(result);

      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Failed to add challan" });
      }
    });


    app.get("/challan/recent", async (req, res) => {
      const result = await challanCollection
        .find()
        .sort({ createdAt: -1 })
        .limit(1)
        .toArray();

      res.send({ data: result });
    });


    // GET /challans logic (Add this to your server.js)
    app.get("/challans", async (req, res) => {
      try {
        let month = parseInt(req.query.month);
        let year = parseInt(req.query.year);
        const search = req.query.search || "";

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

          // createdAt date query (Month and Year extract korte aggregation use kora better)
          const startDate = new Date(year, month - 1, 1);
          const endDate = new Date(year, month, 0, 23, 59, 59);
          query.createdAt = { $gte: startDate, $lte: endDate };
        }

        const data = await challanCollection
          .find(query)
          .sort({ createdAt: -1 })
          .toArray();

        res.send({ data });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Failed to fetch challans" });
      }
    });


    app.delete("/challan/:id", async (req, res) => {
      const id = req.params.id;
      const result = await challanCollection.deleteOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });


    // Update a Challan (Main Details)
    app.patch('/challan/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const { customerName, address, thana, district, receiverNumber, zone, currentUser, createdAt } = req.body;

        const updateDoc = {
          $set: {
            customerName,
            address,
            thana,
            district,
            receiverNumber,
            zone,
            currentUser,
            // Optional: Update month/year if date is changed
            month: createdAt ? new Date(createdAt).getMonth() + 1 : undefined,
            year: createdAt ? new Date(createdAt).getFullYear() : undefined
          }
        };

        // Undefined fields remove kora (jodi value na thake)
        Object.keys(updateDoc.$set).forEach(key => updateDoc.$set[key] === undefined && delete updateDoc.$set[key]);

        const result = await challanCollection.updateOne(
          { _id: new ObjectId(id) },
          updateDoc
        );

        const updatedChallan = await challanCollection.findOne({ _id: new ObjectId(id) });
        res.send({ success: true, data: updatedChallan });

      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false, message: "Failed to update challan" });
      }
    });


    // Update a Challan Single Product
    app.put('/challan/:challanId/product/:productId', async (req, res) => {
      try {
        const { challanId, productId } = req.params;
        const { productName, model, quantity } = req.body;

        const result = await challanCollection.updateOne(
          {
            _id: new ObjectId(challanId),
            "products._id": productId   // ✅ string match (Gate Pass style)
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

        const updatedChallan = await challanCollection.findOne({
          _id: new ObjectId(challanId)
        });

        res.send({ success: true, data: updatedChallan });

      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false, message: "Failed to update product" });
      }
    });


    app.delete("/challans/:challanId/product/:productId", async (req, res) => {
      try {
        const { challanId, productId } = req.params;

        const result = await challanCollection.updateOne(
          { _id: new ObjectId(challanId) },
          { $pull: { products: { _id: productId } } } // প্রোডাক্ট এর string _id দিয়ে রিমুভ করবে
        );

        if (result.modifiedCount > 0) {
          res.send({ success: true, message: "Product removed from challan" });
        } else {
          res.status(404).send({ success: false, message: "Product not found" });
        }
      } catch (error) {
        console.error(error);
        res.status(500).send({ success: false, message: "Failed to delete product" });
      }
    });

    app.patch('/challans/:id', async (req, res) => {
      try {
        const id = req.params.id;
        // বডি থেকে products অ্যারে সহ সব ডাটা রিসিভ করুন
        const {
          customerName,
          receiverNumber,
          zone,
          address,
          thana,
          district,
          products // এইটা যোগ করা হয়েছে
        } = req.body;

        const updateDoc = {
          $set: {
            customerName,
            receiverNumber,
            zone,
            address,
            thana,
            district,
            products // ডাটাবেসে প্রোডাক্ট অ্যারে আপডেট করার জন্য এইটা জরুরি
          }
        };

        const result = await challanCollection.updateOne(
          { _id: new ObjectId(id) },
          updateDoc
        );

        if (result.matchedCount > 0) {
          res.send({ success: true, message: "Challan and Products updated successfully" });
        } else {
          res.status(404).send({ success: false, message: "Challan not found" });
        }
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false, message: "Update failed" });
      }
    });

    //vendor and driver related api//

    app.post("/vendors", async (req, res) => {
      const vendor = req.body;

      const result = await vendorsCollection.insertOne({
        ...vendor,
        vehicles: [],
        createdAt: new Date(),
      });

      res.send(result);
    });

    app.get("/vendors", async (req, res) => {
      const result = await vendorsCollection.find().toArray();
      res.send(result);
    });

    app.patch("/vendors/:id", async (req, res) => {
      const id = req.params.id;
      const updatedVendor = req.body;

      const updateDoc = {
        $set: {
          vendorName: updatedVendor.vendorName,
          vendorImg: updatedVendor.vendorImg,
          vendorAddress: updatedVendor.vendorAddress,
          vendorPhone: updatedVendor.vendorPhone,
        },
      };

      const result = await vendorsCollection.updateOne(
        { _id: new ObjectId(id) },
        updateDoc
      );

      res.send(result);
    });

    app.delete("/vendors/:id", async (req, res) => {
      const id = req.params.id;

      const result = await vendorsCollection.deleteOne({
        _id: new ObjectId(id),
      });

      res.send(result);
    });

    app.get("/vendors/:id", async (req, res) => {

      const id = req.params.id;

      const vendor = await vendorsCollection.findOne({
        _id: new ObjectId(id),
      });

      res.send(vendor);
    });


    // Vehicles-er jonno alada collection lagbe na
    app.post("/vehicles", async (req, res) => {
      const { vendorId, ...vehicleData } = req.body;

      try {
        const query = { _id: new ObjectId(vendorId) };

        // Vendor-er vehicles array-te push kora
        const updateDoc = {
          $push: {
            vehicles: {
              _id: new ObjectId(), // Prti vehicle-er jonno ekti unique ID create kora
              ...vehicleData,
              createdAt: new Date()
            }
          }
        };

        const result = await vendorsCollection.updateOne(query, updateDoc);

        if (result.modifiedCount > 0) {
          res.send({ insertedId: true }); // Frontend-er logic thik rakhar jonno
        } else {
          res.status(404).send({ error: "Vendor not found" });
        }
      } catch (error) {
        res.status(500).send({ error: "Failed to add vehicle" });
      }
    });


    // DELETE: Remove a vehicle from the vendor's array
    app.delete("/vehicles/:vendorId/:vehicleId", async (req, res) => {
      const { vendorId, vehicleId } = req.params;

      try {
        const query = { _id: new ObjectId(vendorId) };
        const updateDoc = {
          $pull: {
            vehicles: { _id: new ObjectId(vehicleId) } // Array theke specific ID remove kora
          }
        };

        const result = await vendorsCollection.updateOne(query, updateDoc);

        if (result.modifiedCount > 0) {
          res.send({ deletedCount: 1 });
        } else {
          res.status(404).send({ error: "Vehicle or Vendor not found" });
        }
      } catch (error) {
        res.status(500).send({ error: "Failed to delete vehicle" });
      }
    });


    // PUT: Update a specific vehicle inside the vendor's array
    app.put("/vehicles/:vendorId/:vehicleId", async (req, res) => {
      const { vendorId, vehicleId } = req.params;
      const updatedData = req.body;

      try {
        const query = { _id: new ObjectId(vendorId) };

        // Proti-ti field-ke array-r bhetore update korar jonno set kora
        const updateDoc = {
          $set: {
            "vehicles.$[elem].vehicleNumber": updatedData.vehicleNumber,
            "vehicles.$[elem].vehicleModel": updatedData.vehicleModel,
            "vehicles.$[elem].driverName": updatedData.driverName,
            "vehicles.$[elem].driverPhone": updatedData.driverPhone,
          }
        };

        const options = {
          arrayFilters: [{ "elem._id": new ObjectId(vehicleId) }]
        };

        const result = await vendorsCollection.updateOne(query, updateDoc, options);

        if (result.modifiedCount > 0) {
          res.send({ modifiedCount: 1 });
        } else {
          res.status(404).send({ error: "Nothing updated" });
        }
      } catch (error) {
        res.status(500).send({ error: "Failed to update vehicle" });
      }
    });


    //delivery related api//
// app.get("/vehicles/search", async (req, res) => {

//   const search = req.query.search;

//   if (!search) return res.send([]);

//   const result = await vendorsCollection.aggregate([
//     { $unwind: "$vehicles" },
//     {
//       $match: {
//         "vehicles.vehicleNumber": {
//           $regex: search,
//           $options: "i"
//         }
//       }
//     },
//     {
//       $project: {
//         vendorName: 1,
//         vendorPhone: 1,
//         vehicleNumber: "$vehicles.vehicleNumber",
//         driverName: "$vehicles.driverName",
//         driverPhone: "$vehicles.driverPhone"
//       }
//     }
//   ]).toArray();

//   res.send(result);
// });

app.get("/vehicles/search", async (req, res) => {
  try {
    const search = req.query.search?.trim();

    if (!search) {
      return res.send([]);
    }

    const result = await vendorsCollection.aggregate([
      { $unwind: "$vehicles" },

      {
        $match: {
          "vehicles.vehicleNumber": {
            $regex: search,
            $options: "i",
          },
        },
      },

      {
        $project: {
          _id: 0,
          vendorName: 1,
          vendorPhone: 1,
          vehicleNumber: "$vehicles.vehicleNumber",
          driverName: "$vehicles.driverName",
          driverPhone: "$vehicles.driverPhone",
        },
      },

      { $limit: 10 } // suggestion limit
    ]).toArray();

    res.send(result);
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: "Server Error" });
  }
});


// app.post("/deliveries", async (req, res) => {
//   try {
//     const deliveries = req.body;

//     // ১️⃣ Delivery collection এ save
//     const result = await deliveriesCollection.insertMany(deliveries);

//     // ২️⃣ Challan IDs বের করা
//     const challanIds = deliveries.map(d =>
//       typeof d.challanId === "string" ? new ObjectId(d.challanId) : d.challanId
//     );

//     console.log("Challan IDs to update:", challanIds); // debug

//     // ৩️⃣ Challan status update করা
//     const updateResult = await challanCollection.updateMany(
//       { _id: { $in: challanIds } },
//       { $set: { status: "delivered" } }
//     );

//     console.log("Challan update result:", updateResult); // debug

//     // ৪️⃣ Response পাঠানো
//     res.send({ insertedCount: result.insertedCount, updatedCount: updateResult.modifiedCount });

//   } catch (error) {
//     console.error("Delivery Error:", error);
//     res.status(500).send({ success: false, message: "Delivery failed", error: error.message });
//   }
// });


// GET all deliveries

// app.post("/deliveries", async (req, res) => {
//   try {
//     const deliveries = req.body;

//     // Insert deliveries
//     const result = await deliveriesCollection.insertMany(deliveries);

//     // Update challan status
//     const challanIds = deliveries.map(d =>
//       typeof d.challanId === "string" ? new ObjectId(d.challanId) : d.challanId
//     );

//     const updateResult = await challanCollection.updateMany(
//       { _id: { $in: challanIds } },
//       { $set: { status: "delivered" } }
//     );

//     res.send({
//       insertedCount: result.insertedCount,
//       updatedCount: updateResult.modifiedCount,
//       tripNumber: deliveries[0].tripNumber // return trip number for frontend
//     });

//   } catch (error) {
//     console.error("Delivery Error:", error);
//     res.status(500).send({ success: false, message: "Delivery failed", error: error.message });
//   }
// });


// app.post("/deliveries", async (req, res) => {
//   try {
//     const deliveries = req.body;

//     if (!Array.isArray(deliveries) || deliveries.length === 0) {
//       return res.status(400).send({ success: false, message: "No deliveries provided" });
//     }

//     // ✅ Trip Number জেনারেট করার জন্য কাউন্টার আপডেট
//     // returnDocument: "after" দিলে এটি আপডেটেড ডাটা সরাসরি রিটার্ন করে
//     const counter = await counterCollection.findOneAndUpdate(
//       { _id: "tripNumber" },
//       { $inc: { seq: 1 } },
//       { upsert: true, returnDocument: "after" } 
//     );

//     // v4+ ড্রাইভার বা Atlas-এ counter সরাসরি আপডেট হওয়া ডকুমেন্টটি দেয়
//     // যদি value এর ভেতর থাকে তবে counter.value.seq হবে, নাহলে counter.seq
//     let seq = counter?.seq || counter?.value?.seq || 1;

//     const tripNumber = `TR-${seq.toString().padStart(6, "0")}`;

//     // প্রতিটি ডেলিভারিতে tripNumber এবং current date যুক্ত করা
//     const deliveriesWithTrip = deliveries.map(d => ({ 
//       ...d, 
//       tripNumber,
//       createdAt: new Date() // সার্ভার সাইড ডেট নিশ্চিত করা
//     }));

//     // ১. Deliveries কালেকশনে ইনসার্ট করা
//     const result = await deliveriesCollection.insertMany(deliveriesWithTrip);

//     // ২. সংশ্লিষ্ট Challan গুলোর স্ট্যাটাস আপডেট করা
//     const challanIds = deliveriesWithTrip.map(d =>
//       typeof d.challanId === "string" ? new ObjectId(d.challanId) : d.challanId
//     );

//     const updateResult = await challanCollection.updateMany(
//       { _id: { $in: challanIds } },
//       { $set: { status: "delivered" } }
//     );

//     res.send({
//       success: true,
//       insertedCount: result.insertedCount,
//       updatedCount: updateResult.modifiedCount,
//       tripNumber
//     });

//   } catch (error) {
//     console.error("Delivery Error:", error);
//     res.status(500).send({ success: false, message: "Delivery failed", error: error.message });
//   }
// });

app.post("/deliveries", async (req, res) => {
  try {

    const deliveries = req.body;

    if (!Array.isArray(deliveries) || deliveries.length === 0) {
      return res.status(400).send({
        success: false,
        message: "No deliveries provided"
      });
    }

    // ✅ Trip Number Counter
    const counter = await counterCollection.findOneAndUpdate(
      { _id: "tripNumber" },
      { $inc: { seq: 1 } },
      { upsert: true, returnDocument: "after" }
    );

    let seq = counter?.seq || counter?.value?.seq || 1;

    const tripNumber = `TR-${seq.toString().padStart(6, "0")}`;

    // ✅ Challan IDs
    const challanIds = deliveries.map(d =>
      typeof d.challanId === "string"
        ? new ObjectId(d.challanId)
        : d.challanId
    );

    // ✅ Trip Document
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

    // ✅ Insert Trip
    const result = await deliveriesCollection.insertOne(tripDocument);

    // ✅ Update Challan Status
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

  } catch (error) {

    console.error("Delivery Error:", error);

    res.status(500).send({
      success: false,
      message: "Delivery failed",
      error: error.message
    });

  }
}); 



app.get("/deliveries", async (req, res) => {
  try {
    const deliveries = await deliveriesCollection.find().sort({ createdAt: -1 }).toArray();
    res.send({ success: true, data: deliveries });
  } catch (error) {
    console.error("Fetch Deliveries Error:", error);
    res.status(500).send({ success: false, message: "Failed to fetch deliveries" });
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
