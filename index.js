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

    const db= client.db('LBTS-OS-DB')
    const userCollection = db.collection('users')
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


//delete //
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




    console.log("✅ MongoDB connected successfully");
  } catch (err) {
    console.error("MongoDB connection failed:", err);
  }
}

run();

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
