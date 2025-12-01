// -------------------------------
// 📦 IMPORTS & INITIAL SETUP
// -------------------------------
const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET);
const port = process.env.PORT || 5000;
const crypto = require("crypto");

// Firebase Admin SDK for token verification
const admin = require("firebase-admin");
const serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// -------------------------------
// 🔐 Tracking ID Generator
// -------------------------------
function generateTrackingId() {
  const prefix = "TRK";
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const random = crypto.randomBytes(3).toString("hex").toUpperCase();
  return `${prefix}-${date}-${random}`;
}

console.log(generateTrackingId());

// -------------------------------
// 🌐 GLOBAL MIDDLEWARE
// -------------------------------
app.use(cors());
app.use(express.json());

// -------------------------------
// 🔐 Verify Firebase Token Middleware
// → Protects routes using Firebase Auth
// -------------------------------
const verifyFBToken = async (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).send({ error: "You are not authorized" });
  }

  try {
    const idToken = token.split(" ")[1];
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.decoded_email = decodedToken.email;
    console.log("decodedToken", decodedToken);
    next();
  } catch (error) {
    return res.status(401).send({ error: "You are not authorized" });
  }
};

// -------------------------------
// 🏦 DATABASE CONNECTION (MongoDB)
// -------------------------------
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@simplecrudserver.fyfvvbn.mongodb.net/?appName=simpleCRUDserver`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    const db = client.db("zapShiftDB");

    // Database collections
    const userCollection = db.collection("users");
    const parcelCollection = db.collection("parcels");

    // -------------------------------
    // 🔐 Verify Admin Middleware
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded_email;
      // Implement admin check
      const query = { email };
      const user = await userCollection.findOne(query);

      if (!user || user.role !== "admin") {
        return res.status(403).send({ error: "You are not authorized" });
      }
      next();
    };

    // -------------------------------
    // 🧑 USERS API
    // -------------------------------

    // GET all users (Protected)
    app.get("/users", verifyFBToken, async (req, res) => {
       const searchText = req.query.search;
      const query = {};

      if(searchText) {
        // query.displayName = { $regex: searchText, $options: "i" };
        query.$or = [
          { displayName: { $regex: searchText, $options: "i" } },
          { email: { $regex: searchText, $options: "i" } },
        ]
      }
      const cursor = userCollection.find(query).sort({ createdAt: -1 });
      const result = await cursor.toArray();
      res.send(result);
    });

    // GET user role by email (Protected)
    app.get("/users/:email/role", verifyFBToken, async (req, res) => {
      const email = req.params.email;
      const user = await userCollection.findOne({ email });
      res.send({ role: user?.role || "user" });
    });

    // Create a new user
    app.post("/users", async (req, res) => {
      const user = req.body;
      user.role = "user";
      user.createdAt = new Date();

      const userExist = await userCollection.findOne({ email: user.email });
      if (userExist) {
        return res.send({ message: "User already exist" });
      }

      const result = await userCollection.insertOne(user);
      res.send(result);
    });

    // Update user role (Admin only)
    app.patch(
      "/users/:id/role",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const roleInfo = req.body;

        const result = await userCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role: roleInfo.role } }
        );

        res.send(result);
      }
    );

    // -------------------------------
    // 📦 PARCEL APIs
    // -------------------------------

    // Get all parcels / filter by sender email
    app.get("/parcels", async (req, res) => {
      const { email } = req.query;
      const query = email ? { senderEmail: email } : {};

      const parcels = await parcelCollection
        .find(query, { sort: { createdAt: -1 } })
        .toArray();

      res.send(parcels);
    });

    // Get parcel by ID
    app.get("/parcels/:id", async (req, res) => {
      const result = await parcelCollection.findOne({
        _id: new ObjectId(req.params.id),
      });
      res.send(result);
    });

    // Create parcel
    app.post("/parcels", async (req, res) => {
      const parcel = req.body;
      parcel.createdAt = new Date();

      const result = await parcelCollection.insertOne(parcel);
      res.send(result);
    });

    // Delete parcel
    app.delete("/parcels/:id", async (req, res) => {
      const result = await parcelCollection.deleteOne({
        _id: new ObjectId(req.params.id),
      });
      res.send(result);
    });

    // -------------------------------
    // 💳 PAYMENT APIs (Stripe)
    // -------------------------------

    // Create Stripe Checkout Session
    app.post("/payment-checkout-session", async (req, res) => {
      const paymentInfo = req.body;
      const amount = parseInt(paymentInfo.cost) * 100;

      const session = await stripe.checkout.sessions.create({
        line_items: [
          {
            price_data: {
              currency: "usd",
              unit_amount: amount,
              product_data: {
                name: `Please pay for: ${paymentInfo.parcelName}`,
              },
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        metadata: {
          parcelId: paymentInfo.parcelId,
          parcelName: paymentInfo.parcelName,
        },
        customer_email: paymentInfo.senderEmail,
        success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment-cancelled`,
      });

      res.send({ url: session.url });
    });

    // After Stripe payment success → update parcel + save payment info
    app.patch("/payment-success", async (req, res) => {
      const sessionId = req.query.session_id;
      const session = await stripe.checkout.sessions.retrieve(sessionId);

      const transactionId = session.payment_intent;

      // Prevent duplicate payment
      const paymentExist = await paymentCollection.findOne({ transactionId });
      if (paymentExist) {
        return res.send({
          message: "Payment already exist",
          transactionId,
          trackingId: paymentExist.trackingId,
        });
      }

      const trackingId = generateTrackingId();

      // Update parcel if paid
      if (session.payment_status === "paid") {
        await parcelCollection.updateOne(
          { _id: new ObjectId(session.metadata.parcelId) },
          {
            $set: {
              paymentStatus: "paid",
              
              trackingId: trackingId,
            },
          }
        );

        // Save payment to DB
        const payment = {
          amount: session.amount_total,
          transactionId,
          parcelId: session.metadata.parcelId,
          parcelName: session.metadata.parcelName,
          senderEmail: session.customer_email,
          currency: session.currency,
          paymentStatus: session.payment_status,
          paidAt: new Date(),
          trackingId,
        };

        const paymentResult = await paymentCollection.insertOne(payment);

        return res.send({
          success: true,
          trackingId,
          transactionId,
          paymentInfo: paymentResult,
        });
      }

      res.send({ sessionId: false });
    });

    // Get payments (Protected + verifies user email)
    app.get("/payments", verifyFBToken, async (req, res) => {
      const email = req.query.email;

      if (email && email !== req.decoded_email) {
        return res.status(401).send({ error: "You are not authorized" });
      }

      const payments = await paymentCollection
        .find(email ? { senderEmail: email } : {})
        .sort({ paidAt: -1 })
        .toArray();

      res.send(payments);
    });

    // -------------------------------
    // 🏍️ RIDERS API
    // -------------------------------

    // Get all riders + filters
    app.get("/riders", async (req, res) => {
      const { status, district, workStatus } = req.query;
      const query = {};

      if (status) query.status = status;
      if (district) query.district = district;
      if (workStatus) query.workStatus = workStatus;

      const riders = await ridersCollection.find(query).toArray();
      res.send(riders);
    });

    // New rider request
    app.post("/riders", async (req, res) => {
      const rider = req.body;
      rider.status = "pending";
      rider.createdAt = new Date();

      const result = await ridersCollection.insertOne(rider);
      res.send(result);
    });

    // Approve/Reject rider + assign role
    app.patch("/riders/:id", verifyFBToken, verifyAdmin, async (req, res) => {
      const status = req.body.status;
      const id = req.params.id;

      const result = await ridersCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            status: status,
            workStatus: "available",
          },
        }
      );

      // Convert user → rider role if approved
      if (status === "approved") {
        await userCollection.updateOne(
          { email: req.body.email },
          { $set: { role: "rider" } }
        );
      }

      res.send(result);
    });

    console.log("Connected to MongoDB server successfully!");
  } finally {
    // Client remains open for performance
  }
}

run().catch(console.dir);

// -------------------------------
// ROOT
// -------------------------------
app.get("/", (req, res) => {
  res.send("Zap Shift Server is running");
});

// -------------------------------
// SERVER
// -------------------------------
app.listen(port, () => {
  console.log(`Zap Shift Server listening on port ${port}`);
});
