require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const port = process.env.PORT || 5000;

// middleware
app.use(cors());
app.use(express.json());

const client = new MongoClient(process.env.MONGO_URI);

const verifyJWT = (req, res, next) => {
  const token = req?.headers?.authorization?.split(" ")[1];
  if (!token) return res.status(401).send({ message: "Unauthorized" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: "Invalid token" });
    req.user = decoded;
    next();
  });
};
async function run() {
  try {
    const db = client.db("tasteTrailDB");
    const usersCollection = db.collection("users");
    const recipesCollection = db.collection("recipes");
    const categoriesCollection = db.collection("categories");
    const reviewsCollection = db.collection("reviews");

    // Verify Admin
    const verifyAdmin = async (req, res, next) => {
      const user = await usersCollection.findOne({ email: req.user.email });
      if (user?.role !== "admin") {
        return res.status(403).send({ message: "Admin only" });
      }
      next();
    };

    // ================= REGISTER =================
    app.post("/auth/register", async (req, res) => {
      const { fullName, email, password, photo } = req.body;

      const existing = await usersCollection.findOne({ email });
      if (existing) {
        return res.status(400).send({ message: "Email already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = {
        fullName,
        email,
        password: hashedPassword,
        photo,
        role: "user",
        createdAt: new Date(),
      };

      await usersCollection.insertOne(newUser);

      const token = jwt.sign(
        { email: newUser.email, role: newUser.role },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
      );

      res.send({ success: true, token, role: newUser.role });
    });

    // ================= LOGIN =================
    app.post("/auth/login", async (req, res) => {
      const { email, password } = req.body;

      const user = await usersCollection.findOne({ email });
      if (!user) return res.status(400).send({ message: "User not found" });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch)
        return res.status(400).send({ message: "Wrong password" });

      const token = jwt.sign(
        { email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
      );

      res.send({ success: true, token, role: user.role,
         photo: user.photo || "https://i.ibb.co/2kR1Y0F/default-avatar.png" });
    });

    // ================= CURRENT USER =================
    app.get("/users/me", verifyJWT, async (req, res) => {
      const user = await usersCollection.findOne(
        { email: req.user.email },
        { projection: { password: 0 } }
      );
      res.send(user);
    });

    // ================= USER ROLE =================
    app.get("/users/role", async (req, res) => {
      const email = req.query.email;
      const user = await usersCollection.findOne({ email });
      if (!user) return res.status(404).send({ message: "User not found" });

      res.send({ role: user.role });
    });

    // ================= ALL USERS (ADMIN) =================
    app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
      const users = await usersCollection.find().toArray();
      res.send(users);
    });

    // ================= ADMIN RECIPE MANAGEMENT =================
// Create Recipe
app.post("/admin/recipes", verifyJWT, verifyAdmin, async (req, res) => {
const recipe = { ...req.body, createdAt: new Date(), updatedAt: new Date() };
const result = await recipesCollection.insertOne(recipe);
res.send({ success: true, recipeId: result.insertedId });
});


// Get All Recipes
app.get("/admin/recipes", async (req, res) => {
const recipes = await recipesCollection.find().toArray();
res.send(recipes);
});
// Update Recipe
app.put("/admin/recipes/:id", verifyJWT, verifyAdmin, async (req, res) => {
const { id } = req.params;
await recipesCollection.updateOne(
{ _id: new ObjectId(id) },
{ $set: { ...req.body, updatedAt: new Date() } }
);
res.send({ success: true });
});

// Delete Recipe
app.delete("/admin/recipes/:id", verifyJWT, verifyAdmin, async (req, res) => {
const { id } = req.params;
await recipesCollection.deleteOne({ _id: new ObjectId(id) });
res.send({ success: true });
});

// ================= CATEGORY CRUD (ADMIN) =================
app.post("/admin/categories", verifyJWT, verifyAdmin, async (req, res) => {
const category = req.body;
await categoriesCollection.insertOne(category);
res.send({ success: true, message: "Category created" });
});


app.put("/admin/categories/:id", verifyJWT, verifyAdmin, async (req, res) => {
const { id } = req.params;
const updateData = req.body;
await categoriesCollection.updateOne(
{ _id: new ObjectId(id) },
{ $set: updateData }
);
res.send({ success: true, message: "Category updated" });
});

  } finally {
  }
}
run();

app.get("/", (req, res) => {
  res.send("TasteTrail Server Running...");
});

app.listen(port, () => {
  console.log("TasteTrail running on port", port);
});