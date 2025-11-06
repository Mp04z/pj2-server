import express from "express";
import bodyParser from "body-parser";
import session from "express-session";
import bcrypt from "bcrypt";
import db from "./db.js";

const app = express();

// Enable CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});

app.use(bodyParser.json());

// ---------------- SESSION ----------------
app.use(
  session({
    secret: "secret-key",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  })
);

// ---------------- REGISTER ----------------
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ message: "Username and password required" });

    const [existing] = await db
      .promise()
      .query("SELECT * FROM users WHERE username = ?", [username]);
    if (existing.length > 0) {
      return res.status(400).json({ message: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db
      .promise()
      .query("INSERT INTO users (username, password) VALUES (?, ?)", [
        username,
        hashedPassword,
      ]);

    res.status(201).json({ message: "Register successful!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ---------------- LOGIN ----------------
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required" });
  }

  try {
    const [rows] = await db
      .promise()
      .query("SELECT * FROM users WHERE username = ?", [username]);

    if (rows.length === 0) {
      return res.status(400).json({ message: "User not found" });
    }

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid password" });
    }

    const sessionUser = { 
      id: user.id, 
      username: user.username,
      role: user.role || 'student' // Default to 'student' if role is not set
    };
    
    req.session.user = sessionUser;

    res.status(200).json({ 
      message: "Login successful", 
      user: sessionUser 
    });
  } catch (error) {
    console.error("❌ Login error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ---------------- GET ALL ASSETS ----------------
app.get("/api/asset", (req, res) => {
  db.query("SELECT * FROM assets", (err, rows) => {
    if (err) return res.status(500).json({ message: "Server error" });
    res.json(rows);
  });
});

// ---------------- BORROW REQUEST ----------------
app.post("/api/borrow", async (req, res) => {
  try {
    const student_id = req.session.user?.id;
    const { asset_id, borrow_date, return_date } = req.body;

    // Check if user is logged in
    if (!student_id) {
      return res.status(401).json({ message: "Unauthorized: please login first" });
    }

    // Validate required fields
    if (!asset_id || !borrow_date || !return_date) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Check if user has already borrowed an asset today
    const [existingBorrows] = await db.promise().query(
      `SELECT * FROM borrowing 
       WHERE user_id = ? 
       AND DATE(borrow_date) = CURDATE()
       AND returned = 'False'`,
      [student_id]
    );

    if (existingBorrows.length > 0) {
      return res.status(400).json({ 
        message: "You have already borrowed an asset today. Only one asset per day is allowed." 
      });
    }

    // 1️⃣ Check if asset exists and is available
    const [assetRows] = await db.promise().query(
      "SELECT status FROM assets WHERE id = ?", 
      [asset_id]
    );

    if (assetRows.length === 0) {
      return res.status(404).json({ message: "Asset not found" });
    }

    const status = assetRows[0].status;
    if (status !== "Available") {
      return res.status(400).json({ message: "Asset not available" });
    }

    // 2️⃣ Insert borrowing record
    await db.promise().query(
      `INSERT INTO borrowing 
       (asset_id, user_id, borrow_date, return_date, status, returned) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [asset_id, student_id, borrow_date, return_date, "Pending", "False"]
    );

    // 3️⃣ Update asset status to Pending
    await db.promise().query(
      "UPDATE assets SET status = 'Pending' WHERE id = ?",
      [asset_id]
    );

    res.json({ message: "Borrow request submitted successfully" });
  } catch (error) {
    console.error("Borrow error:", error);
    res.status(500).json({ message: "Server error" });
  }
});



// ---------------- GET BORROW HISTORY ----------------
app.get("/api/history/:id", (req, res) => {
  const userId = req.params.id;

  db.query(
    `SELECT a.asset_name, b.borrow_date, b.return_date, b.status
     FROM borrowing b
     JOIN assets a ON b.asset_id = a.id
     WHERE b.user_id = ?`,
    [userId],
    (err, rows) => {
      if (err) return res.status(500).json({ message: "Server error" });
      res.json(rows);
    }
  );
});

// ---------------- CHECK SESSION ----------------
app.get("/me", (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

// ---------------- LOGOUT ----------------
app.post("/logout", (req, res) => {
  req.session.destroy();
  res.json({ message: "Logout successful" });
});

// ---------------- HEALTH CHECK ----------------
app.get('/health', async (req, res) => {
  try {
    // Test database connection
    await db.promise().query('SELECT 1');
    res.json({
      status: 'ok',
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Database connection error:', error);
    res.status(500).json({
      status: 'error',
      database: 'connection failed',
      error: error.message
    });
  }
});

// ---------------- START SERVER ----------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ API running on port ${PORT}`);
  console.log(`🔍 Health check available at http://localhost:${PORT}/health`);
});
