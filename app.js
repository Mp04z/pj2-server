import express from "express";
import bodyParser from "body-parser";
import session from "express-session";
import bcrypt from "bcrypt";
import db from "./db.js";

const app = express();

// Enable CORS with credentials
app.use((req, res, next) => {
  // Allow your Flutter app's origin
  const allowedOrigins = ['http://localhost', 'http://localhost:3000', 'http://192.168.1.121:3000'];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
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
    saveUninitialized: false,
    cookie: { 
      secure: false, // Set to true if using HTTPS
      httpOnly: true,
      sameSite: 'lax', // Helps with CSRF protection
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    },
    name: 'sessionId' // Explicitly name the session cookie
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



// ---------------- CHECK BORROW REQUESTS ----------------
app.get("/api/borrow-requests/check", async (req, res) => {
  console.log('Received request to /api/borrow-requests/check');
  try {
    const userId = req.session.user?.id;
    console.log('User ID from session:', userId);

    if (!userId) {
      console.log('No user ID in session');
      return res.status(401).json({ message: "Unauthorized: please login first" });
    }

    console.log('Querying database for user ID:', userId);
    db.query(
      `SELECT b.*, a.asset_name 
       FROM borrowing b
       JOIN assets a ON b.asset_id = a.id 
       WHERE b.user_id = ? AND b.returned = 'False'`,
      [userId],
      (error, rows) => {
        if (error) {
          console.error('Database error:', error);
          return res.status(500).json({ message: "Database error" });
        }
        console.log('Query results:', rows);
        res.json({ 
          hasActiveRequest: rows.length > 0,
          requests: rows 
        });
      }
    );
  } catch (error) {
    console.error("Error checking borrow requests:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ---------------- GET BORROW HISTORY ----------------
app.get("/api/history", (req, res) => {
  // Get the user ID from the session, NOT the URL
  const userId = req.session.user?.id;

  if (!userId) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  // Updated query to select asset image and returned status
  db.query(
    `SELECT 
        a.asset_name,
        DATE_FORMAT(b.borrow_date, '%Y-%m-%d') as borrow_date,
        DATE_FORMAT(b.return_date, '%Y-%m-%d') as return_date,
        (SELECT name FROM users WHERE id = b.approved_by) as approved_by,
        (SELECT name FROM users WHERE id = b.processed_by) as processed_by,
        'Returned' as status
     FROM borrowing b
     JOIN assets a ON b.asset_id = a.id
     WHERE b.user_id = ? AND b.returned = 1
     ORDER BY b.borrow_date DESC`,
    [userId],
    (err, rows) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ message: "Server error" });
      }
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
