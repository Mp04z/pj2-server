import express from "express";
import bodyParser from "body-parser";
import session from "express-session";
import bcrypt from "bcrypt";
import db from "./db.js";

const app = express();

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

    const sessionUser = { id: user.id, username: user.username };
    req.session.user = sessionUser;

    res
      .status(200)
      .json({ message: "Login successful", user: sessionUser });
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
app.post("/api/borrow", (req, res) => {
  // ดึง id ของ user จาก session
  const student_id = req.session.user?.id;
  const { asset_id, borrow_date, return_date } = req.body;

  // ถ้าไม่มี session (ยังไม่ล็อกอิน)
  if (!student_id) {
    return res.status(401).json({ message: "Unauthorized: please login first" });
  }

  // ตรวจสอบว่าข้อมูลครบไหม
  if (!asset_id || !borrow_date || !return_date) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  // 1️⃣ ตรวจสอบว่าสินค้ามีอยู่และยังว่างไหม
  db.query("SELECT status FROM assets WHERE id = ?", [asset_id], (err, rows) => {
    if (err) return res.status(500).json({ message: "Server error" });
    if (rows.length === 0) return res.status(404).json({ message: "Asset not found" });

    const status = rows[0].status;
    if (status !== "Available") {
      return res.status(400).json({ message: "Asset not available" });
    }

    // 2️⃣ บันทึกข้อมูลการยืม (ใช้ student_id จาก session)
    db.query(
      "INSERT INTO borrowing (asset_id, user_id, borrow_date, return_date, status, returned) VALUES (?, ?, ?, ?, ?, ?)",
      [asset_id, student_id, borrow_date, return_date, "Pending", "False"],
      (err2) => {
        if (err2) return res.status(500).json({ message: "Server error" });

        // 3️⃣ อัปเดตสถานะของ asset เป็น Pending
        db.query(
          "UPDATE assets SET status = 'Pending' WHERE id = ?",
          [asset_id],
          (err3) => {
            if (err3) return res.status(500).json({ message: "Server error" });
            res.json({ message: "Borrow request submitted successfully" });
          }
        );
      }
    );
  });
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

// ---------------- START SERVER ----------------
app.listen(3000, () => console.log("✅ API running on port 3000"));
