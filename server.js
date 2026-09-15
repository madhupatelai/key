const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;

const DATA_DIR = path.join(__dirname, "data");
const KEYS_FILE = path.join(DATA_DIR, "keys.json");

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-this-password";

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function ensureKeysFile() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  if (!fs.existsSync(KEYS_FILE)) {
    fs.writeFileSync(KEYS_FILE, "[]", "utf8");
  }
}

function readKeys() {
  ensureKeysFile();

  try {
    return JSON.parse(fs.readFileSync(KEYS_FILE, "utf8"));
  } catch {
    return [];
  }
}

function saveKeys(keys) {
  ensureKeysFile();

  fs.writeFileSync(
    KEYS_FILE,
    JSON.stringify(keys, null, 2),
    "utf8"
  );
}

function hashKey(key) {
  return crypto
    .createHash("sha256")
    .update(key)
    .digest("hex");
}

function checkAdmin(req) {
  return req.headers["x-admin-password"] === ADMIN_PASSWORD;
}


// Home page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});


// User key login
app.post("/api/login", (req, res) => {

  const key = String(req.body.key || "").trim();

  if (!key) {
    return res.status(400).json({
      error: "Key is required."
    });
  }

  const keys = readKeys();
  const hashed = hashKey(key);

  const found = keys.find(item => item.hash === hashed);

  if (!found) {
    return res.status(401).json({
      error: "Invalid key."
    });
  }

  if (found.expiresAt && Date.now() > found.expiresAt) {
    return res.status(401).json({
      error: "Key expired."
    });
  }

  res.json({
    success: true,
    message: "Login successful."
  });
});


// Get all keys - Admin only
app.get("/api/keys", (req, res) => {

  if (!checkAdmin(req)) {
    return res.status(401).json({
      error: "Unauthorized."
    });
  }

  const keys = readKeys();

  res.json({
    keys
  });
});


// Create key - Admin only
app.post("/api/keys", (req, res) => {

  if (!checkAdmin(req)) {
    return res.status(401).json({
      error: "Unauthorized."
    });
  }

  const key = String(req.body.key || "").trim();

  if (!key) {
    return res.status(400).json({
      error: "Key is required."
    });
  }

  const keys = readKeys();
  const hashed = hashKey(key);

  const exists = keys.some(item => item.hash === hashed);

  if (exists) {
    return res.status(409).json({
      error: "Key already exists."
    });
  }

  keys.push({
    id: crypto.randomUUID(),
    hash: hashed,
    createdAt: Date.now(),
    expiresAt: null
  });

  saveKeys(keys);

  res.json({
    success: true,
    message: "Key created successfully."
  });
});


// Delete key - Admin only
app.delete("/api/keys/:id", (req, res) => {

  if (!checkAdmin(req)) {
    return res.status(401).json({
      error: "Unauthorized."
    });
  }

  const keys = readKeys();

  const updated = keys.filter(
    item => item.id !== req.params.id
  );

  if (updated.length === keys.length) {
    return res.status(404).json({
      error: "Key not found."
    });
  }

  saveKeys(updated);

  res.json({
    success: true,
    message: "Key deleted."
  });
});


app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
