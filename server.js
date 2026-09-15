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

function getStatus(item) {
  if (item.revoked) return "Revoked";

  if (
    item.expiresAt &&
    Date.now() >= item.expiresAt
  ) {
    return "Expired";
  }

  return "Active";
}


// Home
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});


// USER LOGIN
app.post("/api/login", (req, res) => {

  const key = String(req.body.key || "").trim();

  if (!key) {
    return res.status(400).json({
      error: "Key is required."
    });
  }

  const keys = readKeys();
  const hashed = hashKey(key);

  const found = keys.find(
    item => item.hash === hashed
  );

  if (!found) {
    return res.status(401).json({
      error: "Invalid key."
    });
  }

  const status = getStatus(found);

  if (status !== "Active") {
    return res.status(401).json({
      error: `Key ${status.toLowerCase()}.`
    });
  }

  res.json({
    success: true,
    message: "Login successful.",
    status: "Active",
    expiresAt: found.expiresAt
  });
});


// ADMIN - GET KEYS
app.get("/api/keys", (req, res) => {

  if (!checkAdmin(req)) {
    return res.status(401).json({
      error: "Unauthorized."
    });
  }

  const keys = readKeys();

  const result = keys.map(item => ({
    id: item.id,
    createdAt: item.createdAt,
    expiresAt: item.expiresAt,
    status: getStatus(item)
  }));

  res.json({
    keys: result
  });
});


// ADMIN - CREATE KEY
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

  let days = Number(req.body.days);

  if (!Number.isFinite(days) || days <= 0) {
    days = 1;
  }

  days = Math.floor(days);

  const keys = readKeys();
  const hashed = hashKey(key);

  const exists = keys.some(
    item => item.hash === hashed
  );

  if (exists) {
    return res.status(409).json({
      error: "Key already exists."
    });
  }

  const now = Date.now();

  const expiresAt =
    now + days * 24 * 60 * 60 * 1000;

  keys.push({
    id: crypto.randomUUID(),
    hash: hashed,
    createdAt: now,
    expiresAt: expiresAt,
    revoked: false
  });

  saveKeys(keys);

  res.json({
    success: true,
    message: `Key created for ${days} day(s).`,
    expiresAt: expiresAt
  });
});


// ADMIN - REVOKE KEY
app.post("/api/keys/:id/revoke", (req, res) => {

  if (!checkAdmin(req)) {
    return res.status(401).json({
      error: "Unauthorized."
    });
  }

  const keys = readKeys();

  const key = keys.find(
    item => item.id === req.params.id
  );

  if (!key) {
    return res.status(404).json({
      error: "Key not found."
    });
  }

  key.revoked = true;

  saveKeys(keys);

  res.json({
    success: true,
    message: "Key revoked."
  });
});


// ADMIN - DELETE KEY
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
