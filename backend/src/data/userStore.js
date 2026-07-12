/**
 * userStore.js
 * Persistent file-based user store.
 * Saves user credentials to users.json so they are preserved across server restarts,
 * and seeds a default administrator account if empty.
 */

const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, 'users.json');

// Memory cache
let users = new Map();

function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) {
      const raw = fs.readFileSync(DB_PATH, 'utf8');
      const data = JSON.parse(raw);
      users = new Map(Object.entries(data));
      console.log(`[DB] Loaded ${users.size} user accounts from users.json`);
    } else {
      seedDefaultAdmin();
    }
  } catch (err) {
    console.error('[DB] Error loading users database:', err.message);
    seedDefaultAdmin();
  }
}

function saveDB() {
  try {
    const obj = Object.fromEntries(users);
    fs.writeFileSync(DB_PATH, JSON.stringify(obj, null, 2), 'utf8');
  } catch (err) {
    console.error('[DB] Error saving users database:', err.message);
  }
}

function seedDefaultAdmin() {
  console.log('[DB] Seeding default administrator account...');
  // Seed admin: admin@sentinel.ai / password123
  const salt = bcrypt.genSaltSync(10);
  const passwordHash = bcrypt.hashSync('password123', salt);
  
  const adminUser = {
    name: 'Admin User',
    email: 'admin@sentinel.ai',
    passwordHash,
    role: 'administrator',
    createdAt: new Date().toISOString(),
  };
  
  users.set(adminUser.email.toLowerCase(), adminUser);
  saveDB();
}

// Initial load on import
loadDB();

module.exports = {
  findByEmail(email) {
    if (!email) return null;
    return users.get(email.toLowerCase());
  },
  createUser(user) {
    users.set(user.email.toLowerCase(), user);
    saveDB();
    return user;
  },
  count() {
    return users.size;
  },
};
