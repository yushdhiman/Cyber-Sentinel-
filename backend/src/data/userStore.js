/**
 * userStore.js
 * Persistent file-based user store.
 * Saves user credentials to users.json so they are preserved across server restarts,
 * and seeds a default administrator account if empty.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
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
  const adminEmail = (process.env.INITIAL_ADMIN_EMAIL || 'admin@sentinel.ai').trim().toLowerCase();
  const adminPassword = process.env.INITIAL_ADMIN_PASSWORD;

  let passwordToHash;
  let mustChange = false;

  if (adminPassword) {
    passwordToHash = adminPassword;
    console.log(`[DB] Seeding primary administrator from environment: ${adminEmail}`);
  } else {
    passwordToHash = crypto.randomBytes(16).toString('hex');
    mustChange = true;
    console.log('\n============================================================');
    console.log('[SECURITY] INITIAL_ADMIN_PASSWORD not set in environment.');
    console.log(`[SECURITY] Generated one-time bootstrap administrator credential:`);
    console.log(`[SECURITY] Email:    ${adminEmail}`);
    console.log(`[SECURITY] Password: ${passwordToHash}`);
    console.log('============================================================\n');
  }

  const salt = bcrypt.genSaltSync(12);
  const passwordHash = bcrypt.hashSync(passwordToHash, salt);

  const adminUser = {
    name: 'Primary Administrator',
    email: adminEmail,
    passwordHash,
    role: 'administrator',
    status: 'active',
    mustChangePassword: mustChange,
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
  findByPhone(phone) {
    if (!phone) return null;
    const normalized = phone.trim();
    for (const user of users.values()) {
      if (user.phone && user.phone.trim() === normalized) return user;
    }
    return null;
  },
  createUser(user) {
    users.set(user.email.toLowerCase(), user);
    saveDB();
    return user;
  },
  updateUser(user) {
    users.set(user.email.toLowerCase(), user);
    saveDB();
    return user;
  },
  updateUserEmail(oldEmail, newEmail, user) {
    users.delete(oldEmail.toLowerCase());
    users.set(newEmail.toLowerCase(), user);
    saveDB();
    return user;
  },
  count() {
    return users.size;
  },
};
