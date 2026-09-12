/**
 * userStore.js
 * Persistent User Store supporting PostgreSQL with local file fallback.
 * 
 * In production with DATABASE_URL, synchronizes with PostgreSQL table 'users'.
 * For local development, persists to users.json.
 * Always maintains an in-memory index for non-blocking sub-millisecond lookups.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { isPostgresConnected, query } = require('./db');
const { ROLES, normalizeRole } = require('../constants/roles');

const DB_PATH = path.join(__dirname, 'users.json');

// Memory cache for zero-latency lookups
let users = new Map();

async function syncFromPostgres() {
  try {
    if (!isPostgresConnected()) return;
    const res = await query('SELECT * FROM users');
    res.rows.forEach(row => {
      users.set(row.email.toLowerCase(), {
        id: row.id,
        email: row.email,
        name: row.name,
        passwordHash: row.password_hash,
        role: normalizeRole(row.role),
        status: row.status,
        mfaEnabled: row.mfa_enabled,
        totpSecret: row.totp_secret,
        createdAt: row.created_at ? new Date(row.created_at).toISOString() : new Date().toISOString(),
        updatedAt: row.updated_at ? new Date(row.updated_at).toISOString() : new Date().toISOString(),
      });
    });
    console.log(`[DB] Synchronized ${res.rows.length} user accounts from PostgreSQL.`);
  } catch (err) {
    console.error('[DB] Error syncing users from PostgreSQL:', err.message);
  }
}

function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) {
      const raw = fs.readFileSync(DB_PATH, 'utf8');
      const data = JSON.parse(raw);
      // Normalize roles when loading
      users = new Map();
      Object.entries(data).forEach(([email, u]) => {
        u.role = normalizeRole(u.role);
        users.set(email.toLowerCase(), u);
      });
      console.log(`[DB] Loaded ${users.size} user accounts into memory cache.`);
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
    console.error('[DB] Error saving users database file:', err.message);
  }
}

function seedDefaultAdmin() {
  const adminEmail = (process.env.INITIAL_ADMIN_EMAIL || 'admin@sentinel.local').trim().toLowerCase();
  const adminPassword = process.env.INITIAL_ADMIN_PASSWORD;

  let passwordToHash;
  let mustChange = false;

  if (adminPassword) {
    passwordToHash = adminPassword;
    console.log(`[DB] Seeding primary administrator: ${adminEmail}`);
  } else {
    passwordToHash = crypto.randomBytes(16).toString('hex');
    mustChange = true;
    console.log('\n============================================================');
    console.log('[SECURITY] INITIAL_ADMIN_PASSWORD not configured.');
    console.log(`[SECURITY] Generated one-time bootstrap administrator credential:`);
    console.log(`[SECURITY] Email:    ${adminEmail}`);
    console.log(`[SECURITY] Password: ${passwordToHash}`);
    console.log('============================================================\n');
  }

  const salt = bcrypt.genSaltSync(12);
  const passwordHash = bcrypt.hashSync(passwordToHash, salt);

  const adminUser = {
    id: 'USR-ADMIN-0001',
    name: 'SOC Lead Administrator',
    email: adminEmail,
    passwordHash,
    role: ROLES.ADMIN,
    status: 'active',
    mustChangePassword: mustChange,
    mfaEnabled: false,
    createdAt: new Date().toISOString(),
  };

  users.set(adminUser.email.toLowerCase(), adminUser);
  saveDB();

  // Async persist to PostgreSQL if connected
  if (isPostgresConnected()) {
    query(
      `INSERT INTO users (id, email, password_hash, name, role, status, mfa_enabled, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (email) DO NOTHING`,
      [adminUser.id, adminUser.email, adminUser.passwordHash, adminUser.name, adminUser.role, adminUser.status, false, adminUser.createdAt]
    ).catch(e => console.error('[DB] Error seeding admin to PostgreSQL:', e.message));
  }
}

// Initial load
loadDB();

module.exports = {
  syncFromPostgres,
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
    user.role = normalizeRole(user.role || ROLES.ANALYST);
    if (!user.id) user.id = `USR-${Date.now().toString().slice(-6)}-${crypto.randomInt(10, 99)}`;
    users.set(user.email.toLowerCase(), user);
    saveDB();

    if (isPostgresConnected()) {
      query(
        `INSERT INTO users (id, email, password_hash, name, role, status, mfa_enabled, totp_secret, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (email) DO UPDATE SET
           password_hash = EXCLUDED.password_hash,
           name = EXCLUDED.name,
           role = EXCLUDED.role,
           status = EXCLUDED.status,
           mfa_enabled = EXCLUDED.mfa_enabled,
           totp_secret = EXCLUDED.totp_secret`,
        [user.id, user.email, user.passwordHash, user.name, user.role, user.status || 'active', Boolean(user.mfaEnabled), user.totpSecret || null, user.createdAt || new Date().toISOString()]
      ).catch(e => console.error('[DB] Error inserting user into PostgreSQL:', e.message));
    }
    return user;
  },
  updateUser(user) {
    user.role = normalizeRole(user.role);
    users.set(user.email.toLowerCase(), user);
    saveDB();

    if (isPostgresConnected()) {
      query(
        `UPDATE users SET
           password_hash = $1,
           name = $2,
           role = $3,
           status = $4,
           mfa_enabled = $5,
           totp_secret = $6,
           updated_at = NOW()
         WHERE email = $7`,
        [user.passwordHash, user.name, user.role, user.status || 'active', Boolean(user.mfaEnabled), user.totpSecret || null, user.email.toLowerCase()]
      ).catch(e => console.error('[DB] Error updating user in PostgreSQL:', e.message));
    }
  },
  updateUserEmail(oldEmail, newEmail, user) {
    user.role = normalizeRole(user.role);
    users.delete(oldEmail.toLowerCase());
    users.set(newEmail.toLowerCase(), user);
    saveDB();

    if (isPostgresConnected()) {
      query(
        `UPDATE users SET
           email = $1,
           name = $2,
           password_hash = $3,
           role = $4,
           updated_at = NOW()
         WHERE email = $5`,
        [newEmail.toLowerCase(), user.name, user.passwordHash, user.role, oldEmail.toLowerCase()]
      ).catch(e => console.error('[DB] Error updating email in PostgreSQL:', e.message));
    }
  },
  getAllUsers() {
    return Array.from(users.values());
  }
};
