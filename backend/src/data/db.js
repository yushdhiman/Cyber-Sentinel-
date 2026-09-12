/**
 * db.js
 * Database Connection & Migration Management for PostgreSQL.
 * 
 * Provides connection pooling, automatic schema migration on startup,
 * and dual-mode detection (PostgreSQL when DATABASE_URL is configured,
 * clean local persistent file storage when running offline/local development).
 */

const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

let pool = null;
let isConnected = false;

function getPool() {
  if (!pool && process.env.DATABASE_URL) {
    const connectionString = process.env.DATABASE_URL;
    const isProduction = process.env.NODE_ENV === 'production';

    pool = new Pool({
      connectionString,
      ssl: isProduction && !connectionString.includes('localhost') ? { rejectUnauthorized: false } : false,
      max: 15,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });

    pool.on('error', (err) => {
      console.error('[DB] Unexpected PostgreSQL client error:', err.message);
    });
  }
  return pool;
}

async function initDb() {
  if (!process.env.DATABASE_URL) {
    console.log('[DB] No DATABASE_URL configured. Active mode: Persistent Local JSON Repositories.');
    return false;
  }

  try {
    const activePool = getPool();
    if (!activePool) return false;

    // Test connection
    const client = await activePool.connect();
    console.log('[DB] Successfully established connection to PostgreSQL.');

    // Execute schema migrations
    const schemaPath = path.join(__dirname, 'schema.sql');
    if (fs.existsSync(schemaPath)) {
      const sql = fs.readFileSync(schemaPath, 'utf8');
      await client.query(sql);
      console.log('[DB] PostgreSQL schema migrations successfully applied.');
    }
    client.release();
    isConnected = true;
    return true;
  } catch (err) {
    console.error('[DB] Failed to connect to PostgreSQL:', err.message);
    console.warn('[DB] Falling back to local persistent repository storage.');
    isConnected = false;
    return false;
  }
}

async function query(text, params) {
  const activePool = getPool();
  if (!activePool) {
    throw new Error('Database pool not available (DATABASE_URL not configured).');
  }
  return activePool.query(text, params);
}

function isPostgresConnected() {
  return isConnected && pool !== null;
}

async function closeDb() {
  if (pool) {
    await pool.end();
    isConnected = false;
    console.log('[DB] PostgreSQL connection pool closed.');
  }
}

module.exports = {
  getPool,
  initDb,
  query,
  isPostgresConnected,
  closeDb,
};
