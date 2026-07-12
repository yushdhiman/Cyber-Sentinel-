/**
 * system.js — Real-time system metrics route.
 * GET /api/system/metrics  → OS-level CPU, RAM, network interfaces, threat score
 * GET /api/system/devices  → Enumerated network adapters as linked device list
 */

const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { collectSystemMetrics } = require('../utils/systemMetrics');

const router = express.Router();
router.use(requireAuth);

// Cache metrics briefly to avoid hammering os.cpus() on every poll
let metricsCache = null;
let cacheTimestamp = 0;
const CACHE_TTL_MS = 3000; // 3 second cache

function getFreshMetrics() {
  const now = Date.now();
  if (!metricsCache || now - cacheTimestamp > CACHE_TTL_MS) {
    metricsCache = collectSystemMetrics();
    cacheTimestamp = now;
  }
  return metricsCache;
}

/**
 * GET /api/system/metrics
 * Full system snapshot: CPU, RAM, threat score, network interfaces, findings.
 */
router.get('/metrics', (req, res) => {
  try {
    const metrics = getFreshMetrics();
    // Also update the global lastScanResult so the dashboard threat score reflects real data
    global.lastSystemMetrics = metrics;
    res.json(metrics);
  } catch (err) {
    console.error('[system/metrics] Error collecting metrics:', err);
    res.status(500).json({ error: 'Failed to collect system metrics', detail: err.message });
  }
});

/**
 * GET /api/system/devices
 * Just the linked devices list (network adapters).
 */
router.get('/devices', (req, res) => {
  try {
    const metrics = getFreshMetrics();
    res.json({
      devices: metrics.linkedDevices,
      hostname: metrics.hostname,
      platform: metrics.platform,
      collectedAt: metrics.collectedAt,
    });
  } catch (err) {
    console.error('[system/devices] Error collecting devices:', err);
    res.status(500).json({ error: 'Failed to collect device list' });
  }
});

module.exports = router;
