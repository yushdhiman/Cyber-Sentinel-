/**
 * realtimeEngine.js
 * Manages Socket.IO real-time broadcasts to all connected clients.
 * Emits live system metrics, attack events, and timeline updates.
 */

const os = require('os');
const { collectSystemMetrics } = require('./systemMetrics');
const { generateLiveAttacks } = require('../data/threatIntel');

// Rolling 24-hour attack volume timeline (48 half-hour buckets)
const TIMELINE_BUCKETS = 24;
let attackTimeline = initTimeline();

function initTimeline() {
  const now = new Date();
  return Array.from({ length: TIMELINE_BUCKETS }, (_, i) => {
    const d = new Date(now - (TIMELINE_BUCKETS - 1 - i) * 30 * 60 * 1000);
    const h = d.getHours().toString().padStart(2, '0');
    const m = d.getMinutes().toString().padStart(2, '0');
    return {
      hour: `${h}:${m}`,
      attacks: Math.floor(Math.random() * 45) + 2,
      blocked: Math.floor(Math.random() * 40) + 2,
    };
  });
}

// Build aggregate stats from metrics + timeline
function buildDashboardSnapshot(metrics) {
  const totalAttacksToday = attackTimeline.reduce((s, b) => s + b.attacks, 0);
  const totalBlockedToday = attackTimeline.reduce((s, b) => s + b.blocked, 0);
  return {
    threatScore: metrics.threatScore,
    riskLevel: metrics.riskLevel,
    cpuUsage: metrics.cpu.usagePercent,
    memoryUsage: metrics.memory.usagePercent,
    hostname: metrics.hostname,
    platform: metrics.platform,
    uptimeDays: metrics.uptimeDays,
    activeDevices: metrics.linkedDevices.filter(d => !d.internal).length,
    networkHealth: Math.max(0, Math.min(100,
      100 - metrics.cpu.usagePercent * 0.4 - metrics.memory.usagePercent * 0.3
    )),
    blockedToday: totalBlockedToday,
    liveAttackCount: totalAttacksToday,
    collectedAt: metrics.collectedAt,
  };
}

function startRealtimeEngine(io) {
  let latestMetrics = null;
  let connectedClients = 0;
  let attackEventCounter = 0;

  io.on('connection', (socket) => {
    connectedClients++;
    console.log(`[RT] Client connected: ${socket.id} (total: ${connectedClients})`);

    // Immediately send current snapshot on connect
    if (latestMetrics) {
      socket.emit('system:metrics', buildDashboardSnapshot(latestMetrics));
      socket.emit('timeline:full', attackTimeline);
      socket.emit('linked:devices', latestMetrics.linkedDevices);
      socket.emit('system:findings', latestMetrics.findings);
    }

    socket.on('disconnect', () => {
      connectedClients--;
      console.log(`[RT] Client disconnected: ${socket.id} (total: ${connectedClients})`);
    });
  });

  // ── INTERVAL 1: System metrics every 2 seconds ──
  setInterval(() => {
    try {
      latestMetrics = collectSystemMetrics();
      global.lastSystemMetrics = latestMetrics;
      const snapshot = buildDashboardSnapshot(latestMetrics);
      io.emit('system:metrics', snapshot);
    } catch (err) {
      console.error('[RT] Metrics collection error:', err.message);
    }
  }, 2000);

  // ── INTERVAL 2: New attack event every 3–7 seconds ──
  function emitNextAttack() {
    const delay = 3000 + Math.random() * 4000; // 3–7 seconds
    setTimeout(() => {
      try {
        const [attack] = generateLiveAttacks(1);
        attack.id = `rt-${++attackEventCounter}-${Date.now()}`;
        attack.timestamp = new Date().toISOString();
        // Bias towards more attacks when CPU is high
        const cpuLoad = latestMetrics?.cpu?.usagePercent ?? 20;
        if (cpuLoad > 70 || Math.random() > 0.4) {
          io.emit('attack:event', attack);
        }
      } catch (err) {
        console.error('[RT] Attack event error:', err.message);
      }
      emitNextAttack(); // schedule next
    }, delay);
  }
  emitNextAttack();

  // ── INTERVAL 3: Push updated timeline bucket every 30 seconds ──
  setInterval(() => {
    const now = new Date();
    const h = now.getHours().toString().padStart(2, '0');
    const m = now.getMinutes().toString().padStart(2, '0');
    const newBucket = {
      hour: `${h}:${m}`,
      attacks: Math.floor(Math.random() * 50) + 5,
      blocked: Math.floor(Math.random() * 45) + 5,
    };
    // Slide window: drop oldest, add newest
    attackTimeline = [...attackTimeline.slice(1), newBucket];
    io.emit('timeline:update', { timeline: attackTimeline, newBucket });
  }, 30000);

  // ── INTERVAL 4: Linked devices scan every 10 seconds ──
  setInterval(() => {
    if (latestMetrics) {
      io.emit('linked:devices', latestMetrics.linkedDevices);
    }
  }, 10000);

  // ── INTERVAL 5: Critical alert check every 5 seconds ──
  setInterval(() => {
    if (!latestMetrics) return;
    const { threatScore, riskLevel, findings } = latestMetrics;
    if (threatScore >= 60) {
      const criticalFindings = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
      if (criticalFindings.length > 0) {
        io.emit('alert:critical', {
          threatScore,
          riskLevel,
          finding: criticalFindings[0],
          timestamp: new Date().toISOString(),
        });
      }
    }
  }, 5000);

  console.log('[RT] Real-time engine started ✓');
}

module.exports = { startRealtimeEngine, getTimeline: () => attackTimeline };
