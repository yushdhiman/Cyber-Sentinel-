/**
 * realtimeEngine.js
 * Manages Socket.IO real-time broadcasts to all connected clients.
 * 
 * DATA SOURCES — all from THIS machine only:
 *  1. system:metrics  → Real CPU, RAM, Disk, Network I/O from your laptop
 *  2. attack:event    → Real active TCP connections on your machine,
 *                       cross-referenced against ThreatFox IOC list in memory
 *  3. timeline        → Cumulative counts of real detected events per 30m bucket
 *  4. linked:devices  → Real network adapters on this machine
 *  5. system:findings → Real security findings from OS scan
 */

const os = require('os');
const { collectSystemMetrics } = require('./systemMetrics');
const { scanLocalConnections, getListeningPorts, getConnectionCount } = require('./localNetworkMonitor');
const { liveThreatPool, getThreatPoolCount, getLastFetchedAt } = require('./liveThreatFetcher');
const {
  blockIp: storeBlockIp,
  isIpBlocked,
  getBlockedIps,
  setLastSystemMetrics,
} = require('../data/securityStore');

// Rolling 24-hour attack volume timeline (24 half-hour buckets)
const TIMELINE_BUCKETS = 24;
let attackTimeline = initTimeline();
let attackHistory  = [];
let sessionAttackCount  = 0;
let sessionBlockedCount = 0;
let severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

// Cache of last local network scan results (to diff new events)
let lastScannedIps = new Set();
let listeningPortsCache = [];
let connectionCountCache = 0;

function initTimeline() {
  const now = new Date();
  return Array.from({ length: TIMELINE_BUCKETS }, (_, i) => {
    const d = new Date(now - (TIMELINE_BUCKETS - 1 - i) * 30 * 60 * 1000);
    return {
      hour:    `${d.getHours().toString().padStart(2,'0')}:${d.getMinutes().toString().padStart(2,'0')}`,
      attacks: 0,
      blocked: 0,
    };
  });
}

// Build aggregate stats from metrics + timeline
function buildDashboardSnapshot(metrics, extraData = {}) {
  const totalAttacks24h = attackTimeline.reduce((s, b) => s + b.attacks, 0);
  const totalBlocked24h = attackTimeline.reduce((s, b) => s + b.blocked, 0);

  const cpuDeduction = metrics.cpu.usagePercent > 80
    ? (metrics.cpu.usagePercent - 80) * 1.0 : metrics.cpu.usagePercent * 0.05;
  const memDeduction = metrics.memory.usagePercent > 90
    ? (metrics.memory.usagePercent - 90) * 0.8 : metrics.memory.usagePercent * 0.02;
  const netHealth = Math.round(Math.max(10, Math.min(100, 100 - cpuDeduction - memDeduction)));

  return {
    threatScore:      metrics.threatScore,
    riskLevel:        metrics.riskLevel,
    cpuUsage:         metrics.cpu.usagePercent,
    cpuCores:         metrics.cpu.cores,
    cpuModel:         metrics.cpu.model,
    memoryUsage:      metrics.memory.usagePercent,
    memoryUsedMb:     metrics.memory.usedMb,
    memoryTotalMb:    metrics.memory.totalMb,
    disk:             metrics.disk || null,
    netIO:            metrics.netIO || null,
    suspiciousProcs:  metrics.suspiciousProcesses || [],
    hostname:         metrics.hostname,
    platform:         metrics.platform,
    arch:             metrics.arch,
    osRelease:        metrics.osRelease,
    uptimeDays:       metrics.uptimeDays,
    uptimeHours:      metrics.uptimeHours || 0,
    uptimeMinutes:    metrics.uptimeMinutes || 0,
    activeDevices:    metrics.linkedDevices.filter(d => !d.internal).length,
    networkHealth:    netHealth,
    blockedToday:     sessionBlockedCount,
    liveAttackCount:  sessionAttackCount,
    totalAttacks24h,
    totalBlocked24h,
    severityCounts:   { ...severityCounts },
    connectionCount:  connectionCountCache,
    listeningPorts:   listeningPortsCache,
    collectedAt:      metrics.collectedAt,
    dataSource: 'LOCAL_MACHINE',
    threatIntelSource: {
      live: getThreatPoolCount() > 0,
      iocCount: getThreatPoolCount(),
      source: 'Local Network Monitor + ThreatFox IOC cross-reference',
      lastSyncedAt: getLastFetchedAt(),
    },
    ...extraData,
  };
}

function startRealtimeEngine(io) {
  let latestMetrics = null;
  let connectedClients = 0;
  let attackEventCounter = 0;
  const blockedIps = new Set();

  // ── CONNECTION HANDLER ──
  io.on('connection', (socket) => {
    connectedClients++;
    console.log(`[RT] Client connected: ${socket.id} (total: ${connectedClients})`);

    socket.on('custom:ping', (cb) => { if (typeof cb === 'function') cb(); });

const { ROLES, normalizeRole } = require('../constants/roles');

    socket.on('attack:block_ip', (data) => {
      const userRole = normalizeRole(socket.user?.role);
      if (!socket.user || ![ROLES.ADMIN, ROLES.SENIOR_ANALYST, ROLES.ANALYST].includes(userRole)) {
        socket.emit('security:unauthorized', { error: 'Containment action denied: requires authenticated analyst or admin privileges.' });
        return;
      }
      if (data?.ip) {
        storeBlockIp(data.ip, `Operator real-time containment (${socket.user?.email || 'authenticated'})`, socket.user?.email || 'operator');
        attackHistory.forEach(a => {
          if (a.sourceIp === data.ip && !a.blocked) {
            a.blocked = true;
            sessionBlockedCount++;
          }
        });
        io.emit('attack:ip_blocked', { ip: data.ip, blockedCount: getBlockedIps().length });
        io.emit('system:metrics', buildDashboardSnapshot(latestMetrics || collectSystemMetrics()));
      }
    });

    socket.on('attack:simulate', async () => {
      const userRole = normalizeRole(socket.user?.role);
      if (!socket.user || ![ROLES.ADMIN, ROLES.SENIOR_ANALYST, ROLES.ANALYST].includes(userRole)) {
        socket.emit('security:unauthorized', { error: 'Simulation scan denied: requires authenticated analyst or admin privileges.' });
        return;
      }
      // On simulate: immediately run a fresh network scan
      try {
        const pool = require('./liveThreatFetcher').liveThreatPool || [];
        const events = await scanLocalConnections(pool);
        events.forEach((attack, idx) => {
          attack.id = `scan-${++attackEventCounter}-${Date.now()}-${idx}`;
          if (isIpBlocked(attack.sourceIp)) attack.blocked = true;
          sessionAttackCount++;
          if (attack.blocked) sessionBlockedCount++;
          severityCounts[attack.severity] = (severityCounts[attack.severity] || 0) + 1;
          attackHistory = [attack, ...attackHistory].slice(0, 60);
          if (attackTimeline.length > 0) {
            attackTimeline[attackTimeline.length - 1].attacks++;
            if (attack.blocked) attackTimeline[attackTimeline.length - 1].blocked++;
          }
          io.emit('attack:event', attack);
        });
        io.emit('system:metrics', buildDashboardSnapshot(latestMetrics || collectSystemMetrics()));
        console.log(`[RT] Manual scan: found ${events.length} suspicious connections`);
      } catch (err) {
        console.error('[RT] Manual scan error:', err.message);
      }
    });

    // Send initial state immediately
    socket.emit('attack:history', attackHistory);
    if (latestMetrics) {
      socket.emit('system:metrics', buildDashboardSnapshot(latestMetrics));
      socket.emit('linked:devices', latestMetrics.linkedDevices);
      socket.emit('system:findings', latestMetrics.findings);
    }
    socket.emit('timeline:full', attackTimeline);
    socket.emit('intel:status', {
      live: true,
      iocCount: getThreatPoolCount(),
      source: 'Local Machine Network Monitor',
      lastSyncedAt: new Date().toISOString(),
      description: `Monitoring real TCP connections on ${os.hostname()} and cross-referencing with ThreatFox IOC database loaded in memory.`,
    });

    socket.on('disconnect', () => {
      connectedClients--;
      console.log(`[RT] Client disconnected: ${socket.id} (total: ${connectedClients})`);
    });
  });

  // ── INTERVAL 1: Real system metrics every 2 seconds ──
  setInterval(async () => {
    try {
      latestMetrics = await collectSystemMetrics();
      setLastSystemMetrics(latestMetrics);
      const snapshot = buildDashboardSnapshot(latestMetrics);
      io.emit('system:metrics', snapshot);
    } catch (err) {
      console.error('[RT] Metrics error:', err.message);
    }
  }, 2000);

  // ── INTERVAL 2: Scan real local network connections every 8 seconds ──
  async function runNetworkScan() {
    try {
      const pool = require('./liveThreatFetcher').liveThreatPool || [];
      const events = await scanLocalConnections(pool);

      // Find NEW connections we haven't reported yet
      const newEvents = events.filter(e => !lastScannedIps.has(e.sourceIp));
      // Update seen IPs cache (expires after 60 seconds to allow re-detection)
      newEvents.forEach(e => lastScannedIps.add(e.sourceIp));
      setTimeout(() => newEvents.forEach(e => lastScannedIps.delete(e.sourceIp)), 60000);

      if (newEvents.length > 0) {
        newEvents.forEach((attack, idx) => {
          attack.id = `local-${++attackEventCounter}-${Date.now()}-${idx}`;
          if (blockedIps.has(attack.sourceIp)) attack.blocked = true;

          sessionAttackCount++;
          if (attack.blocked) sessionBlockedCount++;
          severityCounts[attack.severity] = (severityCounts[attack.severity] || 0) + 1;
          attackHistory = [attack, ...attackHistory].slice(0, 60);

          if (attackTimeline.length > 0) {
            attackTimeline[attackTimeline.length - 1].attacks++;
            if (attack.blocked) attackTimeline[attackTimeline.length - 1].blocked++;
          }

          io.emit('attack:event', attack);
          console.log(`[RT] REAL connection flagged: ${attack.sourceIp} → ${attack.type} [${attack.severity}]`);
        });
      } else {
        console.log(`[RT] Network scan: ${events.length} suspicious IPs found, ${newEvents.length} new since last scan`);
      }
    } catch (err) {
      console.error('[RT] Network scan error:', err.message);
    }
  }

  // Initial scan on startup
  setTimeout(runNetworkScan, 3000);
  setInterval(runNetworkScan, 8000);

  // ── INTERVAL 3: Refresh listening ports + connection count every 15s ──
  async function refreshPortsAndConnections() {
    try {
      const [ports, count] = await Promise.all([getListeningPorts(), getConnectionCount()]);
      listeningPortsCache = ports;
      connectionCountCache = count;
      io.emit('system:ports', { listeningPorts: ports, connectionCount: count });
    } catch {}
  }
  setTimeout(refreshPortsAndConnections, 4000);
  setInterval(refreshPortsAndConnections, 15000);

  // ── INTERVAL 4: Push updated timeline bucket every 30 seconds ──
  setInterval(() => {
    const now = new Date();
    const h = now.getHours().toString().padStart(2, '0');
    const m = now.getMinutes().toString().padStart(2, '0');
    const newBucket = { hour: `${h}:${m}`, attacks: 0, blocked: 0 };
    attackTimeline = [...attackTimeline.slice(1), newBucket];
    io.emit('timeline:update', { timeline: attackTimeline, newBucket });
  }, 30000);

  // ── INTERVAL 5: Linked devices every 10 seconds ──
  setInterval(() => {
    if (latestMetrics) {
      io.emit('linked:devices', latestMetrics.linkedDevices);
    }
  }, 10000);

  // ── INTERVAL 6: Critical alert check every 5 seconds ──
  setInterval(() => {
    if (!latestMetrics) return;
    const { threatScore, riskLevel, findings } = latestMetrics;
    if (threatScore >= 60) {
      const criticalFindings = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
      if (criticalFindings.length > 0) {
        io.emit('alert:critical', {
          threatScore, riskLevel,
          finding: criticalFindings[0],
          timestamp: new Date().toISOString(),
        });
      }
    }
  }, 5000);

  console.log('[RT] Real-time engine started — monitoring LOCAL machine connections ✓');
}

module.exports = { startRealtimeEngine, getTimeline: () => attackTimeline };
