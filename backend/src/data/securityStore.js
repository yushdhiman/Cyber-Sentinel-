/**
 * securityStore.js
 * Centralized, thread-safe repository supporting PostgreSQL with local file persistence.
 * 
 * Manages:
 * - Active firewall containment rules (IP blocklist)
 * - Incident lifecycle and forensic evidence with SHA-256 integrity hashing
 * - Immutable security audit trail
 * - In-memory malware scan histories and real-time state
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { isPostgresConnected, query } = require('./db');

const DATA_FILE = path.join(__dirname, 'security_state.json');

// In-memory state cache
let state = {
  blockedIps: {},      // ip -> { ip, reason, blockedAt, blockedBy, active: true }
  incidents: [],       // list of incident objects
  auditLogs: [],       // append-only log trail
  scans: [],           // malware analysis reports
  lastScanResult: null,
  lastLogAnalysis: null,
  lastProtectionScan: null,
  lastSandboxResult: null,
  lastSystemMetrics: null,
};

async function syncFromPostgres() {
  try {
    if (!isPostgresConnected()) return;

    // 1. Sync Incidents
    const incRes = await query('SELECT * FROM incidents ORDER BY created_at DESC LIMIT 500');
    state.incidents = incRes.rows.map(r => ({
      id: r.id,
      title: r.title,
      severity: r.severity,
      category: r.category,
      status: r.status,
      description: r.description,
      assignee: r.assignee,
      relatedIps: r.related_ips || [],
      relatedAlerts: r.related_alerts || [],
      mitreTechniques: r.mitre_techniques || [],
      evidence: r.evidence || {},
      evidenceHash: r.evidence_hash,
      timeline: r.timeline || [],
      createdAt: r.created_at ? new Date(r.created_at).toISOString() : new Date().toISOString(),
      updatedAt: r.updated_at ? new Date(r.updated_at).toISOString() : new Date().toISOString(),
    }));

    // 2. Sync Firewall Rules
    const fwRes = await query('SELECT * FROM firewall_rules WHERE active = true');
    const fwMap = {};
    fwRes.rows.forEach(r => {
      fwMap[r.ip] = {
        ip: r.ip,
        reason: r.reason,
        blockedAt: r.blocked_at ? new Date(r.blocked_at).toISOString() : new Date().toISOString(),
        blockedBy: r.blocked_by,
        active: r.active,
      };
    });
    state.blockedIps = fwMap;

    // 3. Sync Audit Logs
    const auditRes = await query('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 500');
    state.auditLogs = auditRes.rows.map(r => ({
      id: r.id,
      actor: r.actor,
      actorRole: r.actor_role,
      action: r.action,
      target: r.target,
      result: r.result,
      sourceIp: r.source_ip,
      details: r.details || {},
      timestamp: r.timestamp ? new Date(r.timestamp).toISOString() : new Date().toISOString(),
    }));

    console.log(`[DB] Synchronized security state from PostgreSQL (${state.incidents.length} incidents, ${fwRes.rows.length} blocked IPs).`);
  } catch (err) {
    console.error('[DB] Error syncing security state from PostgreSQL:', err.message);
  }
}

// Load initial state from disk if exists
function loadState() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      state = { ...state, ...parsed };
      if (Array.isArray(state.blockedIps)) {
        const map = {};
        state.blockedIps.forEach(ip => {
          map[ip] = { ip, reason: 'Manual containment', blockedAt: new Date().toISOString(), blockedBy: 'system', active: true };
        });
        state.blockedIps = map;
      }
      if (!Array.isArray(state.scans)) state.scans = [];
    }
  } catch (err) {
    console.warn('[SecurityStore] Error reading state file; initializing fresh store:', err.message);
  }
}

// Persist state atomically
function persistState() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(state, null, 2), 'utf8');
  } catch (err) {
    console.error('[SecurityStore] Failed to write security state:', err.message);
  }
}

// Initial load on import
loadState();

// ── IP Containment Operations ──────────────────────────────────────────────
function blockIp(ip, reason = 'Automated threat containment', blockedBy = 'system') {
  const cleanIp = (ip || '').trim();
  if (!cleanIp) return null;

  const record = {
    ip: cleanIp,
    reason,
    blockedAt: new Date().toISOString(),
    blockedBy,
    active: true,
  };

  state.blockedIps[cleanIp] = record;
  persistState();

  if (isPostgresConnected()) {
    query(
      `INSERT INTO firewall_rules (ip, reason, blocked_at, blocked_by, active)
       VALUES ($1, $2, $3, $4, true)
       ON CONFLICT (ip) DO UPDATE SET
         reason = EXCLUDED.reason,
         blocked_at = EXCLUDED.blocked_at,
         blocked_by = EXCLUDED.blocked_by,
         active = true,
         unblocked_at = NULL`,
      [cleanIp, reason, record.blockedAt, blockedBy]
    ).catch(e => console.error('[DB] Error blocking IP in PostgreSQL:', e.message));
  }

  return record;
}

function unblockIp(ip) {
  const cleanIp = (ip || '').trim();
  if (state.blockedIps[cleanIp]) {
    state.blockedIps[cleanIp].active = false;
    state.blockedIps[cleanIp].unblockedAt = new Date().toISOString();
    delete state.blockedIps[cleanIp];
    persistState();

    if (isPostgresConnected()) {
      query(
        `UPDATE firewall_rules SET active = false, unblocked_at = NOW() WHERE ip = $1`,
        [cleanIp]
      ).catch(e => console.error('[DB] Error unblocking IP in PostgreSQL:', e.message));
    }
    return true;
  }
  return false;
}

function isIpBlocked(ip) {
  const cleanIp = (ip || '').trim();
  const entry = state.blockedIps[cleanIp];
  return Boolean(entry && entry.active);
}

function getBlockedIps() {
  return Object.values(state.blockedIps)
    .filter(item => item.active)
    .map(item => item.ip);
}

function getBlockedRecords() {
  return Object.values(state.blockedIps).filter(item => item.active);
}

// ── Immutable Audit Log Operations ─────────────────────────────────────────
function addAuditLog({ actor, actorRole, action, target, result = 'SUCCESS', sourceIp, details = {} }) {
  const entry = {
    id: `AUDIT-${Date.now().toString().slice(-6)}-${crypto.randomInt(10, 99)}`,
    actor: actor || 'anonymous',
    actorRole: actorRole || 'unauthenticated',
    action,
    target: String(target || 'SYSTEM'),
    result,
    sourceIp: sourceIp || '127.0.0.1',
    details,
    timestamp: new Date().toISOString(),
  };

  state.auditLogs.unshift(entry);
  if (state.auditLogs.length > 1000) {
    state.auditLogs = state.auditLogs.slice(0, 1000);
  }
  persistState();

  if (isPostgresConnected()) {
    query(
      `INSERT INTO audit_logs (id, actor, actor_role, action, target, result, source_ip, details, timestamp)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [entry.id, entry.actor, entry.actorRole, entry.action, entry.target, entry.result, entry.sourceIp, JSON.stringify(entry.details), entry.timestamp]
    ).catch(e => console.error('[DB] Error inserting audit log into PostgreSQL:', e.message));
  }

  return entry;
}

function getAuditLogs(limit = 100) {
  return state.auditLogs.slice(0, limit);
}

// ── Incident Management Operations ─────────────────────────────────────────
function createIncident({ title, severity, category, description, relatedIps = [], relatedAlerts = [], mitreTechniques = [], evidence = null, createdBy = 'correlation-engine' }) {
  const incId = `INC-${Date.now().toString().slice(-5)}${crypto.randomInt(10, 99)}`;
  
  let evidenceHash = null;
  if (evidence) {
    const rawEvidence = typeof evidence === 'string' ? evidence : JSON.stringify(evidence);
    evidenceHash = crypto.createHash('sha256').update(rawEvidence).digest('hex');
  }

  const incident = {
    id: incId,
    title,
    severity: (severity || 'HIGH').toUpperCase(),
    category: category || 'THREAT_DETECTION',
    status: 'NEW',
    description,
    assignee: 'Unassigned',
    relatedIps: Array.isArray(relatedIps) ? relatedIps : [relatedIps],
    relatedAlerts: Array.isArray(relatedAlerts) ? relatedAlerts : [relatedAlerts],
    mitreTechniques: Array.isArray(mitreTechniques) ? mitreTechniques : [mitreTechniques],
    evidence: {
      payload: evidence,
      sha256: evidenceHash,
      preservedAt: new Date().toISOString(),
    },
    evidenceHash: evidenceHash,
    timeline: [
      {
        timestamp: new Date().toISOString(),
        action: 'INCIDENT_CREATED',
        actor: createdBy,
        note: `Incident automatically flagged and correlated: ${title}`,
      }
    ],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  state.incidents.unshift(incident);
  if (state.incidents.length > 500) {
    state.incidents = state.incidents.slice(0, 500);
  }
  persistState();

  if (isPostgresConnected()) {
    query(
      `INSERT INTO incidents (id, title, severity, category, status, description, assignee, related_ips, related_alerts, mitre_techniques, evidence, evidence_hash, timeline, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
      [
        incident.id,
        incident.title,
        incident.severity,
        incident.category,
        incident.status,
        incident.description,
        incident.assignee,
        JSON.stringify(incident.relatedIps),
        JSON.stringify(incident.relatedAlerts),
        JSON.stringify(incident.mitreTechniques),
        JSON.stringify(incident.evidence),
        incident.evidenceHash,
        JSON.stringify(incident.timeline),
        incident.createdAt,
        incident.updatedAt
      ]
    ).catch(e => console.error('[DB] Error inserting incident into PostgreSQL:', e.message));
  }

  return incident;
}

function getIncidents(status = null) {
  if (status && status !== 'ALL') {
    return state.incidents.filter(i => (i.status || '').toUpperCase() === status.toUpperCase());
  }
  return state.incidents;
}

function getIncidentById(id) {
  return state.incidents.find(i => i.id === id) || null;
}

function updateIncidentStatus(id, newStatus, actor = 'analyst', note = '') {
  const incident = state.incidents.find(i => i.id === id);
  if (!incident) return null;

  const validStatuses = ['NEW', 'TRIAGED', 'INVESTIGATING', 'CONTAINED', 'CLOSED', 'FALSE_POSITIVE'];
  const upperStatus = newStatus.toUpperCase();
  if (!validStatuses.includes(upperStatus)) {
    throw new Error(`Invalid status '${newStatus}'. Must be one of: ${validStatuses.join(', ')}`);
  }

  const oldStatus = incident.status;
  incident.status = upperStatus;
  incident.updatedAt = new Date().toISOString();
  incident.timeline.push({
    timestamp: new Date().toISOString(),
    action: 'STATUS_CHANGE',
    actor,
    note: note || `Status transitioned from ${oldStatus} to ${upperStatus}`,
  });
  persistState();

  if (isPostgresConnected()) {
    query(
      `UPDATE incidents SET status = $1, timeline = $2, updated_at = NOW() WHERE id = $3`,
      [incident.status, JSON.stringify(incident.timeline), id]
    ).catch(e => console.error('[DB] Error updating incident status in PostgreSQL:', e.message));
  }

  return incident;
}

// ── Malware Scan Reports ───────────────────────────────────────────────────
function addScan(scan) {
  if (!state.scans) state.scans = [];
  state.scans.unshift(scan);
  if (state.scans.length > 200) {
    state.scans = state.scans.slice(0, 200);
  }
  persistState();

  if (isPostgresConnected()) {
    query(
      `INSERT INTO malware_scans (id, filename, sha256, score, severity, details, analyzed_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (id) DO NOTHING`,
      [scan.id, scan.filename, scan.sha256, scan.score, scan.severity, JSON.stringify(scan.details || {}), scan.analyzedAt || new Date().toISOString()]
    ).catch(e => console.error('[DB] Error inserting malware scan into PostgreSQL:', e.message));
  }

  return scan;
}

function getScans() {
  return state.scans || [];
}

// ── Volatile Module Snapshots ───────────────────────────────────────────────
function setLastScanResult(data)       { state.lastScanResult = data; }
function getLastScanResult()           { return state.lastScanResult; }
function setLastLogAnalysis(data)      { state.lastLogAnalysis = data; }
function getLastLogAnalysis()          { return state.lastLogAnalysis; }
function setLastProtectionScan(data)   { state.lastProtectionScan = data; }
function getLastProtectionScan()       { return state.lastProtectionScan; }
function setLastSandboxResult(data)    { state.lastSandboxResult = data; }
function getLastSandboxResult()        { return state.lastSandboxResult; }
function setLastSystemMetrics(data)    { state.lastSystemMetrics = data; }
function getLastSystemMetrics()        { return state.lastSystemMetrics; }

module.exports = {
  syncFromPostgres,
  blockIp,
  unblockIp,
  isIpBlocked,
  getBlockedIps,
  getBlockedRecords,
  addAuditLog,
  getAuditLogs,
  createIncident,
  getIncidents,
  getIncidentById,
  updateIncidentStatus,
  addScan,
  getScans,
  setLastScanResult,
  getLastScanResult,
  setLastLogAnalysis,
  getLastLogAnalysis,
  setLastProtectionScan,
  getLastProtectionScan,
  setLastSandboxResult,
  getLastSandboxResult,
  setLastSystemMetrics,
  getLastSystemMetrics,
};
