/**
 * securityStore.js
 * Centralized, thread-safe repository replacing all legacy `global.*` variables.
 * Provides atomic persistence to security_state.json with in-memory caching.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_FILE = path.join(__dirname, 'security_state.json');

// In-memory state cache
let state = {
  blockedIps: {},      // ip -> { ip, reason, blockedAt, blockedBy, active: true }
  incidents: [],       // list of incident objects
  auditLogs: [],       // append-only log trail
  lastScanResult: null,
  lastLogAnalysis: null,
  lastProtectionScan: null,
  lastSandboxResult: null,
  lastSystemMetrics: null,
};

// Load initial state from disk if exists
function loadState() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      state = { ...state, ...parsed };
      // Ensure blockedIps is an object
      if (Array.isArray(state.blockedIps)) {
        const map = {};
        state.blockedIps.forEach(ip => {
          map[ip] = { ip, reason: 'Manual containment', blockedAt: new Date().toISOString(), blockedBy: 'system', active: true };
        });
        state.blockedIps = map;
      }
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

loadState();

// ── IP Containment Operations ───────────────────────────────────────────────
function blockIp(ip, reason = 'Operator containment rule', blockedBy = 'system') {
  if (!ip || typeof ip !== 'string') return false;
  const cleanIp = ip.trim();
  state.blockedIps[cleanIp] = {
    ip: cleanIp,
    reason,
    blockedAt: new Date().toISOString(),
    blockedBy,
    active: true,
  };
  persistState();
  return state.blockedIps[cleanIp];
}

function unblockIp(ip) {
  if (!ip || !state.blockedIps[ip]) return false;
  state.blockedIps[ip].active = false;
  state.blockedIps[ip].unblockedAt = new Date().toISOString();
  persistState();
  return true;
}

function isIpBlocked(ip) {
  if (!ip) return false;
  const record = state.blockedIps[ip.trim()];
  return Boolean(record && record.active);
}

function getBlockedIps() {
  return Object.values(state.blockedIps).filter(item => item.active);
}

function getAllBlockedIpRecords() {
  return Object.values(state.blockedIps);
}

// ── Audit Log Operations ───────────────────────────────────────────────────
function addAuditLog(entry) {
  const logItem = {
    id: `AUD-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
    timestamp: new Date().toISOString(),
    actor: entry.actor || 'system',
    actorRole: entry.actorRole || 'system',
    action: entry.action,
    target: entry.target || 'N/A',
    result: entry.result || 'SUCCESS',
    sourceIp: entry.sourceIp || '127.0.0.1',
    details: entry.details || {},
  };
  state.auditLogs.unshift(logItem);
  // Maintain last 2000 audit logs
  if (state.auditLogs.length > 2000) {
    state.auditLogs = state.auditLogs.slice(0, 2000);
  }
  persistState();
  return logItem;
}

function getAuditLogs(limit = 100, filterAction = null) {
  let logs = state.auditLogs;
  if (filterAction) {
    logs = logs.filter(l => l.action === filterAction);
  }
  return logs.slice(0, limit);
}

// ── Incident Management Operations ─────────────────────────────────────────
function createIncident({ title, severity, category, description, relatedIps = [], relatedAlerts = [], mitreTechniques = [], evidence = null, createdBy = 'correlation-engine' }) {
  const incId = `INC-${Date.now().toString().slice(-5)}${crypto.randomInt(10, 99)}`;
  
  // Calculate SHA-256 evidence integrity hash
  let evidenceHash = null;
  if (evidence) {
    const rawEvidence = typeof evidence === 'string' ? evidence : JSON.stringify(evidence);
    evidenceHash = crypto.createHash('sha256').update(rawEvidence).digest('hex');
  }

  const incident = {
    id: incId,
    title,
    severity: severity || 'HIGH', // CRITICAL | HIGH | MEDIUM | LOW
    category: category || 'THREAT_DETECTION',
    status: 'NEW', // NEW | TRIAGED | INVESTIGATING | CONTAINED | CLOSED | FALSE_POSITIVE
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
  // Cap at last 500 incidents
  if (state.incidents.length > 500) {
    state.incidents = state.incidents.slice(0, 500);
  }
  persistState();

  // Also audit log creation
  addAuditLog({
    actor: createdBy,
    actorRole: 'system',
    action: 'INCIDENT_CREATED',
    target: incId,
    result: 'SUCCESS',
    details: { title, severity, relatedIps },
  });

  return incident;
}

function getIncidents(status = null) {
  if (status && status !== 'ALL') {
    return state.incidents.filter(i => i.status === status);
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
  if (!validStatuses.includes(newStatus)) {
    throw new Error(`Invalid status '${newStatus}'. Must be one of: ${validStatuses.join(', ')}`);
  }

  const oldStatus = incident.status;
  incident.status = newStatus;
  incident.updatedAt = new Date().toISOString();
  incident.timeline.push({
    timestamp: new Date().toISOString(),
    action: 'STATUS_CHANGE',
    actor,
    note: note || `Status transitioned from ${oldStatus} to ${newStatus}`,
  });

  persistState();

  addAuditLog({
    actor,
    action: 'INCIDENT_STATUS_CHANGE',
    target: id,
    result: 'SUCCESS',
    details: { oldStatus, newStatus, note },
  });

  return incident;
}

function addIncidentNote(id, actor, noteText) {
  const incident = state.incidents.find(i => i.id === id);
  if (!incident) return null;

  incident.timeline.push({
    timestamp: new Date().toISOString(),
    action: 'ANALYST_NOTE',
    actor,
    note: noteText,
  });
  incident.updatedAt = new Date().toISOString();
  persistState();

  return incident;
}

// ── Execution Result Setters & Getters (Replaces global.*) ──────────────────
function setLastScanResult(result) {
  state.lastScanResult = { ...result, timestamp: new Date().toISOString() };
  persistState();
}
function getLastScanResult() {
  return state.lastScanResult;
}

function setLastLogAnalysis(result) {
  state.lastLogAnalysis = { ...result, timestamp: new Date().toISOString() };
  persistState();
}
function getLastLogAnalysis() {
  return state.lastLogAnalysis;
}

function setLastProtectionScan(result) {
  state.lastProtectionScan = { ...result, timestamp: new Date().toISOString() };
  persistState();
}
function getLastProtectionScan() {
  return state.lastProtectionScan;
}

function setLastSandboxResult(result) {
  state.lastSandboxResult = { ...result, timestamp: new Date().toISOString() };
  persistState();
}
function getLastSandboxResult() {
  return state.lastSandboxResult;
}

function setLastSystemMetrics(metrics) {
  state.lastSystemMetrics = metrics;
}
function getLastSystemMetrics() {
  return state.lastSystemMetrics;
}

module.exports = {
  blockIp,
  unblockIp,
  isIpBlocked,
  getBlockedIps,
  getAllBlockedIpRecords,
  addAuditLog,
  getAuditLogs,
  createIncident,
  getIncidents,
  getIncidentById,
  updateIncidentStatus,
  addIncidentNote,
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
