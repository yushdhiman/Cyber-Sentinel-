/**
 * eventNormalizer.js
 * Normalizes heterogeneous incoming event payloads from multiple sources
 * (Endpoint Agent, Windows Event Logs, Syslog, ThreatFox, CISA KEV, Simulator)
 * into the standardized Cyber Sentinel Event Schema.
 */
const crypto = require('crypto');

const EventTypes = {
  AUTH_FAILURE: 'AUTH_FAILURE',
  AUTH_SUCCESS: 'AUTH_SUCCESS',
  NETWORK_CONNECTION: 'NETWORK_CONNECTION',
  PROCESS_EXECUTION: 'PROCESS_EXECUTION',
  FILE_MODIFICATION: 'FILE_MODIFICATION',
  IOC_MATCH: 'IOC_MATCH',
  EXPLOIT_PROBE: 'EXPLOIT_PROBE',
  PORT_SCAN: 'PORT_SCAN',
  SYSTEM_ANOMALY: 'SYSTEM_ANOMALY',
};

/**
 * Normalizes an arbitrary raw event into the canonical format.
 */
function normalizeEvent(raw = {}) {
  const now = new Date().toISOString();
  const eventId = raw.eventId || `evt-${Date.now().toString().slice(-6)}-${crypto.randomBytes(3).toString('hex')}`;
  const timestamp = raw.timestamp || raw.observedAt || now;

  let eventType = (raw.eventType || raw.type || 'SYSTEM_ANOMALY').toUpperCase();
  if (eventType.includes('LOGIN') && eventType.includes('FAIL')) eventType = EventTypes.AUTH_FAILURE;
  if (eventType.includes('LOGIN') && eventType.includes('SUCC')) eventType = EventTypes.AUTH_SUCCESS;
  if (eventType.includes('CONN') || eventType.includes('TCP') || eventType.includes('UDP')) eventType = EventTypes.NETWORK_CONNECTION;
  if (eventType.includes('PROC') || eventType.includes('EXEC') || eventType.includes('POWERSHELL')) eventType = EventTypes.PROCESS_EXECUTION;
  if (eventType.includes('IOC')) eventType = EventTypes.IOC_MATCH;
  if (eventType.includes('SQL') || eventType.includes('XSS') || eventType.includes('EXPLOIT')) eventType = EventTypes.EXPLOIT_PROBE;

  const source = raw.source || raw.dataSource || 'endpoint-agent';
  const deviceId = raw.deviceId || raw.hostname || 'dev-local-node';
  const severity = (raw.severity || 'MEDIUM').toUpperCase();

  // Extract source IP & ports safely
  let sourceIp = raw.sourceIp || raw.remoteIp || raw.ip || null;
  let destPort = raw.destPort || raw.port || null;
  let sourcePort = raw.sourcePort || null;

  if (typeof sourceIp === 'string' && sourceIp.includes(':') && !sourceIp.startsWith('[')) {
    const parts = sourceIp.split(':');
    sourceIp = parts[0];
    destPort = parseInt(parts[1], 10) || destPort;
  }

  return {
    eventId,
    timestamp,
    observedAt: timestamp,
    ingestedAt: now,
    source,
    dataSource: source,
    eventType,
    deviceId,
    hostname: raw.hostname || deviceId,
    processName: raw.processName || raw.details?.processName || null,
    commandLine: raw.commandLine || raw.details?.commandLine || null,
    destIp: raw.destIp || raw.details?.destIp || null,
    severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(severity) ? severity : 'MEDIUM',
    sourceIp: sourceIp || '127.0.0.1',
    destPort: destPort ? Number(destPort) : null,
    sourcePort: sourcePort ? Number(sourcePort) : null,
    user: raw.user || raw.username || raw.email || 'system',
    protocol: (raw.protocol || 'TCP').toUpperCase(),
    details: raw.details || raw.data || {},
    mitreTechnique: raw.mitreTechnique || null,
    isSimulation: Boolean(raw.isSimulation || raw.simulation || source === 'cyber-sentinel-simulator'),
  };
}

module.exports = {
  EventTypes,
  normalizeEvent,
};
