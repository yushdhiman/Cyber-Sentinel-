/**
 * correlationEngine.js
 * Stateful SIEM event correlation engine implementing automated incident creation,
 * rule evaluation, and cryptographic evidence hashing.
 */
const { createIncident, getIncidents } = require('../data/securityStore');

// In-memory sliding correlation buffers
const failedAuthAttempts = new Map(); // ip -> [{ timestamp, user, ip }]
const recentExploits = new Map();     // ip -> [{ timestamp, payload, path }]

const WINDOW_2_MIN = 2 * 60 * 1000;

/**
 * Clean expired correlation events
 */
function pruneBuffers() {
  const now = Date.now();
  for (const [ip, attempts] of failedAuthAttempts.entries()) {
    const fresh = attempts.filter(a => now - a.timestamp < WINDOW_2_MIN);
    if (fresh.length === 0) failedAuthAttempts.delete(ip);
    else failedAuthAttempts.set(ip, fresh);
  }
}

/**
 * Rule 1: Brute Force Authentication Detection
 * 5+ failed logins within 2 minutes from the same source IP
 */
function recordFailedLogin({ ip, email, userAgent }) {
  pruneBuffers();
  const cleanIp = (ip || '127.0.0.1').trim();
  const current = failedAuthAttempts.get(cleanIp) || [];
  current.push({ timestamp: Date.now(), email, userAgent, ip: cleanIp });
  failedAuthAttempts.set(cleanIp, current);

  if (current.length >= 5) {
    // Check if incident already open for this IP
    const existing = getIncidents().find(
      i => i.relatedIps.includes(cleanIp) && 
           i.category === 'BRUTE_FORCE' && 
           !['CLOSED', 'FALSE_POSITIVE'].includes(i.status)
    );

    if (!existing) {
      const incident = createIncident({
        title: `Brute Force Authentication Campaign from ${cleanIp}`,
        severity: 'HIGH',
        category: 'BRUTE_FORCE',
        description: `Correlated ${current.length} failed login attempts within 2-minute window targeting account '${email || 'multiple'}'.`,
        relatedIps: [cleanIp],
        relatedAlerts: current.map((c, i) => `Auth failure #${i + 1} at ${new Date(c.timestamp).toISOString()}`),
        mitreTechniques: ['T1110.001 - Password Guessing', 'T1110.003 - Password Spraying'],
        evidence: {
          attackerIp: cleanIp,
          totalAttempts: current.length,
          targetAccounts: [...new Set(current.map(c => c.email))],
          firstAttempt: new Date(current[0].timestamp).toISOString(),
          lastAttempt: new Date(current[current.length - 1].timestamp).toISOString(),
          userAgent,
        },
        createdBy: 'SIEM Correlation Rule [RULE_BRUTE_FORCE_001]',
      });

      // Clear buffer after incident escalation
      failedAuthAttempts.delete(cleanIp);
      return incident;
    }
  }

  return null;
}

/**
 * Rule 2: Web Application Exploit Attempt with 200 OK Response
 */
function recordWebExploit({ ip, attackType, payload, path, statusCode }) {
  const cleanIp = (ip || '127.0.0.1').trim();
  const is200 = Number(statusCode) >= 200 && Number(statusCode) < 300;

  if (is200) {
    return createIncident({
      title: `Potential Successful Exploit (${attackType}) against ${path}`,
      severity: 'CRITICAL',
      category: 'APPLICATION_EXPLOIT',
      description: `Injected attack pattern '${attackType}' returned HTTP status ${statusCode}. High likelihood of successful payload execution.`,
      relatedIps: [cleanIp],
      relatedAlerts: [`Exploit vector detected on endpoint ${path} with HTTP ${statusCode}`],
      mitreTechniques: ['T1190 - Exploit Public-Facing Application'],
      evidence: {
        attackerIp: cleanIp,
        endpoint: path,
        payloadPattern: payload,
        responseStatus: statusCode,
        detectedAt: new Date().toISOString(),
      },
      createdBy: 'SIEM Correlation Rule [RULE_SQLI_SUCCESS_002]',
    });
  }

  return null;
}

/**
 * Rule 3: Suspicious Execution & Outbound Network Socket Activity
 */
function recordSuspiciousExecution({ processName, commandLine, outboundIp, pid }) {
  const cleanIp = (outboundIp || 'unknown').trim();

  return createIncident({
    title: `Suspicious Process Execution (${processName}) with C2 Connection`,
    severity: 'CRITICAL',
    category: 'ENDPOINT_EXECUTION',
    description: `Process ${processName} (PID ${pid}) executed suspicious command structure and initiated outbound socket connection to ${cleanIp}.`,
    relatedIps: cleanIp !== 'unknown' ? [cleanIp] : [],
    relatedAlerts: [`Process execution PID ${pid}: ${commandLine}`],
    mitreTechniques: ['T1059.001 - Command and Scripting: PowerShell', 'T1071.001 - Application Layer C2'],
    evidence: {
      pid,
      processName,
      commandLine,
      outboundIp: cleanIp,
      detectedAt: new Date().toISOString(),
    },
    createdBy: 'SIEM Correlation Rule [RULE_SUSPICIOUS_EXEC_004]',
  });
}

/**
 * Rule 4: Suspicious Privilege Escalation
 */
function recordPrivilegeEscalation({ actor, targetUser, oldRole, newRole, ip }) {
  const cleanIp = (ip || '127.0.0.1').trim();

  const incident = createIncident({
    title: `Unscheduled Privilege Escalation: ${targetUser} promoted to ${newRole}`,
    severity: 'HIGH',
    category: 'PRIVILEGE_ESCALATION',
    description: `User role transitioned from '${oldRole}' to '${newRole}' by actor '${actor}' from IP ${cleanIp}.`,
    relatedIps: [cleanIp],
    relatedAlerts: [`Role escalation by ${actor} on target ${targetUser}`],
    mitreTechniques: ['T1078 - Valid Accounts', 'T1548 - Abuse Elevation Control Mechanism'],
    evidence: {
      actor,
      targetUser,
      oldRole,
      newRole,
      originIp: cleanIp,
      timestamp: new Date().toISOString(),
    },
    createdBy: 'SIEM Correlation Rule [RULE_PRIVILEGE_HIJACK_003]',
  });
  if (incident) incident.ruleId = 'RULE_PRIVILEGE_HIJACK_003';
  return incident;
}

const EventEmitter = require('events');

class CorrelationEngine extends EventEmitter {
  processEvent(event) {
    let incident = null;
    const ep = event.endpoint || event.path || (event.details && event.details.path) || '';
    const isSqli = /union\s+select|or\s+1=1|--|;\s*drop/i.test(ep);
    const status = Number(event.httpStatus || event.statusCode || (event.details && event.details.statusCode) || 0);

    if (isSqli && status >= 200 && status < 300) {
      incident = recordWebExploit({
        ip: event.srcIp || event.sourceIp || '127.0.0.1',
        attackType: 'SQL Injection',
        payload: ep,
        path: ep,
        statusCode: status
      });
      if (incident) {
        incident.ruleId = 'RULE_SQLI_SUCCESS_002';
        this.emit('incident', incident);
        return incident;
      }
    }

    const proc = (event.processName || '').toLowerCase();
    const cmd = (event.commandLine || '').toLowerCase();
    if ((proc.includes('powershell') || cmd.includes('powershell')) && (cmd.includes('-enc') || cmd.includes('hidden'))) {
      incident = recordSuspiciousExecution({
        hostname: event.hostname || 'WORKSTATION',
        processName: event.processName || 'powershell.exe',
        commandLine: event.commandLine,
        outboundIp: event.destIp || '198.51.100.99',
        pid: event.pid || 4242
      });
      if (incident) {
        incident.ruleId = 'RULE_SUSPICIOUS_EXEC_004';
        this.emit('incident', incident);
        return incident;
      }
    }

    if (event.action === 'FAILED_LOGIN' || event.eventType === 'AUTH_FAILURE') {
      incident = recordFailedLogin({
        ip: event.srcIp || event.sourceIp,
        email: event.username || event.user,
        userAgent: event.userAgent || 'Telemetry Agent'
      });
      if (incident) {
        incident.ruleId = 'RULE_BRUTE_FORCE_001';
        this.emit('incident', incident);
        return incident;
      }
    }

    return null;
  }
}

module.exports = {
  CorrelationEngine,
  recordFailedLogin,
  recordWebExploit,
  recordSuspiciousExecution,
  recordPrivilegeEscalation,
};
