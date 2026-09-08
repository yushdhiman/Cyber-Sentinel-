/**
 * agentTools.js
 * Sentinel Agent — Tool Registry (v2.0 — Full Action Suite)
 *
 * 18 callable tools for the ReAct agentic loop:
 *   READ tools  (8): Fetch live data from the platform
 *   ACTION tools (10): Actively trigger operations, run scans, block IPs, etc.
 *
 * Tool Registry format:
 *   { name, description, parameters, fn }
 *
 * executeTool(name, params) now supports parameterized tool calls.
 */

// ═══════════════════════════════════════════════════════════════════════════════
// READ TOOLS — Fetch live platform data
// ═══════════════════════════════════════════════════════════════════════════════

// ── Tool: get_system_status ───────────────────────────────────────────────────
function get_system_status() {
  try {
    const m = global.lastSystemMetrics;
    if (!m) return { error: 'System metrics not yet available. The real-time engine may still be initialising.' };

    const findings = (m.findings || []).map(f => ({
      severity: f.severity,
      title: f.title,
      detail: f.detail,
    }));

    const suspiciousProcs = (m.suspiciousProcesses || []).slice(0, 5).map(p => ({
      name: p.name,
      pid: p.pid,
      cpuPercent: p.cpuPercent,
    }));

    return {
      hostname: m.hostname,
      platform: m.platform,
      arch: m.arch,
      uptimeDays: m.uptimeDays,
      uptimeHours: m.uptimeHours,
      cpu: {
        model: m.cpu?.model,
        cores: m.cpu?.cores,
        usagePercent: m.cpu?.usagePercent,
      },
      memory: {
        usedMb: m.memory?.usedMb,
        totalMb: m.memory?.totalMb,
        usagePercent: m.memory?.usagePercent,
      },
      disk: m.disk
        ? { path: m.disk.path, usagePercent: m.disk.usagePercent, usedGb: m.disk.usedGb, totalGb: m.disk.totalGb }
        : null,
      netIO: m.netIO
        ? { rxMbps: m.netIO.rxMbps, txMbps: m.netIO.txMbps }
        : null,
      threatScore: m.threatScore,
      riskLevel: m.riskLevel,
      findings,
      suspiciousProcesses: suspiciousProcs,
    };
  } catch (err) {
    return { error: `Failed to read system metrics: ${err.message}` };
  }
}

// ── Tool: get_attack_feed ─────────────────────────────────────────────────────
function get_attack_feed() {
  try {
    const engine = require('./realtimeEngine');
    const timeline = engine.getTimeline() || [];
    const totalAttacks = timeline.reduce((s, b) => s + (b.attacks || 0), 0);
    const totalBlocked = timeline.reduce((s, b) => s + (b.blocked || 0), 0);
    const blockRate = totalAttacks > 0 ? Math.round((totalBlocked / totalAttacks) * 100) : 0;

    const recentBuckets = timeline.slice(-6).map(b => ({
      time: b.time,
      attacks: b.attacks,
      blocked: b.blocked,
      topTypes: b.topTypes || [],
    }));

    return {
      totalAttacks24h: totalAttacks,
      totalBlocked24h: totalBlocked,
      blockRatePercent: blockRate,
      recentBuckets,
      summary: `${totalAttacks} attacks detected in the last 24h, ${totalBlocked} blocked (${blockRate}% block rate).`,
    };
  } catch (err) {
    return { error: `Failed to read attack feed: ${err.message}` };
  }
}

// ── Tool: get_threat_intel ────────────────────────────────────────────────────
function get_threat_intel() {
  try {
    const { getThreatPoolCount, getLastFetchedAt, liveThreatPool } = require('./liveThreatFetcher');
    const count = getThreatPoolCount();
    const lastSync = getLastFetchedAt();
    const topFamilies = [...new Set(
      liveThreatPool.slice(0, 50).map(t => t.malware).filter(Boolean)
    )].slice(0, 8);

    const topIPIOCs = liveThreatPool
      .filter(t => t.iocType === 'ip:port' || t.iocType === 'ip')
      .slice(0, 5)
      .map(t => ({ ioc: t.ioc, malware: t.malware, confidence: t.confidence }));

    return {
      iocCount: count,
      lastSyncedAt: lastSync ? new Date(lastSync).toLocaleString() : 'Pending',
      source: 'ThreatFox (abuse.ch) + CISA KEV',
      topMalwareFamilies: topFamilies,
      sampleIPIOCs: topIPIOCs,
      summary: `${count} IOCs loaded from ThreatFox + CISA KEV. Top malware families: ${topFamilies.slice(0, 4).join(', ')}.`,
    };
  } catch (err) {
    return { error: `Failed to read threat intel: ${err.message}` };
  }
}

// ── Tool: get_vuln_scan ───────────────────────────────────────────────────────
function get_vuln_scan() {
  try {
    const result = global.lastScanResult;
    if (!result) {
      return {
        available: false,
        message: 'No vulnerability scan has been run yet. Use run_vulnerability_scan to trigger one now.',
      };
    }

    const issues = (result.issues || []).map(i => ({
      severity: i.severity,
      title: i.title,
      cve: i.cve || null,
      description: i.description,
      recommendation: i.recommendation,
    }));

    const critical = issues.filter(i => i.severity === 'CRITICAL');
    const high = issues.filter(i => i.severity === 'HIGH');
    const medium = issues.filter(i => i.severity === 'MEDIUM');

    return {
      available: true,
      riskScore: result.riskScore,
      riskLevel: result.riskLevel,
      scannedAt: result.scannedAt,
      totalIssues: issues.length,
      criticalCount: critical.length,
      highCount: high.length,
      mediumCount: medium.length,
      criticalIssues: critical.slice(0, 5),
      highIssues: high.slice(0, 5),
      allIssues: issues,
      summary: `Risk score ${result.riskScore}/100 (${result.riskLevel}). ${critical.length} critical, ${high.length} high, ${medium.length} medium issues found.`,
    };
  } catch (err) {
    return { error: `Failed to read vuln scan: ${err.message}` };
  }
}

// ── Tool: get_log_analysis ────────────────────────────────────────────────────
function get_log_analysis() {
  try {
    const result = global.lastLogAnalysis;
    if (!result) {
      return {
        available: false,
        message: 'No log analysis has been run yet. Ask the user to paste logs in the Log Analyzer page.',
      };
    }

    const findings = (result.findings || []).slice(0, 10).map(f => ({
      severity: f.severity,
      title: f.title,
      detail: f.detail,
      count: f.count,
    }));

    const categories = Object.entries(result.summary?.categories || {})
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([name, count]) => ({ name, count }));

    return {
      available: true,
      totalEvents: result.summary?.totalEvents,
      threatCount: result.summary?.threatCount,
      criticalCount: result.summary?.criticalCount,
      topCategories: categories,
      keyFindings: findings,
      summary: `${result.summary?.totalEvents} events scanned, ${result.summary?.threatCount} threats, ${result.summary?.criticalCount} critical.`,
    };
  } catch (err) {
    return { error: `Failed to read log analysis: ${err.message}` };
  }
}

// ── Tool: get_protection_scan ─────────────────────────────────────────────────
function get_protection_scan() {
  try {
    const result = global.lastProtectionScan;
    if (!result) {
      return {
        available: false,
        message: 'No protection scan has been run yet. Use scan_url_or_email to trigger one now.',
      };
    }
    return {
      available: true,
      scanType: result.scanType,
      verdict: result.verdict,
      severity: result.severity,
      summary: result.summary,
      indicators: result.indicators || [],
      scannedAt: result.scannedAt,
    };
  } catch (err) {
    return { error: `Failed to read protection scan: ${err.message}` };
  }
}

// ── Tool: get_sandbox_result ──────────────────────────────────────────────────
function get_sandbox_result() {
  try {
    const result = global.lastSandboxResult;
    if (!result) {
      return {
        available: false,
        message: 'No sandbox simulation has been run yet. Use run_sandbox_attack to launch one.',
      };
    }
    return {
      available: true,
      attackType: result.type,
      status: result.status,
      blocked: result.blocked,
      payload: result.payload,
      wafDecision: result.blocked ? 'BLOCKED — WAF is effective' : 'PASSED — Payload evaded WAF',
      analysisSteps: result.steps || [],
      summary: `${result.type?.toUpperCase()} attack simulation. WAF ${result.blocked ? 'BLOCKED' : 'DID NOT BLOCK'} the payload.`,
    };
  } catch (err) {
    return { error: `Failed to read sandbox result: ${err.message}` };
  }
}

// ── Tool: get_network_connections ─────────────────────────────────────────────
async function get_network_connections() {
  try {
    const { scanLocalConnections } = require('./localNetworkMonitor');
    const { liveThreatPool } = require('./liveThreatFetcher');
    const events = await scanLocalConnections(liveThreatPool || []);
    const suspicious = events.slice(0, 10).map(e => ({
      sourceIp: e.sourceIp,
      type: e.type,
      severity: e.severity,
      blocked: e.blocked,
      malware: e.malware || null,
    }));
    return {
      total: events.length,
      suspiciousConnections: suspicious,
      summary: `${events.length} suspicious connections detected on this machine via local TCP scan.`,
    };
  } catch (err) {
    return { error: `Failed to scan network connections: ${err.message}` };
  }
}

// ── Tool: get_listening_ports ─────────────────────────────────────────────────
async function get_listening_ports() {
  try {
    const { getListeningPorts, getConnectionCount } = require('./localNetworkMonitor');
    const [ports, count] = await Promise.all([getListeningPorts(), getConnectionCount()]);
    return {
      listeningPorts: ports,
      totalPortCount: ports.length,
      activeConnectionCount: count,
      riskPorts: ports.filter(p => [21, 22, 23, 25, 3389, 5900, 6379, 27017, 5432, 3306].includes(p.port)),
      summary: `${ports.length} listening ports, ${count} active connections. ${ports.filter(p => [21,22,23,3389].includes(p.port)).length} high-risk service ports open.`,
    };
  } catch (err) {
    return { error: `Failed to get listening ports: ${err.message}` };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ACTION TOOLS — Trigger platform operations
// ═══════════════════════════════════════════════════════════════════════════════

// ── Tool: run_vulnerability_scan ──────────────────────────────────────────────
async function run_vulnerability_scan() {
  try {
    const scanner = require('./scanner');
    if (typeof scanner.runScan === 'function') {
      const result = await scanner.runScan();
      global.lastScanResult = result;
      return {
        triggered: true,
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
        totalIssues: result.issues?.length,
        criticalCount: result.issues?.filter(i => i.severity === 'CRITICAL').length,
        highCount: result.issues?.filter(i => i.severity === 'HIGH').length,
        mediumCount: result.issues?.filter(i => i.severity === 'MEDIUM').length,
        topIssues: (result.issues || []).slice(0, 6).map(i => ({
          severity: i.severity,
          title: i.title,
          cve: i.cve || null,
          recommendation: i.recommendation,
        })),
        summary: `✅ Scan complete. Risk: ${result.riskScore}/100 (${result.riskLevel}). ${result.issues?.filter(i => i.severity === 'CRITICAL').length || 0} critical issues found.`,
      };
    }

    // Heuristic fallback from live system metrics
    const m = global.lastSystemMetrics;
    if (!m) return { triggered: false, error: 'No system metrics available for quick check.' };

    const issues = [];
    if (m.cpu?.usagePercent > 90) issues.push({ severity: 'HIGH', title: 'CPU usage critically high', recommendation: 'Investigate high-CPU processes and kill suspicious ones.' });
    if (m.memory?.usagePercent > 90) issues.push({ severity: 'HIGH', title: 'Memory usage critically high', recommendation: 'Free memory by closing unnecessary applications or increasing RAM.' });
    if (m.disk?.usagePercent > 90) issues.push({ severity: 'MEDIUM', title: 'Disk nearly full', recommendation: 'Delete temporary files and expand storage capacity.' });
    if (m.threatScore > 70) issues.push({ severity: 'CRITICAL', title: 'Threat score dangerously high', recommendation: 'Investigate all active connections and review firewall rules immediately.' });
    (m.suspiciousProcesses || []).forEach(p =>
      issues.push({ severity: 'HIGH', title: `Suspicious process: ${p.name} (PID ${p.pid})`, recommendation: `Kill process ${p.pid} if not recognized.` })
    );

    global.lastScanResult = { riskScore: m.threatScore, riskLevel: m.riskLevel, issues, scannedAt: new Date().toISOString() };

    return {
      triggered: true,
      type: 'heuristic',
      riskScore: m.threatScore,
      riskLevel: m.riskLevel,
      issueCount: issues.length,
      topIssues: issues.slice(0, 6),
      summary: `✅ Quick scan complete. ${issues.length} issue(s) found from live system metrics. Threat score: ${m.threatScore}/100.`,
    };
  } catch (err) {
    return { triggered: false, error: `Vulnerability scan failed: ${err.message}` };
  }
}

// ── Tool: run_network_scan ────────────────────────────────────────────────────
async function run_network_scan() {
  try {
    const { scanLocalConnections, getListeningPorts } = require('./localNetworkMonitor');
    const { liveThreatPool } = require('./liveThreatFetcher');

    const [events, ports] = await Promise.all([
      scanLocalConnections(liveThreatPool || []),
      getListeningPorts(),
    ]);

    const critical = events.filter(e => e.severity === 'CRITICAL');
    const high = events.filter(e => e.severity === 'HIGH');

    return {
      triggered: true,
      totalSuspicious: events.length,
      criticalCount: critical.length,
      highCount: high.length,
      listeningPorts: ports.length,
      topThreats: events.slice(0, 8).map(e => ({
        sourceIp: e.sourceIp,
        type: e.type,
        severity: e.severity,
        malware: e.malware || 'Unknown',
        blocked: e.blocked,
      })),
      riskPorts: ports.filter(p => [21, 22, 23, 3389, 5900].includes(p.port)),
      summary: `✅ Network scan complete. ${events.length} suspicious IPs flagged, ${critical.length} critical. ${ports.length} ports listening.`,
    };
  } catch (err) {
    return { triggered: false, error: `Network scan failed: ${err.message}` };
  }
}

// ── Tool: run_sandbox_attack ──────────────────────────────────────────────────
async function run_sandbox_attack(params = {}) {
  try {
    const { type = 'sqli', payload, securityEnabled = false } = params;

    const ATTACK_TYPES = ['sqli', 'xss', 'cmd'];
    if (!ATTACK_TYPES.includes(type)) {
      return { error: `Invalid attack type "${type}". Choose from: sqli, xss, cmd.` };
    }

    const defaultPayloads = {
      sqli: "' OR '1'='1' --",
      xss: "<script>alert('XSS')</script>",
      cmd: "127.0.0.1; whoami",
    };
    const finalPayload = payload || defaultPayloads[type];

    const logs = [];
    let blocked = false;
    let status = 'SUCCESS';
    let executionResult = '';
    const ts = () => new Date().toLocaleTimeString();

    logs.push(`[${ts()}] INFO: AI-triggered ${type.toUpperCase()} simulation initiated.`);
    logs.push(`[${ts()}] INFO: Payload: ${finalPayload}`);

    // WAF Check
    if (securityEnabled) {
      logs.push(`[${ts()}] WAF: Inspecting payload...`);
      let wafTriggered = false;
      if (type === 'sqli') wafTriggered = /('|--|select|union|insert|delete|update|drop|or\s+\d+=\d+)/i.test(finalPayload);
      else if (type === 'xss') wafTriggered = /(<script|javascript:|onerror|onload|alert|<img)/i.test(finalPayload);
      else if (type === 'cmd') wafTriggered = /(&|\||;|\$|>|<|`|cat|ls|pwd|whoami|sh|bash)/i.test(finalPayload);

      if (wafTriggered) {
        logs.push(`[${ts()}] WAF: BLOCK — Malicious pattern matched.`);
        blocked = true;
        status = 'BLOCKED';
        executionResult = 'WAF BLOCKED the request (HTTP 403 Forbidden).';
      } else {
        logs.push(`[${ts()}] WAF: PASS — No threat pattern matched.`);
      }
    } else {
      logs.push(`[${ts()}] WARNING: WAF disabled — payload will execute unfiltered.`);
    }

    if (!blocked) {
      if (type === 'sqli') {
        const lower = finalPayload.toLowerCase();
        if (lower.includes('or') || lower.includes('union') || lower.includes('--') || lower.includes("'")) {
          executionResult = JSON.stringify([
            { id: 1, username: 'admin', email: 'admin@sentinel.internal', role: 'SuperAdministrator' },
            { id: 2, username: 'db_owner', email: 'db_owner@sentinel.internal', role: 'DBA' },
          ], null, 2);
          logs.push(`[${ts()}] DB: SQL INJECTED — 2 records leaked from database!`);
        } else {
          executionResult = 'No records matched.';
        }
      } else if (type === 'xss') {
        executionResult = `RENDERED: <div>${finalPayload}</div>\n⚠️ XSS executed — session cookie hijacked!`;
        logs.push(`[${ts()}] BROWSER: Inline script injected and executed.`);
      } else if (type === 'cmd') {
        executionResult = finalPayload.includes(';') || finalPayload.includes('|')
          ? `nt authority\\system\n[Shell injection executed successfully]`
          : `PING output: 1 packets transmitted, 0% packet loss.`;
        logs.push(`[${ts()}] SHELL: Command executed${finalPayload.includes(';') ? ' with injection' : ''}.`);
      }
    }

    const result = { type, payload: finalPayload, securityEnabled, blocked, status, logs, executionResult };
    global.lastSandboxResult = result;

    return {
      triggered: true,
      attackType: type,
      payload: finalPayload,
      securityEnabled,
      blocked,
      status,
      wafDecision: blocked ? '🛡️ BLOCKED by WAF' : '❌ EVADED WAF — payload executed',
      executionResult,
      logs: logs.slice(-6),
      summary: `✅ Sandbox simulation complete. ${type.toUpperCase()} attack ${blocked ? 'was BLOCKED by the WAF' : 'EVADED the WAF and executed'}.`,
    };
  } catch (err) {
    return { triggered: false, error: `Sandbox simulation failed: ${err.message}` };
  }
}

// ── Tool: block_ip_address ────────────────────────────────────────────────────
function block_ip_address(params = {}) {
  try {
    const { ip } = params;
    if (!ip) {
      // Auto-block most suspicious IP from attack history
      const m = global.lastSystemMetrics;
      const suspicious = m?.suspiciousProcesses?.[0];
      return {
        triggered: false,
        error: 'No IP provided. Please specify an IP address to block. Example: {"ip": "192.168.1.100"}',
        hint: 'Use get_network_connections first to find suspicious IPs.',
      };
    }

    // IP format validation
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) {
      return { triggered: false, error: `Invalid IP format: "${ip}". Must be IPv4 like 1.2.3.4.` };
    }

    // Store in global blocked list (picked up by realtime engine on next event)
    if (!global.blockedIPs) global.blockedIPs = new Set();
    global.blockedIPs.add(ip);

    return {
      triggered: true,
      blockedIp: ip,
      action: 'FIREWALL_BLOCK',
      method: 'Sentinel Real-time Engine IP Blocklist',
      timestamp: new Date().toISOString(),
      totalBlocked: global.blockedIPs.size,
      summary: `✅ IP ${ip} has been added to the Sentinel blocklist. Future connections from this IP will be flagged as blocked.`,
    };
  } catch (err) {
    return { triggered: false, error: `Block IP failed: ${err.message}` };
  }
}

// ── Tool: scan_url_or_email ───────────────────────────────────────────────────
async function scan_url_or_email(params = {}) {
  try {
    const { target, type = 'url' } = params;
    if (!target) {
      return { triggered: false, error: 'No target provided. Specify {"target": "https://...", "type": "url"} or {"target": "user@example.com", "type": "email"}.' };
    }

    const { liveThreatPool } = require('./liveThreatFetcher');

    // Check against IOC pool
    const lowerTarget = target.toLowerCase();
    const iocMatch = liveThreatPool.find(t =>
      t.ioc && lowerTarget.includes(t.ioc.toLowerCase().split(':')[0])
    );

    const indicators = [];
    let verdict = 'CLEAN';
    let severity = 'LOW';

    if (iocMatch) {
      verdict = 'MALICIOUS';
      severity = 'CRITICAL';
      indicators.push({
        type: 'IOC_MATCH',
        detail: `Matched ThreatFox IOC: ${iocMatch.ioc} (${iocMatch.malware})`,
        confidence: iocMatch.confidence || 'HIGH',
      });
    }

    // Heuristic checks
    const suspiciousPatterns = ['phish', 'login-secure', 'verify-account', 'update-billing', 'account-locked', '.xyz', '.tk', '.ml'];
    suspiciousPatterns.forEach(p => {
      if (lowerTarget.includes(p)) {
        verdict = verdict === 'MALICIOUS' ? 'MALICIOUS' : 'SUSPICIOUS';
        severity = verdict === 'MALICIOUS' ? 'CRITICAL' : 'HIGH';
        indicators.push({ type: 'HEURISTIC', detail: `Suspicious pattern detected: "${p}"` });
      }
    });

    if (type === 'email' && !target.includes('@')) {
      indicators.push({ type: 'FORMAT', detail: 'Invalid email format detected.' });
      verdict = 'SUSPICIOUS';
    }

    const result = {
      scanType: type,
      target,
      verdict,
      severity,
      summary: `${type.toUpperCase()} scan of "${target}": ${verdict} (${severity})`,
      indicators,
      scannedAt: new Date().toISOString(),
    };
    global.lastProtectionScan = result;

    return {
      triggered: true,
      target,
      scanType: type,
      verdict,
      severity,
      indicators,
      summary: `✅ Scan complete. "${target}" is ${verdict}${indicators.length > 0 ? ` — ${indicators[0].detail}` : ' — no threats detected'}.`,
    };
  } catch (err) {
    return { triggered: false, error: `Protection scan failed: ${err.message}` };
  }
}

// ── Tool: fetch_cve_details ───────────────────────────────────────────────────
function fetch_cve_details(params = {}) {
  try {
    const { cve_id } = params;
    const { getLiveCves } = require('./liveThreatFetcher');
    const cves = getLiveCves() || [];

    if (cve_id) {
      const match = cves.find(c => c.cveID?.toLowerCase() === cve_id.toLowerCase());
      if (match) {
        return {
          found: true,
          cveID: match.cveID,
          product: match.product,
          vendor: match.vendor,
          description: match.shortDescription || match.description,
          dateAdded: match.dateAdded,
          dueDate: match.dueDate,
          severity: 'HIGH', // CISA KEV entries are all actively exploited
          remediationGuidance: match.notes || 'Apply vendor patch immediately. This vulnerability is actively exploited in the wild.',
          summary: `CVE ${match.cveID} affects ${match.vendor} ${match.product}. Listed on CISA KEV — actively exploited.`,
        };
      }
      return { found: false, cve_id, message: `${cve_id} not found in the current CISA KEV list. It may not be actively exploited yet.` };
    }

    // Return top CVEs
    const top = cves.slice(0, 8).map(c => ({
      cveID: c.cveID,
      product: `${c.vendor} ${c.product}`,
      dateAdded: c.dateAdded,
    }));

    return {
      totalCVEs: cves.length,
      source: 'CISA Known Exploited Vulnerabilities (KEV)',
      topCVEs: top,
      summary: `${cves.length} CVEs loaded from CISA KEV. Top entry: ${cves[0]?.cveID} (${cves[0]?.vendor} ${cves[0]?.product}).`,
    };
  } catch (err) {
    return { error: `Failed to fetch CVE details: ${err.message}` };
  }
}

// ── Tool: generate_incident_report ────────────────────────────────────────────
async function generate_incident_report() {
  try {
    const m = global.lastSystemMetrics;
    const scanResult = global.lastScanResult;
    const logAnalysis = global.lastLogAnalysis;
    const protection = global.lastProtectionScan;
    const sandbox = global.lastSandboxResult;

    const engine = require('./realtimeEngine');
    const timeline = engine.getTimeline() || [];
    const totalAttacks = timeline.reduce((s, b) => s + (b.attacks || 0), 0);
    const totalBlocked = timeline.reduce((s, b) => s + (b.blocked || 0), 0);

    const { getThreatPoolCount } = require('./liveThreatFetcher');

    const overallRisk = m?.riskLevel || scanResult?.riskLevel || 'UNKNOWN';
    const overallScore = m?.threatScore || scanResult?.riskScore || 0;

    const sections = {
      executive_summary: {
        timestamp: new Date().toISOString(),
        riskLevel: overallRisk,
        threatScore: overallScore,
        attacks24h: totalAttacks,
        blocked24h: totalBlocked,
        blockRate: totalAttacks > 0 ? Math.round((totalBlocked / totalAttacks) * 100) : 0,
        iocCount: getThreatPoolCount(),
        hostname: m?.hostname || 'Unknown',
        platform: m?.platform || 'Unknown',
      },
      system_health: m ? {
        cpu: m.cpu?.usagePercent + '%',
        memory: m.memory?.usagePercent + '%',
        disk: m.disk?.usagePercent + '%' || 'N/A',
        uptime: `${m.uptimeDays}d ${m.uptimeHours}h`,
        findings: (m.findings || []).map(f => `[${f.severity}] ${f.title}`),
        suspiciousProcs: (m.suspiciousProcesses || []).map(p => p.name),
      } : null,
      vulnerabilities: scanResult ? {
        riskScore: scanResult.riskScore,
        riskLevel: scanResult.riskLevel,
        totalIssues: scanResult.issues?.length,
        critical: scanResult.issues?.filter(i => i.severity === 'CRITICAL').length,
        high: scanResult.issues?.filter(i => i.severity === 'HIGH').length,
        topCVEs: (scanResult.issues || []).filter(i => i.cve).slice(0, 3).map(i => i.cve),
      } : null,
      log_analysis: logAnalysis ? {
        totalEvents: logAnalysis.summary?.totalEvents,
        threats: logAnalysis.summary?.threatCount,
        critical: logAnalysis.summary?.criticalCount,
        topCategories: Object.entries(logAnalysis.summary?.categories || {}).slice(0, 4).map(([k, v]) => `${k}: ${v}`),
      } : null,
      protection_scan: protection ? {
        target: protection.target || 'Last scanned target',
        verdict: protection.verdict,
        severity: protection.severity,
      } : null,
      sandbox_test: sandbox ? {
        attackType: sandbox.type,
        payload: sandbox.payload,
        wafBlocked: sandbox.blocked,
        status: sandbox.status,
      } : null,
      recommendations: [
        overallScore > 70 && '🔴 CRITICAL: Threat score is dangerously high — immediate investigation required.',
        totalAttacks > 100 && '🟠 HIGH: Large volume of attacks detected — review firewall rules and block suspicious IPs.',
        scanResult?.issues?.filter(i => i.severity === 'CRITICAL').length > 0 && '🔴 CRITICAL: Unpatched critical vulnerabilities found — apply patches immediately.',
        logAnalysis?.summary?.criticalCount > 0 && '🟠 HIGH: Critical events in logs — escalate to incident response team.',
        sandbox && !sandbox.blocked && '⚠️ WAF Gap: Sandbox attack evaded WAF — review WAF rules.',
        '✅ Maintain 24/7 monitoring via Sentinel real-time engine.',
        '✅ Ensure CISA KEV patches are applied within 14 days of publication.',
        '✅ Conduct quarterly penetration tests and red team exercises.',
      ].filter(Boolean),
    };

    return {
      generated: true,
      reportType: 'FULL_INCIDENT_REPORT',
      generatedAt: new Date().toISOString(),
      report: sections,
      summary: `✅ Incident report generated. Threat score: ${overallScore}/100 (${overallRisk}). ${totalAttacks} attacks in 24h, ${sections.recommendations.length} recommendations issued.`,
    };
  } catch (err) {
    return { triggered: false, error: `Incident report generation failed: ${err.message}` };
  }
}

// ── Tool: get_blocked_ips ─────────────────────────────────────────────────────
function get_blocked_ips() {
  try {
    const blocked = global.blockedIPs ? [...global.blockedIPs] : [];
    return {
      blockedCount: blocked.length,
      blockedIPs: blocked,
      summary: blocked.length > 0
        ? `${blocked.length} IPs are currently blocked: ${blocked.join(', ')}`
        : 'No IPs are currently blocked. Use block_ip_address to block a suspicious IP.',
    };
  } catch (err) {
    return { error: `Failed to get blocked IPs: ${err.message}` };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tool Registry
// ═══════════════════════════════════════════════════════════════════════════════
const TOOLS = [
  // ── READ TOOLS ──
  {
    name: 'get_system_status',
    description: 'Returns live system telemetry: CPU usage, RAM usage, disk usage, network I/O, uptime, threat score, risk level, active security findings, and suspicious processes.',
    parameters: {},
    fn: get_system_status,
  },
  {
    name: 'get_attack_feed',
    description: 'Returns the 24-hour attack timeline: total attacks detected, total blocked, block rate percentage, and recent attack buckets with attack types.',
    parameters: {},
    fn: get_attack_feed,
  },
  {
    name: 'get_threat_intel',
    description: 'Returns live threat intelligence: IOC pool count, last sync time, data sources (ThreatFox + CISA KEV), top malware families, and sample IP-based IOCs.',
    parameters: {},
    fn: get_threat_intel,
  },
  {
    name: 'get_vuln_scan',
    description: 'Returns the most recent vulnerability scan results: risk score, risk level, total issues, critical/high/medium counts, CVE details, and remediation recommendations.',
    parameters: {},
    fn: get_vuln_scan,
  },
  {
    name: 'get_log_analysis',
    description: 'Returns the most recent log analysis: total events scanned, threat count, critical event count, top attack categories (brute-force, SQLi, etc.), and key findings.',
    parameters: {},
    fn: get_log_analysis,
  },
  {
    name: 'get_protection_scan',
    description: 'Returns the last Protection Center scan result for an email, URL, or file: verdict (clean/malicious/suspicious), severity, summary, and threat indicators.',
    parameters: {},
    fn: get_protection_scan,
  },
  {
    name: 'get_sandbox_result',
    description: 'Returns the last Attack Sandbox simulation result: attack type (sqli/xss/cmd), whether the WAF blocked the payload, the payload used, and detailed analysis steps.',
    parameters: {},
    fn: get_sandbox_result,
  },
  {
    name: 'get_network_connections',
    description: 'Scans current active TCP connections on this machine and cross-references against the IOC pool. Returns suspicious connections with severity and malware family tags.',
    parameters: {},
    fn: get_network_connections,
  },
  {
    name: 'get_listening_ports',
    description: 'Returns all currently listening ports on this machine, total connection count, and flags high-risk service ports (SSH=22, RDP=3389, FTP=21, VNC=5900, etc.).',
    parameters: {},
    fn: get_listening_ports,
  },
  {
    name: 'get_blocked_ips',
    description: 'Returns the list of all IP addresses currently blocked by the Sentinel blocklist engine.',
    parameters: {},
    fn: get_blocked_ips,
  },
  // ── ACTION TOOLS ──
  {
    name: 'run_vulnerability_scan',
    description: 'ACTION: Triggers an on-demand vulnerability scan of the current system. Returns risk score, risk level, and all findings with CVEs and remediation advice. Use when the user asks to "run a scan", "check for vulnerabilities", or "scan my system".',
    parameters: {},
    fn: run_vulnerability_scan,
  },
  {
    name: 'run_network_scan',
    description: 'ACTION: Runs a live network scan — checks all active TCP connections against the IOC pool and lists listening ports. Returns suspicious connections with severity ratings.',
    parameters: {},
    fn: run_network_scan,
  },
  {
    name: 'run_sandbox_attack',
    description: 'ACTION: Runs an attack simulation in the sandbox. Parameters: {"type": "sqli|xss|cmd", "payload": "optional custom payload", "securityEnabled": true|false}. Returns WAF decision, execution result, and analysis logs.',
    parameters: {
      type: { type: 'string', enum: ['sqli', 'xss', 'cmd'], description: 'Attack type' },
      payload: { type: 'string', description: 'Optional custom attack payload' },
      securityEnabled: { type: 'boolean', description: 'Whether WAF/security filters are enabled' },
    },
    fn: run_sandbox_attack,
  },
  {
    name: 'block_ip_address',
    description: 'ACTION: Adds an IP address to the Sentinel real-time blocklist. Parameters: {"ip": "1.2.3.4"}. Use after identifying a suspicious IP via get_network_connections.',
    parameters: {
      ip: { type: 'string', description: 'IPv4 address to block, e.g. "192.168.1.100"' },
    },
    fn: block_ip_address,
  },
  {
    name: 'scan_url_or_email',
    description: 'ACTION: Scans a URL, email address, or domain against the IOC pool and heuristic rules. Parameters: {"target": "https://...", "type": "url|email|domain"}. Returns verdict: CLEAN, SUSPICIOUS, or MALICIOUS.',
    parameters: {
      target: { type: 'string', description: 'The URL, email, or domain to scan' },
      type: { type: 'string', enum: ['url', 'email', 'domain'], description: 'Type of target' },
    },
    fn: scan_url_or_email,
  },
  {
    name: 'fetch_cve_details',
    description: 'Fetches CVE details from the CISA Known Exploited Vulnerabilities catalog. Parameters: {"cve_id": "CVE-2024-XXXX"} for a specific CVE, or no parameters to list the top 8 CVEs.',
    parameters: {
      cve_id: { type: 'string', description: 'Optional CVE ID like CVE-2024-1234' },
    },
    fn: fetch_cve_details,
  },
  {
    name: 'generate_incident_report',
    description: 'ACTION: Generates a comprehensive incident report by synthesizing data from all platform modules: system metrics, vulnerability scan, attack feed, log analysis, protection scans, and sandbox results. Returns executive summary + recommendations.',
    parameters: {},
    fn: generate_incident_report,
  },
];

// Build a fast lookup map
const TOOL_MAP = Object.fromEntries(TOOLS.map(t => [t.name, t]));

/**
 * Execute a tool by name with optional parameters.
 * Returns { result } or { error }.
 */
async function executeTool(name, params = {}) {
  const tool = TOOL_MAP[name];
  if (!tool) return { error: `Unknown tool: "${name}". Available tools: ${TOOLS.map(t => t.name).join(', ')}` };
  try {
    const result = await Promise.resolve(tool.fn(params));
    return { result };
  } catch (err) {
    return { error: `Tool "${name}" threw an error: ${err.message}` };
  }
}

/**
 * Returns a formatted string describing all tools for injection into the system prompt.
 */
function getToolSchemaPrompt() {
  const readTools = TOOLS.filter(t => !t.description.startsWith('ACTION:'));
  const actionTools = TOOLS.filter(t => t.description.startsWith('ACTION:'));

  const fmt = tools => tools.map(t => {
    const paramStr = Object.keys(t.parameters || {}).length > 0
      ? `\n  Parameters: ${JSON.stringify(t.parameters)}`
      : '';
    return `- **${t.name}**: ${t.description}${paramStr}`;
  }).join('\n');

  return `### Read Tools (fetch live data)\n${fmt(readTools)}\n\n### Action Tools (trigger platform operations)\n${fmt(actionTools)}`;
}

module.exports = { TOOLS, TOOL_MAP, executeTool, getToolSchemaPrompt };
