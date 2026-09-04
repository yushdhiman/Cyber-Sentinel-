/**
 * agentTools.js
 * Sentinel Agent — Tool Registry
 *
 * Defines 8 callable tools for the ReAct agentic loop.
 * Each tool is a pure function that fetches/computes live data and
 * returns a structured JSON object the agent can reason over.
 *
 * Tool Registry format:
 *   { name, description, parameters, fn }
 */

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
        message: 'No vulnerability scan has been run yet. Ask the user to run a scan from the Vulnerability Scanner page.',
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
        message: 'No protection scan has been run yet. Ask the user to scan an email, URL, or file from the Protection Center.',
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
        message: 'No sandbox simulation has been run yet. Ask the user to run a simulation in the Attack Sandbox.',
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

// ── Tool: run_quick_vuln_check ────────────────────────────────────────────────
async function run_quick_vuln_check() {
  try {
    const scanner = require('./scanner');
    // If a scan function is available, trigger it
    if (typeof scanner.runScan === 'function') {
      const result = await scanner.runScan();
      global.lastScanResult = result;
      return {
        triggered: true,
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
        totalIssues: result.issues?.length,
        criticalCount: result.issues?.filter(i => i.severity === 'CRITICAL').length,
        summary: `On-demand scan complete. Risk: ${result.riskScore}/100 (${result.riskLevel}).`,
      };
    }

    // Fallback: return a quick heuristic-based snapshot from system metrics
    const m = global.lastSystemMetrics;
    if (!m) return { triggered: false, error: 'No system metrics available for quick check.' };

    const issues = [];
    if (m.cpu?.usagePercent > 90) issues.push({ severity: 'HIGH', title: 'CPU usage critically high', detail: `${m.cpu.usagePercent}%` });
    if (m.memory?.usagePercent > 90) issues.push({ severity: 'HIGH', title: 'Memory usage critically high', detail: `${m.memory.usagePercent}%` });
    if (m.disk?.usagePercent > 90) issues.push({ severity: 'MEDIUM', title: 'Disk nearly full', detail: `${m.disk.usagePercent}%` });
    if (m.threatScore > 70) issues.push({ severity: 'CRITICAL', title: 'Threat score dangerously high', detail: `Score: ${m.threatScore}/100` });
    (m.suspiciousProcesses || []).forEach(p =>
      issues.push({ severity: 'HIGH', title: `Suspicious process: ${p.name}`, detail: `PID ${p.pid}, CPU ${p.cpuPercent}%` })
    );

    return {
      triggered: true,
      type: 'quick-heuristic',
      issueCount: issues.length,
      issues: issues.slice(0, 8),
      summary: `Quick check found ${issues.length} issue(s) from live system metrics.`,
    };
  } catch (err) {
    return { triggered: false, error: `Quick vuln check failed: ${err.message}` };
  }
}

// ── Tool Registry ─────────────────────────────────────────────────────────────
const TOOLS = [
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
    description: 'Returns live threat intelligence: IOC pool count, last sync time, data sources, top malware families, and sample IP-based IOCs from ThreatFox and CISA KEV.',
    parameters: {},
    fn: get_threat_intel,
  },
  {
    name: 'get_vuln_scan',
    description: 'Returns the most recent vulnerability scan results: risk score, risk level, total issues found, critical/high/medium counts, and details of all issues with CVE numbers and remediation recommendations.',
    parameters: {},
    fn: get_vuln_scan,
  },
  {
    name: 'get_log_analysis',
    description: 'Returns the most recent log analysis: total events scanned, threat count, critical event count, top attack categories (e.g. brute-force, SQLi), and key findings.',
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
    name: 'run_quick_vuln_check',
    description: 'Triggers an on-demand lightweight vulnerability/heuristic check of the current system and returns findings immediately. Use when the user asks to "run a scan", "check for vulnerabilities now", or "scan my system".',
    parameters: {},
    fn: run_quick_vuln_check,
  },
];

// Build a fast lookup map
const TOOL_MAP = Object.fromEntries(TOOLS.map(t => [t.name, t]));

/**
 * Execute a tool by name. Returns { result } or { error }.
 */
async function executeTool(name) {
  const tool = TOOL_MAP[name];
  if (!tool) return { error: `Unknown tool: "${name}". Available tools: ${TOOLS.map(t => t.name).join(', ')}` };
  try {
    const result = await Promise.resolve(tool.fn());
    return { result };
  } catch (err) {
    return { error: `Tool "${name}" threw an error: ${err.message}` };
  }
}

/**
 * Returns a formatted string describing all tools for injection into the system prompt.
 */
function getToolSchemaPrompt() {
  return TOOLS.map(t => `- **${t.name}**: ${t.description}`).join('\n');
}

module.exports = { TOOLS, TOOL_MAP, executeTool, getToolSchemaPrompt };
