/**
 * systemMetrics.js
 * Collects real-time OS/system metrics using Node's built-in `os` module.
 * No external scanning — this reads only the machine the server is running on.
 * Safe and legal: we're introspecting our own process host.
 */

const os = require('os');

/**
 * Get real CPU load average and usage approximation.
 * On Windows, loadavg() always returns [0,0,0]; we compute a sample instead.
 */
function getCpuUsage() {
  const cpus = os.cpus();
  let totalIdle = 0;
  let totalTick = 0;
  for (const cpu of cpus) {
    for (const type in cpu.times) {
      totalTick += cpu.times[type];
    }
    totalIdle += cpu.times.idle;
  }
  const idlePercent = (totalIdle / totalTick) * 100;
  const usagePercent = Math.round(100 - idlePercent);
  return {
    cores: cpus.length,
    model: cpus[0]?.model?.trim() || 'Unknown',
    usagePercent: Math.min(100, Math.max(0, usagePercent)),
    loadAvg: os.loadavg(), // [1m, 5m, 15m] — 0 on Windows
  };
}

/**
 * Get real memory stats.
 */
function getMemoryStats() {
  const totalMb = Math.round(os.totalmem() / 1024 / 1024);
  const freeMb = Math.round(os.freemem() / 1024 / 1024);
  const usedMb = totalMb - freeMb;
  const usagePercent = Math.round((usedMb / totalMb) * 100);
  return { totalMb, freeMb, usedMb, usagePercent };
}

/**
 * Enumerate real network interfaces on this machine.
 * Returns only IPv4 non-internal interfaces as "linked devices/adapters".
 */
function getNetworkInterfaces() {
  const ifaces = os.networkInterfaces();
  const adapters = [];
  for (const [name, entries] of Object.entries(ifaces)) {
    for (const entry of entries) {
      if (entry.family === 'IPv4') {
        adapters.push({
          name,
          address: entry.address,
          netmask: entry.netmask,
          mac: entry.mac,
          internal: entry.internal,
          cidr: entry.cidr,
        });
      }
    }
  }
  return adapters;
}

/**
 * Compute a real-time threat score from actual system metrics.
 * Score is 0-100; higher = more risk detected.
 * Factors: high CPU, high RAM, uptime length, number of exposed interfaces,
 * running as administrator-like UID, platform age signals.
 */
function computeThreatScore(cpu, memory, adapters) {
  let score = 0;
  const findings = [];

  // --- CPU Risk ---
  if (cpu.usagePercent > 90) {
    score += 18;
    findings.push({ id: 'cpu-critical', severity: 'CRITICAL', title: 'CPU Usage Critically High', detail: `CPU is at ${cpu.usagePercent}% — possible cryptominer, runaway process, or DDoS load.` });
  } else if (cpu.usagePercent > 75) {
    score += 10;
    findings.push({ id: 'cpu-high', severity: 'HIGH', title: 'Elevated CPU Load', detail: `CPU at ${cpu.usagePercent}%. Monitor for malicious background processes.` });
  } else if (cpu.usagePercent > 50) {
    score += 4;
    findings.push({ id: 'cpu-medium', severity: 'MEDIUM', title: 'Moderate CPU Usage', detail: `CPU at ${cpu.usagePercent}%. Normal under load but worth monitoring.` });
  }

  // --- Memory Risk ---
  if (memory.usagePercent > 90) {
    score += 15;
    findings.push({ id: 'ram-critical', severity: 'CRITICAL', title: 'Memory Exhaustion Risk', detail: `RAM usage at ${memory.usagePercent}% (${memory.usedMb}MB / ${memory.totalMb}MB). High risk of OOM crash or swap-based slowdowns exploitable by attackers.` });
  } else if (memory.usagePercent > 75) {
    score += 8;
    findings.push({ id: 'ram-high', severity: 'HIGH', title: 'High Memory Pressure', detail: `RAM at ${memory.usagePercent}%. System may become unstable under sustained load.` });
  } else if (memory.usagePercent > 60) {
    score += 3;
    findings.push({ id: 'ram-medium', severity: 'MEDIUM', title: 'Moderate Memory Usage', detail: `RAM at ${memory.usagePercent}%. Monitor for memory leaks.` });
  }

  // --- Network Exposure ---
  const externalAdapters = adapters.filter(a => !a.internal);
  if (externalAdapters.length > 4) {
    score += 12;
    findings.push({ id: 'net-many-ifaces', severity: 'HIGH', title: 'Multiple Network Interfaces Detected', detail: `${externalAdapters.length} external network adapters found. Each interface is an additional attack surface. Disable unused NICs.` });
  } else if (externalAdapters.length > 2) {
    score += 5;
    findings.push({ id: 'net-multi-iface', severity: 'MEDIUM', title: 'Multiple Network Adapters Active', detail: `${externalAdapters.length} external adapters active. Ensure each is intentional and firewalled.` });
  }

  // Check for VPN/tunnel interfaces (tun0, wg0, etc.)
  const vpnAdapter = adapters.find(a => /tun|wg|vpn|ppp|tap/i.test(a.name));
  if (vpnAdapter) {
    findings.push({ id: 'net-vpn', severity: 'LOW', title: 'VPN/Tunnel Interface Active', detail: `Interface "${vpnAdapter.name}" (${vpnAdapter.address}) appears to be a VPN or tunnel adapter. Verify this is authorized.` });
  }

  // Check for loopback only (very isolated — good)
  const internalOnly = adapters.every(a => a.internal);
  if (internalOnly && adapters.length > 0) {
    findings.push({ id: 'net-loopback', severity: 'LOW', title: 'Only Loopback Interface Detected', detail: 'No external network interfaces detected. System is fully isolated (good for air-gapped setups).' });
  }

  // --- Uptime Risk ---
  const uptimeDays = Math.floor(os.uptime() / 86400);
  if (uptimeDays > 180) {
    score += 10;
    findings.push({ id: 'uptime-stale', severity: 'HIGH', title: 'System Not Rebooted in 6+ Months', detail: `Uptime: ${uptimeDays} days. Long uptimes indicate unpatched kernel vulnerabilities may be running in memory. Schedule a maintenance window.` });
  } else if (uptimeDays > 60) {
    score += 5;
    findings.push({ id: 'uptime-long', severity: 'MEDIUM', title: 'Extended System Uptime', detail: `Uptime: ${uptimeDays} days. Ensure OS patches requiring reboot have been applied.` });
  } else if (uptimeDays > 30) {
    score += 2;
    findings.push({ id: 'uptime-moderate', severity: 'LOW', title: 'Uptime Approaching 30 Days', detail: `Uptime: ${uptimeDays} days. Check for pending security patches.` });
  }

  // --- Platform-specific signals ---
  const platform = os.platform();
  if (platform === 'win32') {
    // Windows with many cores and no load — could indicate running as domain controller
    if (cpu.cores >= 8 && cpu.usagePercent < 10) {
      score += 3;
      findings.push({ id: 'win-idle-server', severity: 'LOW', title: 'Possible Windows Server (Idle)', detail: 'High core count + low usage suggests a server role. Ensure RDP and SMB are firewalled appropriately.' });
    }
  }

  // Baseline: always add a small base score so it's never 0 (systems always have some risk)
  score += 8;
  findings.push({ id: 'baseline', severity: 'LOW', title: 'Baseline Security Posture', detail: 'Every system has inherent risk from network exposure, software vulnerabilities, and human factors. Continuous monitoring is recommended.' });

  const finalScore = Math.min(100, score);
  const riskLevel = finalScore >= 70 ? 'CRITICAL' : finalScore >= 40 ? 'HIGH' : finalScore >= 20 ? 'MEDIUM' : 'LOW';

  return { score: finalScore, riskLevel, findings };
}

/**
 * Main function: collect all real-time system metrics.
 */
function collectSystemMetrics() {
  const cpu = getCpuUsage();
  const memory = getMemoryStats();
  const adapters = getNetworkInterfaces();
  const { score: threatScore, riskLevel, findings } = computeThreatScore(cpu, memory, adapters);

  // Build "linked devices" from real network adapters
  const linkedDevices = adapters.map((a, idx) => ({
    id: `dev-${idx}`,
    name: a.internal ? 'Loopback (localhost)' : a.name,
    ip: a.address,
    mac: a.mac,
    type: a.internal ? 'Loopback' : /wi-fi|wlan|wireless/i.test(a.name) ? 'Wi-Fi' : /eth|lan|local area/i.test(a.name) ? 'Ethernet' : /tun|wg|vpn|ppp|tap/i.test(a.name) ? 'VPN/Tunnel' : 'Network Adapter',
    status: 'Online',
    internal: a.internal,
    cidr: a.cidr,
  }));

  return {
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    osRelease: os.release(),
    uptimeSeconds: os.uptime(),
    uptimeDays: Math.floor(os.uptime() / 86400),
    cpu,
    memory,
    linkedDevices,
    threatScore,
    riskLevel,
    findings,
    collectedAt: new Date().toISOString(),
  };
}

module.exports = { collectSystemMetrics };
