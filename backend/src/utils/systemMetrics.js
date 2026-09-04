/**
 * systemMetrics.js
 * Collects real-time OS/system metrics from the local machine.
 * Uses Node's built-in `os` module + systeminformation for richer data.
 * Safe and legal: introspecting only the machine the server runs on.
 */

const os = require('os');
let si = null;
try { si = require('systeminformation'); } catch(e) { /* optional */ }

// ── CPU ──────────────────────────────────────────────────────────────────────
let prevCpuTicks = null;

function getCpuUsage() {
  const cpus = os.cpus();
  let totalIdle = 0, totalTick = 0;
  for (const cpu of cpus) {
    for (const type in cpu.times) totalTick += cpu.times[type];
    totalIdle += cpu.times.idle;
  }
  let usagePercent = 0;
  if (prevCpuTicks) {
    const idleDelta = totalIdle - prevCpuTicks.idle;
    const totalDelta = totalTick - prevCpuTicks.total;
    if (totalDelta > 0) {
      usagePercent = Math.round((1 - Math.max(0, Math.min(1, idleDelta / totalDelta))) * 100);
    }
  } else {
    usagePercent = Math.round(100 - (totalIdle / (totalTick || 1)) * 100);
  }
  prevCpuTicks = { idle: totalIdle, total: totalTick };
  return {
    cores: cpus.length,
    model: cpus[0]?.model?.trim() || 'Unknown Processor',
    usagePercent: Math.min(100, Math.max(0, usagePercent)),
    loadAvg: os.loadavg(),
  };
}

// ── Memory ───────────────────────────────────────────────────────────────────
function getMemoryStats() {
  const totalMb = Math.round(os.totalmem() / 1024 / 1024);
  const freeMb  = Math.round(os.freemem() / 1024 / 1024);
  const usedMb  = totalMb - freeMb;
  return {
    totalMb, freeMb, usedMb,
    usagePercent: Math.min(100, Math.max(0, Math.round((usedMb / (totalMb || 1)) * 100))),
  };
}

// ── Network Interfaces ────────────────────────────────────────────────────────
function getNetworkInterfaces() {
  const ifaces  = os.networkInterfaces();
  const adapters = [];
  for (const [name, entries] of Object.entries(ifaces)) {
    if (!entries) continue;
    for (const entry of entries) {
      if (entry.family === 'IPv4' || entry.family === 4) {
        adapters.push({ name, address: entry.address, netmask: entry.netmask,
          mac: entry.mac || '00:00:00:00:00:00', internal: entry.internal,
          cidr: entry.cidr || `${entry.address}/24` });
      }
    }
  }
  return adapters;
}

// ── Processes via systeminformation ──────────────────────────────────────────
const SUSPICIOUS_PROCESS_NAMES = [
  'mimikatz', 'nc', 'ncat', 'netcat', 'psexec', 'meterpreter',
  'cobaltstrike', 'beacon', 'powersploit', 'empire', 'nmap',
  'masscan', 'hydra', 'medusa', 'john', 'hashcat', 'sqlmap',
  'metasploit', 'burpsuite', 'wireshark', 'tcpdump',
];

let cachedProcesses = [];
let lastProcessFetch = 0;

async function getSuspiciousProcesses() {
  const now = Date.now();
  if (now - lastProcessFetch < 10000) return cachedProcesses; // cache 10s
  lastProcessFetch = now;
  if (!si) return [];
  try {
    const procs = await si.processes();
    const all = procs.list || [];
    // Processes using high CPU or flagged by name
    const suspicious = all.filter(p => {
      const name = (p.name || '').toLowerCase();
      return SUSPICIOUS_PROCESS_NAMES.some(s => name.includes(s))
        || (p.cpu > 30 && !['system', 'idle', 'antimalware', 'msmpeng'].some(s => name.includes(s)));
    }).slice(0, 10);
    cachedProcesses = suspicious.map(p => ({
      pid: p.pid,
      name: p.name,
      cpuPercent: Math.round(p.cpu || 0),
      memMb: Math.round((p.memVsz || 0) / 1024),
      command: p.command || p.name,
      suspicious: SUSPICIOUS_PROCESS_NAMES.some(s => (p.name || '').toLowerCase().includes(s)),
    }));
    return cachedProcesses;
  } catch {
    return [];
  }
}

// ── Disk via systeminformation ────────────────────────────────────────────────
let cachedDisk = null;
let lastDiskFetch = 0;

async function getDiskStats() {
  const now = Date.now();
  if (now - lastDiskFetch < 30000 && cachedDisk) return cachedDisk;
  lastDiskFetch = now;
  if (!si) return null;
  try {
    const fs = await si.fsSize();
    const main = fs.find(d => d.mount === 'C:' || d.mount === '/') || fs[0];
    if (!main) return null;
    cachedDisk = {
      mount: main.mount,
      totalGb: Math.round(main.size / 1e9),
      usedGb: Math.round(main.used / 1e9),
      usagePercent: Math.round(main.use),
    };
    return cachedDisk;
  } catch {
    return null;
  }
}

// ── Network traffic stats via systeminformation ───────────────────────────────
let lastNetStats = null;
let cachedNetIO = null;
let lastNetFetch = 0;

async function getNetworkIO() {
  const now = Date.now();
  if (now - lastNetFetch < 4000 && cachedNetIO) return cachedNetIO;
  lastNetFetch = now;
  if (!si) return null;
  try {
    const stats = await si.networkStats();
    if (!stats || !stats.length) return null;
    // Pick the most active interface
    const iface = stats.sort((a, b) => (b.rx_bytes + b.tx_bytes) - (a.rx_bytes + a.tx_bytes))[0];
    const rxMbps = ((iface.rx_sec || 0) * 8 / 1e6).toFixed(2);
    const txMbps = ((iface.tx_sec || 0) * 8 / 1e6).toFixed(2);
    cachedNetIO = {
      interface: iface.iface,
      rxMbps: parseFloat(rxMbps),
      txMbps: parseFloat(txMbps),
      totalRxMb: Math.round((iface.rx_bytes || 0) / 1e6),
      totalTxMb: Math.round((iface.tx_bytes || 0) / 1e6),
    };
    return cachedNetIO;
  } catch {
    return null;
  }
}

// ── Threat Score ──────────────────────────────────────────────────────────────
function computeThreatScore(cpu, memory, adapters, disk, suspiciousProcs) {
  let score = 0;
  const findings = [];

  // CPU
  if (cpu.usagePercent > 90) {
    score += 20;
    findings.push({ id: 'cpu-critical', severity: 'CRITICAL', title: 'CPU Usage Critically High', detail: `CPU is at ${cpu.usagePercent}% — possible cryptominer, ransomware encryption, or runaway process.` });
  } else if (cpu.usagePercent > 75) {
    score += 10;
    findings.push({ id: 'cpu-high', severity: 'HIGH', title: 'Elevated CPU Load', detail: `CPU at ${cpu.usagePercent}%. Monitor for unexpected background execution.` });
  } else if (cpu.usagePercent > 50) {
    score += 5;
    findings.push({ id: 'cpu-medium', severity: 'MEDIUM', title: 'Moderate CPU Activity', detail: `CPU at ${cpu.usagePercent}%. Normal load active.` });
  }

  // Memory
  if (memory.usagePercent > 96) {
    score += 15;
    findings.push({ id: 'ram-critical', severity: 'HIGH', title: 'Memory Exhaustion Warning', detail: `RAM usage at ${memory.usagePercent}% (${memory.usedMb}MB / ${memory.totalMb}MB). Potential memory pressure or injection activity.` });
  } else if (memory.usagePercent > 85) {
    score += 6;
    findings.push({ id: 'ram-high', severity: 'MEDIUM', title: 'High Memory Allocation', detail: `RAM at ${memory.usagePercent}%. Active processes utilizing substantial memory.` });
  }

  // Disk
  if (disk && disk.usagePercent > 95) {
    score += 12;
    findings.push({ id: 'disk-critical', severity: 'HIGH', title: 'Disk Nearly Full', detail: `${disk.mount} at ${disk.usagePercent}% (${disk.usedGb}GB / ${disk.totalGb}GB). Possible log flooding or ransomware file creation.` });
  } else if (disk && disk.usagePercent > 80) {
    score += 4;
    findings.push({ id: 'disk-high', severity: 'MEDIUM', title: 'High Disk Usage', detail: `${disk.mount} at ${disk.usagePercent}%.` });
  }

  // Suspicious processes
  if (suspiciousProcs && suspiciousProcs.length > 0) {
    const definitelySuspicious = suspiciousProcs.filter(p => p.suspicious);
    if (definitelySuspicious.length > 0) {
      score += 25;
      findings.push({ id: 'proc-suspicious', severity: 'CRITICAL', title: `Suspicious Process Detected: ${definitelySuspicious[0].name}`, detail: `Process "${definitelySuspicious[0].name}" (PID: ${definitelySuspicious[0].pid}) matches known attack tool signature. CPU: ${definitelySuspicious[0].cpuPercent}%.` });
    }
  }

  // Network
  const externalAdapters = adapters.filter(a => !a.internal);
  if (externalAdapters.length > 5) {
    score += 10;
    findings.push({ id: 'net-many-ifaces', severity: 'HIGH', title: 'Multiple Network Adapters Active', detail: `${externalAdapters.length} external network interfaces detected. Verify all are authorized.` });
  } else if (externalAdapters.length > 2) {
    score += 4;
    findings.push({ id: 'net-multi-iface', severity: 'LOW', title: 'Multi-homed Network Configuration', detail: `${externalAdapters.length} external adapters detected.` });
  }

  const vpnAdapter = adapters.find(a => /tun|wg|vpn|ppp|tap/i.test(a.name));
  if (vpnAdapter) {
    findings.push({ id: 'net-vpn', severity: 'LOW', title: 'VPN / Tunnel Interface Active', detail: `Interface "${vpnAdapter.name}" (${vpnAdapter.address}) is routing encrypted tunnel traffic.` });
  }

  // Uptime
  const uptimeDays = Math.floor(os.uptime() / 86400);
  if (uptimeDays > 180) {
    score += 8;
    findings.push({ id: 'uptime-stale', severity: 'HIGH', title: 'Extended Host Uptime (>6 Months)', detail: `Host uptime: ${uptimeDays} days. Kernel patches may be pending.` });
  } else if (uptimeDays > 30) {
    score += 3;
    findings.push({ id: 'uptime-moderate', severity: 'LOW', title: 'Host Uptime > 30 Days', detail: `Host uptime: ${uptimeDays} days.` });
  }

  score += 6;
  findings.push({ id: 'baseline', severity: 'LOW', title: 'Baseline Security Active', detail: 'Real-time telemetry and network connection monitoring active on your local machine.' });

  const finalScore = Math.min(100, Math.max(0, score));
  return {
    score: finalScore,
    riskLevel: finalScore >= 70 ? 'CRITICAL' : finalScore >= 40 ? 'HIGH' : finalScore >= 20 ? 'MEDIUM' : 'LOW',
    findings,
  };
}

// ── Main Export ───────────────────────────────────────────────────────────────
async function collectSystemMetrics() {
  const cpu = getCpuUsage();
  const memory = getMemoryStats();
  const adapters = getNetworkInterfaces();

  // Async enrichment (non-blocking fallbacks)
  const [disk, suspiciousProcs, netIO] = await Promise.allSettled([
    getDiskStats(), getSuspiciousProcesses(), getNetworkIO(),
  ]).then(results => results.map(r => r.status === 'fulfilled' ? r.value : null));

  const { score: threatScore, riskLevel, findings } = computeThreatScore(cpu, memory, adapters, disk, suspiciousProcs);

  const uptimeSec     = Math.floor(os.uptime());
  const uptimeDays    = Math.floor(uptimeSec / 86400);
  const uptimeHours   = Math.floor((uptimeSec % 86400) / 3600);
  const uptimeMinutes = Math.floor((uptimeSec % 3600) / 60);

  const linkedDevices = adapters.map((a, idx) => ({
    id: `dev-${idx}`, name: a.internal ? 'Loopback (localhost)' : a.name,
    ip: a.address, mac: a.mac,
    type: a.internal ? 'Loopback'
      : /wi-fi|wlan|wireless/i.test(a.name) ? 'Wi-Fi'
      : /eth|lan|local area/i.test(a.name) ? 'Ethernet'
      : /tun|wg|vpn|ppp|tap/i.test(a.name) ? 'VPN/Tunnel'
      : 'Network Adapter',
    status: 'Online', internal: a.internal, cidr: a.cidr,
  }));

  return {
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    osRelease: os.release(),
    uptimeSeconds: uptimeSec,
    uptimeDays, uptimeHours, uptimeMinutes,
    cpu, memory,
    disk: disk || null,
    netIO: netIO || null,
    suspiciousProcesses: suspiciousProcs || [],
    linkedDevices,
    threatScore,
    riskLevel,
    findings,
    collectedAt: new Date().toISOString(),
  };
}

module.exports = { collectSystemMetrics };
