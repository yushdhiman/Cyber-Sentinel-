/**
 * localNetworkMonitor.js
 * 
 * Monitors the LOCAL machine's real active network connections.
 * Uses PowerShell's netstat to get live TCP/UDP connections,
 * then cross-references each remote IP against the loaded ThreatFox IOC pool.
 * 
 * 100% local — no external API calls during monitoring.
 * All threat intelligence is loaded into memory once at startup.
 */

const { exec } = require('child_process');
const os = require('os');

// Known suspicious ports and their associated attack types
const SUSPICIOUS_PORTS = {
  22:    { type: 'SSH Brute Force Probe', severity: 'HIGH', mitre: 'T1110.001 Brute Force: Password Guessing' },
  23:    { type: 'Telnet Unencrypted Access', severity: 'HIGH', mitre: 'T1021.004 Remote Services: SSH' },
  25:    { type: 'SMTP Spam / Relay Attempt', severity: 'MEDIUM', mitre: 'T1566 Phishing' },
  53:    { type: 'DNS Tunneling Probe', severity: 'MEDIUM', mitre: 'T1071.004 DNS Protocol Tunnel' },
  80:    { type: 'HTTP Exploit Scan', severity: 'MEDIUM', mitre: 'T1190 Exploit Public-Facing Application' },
  443:   { type: 'HTTPS C2 Beacon', severity: 'MEDIUM', mitre: 'T1071.001 Application Layer Protocol' },
  445:   { type: 'SMB / EternalBlue Probe', severity: 'CRITICAL', mitre: 'T1021.002 SMB/Windows Admin Shares' },
  1433:  { type: 'MSSQL Injection Attempt', severity: 'HIGH', mitre: 'T1190 Exploit Public-Facing Application' },
  1900:  { type: 'UPnP SSDP Reflection', severity: 'MEDIUM', mitre: 'T1498.002 Reflection Amplification' },
  3306:  { type: 'MySQL Unauthorized Access', severity: 'HIGH', mitre: 'T1190 Exploit Public-Facing Application' },
  3389:  { type: 'RDP Brute Force', severity: 'CRITICAL', mitre: 'T1110.003 Password Spraying' },
  4444:  { type: 'Metasploit Shell', severity: 'CRITICAL', mitre: 'T1059 Command and Scripting Interpreter' },
  5900:  { type: 'VNC Remote Access', severity: 'HIGH', mitre: 'T1021.005 VNC' },
  6379:  { type: 'Redis Unauthorized Access', severity: 'HIGH', mitre: 'T1190 Exploit Public-Facing Application' },
  8080:  { type: 'HTTP Alt-Port Proxy Probe', severity: 'MEDIUM', mitre: 'T1090.002 External Proxy' },
  8443:  { type: 'HTTPS Alt-Port C2', severity: 'MEDIUM', mitre: 'T1071.001 Application Layer Protocol' },
  27017: { type: 'MongoDB Unauthorized Access', severity: 'HIGH', mitre: 'T1190 Exploit Public-Facing Application' },
};

// Country name → ISO code mapping (covers top threat-source countries)
const COUNTRY_RANGES = [
  { prefix: '1.', country: 'CN', city: 'Beijing' },
  { prefix: '27.', country: 'CN', city: 'Chengdu' },
  { prefix: '36.', country: 'CN', city: 'Shanghai' },
  { prefix: '42.', country: 'CN', city: 'Wuhan' },
  { prefix: '43.', country: 'CN', city: 'Shenzhen' },
  { prefix: '47.', country: 'CN', city: 'Hangzhou' },
  { prefix: '5.', country: 'RU', city: 'Moscow' },
  { prefix: '46.', country: 'RU', city: 'Saint Petersburg' },
  { prefix: '77.', country: 'RU', city: 'Novosibirsk' },
  { prefix: '91.', country: 'RU', city: 'Chelyabinsk' },
  { prefix: '185.', country: 'RU', city: 'Yekaterinburg' },
  { prefix: '213.', country: 'RU', city: 'Kazan' },
  { prefix: '198.', country: 'US', city: 'New York' },
  { prefix: '104.', country: 'US', city: 'Los Angeles' },
  { prefix: '52.', country: 'US', city: 'Virginia' },
  { prefix: '54.', country: 'US', city: 'Oregon' },
  { prefix: '35.', country: 'US', city: 'Iowa' },
  { prefix: '34.', country: 'US', city: 'California' },
  { prefix: '202.', country: 'KR', city: 'Seoul' },
  { prefix: '203.', country: 'JP', city: 'Tokyo' },
  { prefix: '103.', country: 'IN', city: 'Mumbai' },
  { prefix: '49.', country: 'IN', city: 'Bangalore' },
  { prefix: '82.', country: 'DE', city: 'Frankfurt' },
  { prefix: '178.', country: 'UA', city: 'Kyiv' },
  { prefix: '176.', country: 'UA', city: 'Kharkiv' },
  { prefix: '188.', country: 'NL', city: 'Amsterdam' },
  { prefix: '217.', country: 'GB', city: 'London' },
  { prefix: '194.', country: 'FR', city: 'Paris' },
  { prefix: '190.', country: 'BR', city: 'São Paulo' },
  { prefix: '45.', country: 'BR', city: 'Rio de Janeiro' },
];

function guessGeo(ip) {
  for (const r of COUNTRY_RANGES) {
    if (ip.startsWith(r.prefix)) return { country: r.country, city: r.city };
  }
  return { country: 'US', city: 'Network Node' };
}

function isPublicIp(ip) {
  if (!ip || ip === '0.0.0.0' || ip === '127.0.0.1' || ip === '::1' || ip === '*') return false;
  if (ip.startsWith('10.')) return false;
  if (ip.startsWith('172.') && parseInt(ip.split('.')[1]) >= 16 && parseInt(ip.split('.')[1]) <= 31) return false;
  if (ip.startsWith('192.168.')) return false;
  if (ip.startsWith('169.254.')) return false;
  if (ip.startsWith('::')) return false;
  if (ip.includes(':')) return false; // skip IPv6
  return true;
}

/**
 * Parse Windows netstat output into connection objects
 */
function parseNetstatOutput(output) {
  const connections = [];
  const lines = output.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    // Match: Proto  Local Address    Foreign Address   State   PID
    const match = trimmed.match(/^(TCP|UDP)\s+(\S+)\s+(\S+)\s+(ESTABLISHED|LISTEN|TIME_WAIT|CLOSE_WAIT|SYN_SENT|SYN_RECEIVED)?\s*(\d+)?/i);
    if (!match) continue;
    const [, proto, localAddr, foreignAddr, state, pid] = match;
    const [localIp, localPort] = localAddr.includes(':')
      ? [localAddr.slice(0, localAddr.lastIndexOf(':')), parseInt(localAddr.slice(localAddr.lastIndexOf(':') + 1))]
      : [localAddr, 0];
    const [remoteIp, remotePort] = foreignAddr.includes(':')
      ? [foreignAddr.slice(0, foreignAddr.lastIndexOf(':')), parseInt(foreignAddr.slice(foreignAddr.lastIndexOf(':') + 1))]
      : [foreignAddr, 0];
    connections.push({
      proto, localIp, localPort, remoteIp, remotePort: remotePort || 0,
      state: state || 'ACTIVE', pid: pid ? parseInt(pid) : null,
    });
  }
  return connections;
}

/**
 * Run netstat on Windows to get real active connections with PIDs
 */
function getRealConnections() {
  return new Promise((resolve) => {
    const cmd = 'netstat -ano -p TCP';
    exec(cmd, { timeout: 8000, windowsHide: true }, (err, stdout) => {
      if (err || !stdout) {
        resolve([]);
        return;
      }
      resolve(parseNetstatOutput(stdout));
    });
  });
}

/**
 * Get actual running process info for a PID using PowerShell
 */
function getProcessName(pid) {
  return new Promise((resolve) => {
    if (!pid) return resolve('Unknown');
    exec(
      `powershell -NoProfile -Command "Get-Process -Id ${pid} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"`,
      { timeout: 3000, windowsHide: true },
      (err, stdout) => {
        resolve(stdout?.trim() || 'Unknown');
      }
    );
  });
}

/**
 * Cross-references a remote IP against the ThreatFox IOC pool in memory.
 * Returns matched threat data or null.
 */
function checkIocPool(ip, iocPool) {
  if (!iocPool || !Array.isArray(iocPool)) return null;
  return iocPool.find(ioc => ioc.sourceIp === ip) || null;
}

/**
 * Main scan: get real active connections, check against IOC pool,
 * flag suspicious ports, and return structured attack-like events.
 */
async function scanLocalConnections(iocPool = []) {
  const connections = await getRealConnections();
  const events = [];
  const seenIps = new Set();

  for (const conn of connections) {
    if (!isPublicIp(conn.remoteIp)) continue;
    if (seenIps.has(conn.remoteIp)) continue;
    seenIps.add(conn.remoteIp);

    const iocMatch = checkIocPool(conn.remoteIp, iocPool);
    const portInfo = SUSPICIOUS_PORTS[conn.remotePort] || SUSPICIOUS_PORTS[conn.localPort];

    // Only report if: IOC match OR suspicious port
    if (!iocMatch && !portInfo) continue;

    const geo = guessGeo(conn.remoteIp);
    const severity = iocMatch?.severity || portInfo?.severity || 'MEDIUM';
    const type = iocMatch?.type || portInfo?.type || 'Suspicious Connection';
    const mitreTechnique = iocMatch?.mitreTechnique || portInfo?.mitre || 'T1071 Application Layer Protocol';
    // In real host telemetry, blocked is determined by firewall / blocklist state, not a coin flip
    const blocked = false; // Real connection detected active; will be true if subsequently contained/blocked

    events.push({
      id: `local-${Date.now()}-${conn.remoteIp.replace(/\./g, '')}`,
      timestamp: new Date().toISOString(),
      observedAt: new Date().toISOString(),
      ingestedAt: new Date().toISOString(),
      dataSource: 'Local Host Agent',
      dataType: 'HOST_TELEMETRY',
      isSimulation: false,
      sourceIp: conn.remoteIp,
      sourcePort: conn.remotePort,
      destPort: conn.localPort,
      country: geo.country,
      city: geo.city,
      type,
      malware: iocMatch?.malware || null,
      severity,
      blocked,
      targetService: SUSPICIOUS_PORTS[conn.localPort]?.type.split(' ')[0] || `Port ${conn.localPort}`,
      protocol: conn.proto,
      bytesTransferred: null, // Omit fabrication when OS socket counters unavailable
      packets: null,
      mitreTechnique,
      payloadSnippet: iocMatch?.payloadSnippet || null,
      remediation: iocMatch?.remediation || `Inspect process PID ${conn.pid} and restrict outbound traffic to ${conn.remoteIp}:${conn.remotePort}.`,
      confidence: iocMatch ? (iocMatch.confidence || 90) : 60,
      threatIntelMatch: iocMatch
        ? `ThreatFox IOC Match — ${conn.remoteIp}`
        : `Suspicious Port ${conn.remotePort} — Active host socket`,
      localSource: true,
      pid: conn.pid,
    });
  }

  return events;
}

/**
 * Get real open listening ports on the machine
 */
function getListeningPorts() {
  return new Promise((resolve) => {
    exec('netstat -ano -p TCP | findstr LISTENING', { timeout: 6000, windowsHide: true }, (err, stdout) => {
      if (err || !stdout) return resolve([]);
      const ports = [];
      const lines = stdout.split('\n');
      for (const line of lines) {
        const m = line.trim().match(/TCP\s+\S+:(\d+)\s+\S+\s+LISTENING\s+(\d+)/i);
        if (m) {
          const port = parseInt(m[1]);
          const pid = parseInt(m[2]);
          if (port > 0 && port < 65535) {
            ports.push({
              port,
              pid,
              risky: !!SUSPICIOUS_PORTS[port],
              service: SUSPICIOUS_PORTS[port]?.type.split(' ')[0] || `Port ${port}`,
            });
          }
        }
      }
      resolve(ports.slice(0, 20));
    });
  });
}

/**
 * Get active established connections count for the metrics panel
 */
function getConnectionCount() {
  return new Promise((resolve) => {
    exec('netstat -ano -p TCP | findstr ESTABLISHED', { timeout: 5000, windowsHide: true }, (err, stdout) => {
      if (err || !stdout) return resolve(0);
      resolve(stdout.split('\n').filter(l => l.trim()).length);
    });
  });
}

module.exports = {
  scanLocalConnections,
  getListeningPorts,
  getConnectionCount,
  getRealConnections,
};
