/**
 * Cyber Sentinel Lightweight Endpoint Telemetry Agent
 * 
 * Collects host metrics, process activities, and network states,
 * and streams normalized telemetry events to the Cyber Sentinel SOC API.
 */

const os = require('os');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { execSync } = require('child_process');

const SERVER_URL = process.env.SENTINEL_SERVER_URL || 'http://localhost:5000';
const API_TOKEN = process.env.SENTINEL_API_TOKEN || '';
const INTERVAL_MS = parseInt(process.env.AGENT_INTERVAL_MS || '5000', 10);
const DEVICE_ID_FILE = path.join(__dirname, '.device_id');

// Retrieve or generate persistent hardware-based deviceId
function getOrCreateDeviceId() {
  try {
    if (fs.existsSync(DEVICE_ID_FILE)) {
      const id = fs.readFileSync(DEVICE_ID_FILE, 'utf8').trim();
      if (id) return id;
    }
  } catch (_) {}

  // Generate deterministic device ID based on network interfaces + hostname
  const ifaces = os.networkInterfaces();
  const macs = [];
  for (const name of Object.keys(ifaces)) {
    for (const net of ifaces[name]) {
      if (!net.internal && net.mac && net.mac !== '00:00:00:00:00:00') {
        macs.push(net.mac);
      }
    }
  }

  const rawSeed = macs.sort().join('-') || `${os.hostname()}-${os.platform()}-${crypto.randomBytes(8).toString('hex')}`;
  const deviceId = `DEV-${crypto.createHash('sha256').update(rawSeed).digest('hex').substring(0, 16).toUpperCase()}`;

  try {
    fs.writeFileSync(DEVICE_ID_FILE, deviceId, 'utf8');
  } catch (_) {}

  return deviceId;
}

const DEVICE_ID = getOrCreateDeviceId();

// Safe process listing
function getRunningProcesses() {
  try {
    const isWin = process.platform === 'win32';
    if (isWin) {
      // Use tasklist format /fo csv
      const output = execSync('tasklist /FO CSV /NH', { timeout: 3000, stdio: ['pipe', 'pipe', 'ignore'] }).toString();
      const lines = output.split('\n').filter(Boolean);
      return lines.slice(0, 25).map(line => {
        const parts = line.split('","').map(s => s.replace(/"/g, '').trim());
        return {
          name: parts[0] || 'unknown',
          pid: parseInt(parts[1], 10) || 0,
          session: parts[2] || '',
          memory: parts[4] || ''
        };
      });
    } else {
      const output = execSync('ps -eo pid,comm,%cpu,%mem --sort=-%cpu | head -n 25', { timeout: 3000, stdio: ['pipe', 'pipe', 'ignore'] }).toString();
      const lines = output.split('\n').slice(1).filter(Boolean);
      return lines.map(line => {
        const [pid, name, cpu, mem] = line.trim().split(/\s+/);
        return { name, pid: parseInt(pid, 10), cpu, mem };
      });
    }
  } catch (_) {
    return [
      { name: 'node.exe', pid: process.pid, memory: 'N/A' },
      { name: 'system_idle', pid: 0, memory: 'N/A' }
    ];
  }
}

// Calculate CPU usage delta
let prevCpuTimes = null;
function getCpuUsagePercentage() {
  const cpus = os.cpus();
  let totalIdle = 0;
  let totalTick = 0;

  cpus.forEach(cpu => {
    for (const type in cpu.times) {
      totalTick += cpu.times[type];
    }
    totalIdle += cpu.times.idle;
  });

  if (!prevCpuTimes) {
    prevCpuTimes = { totalIdle, totalTick };
    return 10.5; // Baseline seed
  }

  const idleDiff = totalIdle - prevCpuTimes.totalIdle;
  const totalDiff = totalTick - prevCpuTimes.totalTick;
  prevCpuTimes = { totalIdle, totalTick };

  if (totalDiff === 0) return 0;
  const percentage = 100 - (100 * idleDiff / totalDiff);
  return parseFloat(percentage.toFixed(1));
}

// Collect host telemetry
function collectHostTelemetry() {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memoryPercent = parseFloat(((usedMem / totalMem) * 100).toFixed(1));

  return {
    deviceId: DEVICE_ID,
    hostname: os.hostname(),
    platform: `${os.platform()} ${os.release()} (${os.arch()})`,
    uptimeSeconds: os.uptime(),
    timestamp: new Date().toISOString(),
    metrics: {
      cpuUsagePercent: getCpuUsagePercentage(),
      memory: {
        totalMB: Math.round(totalMem / (1024 * 1024)),
        freeMB: Math.round(freeMem / (1024 * 1024)),
        usedMB: Math.round(usedMem / (1024 * 1024)),
        usagePercent: memoryPercent
      },
      loadAvg: os.loadavg()
    },
    topProcesses: getRunningProcesses().slice(0, 15)
  };
}

const DEVICE_TOKEN = process.env.SENTINEL_DEVICE_TOKEN || process.env.DEVICE_TOKEN || '';

// HTTP POST helper
function postJson(endpoint, data, token = '', customHeaders = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint, SERVER_URL);
    const isHttps = url.protocol === 'https:';
    const transport = isHttps ? https : http;
    const bodyString = JSON.stringify(data);

    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(bodyString),
      'X-Device-Id': DEVICE_ID,
      ...customHeaders
    };

    if (DEVICE_TOKEN) {
      headers['X-Device-Token'] = DEVICE_TOKEN;
    }

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const req = transport.request(url, {
      method: 'POST',
      headers,
      timeout: 5000
    }, (res) => {
      let responseBody = '';
      res.on('data', chunk => responseBody += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(responseBody);
          resolve({ statusCode: res.statusCode, body: parsed });
        } catch (_) {
          resolve({ statusCode: res.statusCode, body: responseBody });
        }
      });
    });

    req.on('error', err => reject(err));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Connection timed out to Sentinel Server'));
    });

    req.write(bodyString);
    req.end();
  });
}

// Authenticate or get bearer token
let activeAuthToken = API_TOKEN;
async function ensureAuthenticated() {
  if (activeAuthToken) return activeAuthToken;

  const email = process.env.SENTINEL_EMAIL;
  const password = process.env.SENTINEL_PASSWORD;

  if (email && password) {
    try {
      const res = await postJson('/api/auth/login', { email, password });
      if (res.statusCode === 200 && res.body?.token) {
        activeAuthToken = res.body.token;
        console.log(`[Agent] Successfully authenticated as '${email}'`);
        return activeAuthToken;
      }
    } catch (err) {
      console.warn(`[Agent] Auth login failed (${err.message}). Using device token headers.`);
    }
  }
  return '';
}

// Push normalized event to /api/events
async function sendEvent(eventPayload) {
  const token = await ensureAuthenticated();
  try {
    const res = await postJson('/api/events', eventPayload, token);
    if (res.statusCode >= 200 && res.statusCode < 300) {
      return res.body;
    } else {
      console.warn(`[Agent] Server returned HTTP ${res.statusCode}:`, res.body?.error || res.body);
    }
  } catch (err) {
    console.error(`[Agent] Ingestion error: ${err.message}`);
  }
  return null;
}

// Interactive Attack Simulations
async function runSimulations() {
  const args = process.argv.slice(2);

  if (args.includes('--simulate-suspicious-exec')) {
    console.log('\n[Simulation] Emitting Suspicious PowerShell Execution event (MITRE T1059.001)...');
    const res = await sendEvent({
      dataSource: 'endpoint-agent',
      dataType: 'process-execution',
      hostname: os.hostname(),
      processName: 'powershell.exe',
      commandLine: 'powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==',
      destIp: '185.220.101.5',
      destPort: 4444,
      isSimulation: true
    });
    console.log('[Simulation] Result:', res);
    process.exit(0);
  }

  if (args.includes('--simulate-sqli')) {
    console.log('\n[Simulation] Emitting SQLi Exploitation event (MITRE T1190)...');
    const res = await sendEvent({
      dataSource: 'waf-logs',
      dataType: 'http-request',
      srcIp: '198.51.100.77',
      endpoint: '/api/v1/users?id=1%27%20UNION%20SELECT%20null,username,password_hash%20FROM%20users--',
      httpStatus: 200,
      isSimulation: true
    });
    console.log('[Simulation] Result:', res);
    process.exit(0);
  }

  if (args.includes('--simulate-brute-force')) {
    console.log('\n[Simulation] Emitting 5 failed authentication attempts (MITRE T1110)...');
    const targetIp = '203.0.113.88';
    for (let i = 1; i <= 5; i++) {
      await sendEvent({
        dataSource: 'auth-service',
        dataType: 'authentication',
        action: 'FAILED_LOGIN',
        srcIp: targetIp,
        username: `target_admin_${i}`,
        isSimulation: true
      });
      console.log(`[Simulation] Sent attempt ${i}/5 from ${targetIp}`);
    }
    console.log('[Simulation] Brute force stream sent. Check SOC incidents dashboard.');
    process.exit(0);
  }
}

// Main telemetry agent loop
async function start() {
  console.log('====================================================');
  console.log('🛡️  CYBER SENTINEL — ENDPOINT TELEMETRY AGENT');
  console.log('====================================================');
  console.log(`Device ID:    ${DEVICE_ID}`);
  console.log(`Hostname:     ${os.hostname()}`);
  console.log(`Platform:     ${os.platform()} (${os.arch()})`);
  console.log(`Server URL:   ${SERVER_URL}`);
  console.log(`Interval:     ${INTERVAL_MS}ms`);
  console.log('====================================================\n');

  // Check if simulation flags are provided
  await runSimulations();

  console.log('[Agent] Initiating real-time host telemetry stream...\n');

  const emitTelemetry = async () => {
    const telemetry = collectHostTelemetry();
    const eventPayload = {
      dataSource: 'endpoint-agent',
      dataType: 'host-telemetry',
      deviceId: telemetry.deviceId,
      hostname: telemetry.hostname,
      platform: telemetry.platform,
      cpuUsage: telemetry.metrics.cpuUsagePercent,
      memoryUsage: telemetry.metrics.memory.usagePercent,
      metrics: telemetry.metrics,
      processes: telemetry.topProcesses,
      isSimulation: false
    };

    const res = await sendEvent(eventPayload);
    if (res && res.success) {
      process.stdout.write(`\r[${new Date().toLocaleTimeString()}] Telemetry emitted | CPU: ${telemetry.metrics.cpuUsagePercent}% | RAM: ${telemetry.metrics.memory.usagePercent}% | Sockets: Active   `);
    }
  };

  // Immediate first run
  await emitTelemetry();
  // Scheduled interval
  setInterval(emitTelemetry, INTERVAL_MS);
}

start().catch(err => {
  console.error('[Agent] Fatal error:', err);
  process.exit(1);
});
