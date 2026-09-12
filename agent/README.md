# Cyber Sentinel — Endpoint Telemetry Agent

The **Cyber Sentinel Endpoint Agent** is a lightweight, zero-dependency host telemetry and security event collector designed to feed raw endpoint telemetry into the Cyber Sentinel SOC Platform.

---

## 🚀 Capabilities

1. **Hardware Device Identity**: Deterministically derives a unique, persistent hardware Device ID (`DEV-XXXXXXXX`) from system network MAC addresses and hardware characteristics.
2. **Real-time Host Telemetry**: Samples CPU utilization deltas, memory thresholds, top active processes (`tasklist` on Windows / `ps` on Linux/macOS), and host uptime.
3. **Structured Ingestion**: Streams events directly to `POST /api/events` adhering to the standard Cyber Sentinel Provenance Schema (`dataSource: 'endpoint-agent'`).
4. **MITRE Attack Simulation Suite**: Built-in flags to generate benign, reproducible test telemetry for final capstone viva demonstrations:
   - `--simulate-suspicious-exec`: Emits hidden, encoded PowerShell commands with outbound network sockets (MITRE `T1059.001` / SIEM Rule `RULE_SUSPICIOUS_EXEC_004`).
   - `--simulate-sqli`: Emits union-based SQL injection HTTP probes resulting in HTTP 200 (MITRE `T1190` / SIEM Rule `RULE_SQLI_SUCCESS_002`).
   - `--simulate-brute-force`: Emits 5 rapid failed authentication attempts from a single source IP (MITRE `T1110` / SIEM Rule `RULE_BRUTE_FORCE_001`).

---

## 🛠️ Usage

### Prerequisites
Node.js (v18+) is required on the endpoint host. No external `npm install` packages are required!

### 1. Configuration (Environment Variables)
| Variable | Description | Default |
|---|---|---|
| `SENTINEL_SERVER_URL` | URL of the Cyber Sentinel API backend | `http://localhost:5000` |
| `SENTINEL_EMAIL` | SOC operator/agent email | `admin@sentinel.local` |
| `SENTINEL_PASSWORD` | SOC operator/agent password | `Sentinel#Admin2026!` |
| `AGENT_INTERVAL_MS` | Telemetry polling interval in milliseconds | `5000` |

### 2. Running Continuous Telemetry
```bash
cd agent
node agent.js
```

### 3. Demonstrating Detection Rules (Viva Demos)
Run any of the following simulation triggers in a separate terminal:

```bash
# Test SIEM Rule 004 (Suspicious Execution)
node agent.js --simulate-suspicious-exec

# Test SIEM Rule 002 (SQLi Probe with HTTP 200)
node agent.js --simulate-sqli

# Test SIEM Rule 001 (Brute Force Detection)
node agent.js --simulate-brute-force
```

Watch the **Incidents Console** in the Cyber Sentinel web application (`http://localhost:5173/incidents`) instantly register new incidents with calculated SHA-256 evidence integrity hashes and MITRE ATT&CK tags.
