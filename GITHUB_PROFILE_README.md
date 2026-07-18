# Cyber Sentinel — AI-Assisted Threat Operations Dashboard

A full-stack cybersecurity operations and threat monitoring suite designed for security analysts. It features live network telemetry, heuristic security scans, phishing detection, a malware sandbox, and an offline AI Security Assistant.

🚀 **Live Demo:** [https://cyber-sentinel-7xfn.onrender.com/](https://cyber-sentinel-7xfn.onrender.com/)

---

## 🚀 Key Modules

### 1. Real-Time Security Operations (SOC) Dashboard
- **Live Stream telemetry**: Renders live CPU, RAM, and network interface metrics over active WebSockets.
- **Dynamic Threat Index**: Calculates real-time risk severity dynamically using simulated logs and scanner inputs.
- **Intrusion Alerts**: Interactive event log feed reporting mock intrusion events.

### 2. Log Security Inspector
- **Signature & Heuristics scan**: Detects SQL injection, XSS, and command injection attacks inside raw server logs.
- **Brute Force Detection**: High-volume SSH and panel auth failure alerts with per-source-IP risk scoring.

### 3. Vulnerability Config Scanner
- **OWASP Alignment**: Inputs config declarations (HTTPS, HSTS headers, passwords policies, MFA, admin panel exposure, open ports) and maps them to OWASP security standards.

### 4. Threat Prevention Center
- **Email Phishing Scan**: Analyzes headers, sender subdomains, social engineering keywords, and attachment extensions.
- **Link Guard**: Classifies URLs against TLD databases, shorteners, brand-spoofing keywords, and raw IP formats.
- **Malware Sandbox**: Simulated isolated container checking file signatures (WannaCry, EICAR test string) and dual-extension payloads.

### 5. AI Security Assistant
- **Curated Knowledge Base**: Offline intent-matching responder covering SQLi, XSS, DDoS, phishing, and incident response, ready to swap to live LLM services.

---

## 🛠️ Technology Stack
- **Frontend**: React 18, Vite, React Router, Recharts, Axios, Socket.IO Client, CSS Variables
- **Backend**: Node.js, Express, JWT, bcryptjs, Helmet, CORS, express-rate-limit, Socket.IO

---

## 📂 Project Structure
```
cyber-sentinel/
├── backend/
│   ├── src/
│   │   ├── server.js          # Express app entrypoint
│   │   ├── routes/            # auth, threats, logs, vuln, chatbot, protection
│   │   └── utils/             # detection, scanner, chatbot, protectionEngine
│   └── package.json
└── frontend/
    ├── src/
    │   ├── pages/              # Dashboard, LogAnalyzer, VulnScanner, ProtectionCenter
    │   └── components/         # Layout, ProtectedRoute, StatCard
    └── package.json
```

---

## 🔧 Steps to Setup & Run
Ensure Node.js 18+ and npm are installed.

1. **Start Backend**:
   ```bash
   cd backend
   cp .env.example .env
   # Set JWT_SECRET in .env
   npm install
   npm start
   ```
2. **Start Frontend**:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
3. Open [http://localhost:5173](http://localhost:5173) and log in using:
   - **Email**: admin@sentinel.ai
   - **Password**: password123
