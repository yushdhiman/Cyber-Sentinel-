# Cyber Sentinel — AI-Assisted Threat Monitoring Dashboard

A full-stack security operations dashboard built with **React (Vite)** on the frontend and **Node.js / Express** on the backend. It demonstrates authentication, log-based threat detection, a vulnerability checklist scanner, a security-focused chatbot, and a live-feeling attack dashboard — all running end-to-end with no external API keys required.

> **Scope note:** This project is intentionally built to *actually work end-to-end* rather than to claim every buzzword. It does not do real packet capture, real port scanning of arbitrary hosts, or run TensorFlow models — those require infrastructure and legal authorization outside a portfolio project's scope. Instead it uses transparent, explainable heuristics (documented in the code) for its detection logic, which is an honest and interview-defensible design choice. See "Honest scope" below for the full breakdown.

## Live demo screenshots

The dashboard, log analyzer, and AI assistant are all fully functional — screenshots are in `/screenshots` if you want a preview before running it locally.

## Features

- **Authentication** — JWT-based sessions, bcrypt password hashing (12 rounds), rate-limited login/register endpoints, no-user-enumeration error messages.
- **Live Dashboard** — threat score, live attack feed, network health, attack-volume charts (Recharts), auto-refreshing every 15s.
- **Log Analyzer** — paste or upload raw logs (SSH auth logs, access logs, etc.) and run a rule-based detection engine: brute-force threshold detection, SQL injection / XSS / command-injection signature matching, per-IP risk scoring.
- **Vulnerability Scanner** — describe your environment (HTTPS, MFA, open ports, password policy, WAF, etc.) and get an OWASP-aligned risk report. Config-based, not a live network scanner — so it's safe to run against anything, no authorization needed.
- **Threat Intelligence** — sample CVE feed styled after real NVD / MITRE ATT&CK data, in a shape that's a drop-in fit for a real feed integration later.
- **AI Security Assistant** — a rule-based intent-matching chatbot over a curated security knowledge base (SQLi, XSS, brute force, DDoS, phishing, MFA, zero-days, incident response). Architected so the same endpoint can be swapped to call a real LLM later.
- **Dark / light theme toggle**, responsive layout, protected routes.

## Tech stack

**Frontend:** React 18, Vite, React Router, Recharts, Axios, hand-written CSS (no UI framework)
**Backend:** Node.js, Express, JWT (jsonwebtoken), bcryptjs, Helmet, CORS, express-rate-limit

## Project structure

```
cyber-sentinel/
├── backend/
│   ├── src/
│   │   ├── server.js          # Express app entrypoint
│   │   ├── routes/            # auth, threats, logs, vuln, chatbot
│   │   ├── middleware/auth.js # JWT verification middleware
│   │   ├── utils/             # detection.js, scanner.js, chatbot.js (core logic)
│   │   └── data/               # in-memory user store + mock threat intel
│   ├── .env.example
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── pages/              # Login, Register, Dashboard, LogAnalyzer, VulnScanner, ThreatIntel, Assistant
│   │   ├── components/         # Layout, ProtectedRoute, StatCard
│   │   ├── context/AuthContext.jsx
│   │   ├── api/client.js       # Axios instance with JWT interceptor
│   │   └── index.css           # Full design system (CSS variables, dark/light themes)
│   ├── vite.config.js          # Dev proxy: /api -> localhost:5000
│   └── package.json
└── README.md (this file)
```

## Running it locally

**Requirements:** Node.js 18+ and npm.

### 1. Backend

```bash
cd backend
cp .env.example .env
# open .env and set JWT_SECRET to a long random string
npm install
npm run dev        # or: npm start
```

The API runs on `http://localhost:5000`.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

The app runs on `http://localhost:5173` and proxies `/api/*` requests to the backend automatically (see `vite.config.js`).

### 3. Use it

Open `http://localhost:5173`, register an account, and you'll land on the dashboard. All data (users, threat feed) is in-memory for the demo — restarting the backend clears it. Swap `userStore.js` for a real database (Postgres/Mongo) to persist it.

## Honest scope — what's simulated vs. real

Being upfront about this is part of what makes it a credible interview project:

| Feature | What it actually does |
|---|---|
| Auth (JWT, bcrypt, rate limiting) | **Real.** Fully functional, production-pattern auth. |
| Log analysis (brute force, SQLi/XSS/cmd-injection detection) | **Real rule-based detection**, run against whatever text you paste. Not a trained ML model — a documented, explainable heuristic engine, which is a legitimate and common first line of defense in real SOC tooling. |
| Vulnerability scanner | **Real logic**, but scans a *declared configuration* you type in, not a live network probe. Real port/network scanning against arbitrary hosts without authorization is illegal in most jurisdictions — this design sidesteps that safely. |
| Threat intel / CVE feed | **Static sample data**, shaped exactly like a real NVD/MITRE feed response so swapping in `fetch()` calls to the real APIs is a small, well-scoped follow-up. |
| Live attack feed | **Simulated** — randomly generated per request to make the dashboard feel alive. Swappable for a real packet-capture or firewall-log ingestion pipeline. |
| AI chatbot | **Real rule-based intent matching**, not an LLM call — runs fully offline with zero API-key dependency. The code is structured so swapping in a real LLM call is a one-function change. |

## Suggested resume bullet points

- Built a full-stack security dashboard (React/Vite + Node/Express) with JWT authentication, bcrypt password hashing, and rate-limited endpoints following OWASP best practices.
- Designed and implemented a rule-based log-analysis engine detecting brute-force, SQL injection, XSS, and command-injection patterns from raw server logs, with per-source-IP risk scoring.
- Built a configuration-based vulnerability scanner producing OWASP-aligned risk reports without requiring network access to target infrastructure.
- Designed a REST API (Express) with centralized error handling, Helmet security headers, and CORS policy, consumed by a React SPA with protected client-side routing.

## Possible next steps (good "future work" talking points in an interview)

- Swap the in-memory user store for PostgreSQL with a proper migrations layer (Prisma/Knex).
- Replace the rule-based chatbot with a real LLM call (Anthropic/OpenAI API) behind the same `/api/chatbot/message` contract.
- Add a scheduled job pulling live CVE data from the NVD API.
- Add MFA (TOTP) to the auth flow.
- Containerize with Docker Compose (frontend, backend, and a Postgres service).
