/**
 * chatbot.js
 * Sentinel Agent Core — ReAct-style agentic AI for cybersecurity operations.
 *
 * Architecture:
 *   - ReAct Loop: Thought → Action (tool call) → Observation → repeat (max 5 iters)
 *   - 8 callable tools via agentTools.js (get_system_status, get_attack_feed, etc.)
 *   - Per-session conversation memory (20-message sliding window, in-memory Map)
 *   - Streaming: emits agent:step events over Socket.IO for live UI updates
 *   - Graceful offline fallback: rule-based responder when GEMINI_API_KEY is absent
 *
 * If GEMINI_API_KEY is set → full agentic ReAct loop via Gemini 2.0 Flash.
 * Otherwise → offline rule-based responder with live context injection.
 */

const { executeTool, getToolSchemaPrompt, TOOLS } = require('./agentTools');

// ── Conversation Memory Store ─────────────────────────────────────────────────
// Map<sessionId, { messages: Array<{role, content}>, createdAt, lastActive }>
const sessionStore = new Map();
const MAX_SESSION_MESSAGES = 20;   // sliding window per session
const SESSION_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours idle TTL

/**
 * Get or create a session. Prunes idle sessions every time a new one is created.
 */
function getSession(sessionId) {
  if (!sessionStore.has(sessionId)) {
    // Prune sessions older than TTL
    const now = Date.now();
    for (const [id, sess] of sessionStore) {
      if (now - sess.lastActive > SESSION_TTL_MS) sessionStore.delete(id);
    }
    sessionStore.set(sessionId, { messages: [], createdAt: now, lastActive: now });
  }
  const sess = sessionStore.get(sessionId);
  sess.lastActive = Date.now();
  return sess;
}

/**
 * Append a message to session history, enforcing the sliding window.
 */
function appendToSession(sessionId, role, content) {
  const sess = getSession(sessionId);
  sess.messages.push({ role, content });
  if (sess.messages.length > MAX_SESSION_MESSAGES) {
    // Keep the sliding window, but never drop the system context message
    sess.messages.splice(0, sess.messages.length - MAX_SESSION_MESSAGES);
  }
}

/**
 * Clear a session's message history.
 */
function clearSession(sessionId) {
  sessionStore.delete(sessionId);
}

/**
 * Get all sessions info (for debugging/admin).
 */
function getSessionStats() {
  return {
    activeSessions: sessionStore.size,
    sessions: [...sessionStore.entries()].map(([id, s]) => ({
      id,
      messageCount: s.messages.length,
      lastActive: new Date(s.lastActive).toISOString(),
    })),
  };
}

// ── System Prompt ─────────────────────────────────────────────────────────────
function buildSystemPrompt() {
  const toolSchemas = getToolSchemaPrompt();
  return `You are **Sentinel AI** — a highly capable, general-purpose AI assistant with deep expertise in cybersecurity, embedded in the Cyber Sentinel platform.

You are powered by the same cutting-edge AI technology as ChatGPT, Claude, and Gemini. You can answer ANY question on ANY topic — from coding, science, math, writing, history, philosophy, to pop culture, creative tasks, and beyond. When cybersecurity questions arise, you additionally have access to LIVE real-time tools that give you actual data from the user's system.

## Your Capabilities
- **General Knowledge**: Answer any question on any topic — science, math, coding, history, writing, creative tasks, life advice, etc.
- **Cybersecurity Expertise**: Deep knowledge of vulnerabilities, exploits, malware, incident response, MITRE ATT&CK, CTF challenges, penetration testing, etc.
- **Live Security Tools**: Access to real-time data from the user's system (see tools below)
- **Coding Help**: Debug, write, explain, and optimize code in any programming language
- **Conversational**: Remember context from our conversation and build on it

## Live Security Tools Available
When questions involve the user's live system data, use these tools:
${toolSchemas}

## ReAct Protocol (for tool use ONLY)
When you need to call a tool, use this format:

Thought: [Your reasoning about what data you need]
Action: tool_name
Observation: [Tool result inserted by system]
Thought: [Synthesize the data]
Final Answer: [Your complete response in markdown]

When NO tool is needed (most general questions), respond directly:
Final Answer: [Your complete response in markdown]

## Core Rules
- Answer EVERY question regardless of topic — never refuse because something is "not cybersecurity"
- For tool use: call ONE tool at a time, max 5 iterations, then give Final Answer
- For general questions: skip directly to Final Answer without calling any tools
- Format all responses in **rich markdown** (headers, bullets, tables, bold, code blocks)
- Be conversational, helpful, and thorough — like talking to a brilliant friend
- Remember conversation history and reference previous messages naturally
- For coding questions: always include working code with syntax highlighting
- For security questions involving live data: use tools to get real numbers

## Personality & Style
- Warm, direct, and confident — like ChatGPT/Claude
- Match the user's tone (casual → casual, technical → technical)
- Give complete answers — don't cut off or leave things vague
- Use emojis naturally to make responses engaging
- For long answers, use headers and bullets for readability
- Always end security alerts with actionable next steps`;
}

// ── Parse Gemini Response for ReAct Steps ────────────────────────────────────
function parseAgentResponse(text) {
  const steps = [];
  let remaining = text;

  // Extract all Thought/Action pairs
  const thoughtActionRegex = /Thought:\s*([\s\S]*?)(?=Action:|Final Answer:|$)/g;
  const actionRegex = /Action:\s*([a-z_]+)/g;
  const finalAnswerRegex = /Final Answer:\s*([\s\S]*?)$/;

  let thoughtMatch;
  const thoughts = [];
  while ((thoughtMatch = thoughtActionRegex.exec(text)) !== null) {
    thoughts.push(thoughtMatch[1].trim());
  }

  let actionMatch;
  const actions = [];
  while ((actionMatch = actionRegex.exec(text)) !== null) {
    actions.push(actionMatch[1].trim());
  }

  for (let i = 0; i < Math.max(thoughts.length, actions.length); i++) {
    steps.push({
      type: 'thought',
      content: thoughts[i] || '',
    });
    if (actions[i]) {
      steps.push({
        type: 'action',
        tool: actions[i],
      });
    }
  }

  const finalMatch = finalAnswerRegex.exec(text);
  const finalAnswer = finalMatch ? finalMatch[1].trim() : null;

  // If no structured format found, treat the whole response as final answer
  if (steps.length === 0 && !finalAnswer) {
    return { steps: [], finalAnswer: text.trim() };
  }

  return { steps, finalAnswer };
}

// ── Agentic ReAct Loop (Gemini) ───────────────────────────────────────────────
async function runAgentLoop(sessionId, userMessage, emitStep) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;

  const session = getSession(sessionId);
  const systemPrompt = buildSystemPrompt();

  // Build conversation contents for Gemini multi-turn format.
  // Gemini requires: alternating user/model roles, starting with user.
  // We embed the system prompt inside the very first user message.
  const contents = [];

  const history = session.messages; // already stored without current message

  if (history.length === 0) {
    // First turn — embed system prompt
    contents.push({
      role: 'user',
      parts: [{ text: `${systemPrompt}\n\n---\n\nUser: ${userMessage}` }],
    });
  } else {
    // Subsequent turns — inject history then current message
    // First turn must include system prompt
    const firstMsg = history[0];
    contents.push({
      role: firstMsg.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: firstMsg.role === 'user' ? `${systemPrompt}\n\n---\n\nUser: ${firstMsg.content}` : firstMsg.content }],
    });

    for (let i = 1; i < history.length; i++) {
      const msg = history[i];
      contents.push({
        role: msg.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: msg.content }],
      });
    }

    // Add the current user message
    contents.push({
      role: 'user',
      parts: [{ text: userMessage }],
    });
  }

  const toolsUsed = [];
  let conversationContents = [...contents];
  const MAX_ITERATIONS = 5;

  for (let iter = 0; iter < MAX_ITERATIONS; iter++) {
    try {
      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key=${apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: conversationContents,
            generationConfig: {
              temperature: 0.25,
              maxOutputTokens: 4000,
              stopSequences: ['Observation:'],  // Stop before writing its own observation
            },
          }),
        }
      );

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        console.error('[Agent] Gemini error:', response.status, errData?.error?.message);
        return null;
      }

      const data = await response.json();
      // gemini-3.6-flash (thinking model) returns parts array; find the text part
      const parts = data.candidates?.[0]?.content?.parts || [];
      const llmText = (parts.find(p => p.text)?.text || '').trim();
      if (!llmText) return null;

      // Parse the LLM response
      const parsed = parseAgentResponse(llmText);

      // Emit thinking steps to frontend via Socket.IO
      for (const step of parsed.steps) {
        if (step.type === 'thought' && step.content) {
          emitStep?.({ type: 'thought', content: step.content, iteration: iter + 1 });
        }
      }

      // Check if LLM wants to call a tool
      const actionStep = parsed.steps.find(s => s.type === 'action');
      if (actionStep && actionStep.tool) {
        const toolName = actionStep.tool;

        emitStep?.({ type: 'action', tool: toolName, iteration: iter + 1 });

        // Execute the tool
        const { result, error } = await executeTool(toolName);
        const observationText = error
          ? `ERROR: ${error}`
          : JSON.stringify(result, null, 2);

        toolsUsed.push(toolName);

        emitStep?.({ type: 'observation', tool: toolName, result: result || { error }, iteration: iter + 1 });

        // Feed observation back into the conversation
        conversationContents.push({
          role: 'model',
          parts: [{ text: llmText }],
        });
        conversationContents.push({
          role: 'user',
          parts: [{ text: `Observation: ${observationText}\n\nContinue your ReAct reasoning. If you have enough data, provide the Final Answer.` }],
        });

        continue; // Next iteration
      }

      // LLM gave a Final Answer (or no action found)
      if (parsed.finalAnswer) {
        emitStep?.({ type: 'final', toolsUsed, iteration: iter + 1 });
        return { answer: parsed.finalAnswer, steps: parsed.steps, toolsUsed };
      }

      // Fallback: whole response is the answer
      emitStep?.({ type: 'final', toolsUsed, iteration: iter + 1 });
      return { answer: llmText, steps: parsed.steps, toolsUsed };

    } catch (err) {
      console.error('[Agent] Loop error at iteration', iter, ':', err.message);
      return null;
    }
  }

  // Max iterations reached — ask for final answer
  try {
    conversationContents.push({
      role: 'user',
      parts: [{ text: 'You have reached the maximum number of tool calls. Please provide your Final Answer now based on all observations collected.' }],
    });
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: conversationContents,
          generationConfig: { temperature: 0.2, maxOutputTokens: 4000 },
        }),
      }
    );
    const data = await response.json();
    const parts = data.candidates?.[0]?.content?.parts || [];
    const text = (parts.find(p => p.text)?.text || '').trim();
    return { answer: text || 'Analysis complete. Please review the data collected above.', steps: [], toolsUsed };
  } catch (err) {
    return null;
  }
}

// ── Offline fallback — rule-based responder ───────────────────────────────────
function offlineFallback(message) {
  const lower = message.toLowerCase();

  // Build context for inline use
  let ctx = {};
  try {
    const m = global.lastSystemMetrics;
    if (m) ctx.system = m;
    const engine = require('./realtimeEngine');
    const timeline = engine.getTimeline() || [];
    ctx.totalAttacks24h = timeline.reduce((s, b) => s + (b.attacks || 0), 0);
    ctx.totalBlocked24h = timeline.reduce((s, b) => s + (b.blocked || 0), 0);
    const { getThreatPoolCount, liveThreatPool } = require('./liveThreatFetcher');
    ctx.iocCount = getThreatPoolCount();
    ctx.topFamilies = [...new Set(liveThreatPool.slice(0, 30).map(t => t.malware).filter(Boolean))].slice(0, 6);
    ctx.vulnScan = global.lastScanResult;
    ctx.logAnalysis = global.lastLogAnalysis;
    ctx.protection = global.lastProtectionScan;
    ctx.sandbox = global.lastSandboxResult;
  } catch {}

  const s = ctx.system;

  if (lower.match(/\b(status|telemetry|metrics|cpu|ram|memory|disk|threat score|system health|uptime|host)\b/) && s) {
    const findings = (s.findings || []).map(f => `  • [${f.severity}] ${f.title}`).join('\n') || '  • No active findings';
    return `## 🛡️ Live System Status — ${s.hostname}

**Platform**: ${s.platform} (${s.arch}) | **Uptime**: ${s.uptimeDays}d ${s.uptimeHours}h

| Metric | Value | Status |
|--------|-------|--------|
| CPU Usage | ${s.cpu?.usagePercent}% | ${s.cpu?.usagePercent > 80 ? '⚠️ HIGH' : '✅ OK'} |
| RAM Usage | ${s.memory?.usagePercent}% (${s.memory?.usedMb}/${s.memory?.totalMb} MB) | ${s.memory?.usagePercent > 85 ? '⚠️ HIGH' : '✅ OK'} |
| Disk (C:) | ${s.disk ? s.disk.usagePercent + '%' : 'N/A'} | ${s.disk?.usagePercent > 85 ? '⚠️ HIGH' : '✅ OK'} |
| Threat Score | **${s.threatScore}/100** (${s.riskLevel}) | ${s.threatScore > 60 ? '🔴 ALERT' : s.threatScore > 30 ? '🟡 CAUTION' : '🟢 SECURE'} |

**Active Risk Findings:**
${findings}`;
  }

  if (lower.match(/\b(attack|attacks|connection|flagged|detected|threat feed|network scan)\b/)) {
    return `## 🔴 Live Attack Feed Summary

- **Total detected (24h)**: ${ctx.totalAttacks24h || 0}
- **Total blocked (24h)**: ${ctx.totalBlocked24h || 0}
- **IOCs loaded**: ${ctx.iocCount || 0} verified indicators from ThreatFox + CISA KEV
- **Top malware families**: ${(ctx.topFamilies || []).join(', ') || 'N/A'}

All events are detected from **real TCP connections** cross-referenced against the IOC pool.`;
  }

  if (lower.match(/\b(vuln|vulnerability|scan|cve|patch|risk score)\b/) && ctx.vulnScan) {
    const v = ctx.vulnScan;
    const critical = v.issues?.filter(i => i.severity === 'CRITICAL').length || 0;
    const high = v.issues?.filter(i => i.severity === 'HIGH').length || 0;
    return `## 🔍 Last Vulnerability Scan

- **Risk Score**: ${v.riskScore}/100 (${v.riskLevel})
- **Total Issues**: ${v.issues?.length} | 🔴 Critical: ${critical} | 🟠 High: ${high}

**Top Issues:**
${(v.issues || []).slice(0, 5).map(i => `- [${i.severity}] ${i.title}`).join('\n')}

**Recommendation**: Address CRITICAL findings immediately.`;
  }

  if (lower.match(/\b(log|logs|events|apache|nginx|auth|fail2ban)\b/) && ctx.logAnalysis) {
    const l = ctx.logAnalysis;
    return `## 📋 Last Log Analysis

- **Events Scanned**: ${l.summary?.totalEvents} | **Threats**: ${l.summary?.threatCount} | **Critical**: ${l.summary?.criticalCount}

**Key Findings:**
${(l.findings || []).slice(0, 5).map(f => `- [${f.severity}] ${f.title}`).join('\n')}`;
  }

  if (lower.match(/\b(sandbox|sqli|xss|sql injection|command injection|payload|waf)\b/) && ctx.sandbox) {
    const sb = ctx.sandbox;
    return `## ⚗️ Last Sandbox Simulation

- **Type**: ${sb.type?.toUpperCase()} | **Result**: ${sb.status}
- **WAF Blocked**: ${sb.blocked ? '✅ YES' : '❌ NO'}
- **Payload**: \`${sb.payload}\``;
  }

  if (lower.match(/\b(phishing|email|link|url|file|malware|protection)\b/) && ctx.protection) {
    const p = ctx.protection;
    return `## 🛡️ Last Protection Center Scan

- **Type**: ${p.scanType} | **Verdict**: ${p.verdict} | **Severity**: ${p.severity}
- **Summary**: ${p.summary}`;
  }

  if (lower.match(/\b(threatfox|cisa|ioc|indicator|malware family|threat intel)\b/)) {
    return `## 📡 Live Threat Intelligence

- **IOCs Loaded**: ${ctx.iocCount || 0} verified indicators from ThreatFox + CISA KEV
- **Active Malware Families**: ${(ctx.topFamilies || []).join(', ') || 'Loading...'}`;
  }

  // Knowledge base fallback
  const hit = [
    { keywords: ['sql injection', 'sqli'], response: 'SQL Injection: use parameterized queries, least-privilege DB accounts, and server-side input validation.' },
    { keywords: ['xss', 'cross-site scripting'], response: 'XSS: apply output encoding, strict CSP headers, and treat all user input as untrusted.' },
    { keywords: ['brute force', 'bruteforce'], response: 'Brute-force: enforce account lockout, rate limiting, CAPTCHA, and mandatory MFA.' },
    { keywords: ['ransomware'], response: 'Ransomware: maintain offline backups (3-2-1 rule), deploy EDR, segment the network, and restrict RDP.' },
    { keywords: ['phishing'], response: 'Phishing: enforce DMARC/SPF/DKIM, conduct user security training, and sandbox all attachments.' },
    { keywords: ['zero day', 'zero-day'], response: 'Zero-day: apply network segmentation, least privilege, and deploy behavioral EDR monitoring.' },
    { keywords: ['mfa', 'multi-factor', '2fa'], response: 'MFA blocks the vast majority of credential-stuffing attacks. Enforce TOTP/FIDO2 for all privileged accounts.' },
    { keywords: ['ddos', 'denial of service'], response: 'DDoS: use upstream scrubbing (Cloudflare/AWS Shield), rate limiting, connection timeouts, and auto-scaling.' },
    { keywords: ['mitre', 'att&ck', 'ttp'], response: 'MITRE ATT&CK is a knowledge base of adversary TTPs. Map detected behaviors to it to prioritize defenses.' },
    { keywords: ['cve'], response: 'CVEs are standardized vulnerability identifiers. Prioritize patching using the CISA KEV (Known Exploited Vulnerabilities) catalog.' },
    { keywords: ['firewall'], response: 'Firewall hardening: default-deny inbound, allow only required ports, log dropped packets, audit rules quarterly.' },
    { keywords: ['incident response', 'ir plan'], response: 'IR flow: 1) Detect & triage → 2) Contain → 3) Eradicate → 4) Recover → 5) Post-incident review.' },
    { keywords: ['port scan', 'nmap'], response: 'Port scanning: close unused ports, use a firewall, detect scans with IDS/IPS (Snort/Suricata).' },
    { keywords: ['cobalt strike', 'beacon'], response: 'Cobalt Strike Beacon is a common C2 tool. Detect via beaconing intervals on 443/80. Block known C2 IPs at the firewall.' },
    { keywords: ['log4j', 'log4shell', 'cve-2021-44228'], response: 'Log4Shell (CVE-2021-44228): upgrade to Log4j 2.17.1+ or set `log4j2.formatMsgNoLookups=true`.' },
  ].find(entry => entry.keywords.some(k => lower.includes(k)));

  if (hit) return hit.response;

  return `I'm your Sentinel AI SOC analyst. I have live access to:
- 🖥️ **System metrics** (CPU/RAM/Disk/Network)
- 🔴 **Live attack feed** (real TCP monitoring)
- 📋 **Log Analyzer** results
- 🔍 **Vulnerability Scanner** findings
- 📡 **Threat Intel** (ThreatFox + CISA KEV)
- 🛡️ **Protection Center** scan results
- ⚗️ **Attack Sandbox** simulations

Try: "What is my threat score?", "Show vulnerability findings", "Analyze attack feed", "Run a quick vulnerability check"`;
}

// ── Main Agent Entry Point ────────────────────────────────────────────────────
/**
 * Runs the full agentic pipeline for a given session and user message.
 *
 * @param {string} message      - User's input
 * @param {string} sessionId    - Unique session identifier (for memory)
 * @param {Function} emitStep   - Optional callback: fn({type, content, tool, ...}) for streaming
 * @returns {Promise<{reply: string, steps: Array, toolsUsed: Array}>}
 */
async function respond(message, sessionId = 'default', emitStep = null) {
  // Store user message in session memory
  appendToSession(sessionId, 'user', message);

  let reply, steps = [], toolsUsed = [];

  // Try full agentic loop
  const agentResult = await runAgentLoop(sessionId, message, emitStep);

  if (agentResult) {
    reply = agentResult.answer;
    steps = agentResult.steps || [];
    toolsUsed = agentResult.toolsUsed || [];
  } else {
    // Offline fallback
    reply = offlineFallback(message);
    emitStep?.({ type: 'offline', message: 'Running in offline mode — add GEMINI_API_KEY to enable the full agentic loop.' });
  }

  // Store assistant reply in session memory
  appendToSession(sessionId, 'assistant', reply);

  return { reply, steps, toolsUsed };
}

module.exports = { respond, clearSession, getSessionStats, appendToSession };
