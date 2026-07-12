// Rule-based cybersecurity assistant.
//
// This is a keyword/intent-matching responder, not an LLM call — kept
// this way so the project has zero external API-key dependencies and
// runs fully offline. The architecture (intents -> handlers) is written
// so it's trivial to swap in a real LLM call (OpenAI/Anthropic API) later:
// just replace `matchIntent` + `respond` with a fetch to a chat completion
// endpoint using the same function signature.

const knowledgeBase = [
  {
    keywords: ['sql injection', 'sqli'],
    response:
      'SQL Injection happens when untrusted input is concatenated directly into a SQL query. Mitigation: use parameterized queries / prepared statements, apply least-privilege DB accounts, and validate input server-side. Never rely on client-side validation alone.',
  },
  {
    keywords: ['xss', 'cross-site scripting'],
    response:
      'Cross-Site Scripting lets an attacker inject script into pages viewed by other users. Mitigate with output encoding, a strict Content-Security-Policy, and treating all user input as untrusted when rendering HTML.',
  },
  {
    keywords: ['brute force', 'bruteforce'],
    response:
      'Brute-force attacks repeatedly guess credentials. Defend with account lockout / exponential backoff, rate limiting, CAPTCHA after N failures, and mandatory MFA so a leaked password alone is not enough.',
  },
  {
    keywords: ['log4j', 'log4shell', 'cve-2021-44228'],
    response:
      'Log4Shell (CVE-2021-44228) is a remote code execution flaw in Apache Log4j triggered via JNDI lookups in logged strings. Fix: upgrade to Log4j 2.17.1+, or disable JNDI lookups if patching is not immediately possible.',
  },
  {
    keywords: ['ddos', 'denial of service'],
    response:
      'DDoS attacks overwhelm a service with traffic. Mitigations include upstream traffic scrubbing (e.g. Cloudflare/AWS Shield), rate limiting, connection timeouts, and horizontal auto-scaling for absorbing legitimate traffic spikes.',
  },
  {
    keywords: ['phishing'],
    response:
      'Phishing tricks users into revealing credentials or running malicious code, usually via email or lookalike domains. Defenses: user security-awareness training, DMARC/SPF/DKIM email authentication, and link/attachment sandboxing.',
  },
  {
    keywords: ['mfa', 'multi-factor', '2fa', 'two factor'],
    response:
      'Multi-factor authentication requires a second proof of identity beyond a password (TOTP app, hardware key, or push approval). It blocks the vast majority of credential-stuffing and phishing-derived account takeovers.',
  },
  {
    keywords: ['zero day', 'zero-day'],
    response:
      'A zero-day is a vulnerability unknown to the vendor with no patch available yet. Reduce exposure with defense-in-depth: network segmentation, least privilege, EDR/behavioral monitoring, and rapid patch-management processes for when a fix ships.',
  },
  {
    keywords: ['firewall rule', 'firewall'],
    response:
      'A basic hardening firewall policy: default-deny inbound, explicitly allow only required ports (e.g. 443, 22 from admin IPs only), log dropped packets, and review rules quarterly for unused allowances.',
  },
  {
    keywords: ['incident response', 'ir plan'],
    response:
      'A standard IR flow: 1) Detect & triage, 2) Contain (isolate affected hosts / rotate creds), 3) Eradicate root cause, 4) Recover services, 5) Post-incident review with a written timeline and action items.',
  },
];

const fallback =
  "I don't have a canned answer for that specific term, but I can help with SQL injection, XSS, brute force, DDoS, phishing, MFA, zero-days, firewall rules, incident response, or explaining a specific CVE — try asking about one of those.";

async function respond(message, systemContext = null) {
  const apiKey = process.env.GEMINI_API_KEY;
  
  // Format system metrics context for the AI prompt
  let telemetryPrompt = '';
  if (systemContext) {
    telemetryPrompt = `
[REAL-TIME SYSTEM TELEMETRY OF THE HOST MACHINE]
- Hostname: ${systemContext.hostname || 'unknown'}
- OS Platform: ${systemContext.platform || 'unknown'}
- Threat Score: ${systemContext.threatScore}/100 (Risk Level: ${systemContext.riskLevel || 'LOW'})
- CPU Usage: ${systemContext.cpuUsage != null ? systemContext.cpuUsage + '%' : 'unknown'}
- RAM Usage: ${systemContext.memoryUsage != null ? systemContext.memoryUsage + '%' : 'unknown'}
- Network Health: ${systemContext.networkHealth != null ? systemContext.networkHealth + '%' : 'unknown'}
- Active Network Adapters: ${systemContext.activeDevices || 0}
- Uptime: ${systemContext.uptimeDays || 0} days
- Active Risk Findings: ${systemContext.findings ? JSON.stringify(systemContext.findings) : '[]'}
`;
  }

  if (apiKey) {
    try {
      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            contents: [
              {
                role: 'user',
                parts: [
                  {
                    text: `You are Cyber Sentinel, an advanced AI-powered cybersecurity assistant. You have direct access to the host machine's live system metrics and active threat telemetry. 
                    
Use the following real-time system telemetry when answering the user's questions or when they ask about system status, resource usage, active threats, or risk findings. If they ask a general security question, you can answer it normally but relate it back to the host system status if relevant.

${telemetryPrompt}

Here is the user's query:
${message}`,
                  },
                ],
              },
            ],
          }),
        }
      );

      if (response.ok) {
        const data = await response.json();
        const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
        if (text) {
          return text;
        }
      } else {
        console.error('Gemini API returned error status:', response.status);
      }
    } catch (error) {
      console.error('Error calling Gemini API:', error);
    }
  }

  // Fallback to local offline rule-based responder
  const lower = message.toLowerCase();

  // Dynamic real-time responses for offline mode
  if (systemContext && (
    lower.includes('status') || 
    lower.includes('telemetry') || 
    lower.includes('metrics') || 
    lower.includes('cpu') || 
    lower.includes('ram') || 
    lower.includes('memory') || 
    lower.includes('threat') || 
    lower.includes('score') || 
    lower.includes('findings') || 
    lower.includes('uptime') ||
    lower.includes('host')
  )) {
    const findingsList = systemContext.findings && systemContext.findings.length > 0
      ? systemContext.findings.map(f => `  • [${f.severity}] ${f.title}`).join('\n')
      : '  • No active security findings. Configuration secure.';

    return `🛡️ [REAL-TIME SYSTEM MONITORING TELEMETRY]
    
• Hostname: ${systemContext.hostname} (${systemContext.platform})
• Uptime: ${systemContext.uptimeDays} days
• Threat Score: ${systemContext.threatScore}/100 (${systemContext.riskLevel} RISK)
• CPU Usage: ${systemContext.cpuUsage}%
• RAM Usage: ${systemContext.memoryUsage}%
• Network Health: ${systemContext.networkHealth}%
• Active Interfaces: ${systemContext.activeDevices} external adapter(s)

Active Risk Findings:
${findingsList}

*Note: Telemetry is fetched directly from the OS layers via WebSockets with zero latency.*`;
  }

  const hit = knowledgeBase.find((entry) => entry.keywords.some((k) => lower.includes(k)));
  return hit ? hit.response : fallback;
}

module.exports = { respond };
