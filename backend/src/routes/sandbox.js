const express = require('express');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
router.use(requireAuth);

const VULN_CODE = {
  sqli: {
    vuln: `// VULNERABLE CODE: Concatenating input directly into the query
app.post('/api/users/lookup', async (req, res) => {
  const { username } = req.body;
  
  // Vulnerable raw query
  const query = "SELECT id, username, email, role FROM users WHERE username = '" + username + "'";
  const results = await db.query(query);
  
  res.json({ success: true, results });
});`,
    secure: `// SECURE CODE: Using parameterized queries / prepared statements
app.post('/api/users/lookup', async (req, res) => {
  const { username } = req.body;
  
  // Secure parameterized query
  const query = "SELECT id, username, email, role FROM users WHERE username = $1";
  const results = await db.query(query, [username]);
  
  res.json({ success: true, results });
});`
  },
  xss: {
    vuln: `// VULNERABLE CODE: Rendering unsanitized input directly to HTML template
app.get('/profile', (req, res) => {
  const { bio } = req.query;
  
  // Vulnerable rendering
  res.send(\`
    <div class="profile-bio">
      <p>User Bio: \${bio}</p>
    </div>
  \`);
});`,
    secure: `// SECURE CODE: Encoding content using validation or DOMPurify
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const purify = DOMPurify(window);

app.get('/profile', (req, res) => {
  const { bio } = req.query;
  
  // Sanitize the input content before rendering
  const safeBio = purify.sanitize(bio);
  
  res.send(\`
    <div class="profile-bio">
      <p>User Bio: \${safeBio}</p>
    </div>
  \`);
});`
  },
  cmd: {
    vuln: `// VULNERABLE CODE: Passing unvalidated inputs directly to system shell execution
const { exec } = require('child_process');

app.post('/api/ping', (req, res) => {
  const { host } = req.body;
  
  // Vulnerable execution
  exec(\`ping -c 3 \${host}\`, (error, stdout, stderr) => {
    res.json({ output: stdout || stderr });
  });
});`,
    secure: `// SECURE CODE: Validating input against strict patterns or using execFile
const { execFile } = require('child_process');

app.post('/api/ping', (req, res) => {
  const { host } = req.body;
  
  // Secure: Strict validation check (Only allow valid domain/IP characters)
  const ipRegex = /^[a-zA-Z0-9.-]+$/;
  if (!ipRegex.test(host)) {
    return res.status(400).json({ error: 'Invalid hostname format' });
  }
  
  // Use execFile to avoid invoking a shell
  execFile('ping', ['-c', '3', host], (error, stdout, stderr) => {
    res.json({ output: stdout || stderr });
  });
});`
  }
};

router.post('/simulate', (req, res) => {
  const { type, payload, securityEnabled } = req.body;

  if (!type || !payload || typeof payload !== 'string') {
    return res.status(400).json({ error: 'type (string) and payload (string) are required' });
  }

  const logs = [];
  let blocked = false;
  let status = 'SUCCESS';
  let executionResult = '';

  const timestamp = () => new Date().toLocaleTimeString();

  logs.push(`[${timestamp()}] INFO: Connection initiated from client.`);
  logs.push(`[${timestamp()}] INFO: Sending payload via POST request.`);

  // 1. Check WAF / Security Layer
  if (securityEnabled) {
    logs.push(`[${timestamp()}] WAF: Inspecting payload contents.`);
    let wafTriggered = false;

    if (type === 'sqli') {
      const sqliPatterns = [/('|--|select|union|insert|delete|update|drop|or\s+\d+=\d+)/i];
      wafTriggered = sqliPatterns.some(p => p.test(payload));
    } else if (type === 'xss') {
      const xssPatterns = [/(<script|javascript:|onerror|onload|alert|<img)/i];
      wafTriggered = xssPatterns.some(p => p.test(payload));
    } else if (type === 'cmd') {
      const cmdPatterns = [/(&|\||;|\$|>|<|`|cat|ls|pwd|whoami|sh|bash)/i];
      wafTriggered = cmdPatterns.some(p => p.test(payload));
    }

    if (wafTriggered) {
      logs.push(`[${timestamp()}] WAF: BLOCK - Malicious payload pattern matched.`);
      blocked = true;
      status = 'BLOCKED';
      executionResult = 'WAF BLOCK: Request blocked by security policy. (Status Code 403 Forbidden)';
    } else {
      logs.push(`[${timestamp()}] WAF: PASS - No threat patterns detected.`);
    }
  } else {
    logs.push(`[${timestamp()}] WARNING: WAF / Input Sanitization filters are DISABLED.`);
  }

  // 2. Server Processing
  if (!blocked) {
    logs.push(`[${timestamp()}] SERVER: Processing request parameters.`);

    if (type === 'sqli') {
      if (securityEnabled) {
        logs.push(`[${timestamp()}] DB: Executing parameterized SQL query.`);
        logs.push(`[${timestamp()}] DB: SELECT id, username, email FROM users WHERE username = ? [${payload}]`);
        executionResult = 'Database query executed safely. No injection occurred. Empty result set returned.';
      } else {
        logs.push(`[${timestamp()}] DB: Executing raw SQL statement: SELECT id, username, email FROM users WHERE username = '${payload}'`);
        
        // Return simulated leaked data for classic SQLi
        const lower = payload.toLowerCase();
        if (lower.includes('or') || lower.includes('union') || lower.includes('--') || lower.includes("'")) {
          logs.push(`[${timestamp()}] WARNING: SQL Query modified dynamically by input syntax.`);
          logs.push(`[${timestamp()}] DB: Extracted 3 records from target database.`);
          executionResult = JSON.stringify([
            { id: 1, username: 'admin', email: 'admin@sentinel.internal', role: 'SuperAdministrator' },
            { id: 2, username: 'db_owner', email: 'db_owner@sentinel.internal', role: 'DBA' },
            { id: 3, username: 'sec_officer', email: 'officer@sentinel.internal', role: 'Security' }
          ], null, 2);
        } else {
          executionResult = 'Database lookup executed. 0 results match username: ' + payload;
        }
      }
    } else if (type === 'xss') {
      if (securityEnabled) {
        logs.push(`[${timestamp()}] SERVER: Encoding HTML response elements to prevent DOM injection.`);
        executionResult = `Safe DOM string rendered: &lt;div&gt;${payload.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;').replace(/\//g, '&#x2F;')}&lt;/div&gt;`;
      } else {
        logs.push(`[${timestamp()}] WARNING: Rendering raw unsanitized output directly to document context.`);
        logs.push(`[${timestamp()}] BROWSER: Executed inline script context from injected content.`);
        executionResult = `RENDERED HTML CONTEXT:\n-------------------------------\n<div>${payload}</div>\n-------------------------------\n⚠️ Vulnerable browser executes XSS Payload. Cookie session hijacked!`;
      }
    } else if (type === 'cmd') {
      if (securityEnabled) {
        logs.push(`[${timestamp()}] SERVER: Performing input sanitization regex check.`);
        const ipRegex = /^[a-zA-Z0-9.-]+$/;
        if (!ipRegex.test(payload)) {
          logs.push(`[${timestamp()}] SERVER: BLOCK - Command input failed sanity checks.`);
          blocked = true;
          status = 'REJECTED';
          executionResult = 'Error: Invalid hostname parameter pattern matching. Execution aborted.';
        } else {
          logs.push(`[${timestamp()}] SHELL: Safely executing: ping -c 3 ${payload}`);
          executionResult = `PING ${payload} (127.0.0.1) 56(84) bytes of data.\n64 bytes from localhost (127.0.0.1): icmp_seq=1 ttl=64 time=0.031 ms\n\n--- ${payload} ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss`;
        }
      } else {
        logs.push(`[${timestamp()}] SHELL: Executing system shell process: ping -c 3 ${payload}`);
        
        // Return simulated file read or execution if command separator is used
        if (payload.includes(';') || payload.includes('|') || payload.includes('&') || payload.includes('`')) {
          logs.push(`[${timestamp()}] WARNING: Command separator found. Executing secondary injected process.`);
          if (payload.includes('cat') || payload.includes('passwd') || payload.includes('hosts')) {
            executionResult = `root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\n\n[Injected shell instruction execution complete]`;
          } else if (payload.includes('whoami')) {
            executionResult = `nt authority\\system\n[Injected shell instruction execution complete]`;
          } else {
            executionResult = `Directory of C:\\Users\\Ayush\\Downloads\\cyber-sentinel\\cyber-sentinel\\backend\n\n2026-07-11  21:50    <DIR>          .\n2026-07-11  21:50    <DIR>          ..\n2026-07-11  21:50               178 .env\n2026-07-11  21:50               109 .env.example\n2026-07-11  21:52    <DIR>          node_modules\n2026-07-11  21:50            51,127 package-lock.json\n2026-07-11  21:50               569 package.json\n2026-07-11  21:50    <DIR>          src\n\n[Injected shell instruction execution complete]`;
          }
        } else {
          executionResult = `PING ${payload} (127.0.0.1) 56(84) bytes of data.\n64 bytes from localhost (127.0.0.1): icmp_seq=1 ttl=64 time=0.040 ms\n\n--- ${payload} ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss`;
        }
      }
    }
  }

  const result = {
    type,
    payload,
    securityEnabled,
    blocked,
    status,
    logs,
    executionResult,
    code: VULN_CODE[type]
  };
  global.lastSandboxResult = result;
  res.json(result);
});

router.post('/explain', async (req, res) => {
  const { type, payload, securityEnabled } = req.body;
  const apiKey = process.env.GEMINI_API_KEY;

  if (!type || !payload || typeof payload !== 'string') {
    return res.status(400).json({ error: 'type (string) and payload (string) are required' });
  }

  const fallbackReport = `### Local Security Analysis Report
- **Attack Vector**: ${type.toUpperCase()} (${type === 'sqli' ? 'SQL Injection' : type === 'xss' ? 'Cross-Site Scripting' : 'Command Injection'})
- **Submitted Payload**: \`${payload}\`
- **Mitigation Status**: ${securityEnabled ? 'ACTIVE / SECURED' : 'VULNERABLE / INSECURE'}

**Summary**: 
The submitted payload represents a common web application security test. Without adequate parameterization or sanitization, this input overrides application instructions to extract database tables, hijack browser DOM sessions, or run unauthorized shell command directives.

**Recommendations**:
1. ${type === 'sqli' ? 'Ensure all database queries utilize prepared statements.' : type === 'xss' ? 'Encode dynamic output fields to prevent HTML/JS interpretation.' : 'Sanitize shell parameters using regular expressions or avoid calling CLI executors entirely.'}
2. Conduct regular source inspections and audit application inputs with static analysis tools.`;

  if (!apiKey) {
    return res.json({ explanation: fallbackReport });
  }

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
                  text: `You are Cyber Sentinel, an expert SOC Analyst and Secure Coder. Analyze the following web security sandbox simulation details. Explain the mechanics of the submitted payload, why it succeeds or fails under the active configuration, the severity of the threat, and clear coding standards required to block it.

Vulnerability Type: ${type}
Payload: ${payload}
Security Enabled/WAF Active: ${securityEnabled ? 'Yes' : 'No'}

Respond using professional security terminology with readable markdown layout.`
                }
              ]
            }
          ]
        })
      }
    );

    if (response.ok) {
      const data = await response.json();
      const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
      if (text) {
        return res.json({ explanation: text });
      }
    }

    res.json({ explanation: fallbackReport });
  } catch (error) {
    console.error('Error generating sandbox AI explanation:', error);
    res.json({ explanation: fallbackReport });
  }
});

module.exports = router;
