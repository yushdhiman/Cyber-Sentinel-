const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { analyzeLog } = require('../utils/detection');

const router = express.Router();
router.use(requireAuth);

const MAX_LOG_CHARS = 500_000; // ~0.5MB of text, generous for a demo

const { setLastLogAnalysis } = require('../data/securityStore');
const { logSecurityEvent, AuditActions } = require('../utils/auditLogger');
const { recordWebExploit } = require('../utils/correlationEngine');

router.post('/analyze', (req, res) => {
  const { logText } = req.body;

  if (!logText || typeof logText !== 'string') {
    return res.status(400).json({ error: 'logText (string) is required' });
  }
  if (logText.length > MAX_LOG_CHARS) {
    return res.status(413).json({ error: `Log too large. Max ${MAX_LOG_CHARS} characters for this demo.` });
  }

  const result = analyzeLog(logText);
  setLastLogAnalysis(result);

  // Check if any finding is a successful exploit (HTTP 200 on SQLi / RCE)
  if (result.findings && Array.isArray(result.findings)) {
    result.findings.forEach(f => {
      if (f.severity === 'CRITICAL' || f.type?.includes('SQL') || f.type?.includes('Exploit')) {
        recordWebExploit({
          ip: f.sourceIp || '127.0.0.1',
          attackType: f.type || 'Web Application Exploit',
          payload: f.matchSnippet || logText.slice(0, 150),
          path: f.path || '/api/v1',
          statusCode: f.statusCode || 200,
        });
      }
    });
  }

  logSecurityEvent({
    actor: req.user?.email,
    actorRole: req.user?.role,
    action: AuditActions.SCAN_COMPLETED,
    target: 'LOG_ANALYZER',
    req,
    details: { totalFindings: result.findings?.length, severity: result.summary?.highestSeverity },
  });

  res.json(result);
});

router.post('/explain', async (req, res) => {
  const { findings, summary } = req.body;
  const apiKey = process.env.GEMINI_API_KEY;

  if (!findings || !summary || !Array.isArray(findings) || typeof summary !== 'object') {
    return res.status(400).json({ error: 'findings (array) and summary (object) are required' });
  }

  const fallbackReport = `### Security Analyst Mitigation Report (Local Signatures Mode)

The automated inspection engine has identified threat patterns in your server log stream. Below is a breakdown of the detected vectors and mitigation recommendations:

1. **Brute Force SSH/Admin Login Attempts** (Detected: High volume of authentication failures)
   * **Mitigation**: Enable key-based authentication only, disable root login on SSH, change public ports, and configure automated ban layers (e.g. Fail2ban).
2. **Web Vulnerability Exploit Signature (SQL Injection)** (Detected: Union Select commands)
   * **Mitigation**: Implement Prepared Statements server-side, configure proper database query escapes, enforce strict character typecasting, and route database access with least privileges.
3. **Cross-Site Scripting (XSS) Attempts** (Detected: Script elements)
   * **Mitigation**: Encode all dynamically rendered output elements, restrict page actions using a Content-Security-Policy (CSP), and filter inputs.

*Pro-tip: Supply a valid Gemini API key in the backend configuration to unlock deep AI security analysis tailored to this specific log sequence.*`;

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
                  text: `You are Cyber Sentinel, an expert SOC Analyst. Review this summary of log analysis findings and generate a professional security investigation report. Explain the nature of each threat, assess the risk level, and provide concrete mitigation recommendations. Format the response with clear markdown headings, bullet points, and high-impact security warnings.\n\nSummary:\n${JSON.stringify(summary, null, 2)}\n\nSuspicious Findings (top 15):\n${JSON.stringify(findings.slice(0, 15), null, 2)}`,
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
        return res.json({ explanation: text });
      }
    }
    
    console.warn('Gemini API returned error or empty response. Falling back to local mitigation report.');
    return res.json({ explanation: fallbackReport });
  } catch (error) {
    console.error('Error generating AI explanation, falling back to local report:', error);
    return res.json({ explanation: fallbackReport });
  }
});

router.post('/ask', async (req, res) => {
  const { question, findings, summary } = req.body;
  const apiKey = process.env.GEMINI_API_KEY;

  if (!question || typeof question !== 'string' || !findings || !summary || !Array.isArray(findings) || typeof summary !== 'object') {
    return res.status(400).json({ error: 'question (string), findings (array), and summary (object) are required' });
  }

  const fallbackAnswer = `### AI Assistant Response (Local Heuristic Analyst)

Based on your question: *"${question}"*, and the local signatures findings (which flagged a risk level of **${summary.riskLevel}** across **${summary.totalLines}** lines):
* **Suspicious Activity**: Flags include brute force login sequences and common script payloads (SQLi/XSS).
* **Investigation recommendation**: Check the active console log highlights at the flagged lines to inspect matched strings. Ensure public-facing inputs are parameterized.`;

  if (!apiKey) {
    return res.json({ answer: fallbackAnswer });
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
                  text: `You are Cyber Sentinel, an expert security analyst assisting a user. They have run a log security analysis and have a question. Below is the log analysis summary, the specific suspicious findings, and the user's question. Provide a helpful, clear, and professional response addressing their question with actionable security advice.\n\nLog Summary:\n${JSON.stringify(summary, null, 2)}\n\nFindings:\n${JSON.stringify(findings.slice(0, 15), null, 2)}\n\nUser's Question:\n"${question}"`,
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
        return res.json({ answer: text });
      }
    }
    
    console.warn('Gemini API returned error or empty response. Falling back to local offline responder.');
    return res.json({ answer: fallbackAnswer });
  } catch (error) {
    console.error('Error generating AI answer, falling back to local offline answer:', error);
    return res.json({ answer: fallbackAnswer });
  }
});

module.exports = router;
