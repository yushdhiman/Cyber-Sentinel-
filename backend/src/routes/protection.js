const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { analyzeEmail, analyzeLink, analyzeFile } = require('../utils/protectionEngine');

const router = express.Router();
router.use(requireAuth);

/**
 * POST /api/protection/scan-email
 * Scan email subject, sender, and text body.
 */
router.post('/scan-email', (req, res) => {
  const { emailText, emailSubject, emailSender } = req.body;
  if (typeof emailText !== 'string') {
    return res.status(400).json({ error: 'emailText (string) is required' });
  }

  const result = analyzeEmail(emailText, emailSubject || '', emailSender || '');
  res.json(result);
});

/**
 * POST /api/protection/scan-link
 * Scan URL.
 */
router.post('/scan-link', (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'url (string) is required' });
  }

  const result = analyzeLink(url);
  res.json(result);
});

/**
 * POST /api/protection/scan-file
 * Scan file properties/signature.
 */
router.post('/scan-file', (req, res) => {
  const { fileName, fileSize, fileHash, rawContent } = req.body;
  if (!fileName || typeof fileName !== 'string') {
    return res.status(400).json({ error: 'fileName (string) is required' });
  }

  const size = typeof fileSize === 'number' ? fileSize : 0;
  const result = analyzeFile(fileName, size, fileHash || '', rawContent || '');
  res.json(result);
});

/**
 * POST /api/protection/explain
 * Retrieve AI-assisted threat context or mitigation recommendations for a specific protection scan.
 */
router.post('/explain', async (req, res) => {
  const { scanType, scanResult } = req.body;
  const apiKey = process.env.GEMINI_API_KEY;

  if (!scanType || !scanResult || typeof scanResult !== 'object') {
    return res.status(400).json({ error: 'scanType (string) and scanResult (object) are required' });
  }

  // Define static fallback reports
  const fallbacks = {
    email: `### Email Security Mitigation Report (Local Signatures Mode)
- **Status**: ${scanResult.summary?.status}
- **Threat Index**: ${scanResult.summary?.threatScore}/100
- **Identified Indicators**: ${scanResult.tags?.join(', ') || 'None'}

**Analysis**:
The email content shows classic triggers associated with business email compromise (BEC) or credential phishing. Attackers regularly leverage urgency cues (e.g. "immediately", "action required") and brand spoofing to trick users.

**Remediation & Best Practices**:
1. **Enable DMARC/DKIM/SPF**: Ensure incoming server filters enforce validation of sender identity to block brand spoofing.
2. **URL Rewrite Protection**: Route embedded email URLs through secure redirection inspection gateways.
3. **User Security Training**: Train staff to verify unexpected payment or credentials-reset requests via secondary authentic channels.`,

    link: `### Link Protection Mitigation Report (Local Signatures Mode)
- **URL**: \`${scanResult.url}\`
- **Status**: ${scanResult.summary?.status}
- **Threat Index**: ${scanResult.summary?.threatScore}/100

**Analysis**:
The URL contains patterns typical of malicious redirectors or credential-harvesting setups, such as suspicious top-level domains (.xyz/.click), subdomains containing brand names, or direct IP formatting.

**Remediation & Best Practices**:
1. **Implement DNS Filters**: Restrict endpoints by querying real-time DNS blocklists (RBLs) at the gateway layer.
2. **Deploy Endpoint Threat Protection**: Block raw IP navigation in browser sessions for corporate workstations.
3. **URL Sandboxing**: Use inline secure web gateway (SWG) inspection to evaluate links inside sandbox virtual containers before user exposure.`,

    file: `### File Protection & Threat Mitigation Report (Local Signatures Mode)
- **File**: \`${scanResult.fileName}\` (${scanResult.fileSize} bytes)
- **Status**: ${scanResult.summary?.status}
- **Malware Signature**: ${scanResult.detectedMalwareName || 'None Detected'}

**Analysis**:
The file shows indicators matching suspicious execution profiles. These include scripting extensions (.vbs/.bat/.ps1) that facilitate command staging, or classical double extension masking.

**Remediation & Best Practices**:
1. **Disable Windows Script Host / PowerShell for Users**: Prevent non-administrative users from executing active script contexts directly from disk.
2. **Enforce Endpoint Detection & Response (EDR)**: Deploy behavioral detection tools that monitor process parent-child relationships (e.g., Word spawning powershell.exe).
3. **Verify File Hashes**: Query hashes automatically against global threat hubs like VirusTotal prior to execution.`
  };

  const fallbackReport = fallbacks[scanType] || `### Malware & Protection Scan Report\n- **Status**: ${scanResult.summary?.status || 'Unknown'}\n- **Details**: Local inspection completed.`;

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
                  text: `You are Cyber Sentinel, an expert security operations and malware analyst. Write a professional threat mitigation report for the user based on the following security scan result. Explain the mechanics of this threat, the severity of the findings, and clear actionable mitigation protocols.

Scan Type: ${scanType}
Scan Results Data:
${JSON.stringify(scanResult, null, 2)}

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

    console.warn('Gemini API returned error or empty response. Falling back to local mitigation report.');
    return res.json({ explanation: fallbackReport });
  } catch (error) {
    console.error('Error generating AI explanation for protection, falling back to local report:', error);
    return res.json({ explanation: fallbackReport });
  }
});

module.exports = router;
