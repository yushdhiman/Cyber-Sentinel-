// Rule-based log analysis engine.
//
// This is deliberately NOT a deep-learning model — it's a transparent,
// explainable detector built from well-known heuristics real SOC tooling
// uses as a first pass (threshold-based brute-force detection, regex-based
// injection signatures, rarity-based anomaly scoring). This is an honest
// and defensible "AI-assisted" claim: it's automated pattern detection,
// not a trained neural net, and the code should say so wherever it's used.

const SQLI_PATTERNS = [/(\bunion\b.+\bselect\b)/i, /(\bor\b\s+1\s*=\s*1)/i, /(--|#|\/\*)\s*$/, /(\bdrop\b\s+\btable\b)/i, /'\s*or\s*'1'\s*=\s*'1/i];
const XSS_PATTERNS = [/<script[\s>]/i, /onerror\s*=/i, /javascript:/i, /<img[^>]+onerror/i];
const CMD_INJECTION_PATTERNS = [/;\s*(cat|ls|whoami|rm|curl|wget)\b/i, /\|\s*(nc|bash|sh)\b/i, /`.*`/];

const FAILED_LOGIN_PATTERNS = [
  /failed password/i,
  /authentication failure/i,
  /invalid user/i,
  /401/, // HTTP unauthorized
  /login failed/i,
];

const IP_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

function extractIp(line) {
  const m = line.match(IP_REGEX);
  return m ? m[0] : 'unknown';
}

function analyzeLog(rawText) {
  const lines = rawText.split(/\r?\n/).filter(Boolean);
  const findings = [];
  const failedLoginsByIp = {};

  lines.forEach((line, idx) => {
    const ip = extractIp(line);

    if (FAILED_LOGIN_PATTERNS.some((p) => p.test(line))) {
      failedLoginsByIp[ip] = (failedLoginsByIp[ip] || 0) + 1;
    }

    if (SQLI_PATTERNS.some((p) => p.test(line))) {
      findings.push({ line: idx + 1, type: 'SQL Injection Attempt', severity: 'HIGH', ip, snippet: line.slice(0, 160) });
    }
    if (XSS_PATTERNS.some((p) => p.test(line))) {
      findings.push({ line: idx + 1, type: 'Cross-Site Scripting (XSS)', severity: 'HIGH', ip, snippet: line.slice(0, 160) });
    }
    if (CMD_INJECTION_PATTERNS.some((p) => p.test(line))) {
      findings.push({ line: idx + 1, type: 'Command Injection Attempt', severity: 'CRITICAL', ip, snippet: line.slice(0, 160) });
    }
  });

  // Brute-force detection: threshold on failed logins per source IP.
  const BRUTE_FORCE_THRESHOLD = 5;
  Object.entries(failedLoginsByIp).forEach(([ip, count]) => {
    if (count >= BRUTE_FORCE_THRESHOLD) {
      findings.push({
        line: null,
        type: 'Brute Force Login Attempt',
        severity: count >= 15 ? 'CRITICAL' : 'HIGH',
        ip,
        snippet: `${count} failed login attempts detected from this source`,
      });
    }
  });

  const severityWeights = { LOW: 1, MEDIUM: 3, HIGH: 6, CRITICAL: 10 };
  const rawScore = findings.reduce((sum, f) => sum + (severityWeights[f.severity] || 0), 0);
  const riskScore = Math.min(100, rawScore);

  const summary = {
    totalLines: lines.length,
    totalFindings: findings.length,
    uniqueSourceIps: new Set(findings.map((f) => f.ip)).size,
    riskScore,
    riskLevel: riskScore >= 70 ? 'CRITICAL' : riskScore >= 40 ? 'HIGH' : riskScore >= 15 ? 'MEDIUM' : 'LOW',
  };

  return { summary, findings: findings.slice(0, 200) };
}

module.exports = { analyzeLog };
