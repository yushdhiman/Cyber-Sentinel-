// Simulated vulnerability scanner.
//
// IMPORTANT: this does NOT perform real port scanning or network probing.
// Scanning hosts you don't own is illegal in most jurisdictions, and doing
// it from a shared backend would be irresponsible. Instead this module
// takes user-declared inputs (e.g. "I'm running nginx 1.18, no HTTPS
// redirect, password policy allows 6 chars") and evaluates them against a
// checklist derived from OWASP guidance, returning a realistic-looking
// report. This is the honest, safe way to demo "vulnerability scanning"
// in a portfolio project without touching real infrastructure.

function scanConfig(config) {
  const findings = [];

  const {
    usesHttps = true,
    hasHsts = false,
    passwordMinLength = 8,
    mfaEnabled = false,
    softwareVersion = '',
    openPorts = [],
    hasWaf = false,
    exposesAdminPanel = false,
    usesDefaultCredentials = false,
  } = config;

  if (!usesHttps) {
    findings.push({ id: 'no-https', severity: 'CRITICAL', title: 'No HTTPS enforced', detail: 'Traffic can be intercepted or modified in transit. Enable TLS and redirect all HTTP to HTTPS.' });
  }
  if (usesHttps && !hasHsts) {
    findings.push({ id: 'no-hsts', severity: 'MEDIUM', title: 'Missing HSTS header', detail: 'Add Strict-Transport-Security to prevent SSL-stripping downgrade attacks.' });
  }
  if (passwordMinLength < 8) {
    findings.push({ id: 'weak-password-policy', severity: 'HIGH', title: 'Weak password policy', detail: `Minimum length is ${passwordMinLength}. NIST recommends 8+ characters minimum, ideally with a passphrase-friendly policy.` });
  }
  if (!mfaEnabled) {
    findings.push({ id: 'no-mfa', severity: 'HIGH', title: 'Multi-factor authentication disabled', detail: 'Credential-only auth is vulnerable to phishing and credential stuffing. Enable MFA (TOTP or WebAuthn).' });
  }
  if (usesDefaultCredentials) {
    findings.push({ id: 'default-creds', severity: 'CRITICAL', title: 'Default credentials in use', detail: 'Default admin/admin-style credentials are the #1 cause of opportunistic compromise. Rotate immediately.' });
  }
  if (exposesAdminPanel) {
    findings.push({ id: 'exposed-admin', severity: 'HIGH', title: 'Admin panel publicly exposed', detail: 'Restrict admin interfaces to VPN/allow-listed IPs, or place behind a bastion.' });
  }
  if (!hasWaf) {
    findings.push({ id: 'no-waf', severity: 'MEDIUM', title: 'No Web Application Firewall detected', detail: 'A WAF provides a first line of defense against common OWASP Top 10 attacks (SQLi, XSS, etc).' });
  }

  const riskyPorts = { 21: 'FTP (unencrypted)', 23: 'Telnet (unencrypted)', 3389: 'RDP', 3306: 'MySQL exposed publicly', 6379: 'Redis exposed publicly' };
  const portsArray = Array.isArray(openPorts) ? openPorts : [];
  portsArray.forEach((port) => {
    if (riskyPorts[port]) {
      findings.push({ id: `open-port-${port}`, severity: 'HIGH', title: `Risky open port: ${port}`, detail: `${riskyPorts[port]} should not be exposed to the public internet. Restrict via firewall/security group.` });
    }
  });

  if (softwareVersion && /\b(1\.|2\.[0-3])\b/.test(softwareVersion)) {
    findings.push({ id: 'outdated-software', severity: 'MEDIUM', title: 'Potentially outdated software version', detail: `Reported version "${softwareVersion}" looks old — verify against vendor security advisories and patch if needed.` });
  }

  const weights = { LOW: 1, MEDIUM: 3, HIGH: 6, CRITICAL: 10 };
  const rawScore = findings.reduce((s, f) => s + weights[f.severity], 0);
  const maxPossible = 45; // rough ceiling given the checklist above
  const riskScore = Math.min(100, Math.round((rawScore / maxPossible) * 100));

  return {
    findings,
    summary: {
      totalFindings: findings.length,
      riskScore,
      riskLevel: riskScore >= 70 ? 'CRITICAL' : riskScore >= 40 ? 'HIGH' : riskScore >= 15 ? 'MEDIUM' : 'LOW',
      scannedAt: new Date().toISOString(),
    },
  };
}

module.exports = { scanConfig };
