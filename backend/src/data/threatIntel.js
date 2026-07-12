// Static sample threat-intel dataset styled after real CVE/MITRE fields.
// In a production version, this module would be replaced by scheduled
// fetch jobs against the NVD CVE API, MITRE ATT&CK STIX feed, and
// AbuseIPDB — each behind its own API key and cache layer.

const cves = [
  {
    id: 'CVE-2024-3094',
    severity: 'CRITICAL',
    cvss: 10.0,
    summary: 'Backdoor introduced into xz/liblzma via malicious upstream commits, enabling SSH authentication bypass.',
    affected: 'xz-utils 5.6.0 - 5.6.1',
    mitreTactic: 'Initial Access (T1195 - Supply Chain Compromise)',
  },
  {
    id: 'CVE-2023-44487',
    severity: 'HIGH',
    cvss: 7.5,
    summary: 'HTTP/2 Rapid Reset allows attackers to exhaust server resources via rapid stream cancellation.',
    affected: 'HTTP/2-enabled web servers',
    mitreTactic: 'Impact (T1499 - Endpoint Denial of Service)',
  },
  {
    id: 'CVE-2021-44228',
    severity: 'CRITICAL',
    cvss: 10.0,
    summary: 'Log4Shell: JNDI lookup in Log4j allows remote code execution via crafted log messages.',
    affected: 'Apache Log4j 2.0-beta9 to 2.15.0',
    mitreTactic: 'Execution (T1059 - Command and Scripting Interpreter)',
  },
  {
    id: 'CVE-2022-22965',
    severity: 'CRITICAL',
    cvss: 9.8,
    summary: 'Spring4Shell: remote code execution via data binding in Spring MVC/WebFlux on JDK 9+.',
    affected: 'Spring Framework 5.3.0 - 5.3.17',
    mitreTactic: 'Execution (T1190 - Exploit Public-Facing Application)',
  },
  {
    id: 'CVE-2020-1472',
    severity: 'CRITICAL',
    cvss: 10.0,
    summary: 'Zerologon: elevation of privilege via Netlogon Remote Protocol cryptographic flaw.',
    affected: 'Windows Server (all supported versions, pre-patch)',
    mitreTactic: 'Privilege Escalation (T1068)',
  },
];

// Rolling simulated "live" attack feed. Each request perturbs this a bit
// so the dashboard feels alive without needing a real packet capture pipeline.
const attackTypes = [
  'Brute Force (SSH)',
  'Port Scan',
  'SQL Injection Attempt',
  'Cross-Site Scripting',
  'DDoS - SYN Flood',
  'Credential Stuffing',
  'Malware C2 Beacon',
  'Phishing Link Click',
];

const countries = ['RU', 'CN', 'US', 'BR', 'IN', 'NG', 'DE', 'VN', 'KR', 'IR'];

function randomIp() {
  return Array.from({ length: 4 }, () => Math.floor(Math.random() * 255) + 1).join('.');
}

function generateLiveAttacks(count = 12) {
  return Array.from({ length: count }, (_, i) => {
    const severity = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][Math.floor(Math.random() * 4)];
    return {
      id: `${Date.now()}-${i}`,
      timestamp: new Date(Date.now() - i * 1000 * 45).toISOString(),
      sourceIp: randomIp(),
      country: countries[Math.floor(Math.random() * countries.length)],
      type: attackTypes[Math.floor(Math.random() * attackTypes.length)],
      severity,
      blocked: Math.random() > 0.3,
    };
  });
}

module.exports = { cves, generateLiveAttacks };
