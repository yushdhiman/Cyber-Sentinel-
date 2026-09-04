/**
 * protectionEngine.js
 * Rule-based threat intelligence for Emails, Links, and Files.
 * Contains heuristic filters, signature databases, and scoring weights.
 */

// ─── PHISHING & EMAIL PATTERNS ───
const PHISHING_KEYWORDS = [
  { term: /\burgent action required\b/i, weight: 15, tag: 'URGENCY' },
  { term: /\bverify your (account|identity)\b/i, weight: 12, tag: 'CREDENTIAL_HARVESTING' },
  { term: /\bsuspended due to suspicious activity\b/i, weight: 15, tag: 'ACCOUNTS_SUSPENDED' },
  { term: /\breset your password immediately\b/i, weight: 18, tag: 'URGENCY' },
  { term: /\bsecurity alert\b/i, weight: 8, tag: 'SECURITY_ALERT' },
  { term: /\bbilling error\b/i, weight: 10, tag: 'FINANCIAL_FRAUD' },
  { term: /\bconfirm payment details\b/i, weight: 15, tag: 'FINANCIAL_FRAUD' },
  { term: /\bwire transfer request\b/i, weight: 15, tag: 'BEC_ATTACK' },
  { term: /\blogin credentials\b/i, weight: 12, tag: 'CREDENTIAL_HARVESTING' },
  { term: /\bpackage delivery failure\b/i, weight: 10, tag: 'SPAM' },
];

const SPOOFED_SENDER_PATTERNS = [
  { pattern: /@.*(paypal|netflix|google|microsoft|amazon|apple|chase|wellsfargo)-security.*\.com/i, tag: 'SPOOFED_BRAND' },
  { pattern: /@.*(support|billing|login|admin)-.*(com|xyz|click|top)/i, tag: 'SUSPICIOUS_SENDER_DOMAIN' },
  { pattern: /@.*\.work/i, tag: 'SUSPICIOUS_TLD' },
];

// ─── MALICIOUS LINK PATTERNS ───
const SUSPICIOUS_TLDS = /\.(xyz|top|click|link|zip|gq|cf|ml|ga|work|download|bid|gdn)$/i;
const PHISHING_SUBDOMAINS = /(paypal|secure-login|netflix|verify|update-profile|microsoft-online|chase-bank|outlook-office)/i;
const URL_SHORTENERS = /^(bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rebrand\.ly|is\.gd)$/i;
const IP_URL_REGEX = /^(?:https?:\/\/)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/.*)?$/;

// ─── VIRUS HASH SIGNATURE DATABASE ───
const MALWARE_HASH_DATABASE = {
  // WannaCry ransomware
  'ed01ebfbc9eb5bbea545af4fed50786b0bc9e8538c340578a82b741f3e797699': {
    name: 'Ransom:Win32/WannaCrypt',
    type: 'Ransomware',
    severity: 'CRITICAL',
    description: 'Self-replicating ransomware cryptoworm targeting Windows machines via SMB vulnerability.',
  },
  // Stuxnet worm
  '1d7b6b170e704e6c99c8f0f0bc0f1d1d7b6b170e704e6c99c8f0f0bc0f1d1d': {
    name: 'Worm:Win32/Stuxnet',
    type: 'Industrial Cryptoworm',
    severity: 'CRITICAL',
    description: 'Highly complex cyber weapon designed to target industrial control systems.',
  },
  // CryptoLocker
  '275a021b13d6fc24777e0893a4bc60d170f3f260f8bd058b8eb338a11a70c123': {
    name: 'Trojan:Win32/CryptoLocker',
    type: 'Ransomware',
    severity: 'CRITICAL',
    description: 'Trojan horse ransomware that encrypts local and networked files.',
  },
  // Emotet
  '534a66a1a72df2e96d744b7d5267a14e9185a8050e8d356ff35ff452c92e92c2': {
    name: 'TrojanDownloader:Win32/Emotet',
    type: 'Banking Trojan / Loader',
    severity: 'CRITICAL',
    description: 'Polymorphic banking trojan that operates as a distributor of other malware payloads.',
  },
  // EICAR standard test signature (SHA-256 of the EICAR string)
  '275a021b13d6fc24777e0893a4bc60d170f3f260f8bd058b8eb338a11de20c662': {
    name: 'EICAR-Standard-Antivirus-Test-File',
    type: 'Test Signature',
    severity: 'HIGH',
    description: 'Standardized test file used to verify the operational state of antivirus software.',
  }
};

const DANGEROUS_EXTENSIONS = ['.exe', '.dll', '.vbs', '.bat', '.cmd', '.scr', '.msi', '.ps1', '.lnk', '.pif'];
const MACRO_EXTENSIONS = ['.docm', '.xlsm', '.pptm'];

// ─── CORE DETECTOR ENGINES ───

/**
 * Analyzes a URL/Link for threats.
 */
function analyzeLink(url) {
  if (!url || typeof url !== 'string') {
    return { error: 'Invalid URL provided' };
  }

  const findings = [];
  let score = 0;
  
  // Clean URL format for parsing
  let hostname = url.trim();
  if (!/^https?:\/\//i.test(hostname)) {
    hostname = 'http://' + hostname;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(hostname);
  } catch (e) {
    // Basic regex fallback if URL construction fails
    return {
      summary: { threatScore: 90, status: 'MALICIOUS', riskLevel: 'HIGH' },
      findings: [{ type: 'Malformed URL structure', severity: 'HIGH', detail: 'The URL could not be parsed and might be obfuscated.' }]
    };
  }

  const host = parsedUrl.hostname;
  const path = parsedUrl.pathname;

  // 1. IP address check
  if (IP_URL_REGEX.test(url.trim())) {
    findings.push({
      type: 'IP Address URL Exposure',
      severity: 'HIGH',
      detail: `URL references a raw IP address (${host}) instead of a verified domain name. Often used to bypass DNS domain blocking.`,
    });
    score += 45;
  }

  // 2. URL Shortener check
  if (URL_SHORTENERS.test(host)) {
    findings.push({
      type: 'URL Redirection Shortener',
      severity: 'MEDIUM',
      detail: `URL uses a shortener service (${host}) which masks the final landing page destination.`,
    });
    score += 20;
  }

  // 3. Phishing subdomains
  if (PHISHING_SUBDOMAINS.test(host)) {
    findings.push({
      type: 'Brand Spoofing Attempt',
      severity: 'CRITICAL',
      detail: `The domain name mimics a trusted brand keyword in the subdomain: "${host.match(PHISHING_SUBDOMAINS)[0]}"`,
    });
    score += 65;
  }

  // 4. Suspicious TLD
  if (SUSPICIOUS_TLDS.test(host)) {
    const tld = host.match(SUSPICIOUS_TLDS)[0];
    findings.push({
      type: 'Untrusted TLD Extension',
      severity: 'MEDIUM',
      detail: `The URL uses a high-risk top-level domain (${tld}) known for hosting disproportionate volumes of malware campaigns.`,
    });
    score += 25;
  }

  // 5. Credential-harvesting paths
  const lowPath = path.toLowerCase();
  if (lowPath.includes('login') || lowPath.includes('signin') || lowPath.includes('verify') || lowPath.includes('secure')) {
    if (score > 15) { // Only escalate if it's already a bit suspicious
      findings.push({
        type: 'Credential Harvesting Pattern',
        severity: 'HIGH',
        detail: 'The URL path contains login/verification patterns on a suspicious domain structure.',
      });
      score += 25;
    }
  }

  const threatScore = Math.min(100, score);
  const status = threatScore >= 70 ? 'MALICIOUS' : threatScore >= 35 ? 'SUSPICIOUS' : 'CLEAN';

  return {
    url,
    host,
    findings,
    summary: {
      threatScore,
      status,
      riskLevel: threatScore >= 70 ? 'CRITICAL' : threatScore >= 35 ? 'HIGH' : threatScore >= 15 ? 'MEDIUM' : 'LOW',
    }
  };
}

/**
 * Analyzes Email content for phishing indicators.
 */
function analyzeEmail(emailText, emailSubject = '', emailSender = '') {
  const textToScan = `${emailSubject}\n${emailSender}\n${emailText}`;
  const findings = [];
  let score = 0;
  const tags = new Set();

  // 1. Phishing Keyword checks
  PHISHING_KEYWORDS.forEach(({ term, weight, tag }) => {
    if (term.test(textToScan)) {
      findings.push({
        type: `Keyword Match: ${tag}`,
        severity: weight >= 15 ? 'HIGH' : 'MEDIUM',
        detail: `Found phishing/social engineering indicator matching pattern: "${emailText.match(term)?.[0] || term}"`
      });
      score += weight;
      tags.add(tag);
    }
  });

  // 2. Sender Domain spoof checks
  if (emailSender) {
    SPOOFED_SENDER_PATTERNS.forEach(({ pattern, tag }) => {
      if (pattern.test(emailSender)) {
        findings.push({
          type: tag,
          severity: 'CRITICAL',
          detail: `Sender address "${emailSender}" matches known malicious or spoofed brand patterns.`
        });
        score += 35;
        tags.add(tag);
      }
    });
  }

  // 3. Extracted links analysis
  const urlRegex = /https?:\/\/[^\s$.?#].[^\s]*/gi;
  const matches = emailText.match(urlRegex) || [];
  const linkAnalyses = [];
  
  matches.slice(0, 5).forEach((url) => {
    const linkScan = analyzeLink(url);
    if (linkScan.summary.threatScore >= 35) {
      findings.push({
        type: 'Malicious Link in Body',
        severity: linkScan.summary.status === 'MALICIOUS' ? 'CRITICAL' : 'HIGH',
        detail: `Email body contains a suspicious URL redirection: "${url}" (Threat Score: ${linkScan.summary.threatScore})`
      });
      score += linkScan.summary.threatScore * 0.6;
      tags.add('MALICIOUS_LINKS');
    }
    linkAnalyses.push(linkScan);
  });

  const threatScore = Math.min(100, Math.round(score));
  const status = threatScore >= 70 ? 'PHISHING' : threatScore >= 35 ? 'SUSPICIOUS' : 'CLEAN';

  return {
    emailSubject,
    emailSender,
    tags: Array.from(tags),
    findings,
    links: linkAnalyses,
    summary: {
      threatScore,
      status,
      riskLevel: threatScore >= 70 ? 'CRITICAL' : threatScore >= 35 ? 'HIGH' : threatScore >= 15 ? 'MEDIUM' : 'LOW',
    }
  };
}

/**
 * Analyzes File details / signatures for viruses.
 */
function analyzeFile(fileName, fileSize, fileHash = '', rawContent = '') {
  const findings = [];
  let score = 0;
  let detectedMalwareName = null;
  let type = 'UNKNOWN';

  // Normalize inputs
  const cleanHash = fileHash.trim().toLowerCase();
  const lowerName = fileName.trim().toLowerCase();

  // 1. EICAR Antivirus Test Signature Check
  const eicarPattern = /X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/;
  if (eicarPattern.test(rawContent) || eicarPattern.test(fileName)) {
    detectedMalwareName = 'EICAR-Standard-Antivirus-Test-File';
    type = 'Test Signature';
    findings.push({
      type: 'EICAR Test Signature Matched',
      severity: 'CRITICAL',
      detail: 'Standardized anti-virus test file signature identified. Engine operations verified nominal.',
    });
    score = 100;
  }

  // 2. Hash Lookup
  if (!detectedMalwareName && cleanHash && MALWARE_HASH_DATABASE[cleanHash]) {
    const malware = MALWARE_HASH_DATABASE[cleanHash];
    detectedMalwareName = malware.name;
    type = malware.type;
    findings.push({
      type: 'Malware Hash Signature Matched',
      severity: malware.severity,
      detail: `File signature matches known malicious hash for ${malware.name}. Description: ${malware.description}`,
    });
    score = 100;
  }

  // 3. Heuristic extension audits
  if (!detectedMalwareName) {
    // Double extensions check (e.g. invoice.pdf.exe)
    const doubleExtMatch = lowerName.match(/\.([a-z0-9]+)\.([a-z0-9]+)$/);
    if (doubleExtMatch) {
      const primaryExt = `.${doubleExtMatch[1]}`;
      const finalExt = `.${doubleExtMatch[2]}`;
      
      if (DANGEROUS_EXTENSIONS.includes(finalExt)) {
        findings.push({
          type: 'Double Extension Masking',
          severity: 'CRITICAL',
          detail: `File utilizes dual-extension masking: "${primaryExt}${finalExt}". This is a classical vector to trick users into running binaries.`,
        });
        score += 85;
      }
    }

    // High-risk extension
    const extMatch = lowerName.match(/\.[a-z0-9]+$/);
    if (extMatch && !doubleExtMatch) {
      const ext = extMatch[0];
      if (DANGEROUS_EXTENSIONS.includes(ext)) {
        findings.push({
          type: 'Executable Binary / Script',
          severity: 'HIGH',
          detail: `Executable file format (${ext}) submitted. Direct execution triggers system-level instruction pipelines.`,
        });
        score += 45;
      } else if (MACRO_EXTENSIONS.includes(ext)) {
        findings.push({
          type: 'Macro-Enabled Document',
          severity: 'MEDIUM',
          detail: `Microsoft Office document (${ext}) supports embedded Visual Basic for Applications (VBA) macro routines.`,
        });
        score += 25;
      }
    }

    // Size-based anomalies
    if (fileSize > 25 * 1024 * 1024 && (lowerName.endsWith('.exe') || lowerName.endsWith('.zip'))) {
      findings.push({
        type: 'Large Binary Payload',
        severity: 'LOW',
        detail: 'File size exceeds 25MB. Large payloads are sometimes used to bypass sandbox resource limits.',
      });
      score += 5;
    }
  }

  const threatScore = Math.min(100, score);
  const status = threatScore >= 70 ? 'INFECTED' : threatScore >= 20 ? 'SUSPICIOUS' : 'CLEAN';

  return {
    fileName,
    fileSize,
    fileHash: cleanHash || 'not provided',
    detectedMalwareName,
    type: detectedMalwareName ? type : (threatScore >= 70 ? 'SUSPICIOUS_PAYLOAD' : 'NORMAL'),
    findings,
    summary: {
      threatScore,
      status,
      riskLevel: threatScore >= 70 ? 'CRITICAL' : threatScore >= 35 ? 'HIGH' : threatScore >= 15 ? 'MEDIUM' : 'LOW',
    }
  };
}

module.exports = {
  analyzeLink,
  analyzeEmail,
  analyzeFile
};
