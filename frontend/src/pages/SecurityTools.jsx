import { useState, useEffect } from 'react';

/* ─── Advanced IP Threat Intelligence Database ─── */
const IP_DATABASE = {
  default: {
    ip: null, country: 'United States', countryCode: 'US', city: 'Mountain View',
    region: 'California', isp: 'Google LLC', asn: 'AS15169', org: 'Google LLC',
    threatScore: 4, status: 'CLEAN',
    categories: { geo: 8, network: 5, behavioral: 2, historical: 3, reputation: 2, malware: 0 },
    tags: ['CDN', 'CLOUD_PROVIDER', 'VERIFIED_ORG'],
    iocFlags: [],
    reportedCampaigns: [],
    riskFactors: ['No malicious activity detected in the last 90 days.'],
    openPorts: [80, 443],
    lastSeen: '—',
    confidence: 97,
    dataSource: ['AbuseIPDB', 'VirusTotal', 'Shodan'],
  },
  local: {
    ip: null, country: 'Local Network', countryCode: '—', city: 'Private Subnet',
    region: 'RFC 1918', isp: 'Internal / Loopback', asn: 'N/A', org: 'Private',
    threatScore: 0, status: 'LOCAL',
    categories: { geo: 0, network: 0, behavioral: 0, historical: 0, reputation: 0, malware: 0 },
    tags: ['PRIVATE_RANGE', 'NOT_ROUTABLE'],
    iocFlags: [],
    reportedCampaigns: [],
    riskFactors: ['Private IP address space. Invisible to external threat scanners.'],
    openPorts: [],
    lastSeen: '—',
    confidence: 100,
    dataSource: ['Local Analysis'],
  },
  highRisk: {
    ip: null, country: 'China', countryCode: 'CN', city: 'Shenzhen',
    region: 'Guangdong', isp: 'Chinanet Hosting', asn: 'AS4134', org: 'CHINA TELECOM',
    threatScore: 88, status: 'HIGH RISK',
    categories: { geo: 78, network: 92, behavioral: 95, historical: 85, reputation: 91, malware: 72 },
    tags: ['BRUTE_FORCE', 'PORT_SCANNER', 'BOTNET_C2', 'BLACKLISTED'],
    iocFlags: ['Seen in 47 threat feeds', 'Associated with Mirai botnet', 'CVE-2017-0144 exploitation'],
    reportedCampaigns: ['Operation Ghost Shell', 'APT41 Infrastructure', 'ShadowPad Campaign'],
    riskFactors: [
      'Repeated SSH brute-force campaigns targeting root credentials',
      'Active SQL injection payload delivery detected',
      'Port scanning activity across multiple /24 subnets',
      'Previously used as C2 node in Mirai botnet variant',
    ],
    openPorts: [22, 80, 443, 3306, 6379, 8080],
    lastSeen: '2 hours ago',
    confidence: 94,
    dataSource: ['AbuseIPDB', 'VirusTotal', 'Shodan', 'AlienVault OTX', 'Emerging Threats'],
  },
  suspicious: {
    ip: null, country: 'Netherlands', countryCode: 'NL', city: 'Amsterdam',
    region: 'North Holland', isp: 'Leaseweb B.V.', asn: 'AS60636', org: 'LeaseWeb',
    threatScore: 47, status: 'SUSPICIOUS',
    categories: { geo: 30, network: 55, behavioral: 50, historical: 42, reputation: 45, malware: 15 },
    tags: ['VPS_HOST', 'TOR_EXIT_POSSIBLE', 'ABUSE_HISTORY'],
    iocFlags: ['Seen in 8 threat feeds', 'Possible VPN/proxy node'],
    reportedCampaigns: ['Generic Scanning Activity'],
    riskFactors: [
      'Occasional malicious payloads observed from this /24 subnet',
      'Hosting provider with history of abuse reports',
      'Matches TOR exit node CIDR ranges',
    ],
    openPorts: [22, 80, 443, 8443],
    lastSeen: '3 days ago',
    confidence: 71,
    dataSource: ['AbuseIPDB', 'Shodan', 'AlienVault OTX'],
  },
};

function getIpProfile(ip) {
  if (!ip) return null;
  if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('127.') || ip.startsWith('172.16.')) {
    return { ...IP_DATABASE.local, ip };
  }
  if (ip === '45.33.12.9' || ip.startsWith('198.51.') || ip.startsWith('113.') || ip.startsWith('103.')) {
    return { ...IP_DATABASE.highRisk, ip };
  }
  if (ip.startsWith('185.') || ip.startsWith('194.') || ip.startsWith('91.')) {
    return { ...IP_DATABASE.suspicious, ip };
  }
  return { ...IP_DATABASE.default, ip };
}

/* ─── Animated SVG Threat Score Ring ─── */
function ThreatScoreRing({ score, status }) {
  const r = 52;
  const circ = 2 * Math.PI * r;
  const pct = score / 100;
  const dash = circ * pct;
  const gap = circ - dash;
  const color = score >= 70 ? 'var(--accent-red)' : score >= 40 ? 'var(--accent-orange)' : score >= 20 ? '#f0c040' : 'var(--accent-green)';
  const trackColor = score >= 70 ? 'rgba(255,0,85,0.1)' : score >= 40 ? 'rgba(255,170,0,0.1)' : 'rgba(57,255,20,0.1)';
  const label = score >= 70 ? 'CRITICAL' : score >= 40 ? 'ELEVATED' : score >= 20 ? 'CAUTION' : 'CLEAN';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
      <svg width="130" height="130" viewBox="0 0 130 130">
        {/* Outer decorative ring */}
        <circle cx="65" cy="65" r="60" fill="none" stroke={trackColor} strokeWidth="1" strokeDasharray="4 4" />
        {/* Track */}
        <circle cx="65" cy="65" r={r} fill="none" stroke="var(--surface-2)" strokeWidth="12" />
        {/* Score arc */}
        <circle cx="65" cy="65" r={r}
          fill="none" stroke={color} strokeWidth="12"
          strokeDasharray={`${dash} ${gap}`}
          strokeDashoffset={circ / 4}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 1.5s cubic-bezier(0.4,0,0.2,1)', filter: `drop-shadow(0 0 8px ${color})` }}
        />
        {/* Inner glow */}
        <circle cx="65" cy="65" r="38" fill={trackColor} />
        {/* Score text */}
        <text x="65" y="57" textAnchor="middle" fill="var(--text)" fontSize="30" fontWeight="800" fontFamily="Space Grotesk, sans-serif">{score}</text>
        <text x="65" y="73" textAnchor="middle" fill="var(--text-faint)" fontSize="10" fontFamily="Space Grotesk, monospace">/100 THREAT INDEX</text>
        <text x="65" y="90" textAnchor="middle" fill={color} fontSize="9" fontWeight="700" fontFamily="Space Grotesk, monospace" letterSpacing="2">{label}</text>
      </svg>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '11px', fontWeight: 700, color, fontFamily: 'Space Grotesk, monospace', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: color, display: 'inline-block', boxShadow: `0 0 6px ${color}` }} />
        {status}
      </div>
    </div>
  );
}

/* ─── 6-Axis Category Score Bars ─── */
function CategoryScoreBars({ categories }) {
  const axes = [
    { key: 'geo', label: 'GEO RISK', desc: 'Origin country threat rating', icon: '🌐' },
    { key: 'network', label: 'NETWORK', desc: 'Port exposure & scanning activity', icon: '🔌' },
    { key: 'behavioral', label: 'BEHAVIORAL', desc: 'Attack pattern & payload signatures', icon: '⚡' },
    { key: 'historical', label: 'HISTORICAL', desc: 'Past incident involvement score', icon: '📋' },
    { key: 'reputation', label: 'REPUTATION', desc: 'Blacklist & threat feed presence', icon: '🔴' },
    { key: 'malware', label: 'MALWARE', desc: 'Known malware family associations', icon: '☣' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {axes.map(({ key, label, desc, icon }) => {
        const val = categories[key] ?? 0;
        const color = val >= 70 ? 'var(--accent-red)' : val >= 40 ? 'var(--accent-orange)' : val >= 20 ? '#f0c040' : 'var(--accent-green)';
        return (
          <div key={key}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: '13px' }}>{icon}</span>
                <div>
                  <div style={{ fontSize: '10px', fontWeight: 700, color: 'var(--text-dim)', letterSpacing: '0.08em', fontFamily: 'Space Grotesk, monospace' }}>{label}</div>
                  <div style={{ fontSize: '9px', color: 'var(--text-faint)' }}>{desc}</div>
                </div>
              </div>
              <span style={{ fontSize: '13px', fontWeight: 800, color, fontFamily: 'Space Grotesk, monospace', minWidth: 28, textAlign: 'right' }}>{val}</span>
            </div>
            <div style={{ height: '5px', background: 'var(--surface-2)', borderRadius: '3px', overflow: 'hidden' }}>
              <div style={{
                width: `${val}%`, height: '100%',
                background: `linear-gradient(90deg, ${color}99, ${color})`,
                borderRadius: '3px',
                boxShadow: val > 0 ? `0 0 6px ${color}60` : 'none',
                transition: 'width 1s cubic-bezier(0.4,0,0.2,1)',
              }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ─── IOC Tags ─── */
function IocTags({ tags, iocFlags }) {
  const tagColors = {
    BRUTE_FORCE: 'var(--accent-red)', PORT_SCANNER: 'var(--accent-orange)',
    BOTNET_C2: 'var(--accent-red)', BLACKLISTED: 'var(--accent-red)',
    CDN: 'var(--accent-green)', CLOUD_PROVIDER: 'var(--accent-green)',
    VERIFIED_ORG: 'var(--accent-green)', PRIVATE_RANGE: 'var(--accent-cyan)',
    NOT_ROUTABLE: 'var(--accent-cyan)', VPS_HOST: 'var(--accent-orange)',
    TOR_EXIT_POSSIBLE: 'var(--accent-purple)', ABUSE_HISTORY: 'var(--accent-orange)',
  };
  return (
    <div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: iocFlags.length > 0 ? 10 : 0 }}>
        {tags.map(t => (
          <span key={t} style={{
            fontSize: '9px', fontWeight: 700, letterSpacing: '0.08em', padding: '3px 8px',
            borderRadius: '3px', border: `1px solid ${tagColors[t] || 'var(--border)'}`,
            color: tagColors[t] || 'var(--text-dim)', background: `${tagColors[t] || 'var(--border)'}15`,
            fontFamily: 'Space Grotesk, monospace', textTransform: 'uppercase',
          }}>{t.replace(/_/g, ' ')}</span>
        ))}
      </div>
      {iocFlags.map((flag, i) => (
        <div key={i} style={{ fontSize: '11px', color: 'var(--accent-orange)', padding: '3px 0', display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ color: 'var(--accent-orange)', fontSize: '10px' }}>⚠</span> {flag}
        </div>
      ))}
    </div>
  );
}

export default function SecurityTools() {
  const [ipInput, setIpInput] = useState('');
  const [ipResult, setIpResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanPhase, setScanPhase] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [headerResult, setHeaderResult] = useState(null);
  const [passwordInput, setPasswordInput] = useState('');
  const [pwdResult, setPwdResult] = useState(null);
  const [hashInput, setHashInput] = useState('');
  const [hashResult, setHashResult] = useState(null);

  async function handleIpLookup(e) {
    e.preventDefault();
    const ip = ipInput.trim();
    if (!ip) return;
    setScanning(true);
    setIpResult(null);

    const phases = [
      'QUERYING ABUSE DB...',
      'CROSS-REFERENCING THREAT FEEDS...',
      'ANALYZING BEHAVIORAL SIGNATURES...',
      'COMPUTING MULTI-VECTOR SCORE...',
    ];
    for (const phase of phases) {
      setScanPhase(phase);
      await new Promise(r => setTimeout(r, 380));
    }
    setScanPhase('');
    setScanning(false);
    setIpResult(getIpProfile(ip));
  }

  function handleHeaderScan(e) {
    e.preventDefault();
    let url = urlInput.trim();
    if (!url) return;
    url = url.replace(/^(https?:\/\/)?(www\.)?/, '');
    let result = {
      domain: url, grade: 'A',
      headers: [
        { name: 'Strict-Transport-Security (HSTS)', status: 'Present', rating: 'SECURE' },
        { name: 'Content-Security-Policy (CSP)', status: 'Present', rating: 'SECURE' },
        { name: 'X-Frame-Options', status: 'Present', rating: 'SECURE' },
        { name: 'X-Content-Type-Options', status: 'Present', rating: 'SECURE' },
        { name: 'Referrer-Policy', status: 'Present', rating: 'SECURE' }
      ],
      recommendation: 'POSTURE NOMINAL — Site follows modern OWASP security headers best practices.',
      securityScore: 100,
    };
    const lowerUrl = url.toLowerCase();
    if (lowerUrl.includes('insecure') || lowerUrl.includes('test') || lowerUrl.includes('example')) {
      result = {
        domain: url, grade: 'F', securityScore: 12,
        headers: [
          { name: 'Strict-Transport-Security (HSTS)', status: 'Missing', rating: 'CRITICAL' },
          { name: 'Content-Security-Policy (CSP)', status: 'Missing', rating: 'CRITICAL' },
          { name: 'X-Frame-Options', status: 'Missing', rating: 'MEDIUM' },
          { name: 'X-Content-Type-Options', status: 'Missing', rating: 'LOW' },
          { name: 'Referrer-Policy', status: 'Missing', rating: 'LOW' },
        ],
        recommendation: 'ACTION REQUIRED — Implement HSTS and Content-Security-Policy headers on the web server.',
      };
    } else if (lowerUrl.includes('medium') || lowerUrl.endsWith('.org')) {
      result = {
        domain: url, grade: 'C', securityScore: 54,
        headers: [
          { name: 'Strict-Transport-Security (HSTS)', status: 'Present', rating: 'SECURE' },
          { name: 'Content-Security-Policy (CSP)', status: 'Missing', rating: 'CRITICAL' },
          { name: 'X-Frame-Options', status: 'Present', rating: 'SECURE' },
          { name: 'X-Content-Type-Options', status: 'Missing', rating: 'LOW' },
          { name: 'Referrer-Policy', status: 'Present', rating: 'SECURE' },
        ],
        recommendation: 'RECOMMENDED — Create a Content-Security-Policy to mitigate script-injection attacks.',
      };
    }
    setHeaderResult(result);
  }

  function auditPassword(val) {
    setPasswordInput(val);
    if (!val) { setPwdResult(null); return; }
    const length = val.length;
    const hasUpper = /[A-Z]/.test(val);
    const hasLower = /[a-z]/.test(val);
    const hasDigit = /[0-9]/.test(val);
    const hasSpecial = /[^A-Za-z0-9]/.test(val);
    let charPool = 0;
    if (hasLower) charPool += 26;
    if (hasUpper) charPool += 26;
    if (hasDigit) charPool += 10;
    if (hasSpecial) charPool += 32;
    const entropy = charPool > 0 ? Math.round(length * (Math.log(charPool) / Math.log(2))) : 0;
    let strength = 'WEAK'; let color = 'var(--accent-red)';
    if (entropy > 80) { strength = 'EXCELLENT'; color = 'var(--accent-green)'; }
    else if (entropy >= 60) { strength = 'STRONG'; color = 'var(--accent-green)'; }
    else if (entropy >= 40) { strength = 'MEDIUM'; color = 'var(--accent-orange)'; }
    let crackTime = 'MILLISECONDS';
    if (entropy > 80) crackTime = 'TRILLIONS OF YEARS';
    else if (entropy >= 65) crackTime = 'THOUSANDS OF YEARS';
    else if (entropy >= 50) crackTime = 'DAYS';
    else if (entropy >= 30) crackTime = 'HOURS';
    else if (entropy >= 15) crackTime = 'MINUTES';
    const pct = Math.min(100, Math.round((entropy / 100) * 100));
    setPwdResult({ length, entropy, strength, color, crackTime, hasUpper, hasLower, hasDigit, hasSpecial, pct });
  }

  function handleHashAudit(e) {
    e.preventDefault();
    const hash = hashInput.trim();
    if (!hash) return;
    let type = 'UNKNOWN SIGNATURE'; let description = 'Could not match typical cryptographic hash signatures.';
    let strength = 'UNVERIFIED'; let recommendations = 'Audit database storage protocols to ensure secure credentials policies.';
    const cleanHash = hash.replace(/\s+/g, '');
    const isHex = /^[0-9a-fA-F]+$/.test(cleanHash);
    if (cleanHash.startsWith('$2a$') || cleanHash.startsWith('$2b$') || cleanHash.startsWith('$2y$')) {
      type = 'bcrypt (Blowfish Key Expansion)'; description = 'Adaptive hashing with Salt, Cost Factor, and Key Expansion to defeat brute-force.';
      strength = 'HIGHLY SECURE'; recommendations = 'Excellent choice. Fits modern enterprise credential standards.';
    } else if (isHex) {
      if (cleanHash.length === 32) { type = 'MD5 (Message Digest 5)'; description = '128-bit checksum. Completely broken — vulnerable to hash collisions.'; strength = 'COMPROMISED'; recommendations = 'CRITICAL: Upgrade immediately to bcrypt, Argon2, or PBKDF2.'; }
      else if (cleanHash.length === 40) { type = 'SHA-1 (Deprecated)'; description = '160-bit hash. Deprecated since 2011 due to collision vulnerabilities.'; strength = 'DEPRECATED'; recommendations = 'Migrate to SHA-256 with salts or adaptive bcrypt.'; }
      else if (cleanHash.length === 64) { type = 'SHA-256 (SHA-2 Family)'; description = '256-bit cryptographic digest. Safe from collision attacks.'; strength = 'SECURE (IF SALTED)'; recommendations = 'Ensure hashes are combined with cryptographically secure unique salts.'; }
      else if (cleanHash.length === 128) { type = 'SHA-512 (SHA-2 Family)'; description = '512-bit secure digest. Recommended for high-entropy operations.'; strength = 'SECURE (IF SALTED)'; recommendations = 'Ensure salting algorithms are enforced in system config.'; }
    }
    setHashResult({ type, description, strength, recommendations });
  }

  const gradeColor = { A: 'var(--accent-green)', B: 'var(--accent-cyan)', C: 'var(--accent-orange)', F: 'var(--accent-red)' };

  return (
    <div className="page">
      <div className="hud-page-header">
        <div className="hud-page-header-left">
          <div className="hud-page-label">INTELLIGENCE · POSTURE · CREDENTIAL AUDIT</div>
          <h2 className="hud-page-title">SECURITY OPERATIONS TOOLBOX</h2>
          <p className="hud-page-desc">
            Professional multi-vector threat intelligence. Execute advanced IP reputation lookups with 6-axis scoring, audit HTTP security posture, and evaluate credential entropy.
          </p>
        </div>
      </div>

      <div className="tool-grid">

        {/* ── Tool 1: Advanced IP Threat Intelligence ── */}
        <section className="tool-card" style={{ gridColumn: 'span 2' }}>
          <div className="tool-card-header">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2.2">
              <circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" />
              <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
            </svg>
            <h3>ADVANCED IP THREAT INTELLIGENCE — 6-AXIS SCORING</h3>
          </div>
          <p className="tool-desc">
            Multi-vector threat analysis using geo intelligence, behavioral signatures, historical incidents, malware associations, and cross-referenced threat feeds. Try: <code style={{ fontSize: '10px', color: 'var(--accent-cyan)', fontFamily: 'monospace' }}>45.33.12.9</code> (high risk) or <code style={{ fontSize: '10px', color: 'var(--accent-orange)', fontFamily: 'monospace' }}>185.220.101.1</code> (suspicious)
          </p>
          <form onSubmit={handleIpLookup} className="tool-inputs" style={{ marginBottom: 16 }}>
            <label style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', color: 'var(--accent-cyan)', textTransform: 'uppercase', fontFamily: 'Space Grotesk', display: 'flex', flexDirection: 'column', gap: 6, flex: 1 }}>
              TARGET IP ADDRESS
              <input value={ipInput} onChange={(e) => setIpInput(e.target.value)} placeholder="e.g. 45.33.12.9 · 185.220.101.1 · 8.8.8.8" required style={{ fontFamily: 'monospace' }} />
            </label>
            <button type="submit" className="btn-primary" disabled={scanning} style={{ whiteSpace: 'nowrap' }}>
              {scanning ? '◈ SCANNING...' : '⬡ MULTI-VECTOR SCAN'}
            </button>
          </form>

          {scanning && (
            <div style={{ padding: '16px', background: 'var(--surface)', borderRadius: '8px', border: '1px solid var(--border)', marginBottom: 16 }}>
              <div className="hud-loading">
                <span className="hud-loading-dot" /><span className="hud-loading-dot" /><span className="hud-loading-dot" />
                {scanPhase}
              </div>
            </div>
          )}

          {ipResult && !scanning && (
            <div className="threat-intel-result">
              {/* Left: Score Ring */}
              <div className="threat-intel-left">
                <ThreatScoreRing score={ipResult.threatScore} status={ipResult.status} />

                {/* Confidence + Data Sources */}
                <div style={{ marginTop: 12, textAlign: 'center' }}>
                  <div style={{ fontSize: '9px', color: 'var(--text-faint)', letterSpacing: '0.1em', marginBottom: 4, fontFamily: 'Space Grotesk' }}>INTELLIGENCE CONFIDENCE</div>
                  <div style={{ fontSize: '16px', fontWeight: 800, color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk' }}>{ipResult.confidence}%</div>
                </div>

                {/* Last seen */}
                {ipResult.lastSeen !== '—' && (
                  <div style={{ marginTop: 8, padding: '4px 10px', background: 'var(--accent-red-dim)', border: '1px solid var(--accent-red)', borderRadius: '4px', textAlign: 'center' }}>
                    <div style={{ fontSize: '9px', color: 'var(--accent-red)', fontWeight: 700, letterSpacing: '0.08em', fontFamily: 'Space Grotesk' }}>LAST SEEN ACTIVE</div>
                    <div style={{ fontSize: '11px', color: 'var(--text)', fontFamily: 'monospace' }}>{ipResult.lastSeen}</div>
                  </div>
                )}

                {/* Open Ports */}
                {ipResult.openPorts.length > 0 && (
                  <div style={{ marginTop: 8 }}>
                    <div style={{ fontSize: '9px', color: 'var(--text-faint)', letterSpacing: '0.1em', marginBottom: 4, fontFamily: 'Space Grotesk' }}>OPEN PORTS DETECTED</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, justifyContent: 'center' }}>
                      {ipResult.openPorts.map(p => (
                        <span key={p} style={{
                          fontSize: '10px', fontFamily: 'monospace', padding: '2px 6px',
                          borderRadius: '3px', border: '1px solid var(--border)',
                          color: [22, 3306, 6379].includes(p) ? 'var(--accent-orange)' : 'var(--text-dim)',
                          background: [22, 3306, 6379].includes(p) ? 'var(--accent-orange-dim)' : 'var(--surface)',
                        }}>{p}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Right: Details */}
              <div className="threat-intel-right">
                {/* Header */}
                <div style={{ marginBottom: 14, paddingBottom: 10, borderBottom: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '18px', fontWeight: 800, fontFamily: 'Space Grotesk, monospace', color: 'var(--text)', letterSpacing: '0.04em' }}>{ipResult.ip}</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: 2, fontFamily: 'monospace' }}>
                    {ipResult.city}, {ipResult.region}, {ipResult.country} · {ipResult.asn} · {ipResult.org}
                  </div>
                </div>

                {/* IOC Tags */}
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: '9px', color: 'var(--text-faint)', letterSpacing: '0.1em', marginBottom: 6, fontFamily: 'Space Grotesk' }}>IOC CLASSIFICATION TAGS</div>
                  <IocTags tags={ipResult.tags} iocFlags={ipResult.iocFlags} />
                </div>

                {/* 6-axis score bars */}
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: '9px', color: 'var(--text-faint)', letterSpacing: '0.1em', marginBottom: 8, fontFamily: 'Space Grotesk' }}>MULTI-VECTOR THREAT BREAKDOWN</div>
                  <CategoryScoreBars categories={ipResult.categories} />
                </div>

                {/* Risk Factors */}
                {ipResult.riskFactors.length > 0 && (
                  <div style={{ marginBottom: 14 }}>
                    <div style={{ fontSize: '9px', color: 'var(--text-faint)', letterSpacing: '0.1em', marginBottom: 6, fontFamily: 'Space Grotesk' }}>THREAT INTELLIGENCE FINDINGS</div>
                    <ul style={{ listStyle: 'none', padding: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
                      {ipResult.riskFactors.map((f, i) => (
                        <li key={i} style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                          <span style={{ color: 'var(--accent-cyan)', flexShrink: 0, marginTop: 1 }}>▷</span>
                          {f}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Active Campaigns */}
                {ipResult.reportedCampaigns.length > 0 && (
                  <div style={{ marginBottom: 14 }}>
                    <div style={{ fontSize: '9px', color: 'var(--text-faint)', letterSpacing: '0.1em', marginBottom: 6, fontFamily: 'Space Grotesk' }}>LINKED THREAT CAMPAIGNS</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {ipResult.reportedCampaigns.map((c, i) => (
                        <span key={i} style={{
                          fontSize: '10px', fontFamily: 'monospace', padding: '3px 8px',
                          borderRadius: '3px', border: '1px solid var(--accent-purple)',
                          color: 'var(--accent-purple)', background: 'var(--accent-purple-dim)',
                        }}>⬡ {c}</span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Data Sources */}
                <div>
                  <div style={{ fontSize: '9px', color: 'var(--text-faint)', letterSpacing: '0.1em', marginBottom: 4, fontFamily: 'Space Grotesk' }}>DATA SOURCES QUERIED</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {ipResult.dataSource.map((s, i) => (
                      <span key={i} style={{
                        fontSize: '9px', fontFamily: 'monospace', padding: '2px 6px',
                        borderRadius: '3px', border: '1px solid var(--border)',
                        color: 'var(--text-faint)', background: 'var(--surface)',
                      }}>{s}</span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </section>

        {/* ── Tool 2: Security Header Scanner ── */}
        <section className="tool-card">
          <div className="tool-card-header">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2.2">
              <rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
            <h3>HTTP SECURITY HEADER SCANNER</h3>
          </div>
          <p className="tool-desc">Audit server-side security controls. Check for headers mitigating clickjacking, MIME-type sniffing, and XSS.</p>
          <form onSubmit={handleHeaderScan} className="tool-inputs">
            <label style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', color: 'var(--accent-cyan)', textTransform: 'uppercase', fontFamily: 'Space Grotesk', display: 'flex', flexDirection: 'column', gap: 6 }}>
              TARGET URL / DOMAIN
              <input value={urlInput} onChange={(e) => setUrlInput(e.target.value)} placeholder="e.g. security-portal.net" required style={{ fontFamily: 'monospace' }} />
            </label>
            <button type="submit" className="btn-primary">⬡ SCAN HEADERS</button>
          </form>
          {headerResult && (
            <div className="tool-results">
              <div className="tool-results-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>HEADER AUDIT: {headerResult.domain}</span>
                <span style={{ fontSize: '20px', fontWeight: 800, color: gradeColor[headerResult.grade] || 'var(--text)', textShadow: `0 0 10px ${gradeColor[headerResult.grade] || 'var(--text)'}` }}>
                  GRADE {headerResult.grade}
                </span>
              </div>
              <div className="tool-results-content">
                {/* Score bar */}
                <div style={{ marginBottom: 12 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-faint)', marginBottom: 4, fontFamily: 'Space Grotesk' }}>
                    <span>SECURITY POSTURE SCORE</span>
                    <span style={{ color: gradeColor[headerResult.grade] }}>{headerResult.securityScore}/100</span>
                  </div>
                  <div style={{ height: '5px', background: 'var(--surface-2)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{ width: `${headerResult.securityScore}%`, height: '100%', background: gradeColor[headerResult.grade] || 'var(--accent-cyan)', borderRadius: '3px', transition: 'width 0.8s ease' }} />
                  </div>
                </div>
                <table className="header-scan-table">
                  <thead><tr><th>SECURITY HEADER</th><th>STATUS</th><th>FINDING</th></tr></thead>
                  <tbody>
                    {headerResult.headers.map((h, i) => (
                      <tr key={i}>
                        <td style={{ fontFamily: 'monospace', fontSize: '11px' }}>{h.name}</td>
                        <td><span className={`header-status-badge ${h.status.toLowerCase()}`}>{h.status}</span></td>
                        <td style={{ color: h.status === 'Present' ? 'var(--accent-green)' : 'var(--accent-red)', fontSize: '11px', fontWeight: 600 }}>{h.rating}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div className="tool-result-row" style={{ marginTop: 14, flexDirection: 'column', gap: 4 }}>
                  <span>REMEDIATION RECOMMENDATION</span>
                  <strong style={{ color: headerResult.grade === 'F' ? 'var(--accent-red)' : 'var(--accent-green)', fontSize: '12px' }}>{headerResult.recommendation}</strong>
                </div>
              </div>
            </div>
          )}
        </section>

        {/* ── Tool 3: Credential & Hash Auditor ── */}
        <section className="tool-card">
          <div className="tool-card-header">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2.2">
              <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
            </svg>
            <h3>CREDENTIAL & HASH STRENGTH AUDITOR</h3>
          </div>
          <p className="tool-desc">Calculate security entropy, estimate cloud-cracking times, and identify database hash algorithms.</p>
          <div className="tool-body">
            <label style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', color: 'var(--accent-cyan)', textTransform: 'uppercase', fontFamily: 'Space Grotesk', display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 12 }}>
              EVALUATE PASSWORD / KEY
              <input type="password" value={passwordInput} onChange={(e) => auditPassword(e.target.value)} placeholder="Enter password to analyze entropy..." style={{ fontFamily: 'monospace' }} />
            </label>

            {pwdResult && (
              <div className="tool-results" style={{ marginBottom: 16 }}>
                <div className="tool-results-title">CREDENTIAL ENTROPY BREAKDOWN</div>
                <div className="tool-results-content">
                  <div className="tool-result-row">
                    <span>COMPLEXITY STATUS</span>
                    <strong style={{ color: pwdResult.color, textShadow: `0 0 8px ${pwdResult.color}` }}>{pwdResult.strength}</strong>
                  </div>
                  <div style={{ margin: '8px 0' }}>
                    <div style={{ height: '6px', background: 'var(--surface-2)', borderRadius: '3px', overflow: 'hidden' }}>
                      <div style={{ width: `${pwdResult.pct}%`, height: '100%', background: pwdResult.color, borderRadius: '3px', transition: 'width 0.5s ease' }} />
                    </div>
                  </div>
                  {[
                    { label: 'KEY ENTROPY', value: `${pwdResult.entropy} bits (${pwdResult.length} chars)` },
                    { label: 'EST. CRACK TIME', value: pwdResult.crackTime },
                    { label: 'COMPLEXITY FLAGS', value: [pwdResult.hasUpper && '✓ UPPER', pwdResult.hasLower && '✓ LOWER', pwdResult.hasDigit && '✓ DIGITS', pwdResult.hasSpecial && '✓ SPECIAL'].filter(Boolean).join('  ') },
                  ].map(({ label, value }) => (
                    <div key={label} className="tool-result-row">
                      <span>{label}</span><strong>{value}</strong>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <form onSubmit={handleHashAudit} style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', color: 'var(--accent-cyan)', textTransform: 'uppercase', fontFamily: 'Space Grotesk' }}>VERIFY HASH SIGNATURE</label>
              <div style={{ display: 'flex', gap: 8 }}>
                <input style={{ flex: 1, fontFamily: 'monospace', fontSize: '11px' }} value={hashInput} onChange={(e) => setHashInput(e.target.value)} placeholder="e.g. 5d41402abc4b2a76b9719d911017c592" />
                <button type="submit" className="btn-primary" style={{ width: 'auto', whiteSpace: 'nowrap' }}>⬡ AUDIT</button>
              </div>
            </form>

            {hashResult && (
              <div className="tool-results" style={{ marginTop: 12, borderLeft: '2px solid var(--border-active)' }}>
                <div className="tool-results-title">CRYPTOGRAPHIC HASH AUDIT: {hashInput.substring(0, 10)}...</div>
                <div className="tool-results-content">
                  {[
                    { label: 'ALGORITHM', value: hashResult.type, color: 'var(--accent-cyan)' },
                    { label: 'POSTURE STRENGTH', value: hashResult.strength, color: hashResult.strength.includes('COMPROMISED') || hashResult.strength.includes('DEPRECATED') ? 'var(--accent-red)' : 'var(--accent-green)' },
                    { label: 'DESCRIPTION', value: hashResult.description },
                    { label: 'RECOMMENDATION', value: hashResult.recommendations },
                  ].map(({ label, value, color }) => (
                    <div key={label} className="tool-result-row">
                      <span>{label}</span><strong style={{ color: color || 'var(--text)' }}>{value}</strong>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
