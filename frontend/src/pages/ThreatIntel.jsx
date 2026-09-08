import { useEffect, useState } from 'react';
import client from '../api/client';
import { SeverityBadge } from '../components/StatCard';

const MITIGATION_GUIDES = {
  'CVE-2021-44228': 'Upgrade Apache Log4j to version 2.17.1 or higher. If patching is delayed, set JVM system property log4j2.formatMsgNoLookups=true, or remove the JndiLookup class from the classpath.',
  'CVE-2017-0144': 'Disable SMBv1 protocol on all endpoints, block port 445 at network security boundaries, and enforce installation of Microsoft update MS17-010.',
  'CVE-2020-1472': 'Deploy Microsoft server security patches enforcing secure Netlogon channels. Restrict administrative system binds from remote subnets.',
  'CVE-2024-3094': 'Downgrade Liblzma/XZ-utils libraries to version 5.4.6 immediately. Verify active sshd binaries are compiled from source without backdoor flags.'
};

const FALLBACK_CVES = [
  {
    id: 'CVE-2024-3094',
    severity: 'CRITICAL',
    cvss: 10.0,
    vendor: 'Xz / Liblzma',
    product: 'xz-utils',
    summary: 'Backdoor introduced into xz/liblzma via malicious upstream commits, enabling unauthorized SSH authentication bypass and remote code execution.',
    affected: 'xz-utils 5.6.0 - 5.6.1',
    mitreTactic: 'Initial Access (T1195 - Supply Chain Compromise)',
    remediation: 'Downgrade Liblzma/XZ-utils libraries to version 5.4.6 immediately. Verify active sshd binaries are compiled from source without backdoor flags.',
    publishedDate: '2024-03-29',
    status: 'ACTIVE EXPLOITATION'
  },
  {
    id: 'CVE-2023-44487',
    severity: 'HIGH',
    cvss: 7.5,
    vendor: 'Internet Engineering Task Force',
    product: 'HTTP/2 Protocol',
    summary: 'HTTP/2 Rapid Reset vulnerability allows distributed denial of service through continuous stream cancellation frames (RST_STREAM).',
    affected: 'HTTP/2-enabled web servers (NGINX, Envoy, Apache, Cloudflare)',
    mitreTactic: 'Impact (T1499 - Endpoint Denial of Service)',
    remediation: 'Apply vendor patches implementing rate limiting on RST_STREAM frames or temporarily disable HTTP/2 protocol support at edge proxies.',
    publishedDate: '2023-10-10',
    status: 'ACTIVE EXPLOITATION'
  },
  {
    id: 'CVE-2021-44228',
    severity: 'CRITICAL',
    cvss: 10.0,
    vendor: 'Apache Software Foundation',
    product: 'Log4j2',
    summary: 'Log4Shell: JNDI lookup vulnerability in Apache Log4j2 allows unauthenticated remote code execution via LDAP/RMI message format strings.',
    affected: 'Apache Log4j 2.0-beta9 to 2.15.0',
    mitreTactic: 'Execution (T1059 - Command and Scripting Interpreter)',
    remediation: 'Upgrade Apache Log4j to version 2.17.1 or higher. If patching is delayed, set JVM system property log4j2.formatMsgNoLookups=true, or remove the JndiLookup class from classpath.',
    publishedDate: '2021-12-10',
    status: 'ACTIVE EXPLOITATION'
  },
  {
    id: 'CVE-2024-21887',
    severity: 'CRITICAL',
    cvss: 9.1,
    vendor: 'Ivanti',
    product: 'Connect Secure / Policy Secure',
    summary: 'Command injection vulnerability in web components of Ivanti Connect Secure allows authenticated administrators to send crafted requests and execute arbitrary commands.',
    affected: 'Ivanti Connect Secure 9.x, 22.x',
    mitreTactic: 'Privilege Escalation (T1068)',
    remediation: 'Apply vendor security mitigation XML files or upgrade to patched firmware release. Restrict administrative port access to trusted management networks.',
    publishedDate: '2024-01-12',
    status: 'ACTIVE EXPLOITATION'
  },
  {
    id: 'CVE-2023-4966',
    severity: 'CRITICAL',
    cvss: 9.4,
    vendor: 'Citrix',
    product: 'NetScaler ADC and Gateway',
    summary: 'Citrix Bleed: Buffer overflow in NetScaler ADC and Gateway allows sensitive memory disclosure including session hijacking tokens.',
    affected: 'NetScaler ADC and NetScaler Gateway 13.0, 13.1, 14.1',
    mitreTactic: 'Credential Access (T1539 - Steal Web Session Cookie)',
    remediation: 'Install vendor hotfix immediately and kill all active persistent user sessions across AAA virtual servers.',
    publishedDate: '2023-10-25',
    status: 'ACTIVE EXPLOITATION'
  },
  {
    id: 'CVE-2022-22965',
    severity: 'CRITICAL',
    cvss: 9.8,
    vendor: 'VMware Spring',
    product: 'Spring Framework',
    summary: 'Spring4Shell: Remote code execution vulnerability in Spring Framework via DataBinder parameter binding on JDK 9+ executing on Apache Tomcat.',
    affected: 'Spring Framework 5.3.0 - 5.3.17, 5.2.0 - 5.2.19',
    mitreTactic: 'Execution (T1190 - Exploit Public-Facing Application)',
    remediation: 'Upgrade to Spring Framework 5.3.18 or 5.2.20+. Ensure web application parameters use allow/disallow lists on WebDataBinder.',
    publishedDate: '2022-03-31',
    status: 'ACTIVE EXPLOITATION'
  },
  {
    id: 'CVE-2020-1472',
    severity: 'CRITICAL',
    cvss: 10.0,
    vendor: 'Microsoft',
    product: 'Windows Server / Netlogon',
    summary: 'Zerologon: Elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller.',
    affected: 'Windows Server 2008 R2, 2012, 2016, 2019',
    mitreTactic: 'Privilege Escalation (T1068)',
    remediation: 'Deploy Microsoft security update enforcing secure RPC for Netlogon channels on all domain controllers.',
    publishedDate: '2020-08-11',
    status: 'ACTIVE EXPLOITATION'
  },
  {
    id: 'CVE-2021-34527',
    severity: 'HIGH',
    cvss: 8.8,
    vendor: 'Microsoft',
    product: 'Windows Print Spooler',
    summary: 'PrintNightmare: Remote code execution vulnerability in the Windows Print Spooler service (spoolsv.exe) improperly performs privileged file operations.',
    affected: 'All supported Windows client and server operating systems',
    mitreTactic: 'Execution (T1059)',
    remediation: 'Disable the Print Spooler service on systems that do not require printing (especially Domain Controllers), or install the official out-of-band security update.',
    publishedDate: '2021-07-01',
    status: 'ACTIVE EXPLOITATION'
  }
];

export default function ThreatIntel() {
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [expandedCve, setExpandedCve] = useState(null);
  const [feedSource, setFeedSource] = useState('SYNCING');

  const fetchThreats = () => {
    setLoading(true);
    setError('');
    client
      .get('/threats/cves')
      .then(({ data }) => {
        if (data?.cves && Array.isArray(data.cves) && data.cves.length > 0) {
          setCves(data.cves);
          setFeedSource('LIVE CISA KEV & NVD');
        } else {
          setCves(FALLBACK_CVES);
          setFeedSource('CURATED CISA KEV CATALOG');
        }
      })
      .catch((err) => {
        console.warn('[ThreatIntel] Live feed request failed, utilizing curated threat catalog:', err);
        setCves(FALLBACK_CVES);
        setFeedSource('CURATED CISA KEV CATALOG (OFFLINE RESILIENT)');
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchThreats();
  }, []);

  const toggleExpand = (id) => {
    setExpandedCve(prev => prev === id ? null : id);
  };

  const filteredCves = cves.filter((cve) => {
    const matchesSearch =
      cve.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      cve.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (cve.mitreTactic && cve.mitreTactic.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesSeverity = severityFilter === 'ALL' || cve.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="page">
      {/* HUD Page Header */}
      <div className="hud-page-header">
        <div className="hud-page-header-left">
          <div className="hud-page-label">MITRE ATT&CK · NVD SYNC</div>
          <h2 className="hud-page-title">THREAT INTELLIGENCE FEED</h2>
          <p className="hud-page-desc">
            High-impact CVEs synchronized from MITRE ATT&CK and NVD databases. Click any card to expand active remediation protocols.
          </p>
        </div>
        <div className="hud-page-header-right" style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <div className="hud-stat-badge">
            <span className="hud-stat-badge-label">FEED STATUS</span>
            <span className="hud-stat-badge-value" style={{ color: 'var(--accent-green)', fontSize: '10px' }}>
              ● {feedSource}
            </span>
          </div>
          <div className="hud-stat-badge">
            <span className="hud-stat-badge-label">ACTIVE CVEs</span>
            <span className="hud-stat-badge-value">{cves.length}</span>
          </div>
          <button
            onClick={fetchThreats}
            style={{
              padding: '6px 12px',
              borderRadius: '6px',
              background: 'rgba(0, 212, 255, 0.08)',
              border: '1px solid var(--accent-cyan)',
              color: 'var(--accent-cyan)',
              fontFamily: 'Space Grotesk, monospace',
              fontSize: '11px',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            🔄 RE-SYNC
          </button>
        </div>
      </div>

      {loading && (
        <div className="hud-loading">
          <span className="hud-loading-dot" />
          <span className="hud-loading-dot" />
          <span className="hud-loading-dot" />
          SYNCHRONIZING THREAT DATABASE...
        </div>
      )}
      {error && <div className="form-error">{error}</div>}

      {!loading && !error && (
        <>
          {/* Filters Row */}
          <div className="hud-filter-row">
            <div className="hud-search-wrap">
              <svg className="hud-search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14">
                <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
              </svg>
              <input
                type="text"
                className="hud-search-input"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search CVE ID, summary, ATT&CK tactic..."
              />
            </div>
            <div className="filter-tabs">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                <button
                  key={sev}
                  className={`filter-tab ${severityFilter === sev ? 'active' : ''}`}
                  onClick={() => setSeverityFilter(sev)}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* CVE Cards Grid */}
          <div className="cve-grid">
            {filteredCves.map((cve) => {
              const isExpanded = expandedCve === cve.id;
              const mitigationText = cve.remediation || MITIGATION_GUIDES[cve.id] || 'Audit affected software packages and update system dependencies to their latest secure releases.';

              return (
                <div
                  key={cve.id}
                  className={`cve-card expandable ${isExpanded ? 'active' : ''}`}
                  onClick={() => toggleExpand(cve.id)}
                >
                  <div className="cve-head">
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span className="cve-id">{cve.id}</span>
                      {cve.dateAdded && (
                        <span style={{ fontSize: '10px', color: 'var(--text-faint)', background: 'var(--surface-2)', padding: '2px 6px', borderRadius: 4, fontFamily: 'JetBrains Mono' }}>
                          CISA KEV: {cve.dateAdded}
                        </span>
                      )}
                    </div>
                    <SeverityBadge severity={cve.severity} />
                  </div>
                  <p className="cve-summary">{cve.summary}</p>

                  <div className="cve-meta">
                    <div className="cve-meta-item">
                      <span className="cve-meta-key">CVSS</span>
                      <span className="cve-meta-val">{cve.cvss}</span>
                    </div>
                    <div className="cve-meta-item">
                      <span className="cve-meta-key">SCOPE</span>
                      <span className="cve-meta-val">{cve.affected}</span>
                    </div>
                    <div className="cve-meta-item">
                      <span className="cve-meta-key">ATT&CK</span>
                      <span className="cve-meta-val">{cve.mitreTactic}</span>
                    </div>
                  </div>

                  <div className="cve-expand-hint">
                    {isExpanded ? '▲ HIDE REMEDIATION' : '▼ SHOW REMEDIATION PROTOCOL'}
                  </div>

                  {isExpanded && (
                    <div className="cve-remediation-details" onClick={(e) => e.stopPropagation()}>
                      <div className="cve-remediation-title">⬡ CISA REQUIRED REMEDIATION DIRECTIVE</div>
                      <p className="cve-remediation-text">{mitigationText}</p>
                      {cve.notes && (
                        <div style={{ marginTop: 8, fontSize: '11px', color: 'var(--text-faint)', wordBreak: 'break-all' }}>
                          <strong>References: </strong>{cve.notes}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}

            {filteredCves.length === 0 && (
              <div className="hud-empty-state">
                <div className="hud-empty-icon">◈</div>
                <div>NO VULNERABILITIES MATCHED FILTERS</div>
                <p>Adjust severity filter or clear the search query to broaden results.</p>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
