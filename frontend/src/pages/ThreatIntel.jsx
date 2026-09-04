import { useEffect, useState } from 'react';
import client from '../api/client';
import { SeverityBadge } from '../components/StatCard';

const MITIGATION_GUIDES = {
  'CVE-2021-44228': 'Upgrade Apache Log4j to version 2.17.1 or higher. If patching is delayed, set JVM system property log4j2.formatMsgNoLookups=true, or remove the JndiLookup class from the classpath.',
  'CVE-2017-0144': 'Disable SMBv1 protocol on all endpoints, block port 445 at network security boundaries, and enforce installation of Microsoft update MS17-010.',
  'CVE-2020-1472': 'Deploy Microsoft server security patches enforcing secure Netlogon channels. Restrict administrative system binds from remote subnets.',
  'CVE-2024-3094': 'Downgrade Liblzma/XZ-utils libraries to version 5.4.6 immediately. Verify active sshd binaries are compiled from source without backdoor flags.'
};

export default function ThreatIntel() {
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [expandedCve, setExpandedCve] = useState(null);

  useEffect(() => {
    client
      .get('/threats/cves')
      .then(({ data }) => setCves(data.cves))
      .catch(() => setError('Failed to load threat intelligence feed.'))
      .finally(() => setLoading(false));
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
        <div className="hud-page-header-right">
          <div className="hud-stat-badge">
            <span className="hud-stat-badge-label">ACTIVE FEEDS</span>
            <span className="hud-stat-badge-value">{cves.length}</span>
          </div>
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
