import { useState } from 'react';
import client from '../api/client';
import { SeverityBadge } from '../components/StatCard';

const DEFAULT_CONFIG = {
  usesHttps: true,
  hasHsts: false,
  passwordMinLength: 8,
  mfaEnabled: false,
  softwareVersion: '',
  openPortsText: '22, 443',
  hasWaf: false,
  exposesAdminPanel: false,
  usesDefaultCredentials: false,
};

export default function VulnScanner() {
  const [config, setConfig] = useState(DEFAULT_CONFIG);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanLogs, setScanLogs] = useState([]);
  const [scanProgress, setScanProgress] = useState(0);

  function update(field, value) {
    setConfig((c) => ({ ...c, [field]: value }));
  }

  async function handleScan() {
    setError('');
    setResult(null);
    setScanning(true);
    setScanProgress(0);
    setScanLogs([]);
    setLoading(true);

    const logMessages = [
      { text: 'INIT — Cyber Sentinel diagnostic checklist probe engaged...', type: 'info', progress: 10 },
      { text: 'CHK1 — Verifying SSL/TLS layers and HTTP redirect coverage...', type: 'info', progress: 30 },
      { text: 'CHK2 — Probing open ports and boundary firewall rules...', type: 'info', progress: 55 },
      { text: 'CHK3 — Evaluating credential strength and MFA policy enforcement...', type: 'info', progress: 80 },
      { text: 'CHK4 — Scanning version headers against known CVE catalog vectors...', type: 'info', progress: 95 }
    ];

    try {
      const openPorts = config.openPortsText
        .split(',')
        .map((p) => parseInt(p.trim(), 10))
        .filter((n) => !Number.isNaN(n));

      for (let i = 0; i < logMessages.length; i++) {
        await new Promise(r => setTimeout(r, 260));
        setScanLogs(prev => [...prev, logMessages[i]]);
        setScanProgress(logMessages[i].progress);
      }

      const { data } = await client.post('/vuln/scan', { ...config, openPorts });
      await new Promise(r => setTimeout(r, 150));
      setScanProgress(100);
      setScanLogs(prev => [...prev, { text: 'COMPLETE — OWASP analysis reports loaded. Threat assessment finalized.', type: 'success', progress: 100 }]);
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.error || 'Scan failed.');
    } finally {
      setScanning(false);
      setLoading(false);
    }
  }

  return (
    <div className="page">
      {/* HUD Page Header */}
      <div className="hud-page-header">
        <div className="hud-page-header-left">
          <div className="hud-page-label">OWASP TOP 10 · CHECKLIST ENGINE</div>
          <h2 className="hud-page-title">VULNERABILITY SCANNER</h2>
          <p className="hud-page-desc">
            Configure boundary parameters, authentication policies, and active services. The offline analysis engine evaluates your exposure against OWASP Top 10 vulnerability classes.
          </p>
        </div>
      </div>

      {/* Configuration Panel */}
      <div className="panel scan-form">
        <h3 style={{ marginBottom: 20 }}>⬡ SYSTEM CONFIGURATION PARAMETERS</h3>

        <div className="vuln-checkbox-grid">
          {[
            { field: 'usesHttps', label: 'HTTPS enforced site-wide', icon: '🔒' },
            { field: 'hasHsts', label: 'HSTS header active', icon: '🛡' },
            { field: 'mfaEnabled', label: 'MFA enabled for operators', icon: '🔐' },
            { field: 'hasWaf', label: 'Web Application Firewall active', icon: '⚔' },
            { field: 'exposesAdminPanel', label: 'Admin panel publicly reachable', icon: '⚠' },
            { field: 'usesDefaultCredentials', label: 'Default credentials still in use', icon: '☠' },
          ].map(({ field, label, icon }) => (
            <label key={field} className={`vuln-checkbox-card ${config[field] ? 'checked' : ''}`}>
              <input
                type="checkbox"
                checked={config[field]}
                onChange={(e) => update(field, e.target.checked)}
                style={{ display: 'none' }}
              />
              <span className="vuln-checkbox-icon">{icon}</span>
              <span className="vuln-checkbox-label">{label}</span>
              <span className={`vuln-checkbox-state ${config[field] ? 'on' : 'off'}`}>
                {config[field] ? 'ON' : 'OFF'}
              </span>
            </label>
          ))}
        </div>

        <div className="form-row" style={{ marginTop: 20 }}>
          <label className="field">
            <span style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', color: 'var(--accent-cyan)', textTransform: 'uppercase', fontFamily: 'Space Grotesk' }}>
              MIN PASSWORD LENGTH
            </span>
            <input type="number" min={1} max={64} value={config.passwordMinLength}
              onChange={(e) => update('passwordMinLength', Number(e.target.value))} />
          </label>
          <label className="field">
            <span style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', color: 'var(--accent-cyan)', textTransform: 'uppercase', fontFamily: 'Space Grotesk' }}>
              SOFTWARE / SERVER VERSION
            </span>
            <input value={config.softwareVersion}
              onChange={(e) => update('softwareVersion', e.target.value)} placeholder="e.g. nginx 1.18.0" />
          </label>
        </div>

        <label className="field full-width" style={{ marginTop: 12 }}>
          <span style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', color: 'var(--accent-cyan)', textTransform: 'uppercase', fontFamily: 'Space Grotesk' }}>
            OPEN PORTS (COMMA-SEPARATED)
          </span>
          <input value={config.openPortsText}
            onChange={(e) => update('openPortsText', e.target.value)} placeholder="22, 443, 3306" style={{ fontFamily: 'monospace' }} />
        </label>

        {error && <div className="form-error">{error}</div>}

        <button className="btn-primary" onClick={handleScan} disabled={loading} style={{ marginTop: 20 }}>
          {loading ? 'RUNNING DIAGNOSTICS...' : '⬡ EXECUTE SECURITY SCAN'}
        </button>
      </div>

      {/* Scan Console Log */}
      {(scanning || scanLogs.length > 0) && (
        <div className="panel" style={{ marginTop: 24 }}>
          <h3>⬡ DIAGNOSTIC SCAN CONSOLE</h3>

          <div className="vuln-progress-wrapper">
            <div className="vuln-progress-label">
              <span>SECURITY ASSESSMENT CHECKPOINTS</span>
              <span style={{ color: 'var(--accent-cyan)', fontFamily: 'monospace' }}>{scanProgress}%</span>
            </div>
            <div className="vuln-progress-track">
              <div className="vuln-progress-fill" style={{ width: `${scanProgress}%` }} />
            </div>
          </div>

          <div className="vuln-console-box">
            {scanLogs.map((log, idx) => (
              <div key={idx} className={`vuln-console-line ${log.type}`}>
                <span style={{ color: 'var(--text-faint)', marginRight: 8, fontFamily: 'monospace' }}>
                  {new Date().toLocaleTimeString()}
                </span>
                {log.text}
              </div>
            ))}
            {scanning && (
              <div className="vuln-console-line info" style={{ opacity: 0.6 }}>
                <span className="hud-loading-dot" /><span className="hud-loading-dot" /><span className="hud-loading-dot" />
                {' '}RUNNING VECTOR ANALYSIS...
              </div>
            )}
          </div>
        </div>
      )}

      {/* Results */}
      {result && !scanning && (
        <>
          <div className="stat-grid stat-grid-2" style={{ marginTop: 24 }}>
            <div className="stat-card">
              <div className="stat-label">SECURITY RISK SCORE</div>
              <div className="stat-value" style={{ color: result.summary.riskScore >= 70 ? 'var(--accent-red)' : result.summary.riskScore >= 40 ? 'var(--accent-orange)' : 'var(--accent-green)' }}>
                {result.summary.riskScore}<span style={{ fontSize: '16px', color: 'var(--text-dim)' }}>/100</span>
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-label">THREAT CLASSIFICATION</div>
              <div className="stat-value" style={{ color: ['CRITICAL', 'HIGH'].includes(result.summary.riskLevel) ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                {result.summary.riskLevel}
              </div>
            </div>
          </div>

          <section className="panel" style={{ marginTop: 0 }}>
            <h3>⬡ OWASP RISK ASSESSMENT FINDINGS</h3>
            {result.findings.length === 0 ? (
              <div className="hud-empty-state">
                <div className="hud-empty-icon">✓</div>
                <div style={{ color: 'var(--accent-green)' }}>ALL CHECKPOINTS PASSED</div>
                <p>No anomalies detected. Environment aligns with OWASP best practices.</p>
              </div>
            ) : (
              <ul className="finding-list">
                {result.findings.map((f) => (
                  <li key={f.id} className="finding-item">
                    <div className="finding-head">
                      <SeverityBadge severity={f.severity} />
                      <strong>{f.title}</strong>
                    </div>
                    <p style={{ fontSize: '13px', color: 'var(--text-dim)', marginTop: 6 }}>{f.detail}</p>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </div>
  );
}
