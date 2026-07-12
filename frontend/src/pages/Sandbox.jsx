import { useState } from 'react';
import axios from '../api/client';

export default function Sandbox() {
  const [vulnType, setVulnType] = useState('sqli');
  const [securityEnabled, setSecurityEnabled] = useState(false);
  const [payload, setPayload] = useState("' OR '1'='1");
  const [loading, setLoading] = useState(false);
  const [simulationResult, setSimulationResult] = useState(null);
  const [explanation, setExplanation] = useState('');
  const [explaining, setExplaining] = useState(false);

  const PRESETS = {
    sqli: [
      { label: 'Basic SQL bypass', value: "' OR '1'='1" },
      { label: 'SQL UNION leak', value: "' UNION SELECT null, username, password, email FROM users --" },
      { label: 'Stacking SQL query', value: "'; DROP TABLE logs; --" }
    ],
    xss: [
      { label: 'Simple script alert', value: "<script>alert('XSS!')</script>" },
      { label: 'Broken img tag event', value: "<img src=x onerror=alert('ImageLoadError')>" },
      { label: 'Javascript href redirect', value: "javascript:alert(document.cookie)" }
    ],
    cmd: [
      { label: 'Concatenated shell run', value: "127.0.0.1; whoami" },
      { label: 'Read critical files', value: "8.8.8.8 | cat /etc/passwd" },
      { label: 'List server directory', value: "127.0.0.1 & dir" }
    ]
  };

  function handleTypeChange(type) {
    setVulnType(type);
    setPayload(PRESETS[type][0].value);
    setSimulationResult(null);
    setExplanation('');
  }

  async function handleSimulate(e) {
    e.preventDefault();
    if (!payload.trim()) return;

    setLoading(true);
    setSimulationResult(null);
    setExplanation('');

    try {
      const response = await axios.post('/sandbox/simulate', {
        type: vulnType,
        payload,
        securityEnabled
      });
      setSimulationResult(response.data);
    } catch (err) {
      console.error('Simulation request failed:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleExplain() {
    if (!simulationResult) return;

    setExplaining(true);
    try {
      const response = await axios.post('/sandbox/explain', {
        type: vulnType,
        payload,
        securityEnabled
      });
      setExplanation(response.data.explanation);
    } catch (err) {
      console.error('Failed to get security explanation:', err);
      setExplanation('Unable to contact the security analyzer. Please verify system connections.');
    } finally {
      setExplaining(false);
    }
  }

  function renderMarkdown(text) {
    if (!text) return null;
    return text.split('\n').map((line, index) => {
      let trimmed = line.trim();
      if (trimmed.startsWith('###')) {
        return (
          <h4 key={index} style={{ fontSize: '14px', marginTop: '18px', marginBottom: '8px', color: 'var(--text)', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ display: 'inline-block', width: '5px', height: '5px', background: 'var(--accent-cyan)', borderRadius: '50%' }}></span>
            {trimmed.replace('###', '').trim()}
          </h4>
        );
      }
      if (trimmed.startsWith('##')) {
        return (
          <h3 key={index} style={{ fontSize: '16px', marginTop: '22px', marginBottom: '10px', color: 'var(--text)', fontWeight: '600' }}>
            {trimmed.replace('##', '').trim()}
          </h3>
        );
      }
      if (trimmed.startsWith('*') || trimmed.startsWith('-')) {
        const cleanLine = trimmed.substring(1).trim();
        const parts = cleanLine.split('**');
        return (
          <li key={index} style={{ marginLeft: '18px', marginBottom: '6px', color: 'var(--text-dim)' }}>
            {parts.map((p, i) => i % 2 === 1 ? <strong key={i}>{p}</strong> : p)}
          </li>
        );
      }
      const parts = line.split('**');
      return (
        <p key={index} style={{ marginBottom: '8px', color: 'var(--text-dim)' }}>
          {parts.map((p, i) => i % 2 === 1 ? <strong key={i}>{p}</strong> : p)}
        </p>
      );
    });
  }

  return (
    <div className="page sandbox-page">
      <div className="page-header">
        <h2>Cyber Attack Sandbox & WAF Lab</h2>
        <p className="page-desc">
          Interactive security playground. Execute simulated exploits, toggle Web Application Firewall (WAF) rule sets, inspect code vulnerability layers, and get real-time AI security advice.
        </p>
      </div>

      <div className="sandbox-grid">
        {/* Left Column: Input Panel */}
        <div className="sandbox-column">
          {/* Card 1: Configuration */}
          <section className="sandbox-card">
            <h3 className="sandbox-card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              Exploit Lab Configuration
            </h3>

            {/* Vuln Type Selector */}
            <div className="field">
              <span>Attack Vector Model</span>
              <div className="sandbox-type-selector">
                {['sqli', 'xss', 'cmd'].map((type) => (
                  <button
                    key={type}
                    type="button"
                    onClick={() => handleTypeChange(type)}
                    className={`sandbox-type-btn ${vulnType === type ? 'btn-primary' : 'btn-outline'}`}
                  >
                    {type === 'sqli' ? 'SQLi' : type === 'xss' ? 'XSS' : 'Command'}
                  </button>
                ))}
              </div>
            </div>

            {/* WAF Toggle */}
            <div className="sandbox-toggle-row">
              <div className="sandbox-toggle-info">
                <span className="sandbox-toggle-label">Secure Mode / WAF Filters</span>
                <span className="sandbox-toggle-desc">Interceptor shields & input query parameters</span>
              </div>
              <label className="sandbox-switch">
                <input
                  type="checkbox"
                  checked={securityEnabled}
                  onChange={(e) => {
                    setSecurityEnabled(e.target.checked);
                    setSimulationResult(null);
                    setExplanation('');
                  }}
                />
                <span className="sandbox-switch-slider"></span>
              </label>
            </div>

            {/* Presets & Payload Input */}
            <form onSubmit={handleSimulate}>
              <div className="field" style={{ marginBottom: '16px' }}>
                <span>Pre-configured Payloads</span>
                <div className="sandbox-preset-list">
                  {PRESETS[vulnType].map((preset, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => {
                        setPayload(preset.value);
                        setSimulationResult(null);
                        setExplanation('');
                      }}
                      className="sandbox-preset-btn"
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="field" style={{ marginBottom: '20px' }}>
                <span>Active Exploit Payload</span>
                <textarea
                  value={payload}
                  onChange={(e) => {
                    setPayload(e.target.value);
                    setSimulationResult(null);
                    setExplanation('');
                  }}
                  placeholder="Type or click a preset payload..."
                  className="sandbox-textarea"
                />
              </div>

              <button
                type="submit"
                className="btn-primary sandbox-submit-btn"
                disabled={loading}
              >
                {loading ? 'Executing Exploit Flow...' : 'Launch Simulation'}
              </button>
            </form>
          </section>

          {/* Code comparison panel */}
          {simulationResult && (
            <section className="sandbox-card">
              <h3 className="sandbox-card-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-orange)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="16 18 22 12 16 6" />
                  <polyline points="8 6 2 12 8 18" />
                </svg>
                Vulnerable vs Secure Code Implementation
              </h3>
              <div className="sandbox-code-split">
                <div>
                  <div className="sandbox-code-title vulnerable">
                    <span className="sandbox-code-title-dot"></span>
                    Vulnerable Logic
                  </div>
                  <pre className="sandbox-code-pre">
                    <code>{simulationResult.code.vuln}</code>
                  </pre>
                </div>
                <div>
                  <div className="sandbox-code-title secure">
                    <span className="sandbox-code-title-dot"></span>
                    Secure / Parameterized Logic
                  </div>
                  <pre className="sandbox-code-pre">
                    <code>{simulationResult.code.secure}</code>
                  </pre>
                </div>
              </div>
            </section>
          )}
        </div>

        {/* Right Column: Execution Output Panel */}
        <div className="sandbox-column">
          {/* Card 2: Interactive Monitor Logs */}
          <section className="sandbox-card" style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: '450px' }}>
            <h3 className="sandbox-card-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
                <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
                <line x1="6" y1="6" x2="6.01" y2="6" />
                <line x1="6" y1="18" x2="6.01" y2="18" />
              </svg>
              Execution Trace Monitor
            </h3>

            {!simulationResult ? (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '40px', textAlign: 'center' }}>
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-faint)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginBottom: '16px', opacity: 0.6 }}>
                  <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                </svg>
                <p style={{ color: 'var(--text-dim)', fontSize: '13.5px' }}>
                  Awaiting attack execution. Configure your setup and click "Launch Simulation" to trace pipeline events.
                </p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', height: '100%', flex: 1 }}>
                {/* Visual Route */}
                <div>
                  <h4 style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-dim)', marginBottom: '10px', letterSpacing: '0.05em' }}>
                    Network Connection Path
                  </h4>
                  <div className="sandbox-routing-map">
                    <div className="sandbox-routing-node">
                      <span className="sandbox-routing-node-label">CLIENT</span>
                      <span className="sandbox-routing-node-name" style={{ color: 'var(--accent-cyan)' }}>ATTACKER</span>
                    </div>
                    <div className="sandbox-routing-line">
                      <div className="sandbox-routing-dot" style={{ background: securityEnabled ? 'var(--accent-green)' : 'var(--accent-orange)' }}></div>
                    </div>
                    <div className="sandbox-routing-node">
                      <span className="sandbox-routing-node-label">DEFENSE</span>
                      <span className="sandbox-routing-node-name" style={{ color: securityEnabled ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                        {securityEnabled ? 'WAF ON' : 'WAF OFF'}
                      </span>
                    </div>
                    <div className="sandbox-routing-line">
                      <div className="sandbox-routing-dot" style={{ background: simulationResult.blocked ? 'var(--accent-red)' : 'var(--accent-green)' }}></div>
                    </div>
                    <div className="sandbox-routing-node">
                      <span className="sandbox-routing-node-label">SERVER</span>
                      <span className="sandbox-routing-node-name" style={{ color: simulationResult.blocked ? 'var(--text-faint)' : 'var(--accent-red)' }}>
                        {simulationResult.blocked ? 'SECURED' : 'COMPROMISED'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Logs Stream */}
                <div>
                  <h4 style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-dim)', marginBottom: '10px', letterSpacing: '0.05em' }}>
                    Simulation Execution Pipeline Stream
                  </h4>
                  <div className="sandbox-logs-stream">
                    {simulationResult.logs.map((log, idx) => {
                      let color = 'var(--text)';
                      if (log.includes('WARNING')) color = 'var(--accent-orange)';
                      else if (log.includes('BLOCK')) color = 'var(--accent-red)';
                      else if (log.includes('WAF')) color = 'var(--accent-cyan)';
                      else if (log.includes('DB') || log.includes('SHELL')) color = 'var(--text-dim)';
                      
                      return (
                        <div key={idx} style={{ color }}>
                          {log}
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Console Output */}
                <div>
                  <h4 style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-dim)', marginBottom: '10px', letterSpacing: '0.05em' }}>
                    Response Payload Console
                  </h4>
                  <div
                    className="sandbox-response-console"
                    style={{ borderLeft: simulationResult.blocked ? '4px solid var(--accent-red)' : '4px solid var(--accent-green)' }}
                  >
                    {simulationResult.executionResult}
                  </div>
                </div>

                {/* AI Advice Button */}
                <div style={{ marginTop: 'auto', paddingTop: '16px', borderTop: '1px solid var(--border)' }}>
                  <button
                    onClick={handleExplain}
                    className="btn-outline"
                    disabled={explaining}
                    style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', fontWeight: '600', padding: '12px' }}
                  >
                    {explaining ? (
                      'Consulting Cyber Sentinel AI Analyst...'
                    ) : (
                      <>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
                        </svg>
                        Request AI Threat Remediation
                      </>
                    )}
                  </button>
                </div>
              </div>
            )}
          </section>

          {/* AI Response Card */}
          {explanation && (
            <section className="sandbox-card" style={{ borderLeft: '4px solid var(--accent-cyan)' }}>
              <h3 className="sandbox-card-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                AI Threat Assessment & Secure Recommendations
              </h3>
              <div className="sandbox-ai-report-body">
                {renderMarkdown(explanation)}
              </div>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}
