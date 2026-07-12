import { useState } from 'react';
import client from '../api/client';
import { SeverityBadge } from '../components/StatCard';

const EMAIL_SAMPLES = {
  phishing: {
    sender: 'billing-support@netflix-update.click',
    subject: 'URGENT: Action Required - Account Suspended',
    body: `Dear customer,

We detected suspicious activity on your account. To prevent immediate suspension, please login and reset your password immediately at http://netflix-online.xyz/login.

Failure to confirm your billing payment details within 24 hours will lead to account termination.

Sincerely,
Netflix Account Security Team`
  },
  clean: {
    sender: 'security-alerts@github.com',
    subject: '[GitHub] Security Advisory Notification',
    body: `Hey there,

We are notifying you about a new security advisory in one of your dependencies. The package "express-rate-limit" has released a version fixing a potential denial-of-service vulnerability.

Please review the advisory on GitHub and run "npm audit fix" to upgrade.

Best,
GitHub Security`
  }
};

const LINK_SAMPLES = {
  spoofed: 'http://paypal-security-update.xyz/login.html',
  ipBased: 'http://45.33.12.9/secure/bank/verify',
  shortener: 'https://bit.ly/suspect-malware-download',
  clean: 'https://github.com/google/alloydb-omni'
};

const FILE_SAMPLES = {
  eicar: {
    name: 'eicar.txt',
    size: 68,
    hash: '275a021b13d6fc24777e0893a4bc60d170f3f260f8bd058b8eb338a11de20c662',
    content: 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
  },
  wannacry: {
    name: 'tasksche.exe',
    size: 3512320,
    hash: 'ed01ebfbc9eb5bbea545af4fed50786b0bc9e8538c340578a82b741f3e797699',
    content: ''
  },
  doubleExt: {
    name: 'receipt_payment_2026.pdf.exe',
    size: 24576,
    hash: '4d8a5c3b1e7f9a2b0c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b',
    content: 'Obfuscated command instruction header'
  },
  clean: {
    name: 'project_report.pdf',
    size: 1048576,
    hash: '3f7b8c2d1a0b9c8e7d6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d',
    content: '%PDF-1.4 ...'
  }
};

export default function ProtectionCenter() {
  const [activeSubTab, setActiveSubTab] = useState('email');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  
  // Email states
  const [emailSender, setEmailSender] = useState('');
  const [emailSubject, setEmailSubject] = useState('');
  const [emailBody, setEmailBody] = useState('');
  const [emailResult, setEmailResult] = useState(null);

  // Link states
  const [linkInput, setLinkInput] = useState('');
  const [linkResult, setLinkResult] = useState(null);

  // File states
  const [fileName, setFileName] = useState('');
  const [fileSize, setFileSize] = useState('');
  const [fileHash, setFileHash] = useState('');
  const [fileContent, setFileContent] = useState('');
  const [fileResult, setFileResult] = useState(null);
  const [scanLogs, setScanLogs] = useState([]);

  // AI Explanation states
  const [aiLoading, setAiLoading] = useState(false);
  const [aiExplanation, setAiExplanation] = useState('');

  // Helpers
  function handleLoadEmailSample(sampleKey) {
    const sample = EMAIL_SAMPLES[sampleKey];
    setEmailSender(sample.sender);
    setEmailSubject(sample.subject);
    setEmailBody(sample.body);
    setEmailResult(null);
    setAiExplanation('');
  }

  function handleLoadLinkSample(url) {
    setLinkInput(url);
    setLinkResult(null);
    setAiExplanation('');
  }

  function handleLoadFileSample(sampleKey) {
    const sample = FILE_SAMPLES[sampleKey];
    setFileName(sample.name);
    setFileSize(sample.size);
    setFileHash(sample.hash);
    setFileContent(sample.content);
    setFileResult(null);
    setScanLogs([]);
    setAiExplanation('');
  }

  async function handleEmailScan() {
    if (!emailBody.trim()) {
      setError('Please provide email body text.');
      return;
    }
    setError('');
    setEmailResult(null);
    setAiExplanation('');
    setLoading(true);

    try {
      const { data } = await client.post('/protection/scan-email', {
        emailText: emailBody,
        emailSubject,
        emailSender
      });
      setEmailResult(data);
    } catch (err) {
      setError(err.response?.data?.error || 'Email scan failed.');
    } finally {
      setLoading(false);
    }
  }

  async function handleLinkScan() {
    if (!linkInput.trim()) {
      setError('Please provide a URL to check.');
      return;
    }
    setError('');
    setLinkResult(null);
    setAiExplanation('');
    setLoading(true);

    try {
      const { data } = await client.post('/protection/scan-link', {
        url: linkInput
      });
      setLinkResult(data);
    } catch (err) {
      setError(err.response?.data?.error || 'Link check failed.');
    } finally {
      setLoading(false);
    }
  }

  async function handleFileScan() {
    if (!fileName.trim()) {
      setError('Please provide a file name.');
      return;
    }
    setError('');
    setFileResult(null);
    setAiExplanation('');
    setLoading(true);
    setScanLogs([]);

    const logs = [
      'Initializing Sandbox Container...',
      'Mapping file parameters to signature database...',
      'Calculating cryptographic SHA-256 integrity hash...',
      'Analyzing structural file layout and extensions...',
      'Executing static pattern heuristics matching...'
    ];

    for (const logLine of logs) {
      setScanLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] INFO: ${logLine}`]);
      await new Promise(r => setTimeout(r, 300));
    }

    try {
      const sizeInt = parseInt(fileSize) || 0;
      const { data } = await client.post('/protection/scan-file', {
        fileName,
        fileSize: sizeInt,
        fileHash,
        rawContent: fileContent
      });
      setFileResult(data);
      setScanLogs(prev => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] SUCCESS: Sandbox execution terminated. Threat Score: ${data.summary.threatScore}/100. Status: ${data.summary.status}`
      ]);
    } catch (err) {
      setError(err.response?.data?.error || 'File analysis failed.');
      setScanLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ERROR: File sandbox scan crashed.`]);
    } finally {
      setLoading(false);
    }
  }

  async function handleAIExplain(scanType, scanResult) {
    if (!scanResult) return;
    setAiLoading(true);
    setAiExplanation('');
    try {
      const { data } = await client.post('/protection/explain', {
        scanType,
        scanResult
      });
      setAiExplanation(data.explanation);
    } catch {
      setError('Failed to retrieve AI explanation.');
    } finally {
      setAiLoading(false);
    }
  }

  function renderMarkdown(text) {
    if (!text) return null;
    return text.split('\n').map((line, index) => {
      let trimmed = line.trim();
      if (trimmed.startsWith('###')) return <h4 key={index} style={{ color: 'var(--accent-cyan)', marginTop: 14, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{trimmed.replace('###', '').trim()}</h4>;
      if (trimmed.startsWith('##')) return <h3 key={index} style={{ color: 'var(--accent-cyan)', marginTop: 18, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{trimmed.replace('##', '').trim()}</h3>;
      if (trimmed.startsWith('*') || trimmed.startsWith('-')) {
        const cleanLine = trimmed.substring(1).trim();
        const parts = cleanLine.split('**');
        return <li key={index} style={{ marginLeft: 16, marginBottom: 4, color: 'var(--text-dim)' }}>{parts.map((p, i) => i % 2 === 1 ? <span key={i} style={{ color: 'var(--text)', fontWeight: 'normal' }}>{p}</span> : p)}</li>;
      }
      const parts = line.split('**');
      return <p key={index} style={{ marginBottom: 8, color: 'var(--text-dim)', fontSize: '13px' }}>{parts.map((p, i) => i % 2 === 1 ? <span key={i} style={{ color: 'var(--accent-cyan)', fontWeight: 'normal' }}>{p}</span> : p)}</p>;
    });
  }

  // Formatting helpers for styles
  function getScoreColor(score) {
    if (score >= 70) return 'var(--accent-red)';
    if (score >= 35) return 'var(--accent-orange)';
    return 'var(--accent-green)';
  }

  return (
    <div className="page">
      {/* Page Header */}
      <div className="hud-page-header">
        <div className="hud-page-header-left">
          <div className="hud-page-label">PROTECTION SUITE · EMAIL · LINKS · FILES</div>
          <h2 className="hud-page-title">THREAT PREVENTION CENTER</h2>
          <p className="hud-page-desc">
            Analyze messaging payloads, evaluate suspicious web resources, and execute files within our simulated security sandbox to detect phishing, credential harvesting, and malware signatures.
          </p>
        </div>
      </div>

      {/* Sub-tab selection */}
      <div className="tab-container" style={{ display: 'flex', gap: 10, marginBottom: 24, borderBottom: '1px solid var(--border)', paddingBottom: 10 }}>
        {[
          { id: 'email', label: '📧 EMAIL SCANS', desc: 'Phishing & social engineering detector' },
          { id: 'link', label: '🔗 LINK GUARD', desc: 'URL TLD & domain blacklist scanner' },
          { id: 'virus', label: '🦠 VIRUS SANDBOX', desc: 'File signature & binary integrity checks' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => {
              setActiveSubTab(tab.id);
              setError('');
              setEmailResult(null);
              setLinkResult(null);
              setFileResult(null);
              setAiExplanation('');
              setScanLogs([]);
            }}
            className={`btn-outline ${activeSubTab === tab.id ? 'active' : ''}`}
            style={{ flex: 1, padding: '10px 16px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, height: 'auto', border: activeSubTab === tab.id ? '1px solid var(--border-active)' : undefined }}
          >
            <span style={{ fontSize: '14px' }}>{tab.label}</span>
            <span style={{ fontSize: '9px', color: 'var(--text-faint)' }}>{tab.desc}</span>
          </button>
        ))}
      </div>

      {error && <div className="form-error" style={{ marginBottom: 16 }}>{error}</div>}

      {/* Tab 1: Email Scanner */}
      {activeSubTab === 'email' && (
        <div className="panel">
          <h3>⬡ PHISHING PAYLOAD DESTRUCTOR</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 12 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '11px', color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk, sans-serif' }}>
                SENDER ADDRESS
                <input
                  type="text"
                  placeholder="e.g. support@netflix-update.click"
                  value={emailSender}
                  onChange={(e) => setEmailSender(e.target.value)}
                  style={{ fontFamily: 'monospace' }}
                />
              </label>
              <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '11px', color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk, sans-serif' }}>
                EMAIL SUBJECT
                <input
                  type="text"
                  placeholder="e.g. URGENT: Verify your billing information"
                  value={emailSubject}
                 onChange={(e) => setEmailSubject(e.target.value)}
                />
              </label>
            </div>
            
            <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '11px', color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk, sans-serif' }}>
              EMAIL BODY / MESSAGE HEADER TEXT
              <textarea
                rows={6}
                placeholder="Paste the email content to check for social engineering keywords or URL blocks..."
                value={emailBody}
                onChange={(e) => setEmailBody(e.target.value)}
                style={{ fontFamily: 'monospace', fontSize: '12px' }}
              />
            </label>

            <div className="log-actions" style={{ justifyContent: 'flex-start', flexWrap: 'wrap' }}>
              <button className="btn-outline" onClick={() => handleLoadEmailSample('phishing')}>LOAD PHISHING SAMPLE</button>
              <button className="btn-outline" onClick={() => handleLoadEmailSample('clean')}>LOAD ADVISORY SAMPLE</button>
              <button className="btn-primary" onClick={handleEmailScan} disabled={loading} style={{ marginLeft: 'auto', width: 'auto' }}>
                {loading ? 'ANALYZING EMAIL...' : '⬡ EXECUTE EMAIL ANALYSIS'}
              </button>
            </div>
          </div>

          {emailResult && (
            <div style={{ marginTop: 24 }}>
              <h3>⬡ EMAIL ANALYSIS REPORT</h3>
              
              <div className="stat-grid stat-grid-4" style={{ marginTop: 12 }}>
                {[
                  { label: 'THREAT INDEX', value: `${emailResult.summary.threatScore}/100`, color: getScoreColor(emailResult.summary.threatScore) },
                  { label: 'STATUS', value: emailResult.summary.status, color: getScoreColor(emailResult.summary.threatScore) },
                  { label: 'MATCHED TAGS', value: emailResult.tags.length || 'NONE', color: 'var(--accent-cyan)' },
                  { label: 'LINKS EXTRACTED', value: emailResult.links.length, color: 'var(--text)' },
                ].map(({ label, value, color }) => (
                  <div key={label} className="stat-card">
                    <div className="stat-label">{label}</div>
                    <div className="stat-value" style={{ color }}>{value}</div>
                  </div>
                ))}
              </div>

              {/* Tags classified */}
              {emailResult.tags.length > 0 && (
                <div style={{ marginTop: 14 }}>
                  <div style={{ fontSize: '10px', color: 'var(--text-faint)', letterSpacing: '0.1em', marginBottom: 6 }}>CLASSIFIED RISK INDICATORS</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {emailResult.tags.map(tag => (
                      <span key={tag} style={{
                        fontSize: '9px', padding: '3px 8px', borderRadius: '3px',
                        border: '1px solid var(--accent-orange)', color: 'var(--accent-orange)', background: 'rgba(255,170,0,0.08)',
                        fontFamily: 'monospace'
                      }}>{tag}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* Findings */}
              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: '10px', color: 'var(--text-faint)', letterSpacing: '0.1em', marginBottom: 8 }}>DETAILED PHISHING HEURISTIC FINDINGS</div>
                {emailResult.findings.length === 0 ? (
                  <div className="hud-empty-state" style={{ padding: '20px' }}>✓ NO SOCIAL ENGINEERING TRIGGERS DETECTED</div>
                ) : (
                  <div className="table-wrap">
                    <table className="data-table">
                      <thead>
                        <tr><th>INDICATOR TYPE</th><th>SEVERITY</th><th>DETAIL DESCRIPTION</th></tr>
                      </thead>
                      <tbody>
                        {emailResult.findings.map((f, i) => (
                          <tr key={i}>
                            <td style={{ fontWeight: 700 }}>{f.type}</td>
                            <td><SeverityBadge severity={f.severity} /></td>
                            <td style={{ fontSize: '12px', color: 'var(--text-dim)' }}>{f.detail}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div style={{ marginTop: 20 }}>
                <button className="btn-primary" onClick={() => handleAIExplain('email', emailResult)} disabled={aiLoading} style={{ width: 'auto' }}>
                  {aiLoading ? '◈ COMPUTING AI MITIGATION...' : '⬡ MITIGATE PHISHING WITH SENTINEL AI'}
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Link Guard */}
      {activeSubTab === 'link' && (
        <div className="panel">
          <h3>⬡ URL / DOMAIN THREAT AUDITOR</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 12 }}>
            <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '11px', color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk, sans-serif' }}>
              TARGET LINK / REDIRECTION URL
              <input
                type="text"
                placeholder="e.g. http://paypal-verification-update.xyz/signin"
                value={linkInput}
                onChange={(e) => setLinkInput(e.target.value)}
                style={{ fontFamily: 'monospace' }}
              />
            </label>

            <div className="log-actions" style={{ justifyContent: 'flex-start', flexWrap: 'wrap' }}>
              <button className="btn-outline" onClick={() => handleLoadLinkSample(LINK_SAMPLES.spoofed)}>SPOOFED DOMAIN</button>
              <button className="btn-outline" onClick={() => handleLoadLinkSample(LINK_SAMPLES.ipBased)}>IP-BASED HOST</button>
              <button className="btn-outline" onClick={() => handleLoadLinkSample(LINK_SAMPLES.shortener)}>SHORTENER LINK</button>
              <button className="btn-outline" onClick={() => handleLoadLinkSample(LINK_SAMPLES.clean)}>CLEAN LINK</button>
              <button className="btn-primary" onClick={handleLinkScan} disabled={loading} style={{ marginLeft: 'auto', width: 'auto' }}>
                {loading ? 'SCANNING LINK...' : '⬡ AUDIT RESOURCE SAFEGUARD'}
              </button>
            </div>
          </div>

          {linkResult && (
            <div style={{ marginTop: 24 }}>
              <h3>⬡ LINK DIAGNOSTICS REPORT</h3>
              
              <div className="stat-grid stat-grid-4" style={{ marginTop: 12 }}>
                {[
                  { label: 'URL HOSTNAME', value: linkResult.host, color: 'var(--text)' },
                  { label: 'THREAT INDEX', value: `${linkResult.summary.threatScore}/100`, color: getScoreColor(linkResult.summary.threatScore) },
                  { label: 'STATUS STATUS', value: linkResult.summary.status, color: getScoreColor(linkResult.summary.threatScore) },
                  { label: 'HEURISTICS FLAGS', value: linkResult.findings.length, color: linkResult.findings.length > 0 ? 'var(--accent-orange)' : 'var(--accent-green)' },
                ].map(({ label, value, color }) => (
                  <div key={label} className="stat-card">
                    <div className="stat-label">{label}</div>
                    <div className="stat-value" style={{ color, fontSize: '15px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{value}</div>
                  </div>
                ))}
              </div>

              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: '10px', color: 'var(--text-faint)', letterSpacing: '0.1em', marginBottom: 8 }}>REPUTATION AUDIT RESULTS</div>
                {linkResult.findings.length === 0 ? (
                  <div className="hud-empty-state" style={{ padding: '20px' }}>✓ DOMAIN REPUTATION IS NOMINAL</div>
                ) : (
                  <div className="table-wrap">
                    <table className="data-table">
                      <thead>
                        <tr><th>THREAT PATTERN</th><th>SEVERITY</th><th>DESCRIPTION</th></tr>
                      </thead>
                      <tbody>
                        {linkResult.findings.map((f, i) => (
                          <tr key={i}>
                            <td style={{ fontWeight: 700 }}>{f.type}</td>
                            <td><SeverityBadge severity={f.severity} /></td>
                            <td style={{ fontSize: '12px', color: 'var(--text-dim)' }}>{f.detail}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div style={{ marginTop: 20 }}>
                <button className="btn-primary" onClick={() => handleAIExplain('link', linkResult)} disabled={aiLoading} style={{ width: 'auto' }}>
                  {aiLoading ? '◈ COMPUTING AI MITIGATION...' : '⬡ MITIGATE DOMAIN WITH SENTINEL AI'}
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Virus Scanner */}
      {activeSubTab === 'virus' && (
        <div className="panel">
          <h3>⬡ MALWARE BINARY ANALYSIS SANDBOX</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 12 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 12 }}>
              <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '11px', color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk, sans-serif' }}>
                FILENAME
                <input
                  type="text"
                  placeholder="e.g. invoice.pdf.exe"
                  value={fileName}
                  onChange={(e) => setFileName(e.target.value)}
                  style={{ fontFamily: 'monospace' }}
                />
              </label>
              <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '11px', color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk, sans-serif' }}>
                FILE SIZE (BYTES)
                <input
                  type="number"
                  placeholder="e.g. 24576"
                  value={fileSize}
                  onChange={(e) => setFileSize(e.target.value)}
                  style={{ fontFamily: 'monospace' }}
                />
              </label>
            </div>

            <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '11px', color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk, sans-serif' }}>
              INTEGRITY HASH (SHA-256 / MD5)
              <input
                type="text"
                placeholder="Paste cryptographic file signature hash..."
                value={fileHash}
                onChange={(e) => setFileHash(e.target.value)}
                style={{ fontFamily: 'monospace' }}
              />
            </label>

            <label style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: '11px', color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk, sans-serif' }}>
              RAW CONTENT / HEADER STRINGS (SIMULATED)
              <input
                type="text"
                placeholder="Optional text block contained in file (e.g., EICAR test code)..."
                value={fileContent}
                onChange={(e) => setFileContent(e.target.value)}
                style={{ fontFamily: 'monospace' }}
              />
            </label>

            <div className="log-actions" style={{ justifyContent: 'flex-start', flexWrap: 'wrap' }}>
              <button className="btn-outline" onClick={() => handleLoadFileSample('eicar')}>EICAR VIRUS TEST</button>
              <button className="btn-outline" onClick={() => handleLoadFileSample('wannacry')}>WANNACRY HASH</button>
              <button className="btn-outline" onClick={() => handleLoadFileSample('doubleExt')}>DOUBLE EXTENSION</button>
              <button className="btn-outline" onClick={() => handleLoadFileSample('clean')}>CLEAN FILE</button>
              <button className="btn-primary" onClick={handleFileScan} disabled={loading} style={{ marginLeft: 'auto', width: 'auto' }}>
                {loading ? 'SANDBOX RUNNING...' : '⬡ UPLOAD & SCAN FILE'}
              </button>
            </div>
          </div>

          {/* Sandbox Running Progress Logs */}
          {scanLogs.length > 0 && (
            <div style={{ marginTop: 20, padding: '12px', background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: '6px' }}>
              <div style={{ fontSize: '10px', color: 'var(--text-faint)', letterSpacing: '0.1em', marginBottom: 6, fontFamily: 'Space Grotesk' }}>SANDBOX CONSOLE LOGS</div>
              <div style={{ fontFamily: 'monospace', fontSize: '11px', color: 'var(--text-dim)', lineHeight: '1.5em', display: 'flex', flexDirection: 'column', gap: 2 }}>
                {scanLogs.map((log, idx) => (
                  <div key={idx}>{log}</div>
                ))}
              </div>
            </div>
          )}

          {fileResult && !loading && (
            <div style={{ marginTop: 24 }}>
              <h3>⬡ MALWARE DEFENSE SNAPSHOT</h3>
              
              <div className="stat-grid stat-grid-4" style={{ marginTop: 12 }}>
                {[
                  { label: 'THREAT SCORE', value: `${fileResult.summary.threatScore}/100`, color: getScoreColor(fileResult.summary.threatScore) },
                  { label: 'POSTURE STATUS', value: fileResult.summary.status, color: getScoreColor(fileResult.summary.threatScore) },
                  { label: 'MALWARE SIGNATURE', value: fileResult.detectedMalwareName || 'NONE MATCHED', color: fileResult.detectedMalwareName ? 'var(--accent-red)' : 'var(--accent-green)' },
                  { label: 'HEURISTICS TRIGGERED', value: fileResult.findings.length, color: 'var(--accent-cyan)' },
                ].map(({ label, value, color }) => (
                  <div key={label} className="stat-card">
                    <div className="stat-label">{label}</div>
                    <div className="stat-value" style={{ color, fontSize: '15px' }}>{value}</div>
                  </div>
                ))}
              </div>

              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: '10px', color: 'var(--text-faint)', letterSpacing: '0.1em', marginBottom: 8 }}>STATIC SANDBOX ANALYSIS FINDINGS</div>
                {fileResult.findings.length === 0 ? (
                  <div className="hud-empty-state" style={{ padding: '20px' }}>✓ NO THREAT SIGNATURES IDENTIFIED IN FILE</div>
                ) : (
                  <div className="table-wrap">
                    <table className="data-table">
                      <thead>
                        <tr><th>DETECTION VECTOR</th><th>SEVERITY</th><th>MITIGATION DIRECTIVE</th></tr>
                      </thead>
                      <tbody>
                        {fileResult.findings.map((f, i) => (
                          <tr key={i}>
                            <td style={{ fontWeight: 700 }}>{f.type}</td>
                            <td><SeverityBadge severity={f.severity} /></td>
                            <td style={{ fontSize: '12px', color: 'var(--text-dim)' }}>{f.detail}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div style={{ marginTop: 20 }}>
                <button className="btn-primary" onClick={() => handleAIExplain('file', fileResult)} disabled={aiLoading} style={{ width: 'auto' }}>
                  {aiLoading ? '◈ COMPUTING AI MITIGATION...' : '⬡ MITIGATE MALWARE WITH SENTINEL AI'}
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Shared AI Report Box */}
      {aiExplanation && (
        <div className="ai-mitigation-box" style={{ marginTop: 24 }}>
          <h3>⬡ AI ASSISTANT COUNSEL REPORT</h3>
          <div className="ai-report-body">{renderMarkdown(aiExplanation)}</div>
        </div>
      )}
    </div>
  );
}
