import { useState, useRef, useEffect } from 'react';
import client from '../api/client';

const SUGGESTIONS = [
  'What is SQL injection?',
  'Explain Log4Shell CVE',
  'How do I defend against DDoS?',
  'What is a zero-day exploit?',
  'Explain XSS attack vectors',
  'What is Netlogon vulnerability?'
];

export default function Assistant() {
  const [messages, setMessages] = useState([
    { role: 'bot', text: "SENTINEL AI CORE — ONLINE\n\nI'm your neural security analyst. Query me on attack types, CVE exploits, defensive mitigations, or live threat classification." },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  async function send(text) {
    const trimmed = text.trim();
    if (!trimmed) return;
    setMessages((m) => [...m, { role: 'user', text: trimmed }]);
    setInput('');
    setLoading(true);
    try {
      const { data } = await client.post('/chatbot/message', { message: trimmed });
      setMessages((m) => [...m, { role: 'bot', text: data.reply }]);
    } catch {
      setMessages((m) => [...m, { role: 'bot', text: '[ERROR] Neural link disrupted. Unable to reach Sentinel AI core. Retry connection.' }]);
    } finally {
      setLoading(false);
    }
  }

  function renderMarkdown(text) {
    if (!text) return null;
    return text.split('\n').map((line, index) => {
      let trimmed = line.trim();
      if (trimmed.startsWith('###')) {
        return <h4 key={index} style={{ color: 'var(--accent-cyan)', marginTop: 10, marginBottom: 4, fontSize: '13px', letterSpacing: '0.05em', textTransform: 'uppercase' }}>{trimmed.replace('###', '').trim()}</h4>;
      }
      if (trimmed.startsWith('##')) {
        return <h3 key={index} style={{ color: 'var(--accent-cyan)', marginTop: 14, marginBottom: 6, fontSize: '14px', letterSpacing: '0.05em', textTransform: 'uppercase' }}>{trimmed.replace('##', '').trim()}</h3>;
      }
      if (trimmed.startsWith('*') || trimmed.startsWith('-')) {
        const cleanLine = trimmed.substring(1).trim();
        const parts = cleanLine.split('**');
        return (
          <li key={index} style={{ marginLeft: 16, marginBottom: 4, fontSize: '12.5px', color: 'var(--text-dim)' }}>
            {parts.map((p, i) => i % 2 === 1 ? <strong key={i} style={{ color: 'var(--text)' }}>{p}</strong> : p)}
          </li>
        );
      }
      const parts = line.split('**');
      return (
        <p key={index} style={{ marginBottom: 6, fontSize: '12.5px', color: 'var(--text-dim)', lineHeight: '1.6' }}>
          {parts.map((p, i) => i % 2 === 1 ? <strong key={i} style={{ color: 'var(--accent-cyan)' }}>{p}</strong> : p)}
        </p>
      );
    });
  }

  return (
    <div className="page">
      {/* HUD Page Header */}
      <div className="hud-page-header">
        <div className="hud-page-header-left">
          <div className="hud-page-label">NEURAL CORE · GEMINI AI</div>
          <h2 className="hud-page-title">AI SECURITY ANALYST</h2>
          <p className="hud-page-desc">
            Query the Sentinel neural network on attack types, CVE exploits, mitigation protocols, or classified threat intelligence.
          </p>
        </div>
        <div className="hud-page-header-right">
          <div className="hud-stat-badge" style={{ borderColor: 'var(--accent-green)', color: 'var(--accent-green)' }}>
            <span className="hud-pulse-dot" style={{ background: 'var(--accent-green)', display: 'inline-block', width: '6px', height: '6px', borderRadius: '50%', marginRight: '6px' }} />
            <span className="hud-stat-badge-label">AI CORE</span>
            <span className="hud-stat-badge-value" style={{ color: 'var(--accent-green)' }}>ONLINE</span>
          </div>
        </div>
      </div>

      <div className="panel chat-panel">
        {/* Chat window */}
        <div className="chat-window">
          {messages.map((m, i) => (
            <div key={i} className={`chat-bubble ${m.role}`}>
              {m.role === 'bot' && (
                <div className="chat-bot-label">
                  <span className="hud-pulse-dot" style={{ display: 'inline-block', width: '5px', height: '5px', background: 'var(--accent-green)', borderRadius: '50%', marginRight: 6 }} />
                  SENTINEL AI
                </div>
              )}
              {m.role === 'user' && (
                <div className="chat-user-label">OPERATOR INPUT</div>
              )}
              {m.role === 'bot' ? renderMarkdown(m.text) : <p style={{ margin: 0, fontSize: '13px' }}>{m.text}</p>}
            </div>
          ))}
          {loading && (
            <div className="chat-bubble bot typing">
              <div className="chat-bot-label">
                <span className="hud-pulse-dot" style={{ display: 'inline-block', width: '5px', height: '5px', background: 'var(--accent-green)', borderRadius: '50%', marginRight: 6 }} />
                SENTINEL AI
              </div>
              <div className="hud-loading" style={{ padding: '4px 0' }}>
                <span className="hud-loading-dot" />
                <span className="hud-loading-dot" />
                <span className="hud-loading-dot" />
                PROCESSING NEURAL QUERY...
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* Suggestion chips */}
        <div className="chat-suggestions">
          {SUGGESTIONS.map((s) => (
            <button key={s} className="suggestion-chip" onClick={() => send(s)}>
              ▷ {s}
            </button>
          ))}
        </div>

        {/* Input row */}
        <form
          className="chat-input-row"
          onSubmit={(e) => { e.preventDefault(); send(input); }}
        >
          <div style={{ flex: 1, position: 'relative' }}>
            <span style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--accent-cyan)', fontSize: '12px', fontFamily: 'monospace', pointerEvents: 'none' }}>▷</span>
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Enter query for Sentinel AI Core..."
              style={{ paddingLeft: '28px' }}
            />
          </div>
          <button type="submit" className="btn-primary" disabled={loading} style={{ width: 'auto', minWidth: '90px' }}>
            {loading ? '...' : 'TRANSMIT'}
          </button>
        </form>
      </div>
    </div>
  );
}
