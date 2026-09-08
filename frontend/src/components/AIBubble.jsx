import { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import client from '../api/client';
import { useRealTime } from '../context/RealTimeContext';

// Page-contextual suggestions
const PAGE_CONTEXT = {
  '/dashboard': {
    label: 'Dashboard',
    icon: '📊',
    suggestions: [
      'What is my current threat score?',
      'Are there any critical alerts right now?',
      'Summarize my system health',
    ],
  },
  '/threat-intel': {
    label: 'Threat Intel',
    icon: '📡',
    suggestions: [
      'What malware families are active right now?',
      'Check the top IOCs from ThreatFox',
      'Correlate attack feed with threat intelligence',
    ],
  },
  '/vuln-scanner': {
    label: 'Vuln Scanner',
    icon: '🔍',
    suggestions: [
      'Run a vulnerability scan now',
      'Show me critical CVEs on my system',
      'What is my current risk score?',
    ],
  },
  '/logs': {
    label: 'Log Analyzer',
    icon: '📋',
    suggestions: [
      'Analyze the last log scan for threats',
      'What attack patterns were found?',
      'Classify the most critical log events',
    ],
  },
  '/sandbox': {
    label: 'Sandbox',
    icon: '⚗️',
    suggestions: [
      'Run an SQL injection test',
      'Simulate an XSS attack and check my WAF',
      'Test command injection protection',
    ],
  },
  '/protection': {
    label: 'Protection',
    icon: '🛡️',
    suggestions: [
      'Scan a suspicious URL for me',
      'Check if an email is a phishing attempt',
      'Review my last protection scan',
    ],
  },
  '/assistant': {
    label: 'AI Assistant',
    icon: '🤖',
    suggestions: [
      'Generate a full incident report',
      'Block suspicious IPs on my network',
      'Run a complete security assessment',
    ],
  },
};

const DEFAULT_SESSION = `bubble-${Date.now()}`;

export default function AIBubble() {
  const location = useLocation();
  const navigate = useNavigate();
  const { systemMetrics } = useRealTime();

  const [open, setOpen] = useState(false);
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(false);
  const [sessionId] = useState(DEFAULT_SESSION);
  const [pulse, setPulse] = useState(false);

  const bottomRef = useRef(null);
  const inputRef = useRef(null);

  const pageCtx = PAGE_CONTEXT[location.pathname] || {
    label: 'Sentinel',
    icon: '🤖',
    suggestions: ['What is my threat score?', 'Run a quick scan', 'Show attack feed'],
  };

  // Pulse the bubble on high threat
  useEffect(() => {
    if (systemMetrics?.threatScore > 60) {
      setPulse(true);
      const t = setTimeout(() => setPulse(false), 4000);
      return () => clearTimeout(t);
    }
  }, [systemMetrics?.threatScore]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  useEffect(() => {
    if (open && inputRef.current) {
      setTimeout(() => inputRef.current?.focus(), 150);
    }
  }, [open]);

  // Initialize with a context-aware greeting when first opened
  useEffect(() => {
    if (open && messages.length === 0) {
      const threatInfo = systemMetrics
        ? ` Threat score: **${systemMetrics.threatScore}/100** (${systemMetrics.riskLevel}).`
        : '';
      setMessages([{
        role: 'bot',
        text: `**Sentinel AI** — contextual assistant for **${pageCtx.label}**.${threatInfo}\n\nHow can I help you? Try one of the quick suggestions below or ask me anything.`,
      }]);
    }
  }, [open]);

  const send = useCallback(async (text) => {
    const trimmed = text?.trim();
    if (!trimmed || loading) return;

    setMessages(m => [...m, { role: 'user', text: trimmed }]);
    setInput('');
    setLoading(true);

    try {
      const { data } = await client.post('/chatbot/message', {
        message: `[Context: User is on the ${pageCtx.label} page] ${trimmed}`,
        sessionId,
      });
      setMessages(m => [...m, {
        role: 'bot',
        text: data.reply,
        toolsUsed: data.toolsUsed || [],
      }]);
    } catch {
      setMessages(m => [...m, {
        role: 'bot',
        text: '⚠️ Connection error. Check backend.',
        isError: true,
      }]);
    } finally {
      setLoading(false);
    }
  }, [loading, sessionId, pageCtx.label]);

  const handleKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(input); }
  };

  const openFullAssistant = () => {
    setOpen(false);
    navigate('/assistant');
  };

  // Simple inline markdown renderer for bubble
  const renderText = (text) => {
    if (!text) return null;
    return text.split('\n').map((line, i) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('## ') || trimmed.startsWith('### ')) {
        const level = trimmed.startsWith('## ') ? 3 : 4;
        const content = trimmed.replace(/^#+\s/, '');
        return <div key={i} style={{ fontWeight: 700, color: 'var(--accent-cyan)', marginTop: 6, marginBottom: 2, fontSize: level === 3 ? 11 : 10.5 }}>{content}</div>;
      }
      if (trimmed.startsWith('- ') || trimmed.startsWith('• ')) {
        return <div key={i} style={{ color: 'var(--text-dim)', fontSize: 11, marginLeft: 8, marginBottom: 1 }}>▸ {trimmed.slice(2)}</div>;
      }
      if (!trimmed) return <div key={i} style={{ height: 4 }} />;
      // Bold inline
      const parts = trimmed.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
      return (
        <div key={i} style={{ color: 'var(--text-dim)', fontSize: 11, lineHeight: 1.6, marginBottom: 2 }}>
          {parts.map((p, j) => {
            if (p.startsWith('**') && p.endsWith('**')) return <strong key={j} style={{ color: 'var(--text)', fontWeight: 700 }}>{p.slice(2, -2)}</strong>;
            if (p.startsWith('`') && p.endsWith('`')) return <code key={j} style={{ background: 'rgba(0,212,255,0.12)', color: 'var(--accent-cyan)', borderRadius: 3, padding: '1px 4px', fontSize: 10, fontFamily: 'monospace' }}>{p.slice(1, -1)}</code>;
            return p;
          })}
        </div>
      );
    });
  };

  return (
    <>
      {/* ── Floating Bubble Button ─────────────────────────────────────── */}
      <button
        id="ai-bubble-trigger"
        onClick={() => setOpen(o => !o)}
        style={{
          position: 'fixed',
          bottom: 28,
          right: 28,
          width: 56,
          height: 56,
          borderRadius: '50%',
          background: open
            ? 'linear-gradient(135deg, rgba(0,212,255,0.3), rgba(0,255,136,0.2))'
            : 'linear-gradient(135deg, #00d4ff22, #00ff8822)',
          border: `2px solid ${pulse ? 'var(--accent-red)' : open ? 'var(--accent-cyan)' : 'rgba(0,212,255,0.5)'}`,
          boxShadow: pulse
            ? '0 0 20px rgba(255,70,96,0.6), 0 4px 20px rgba(0,0,0,0.4)'
            : open
              ? '0 0 20px rgba(0,212,255,0.4), 0 4px 20px rgba(0,0,0,0.4)'
              : '0 0 12px rgba(0,212,255,0.2), 0 4px 16px rgba(0,0,0,0.4)',
          cursor: 'pointer',
          zIndex: 1000,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: 22,
          transition: 'all 0.25s ease',
          animation: pulse ? 'pulse 0.8s ease-in-out infinite alternate' : 'none',
        }}
        title={open ? 'Close AI Assistant' : 'Open Sentinel AI'}
      >
        {open ? '✕' : '🤖'}
      </button>

      {/* ── Threat badge on bubble ──────────────────────────────────────── */}
      {!open && systemMetrics?.threatScore > 0 && (
        <div style={{
          position: 'fixed',
          bottom: 70,
          right: 24,
          background: systemMetrics.threatScore > 60 ? 'var(--accent-red)' : systemMetrics.threatScore > 30 ? 'var(--accent-orange)' : 'var(--accent-green)',
          color: '#fff',
          borderRadius: 10,
          fontSize: 9,
          fontWeight: 700,
          padding: '2px 5px',
          zIndex: 1001,
          fontFamily: 'Space Grotesk',
          letterSpacing: '0.05em',
          pointerEvents: 'none',
        }}>
          {systemMetrics.threatScore}
        </div>
      )}

      {/* ── Chat Panel ─────────────────────────────────────────────────── */}
      {open && (
        <div
          id="ai-bubble-panel"
          style={{
            position: 'fixed',
            bottom: 96,
            right: 28,
            width: 360,
            maxHeight: 520,
            borderRadius: 16,
            background: 'var(--bg)',
            border: '1px solid rgba(0,212,255,0.25)',
            boxShadow: '0 24px 60px rgba(0,0,0,0.6), 0 0 30px rgba(0,212,255,0.08)',
            zIndex: 999,
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            backdropFilter: 'blur(20px)',
            animation: 'slideUpFade 0.25s ease',
          }}
        >
          {/* Header */}
          <div style={{
            padding: '10px 14px',
            borderBottom: '1px solid var(--border)',
            background: 'linear-gradient(90deg, rgba(0,212,255,0.06), rgba(0,255,136,0.03))',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--accent-green)', boxShadow: '0 0 6px var(--accent-green)', animation: 'pulse 2s infinite' }} />
              <span style={{ fontFamily: 'Space Grotesk', fontWeight: 700, fontSize: 11, color: 'var(--accent-cyan)', letterSpacing: '0.1em' }}>
                SENTINEL AI
              </span>
              <span style={{
                fontSize: 9, padding: '1px 6px', borderRadius: 4,
                background: 'rgba(0,212,255,0.1)', color: 'var(--accent-cyan)',
                border: '1px solid rgba(0,212,255,0.3)', fontFamily: 'Space Grotesk',
              }}>
                {pageCtx.icon} {pageCtx.label}
              </span>
            </div>
            <button
              onClick={openFullAssistant}
              style={{
                background: 'none', cursor: 'pointer',
                fontSize: 9, color: 'var(--text-faint)', fontFamily: 'Space Grotesk',
                letterSpacing: '0.08em', padding: '2px 6px',
                borderRadius: 4, border: '1px solid var(--border)',
              }}
              title="Open full AI Assistant page"
            >
              EXPAND ↗
            </button>
          </div>

          {/* Messages */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {messages.map((m, i) => (
              <div key={i} style={{ display: 'flex', flexDirection: 'column', alignItems: m.role === 'user' ? 'flex-end' : 'flex-start' }}>
                <div style={{
                  maxWidth: '90%',
                  padding: '8px 12px',
                  borderRadius: m.role === 'user' ? '12px 12px 2px 12px' : '2px 12px 12px 12px',
                  background: m.role === 'user'
                    ? 'linear-gradient(135deg, rgba(0,212,255,0.18), rgba(0,212,255,0.08))'
                    : m.isError ? 'rgba(255,70,96,0.1)' : 'var(--surface)',
                  border: `1px solid ${m.role === 'user' ? 'rgba(0,212,255,0.3)' : m.isError ? 'rgba(255,70,96,0.3)' : 'var(--border)'}`,
                  width: m.role === 'bot' ? '100%' : undefined,
                }}>
                  {m.role === 'bot' ? renderText(m.text) : (
                    <span style={{ fontSize: 12, color: 'var(--text)' }}>{m.text}</span>
                  )}
                  {m.toolsUsed?.length > 0 && (
                    <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap', marginTop: 5 }}>
                      {m.toolsUsed.map((t, j) => (
                        <span key={j} style={{ fontSize: 8, padding: '1px 5px', borderRadius: 3, background: 'rgba(0,212,255,0.1)', color: 'var(--accent-cyan)', border: '1px solid rgba(0,212,255,0.3)', fontFamily: 'Space Grotesk' }}>
                          🔧 {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}

            {loading && (
              <div style={{ display: 'flex', gap: 5, alignItems: 'center', padding: '8px 0' }}>
                {[0, 1, 2].map(j => (
                  <span key={j} style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-cyan)', opacity: 0.7, animation: `pulse ${0.5 + j * 0.2}s ease-in-out infinite alternate` }} />
                ))}
                <span style={{ fontSize: 10, color: 'var(--text-faint)', fontFamily: 'Space Grotesk' }}>Thinking...</span>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          {/* Quick Suggestions */}
          {messages.length <= 1 && !loading && (
            <div style={{ padding: '6px 10px', borderTop: '1px solid var(--border)', display: 'flex', gap: 5, flexWrap: 'wrap' }}>
              {pageCtx.suggestions.map((s, i) => (
                <button
                  key={i}
                  onClick={() => send(s)}
                  style={{
                    fontSize: 9, padding: '4px 8px', borderRadius: 5,
                    background: 'rgba(0,212,255,0.08)', color: 'var(--accent-cyan)',
                    border: '1px solid rgba(0,212,255,0.25)', cursor: 'pointer',
                    fontFamily: 'Space Grotesk', textAlign: 'left', lineHeight: 1.4,
                    transition: 'all 0.15s',
                  }}
                  onMouseEnter={e => e.target.style.background = 'rgba(0,212,255,0.18)'}
                  onMouseLeave={e => e.target.style.background = 'rgba(0,212,255,0.08)'}
                >
                  {s}
                </button>
              ))}
            </div>
          )}

          {/* Input */}
          <div style={{ padding: '8px 10px', borderTop: '1px solid var(--border)' }}>
            <form onSubmit={e => { e.preventDefault(); send(input); }} style={{ display: 'flex', gap: 6 }}>
              <input
                ref={inputRef}
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={handleKey}
                placeholder="Ask anything..."
                disabled={loading}
                style={{
                  flex: 1, padding: '7px 10px',
                  background: 'var(--surface)', border: '1px solid var(--border)',
                  borderRadius: 6, color: 'var(--text)', fontSize: 11, fontFamily: 'inherit',
                  outline: 'none', transition: 'border-color 0.2s',
                }}
                onFocus={e => e.target.style.borderColor = 'var(--accent-cyan)'}
                onBlur={e => e.target.style.borderColor = 'var(--border)'}
              />
              <button
                type="submit"
                disabled={loading || !input.trim()}
                style={{
                  padding: '7px 12px', borderRadius: 6, border: 'none',
                  background: loading || !input.trim() ? 'rgba(0,212,255,0.1)' : 'var(--accent-cyan)',
                  color: loading || !input.trim() ? 'var(--text-faint)' : '#000',
                  cursor: loading || !input.trim() ? 'not-allowed' : 'pointer',
                  fontSize: 12, fontWeight: 700, transition: 'all 0.2s',
                }}
              >
                {loading ? '⟳' : '▷'}
              </button>
            </form>
          </div>
        </div>
      )}

      <style>{`
        @keyframes slideUpFade {
          from { opacity: 0; transform: translateY(12px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </>
  );
}
