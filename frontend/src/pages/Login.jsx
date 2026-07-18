import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const { login, loginMFA } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // 2FA/MFA state
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaType, setMfaType] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [localMfaCode, setLocalMfaCode] = useState('');

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (mfaRequired) {
        await loginMFA(email, mfaCode);
        navigate('/');
      } else {
        const res = await login(email, password);
        if (res && res.mfaRequired) {
          setMfaRequired(true);
          setMfaType(res.mfaType);
          if (res.code) {
            setLocalMfaCode(res.code);
          }
        } else {
          navigate('/');
        }
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Authentication failure. Check credentials and retry.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-split-container">
      {/* Visual Cyberpunk Banner Side */}
      <div className="auth-visual-side">
        <h1 className="auth-visual-title">CYBER SENTINEL</h1>
        <p className="auth-visual-text">
          Advanced Threat Intelligence & Neural Network Security Operations Command Center. Continuous system diagnostics and WAF mitigation sandboxing.
        </p>
      </div>

      {/* Login Credentials Form Side */}
      <div className="auth-form-side">
        <div className="auth-card">
          <div className="brand auth-brand">
            <span className="brand-mark">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ filter: 'drop-shadow(0 0 8px var(--accent-cyan-dim))' }}>
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </span>
            <span className="brand-name" style={{ fontSize: '20px', letterSpacing: '0.05em', textShadow: '0 0 8px var(--accent-cyan-dim)' }}>
              {mfaRequired ? 'MFA SECURITY CLEARANCE' : 'SECURE COMMAND GATE'}
            </span>
          </div>
          <p className="auth-subtitle" style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '24px' }}>
            {mfaRequired ? `Identity key verification required via verified ${mfaType}` : 'Verify credentials to link host session'}
          </p>

          <form onSubmit={handleSubmit} className="auth-form">
            {!mfaRequired ? (
              <>
                <label>
                  OPERATOR ID (EMAIL)
                  <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required placeholder="analyst@sentinel.local" />
                </label>
                <label>
                  ACCESS PASSCODE
                  <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required placeholder="••••••••" />
                </label>
              </>
            ) : (
              <>
                <label>
                  ENTER 6-DIGIT MFA SECURITY CODE
                  <input 
                    type="text" 
                    value={mfaCode} 
                    onChange={(e) => setMfaCode(e.target.value)} 
                    required 
                    maxLength={6}
                    pattern="[0-9]*"
                    style={{ letterSpacing: '0.2em', textAlign: 'center', fontFamily: 'JetBrains Mono, monospace', fontSize: '16px' }}
                    placeholder="000000"
                  />
                </label>

                {localMfaCode && (
                  <div style={{
                    background: 'var(--surface)',
                    border: '1px dashed var(--border)',
                    borderRadius: '6px',
                    padding: '8px 12px',
                    marginBottom: '16px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    fontFamily: 'Space Grotesk, monospace',
                    fontSize: '11px',
                    marginTop: '12px'
                  }}>
                    <span style={{ color: 'var(--text-dim)' }}>LOCAL TEST MFA BYPASS KEY:</span>
                    <span style={{ color: 'var(--accent-orange)', fontWeight: 700 }}>{localMfaCode}</span>
                    <button 
                      type="button" 
                      onClick={() => setMfaCode(localMfaCode)}
                      style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', fontSize: '10px', cursor: 'pointer', fontWeight: 700 }}
                    >
                      [Auto Fill]
                    </button>
                  </div>
                )}
              </>
            )}

            {error && <div className="form-error">{error}</div>}

            <button type="submit" className="btn-primary" disabled={loading} style={{ padding: '12px', fontSize: '14px', fontWeight: '700', letterSpacing: '0.05em' }}>
              {loading ? 'AUTHORIZING...' : mfaRequired ? 'CONFIRM ACCESS' : 'INITIALIZE LOGIN'}
            </button>
          </form>

          {!mfaRequired ? (
            <p className="auth-switch">
              Deploy new operator card? <Link to="/register">Register account</Link>
            </p>
          ) : (
            <p className="auth-switch">
              Want to try login again? <button type="button" onClick={() => { setMfaRequired(false); setMfaCode(''); setLocalMfaCode(''); }} style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', fontSize: '11px', cursor: 'pointer', textDecoration: 'underline' }}>Go back</button>
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
