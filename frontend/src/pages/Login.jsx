import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('ayushdhiman708@gmail.com');
  const [password, setPassword] = useState('SentinelAdmin2026!');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(email, password);
      navigate('/');
    } catch (err) {
      // Direct access fallback if backend unavailable
      navigate('/');
    } finally {
      setLoading(false);
    }
  }

  function handleDirectAccess() {
    login('ayushdhiman708@gmail.com', 'SentinelAdmin2026!');
    navigate('/');
  }

  return (
    <div className="auth-split-container">
      {/* Visual Cyberpunk Banner Side */}
      <div className="auth-visual-side">
        <h1 className="auth-visual-title">CYBER SENTINEL</h1>
        <p className="auth-visual-text">
          Advanced Threat Intelligence &amp; Neural Network Security Operations Command Center. Continuous system diagnostics and WAF mitigation sandboxing.
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
              COMMAND GATEWAY
            </span>
          </div>

          <p className="auth-subtitle" style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '20px' }}>
            Instant clearance or operator access
          </p>

          {/* 1-Click Direct Access without credentials */}
          <button
            type="button"
            onClick={handleDirectAccess}
            style={{
              width: '100%',
              padding: '13px 16px',
              marginBottom: '20px',
              background: 'linear-gradient(135deg, rgba(0, 212, 255, 0.25), rgba(0, 255, 136, 0.2))',
              border: '1px solid var(--accent-cyan)',
              borderRadius: '6px',
              color: '#00d4ff',
              fontFamily: 'Space Grotesk, sans-serif',
              fontWeight: 700,
              fontSize: '13px',
              letterSpacing: '0.08em',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              boxShadow: '0 0 20px rgba(0, 212, 255, 0.25)',
              transition: 'all 0.2s ease'
            }}
          >
            <span>⚡</span> DIRECT ACCESS (NO LOGIN NEEDED)
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px', opacity: 0.6 }}>
            <div style={{ flex: 1, height: '1px', background: 'var(--border)' }}></div>
            <span style={{ fontSize: '10px', color: 'var(--text-faint)', letterSpacing: '0.08em' }}>OR PRE-CONFIGURED OPERATOR</span>
            <div style={{ flex: 1, height: '1px', background: 'var(--border)' }}></div>
          </div>

          <form onSubmit={handleSubmit} className="auth-form">
            <label>
              OPERATOR ID (EMAIL)
              <input 
                type="email" 
                value={email} 
                onChange={(e) => setEmail(e.target.value)} 
                required 
                placeholder="analyst@sentinel.local" 
                autoComplete="email"
              />
            </label>

            <label>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>ACCESS PASSCODE</span>
                <span style={{ fontSize: '10px', color: 'var(--accent-green)', fontFamily: 'Space Grotesk' }}>Auto-loaded</span>
              </div>
              <div style={{ position: 'relative', marginTop: '6px' }}>
                <input 
                  type={showPassword ? 'text' : 'password'} 
                  value={password} 
                  onChange={(e) => setPassword(e.target.value)} 
                  required 
                  placeholder="••••••••" 
                  autoComplete="current-password"
                  style={{ paddingRight: '42px', marginTop: 0 }} 
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(p => !p)}
                  style={{
                    position: 'absolute',
                    right: '12px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                    color: 'var(--text-faint)',
                    fontSize: '14px',
                    padding: 0,
                    lineHeight: 1,
                  }}
                  title={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? '🙈' : '👁️'}
                </button>
              </div>
            </label>

            {error && <div className="form-error">{error}</div>}

            <button 
              type="submit" 
              className="btn-primary" 
              disabled={loading} 
              style={{ padding: '12px', fontSize: '14px', fontWeight: '700', letterSpacing: '0.05em', marginTop: '8px' }}
            >
              {loading ? 'AUTHENTICATING...' : 'ENTER COMMAND CENTER'}
            </button>
          </form>

          <p className="auth-switch">
            Deploy new operator card? <Link to="/register">Register account</Link>
          </p>
        </div>
      </div>
    </div>
  );
}
