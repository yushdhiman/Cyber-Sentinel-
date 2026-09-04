import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import client from '../api/client';

export default function Login() {
  const { login, loginMFA } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // 2FA/MFA OTP state
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaType, setMfaType] = useState('phone'); // 'phone' | 'email'
  const [maskedTarget, setMaskedTarget] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [resendTimer, setResendTimer] = useState(30);
  const [canResend, setCanResend] = useState(false);
  const [resendSuccess, setResendSuccess] = useState('');

  // Resend countdown timer
  useEffect(() => {
    let timer;
    if (mfaRequired && resendTimer > 0) {
      timer = setTimeout(() => setResendTimer(t => t - 1), 1000);
    } else if (resendTimer === 0) {
      setCanResend(true);
    }
    return () => clearTimeout(timer);
  }, [mfaRequired, resendTimer]);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setResendSuccess('');
    setLoading(true);
    try {
      if (mfaRequired) {
        await loginMFA(email, mfaCode);
        navigate('/');
      } else {
        const res = await login(email, password);
        if (res && res.mfaRequired) {
          setMfaRequired(true);
          setMfaType(res.mfaType || 'phone');
          setMaskedTarget(res.maskedTarget || '');
          setResendTimer(30);
          setCanResend(false);
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

  async function handleResend() {
    if (!canResend) return;
    setError('');
    setResendSuccess('');
    try {
      await client.post('/auth/login', { email, password });
      setResendSuccess('New security OTP has been dispatched.');
      setResendTimer(30);
      setCanResend(false);
    } catch (err) {
      setError('Unable to resend OTP at this time. Please retry shortly.');
    }
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
              {!mfaRequired 
                ? 'SECURE COMMAND GATE' 
                : mfaType === 'phone' 
                  ? 'MOBILE OTP CLEARANCE' 
                  : 'EMAIL 2FA CLEARANCE'
              }
            </span>
          </div>

          <p className="auth-subtitle" style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '24px' }}>
            {!mfaRequired
              ? 'Verify credentials to link host session'
              : mfaType === 'phone'
                ? `6-Digit verification code dispatched via SMS to ${maskedTarget || 'registered mobile'}`
                : `6-Digit verification code dispatched to ${maskedTarget || 'email'}`
            }
          </p>

          <form onSubmit={handleSubmit} className="auth-form">
            {!mfaRequired ? (
              <>
                <label>
                  OPERATOR ID (EMAIL)
                  <input 
                    type="email" 
                    value={email} 
                    onChange={(e) => setEmail(e.target.value)} 
                    required 
                    placeholder="analyst@sentinel.local" 
                  />
                </label>
                <label>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span>ACCESS PASSCODE</span>
                    <Link 
                      to="/forgot-password" 
                      style={{ 
                        fontSize: '11px', 
                        color: 'var(--accent-cyan)', 
                        textDecoration: 'none',
                        fontFamily: 'Space Grotesk, sans-serif'
                      }}
                    >
                      Forgot passcode?
                    </Link>
                  </div>
                  <input 
                    type="password" 
                    value={password} 
                    onChange={(e) => setPassword(e.target.value)} 
                    required 
                    placeholder="••••••••" 
                    style={{ marginTop: '6px' }} 
                  />
                </label>
              </>
            ) : (
              <>
                <div style={{
                  background: 'rgba(0, 212, 255, 0.06)',
                  border: '1px solid rgba(0, 212, 255, 0.25)',
                  borderRadius: '6px',
                  padding: '12px 14px',
                  marginBottom: '16px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px'
                }}>
                  <span style={{ fontSize: '24px' }}>{mfaType === 'phone' ? '📱' : '✉️'}</span>
                  <div style={{ fontSize: '11px', lineHeight: 1.45 }}>
                    <div style={{ color: 'var(--accent-cyan)', fontWeight: 700, fontFamily: 'Space Grotesk', letterSpacing: '0.04em' }}>
                      {mfaType === 'phone' ? 'SECURITY OTP TRANSMITTED' : '2FA SECURITY CODE TRANSMITTED'}
                    </div>
                    <div style={{ color: 'var(--text-dim)' }}>
                      Enter the 6-digit single-use authorization code sent to <strong>{maskedTarget || (mfaType === 'phone' ? 'your mobile' : 'your email')}</strong>.
                    </div>
                  </div>
                </div>

                <label>
                  ENTER 6-DIGIT OTP
                  <input 
                    type="text" 
                    value={mfaCode} 
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))} 
                    required 
                    maxLength={6}
                    pattern="[0-9]*"
                    style={{ letterSpacing: '0.35em', textAlign: 'center', fontFamily: 'JetBrains Mono, monospace', fontSize: '20px', fontWeight: 700, padding: '12px' }}
                    placeholder="000000"
                    autoFocus
                  />
                </label>

                {resendSuccess && (
                  <div style={{ color: 'var(--accent-green)', fontSize: '11px', marginBottom: '10px', fontFamily: 'Space Grotesk' }}>
                    ✓ {resendSuccess}
                  </div>
                )}

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', fontSize: '11px', fontFamily: 'Space Grotesk' }}>
                  <span style={{ color: 'var(--text-dim)' }}>Didn't receive code?</span>
                  {canResend ? (
                    <button
                      type="button"
                      onClick={handleResend}
                      style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', cursor: 'pointer', fontWeight: 700, textDecoration: 'underline' }}
                    >
                      Resend OTP Now
                    </button>
                  ) : (
                    <span style={{ color: 'var(--text-faint)' }}>
                      Resend in {resendTimer}s
                    </span>
                  )}
                </div>
              </>
            )}

            {error && <div className="form-error">{error}</div>}

            <button 
              type="submit" 
              className="btn-primary" 
              disabled={loading || (mfaRequired && mfaCode.length < 6)} 
              style={{ padding: '12px', fontSize: '14px', fontWeight: '700', letterSpacing: '0.05em' }}
            >
              {loading ? 'AUTHENTICATING...' : mfaRequired ? 'VERIFY OTP & LOGIN' : 'INITIALIZE LOGIN'}
            </button>
          </form>

          {!mfaRequired ? (
            <p className="auth-switch">
              Deploy new operator card? <Link to="/register">Register account</Link>
            </p>
          ) : (
            <p className="auth-switch">
              Want to try credentials again? <button type="button" onClick={() => { setMfaRequired(false); setMfaCode(''); setError(''); }} style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', fontSize: '11px', cursor: 'pointer', textDecoration: 'underline' }}>Back to login</button>
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
