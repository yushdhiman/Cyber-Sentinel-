import { useState, useEffect } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function ResetPassword() {
  const { resetPassword } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const queryToken = searchParams.get('token') || '';
  const queryMethod = searchParams.get('method') || (queryToken ? 'email' : 'phone');
  const queryEmail = searchParams.get('email') || '';
  const queryPhone = searchParams.get('phone') || '';

  const [method, setMethod] = useState(queryMethod);
  const [token, setToken] = useState(queryToken);
  const [email, setEmail] = useState(queryEmail);
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (queryToken) {
      setMethod('email');
      setToken(queryToken);
    }
  }, [queryToken]);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');

    if (newPassword !== confirmPassword) {
      return setError('Passcodes do not match. Verify and re-enter.');
    }
    if (newPassword.length < 8) {
      return setError('Passcode must be at least 8 characters in length.');
    }

    setLoading(true);
    try {
      const payload = method === 'email'
        ? { method: 'email', token: token.trim(), newPassword }
        : { method: 'phone', email: email.trim(), otp: otp.trim(), newPassword };

      await resetPassword(payload);
      setSuccess(true);
    } catch (err) {
      setError(err.response?.data?.error || 'Password reset failed. Check OTP/token and retry.');
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
          Host Authorization Overwrite. Zero-trust passcode rotation protocol.
        </p>
      </div>

      {/* Form Side */}
      <div className="auth-form-side">
        <div className="auth-card">
          <div className="brand auth-brand">
            <span className="brand-mark">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ filter: 'drop-shadow(0 0 8px var(--accent-cyan-dim))' }}>
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </span>
            <span className="brand-name" style={{ fontSize: '20px', letterSpacing: '0.05em', textShadow: '0 0 8px var(--accent-cyan-dim)' }}>
              OVERWRITE PASSCODE
            </span>
          </div>
          <p className="auth-subtitle" style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '24px' }}>
            {success ? 'PASSCODE RE-ENCRYPTED SUCCESSFULLY' : method === 'phone' ? 'VERIFY MOBILE OTP & SET NEW PASSCODE' : 'SET NEW ACCOUNT PASSCODE'}
          </p>

          {success ? (
            <div>
              <div style={{
                background: 'rgba(0, 255, 136, 0.08)',
                border: '1px solid rgba(0, 255, 136, 0.3)',
                borderRadius: '8px',
                padding: '20px',
                textAlign: 'center',
                marginBottom: '24px'
              }}>
                <div style={{ fontSize: '32px', marginBottom: '8px' }}>🛡️</div>
                <div style={{ color: 'var(--accent-green)', fontWeight: 700, fontFamily: 'Space Grotesk', fontSize: '15px', marginBottom: '6px' }}>
                  SECURITY CLEARANCE RESTORED
                </div>
                <p style={{ color: 'var(--text-dim)', fontSize: '12px', margin: 0 }}>
                  Your access passcode has been securely overwritten. You can now authenticate with your new credentials.
                </p>
              </div>

              <button
                type="button"
                onClick={() => navigate('/login')}
                className="btn-primary"
                style={{ padding: '12px', width: '100%', fontSize: '14px', fontWeight: '700', letterSpacing: '0.05em' }}
              >
                PROCEED TO LOGIN GATE
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="auth-form">
              {method === 'phone' ? (
                <>
                  <label>
                    OPERATOR ID (EMAIL)
                    <input
                      type="email"
                      value={email}
                      onChange={e => setEmail(e.target.value)}
                      required
                      placeholder="analyst@sentinel.local"
                    />
                  </label>

                  <label>
                    ENTER 6-DIGIT MOBILE OTP {queryPhone && <span style={{ color: 'var(--accent-cyan)', fontSize: '10px' }}>({queryPhone})</span>}
                    <input
                      type="text"
                      value={otp}
                      onChange={e => setOtp(e.target.value.replace(/\D/g, ''))}
                      required
                      maxLength={6}
                      pattern="[0-9]*"
                      style={{ letterSpacing: '0.35em', textAlign: 'center', fontFamily: 'JetBrains Mono, monospace', fontSize: '18px', fontWeight: 700, padding: '10px' }}
                      placeholder="000000"
                    />
                  </label>
                </>
              ) : (
                !queryToken && (
                  <label>
                    SECURITY RESET TOKEN
                    <input
                      type="text"
                      value={token}
                      onChange={e => setToken(e.target.value)}
                      required
                      placeholder="Paste token from email link"
                    />
                  </label>
                )
              )}

              <label>
                NEW ACCESS PASSCODE
                <div style={{ position: 'relative', marginTop: '6px' }}>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={newPassword}
                    onChange={e => setNewPassword(e.target.value)}
                    required
                    minLength={8}
                    placeholder="At least 8 characters"
                    style={{ paddingRight: '40px', marginTop: 0 }}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(p => !p)}
                    style={{
                      position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
                      background: 'none', border: 'none', cursor: 'pointer',
                      color: 'var(--text-faint)', fontSize: 14, padding: 0
                    }}
                  >
                    {showPassword ? '🙈' : '👁️'}
                  </button>
                </div>
              </label>

              <label>
                CONFIRM NEW ACCESS PASSCODE
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)}
                  required
                  minLength={8}
                  placeholder="Re-enter passcode"
                />
              </label>

              {error && <div className="form-error">{error}</div>}

              <button
                type="submit"
                className="btn-primary"
                disabled={loading}
                style={{ padding: '12px', fontSize: '14px', fontWeight: '700', letterSpacing: '0.05em' }}
              >
                {loading ? 'ENCRYPTING NEW PASSCODE...' : 'SAVE & RESTORE ACCESS'}
              </button>
            </form>
          )}

          <p className="auth-switch">
            Return to security terminal? <Link to="/login">Sign in</Link>
          </p>
        </div>
      </div>
    </div>
  );
}
