import { useState, useRef, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

// ── Top country dialing codes ───────────────────────────────────────────────
const COUNTRIES = [
  { code: 'IN', name: 'India',                dial: '+91',  flag: '🇮🇳' },
  { code: 'US', name: 'United States',         dial: '+1',   flag: '🇺🇸' },
  { code: 'GB', name: 'United Kingdom',        dial: '+44',  flag: '🇬🇧' },
  { code: 'AU', name: 'Australia',             dial: '+61',  flag: '🇦🇺' },
  { code: 'CA', name: 'Canada',                dial: '+1',   flag: '🇨🇦' },
  { code: 'DE', name: 'Germany',               dial: '+49',  flag: '🇩🇪' },
  { code: 'FR', name: 'France',                dial: '+33',  flag: '🇫🇷' },
  { code: 'JP', name: 'Japan',                 dial: '+81',  flag: '🇯🇵' },
  { code: 'SG', name: 'Singapore',             dial: '+65',  flag: '🇸🇬' },
  { code: 'AE', name: 'UAE',                   dial: '+971', flag: '🇦🇪' },
  { code: 'SA', name: 'Saudi Arabia',          dial: '+966', flag: '🇸🇦' },
  { code: 'BR', name: 'Brazil',                dial: '+55',  flag: '🇧🇷' },
  { code: 'ZA', name: 'South Africa',          dial: '+27',  flag: '🇿🇦' },
];

function CountrySelector({ selected, onChange }) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const dropRef = useRef(null);
  const searchRef = useRef(null);

  const filtered = COUNTRIES.filter(c =>
    c.name.toLowerCase().includes(search.toLowerCase()) ||
    c.dial.includes(search) ||
    c.code.toLowerCase().includes(search.toLowerCase())
  );

  useEffect(() => {
    function handleClick(e) {
      if (dropRef.current && !dropRef.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  useEffect(() => {
    if (open) setTimeout(() => searchRef.current?.focus(), 50);
    else setSearch('');
  }, [open]);

  return (
    <div ref={dropRef} style={{ position: 'relative', flexShrink: 0 }}>
      <button
        type="button"
        onClick={() => setOpen(p => !p)}
        style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '10px 10px 10px 12px',
          background: 'var(--surface)',
          border: `1px solid ${open ? 'var(--accent-cyan)' : 'var(--border)'}`,
          borderRadius: '6px 0 0 6px',
          borderRight: 'none',
          cursor: 'pointer', color: 'var(--text)',
          fontSize: 13, fontFamily: 'inherit',
          minWidth: 100, whiteSpace: 'nowrap',
        }}
      >
        <span style={{ fontSize: 16 }}>{selected.flag}</span>
        <span style={{ color: 'var(--accent-cyan)', fontWeight: 700, fontFamily: 'Space Grotesk', fontSize: 12 }}>
          {selected.dial}
        </span>
        <span style={{ color: 'var(--text-faint)', fontSize: 10, marginLeft: 2 }}>▼</span>
      </button>

      {open && (
        <div style={{
          position: 'absolute', top: '100%', left: 0, zIndex: 9999,
          width: 250, marginTop: 4,
          background: 'var(--surface)',
          border: '1px solid var(--accent-cyan)',
          borderRadius: 8,
          boxShadow: '0 12px 40px rgba(0,0,0,0.6)',
          overflow: 'hidden',
        }}>
          <div style={{ padding: '8px 10px', borderBottom: '1px solid var(--border)' }}>
            <input
              ref={searchRef}
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search country..."
              style={{
                width: '100%', padding: '6px 8px',
                background: 'rgba(0,212,255,0.06)',
                border: '1px solid rgba(0,212,255,0.25)',
                borderRadius: 4, color: 'var(--text)',
                fontSize: 12, outline: 'none',
              }}
            />
          </div>
          <div style={{ maxHeight: 180, overflowY: 'auto' }}>
            {filtered.map(c => (
              <button
                key={c.code}
                type="button"
                onClick={() => { onChange(c); setOpen(false); }}
                style={{
                  width: '100%', display: 'flex', alignItems: 'center', gap: 8,
                  padding: '8px 12px', background: 'none',
                  border: 'none', cursor: 'pointer', textAlign: 'left',
                  borderBottom: '1px solid rgba(255,255,255,0.04)',
                }}
              >
                <span>{c.flag}</span>
                <span style={{ flex: 1, color: 'var(--text)', fontSize: 12 }}>{c.name}</span>
                <span style={{ color: 'var(--accent-cyan)', fontSize: 11, fontWeight: 700 }}>{c.dial}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function ForgotPassword() {
  const { forgotPassword } = useAuth();
  const navigate = useNavigate();

  const [method, setMethod] = useState('phone'); // 'phone' | 'email'
  const [email, setEmail] = useState('');
  const [phoneNumber, setPhoneNumber] = useState('');
  const [country, setCountry] = useState(COUNTRIES[0]); // Default: India +91
  const [statusMsg, setStatusMsg] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const fullPhone = phoneNumber.trim() ? `${country.dial}${phoneNumber.trim()}` : '';

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setStatusMsg('');
    setLoading(true);

    try {
      const payload = method === 'email' 
        ? { method: 'email', email: email.trim() }
        : { method: 'phone', phone: fullPhone };

      const res = await forgotPassword(payload);

      if (method === 'email') {
        setStatusMsg(res.message || 'Password reset authorization link has been dispatched to your email.');
      } else {
        setStatusMsg(res.message || 'Single-use OTP dispatched to your registered mobile number.');
        // Redirect to Reset page to enter the OTP and new password
        setTimeout(() => {
          navigate(`/reset-password?method=phone&email=${encodeURIComponent(res.email || '')}&phone=${encodeURIComponent(fullPhone)}`);
        }, 1200);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Unable to process recovery request. Please verify inputs and retry.');
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
          Credential Recovery Protocols &amp; Cryptographic Identity Verification. Secure single-use token and SMS OTP channels.
        </p>
      </div>

      {/* Form Side */}
      <div className="auth-form-side">
        <div className="auth-card">
          <div className="brand auth-brand">
            <span className="brand-mark">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ filter: 'drop-shadow(0 0 8px var(--accent-cyan-dim))' }}>
                <path d="M21 2l-2 2m-1.5 1.5L14 9a5 5 0 10-2.5 7.5L20 8l-2-2 3-4z"/>
              </svg>
            </span>
            <span className="brand-name" style={{ fontSize: '20px', letterSpacing: '0.05em', textShadow: '0 0 8px var(--accent-cyan-dim)' }}>
              PASSCODE RECOVERY
            </span>
          </div>
          <p className="auth-subtitle" style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '20px' }}>
            Choose authorization recovery channel
          </p>

          {/* Recovery Channel Selector Tabs */}
          <div style={{
            display: 'flex',
            background: 'rgba(0, 0, 0, 0.4)',
            padding: '4px',
            borderRadius: '8px',
            border: '1px solid var(--border)',
            marginBottom: '20px',
            gap: '4px'
          }}>
            <button
              type="button"
              onClick={() => { setMethod('phone'); setError(''); setStatusMsg(''); }}
              style={{
                flex: 1,
                padding: '9px 12px',
                background: method === 'phone' ? 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(0,255,136,0.1))' : 'transparent',
                border: method === 'phone' ? '1px solid var(--accent-cyan)' : '1px solid transparent',
                borderRadius: '6px',
                color: method === 'phone' ? 'var(--accent-cyan)' : 'var(--text-dim)',
                fontFamily: 'Space Grotesk, sans-serif',
                fontWeight: 700,
                fontSize: '12px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '6px',
                transition: 'all 0.2s'
              }}
            >
              <span>📱</span> Mobile OTP (+91)
            </button>
            <button
              type="button"
              onClick={() => { setMethod('email'); setError(''); setStatusMsg(''); }}
              style={{
                flex: 1,
                padding: '9px 12px',
                background: method === 'email' ? 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(0,255,136,0.1))' : 'transparent',
                border: method === 'email' ? '1px solid var(--accent-cyan)' : '1px solid transparent',
                borderRadius: '6px',
                color: method === 'email' ? 'var(--accent-cyan)' : 'var(--text-dim)',
                fontFamily: 'Space Grotesk, sans-serif',
                fontWeight: 700,
                fontSize: '12px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '6px',
                transition: 'all 0.2s'
              }}
            >
              <span>📧</span> Email Reset Link
            </button>
          </div>

          <form onSubmit={handleSubmit} className="auth-form">
            {method === 'phone' ? (
              <label>
                REGISTERED MOBILE NUMBER
                <div style={{ display: 'flex', marginTop: '6px' }}>
                  <CountrySelector selected={country} onChange={setCountry} />
                  <input
                    type="tel"
                    value={phoneNumber}
                    onChange={e => setPhoneNumber(e.target.value.replace(/\D/g, ''))}
                    placeholder="Enter registered mobile"
                    required
                    maxLength={15}
                    style={{
                      flex: 1,
                      borderRadius: '0 6px 6px 0',
                      borderLeft: 'none',
                      marginTop: 0,
                    }}
                  />
                </div>
                {phoneNumber.trim() && (
                  <div style={{ marginTop: '5px', fontSize: '10px', color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk' }}>
                    Target: <strong>{fullPhone}</strong>
                  </div>
                )}
              </label>
            ) : (
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
            )}

            {error && <div className="form-error">{error}</div>}
            
            {statusMsg && (
              <div style={{
                background: 'rgba(0, 255, 136, 0.08)',
                border: '1px solid rgba(0, 255, 136, 0.3)',
                borderRadius: '6px',
                padding: '10px 12px',
                color: 'var(--accent-green)',
                fontSize: '12px',
                fontFamily: 'Space Grotesk, sans-serif',
                marginBottom: '16px'
              }}>
                ✓ {statusMsg}
              </div>
            )}

            <button
              type="submit"
              className="btn-primary"
              disabled={loading}
              style={{ padding: '12px', fontSize: '14px', fontWeight: '700', letterSpacing: '0.05em' }}
            >
              {loading ? 'TRANSMITTING REQUEST...' : method === 'phone' ? 'SEND RESET OTP TO MOBILE' : 'TRANSMIT RESET LINK'}
            </button>
          </form>

          <p className="auth-switch">
            Remembered passcode? <Link to="/login">Sign in</Link>
          </p>
        </div>
      </div>
    </div>
  );
}
