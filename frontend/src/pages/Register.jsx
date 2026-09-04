import { useState, useRef, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

// ── Full country dialing code list ──────────────────────────────────────────
const COUNTRIES = [
  { code: 'IN', name: 'India',                dial: '+91',  flag: '🇮🇳' },
  { code: 'US', name: 'United States',         dial: '+1',   flag: '🇺🇸' },
  { code: 'GB', name: 'United Kingdom',        dial: '+44',  flag: '🇬🇧' },
  { code: 'AU', name: 'Australia',             dial: '+61',  flag: '🇦🇺' },
  { code: 'CA', name: 'Canada',                dial: '+1',   flag: '🇨🇦' },
  { code: 'DE', name: 'Germany',               dial: '+49',  flag: '🇩🇪' },
  { code: 'FR', name: 'France',                dial: '+33',  flag: '🇫🇷' },
  { code: 'JP', name: 'Japan',                 dial: '+81',  flag: '🇯🇵' },
  { code: 'CN', name: 'China',                 dial: '+86',  flag: '🇨🇳' },
  { code: 'BR', name: 'Brazil',                dial: '+55',  flag: '🇧🇷' },
  { code: 'RU', name: 'Russia',                dial: '+7',   flag: '🇷🇺' },
  { code: 'MX', name: 'Mexico',                dial: '+52',  flag: '🇲🇽' },
  { code: 'KR', name: 'South Korea',           dial: '+82',  flag: '🇰🇷' },
  { code: 'ZA', name: 'South Africa',          dial: '+27',  flag: '🇿🇦' },
  { code: 'SG', name: 'Singapore',             dial: '+65',  flag: '🇸🇬' },
  { code: 'AE', name: 'UAE',                   dial: '+971', flag: '🇦🇪' },
  { code: 'SA', name: 'Saudi Arabia',          dial: '+966', flag: '🇸🇦' },
  { code: 'NG', name: 'Nigeria',               dial: '+234', flag: '🇳🇬' },
  { code: 'EG', name: 'Egypt',                 dial: '+20',  flag: '🇪🇬' },
  { code: 'PK', name: 'Pakistan',              dial: '+92',  flag: '🇵🇰' },
  { code: 'BD', name: 'Bangladesh',            dial: '+880', flag: '🇧🇩' },
  { code: 'ID', name: 'Indonesia',             dial: '+62',  flag: '🇮🇩' },
  { code: 'PH', name: 'Philippines',           dial: '+63',  flag: '🇵🇭' },
  { code: 'VN', name: 'Vietnam',               dial: '+84',  flag: '🇻🇳' },
  { code: 'TH', name: 'Thailand',              dial: '+66',  flag: '🇹🇭' },
  { code: 'MY', name: 'Malaysia',              dial: '+60',  flag: '🇲🇾' },
  { code: 'NZ', name: 'New Zealand',           dial: '+64',  flag: '🇳🇿' },
  { code: 'IT', name: 'Italy',                 dial: '+39',  flag: '🇮🇹' },
  { code: 'ES', name: 'Spain',                 dial: '+34',  flag: '🇪🇸' },
  { code: 'NL', name: 'Netherlands',           dial: '+31',  flag: '🇳🇱' },
  { code: 'PL', name: 'Poland',                dial: '+48',  flag: '🇵🇱' },
  { code: 'SE', name: 'Sweden',                dial: '+46',  flag: '🇸🇪' },
  { code: 'NO', name: 'Norway',                dial: '+47',  flag: '🇳🇴' },
  { code: 'DK', name: 'Denmark',               dial: '+45',  flag: '🇩🇰' },
  { code: 'FI', name: 'Finland',               dial: '+358', flag: '🇫🇮' },
  { code: 'CH', name: 'Switzerland',           dial: '+41',  flag: '🇨🇭' },
  { code: 'AT', name: 'Austria',               dial: '+43',  flag: '🇦🇹' },
  { code: 'BE', name: 'Belgium',               dial: '+32',  flag: '🇧🇪' },
  { code: 'PT', name: 'Portugal',              dial: '+351', flag: '🇵🇹' },
  { code: 'GR', name: 'Greece',               dial: '+30',  flag: '🇬🇷' },
  { code: 'CZ', name: 'Czech Republic',        dial: '+420', flag: '🇨🇿' },
  { code: 'HU', name: 'Hungary',               dial: '+36',  flag: '🇭🇺' },
  { code: 'RO', name: 'Romania',               dial: '+40',  flag: '🇷🇴' },
  { code: 'UA', name: 'Ukraine',               dial: '+380', flag: '🇺🇦' },
  { code: 'TR', name: 'Turkey',                dial: '+90',  flag: '🇹🇷' },
  { code: 'IL', name: 'Israel',                dial: '+972', flag: '🇮🇱' },
  { code: 'AR', name: 'Argentina',             dial: '+54',  flag: '🇦🇷' },
  { code: 'CL', name: 'Chile',                 dial: '+56',  flag: '🇨🇱' },
  { code: 'CO', name: 'Colombia',              dial: '+57',  flag: '🇨🇴' },
  { code: 'PE', name: 'Peru',                  dial: '+51',  flag: '🇵🇪' },
  { code: 'KE', name: 'Kenya',                 dial: '+254', flag: '🇰🇪' },
  { code: 'GH', name: 'Ghana',                 dial: '+233', flag: '🇬🇭' },
  { code: 'TZ', name: 'Tanzania',              dial: '+255', flag: '🇹🇿' },
  { code: 'ET', name: 'Ethiopia',              dial: '+251', flag: '🇪🇹' },
  { code: 'MA', name: 'Morocco',               dial: '+212', flag: '🇲🇦' },
  { code: 'LK', name: 'Sri Lanka',             dial: '+94',  flag: '🇱🇰' },
  { code: 'NP', name: 'Nepal',                 dial: '+977', flag: '🇳🇵' },
  { code: 'MM', name: 'Myanmar',               dial: '+95',  flag: '🇲🇲' },
  { code: 'KH', name: 'Cambodia',              dial: '+855', flag: '🇰🇭' },
  { code: 'HK', name: 'Hong Kong',             dial: '+852', flag: '🇭🇰' },
  { code: 'TW', name: 'Taiwan',                dial: '+886', flag: '🇹🇼' },
  { code: 'IR', name: 'Iran',                  dial: '+98',  flag: '🇮🇷' },
  { code: 'IQ', name: 'Iraq',                  dial: '+964', flag: '🇮🇶' },
  { code: 'AF', name: 'Afghanistan',           dial: '+93',  flag: '🇦🇫' },
  { code: 'KZ', name: 'Kazakhstan',            dial: '+7',   flag: '🇰🇿' },
  { code: 'UZ', name: 'Uzbekistan',            dial: '+998', flag: '🇺🇿' },
  { code: 'QA', name: 'Qatar',                 dial: '+974', flag: '🇶🇦' },
  { code: 'KW', name: 'Kuwait',                dial: '+965', flag: '🇰🇼' },
  { code: 'BH', name: 'Bahrain',               dial: '+973', flag: '🇧🇭' },
  { code: 'OM', name: 'Oman',                  dial: '+968', flag: '🇴🇲' },
  { code: 'JO', name: 'Jordan',                dial: '+962', flag: '🇯🇴' },
  { code: 'LB', name: 'Lebanon',               dial: '+961', flag: '🇱🇧' },
  { code: 'JM', name: 'Jamaica',               dial: '+1876',flag: '🇯🇲' },
  { code: 'CU', name: 'Cuba',                  dial: '+53',  flag: '🇨🇺' },
  { code: 'DZ', name: 'Algeria',               dial: '+213', flag: '🇩🇿' },
  { code: 'TN', name: 'Tunisia',               dial: '+216', flag: '🇹🇳' },
  { code: 'LY', name: 'Libya',                 dial: '+218', flag: '🇱🇾' },
  { code: 'SD', name: 'Sudan',                 dial: '+249', flag: '🇸🇩' },
  { code: 'UG', name: 'Uganda',                dial: '+256', flag: '🇺🇬' },
  { code: 'MG', name: 'Madagascar',            dial: '+261', flag: '🇲🇬' },
];

// ── Country Selector Component ────────────────────────────────────────────────
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

  // Close on outside click
  useEffect(() => {
    function handleClick(e) {
      if (dropRef.current && !dropRef.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  // Focus search when opened
  useEffect(() => {
    if (open) setTimeout(() => searchRef.current?.focus(), 50);
    else setSearch('');
  }, [open]);

  return (
    <div ref={dropRef} style={{ position: 'relative', flexShrink: 0 }}>
      {/* Trigger button */}
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
          minWidth: 110, whiteSpace: 'nowrap',
          transition: 'border-color 0.2s',
          boxShadow: open ? '0 0 0 1px var(--accent-cyan)' : 'none',
        }}
      >
        <span style={{ fontSize: 16 }}>{selected.flag}</span>
        <span style={{ color: 'var(--accent-cyan)', fontWeight: 700, fontFamily: 'Space Grotesk', letterSpacing: '0.03em', fontSize: 12 }}>
          {selected.dial}
        </span>
        <span style={{ color: 'var(--text-faint)', fontSize: 10, marginLeft: 2, transition: 'transform 0.2s', display: 'inline-block', transform: open ? 'rotate(180deg)' : 'none' }}>▼</span>
      </button>

      {/* Dropdown */}
      {open && (
        <div style={{
          position: 'absolute', top: '100%', left: 0, zIndex: 9999,
          width: 280, marginTop: 4,
          background: 'var(--surface)',
          border: '1px solid var(--accent-cyan)',
          borderRadius: 8,
          boxShadow: '0 12px 40px rgba(0,0,0,0.6), 0 0 20px rgba(0,212,255,0.1)',
          overflow: 'hidden',
          animation: 'fadeInDown 0.15s ease',
        }}>
          {/* Search */}
          <div style={{ padding: '8px 10px', borderBottom: '1px solid var(--border)' }}>
            <input
              ref={searchRef}
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="🔍 Search country or code..."
              style={{
                width: '100%', padding: '7px 10px',
                background: 'rgba(0,212,255,0.06)',
                border: '1px solid rgba(0,212,255,0.25)',
                borderRadius: 5, color: 'var(--text)',
                fontSize: 12, fontFamily: 'inherit', outline: 'none',
              }}
            />
          </div>

          {/* List */}
          <div style={{ maxHeight: 220, overflowY: 'auto' }}>
            {filtered.length === 0 ? (
              <div style={{ padding: '12px 14px', color: 'var(--text-faint)', fontSize: 12, textAlign: 'center' }}>No results</div>
            ) : filtered.map(c => (
              <button
                key={c.code}
                type="button"
                onClick={() => { onChange(c); setOpen(false); }}
                style={{
                  width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                  padding: '9px 14px',
                  border: 'none', cursor: 'pointer', textAlign: 'left',
                  borderBottom: '1px solid rgba(255,255,255,0.04)',
                  transition: 'background 0.15s',
                  background: selected.code === c.code ? 'rgba(0,212,255,0.1)' : 'transparent',
                }}
                onMouseEnter={e => e.currentTarget.style.background = 'rgba(0,212,255,0.08)'}
                onMouseLeave={e => e.currentTarget.style.background = selected.code === c.code ? 'rgba(0,212,255,0.1)' : 'none'}
              >
                <span style={{ fontSize: 18, lineHeight: 1 }}>{c.flag}</span>
                <span style={{ flex: 1, color: 'var(--text)', fontSize: 12, fontFamily: 'inherit' }}>{c.name}</span>
                <span style={{ color: 'var(--accent-cyan)', fontSize: 11, fontWeight: 700, fontFamily: 'Space Grotesk' }}>{c.dial}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main Register Component ───────────────────────────────────────────────────
export default function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [phoneNumber, setPhoneNumber] = useState('');
  const [country, setCountry] = useState(COUNTRIES[0]); // Default: India (+91)
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Build full phone: +91-9876543210 or empty if not entered
  const fullPhone = phoneNumber.trim() ? `${country.dial}${phoneNumber.trim()}` : '';

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');

    // Optional phone validation
    if (phoneNumber.trim() && !/^\d{4,15}$/.test(phoneNumber.trim())) {
      return setError('Enter a valid phone number (digits only, 4–15 chars)');
    }

    setLoading(true);
    try {
      await register(name, email, password, fullPhone);
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.error || 'Registration failed. Review details and retry.');
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
          Advanced Threat Intelligence &amp; Neural Network Security Operations Command Center. Continuous system diagnostics and WAF mitigation sandboxing.
        </p>
      </div>

      {/* Register operator form side */}
      <div className="auth-form-side">
        <div className="auth-card">
          <div className="brand auth-brand">
            <span className="brand-mark">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ filter: 'drop-shadow(0 0 8px var(--accent-cyan-dim))' }}>
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </span>
            <span className="brand-name" style={{ fontSize: '20px', letterSpacing: '0.05em', textShadow: '0 0 8px var(--accent-cyan-dim)' }}>
              DEPLOY NEW NODE
            </span>
          </div>
          <p className="auth-subtitle" style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '24px' }}>
            Register new operator key profile
          </p>

          <form onSubmit={handleSubmit} className="auth-form">
            {/* Username */}
            <label>
              OPERATOR USERNAME
              <input
                value={name}
                onChange={e => setName(e.target.value)}
                required
                placeholder="e.g. Operator Alpha"
              />
            </label>

            {/* Email */}
            <label>
              OPERATOR ID (EMAIL)
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                placeholder="you@sentinel.local"
              />
            </label>

            {/* Phone with country selector */}
            <label>
              <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span>REGISTERED MOBILE</span>
                <span style={{ fontSize: 10, color: 'var(--text-faint)', fontWeight: 400, letterSpacing: 0 }}>Optional</span>
              </span>
              <div style={{ display: 'flex', marginTop: 6 }}>
                <CountrySelector selected={country} onChange={setCountry} />
                <input
                  type="tel"
                  value={phoneNumber}
                  onChange={e => setPhoneNumber(e.target.value.replace(/\D/g, ''))}
                  placeholder="Mobile number"
                  maxLength={15}
                  style={{
                    flex: 1,
                    borderRadius: '0 6px 6px 0',
                    borderLeft: 'none',
                    marginTop: 0,
                  }}
                />
              </div>
              {/* Preview */}
              {phoneNumber.trim() && (
                <div style={{ marginTop: 5, fontSize: 10, color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk', letterSpacing: '0.06em' }}>
                  ✓ {country.flag} {country.name} · Full number: <strong>{fullPhone}</strong>
                </div>
              )}
            </label>

            {/* Password */}
            <label>
              ACCESS PASSCODE
              <div style={{ position: 'relative', marginTop: 6 }}>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  minLength={8}
                  placeholder="At least 8 characters"
                  style={{ paddingRight: 42, marginTop: 0 }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(p => !p)}
                  style={{
                    position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: 'var(--text-faint)', fontSize: 14, padding: 0, lineHeight: 1,
                  }}
                  title={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? '🙈' : '👁️'}
                </button>
              </div>
              {/* Strength bar */}
              {password.length > 0 && (
                <div style={{ marginTop: 5 }}>
                  <div style={{ display: 'flex', gap: 3 }}>
                    {[1,2,3,4].map(i => {
                      const strength = password.length >= 12 && /[A-Z]/.test(password) && /[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password) ? 4
                        : password.length >= 10 && /[A-Z]/.test(password) && /[0-9]/.test(password) ? 3
                        : password.length >= 8 ? 2
                        : 1;
                      const colors = ['', '#ff4560', '#f0c040', '#00d4ff', '#00ff88'];
                      return (
                        <div key={i} style={{
                          flex: 1, height: 3, borderRadius: 2,
                          background: i <= strength ? colors[strength] : 'var(--border)',
                          transition: 'background 0.3s',
                        }} />
                      );
                    })}
                  </div>
                  <div style={{ fontSize: 9, color: 'var(--text-faint)', marginTop: 3, fontFamily: 'Space Grotesk' }}>
                    {password.length < 8 ? '⚠ Too short' : password.length >= 12 && /[A-Z]/.test(password) && /[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password) ? '🟢 Strong' : password.length >= 10 && /[A-Z]/.test(password) && /[0-9]/.test(password) ? '🔵 Good' : '🟡 Fair — add uppercase, numbers & symbols'}
                  </div>
                </div>
              )}
            </label>

            {error && <div className="form-error">{error}</div>}

            <button
              type="submit"
              className="btn-primary"
              disabled={loading}
              style={{ padding: '12px', fontSize: '14px', fontWeight: '700', letterSpacing: '0.05em' }}
            >
              {loading ? 'CREATING IDENTITY...' : 'INITIALIZE PROFILE'}
            </button>
          </form>

          <p className="auth-switch">
            Operator profile exists? <Link to="/login">Sign in</Link>
          </p>
        </div>
      </div>
    </div>
  );
}
