import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await register(name, email, password, phone);
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
          Advanced Threat Intelligence & Neural Network Security Operations Command Center. Continuous system diagnostics and WAF mitigation sandboxing.
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
            <label>
              OPERATOR USERNAME
              <input value={name} onChange={(e) => setName(e.target.value)} required placeholder="e.g. Operator Alpha" />
            </label>
            <label>
              OPERATOR ID (EMAIL)
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required placeholder="you@sentinel.local" />
            </label>
            <label>
              OPERATOR PHONE NUMBER (OPTIONAL)
              <input type="tel" value={phone} onChange={(e) => setPhone(e.target.value)} placeholder="e.g. +15550000000" />
            </label>
            <label>
              ACCESS PASSCODE
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} placeholder="At least 8 characters" />
            </label>

            {error && <div className="form-error">{error}</div>}

            <button type="submit" className="btn-primary" disabled={loading} style={{ padding: '12px', fontSize: '14px', fontWeight: '700', letterSpacing: '0.05em' }}>
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
