import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useRealTime } from '../context/RealTimeContext';
import { useState, useEffect } from 'react';

const NAV_ITEMS = [
  {
    to: '/',
    label: 'Dashboard',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="7" height="9"></rect><rect x="14" y="3" width="7" height="5"></rect>
        <rect x="14" y="12" width="7" height="9"></rect><rect x="3" y="16" width="7" height="5"></rect>
      </svg>
    )
  },
  {
    to: '/log-analyzer',
    label: 'Log Analyzer',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <line x1="8" y1="6" x2="21" y2="6"></line><line x1="8" y1="12" x2="21" y2="12"></line>
        <line x1="8" y1="18" x2="21" y2="18"></line><line x1="3" y1="6" x2="3.01" y2="6"></line>
        <line x1="3" y1="12" x2="3.01" y2="12"></line><line x1="3" y1="18" x2="3.01" y2="18"></line>
      </svg>
    )
  },
  {
    to: '/vuln-scanner',
    label: 'Vuln Scanner',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
        <line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line>
      </svg>
    )
  },
  {
    to: '/threat-intel',
    label: 'Threat Intel',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"></path>
        <line x1="4" y1="22" x2="4" y2="15"></line>
      </svg>
    )
  },
  {
    to: '/assistant',
    label: 'AI Assistant',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
        <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
        <line x1="12" y1="22.08" x2="12" y2="12"></line>
      </svg>
    ),
    badge: 'AGENT'
  },
  {
    to: '/security-tools',
    label: 'Security Tools',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
      </svg>
    )
  },
  {
    to: '/protection-center',
    label: 'Protection Center',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    )
  },
  {
    to: '/sandbox',
    label: 'Attack Sandbox',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
      </svg>
    )
  },
  {
    to: '/profile',
    label: 'Operator Profile',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
        <circle cx="12" cy="7" r="4"></circle>
      </svg>
    )
  },
];

const THEMES = [
  {
    id: 'dark',
    name: 'CYBER DARK',
    desc: 'Neon cyan on deep space black',
    colors: ['#030712', '#00d4ff', '#ff3366', '#00ff88'],
  },
  {
    id: 'light',
    name: 'INDIGO LIGHT',
    desc: 'Electric indigo on frost white',
    colors: ['#f4f7fc', '#4f46e5', '#ef4444', '#10b981'],
  },
];

export default function Layout({ children, theme, onToggleTheme }) {
  const { user, logout } = useAuth();
  const { connected, latencyMs, liveAttackCount, systemMetrics } = useRealTime();
  const navigate = useNavigate();
  const [showThemePanel, setShowThemePanel] = useState(false);
  const [timeStr, setTimeStr] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const d = new Date();
      setTimeStr(d.toLocaleTimeString('en-US', { hour12: false }));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  function handleLogout() {
    logout();
    navigate('/');
  }

  const currentTheme = THEMES.find(t => t.id === theme) || THEMES[0];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        {/* Brand */}
        <div className="brand" style={{ padding: '0 8px 24px', borderBottom: '1px solid var(--border-subtle)', marginBottom: '16px' }}>
          <span className="brand-mark" style={{
            background: 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(0,255,136,0.1))',
            padding: '8px', borderRadius: '10px', border: '1px solid rgba(0,212,255,0.4)',
            boxShadow: '0 0 16px rgba(0,212,255,0.25)', display: 'flex'
          }}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </span>
          <div>
            <div className="brand-name" style={{ letterSpacing: '0.08em', fontSize: '15px', fontWeight: 800 }}>CYBER SENTINEL</div>
            <div style={{ fontSize: '9px', color: 'var(--accent-cyan)', letterSpacing: '0.18em', fontWeight: 700, opacity: 0.85, fontFamily: 'Space Grotesk, monospace' }}>
              THREAT OPS v2.0
            </div>
          </div>
        </div>

        {/* Navigation List with Glow & Active Laser */}
        <nav className="nav-list">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
              style={({ isActive }) => ({
                position: 'relative',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '10px 14px',
                borderRadius: '8px',
                marginBottom: '3px',
                textDecoration: 'none',
                color: isActive ? 'var(--accent-cyan)' : 'var(--text-dim)',
                background: isActive ? 'linear-gradient(90deg, rgba(0,212,255,0.14), rgba(0,212,255,0.03))' : 'transparent',
                border: isActive ? '1px solid rgba(0,212,255,0.3)' : '1px solid transparent',
                fontWeight: isActive ? 700 : 500,
                boxShadow: isActive ? '0 0 16px rgba(0,212,255,0.12)' : 'none',
                transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)'
              })}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span className="nav-icon" style={{ opacity: 0.9 }}>{item.icon}</span>
                <span style={{ fontSize: '13.5px', fontFamily: 'Outfit, sans-serif' }}>{item.label}</span>
              </div>
              {item.badge && (
                <span style={{
                  fontSize: '8.5px',
                  fontFamily: 'Space Grotesk, monospace',
                  fontWeight: 800,
                  letterSpacing: '0.08em',
                  background: 'rgba(0,212,255,0.18)',
                  color: 'var(--accent-cyan)',
                  padding: '2px 5px',
                  borderRadius: '4px',
                  border: '1px solid rgba(0,212,255,0.4)',
                }}>
                  {item.badge}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Sidebar Footer HUD Telemetry */}
        <div className="sidebar-footer" style={{ marginTop: 'auto' }}>
          {/* Live Node Telemetry Widget */}
          <div style={{
            background: 'var(--surface-glass)',
            backdropFilter: 'blur(12px)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '12px 14px',
            marginBottom: '12px',
            fontFamily: 'Space Grotesk, monospace',
            fontSize: '11px',
            display: 'flex',
            flexDirection: 'column',
            gap: '6px'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: 'var(--text-faint)', fontSize: '10px' }}>REALTIME LINK</span>
              <span style={{ color: connected ? 'var(--accent-green)' : 'var(--accent-red)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '4px', fontSize: '10px' }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: connected ? 'var(--accent-green)' : 'var(--accent-red)', animation: 'blipPulse 1.5s infinite alternate' }} />
                {connected ? 'CONNECTED' : 'STANDBY'}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: 'var(--text-faint)', fontSize: '10px' }}>NODE LATENCY</span>
              <span style={{ color: 'var(--accent-cyan)', fontWeight: 700, fontSize: '10px' }}>
                {latencyMs ? `${latencyMs}ms` : '12ms'}
              </span>
            </div>
            {systemMetrics && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: 'var(--text-faint)', fontSize: '10px' }}>CPU LOAD</span>
                <span style={{ color: systemMetrics.cpuUsage > 75 ? 'var(--accent-red)' : 'var(--accent-cyan)', fontWeight: 700, fontSize: '10px' }}>
                  {systemMetrics.cpuUsage}%
                </span>
              </div>
            )}
            <div style={{ height: '3px', width: '100%', background: 'rgba(255,255,255,0.05)', borderRadius: '2px', overflow: 'hidden', marginTop: '2px' }}>
              <div style={{ height: '100%', width: `${Math.min(100, Math.max(10, systemMetrics?.cpuUsage || 28))}%`, background: 'linear-gradient(90deg, var(--accent-cyan), var(--accent-green))', transition: 'width 0.5s ease' }} />
            </div>
          </div>

          {/* Theme Switcher Button */}
          <button
            className="theme-switch-btn"
            onClick={() => setShowThemePanel(prev => !prev)}
            style={{
              width: '100%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '8px 12px',
              background: 'var(--surface-glass)',
              border: '1px solid var(--border)',
              borderRadius: '6px',
              color: 'var(--text-dim)',
              fontSize: '11px',
              fontWeight: 700,
              fontFamily: 'Space Grotesk, sans-serif',
              marginBottom: '8px',
            }}
          >
            <span style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
              {currentTheme.colors.map((c, i) => (
                <span key={i} style={{ width: 8, height: 8, borderRadius: '50%', background: c, display: 'inline-block', border: '1px solid rgba(255,255,255,0.1)' }} />
              ))}
              <span style={{ marginLeft: '6px' }}>{currentTheme.name}</span>
            </span>
            <span style={{ fontSize: '10px', opacity: 0.6 }}>▼</span>
          </button>

          {/* Expanded Theme Panel */}
          {showThemePanel && (
            <div style={{
              background: 'var(--surface-glass)',
              backdropFilter: 'blur(16px)',
              border: '1px solid var(--accent-cyan)',
              borderRadius: '8px',
              padding: '8px',
              marginBottom: '8px',
              display: 'flex',
              flexDirection: 'column',
              gap: '4px'
            }}>
              {THEMES.map((t) => (
                <button
                  key={t.id}
                  onClick={() => { onToggleTheme(); setShowThemePanel(false); }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '6px 10px',
                    borderRadius: '5px',
                    border: 'none',
                    background: theme === t.id ? 'rgba(0,212,255,0.12)' : 'transparent',
                    color: theme === t.id ? 'var(--accent-cyan)' : 'var(--text-dim)',
                    cursor: 'pointer',
                    fontSize: '11px',
                    fontFamily: 'Space Grotesk, sans-serif',
                    fontWeight: 700
                  }}
                >
                  <span>{t.name}</span>
                  {theme === t.id && <span style={{ color: 'var(--accent-cyan)' }}>✓</span>}
                </button>
              ))}
            </div>
          )}

          {/* Granted Access Status Indicator */}
          <div
            style={{
              width: '100%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '9px 12px',
              background: 'rgba(0, 255, 136, 0.08)',
              border: '1px solid rgba(0, 255, 136, 0.28)',
              borderRadius: '6px',
              color: 'var(--accent-green)',
              fontSize: '11px',
              fontWeight: 700,
              fontFamily: 'Space Grotesk, sans-serif',
              letterSpacing: '0.05em'
            }}
          >
            <span style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--accent-green)', boxShadow: '0 0 10px var(--accent-green)' }}></span>
              CLEARANCE: VERIFIED
            </span>
            <span style={{ fontSize: '10px', color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk' }}>DIRECT</span>
          </div>
        </div>
      </aside>

      {/* Main Column */}
      <div className="main-column">
        {/* Topbar HUD */}
        <header className="topbar" style={{
          height: '64px',
          padding: '0 28px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'var(--bg-elevated)',
          backdropFilter: 'blur(16px)',
          borderBottom: '1px solid var(--border)',
          position: 'sticky',
          top: 0,
          zIndex: 100,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 800, fontSize: '13px', letterSpacing: '0.08em', color: 'var(--text)', fontFamily: 'Space Grotesk, monospace' }}>
              <span style={{ color: 'var(--accent-cyan)', textShadow: '0 0 8px var(--accent-cyan)' }}>◈</span>
              SECURITY OPERATIONS CENTER
            </div>
            {/* Live UTC time */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '4px 10px', background: 'var(--surface-glass)', border: '1px solid var(--border-subtle)', borderRadius: '4px', fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent-cyan)' }}>
              <span style={{ color: 'var(--text-faint)' }}>SYS TIME:</span> {timeStr || '00:00:00'}
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            {/* Live Attack Counter in Topbar */}
            {liveAttackCount > 0 && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: '6px',
                padding: '4px 10px',
                background: 'rgba(255, 51, 102, 0.1)',
                border: '1px solid rgba(255, 51, 102, 0.4)',
                borderRadius: '20px',
                fontSize: '11px', fontWeight: 700,
                color: 'var(--accent-red)',
                fontFamily: 'Space Grotesk, monospace'
              }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-red)', animation: 'blipPulse 1s infinite alternate' }} />
                {liveAttackCount} INCIDENTS TODAY
              </div>
            )}

            {/* Operator Card */}
            <div 
              onClick={() => navigate('/profile')} 
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '4px 12px 4px 6px',
                background: 'var(--surface-glass)',
                border: '1px solid var(--border)',
                borderRadius: '24px',
                cursor: 'pointer',
                transition: 'all 0.2s ease'
              }}
            >
              {user?.profilePic ? (
                <img src={user.profilePic} alt={user.name} style={{ width: 28, height: 28, borderRadius: '50%', objectFit: 'cover', border: '1px solid var(--accent-cyan)' }} />
              ) : (
                <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'var(--accent-cyan-dim)', border: '1px solid var(--accent-cyan)', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, fontSize: '12px', fontFamily: 'Space Grotesk' }}>
                  {user?.name?.[0]?.toUpperCase() || 'A'}
                </div>
              )}
              <span style={{ fontSize: '12px', fontWeight: 700, fontFamily: 'Outfit, sans-serif', color: 'var(--text)' }}>
                {user?.name || 'Operator'}
              </span>
            </div>
          </div>
        </header>

        {/* Main Content Viewport */}
        <main className="content" style={{ padding: '24px 28px', maxWidth: '1440px', width: '100%', margin: '0 auto' }}>
          {children}
        </main>
      </div>
    </div>
  );
}
