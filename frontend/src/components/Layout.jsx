import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useState } from 'react';

const NAV_ITEMS = [
  {
    to: '/',
    label: 'Dashboard',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="7" height="9"></rect><rect x="14" y="3" width="7" height="5"></rect>
        <rect x="14" y="12" width="7" height="9"></rect><rect x="3" y="16" width="7" height="5"></rect>
      </svg>
    )
  },
  {
    to: '/log-analyzer',
    label: 'Log Analyzer',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
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
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
        <line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line>
      </svg>
    )
  },
  {
    to: '/threat-intel',
    label: 'Threat Intel',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"></path>
        <line x1="4" y1="22" x2="4" y2="15"></line>
      </svg>
    )
  },
  {
    to: '/assistant',
    label: 'AI Assistant',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
        <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
        <line x1="12" y1="22.08" x2="12" y2="12"></line>
      </svg>
    )
  },
  {
    to: '/security-tools',
    label: 'Security Tools',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
      </svg>
    )
  },
  {
    to: '/protection-center',
    label: 'Protection Center',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    )
  },
  {
    to: '/sandbox',
    label: 'Attack Sandbox',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
      </svg>
    )
  },
  {
    to: '/profile',
    label: 'Operator Profile',
    icon: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
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
    colors: ['#02050d', '#00ffff', '#ff0055', '#39ff14'],
  },
  {
    id: 'light',
    name: 'INDIGO LIGHT',
    desc: 'Electric indigo on ice white',
    colors: ['#f0f2ff', '#4f46e5', '#dc2626', '#16a34a'],
  },
];


export default function Layout({ children, theme, onToggleTheme }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [showThemePanel, setShowThemePanel] = useState(false);

  function handleLogout() {
    logout();
    navigate('/login');
  }

  const currentTheme = THEMES.find(t => t.id === theme) || THEMES[0];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        {/* Brand */}
        <div className="brand">
          <span className="brand-mark">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ filter: 'drop-shadow(0 0 6px var(--accent-cyan))' }}>
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </span>
          <div>
            <div className="brand-name" style={{ letterSpacing: '0.08em', fontSize: '15px' }}>CYBER SENTINEL</div>
            <div style={{ fontSize: '9px', color: 'var(--accent-cyan)', letterSpacing: '0.15em', opacity: 0.6, fontFamily: 'Space Grotesk, monospace' }}>THREAT OPS v2.0</div>
          </div>
        </div>

        {/* Nav */}
        <nav className="nav-list">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>

        {/* Sidebar Footer */}
        <div className="sidebar-footer">
          {/* HUD Diagnostics Widget */}
          <div className="hud-diagnostics-widget">
            <div className="hud-diag-row">
              <span>SENTINEL AI</span>
              <span style={{ color: 'var(--accent-green)', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <span className="hud-pulse-dot" style={{ display: 'inline-block', width: '6px', height: '6px', background: 'var(--accent-green)', borderRadius: '50%' }} />
                ONLINE
              </span>
            </div>
            <div className="hud-diag-row">
              <span>THREAT INDEX</span>
              <span style={{ color: 'var(--accent-cyan)', fontWeight: 'bold' }}>STABLE</span>
            </div>
            <div className="hud-diag-row">
              <span>NODE LATENCY</span>
              <span style={{ color: 'var(--accent-cyan)' }}>12 ms</span>
            </div>
            <div className="hud-diag-bar-track">
              <div className="hud-diag-bar-fill" style={{ width: '94%' }} />
            </div>
          </div>

          {/* Theme Switcher Button */}
          <button
            className="theme-switch-btn"
            onClick={() => setShowThemePanel(prev => !prev)}
          >
            <span className="theme-switch-preview">
              {currentTheme.colors.map((c, i) => (
                <span key={i} style={{ width: 10, height: 10, borderRadius: '50%', background: c, display: 'inline-block', border: '1px solid rgba(255,255,255,0.1)' }} />
              ))}
            </span>
            <span>{currentTheme.name}</span>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ marginLeft: 'auto', opacity: 0.5, transform: showThemePanel ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }}>
              <polyline points="6 9 12 15 18 9" />
            </svg>
          </button>

          {/* Expanded Theme Panel */}
          {showThemePanel && (
            <div className="theme-panel">
              <div className="theme-panel-label">SELECT DISPLAY MODE</div>
              {THEMES.map((t) => (
                <button
                  key={t.id}
                  className={`theme-option ${theme === t.id ? 'active' : ''}`}
                  onClick={() => { onToggleTheme(); setShowThemePanel(false); }}
                >
                  <div className="theme-option-swatches">
                    {t.colors.map((c, i) => (
                      <span key={i} style={{ width: 8, height: 8, borderRadius: '50%', background: c, display: 'inline-block' }} />
                    ))}
                  </div>
                  <div className="theme-option-text">
                    <span className="theme-option-name">{t.name}</span>
                    <span className="theme-option-desc">{t.desc}</span>
                  </div>
                  {theme === t.id && (
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="3">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                  )}
                </button>
              ))}
            </div>
          )}

          {/* Logout */}
          <button className="sidebar-logout-btn" onClick={handleLogout}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/>
              <line x1="21" y1="12" x2="9" y2="12"/>
            </svg>
            DISCONNECT SESSION
          </button>
        </div>
      </aside>

      {/* Main Content Column */}
      <div className="main-column">
        {/* Topbar */}
        <header className="topbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <div className="topbar-title">
              <span style={{ color: 'var(--accent-cyan)', marginRight: 8, opacity: 0.6 }}>◈</span>
              SECURITY OPERATIONS CENTER
            </div>
            {/* Live status indicator in topbar */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '10px', color: 'var(--accent-green)', fontFamily: 'Space Grotesk, monospace', letterSpacing: '0.1em', fontWeight: 700 }}>
              <span className="hud-pulse-dot" style={{ display: 'inline-block', width: '5px', height: '5px', background: 'var(--accent-green)', borderRadius: '50%' }} />
              LIVE
            </div>
          </div>
          <div className="topbar-user">
            {/* Theme indicator pill */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6, padding: '4px 10px',
              border: '1px solid var(--border)', borderRadius: '20px',
              fontSize: '10px', fontWeight: 700, letterSpacing: '0.08em',
              color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk, monospace',
              background: 'var(--surface)'
            }}>
              {currentTheme.colors.slice(1, 3).map((c, i) => (
                <span key={i} style={{ width: 6, height: 6, borderRadius: '50%', background: c, display: 'inline-block' }} />
              ))}
              {currentTheme.name}
            </div>
            <div className="user-badge" onClick={() => navigate('/profile')} style={{ cursor: 'pointer' }}>
              {user?.profilePic ? (
                <img src={user.profilePic} alt={user.name} className="user-avatar" style={{ objectFit: 'cover' }} />
              ) : (
                <span className="user-avatar">{user?.name?.[0]?.toUpperCase() || 'U'}</span>
              )}
              <span style={{ fontSize: '13px', letterSpacing: '0.03em' }}>{user?.name}</span>
            </div>
          </div>
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  );
}
