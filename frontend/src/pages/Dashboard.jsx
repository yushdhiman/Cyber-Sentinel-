import { useState, useRef, useEffect } from 'react';
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis,
  CartesianGrid, Tooltip, BarChart, Bar,
} from 'recharts';
import { SeverityBadge } from '../components/StatCard';
import { useRealTime } from '../context/RealTimeContext';

/* ── Custom chart tooltip ── */
const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="custom-chart-tooltip">
      <div className="label">{label}</div>
      {payload.map((item, idx) => (
        <div key={idx} className="value-row">
          <span className="dot" style={{ backgroundColor: item.stroke || item.fill || 'var(--accent-cyan)' }} />
          <span>{item.name === 'attacks' ? 'Attacks' : 'Blocked'}: <strong>{item.value}</strong></span>
        </div>
      ))}
    </div>
  );
};

/* ── Live threat score ring ── */
function ThreatGauge({ score, riskLevel }) {
  const color = score >= 70 ? 'var(--accent-red)' : score >= 40 ? 'var(--accent-orange)' : score >= 20 ? '#f0c040' : 'var(--accent-green)';
  const r = 54, circ = 2 * Math.PI * r;
  const dash = circ * (score / 100), gap = circ - dash;
  return (
    <div className="threat-gauge-wrap">
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r={r} fill="none" stroke="var(--border)" strokeWidth="10" />
        <circle cx="70" cy="70" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={`${dash} ${gap}`} strokeDashoffset={circ / 4} strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 1.2s cubic-bezier(0.4,0,0.2,1)', filter: `drop-shadow(0 0 8px ${color}80)` }} />
        <text x="70" y="63" textAnchor="middle" fill="var(--text)" fontSize="28" fontWeight="700" fontFamily="Inter">{score}</text>
        <text x="70" y="82" textAnchor="middle" fill="var(--text-dim)" fontSize="11" fontFamily="Inter">/100</text>
        <text x="70" y="98" textAnchor="middle" fill={color} fontSize="10" fontWeight="600" fontFamily="Inter" letterSpacing="1">{riskLevel}</text>
      </svg>
    </div>
  );
}

/* ── Resource bar ── */
function ResourceBar({ label, value, color = 'var(--accent-cyan)', unit = '%' }) {
  const safeVal = Math.min(100, Math.max(0, value ?? 0));
  const barColor = safeVal > 85 ? 'var(--accent-red)' : safeVal > 65 ? 'var(--accent-orange)' : color;
  return (
    <div className="resource-bar-row">
      <div className="resource-bar-header">
        <span className="resource-bar-label">{label}</span>
        <span className="resource-bar-value" style={{ color: barColor }}>{safeVal}{unit}</span>
      </div>
      <div className="resource-bar-track">
        <div className="resource-bar-fill" style={{ width: `${safeVal}%`, background: barColor, transition: 'width 0.8s ease' }} />
      </div>
    </div>
  );
}

/* ── Live APM sparkline ── */
function ApmSparkline({ data }) {
  const max = Math.max(...data, 1);
  const w = 80, h = 28;
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - (v / max) * h;
    return `${x},${y}`;
  }).join(' ');
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} style={{ overflow: 'visible' }}>
      <polyline points={pts} fill="none" stroke="var(--accent-red)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/* ── Device icon ── */
function DeviceIcon({ type }) {
  const icons = {
    'Ethernet': <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" width="16" height="16"><rect x="2" y="7" width="20" height="14" rx="2" /><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16" /></svg>,
    'Wi-Fi': <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" width="16" height="16"><path d="M5 12.55a11 11 0 0 1 14.08 0" /><path d="M1.42 9a16 16 0 0 1 21.16 0" /><path d="M8.53 16.11a6 6 0 0 1 6.95 0" /><circle cx="12" cy="20" r="1" fill="currentColor" /></svg>,
    'VPN/Tunnel': <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" width="16" height="16"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>,
    'Loopback': <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" width="16" height="16"><circle cx="12" cy="12" r="3" /><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4" /></svg>,
    default: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" width="16" height="16"><rect x="2" y="2" width="20" height="8" rx="2" /><rect x="2" y="14" width="20" height="8" rx="2" /><line x1="6" y1="6" x2="6.01" y2="6" /><line x1="6" y1="18" x2="6.01" y2="18" /></svg>,
  };
  return <span className="device-icon">{icons[type] || icons.default}</span>;
}

export default function Dashboard() {
  const {
    connected, systemMetrics, attackFeed, timeline,
    linkedDevices, systemFindings, criticalAlert,
    blockedCount, attacksPerMinute,
  } = useRealTime();

  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [isFeedPaused, setIsFeedPaused] = useState(false);
  const [showRiskModal, setShowRiskModal] = useState(false);
  const [showDevicePanel, setShowDevicePanel] = useState(false);
  const [flashRow, setFlashRow] = useState(null);

  // Track last 12 apm samples for sparkline
  const apmHistory = useRef([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  useEffect(() => {
    apmHistory.current = [...apmHistory.current.slice(1), attacksPerMinute];
  }, [attacksPerMinute]);

  // Flash newest attack row
  useEffect(() => {
    if (attackFeed.length > 0 && !isFeedPaused) {
      setFlashRow(attackFeed[0].id);
      const t = setTimeout(() => setFlashRow(null), 600);
      return () => clearTimeout(t);
    }
  }, [attackFeed, isFeedPaused]);

  const metrics = systemMetrics;
  const platformName = metrics?.platform === 'win32' ? 'Windows'
    : metrics?.platform === 'darwin' ? 'macOS'
    : metrics?.platform === 'linux' ? 'Linux'
    : metrics?.platform ?? 'Unknown';

  const filteredFeed = (isFeedPaused ? attackFeed : attackFeed).filter(
    a => selectedSeverity === 'ALL' || a.severity === selectedSeverity
  );

  const externalDevices = linkedDevices.filter(d => !d.internal);

  return (
    <div className="dashboard">

      {/* Critical Alert Toast */}
      {criticalAlert && (
        <div className="critical-alert-toast">
          <span style={{ color: 'var(--accent-red)', fontSize: '16px' }}>⚠</span>
          <div>
            <strong style={{ color: 'var(--accent-red)' }}>CRITICAL: {criticalAlert.finding?.title}</strong>
            <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>{criticalAlert.finding?.detail}</div>
          </div>
          <span style={{ fontSize: '10px', color: 'var(--text-faint)', marginLeft: 'auto', fontFamily: 'monospace' }}>
            Score: {criticalAlert.threatScore}
          </span>
        </div>
      )}

      {/* System Status Banner */}
      <div className="system-status-banner">
        <div className="status-indicator">
          <span className={`pulse-dot ${!connected ? 'red' : ''}`} />
          <div>
            <div className="status-text">
              {connected ? '⚡ REAL-TIME ACTIVE' : '⚠ CONNECTING...'}
            </div>
            <div className="status-meta">
              Host: <strong>{metrics?.hostname ?? '...'}</strong>
              {metrics?.platform && <> · <strong>{platformName}</strong></>}
              {metrics?.uptimeDays != null && <> · {metrics.uptimeDays === 0 ? 'Today' : `${metrics.uptimeDays}d uptime`}</>}
              {' · '}<span style={{ color: connected ? 'var(--accent-green)' : 'var(--accent-orange)' }}>
                {connected ? 'WebSocket Connected' : 'Reconnecting...'}
              </span>
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          {/* Live APM indicator */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 12px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '6px' }}>
            <ApmSparkline data={apmHistory.current} />
            <div>
              <div style={{ fontSize: '9px', color: 'var(--text-faint)', letterSpacing: '0.1em', fontFamily: 'Space Grotesk' }}>ATTACKS/MIN</div>
              <div style={{ fontSize: '16px', fontWeight: 800, color: 'var(--accent-red)', fontFamily: 'Space Grotesk' }}>{attacksPerMinute}</div>
            </div>
          </div>
          <button className="btn-outline" onClick={() => setIsFeedPaused(p => !p)} style={{ fontSize: '11px', fontFamily: 'Space Grotesk', letterSpacing: '0.06em', fontWeight: 700 }}>
            {isFeedPaused ? '▶ RESUME FEED' : '⏸ PAUSE FEED'}
          </button>
        </div>
      </div>

      {/* Hero Banner */}
      <div className="panel" style={{ padding: 0, marginBottom: 24, height: 160, overflow: 'hidden', backgroundImage: "url('/cyber_dashboard_hero.png')", backgroundSize: 'cover', backgroundPosition: 'center', position: 'relative', borderRadius: 8, border: '1px solid var(--border)' }}>
        <div style={{ position: 'absolute', inset: 0, background: 'linear-gradient(to right, rgba(2,5,13,0.95) 40%, rgba(2,5,13,0.2))', display: 'flex', flexDirection: 'column', justifyContent: 'center', padding: 24 }}>
          <h2 style={{ color: 'var(--accent-cyan)', fontSize: 20, fontWeight: 'bold', margin: '0 0 6px', textShadow: '1px 1px 2px #000, -1px -1px 2px #000, 1px -1px 2px #000, -1px 1px 2px #000' }}>
            ⬡ REAL-TIME THREAT OPERATIONS CENTER
          </h2>
          <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)', maxWidth: 520, lineHeight: 1.5 }}>
            Zero-latency WebSocket feed. Monitoring CPU · RAM · Network · Attack vectors in real-time from your machine.
          </p>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="stat-grid">
        {/* Threat Score */}
        <div className="stat-card accent-orange clickable" onClick={() => setShowRiskModal(true)} style={{ cursor: 'pointer' }}>
          <div className="stat-label">THREAT SCORE</div>
          <div className="stat-value" style={{ color: (metrics?.threatScore ?? 0) >= 60 ? 'var(--accent-red)' : 'var(--accent-orange)' }}>
            {metrics?.threatScore ?? '—'}<span style={{ fontSize: '14px', fontWeight: 400, color: 'var(--text-faint)' }}>/100</span>
          </div>
          <div style={{ fontSize: '10px', color: 'var(--accent-orange)', fontFamily: 'Space Grotesk', letterSpacing: '0.08em', marginTop: 4 }}>
            {metrics?.riskLevel ?? 'LOADING...'} · click to expand
          </div>
        </div>

        {/* Live Attack Count */}
        <div className="stat-card accent-red clickable" onClick={() => setIsFeedPaused(p => !p)}>
          <div className="stat-label">LIVE ATTACKS (TOTAL)</div>
          <div className="stat-value" style={{ color: 'var(--accent-red)' }}>{attackFeed.length}</div>
          <div style={{ fontSize: '10px', color: 'var(--text-faint)', fontFamily: 'Space Grotesk', letterSpacing: '0.06em', marginTop: 4 }}>
            {isFeedPaused ? '⏸ PAUSED' : `${attacksPerMinute} per minute · live`}
          </div>
        </div>

        {/* Active Devices */}
        <div className="stat-card accent-cyan clickable" onClick={() => setShowDevicePanel(p => !p)}>
          <div className="stat-label">NETWORK INTERFACES</div>
          <div className="stat-value" style={{ color: 'var(--accent-cyan)' }}>{externalDevices.length || linkedDevices.length}</div>
          <div style={{ fontSize: '10px', color: 'var(--text-faint)', fontFamily: 'Space Grotesk', letterSpacing: '0.06em', marginTop: 4 }}>
            {externalDevices.length} external · {linkedDevices.filter(d => d.internal).length} loopback
          </div>
        </div>

        {/* Network Health */}
        <div className="stat-card accent-green">
          <div className="stat-label">NETWORK HEALTH</div>
          <div className="stat-value" style={{ color: 'var(--accent-green)' }}>
            {metrics ? `${Math.round(metrics.networkHealth ?? 80)}%` : '—'}
          </div>
          <div style={{ height: 3, background: 'var(--surface-2)', borderRadius: 2, marginTop: 6, overflow: 'hidden' }}>
            <div style={{ width: `${metrics?.networkHealth ?? 0}%`, height: '100%', background: 'var(--accent-green)', transition: 'width 0.8s ease' }} />
          </div>
        </div>

        {/* Blocked Today */}
        <div className="stat-card accent-green">
          <div className="stat-label">BLOCKED (SESSION)</div>
          <div className="stat-value" style={{ color: 'var(--accent-green)' }}>{blockedCount}</div>
          <div style={{ fontSize: '10px', color: 'var(--text-faint)', fontFamily: 'Space Grotesk', letterSpacing: '0.06em', marginTop: 4 }}>
            auto-blocked by WAF · live
          </div>
        </div>

        {/* CPU / RAM */}
        <div className="stat-card accent-cyan">
          <div className="stat-label">SYSTEM LOAD</div>
          <div style={{ display: 'flex', gap: 12, marginTop: 8 }}>
            <div>
              <div style={{ fontSize: '10px', color: 'var(--text-faint)', fontFamily: 'Space Grotesk' }}>CPU</div>
              <div style={{ fontSize: '20px', fontWeight: 800, color: (metrics?.cpuUsage ?? 0) > 75 ? 'var(--accent-red)' : 'var(--accent-cyan)' }}>
                {metrics?.cpuUsage ?? '—'}%
              </div>
            </div>
            <div>
              <div style={{ fontSize: '10px', color: 'var(--text-faint)', fontFamily: 'Space Grotesk' }}>RAM</div>
              <div style={{ fontSize: '20px', fontWeight: 800, color: (metrics?.memoryUsage ?? 0) > 80 ? 'var(--accent-red)' : 'var(--accent-cyan)' }}>
                {metrics?.memoryUsage ?? '—'}%
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* System Resource Bars */}
      {metrics && (
        <div className="system-resources-panel">
          <div className="resources-header">
            <div className="resources-title">⬡ Live System Resources</div>
            <span className="resources-source-tag">
              <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: connected ? 'var(--accent-green)' : 'var(--accent-red)', marginRight: 4 }} />
              WebSocket · {metrics.hostname}
            </span>
          </div>
          <div className="resources-bars">
            <ResourceBar label="CPU Usage" value={metrics.cpuUsage} color="var(--accent-cyan)" />
            <ResourceBar label="RAM Usage" value={metrics.memoryUsage} color="var(--accent-purple, #a78bfa)" />
            <ResourceBar label="Network Health" value={metrics.networkHealth} color="var(--accent-green)" />
          </div>
        </div>
      )}

      {/* Charts */}
      <div className="panel-grid">
        <section className="panel">
          <h3>⬡ ATTACK VOLUME — ROLLING 24H (LIVE)</h3>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={timeline}>
              <defs>
                <linearGradient id="attacksGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--accent-red)" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="var(--accent-red)" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--accent-green)" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="var(--accent-green)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" opacity={0.5} />
              <XAxis dataKey="hour" stroke="var(--text-dim)" fontSize={10} tickLine={false} interval={3} />
              <YAxis stroke="var(--text-dim)" fontSize={11} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="attacks" stroke="var(--accent-red)" fill="url(#attacksGrad)" strokeWidth={2.5} name="attacks" isAnimationActive={false} />
              <Area type="monotone" dataKey="blocked" stroke="var(--accent-green)" fill="url(#blockedGrad)" strokeWidth={2.5} name="blocked" isAnimationActive={false} />
            </AreaChart>
          </ResponsiveContainer>
        </section>

        <section className="panel">
          <h3>⬡ ATTACK FREQUENCY BAR (LIVE)</h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={timeline}>
              <defs>
                <linearGradient id="barGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--accent-cyan)" stopOpacity={0.9} />
                  <stop offset="100%" stopColor="var(--accent-cyan)" stopOpacity={0.15} />
                </linearGradient>
                <linearGradient id="barBlockGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--accent-green)" stopOpacity={0.9} />
                  <stop offset="100%" stopColor="var(--accent-green)" stopOpacity={0.15} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" opacity={0.5} />
              <XAxis dataKey="hour" stroke="var(--text-dim)" fontSize={10} tickLine={false} interval={3} />
              <YAxis stroke="var(--text-dim)" fontSize={11} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="attacks" fill="url(#barGrad)" radius={[4, 4, 0, 0]} name="attacks" isAnimationActive={false} />
              <Bar dataKey="blocked" fill="url(#barBlockGrad)" radius={[4, 4, 0, 0]} name="blocked" isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </section>
      </div>

      {/* Live Attack Feed */}
      <section className="panel" id="live-feed">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12, marginBottom: 16 }}>
          <h3 style={{ margin: 0, borderBottom: 'none', paddingBottom: 0 }}>
            ⬡ LIVE ATTACK FEED
            <span style={{ fontSize: '10px', color: connected ? 'var(--accent-green)' : 'var(--accent-red)', marginLeft: 10, fontFamily: 'monospace', letterSpacing: '0.06em' }}>
              {connected ? '● STREAMING' : '○ DISCONNECTED'}
            </span>
          </h3>
          <div className="filter-tabs">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
              <button key={sev} className={`filter-tab ${selectedSeverity === sev ? 'active' : ''}`} onClick={() => setSelectedSeverity(sev)}>{sev}</button>
            ))}
          </div>
        </div>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>TIME</th><th>SOURCE IP</th><th>COUNTRY</th><th>VECTOR</th><th>SEVERITY</th><th>STATUS</th>
              </tr>
            </thead>
            <tbody>
              {filteredFeed.slice(0, 25).map((a) => (
                <tr key={a.id} style={{ animation: flashRow === a.id ? 'flashRow 0.5s ease' : 'none' }}>
                  <td style={{ fontFamily: 'monospace', fontSize: '11px', color: 'var(--text-faint)' }}>{new Date(a.timestamp).toLocaleTimeString()}</td>
                  <td className="mono">{a.sourceIp}</td>
                  <td>{a.country}</td>
                  <td style={{ fontSize: '12px' }}>{a.type}</td>
                  <td><SeverityBadge severity={a.severity} /></td>
                  <td className={`status-indicator-dot ${a.blocked ? 'blocked' : 'active'}`}>{a.blocked ? '⬡ Blocked' : '◈ Monitoring'}</td>
                </tr>
              ))}
              {filteredFeed.length === 0 && (
                <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-dim)', padding: 24 }}>
                  {connected ? `No ${selectedSeverity !== 'ALL' ? selectedSeverity : ''} events yet — stream active` : 'Connecting to real-time feed...'}
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Linked Devices Panel */}
      {showDevicePanel && linkedDevices.length > 0 && (
        <section className="panel">
          <h3>⬡ LINKED NETWORK INTERFACES — LIVE</h3>
          <div className="linked-devices-grid-full">
            {linkedDevices.map((dev) => (
              <div key={dev.id} className={`linked-device-card ${dev.internal ? 'loopback' : ''}`}>
                <div className="ldc-header">
                  <DeviceIcon type={dev.type} />
                  <span className="ldc-name">{dev.name}</span>
                  <span className={`ldc-badge ${dev.internal ? 'internal' : 'external'}`}>{dev.type}</span>
                </div>
                <div className="ldc-ip">{dev.ip}</div>
                <div className="ldc-meta">
                  {dev.mac && dev.mac !== '00:00:00:00:00:00' && <span>MAC: {dev.mac}</span>}
                  {dev.cidr && <span>{dev.cidr}</span>}
                </div>
                <div className="ldc-status"><span className="status-dot-green" />Online</div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Threat Risk Modal */}
      {showRiskModal && metrics && (
        <div className="modal-overlay" onClick={() => setShowRiskModal(false)}>
          <div className="modal-content threat-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>⬡ REAL-TIME THREAT ASSESSMENT</h3>
              <button className="modal-close-btn" onClick={() => setShowRiskModal(false)}>×</button>
            </div>
            <div className="threat-modal-body">
              <div className="threat-modal-gauge-section">
                <ThreatGauge score={metrics.threatScore} riskLevel={metrics.riskLevel ?? 'MEDIUM'} />
                <div className="threat-modal-host-info">
                  {[
                    { label: 'Host', val: metrics.hostname },
                    { label: 'Platform', val: platformName },
                    { label: 'CPU Usage', val: `${metrics.cpuUsage}%` },
                    { label: 'RAM Usage', val: `${metrics.memoryUsage}%` },
                    { label: 'Network Adapters', val: externalDevices.length },
                    { label: 'Uptime', val: metrics.uptimeDays === 0 ? 'Today' : `${metrics.uptimeDays} days` },
                    { label: 'Last Updated', val: new Date(metrics.collectedAt).toLocaleTimeString() },
                  ].map(({ label, val }) => (
                    <div key={label} className="tmi-row"><span>{label}</span><strong>{val}</strong></div>
                  ))}
                </div>
              </div>
              <div className="threat-modal-findings-label">Active Risk Findings ({systemFindings.length})</div>
              <div className="risk-breakdown-list" style={{ maxHeight: 260, overflowY: 'auto' }}>
                {systemFindings.length > 0 ? systemFindings.map((f, i) => (
                  <div key={i} className="risk-item">
                    <div className="risk-item-header"><strong>{f.title}</strong><SeverityBadge severity={f.severity} /></div>
                    <div className="risk-item-detail">{f.detail}</div>
                  </div>
                )) : (
                  <div style={{ textAlign: 'center', padding: 24, color: 'var(--text-faint)' }}>No active threats detected!</div>
                )}
              </div>
              <div className="risk-summary-note">
                Threat score is computed live via WebSocket from your machine's CPU, RAM, network interfaces, and uptime. Updates every 2 seconds.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
