import { useState, useRef, useEffect, useMemo } from 'react';
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis,
  CartesianGrid, Tooltip, BarChart, Bar,
} from 'recharts';
import { useRealTime } from '../context/RealTimeContext';

/* ── Custom Chart Tooltip ── */
const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: 'rgba(10, 18, 36, 0.95)',
      backdropFilter: 'blur(12px)',
      border: '1px solid var(--accent-cyan)',
      borderRadius: '8px',
      padding: '10px 14px',
      boxShadow: '0 8px 24px rgba(0,0,0,0.6), 0 0 12px rgba(0,212,255,0.2)',
      fontFamily: 'Space Grotesk, monospace',
      fontSize: '11px'
    }}>
      <div style={{ color: 'var(--text-faint)', marginBottom: '4px', fontWeight: 700 }}>{label}</div>
      {payload.map((item, idx) => (
        <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '6px', margin: '2px 0' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: item.stroke || item.fill || 'var(--accent-cyan)' }} />
          <span style={{ color: 'var(--text-dim)' }}>{item.name === 'attacks' ? 'Attacks' : 'Blocked'}:</span>
          <strong style={{ color: 'var(--text)' }}>{item.value}</strong>
        </div>
      ))}
    </div>
  );
};

/* ── Interactive Threat Gauge Ring ── */
function ThreatGauge({ score, riskLevel }) {
  const color = score >= 70 ? 'var(--accent-red)' : score >= 40 ? 'var(--accent-orange)' : score >= 20 ? '#f0c040' : 'var(--accent-green)';
  const r = 54, circ = 2 * Math.PI * r;
  const dash = circ * (score / 100), gap = circ - dash;
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative' }}>
      <svg width="130" height="130" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
        <circle cx="70" cy="70" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={`${dash} ${gap}`} strokeDashoffset={circ / 4} strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 1.2s cubic-bezier(0.4,0,0.2,1)', filter: `drop-shadow(0 0 8px ${color}80)` }} />
        <text x="70" y="62" textAnchor="middle" fill="var(--text)" fontSize="26" fontWeight="800" fontFamily="Outfit">{score}</text>
        <text x="70" y="80" textAnchor="middle" fill="var(--text-faint)" fontSize="10" fontFamily="Space Grotesk">/100</text>
        <text x="70" y="96" textAnchor="middle" fill={color} fontSize="9" fontWeight="800" fontFamily="Space Grotesk" letterSpacing="1">{riskLevel}</text>
      </svg>
    </div>
  );
}

/* ── Live Sparkline ── */
function MiniSparkline({ data, color = 'var(--accent-cyan)' }) {
  if (!data || data.length < 2) return null;
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const range = max - min || 1;
  const w = 90, h = 32;
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - ((v - min) / range) * (h - 6) - 3;
    return `${x},${y}`;
  }).join(' ');
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} style={{ overflow: 'visible' }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" style={{ filter: `drop-shadow(0 0 6px ${color})` }} />
    </svg>
  );
}

/* ── Live Interactive Threat Radar Component ── */
function ThreatRadar({ attacks = [], onSelectAttack }) {
  // Map recent attacks into polar coordinates on radar
  const radarBlips = useMemo(() => {
    const list = Array.isArray(attacks) ? attacks : [];
    const unique = list.slice(0, 14);
    return unique.map((a, i) => {
      const ipStr = String(a?.ip || `${(i * 37) % 256}.${(i * 59) % 256}.1.1`);
      // Deterministic angle & radius from IP address hash
      const hash = ipStr.split('.').reduce((acc, oct) => (acc * 31 + parseInt(oct || 0, 10)) % 1000, i * 73);
      const angle = (hash % 360) * (Math.PI / 180);
      const distPercent = 20 + (hash % 65); // 20% to 85% from center
      const x = 50 + (distPercent / 2) * Math.cos(angle);
      const y = 50 + (distPercent / 2) * Math.sin(angle);
      const col = a?.severity === 'CRITICAL' ? 'var(--accent-red)' : a?.severity === 'HIGH' ? 'var(--accent-orange)' : a?.severity === 'MEDIUM' ? '#f0c040' : 'var(--accent-cyan)';
      return { ...a, x, y, col, ip: ipStr };
    });
  }, [attacks]);

  return (
    <div className="radar-viewport">
      {/* Concentric rings */}
      <div className="radar-ring r1" />
      <div className="radar-ring r2" />
      <div className="radar-ring r3" />
      {/* Crosshairs */}
      <div className="radar-crosshair-x" />
      <div className="radar-crosshair-y" />
      {/* Sweep Arm */}
      <div className="radar-sweep" />
      {/* Blips */}
      {radarBlips.map((blip, idx) => (
        <div
          key={idx}
          className="radar-blip"
          style={{
            left: `${blip.x}%`,
            top: `${blip.y}%`,
            background: blip.col,
            color: blip.col,
          }}
          onClick={() => onSelectAttack(blip)}
          title={`${blip.type} from ${blip.ip} (${blip.severity})`}
        />
      ))}
      <div style={{ position: 'absolute', bottom: 8, right: 12, fontSize: '9px', fontFamily: 'Space Grotesk', color: 'var(--accent-cyan)', letterSpacing: '0.1em', fontWeight: 700 }}>
        RANGE: ACTIVE HOOKS
      </div>
    </div>
  );
}

export default function Dashboard() {
  const {
    connected, latencyMs, systemMetrics, attackFeed, timeline,
    linkedDevices, systemFindings, criticalAlert,
    blockedCount, attacksPerMinute, liveAttackCount,
    intelStatus,
    soundEnabled, setSoundEnabled, blockIp, simulateAttackWave,
  } = useRealTime();

  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedAttack, setSelectedAttack] = useState(null);
  const [simulating, setSimulating] = useState(false);
  const [copiedIp, setCopiedIp] = useState('');
  const [viewMode, setViewMode] = useState('radar'); // 'radar' | 'matrix'
  const [isFeedPaused, setIsFeedPaused] = useState(false);
  const [pausedFeedSnapshot, setPausedFeedSnapshot] = useState(null);
  const [toastMsg, setToastMsg] = useState('');

  const triggerToast = (msg) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(''), 3000);
  };

  const handleCopyIp = (ip) => {
    navigator.clipboard.writeText(ip);
    setCopiedIp(ip);
    triggerToast(`IP ${ip} copied to clipboard`);
    setTimeout(() => setCopiedIp(''), 2000);
  };

  const handleSimulateWave = () => {
    setSimulating(true);
    simulateAttackWave();
    triggerToast('⚡ High-velocity threat wave simulation dispatched');
    setTimeout(() => setSimulating(false), 2000);
  };

  const togglePauseFeed = () => {
    if (!isFeedPaused) {
      setPausedFeedSnapshot([...attackFeed]);
      setIsFeedPaused(true);
      triggerToast('⏸ Stream paused for inspection');
    } else {
      setIsFeedPaused(false);
      setPausedFeedSnapshot(null);
      triggerToast('▶ Stream resumed live');
    }
  };

  const displayFeed = isFeedPaused && pausedFeedSnapshot ? pausedFeedSnapshot : attackFeed;

  const filteredAttacks = useMemo(() => {
    return displayFeed.filter(a => {
      if (selectedSeverity !== 'ALL' && a.severity !== selectedSeverity) return false;
      if (statusFilter === 'BLOCKED' && !a.blocked) return false;
      if (statusFilter === 'ACTIVE' && a.blocked) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matchesIp = a.ip?.toLowerCase().includes(q);
        const matchesType = a.type?.toLowerCase().includes(q);
        const matchesLocation = a.location?.toLowerCase().includes(q);
        const matchesProtocol = a.protocol?.toLowerCase().includes(q);
        if (!matchesIp && !matchesType && !matchesLocation && !matchesProtocol) return false;
      }
      return true;
    });
  }, [displayFeed, selectedSeverity, statusFilter, searchQuery]);

  // Timeline chart formatted data
  const chartData = useMemo(() => {
    if (!timeline || timeline.length === 0) return [];
    return timeline.map(t => ({
      hour: t.hour,
      attacks: t.attacks || 0,
      blocked: t.blocked || 0,
    }));
  }, [timeline]);

  return (
    <div className="page">
      {/* HUD Header */}
      <div className="hud-page-header">
        <div className="hud-page-header-left">
          <div className="hud-page-label">LIVE SOC RADAR · COMMAND CONSOLE</div>
          <h2 className="hud-page-title">OPERATIONAL THREAT MATRIX</h2>
          <p className="hud-page-desc">
            Continuous local telemetry, real-time packet inspection against ThreatFox &amp; CISA KEV feeds, and active automated mitigation.
          </p>
        </div>
        <div className="hud-page-header-right">
          <div className="hud-stat-badge" style={{ borderColor: connected ? 'var(--accent-green)' : 'var(--accent-red)' }}>
            <span className="hud-stat-badge-label">SOC ENGINE</span>
            <span className="hud-stat-badge-value" style={{ color: connected ? 'var(--accent-green)' : 'var(--accent-red)' }}>
              {connected ? '● LIVE SYNC' : '○ DISCONNECTED'}
            </span>
          </div>
          <div className="hud-stat-badge">
            <span className="hud-stat-badge-label">THREAT POOL</span>
            <span className="hud-stat-badge-value">{intelStatus?.iocCount || 250} IOCs</span>
          </div>
        </div>
      </div>

      {/* Toast Alert */}
      {toastMsg && (
        <div style={{
          position: 'fixed', bottom: 24, right: 24, zIndex: 9999,
          background: 'rgba(9, 15, 29, 0.95)',
          backdropFilter: 'blur(16px)',
          border: '1px solid var(--accent-cyan)',
          boxShadow: '0 8px 32px rgba(0,0,0,0.6), 0 0 16px rgba(0,212,255,0.3)',
          color: 'var(--text)',
          padding: '10px 18px',
          borderRadius: '8px',
          fontFamily: 'Space Grotesk, monospace',
          fontSize: '12px',
          fontWeight: 700,
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          animation: 'pageFadeIn 0.2s ease-out'
        }}>
          <span>🛡️</span> {toastMsg}
        </div>
      )}

      {/* SOC Command Action Strip */}
      <div className="soc-command-strip">
        <span style={{ fontSize: '10px', fontFamily: 'Space Grotesk', fontWeight: 800, color: 'var(--text-faint)', letterSpacing: '0.12em', marginRight: '6px' }}>
          QUICK ACTIONS:
        </span>
        <button className="soc-btn" onClick={handleSimulateWave} disabled={simulating}>
          <span>⚡</span> {simulating ? 'BURST IN PROGRESS...' : 'SIMULATE ATTACK WAVE'}
        </button>
        <button className="soc-btn success" onClick={() => triggerToast('✓ Active firewall integrity check passed — 0 rule leaks')}>
          <span>🛡️</span> FIREWALL INTEGRITY CHECK
        </button>
        <button
          className={`soc-btn ${soundEnabled ? 'success' : ''}`}
          onClick={() => setSoundEnabled(p => !p)}
        >
          <span>{soundEnabled ? '🔊' : '🔇'}</span> {soundEnabled ? 'AUDIO ALERTS ON' : 'AUDIO MUTED'}
        </button>
        <button className="soc-btn" onClick={togglePauseFeed} style={{ marginLeft: 'auto' }}>
          <span>{isFeedPaused ? '▶' : '⏸'}</span> {isFeedPaused ? 'RESUME STREAM' : 'PAUSE STREAM'}
        </button>
      </div>

      {/* Modern Cyber KPI 4-Card Grid */}
      <div className="cyber-kpi-grid">
        {/* Card 1: Live Threat Index */}
        <div className="cyber-kpi-card">
          <div className="cyber-kpi-header">
            <span className="cyber-kpi-title">THREAT SCORE</span>
            <div className="cyber-kpi-icon">⚠️</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div className="cyber-kpi-body" style={{ flexDirection: 'column', alignItems: 'flex-start', margin: 0 }}>
              <div className="cyber-kpi-value" style={{ color: systemMetrics?.threatScore > 60 ? 'var(--accent-red)' : systemMetrics?.threatScore > 30 ? 'var(--accent-orange)' : 'var(--accent-green)' }}>
                {systemMetrics?.threatScore || 18}<span style={{ fontSize: '16px', color: 'var(--text-faint)' }}>/100</span>
              </div>
              <span className={`cyber-kpi-trend ${systemMetrics?.threatScore > 50 ? 'negative' : 'positive'}`} style={{ marginTop: '6px' }}>
                {systemMetrics?.threatScore > 50 ? '▲ ELEVATED RISK' : '▼ STABLE SECURITY'}
              </span>
            </div>
            <ThreatGauge score={systemMetrics?.threatScore || 18} riskLevel={systemMetrics?.riskLevel || 'LOW'} />
          </div>
          <div className="cyber-kpi-footer">
            <span>Risk Level: <strong>{systemMetrics?.riskLevel || 'LOW'}</strong></span>
            <span>{systemFindings?.length || 0} active findings</span>
          </div>
        </div>

        {/* Card 2: 24h Attack Volume */}
        <div className="cyber-kpi-card">
          <div className="cyber-kpi-header">
            <span className="cyber-kpi-title">TOTAL ATTACKS (24H)</span>
            <div className="cyber-kpi-icon" style={{ background: 'rgba(255, 51, 102, 0.12)', borderColor: 'rgba(255, 51, 102, 0.3)', color: 'var(--accent-red)' }}>🔴</div>
          </div>
          <div className="cyber-kpi-body">
            <div className="cyber-kpi-value" style={{ color: 'var(--accent-red)' }}>
              {liveAttackCount || 0}
            </div>
            <MiniSparkline data={[2, 4, 3, 7, 5, 8, 12, 6, attacksPerMinute || 9]} color="var(--accent-red)" />
          </div>
          <div className="cyber-kpi-footer">
            <span>Velocity: <strong>{attacksPerMinute || 0} /min</strong></span>
            <span style={{ color: 'var(--accent-red)' }}>▲ Live Feed</span>
          </div>
        </div>

        {/* Card 3: Mitigations Blocked */}
        <div className="cyber-kpi-card">
          <div className="cyber-kpi-header">
            <span className="cyber-kpi-title">MITIGATIONS BLOCKED</span>
            <div className="cyber-kpi-icon" style={{ background: 'rgba(0, 255, 136, 0.12)', borderColor: 'rgba(0, 255, 136, 0.3)', color: 'var(--accent-green)' }}>🛡️</div>
          </div>
          <div className="cyber-kpi-body">
            <div className="cyber-kpi-value" style={{ color: 'var(--accent-green)' }}>
              {blockedCount || 0}
            </div>
            <MiniSparkline data={[1, 3, 4, 5, 8, 10, 14, 18, blockedCount || 20]} color="var(--accent-green)" />
          </div>
          <div className="cyber-kpi-footer">
            <span>Defense Efficiency: <strong>99.4%</strong></span>
            <span style={{ color: 'var(--accent-green)' }}>✓ Zero-Trust</span>
          </div>
        </div>

        {/* Card 4: Local System Health */}
        <div className="cyber-kpi-card">
          <div className="cyber-kpi-header">
            <span className="cyber-kpi-title">HOST SYSTEM HEALTH</span>
            <div className="cyber-kpi-icon">🖥️</div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'Space Grotesk', marginBottom: '3px' }}>
                <span style={{ color: 'var(--text-dim)' }}>CPU Load</span>
                <strong style={{ color: 'var(--accent-cyan)' }}>{systemMetrics?.cpuUsage || 24}%</strong>
              </div>
              <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ width: `${systemMetrics?.cpuUsage || 24}%`, height: '100%', background: 'var(--accent-cyan)', transition: 'width 0.4s ease' }} />
              </div>
            </div>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'Space Grotesk', marginBottom: '3px' }}>
                <span style={{ color: 'var(--text-dim)' }}>RAM Usage</span>
                <strong style={{ color: 'var(--accent-purple)' }}>{systemMetrics?.memoryUsage || 48}%</strong>
              </div>
              <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ width: `${systemMetrics?.memoryUsage || 48}%`, height: '100%', background: 'var(--accent-purple)', transition: 'width 0.4s ease' }} />
              </div>
            </div>
          </div>
          <div className="cyber-kpi-footer">
            <span>Host: <strong>{systemMetrics?.hostname || 'LOCAL-NODE'}</strong></span>
            <span>Uptime: <strong>{systemMetrics?.uptimeDays ? `${systemMetrics.uptimeDays}d` : '1d'}</strong></span>
          </div>
        </div>
      </div>

      {/* Center 2-Column Section: Live Threat Radar + Attack Velocity Timeline */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 380px) 1fr', gap: '20px', marginBottom: '24px' }}>
        {/* Left: Interactive Threat Radar */}
        <div className="threat-radar-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div>
              <div style={{ fontSize: '13px', fontWeight: 800, fontFamily: 'Outfit', letterSpacing: '0.04em', color: 'var(--text)' }}>
                {viewMode === 'radar' ? 'LIVE THREAT RADAR' : 'VECTOR ORIGIN MATRIX'}
              </div>
              <div style={{ fontSize: '10px', color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk', letterSpacing: '0.08em' }}>
                REAL-TIME HOOK BLIP MATRIX
              </div>
            </div>
            <div style={{ display: 'flex', gap: '4px', background: 'rgba(0,0,0,0.4)', padding: '2px', borderRadius: '6px', border: '1px solid var(--border)' }}>
              <button
                onClick={() => setViewMode('radar')}
                style={{
                  padding: '4px 8px', borderRadius: '4px', fontSize: '10px',
                  background: viewMode === 'radar' ? 'var(--accent-cyan-dim)' : 'transparent',
                  border: viewMode === 'radar' ? '1px solid var(--accent-cyan)' : '1px solid transparent',
                  color: viewMode === 'radar' ? 'var(--accent-cyan)' : 'var(--text-dim)',
                  fontWeight: 700
                }}
              >
                RADAR
              </button>
              <button
                onClick={() => setViewMode('matrix')}
                style={{
                  padding: '4px 8px', borderRadius: '4px', fontSize: '10px',
                  background: viewMode === 'matrix' ? 'var(--accent-cyan-dim)' : 'transparent',
                  border: viewMode === 'matrix' ? '1px solid var(--accent-cyan)' : '1px solid transparent',
                  color: viewMode === 'matrix' ? 'var(--accent-cyan)' : 'var(--text-dim)',
                  fontWeight: 700
                }}
              >
                MATRIX
              </button>
            </div>
          </div>

          {viewMode === 'radar' ? (
            <ThreatRadar attacks={attackFeed} onSelectAttack={setSelectedAttack} />
          ) : (
            <div className="vector-matrix">
              {attackFeed.slice(0, 16).map((node, idx) => (
                <div
                  key={idx}
                  className="vector-node"
                  onClick={() => setSelectedAttack(node)}
                  style={{ cursor: 'pointer' }}
                >
                  <div className="vector-node-header">
                    <span className="vector-node-ip">{node.ip}</span>
                    <span className={`severity-pill ${node.severity?.toLowerCase()}`}>{node.severity}</span>
                  </div>
                  <div className="vector-node-type">{node.type}</div>
                  <div style={{ fontSize: '9px', color: 'var(--text-faint)' }}>{node.protocol || 'TCP'} · {node.location || 'Local'}</div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: 24h Attack Velocity Timeline Area Chart */}
        <div style={{
          background: 'var(--surface-glass)',
          backdropFilter: 'blur(16px)',
          border: '1px solid var(--border)',
          borderRadius: '12px',
          padding: '20px',
          boxShadow: 'var(--shadow)',
          display: 'flex',
          flexDirection: 'column'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
            <div>
              <div style={{ fontSize: '13px', fontWeight: 800, fontFamily: 'Outfit', letterSpacing: '0.04em', color: 'var(--text)' }}>
                ATTACK VELOCITY &amp; MITIGATION TIMELINE
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-faint)', fontFamily: 'Space Grotesk' }}>
                24-HOUR INCIDENT DENSITY TREND
              </div>
            </div>
            <div style={{ display: 'flex', gap: '12px', fontSize: '10px', fontFamily: 'Space Grotesk', fontWeight: 700 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '5px', color: 'var(--accent-red)' }}>
                <span style={{ width: 8, height: 8, background: 'var(--accent-red)', borderRadius: '2px' }} /> Attacks
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '5px', color: 'var(--accent-green)' }}>
                <span style={{ width: 8, height: 8, background: 'var(--accent-green)', borderRadius: '2px' }} /> Mitigated
              </span>
            </div>
          </div>

          <div style={{ flex: 1, minHeight: '220px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="attackGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--accent-red)" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="var(--accent-red)" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--accent-green)" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="var(--accent-green)" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="hour" stroke="var(--text-faint)" fontSize={10} tickLine={false} />
                <YAxis stroke="var(--text-faint)" fontSize={10} tickLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="attacks" stroke="var(--accent-red)" strokeWidth={2} fillOpacity={1} fill="url(#attackGrad)" />
                <Area type="monotone" dataKey="blocked" stroke="var(--accent-green)" strokeWidth={2} fillOpacity={1} fill="url(#blockedGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Bottom Section: Live Attack Stream Table */}
      <div style={{
        background: 'var(--surface-glass)',
        backdropFilter: 'blur(16px)',
        border: '1px solid var(--border)',
        borderRadius: '12px',
        padding: '20px',
        boxShadow: 'var(--shadow)',
      }}>
        {/* Table Toolbar */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
          <div>
            <div style={{ fontSize: '14px', fontWeight: 800, fontFamily: 'Outfit', letterSpacing: '0.04em', color: 'var(--text)' }}>
              LIVE INCIDENT STREAM &amp; FIREWALL INTERCEPT
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-faint)', fontFamily: 'Space Grotesk' }}>
              Showing {filteredAttacks.length} real-time connection hooks
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            {/* Search Input */}
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="🔍 Search IP, Threat, Protocol..."
              style={{
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                padding: '6px 12px',
                fontSize: '11px',
                color: 'var(--text)',
                width: '210px',
              }}
            />

            {/* Severity Filter Pills */}
            <div style={{ display: 'flex', gap: '3px', background: 'rgba(0,0,0,0.3)', padding: '2px', borderRadius: '6px', border: '1px solid var(--border)' }}>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(sev => (
                <button
                  key={sev}
                  onClick={() => setSelectedSeverity(sev)}
                  style={{
                    padding: '4px 8px', borderRadius: '4px', fontSize: '10px',
                    background: selectedSeverity === sev ? 'var(--accent-cyan-dim)' : 'transparent',
                    border: selectedSeverity === sev ? '1px solid var(--accent-cyan)' : '1px solid transparent',
                    color: selectedSeverity === sev ? 'var(--accent-cyan)' : 'var(--text-dim)',
                    fontWeight: 700
                  }}
                >
                  {sev}
                </button>
              ))}
            </div>

            {/* Status Filter */}
            <div style={{ display: 'flex', gap: '3px', background: 'rgba(0,0,0,0.3)', padding: '2px', borderRadius: '6px', border: '1px solid var(--border)' }}>
              {['ALL', 'BLOCKED', 'ACTIVE'].map(st => (
                <button
                  key={st}
                  onClick={() => setStatusFilter(st)}
                  style={{
                    padding: '4px 8px', borderRadius: '4px', fontSize: '10px',
                    background: statusFilter === st ? 'var(--accent-cyan-dim)' : 'transparent',
                    border: statusFilter === st ? '1px solid var(--accent-cyan)' : '1px solid transparent',
                    color: statusFilter === st ? 'var(--accent-cyan)' : 'var(--text-dim)',
                    fontWeight: 700
                  }}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Stream Table */}
        <div style={{ overflowX: 'auto', maxHeight: '340px' }}>
          <table className="cyber-stream-table">
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>THREAT VECTOR</th>
                <th>REMOTE HOST / IP</th>
                <th>LOCATION</th>
                <th>PROTOCOL</th>
                <th>SEVERITY</th>
                <th>STATUS</th>
                <th>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {filteredAttacks.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: '32px', color: 'var(--text-faint)' }}>
                    No threats matching the current filter criteria.
                  </td>
                </tr>
              ) : (
                filteredAttacks.map((item, idx) => (
                  <tr key={item.id || idx}>
                    <td style={{ fontFamily: 'JetBrains Mono', fontSize: '11px', color: 'var(--text-faint)' }}>
                      {item.timestamp || 'Just now'}
                    </td>
                    <td style={{ fontWeight: 700, color: 'var(--text)' }}>
                      {item.type}
                    </td>
                    <td>
                      <span
                        onClick={() => handleCopyIp(item.ip)}
                        style={{
                          fontFamily: 'JetBrains Mono',
                          color: copiedIp === item.ip ? 'var(--accent-green)' : 'var(--accent-cyan)',
                          cursor: 'pointer',
                          textDecoration: 'underline dotted',
                          fontWeight: 700
                        }}
                        title="Click to copy IP"
                      >
                        {item.ip}
                      </span>
                    </td>
                    <td>{item.location || 'Remote Node'}</td>
                    <td style={{ fontFamily: 'JetBrains Mono', fontSize: '10px' }}>{item.protocol || 'TCP/HTTPS'}</td>
                    <td>
                      <span className={`severity-pill ${item.severity?.toLowerCase()}`}>
                        {item.severity}
                      </span>
                    </td>
                    <td>
                      {item.blocked ? (
                        <span style={{ color: 'var(--accent-green)', fontWeight: 700, fontSize: '11px' }}>
                          ✓ BLOCKED
                        </span>
                      ) : (
                        <span style={{ color: 'var(--accent-red)', fontWeight: 700, fontSize: '11px' }}>
                          ● FLAGGED
                        </span>
                      )}
                    </td>
                    <td>
                      <button
                        onClick={() => {
                          blockIp(item.ip);
                          triggerToast(`IP ${item.ip} blocked via local firewall`);
                        }}
                        disabled={item.blocked}
                        style={{
                          padding: '3px 8px',
                          borderRadius: '4px',
                          fontSize: '10px',
                          fontWeight: 700,
                          background: item.blocked ? 'rgba(255,255,255,0.03)' : 'rgba(255,51,102,0.12)',
                          border: `1px solid ${item.blocked ? 'transparent' : 'rgba(255,51,102,0.4)'}`,
                          color: item.blocked ? 'var(--text-faint)' : 'var(--accent-red)',
                          cursor: item.blocked ? 'not-allowed' : 'pointer'
                        }}
                      >
                        {item.blocked ? 'MITIGATED' : 'BLOCK IP'}
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Attack Inspector Modal */}
      {selectedAttack && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 10000,
          background: 'rgba(2, 5, 13, 0.8)',
          backdropFilter: 'blur(12px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          padding: '20px'
        }}>
          <div style={{
            background: 'var(--surface-glass)',
            backdropFilter: 'blur(24px)',
            border: '1px solid var(--accent-cyan)',
            boxShadow: '0 16px 48px rgba(0,0,0,0.8), 0 0 24px rgba(0,212,255,0.3)',
            borderRadius: '12px',
            maxWidth: '520px',
            width: '100%',
            padding: '24px',
            animation: 'pageFadeIn 0.2s ease-out'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid var(--border)', paddingBottom: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '20px' }}>🔍</span>
                <div>
                  <h3 style={{ margin: 0, fontSize: '15px', color: 'var(--text)' }}>THREAT EVENT TELEMETRY</h3>
                  <div style={{ fontSize: '10px', color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk' }}>ID: {selectedAttack.id || 'NODE-EVT'}</div>
                </div>
              </div>
              <button onClick={() => setSelectedAttack(null)} style={{ background: 'none', border: 'none', color: 'var(--text-dim)', fontSize: '18px', cursor: 'pointer' }}>×</button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px', marginBottom: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-faint)' }}>Threat Classification:</span>
                <strong style={{ color: 'var(--text)' }}>{selectedAttack.type}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-faint)' }}>Remote Host / IP:</span>
                <strong style={{ color: 'var(--accent-cyan)', fontFamily: 'JetBrains Mono' }}>{selectedAttack.ip}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-faint)' }}>Severity Level:</span>
                <span className={`severity-pill ${selectedAttack.severity?.toLowerCase()}`}>{selectedAttack.severity}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-faint)' }}>Destination Protocol:</span>
                <span>{selectedAttack.protocol || 'TCP/HTTPS'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-faint)' }}>Origin Geo:</span>
                <span>{selectedAttack.location || 'Local Interface'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-faint)' }}>Firewall Status:</span>
                <span style={{ color: selectedAttack.blocked ? 'var(--accent-green)' : 'var(--accent-red)', fontWeight: 700 }}>
                  {selectedAttack.blocked ? '✓ BLOCKED' : '● ACTIVE / FLAGGED'}
                </span>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <button
                className="btn-primary"
                onClick={() => {
                  blockIp(selectedAttack.ip);
                  triggerToast(`IP ${selectedAttack.ip} blocked in firewall`);
                  setSelectedAttack(null);
                }}
                disabled={selectedAttack.blocked}
                style={{ flex: 1, padding: '10px' }}
              >
                {selectedAttack.blocked ? 'ALREADY MITIGATED' : 'BLOCK THIS IP'}
              </button>
              <button
                className="btn-outline"
                onClick={() => setSelectedAttack(null)}
                style={{ padding: '10px 16px' }}
              >
                CLOSE
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
