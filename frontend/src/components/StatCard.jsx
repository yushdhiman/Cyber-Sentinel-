function getIcon(label) {
  const norm = label.toLowerCase();
  if (norm.includes('threat')) {
    return (
      <svg className="stat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
    );
  }
  if (norm.includes('attack')) {
    return (
      <svg className="stat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10"/>
        <circle cx="12" cy="12" r="6"/>
        <circle cx="12" cy="12" r="2"/>
      </svg>
    );
  }
  if (norm.includes('device')) {
    return (
      <svg className="stat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
        <line x1="8" y1="21" x2="16" y2="21"/>
        <line x1="12" y1="17" x2="12" y2="21"/>
      </svg>
    );
  }
  if (norm.includes('health')) {
    return (
      <svg className="stat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
      </svg>
    );
  }
  if (norm.includes('blocked')) {
    return (
      <svg className="stat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
    );
  }
  if (norm.includes('alert')) {
    return (
      <svg className="stat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/>
        <line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
    );
  }
  return null;
}

function renderCardVisual(label, value, diagnosticState, displayFormat, isPaused, securedPercent) {
  const norm = label.toLowerCase();
  const numVal = parseInt(value, 10) || 0;

  if (norm.includes('threat') || norm.includes('health')) {
    const isScanning = norm.includes('health') && diagnosticState === 'running';
    const strokeColor = norm.includes('threat') ? 'var(--accent-orange)' : 'var(--accent-green)';
    const circumference = 2 * Math.PI * 15.9155; // ~100
    const offset = circumference - (numVal / 100) * circumference;

    return (
      <div className={`stat-visual-gauge ${isScanning ? 'scanning-spinner' : ''}`}>
        <svg width="40" height="40" viewBox="0 0 36 36">
          <circle cx="18" cy="18" r="15.9155" fill="none" stroke="rgba(255, 255, 255, 0.05)" strokeWidth="3" />
          <circle cx="18" cy="18" r="15.9155" fill="none" stroke={strokeColor} strokeWidth="3"
            strokeDasharray={circumference}
            strokeDashoffset={isScanning ? 30 : offset}
            strokeLinecap="round"
            style={{ 
              transition: isScanning ? 'none' : 'stroke-dashoffset 0.5s ease-in-out', 
              transform: 'rotate(-90deg)', 
              transformOrigin: '50% 50%' 
            }}
          />
        </svg>
      </div>
    );
  }

  if (norm.includes('attack')) {
    return (
      <div className="stat-visual-sparkline">
        {isPaused ? (
          <div className="paused-badge">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor">
              <rect x="4" y="4" width="6" height="16" />
              <rect x="14" y="4" width="6" height="16" />
            </svg>
            PAUSED
          </div>
        ) : (
          <svg width="60" height="24" viewBox="0 0 70 20">
            <path
              d="M0,10 L15,10 L20,3 L25,17 L30,10 L45,10 L48,6 L52,14 L55,10 L70,10"
              fill="none"
              stroke="var(--accent-red)"
              strokeWidth="2"
              strokeLinecap="round"
              className="pulse-path"
            />
          </svg>
        )}
      </div>
    );
  }

  if (norm.includes('blocked')) {
    return (
      <div className="stat-visual-sparkline">
        <svg width="60" height="24" viewBox="0 0 70 20">
          <path
            d="M0,18 L12,15 L24,16 L36,11 L48,9 L60,4 L70,2"
            fill="none"
            stroke="var(--accent-green)"
            strokeWidth="2"
            strokeLinecap="round"
            className="blocked-trend-path"
          />
        </svg>
      </div>
    );
  }

  if (norm.includes('device')) {
    const percent = typeof securedPercent === 'number' ? securedPercent : Math.min(100, Math.round((numVal / 200) * 100));
    return (
      <div className="stat-visual-progress">
        <div className="progress-track">
          <div className="progress-fill" style={{ width: `${percent}%` }} />
        </div>
        <div className="progress-meta">{percent}% Secured</div>
      </div>
    );
  }

  if (norm.includes('alert')) {
    if (numVal > 0) {
      return (
        <div className="stat-visual-alert active">
          <span className="alert-ping-ring"></span>
          <span className="alert-dot-core"></span>
        </div>
      );
    }
    return (
      <div className="stat-visual-alert secure">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--accent-green)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="20 6 9 17 4 12" />
        </svg>
        <span className="secure-label">SECURE</span>
      </div>
    );
  }

  return null;
}

export function StatCard({ 
  label, 
  value, 
  suffix = '', 
  trend, 
  accent = 'cyan', 
  onClick,
  isPaused,
  diagnosticState,
  displayFormat,
  isAcknowledged,
  isExpanded,
  expandableContent,
  securedPercent
}) {
  const norm = label.toLowerCase();
  const numVal = parseInt(value, 10) || 0;
  const isCriticalAlertActive = norm.includes('alert') && numVal > 0 && !isAcknowledged;
  
  let displayVal = value;
  let displaySuffix = suffix;
  if (norm.includes('blocked') && displayFormat === 'rate') {
    displayVal = (numVal / 24).toFixed(1);
    displaySuffix = '/hr';
  }

  if (norm.includes('health') && diagnosticState === 'running') {
    displayVal = 'Scanning';
    displaySuffix = '...';
  }

  return (
    <div 
      className={`stat-card accent-${accent} ${onClick ? 'clickable' : ''} ${isCriticalAlertActive ? 'pulse-warning-card' : ''} ${isExpanded ? 'expanded' : ''}`}
      onClick={onClick}
    >
      <div className="stat-header">
        <div className="stat-label">{label}</div>
        {getIcon(label)}
      </div>
      
      <div className="stat-main-row">
        <div className="stat-value">
          {displayVal}
          {displaySuffix}
        </div>
        {renderCardVisual(label, value, diagnosticState, displayFormat, isPaused, securedPercent)}
      </div>
      
      {trend && <div className="stat-trend">{trend}</div>}

      {isExpanded && expandableContent && (
        <div className="stat-expandable-content" onClick={(e) => e.stopPropagation()}>
          {expandableContent}
        </div>
      )}
    </div>
  );
}

const SEVERITY_CLASS = {
  LOW: 'badge-low',
  MEDIUM: 'badge-medium',
  HIGH: 'badge-high',
  CRITICAL: 'badge-critical',
};

export function SeverityBadge({ severity }) {
  return <span className={`badge ${SEVERITY_CLASS[severity] || 'badge-low'}`}>{severity}</span>;
}
