import { useState, useRef, useEffect, useMemo } from 'react';
import { useAuth } from '../context/AuthContext';
import client from '../api/client';

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
  { code: 'TR', name: 'Turkey',                dial: '+90',  flag: '🇹🇷' },
  { code: 'IL', name: 'Israel',                dial: '+972', flag: '🇮🇱' },
  { code: 'AR', name: 'Argentina',             dial: '+54',  flag: '🇦🇷' },
  { code: 'CL', name: 'Chile',                 dial: '+56',  flag: '🇨🇱' },
  { code: 'CO', name: 'Colombia',              dial: '+57',  flag: '🇨🇴' },
  { code: 'PE', name: 'Peru',                  dial: '+51',  flag: '🇵🇪' },
  { code: 'KE', name: 'Kenya',                 dial: '+254', flag: '🇰🇪' },
  { code: 'GH', name: 'Ghana',                 dial: '+233', flag: '🇬🇭' },
  { code: 'LK', name: 'Sri Lanka',             dial: '+94',  flag: '🇱🇰' },
  { code: 'NP', name: 'Nepal',                 dial: '+977', flag: '🇳🇵' },
  { code: 'QA', name: 'Qatar',                 dial: '+974', flag: '🇶🇦' },
  { code: 'KW', name: 'Kuwait',                dial: '+965', flag: '🇰🇼' },
];

function parseExistingPhone(rawPhone) {
  if (!rawPhone) return { country: COUNTRIES[0], digits: '' };
  const trimmed = rawPhone.trim();
  // Find matching country by dial code (longest match first)
  const sorted = [...COUNTRIES].sort((a, b) => b.dial.length - a.dial.length);
  for (const c of sorted) {
    if (trimmed.startsWith(c.dial)) {
      return { country: c, digits: trimmed.slice(c.dial.length) };
    }
  }
  return { country: COUNTRIES[0], digits: trimmed.replace(/\D/g, '') };
}

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
          minWidth: 105, whiteSpace: 'nowrap',
          height: '100%',
        }}
      >
        <span style={{ fontSize: 16 }}>{selected.flag}</span>
        <span style={{ color: 'var(--accent-cyan)', fontWeight: 700, fontFamily: 'Space Grotesk', fontSize: 12 }}>
          {selected.dial}
        </span>
        <span style={{ color: 'var(--text-faint)', fontSize: 10, marginLeft: 2, transform: open ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }}>▼</span>
      </button>

      {open && (
        <div style={{
          position: 'absolute', top: '100%', left: 0, zIndex: 9999,
          width: 270, marginTop: 4,
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
              placeholder="Search country or code..."
              style={{
                width: '100%', padding: '6px 10px',
                background: 'rgba(0,212,255,0.06)',
                border: '1px solid rgba(0,212,255,0.25)',
                borderRadius: 4, color: 'var(--text)',
                fontSize: 12, outline: 'none',
              }}
            />
          </div>
          <div style={{ maxHeight: 200, overflowY: 'auto' }}>
            {filtered.map(c => (
              <button
                key={c.code}
                type="button"
                onClick={() => { onChange(c); setOpen(false); }}
                style={{
                  width: '100%', display: 'flex', alignItems: 'center', gap: 8,
                  padding: '8px 12px', background: selected.code === c.code ? 'rgba(0,212,255,0.1)' : 'none',
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

export default function Profile() {
  const { user, updateProfile } = useAuth();
  const [name, setName] = useState(user?.name || '');
  const [email, setEmail] = useState(user?.email || '');
  
  // Country & phone state
  const initialPhoneParsed = useMemo(() => parseExistingPhone(user?.phone), [user?.phone]);
  const [country, setCountry] = useState(initialPhoneParsed.country);
  const [phoneNumber, setPhoneNumber] = useState(initialPhoneParsed.digits);

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [profilePic, setProfilePic] = useState(user?.profilePic || null);
  const [previewPic, setPreviewPic] = useState(null);
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  const fileInputRef = useRef(null);

  const fullPhone = phoneNumber.trim() ? `${country.dial}${phoneNumber.trim()}` : '';

  // Compress image before saving
  const compressAndSetImage = (file) => {
    setError('');
    setSuccess('');
    
    if (!file.type.startsWith('image/')) {
      setError('Invalid file format. Please select an image.');
      return;
    }

    const reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onload = (event) => {
      const img = new Image();
      img.src = event.target.result;
      img.onload = () => {
        const canvas = document.createElement('canvas');
        const MAX_WIDTH = 300;
        const MAX_HEIGHT = 300;
        let width = img.width;
        let height = img.height;

        if (width > height) {
          if (width > MAX_WIDTH) {
            height = Math.round((height * MAX_WIDTH) / width);
            width = MAX_WIDTH;
          }
        } else {
          if (height > MAX_HEIGHT) {
            width = Math.round((width * MAX_HEIGHT) / height);
            height = MAX_HEIGHT;
          }
        }

        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, width, height);
        const dataUrl = canvas.toDataURL('image/jpeg', 0.8);
        setPreviewPic(dataUrl);
      };
    };
    reader.onerror = () => setError('Error reading file.');
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) compressAndSetImage(file);
  };

  const triggerFileSelect = () => fileInputRef.current?.click();

  const handleRemovePic = () => {
    setPreviewPic(null);
    setProfilePic(null);
    setSuccess('');
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (newPassword) {
      if (!currentPassword) {
        setError('Current passcode is required to change access passcode.');
        return;
      }
      if (newPassword !== confirmPassword) {
        setError('New passcodes do not match.');
        return;
      }
      if (newPassword.length < 8) {
        setError('New passcode must be at least 8 characters long.');
        return;
      }
    }

    setLoading(true);
    try {
      const payload = {
        name,
        email,
        phone: fullPhone,
      };

      if (newPassword) {
        payload.currentPassword = currentPassword;
        payload.newPassword = newPassword;
      }

      if (previewPic) {
        payload.profilePic = previewPic;
      } else if (profilePic === null) {
        payload.profilePic = null;
      }

      const updatedUser = await updateProfile(payload);
      setProfilePic(updatedUser.profilePic);
      setPreviewPic(null);
      const parsed = parseExistingPhone(updatedUser.phone);
      setCountry(parsed.country);
      setPhoneNumber(parsed.digits);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setSuccess('Identity profile & registered mobile updated successfully.');
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.error || 'Profile update failed. Verify current credentials.');
    } finally {
      setLoading(false);
    }
  };

  const formattedDate = user?.createdAt 
    ? new Date(user.createdAt).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      })
    : 'System Origin Epoch';

  return (
    <div className="page">
      <style>{`
        .profile-container {
          display: grid;
          grid-template-columns: 1fr 2fr;
          gap: 24px;
          margin-top: 20px;
        }
        
        .profile-card-left {
          display: flex;
          flex-direction: column;
          align-items: center;
          background: var(--bg-elevated);
          border: 1px solid var(--border);
          border-radius: 8px;
          padding: 24px;
          box-shadow: var(--shadow);
          text-align: center;
          height: fit-content;
        }

        .profile-avatar-wrapper {
          position: relative;
          width: 140px;
          height: 140px;
          margin-bottom: 20px;
          border-radius: 50%;
          padding: 4px;
          background: linear-gradient(135deg, var(--accent-cyan), var(--border));
          box-shadow: 0 0 16px var(--accent-cyan-dim);
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .profile-avatar-img {
          width: 100%;
          height: 100%;
          border-radius: 50%;
          object-fit: cover;
          background: var(--surface);
          border: 2px solid var(--bg-elevated);
        }

        .profile-avatar-fallback {
          width: 100%;
          height: 100%;
          border-radius: 50%;
          background: var(--surface);
          color: var(--accent-cyan);
          font-size: 48px;
          font-weight: 700;
          font-family: 'Space Grotesk', sans-serif;
          display: flex;
          align-items: center;
          justify-content: center;
          border: 2px solid var(--bg-elevated);
        }

        .avatar-action-overlay {
          position: absolute;
          inset: 4px;
          border-radius: 50%;
          background: rgba(2, 5, 13, 0.8);
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          opacity: 0;
          transition: opacity 0.2s ease;
          cursor: pointer;
          border: 2px solid var(--accent-cyan);
        }

        .profile-avatar-wrapper:hover .avatar-action-overlay {
          opacity: 1;
        }

        .overlay-icon {
          font-size: 18px;
          color: var(--accent-cyan);
          margin-bottom: 4px;
        }

        .overlay-text {
          font-size: 9px;
          font-weight: 700;
          letter-spacing: 0.1em;
          color: var(--text);
          text-transform: uppercase;
        }

        .profile-badge-row {
          width: 100%;
          margin-top: 16px;
          padding-top: 16px;
          border-top: 1px solid var(--border);
          display: flex;
          flex-direction: column;
          gap: 12px;
          text-align: left;
        }

        .badge-info-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          font-size: 11px;
          font-family: 'Space Grotesk', monospace;
        }

        .badge-info-label {
          color: var(--text-faint);
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }

        .badge-info-value {
          font-weight: 600;
          color: var(--text);
        }

        .role-badge {
          background: var(--accent-cyan-dim);
          border: 1px solid var(--accent-cyan);
          color: var(--accent-cyan);
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 10px;
          font-weight: 700;
          letter-spacing: 0.05em;
          text-transform: uppercase;
        }

        .avatar-button-group {
          display: flex;
          gap: 8px;
          width: 100%;
          margin-top: 16px;
        }

        .avatar-btn {
          flex: 1;
          padding: 8px;
          font-size: 10px;
          font-weight: 700;
          letter-spacing: 0.05em;
          border-radius: 6px;
          font-family: 'Space Grotesk', sans-serif;
          text-transform: uppercase;
          background: var(--surface);
          border: 1px solid var(--border);
          color: var(--text-dim);
        }

        .avatar-btn:hover {
          border-color: var(--accent-cyan);
          color: var(--text);
          background: var(--surface-2);
        }

        .avatar-btn.danger {
          border-color: rgba(255, 0, 85, 0.4);
          color: var(--accent-red);
        }

        .profile-form-right {
          background: var(--bg-elevated);
          border: 1px solid var(--border);
          border-radius: 8px;
          padding: 24px;
          box-shadow: var(--shadow);
        }

        .form-section-title {
          font-size: 13px;
          font-weight: 700;
          color: var(--accent-cyan);
          letter-spacing: 0.08em;
          border-bottom: 1px solid var(--border);
          padding-bottom: 8px;
          margin-bottom: 18px;
          text-transform: uppercase;
        }

        .form-grid-2 {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 16px;
          margin-bottom: 24px;
        }

        .profile-input-label {
          display: flex;
          flex-direction: column;
          gap: 8px;
          font-size: 11px;
          font-weight: 600;
          letter-spacing: 0.05em;
          color: var(--text-dim);
          text-transform: uppercase;
        }

        .profile-input-label input {
          width: 100%;
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: 6px;
          padding: 10px 14px;
          color: var(--text);
          font-size: 13px;
          transition: all 0.2s;
        }

        .profile-input-label input:focus {
          border-color: var(--accent-cyan);
          box-shadow: 0 0 8px var(--accent-cyan-dim);
        }

        .form-status-msg {
          padding: 12px 16px;
          border-radius: 6px;
          font-size: 12px;
          margin-bottom: 20px;
          font-family: 'Space Grotesk', monospace;
        }

        .form-status-msg.success {
          background: var(--accent-green-dim);
          border: 1px solid var(--accent-green);
          color: var(--accent-green);
        }

        .form-status-msg.error {
          background: var(--accent-red-dim);
          border: 1px solid var(--accent-red);
          color: var(--accent-red);
        }

        .verification-badge {
          font-family: 'Space Grotesk', monospace;
          font-size: 10px;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          padding: 2px 6px;
          border-radius: 4px;
        }

        .verification-badge.verified {
          background: var(--accent-green-dim);
          border: 1px solid var(--accent-green);
          color: var(--accent-green);
        }

        .verification-badge.unverified {
          background: var(--accent-red-dim);
          border: 1px solid var(--accent-red);
          color: var(--accent-red);
        }

        .verify-action-btn {
          background: none;
          border: none;
          color: var(--accent-cyan);
          font-family: 'Space Grotesk', monospace;
          font-size: 10px;
          font-weight: 700;
          cursor: pointer;
          padding: 0;
          text-transform: uppercase;
        }

        .verify-action-btn:hover {
          text-shadow: 0 0 6px var(--accent-cyan);
          color: var(--text);
        }

        .verification-box {
          margin-top: 18px;
          margin-bottom: 24px;
          background: var(--surface);
          border: 1px solid var(--accent-cyan);
          border-radius: 8px;
          padding: 16px;
          box-shadow: 0 0 16px rgba(0, 212, 255, 0.1);
        }

        .verification-box-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          font-family: 'Space Grotesk', sans-serif;
          font-size: 11px;
          font-weight: 700;
          color: var(--accent-cyan);
          letter-spacing: 0.05em;
        }

        .verification-box-header .close-btn {
          background: none;
          border: none;
          color: var(--text-dim);
          font-size: 16px;
          cursor: pointer;
        }

        @media (max-width: 768px) {
          .profile-container {
            grid-template-columns: 1fr;
          }
          .form-grid-2 {
            grid-template-columns: 1fr;
          }
        }
      `}</style>

      {/* HUD Page Header */}
      <div className="hud-page-header">
        <div className="hud-page-header-left">
          <div className="hud-page-label">IDENTITY MANAGEMENT · USER CARD</div>
          <h2 className="hud-page-title">OPERATOR PROFILE</h2>
          <p className="hud-page-desc">
            View active session privileges, configure registered mobile number (+91 India &amp; global), and manage cryptographic credentials.
          </p>
        </div>
      </div>

      <div className="profile-container">
        {/* Left Column: Avatar Display & Metadata */}
        <div className="profile-card-left">
          <div className="profile-avatar-wrapper">
            {previewPic ? (
              <img src={previewPic} alt="Preview Avatar" className="profile-avatar-img" />
            ) : profilePic ? (
              <img src={profilePic} alt={user?.name} className="profile-avatar-img" />
            ) : (
              <div className="profile-avatar-fallback">
                {name ? name[0].toUpperCase() : 'U'}
              </div>
            )}
            
            <div className="avatar-action-overlay" onClick={triggerFileSelect}>
              <div className="overlay-icon">📷</div>
              <div className="overlay-text">Change Image</div>
            </div>
            
            <input 
              type="file" 
              ref={fileInputRef} 
              style={{ display: 'none' }} 
              accept="image/*" 
              onChange={handleFileChange} 
            />
          </div>

          <h3 className="mono" style={{ fontSize: '16px', letterSpacing: '0.02em', margin: '0 0 4px' }}>
            {name || 'OPERATOR'}
          </h3>
          <span style={{ fontSize: '11px', color: 'var(--text-faint)', wordBreak: 'break-all' }}>
            {email}
          </span>

          <div className="avatar-button-group">
            <button className="avatar-btn" onClick={triggerFileSelect}>
              Upload Pic
            </button>
            {(profilePic || previewPic) && (
              <button className="avatar-btn danger" onClick={handleRemovePic}>
                Remove
              </button>
            )}
          </div>

          <div className="profile-badge-row">
            <div className="badge-info-item">
              <span className="badge-info-label">Privilege Level</span>
              <span className="role-badge">{user?.role}</span>
            </div>
            <div className="badge-info-item">
              <span className="badge-info-label">Registered Mobile</span>
              <span className="badge-info-value" style={{ color: 'var(--accent-cyan)' }}>
                {user?.phone || 'Not configured'}
              </span>
            </div>
            <div className="badge-info-item">
              <span className="badge-info-label">Sync Status</span>
              <span className="badge-info-value" style={{ color: 'var(--accent-green)' }}>ONLINE</span>
            </div>
            <div className="badge-info-item" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '4px' }}>
              <span className="badge-info-label">Host Registered Since</span>
              <span className="badge-info-value" style={{ fontSize: '10px', color: 'var(--text-dim)' }}>{formattedDate}</span>
            </div>
          </div>
        </div>

        {/* Right Column: Update Settings Form */}
        <div className="profile-form-right">
          <form onSubmit={handleSave}>
            <div className="form-section-title">⬡ Personal Information</div>
            <div className="form-grid-2">
              <label className="profile-input-label">
                Username Signature
                <input 
                  type="text" 
                  value={name} 
                  onChange={(e) => setName(e.target.value)} 
                  required 
                  placeholder="Operator Name" 
                />
              </label>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <span className="profile-input-label" style={{ margin: 0 }}>Registered Email ID</span>
                <input 
                  type="email" 
                  value={email} 
                  onChange={(e) => setEmail(e.target.value)} 
                  required 
                  placeholder="operator@sentinel.ai" 
                />
              </div>
            </div>

            {/* Mobile Number Section with Full Country Selector */}
            <div style={{ marginBottom: '24px' }}>
              <span className="profile-input-label" style={{ display: 'block', marginBottom: '8px' }}>
                REGISTERED OPERATOR MOBILE NUMBER
              </span>

              <div style={{ display: 'flex', height: '42px' }}>
                <CountrySelector selected={country} onChange={setCountry} />
                <input 
                  type="tel" 
                  value={phoneNumber} 
                  onChange={(e) => setPhoneNumber(e.target.value.replace(/\D/g, ''))} 
                  placeholder="Enter mobile number" 
                  maxLength={15}
                  style={{ 
                    flex: 1,
                    background: 'var(--surface)', 
                    border: '1px solid var(--border)', 
                    borderLeft: 'none',
                    borderRadius: '0 6px 6px 0', 
                    padding: '10px 14px', 
                    color: 'var(--text)',
                    fontSize: '13px'
                  }}
                />
              </div>

              {phoneNumber.trim() && (
                <div style={{ marginTop: '6px', fontSize: '10px', color: 'var(--accent-cyan)', fontFamily: 'Space Grotesk' }}>
                  ✓ {country.flag} {country.name} · Full registered mobile: <strong>{fullPhone}</strong>
                </div>
              )}
            </div>

            <div className="form-section-title">⬡ Cryptographic Access Passcode</div>
            <div className="form-grid-2">
              <label className="profile-input-label">
                New Passcode
                <input 
                  type="password" 
                  value={newPassword} 
                  onChange={(e) => setNewPassword(e.target.value)} 
                  placeholder="At least 8 characters"
                  minLength={8}
                />
              </label>
              <label className="profile-input-label">
                Confirm New Passcode
                <input 
                  type="password" 
                  value={confirmPassword} 
                  onChange={(e) => setConfirmPassword(e.target.value)} 
                  placeholder="Repeat new passcode"
                  minLength={8}
                />
              </label>
            </div>

            <div className="form-section-title">⬡ Passcode Confirmation</div>
            <div style={{ marginBottom: '24px' }}>
              <label className="profile-input-label" style={{ maxWidth: '350px' }}>
                Current Passcode
                <input 
                  type="password" 
                  value={currentPassword} 
                  onChange={(e) => setCurrentPassword(e.target.value)} 
                  placeholder="••••••••"
                  required={!!newPassword}
                />
                <span style={{ fontSize: '9px', color: 'var(--text-faint)', textTransform: 'none', marginTop: '4px' }}>
                  * Required only when modifying your access passcode.
                </span>
              </label>
            </div>

            {error && <div className="form-status-msg error">{error}</div>}
            {success && <div className="form-status-msg success">{success}</div>}

            <button 
              type="submit" 
              className="btn-primary" 
              disabled={loading}
              style={{ padding: '12px 24px', fontSize: '13px', fontWeight: '700', letterSpacing: '0.05em' }}
            >
              {loading ? 'SYNCHRONIZING PROFILE KEY...' : 'SAVE SETTINGS'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
