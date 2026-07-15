import { useState, useRef } from 'react';
import { useAuth } from '../context/AuthContext';

export default function Profile() {
  const { user, updateProfile } = useAuth();
  const [name, setName] = useState(user?.name || '');
  const [email, setEmail] = useState(user?.email || '');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [profilePic, setProfilePic] = useState(user?.profilePic || null);
  const [previewPic, setPreviewPic] = useState(null);
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  const fileInputRef = useRef(null);

  // Compress image before saving to database (to keep users.json file tiny and performant)
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

        // Compress as JPEG with 0.8 quality
        const dataUrl = canvas.toDataURL('image/jpeg', 0.8);
        setPreviewPic(dataUrl);
      };
    };
    reader.onerror = () => {
      setError('Error reading file.');
    };
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      compressAndSetImage(file);
    }
  };

  const triggerFileSelect = () => {
    fileInputRef.current?.click();
  };

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
      };

      if (newPassword) {
        payload.currentPassword = currentPassword;
        payload.newPassword = newPassword;
      }

      // If a preview picture was selected, update to it, otherwise keep existing
      if (previewPic) {
        payload.profilePic = previewPic;
      } else if (profilePic === null) {
        payload.profilePic = null;
      }

      const updatedUser = await updateProfile(payload);
      setProfilePic(updatedUser.profilePic);
      setPreviewPic(null);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setSuccess('Identity profile updated successfully.');
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
      {/* Component Styles (scoped to this component) */}
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

        .avatar-btn.danger:hover {
          background: var(--accent-red-dim);
          border-color: var(--accent-red);
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
            View active session privileges, customize operator visual signature avatar, and modify account credentials.
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
              <label className="profile-input-label">
                Registered Email ID
                <input 
                  type="email" 
                  value={email} 
                  onChange={(e) => setEmail(e.target.value)} 
                  required 
                  placeholder="operator@sentinel.ai" 
                />
              </label>
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

            <div className="form-section-title">⬡ Security Verification</div>
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
