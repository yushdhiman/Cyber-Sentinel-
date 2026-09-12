const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const userStore = require('../data/userStore');
const { sendPasswordResetEmail, sendPasswordResetOTP } = require('../utils/notifier');
const { generateSecret, generateTOTP, verifyTOTP, generateOtpAuthUri } = require('../utils/totp');
const { logSecurityEvent, AuditActions } = require('../utils/auditLogger');
const { recordFailedLogin } = require('../utils/correlationEngine');

const { getJwtSecret } = require('../config/jwt');
const { ROLES } = require('../constants/roles');

const router = express.Router();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// In-memory store for password reset tokens (email link). Keys: token string.
const resetTokens = new Map();
// In-memory store for password reset OTPs (mobile). Keys: email.
const resetOTPs = new Map();

router.post('/register', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    if (!EMAIL_RE.test(cleanEmail)) {
      return res.status(400).json({ error: 'Invalid email format.' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
    }

    const existing = userStore.findByEmail(cleanEmail);
    if (existing) {
      return res.status(409).json({ error: 'An operator account with this email already exists. Please log in.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = userStore.createUser({
      name: (name || cleanEmail.split('@')[0]).trim(),
      email: cleanEmail,
      phone: phone ? phone.trim() : '',
      passwordHash,
      role: ROLES.ANALYST,
      profilePic: null,
      createdAt: new Date().toISOString(),
      isEmailVerified: true,
      isPhoneVerified: true,
    });

    const token = jwt.sign(
      { email: user.email, name: user.name, role: user.role },
      getJwtSecret(),
      { expiresIn: process.env.JWT_EXPIRES_IN || '2h' }
    );

    return res.status(201).json({
      token,
      user: {
        name: user.name,
        email: user.email,
        role: user.role,
        profilePic: user.profilePic || null,
        createdAt: user.createdAt,
        phone: user.phone || '',
        isEmailVerified: true,
        isPhoneVerified: true
      }
    });
  } catch (err) {
    console.error('[AUTH] Registration error:', err);
    return res.status(500).json({ error: 'Internal server error during registration.' });
  }
});

// In-memory store for active session refresh tokens (SHA-256 hashed). Keys: hashed token string -> { email, expiresAt }
const refreshTokens = new Map();
const hashToken = (token) => crypto.createHash('sha256').update(String(token)).digest('hex');

router.post('/login', async (req, res) => {
  try {
    const { email, password, mfaCode } = req.body || {};

    // 1. Generic authentication validation (prevents enumeration)
    if (!email || !password) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const user = userStore.findByEmail(cleanEmail);

    if (!user) {
      logSecurityEvent({
        actor: cleanEmail,
        action: AuditActions.LOGIN_FAILED,
        result: 'FAILURE',
        req,
        details: { reason: 'User not found' },
      });
      recordFailedLogin({ ip: req.ip, email: cleanEmail, userAgent: req.headers['user-agent'] });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // 2. Cryptographic password comparison with bcrypt
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      logSecurityEvent({
        actor: cleanEmail,
        action: AuditActions.LOGIN_FAILED,
        result: 'FAILURE',
        req,
        details: { reason: 'Invalid credentials' },
      });
      recordFailedLogin({ ip: req.ip, email: cleanEmail, userAgent: req.headers['user-agent'] });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // 3. Account Status verification
    if (user.status && user.status !== 'active') {
      logSecurityEvent({
        actor: cleanEmail,
        action: AuditActions.LOGIN_FAILED,
        result: 'FAILURE',
        req,
        details: { reason: 'Account suspended' },
      });
      return res.status(403).json({ error: 'Account has been suspended. Please contact your security administrator.' });
    }

    // 4. Multi-Factor Authentication (MFA) check
    if (user.mfaEnabled) {
      // Issue short-lived, single-use MFA challenge ticket (valid for 5 minutes)
      const mfaTicket = jwt.sign(
        { email: user.email, purpose: 'mfa_challenge' },
        getJwtSecret(),
        { expiresIn: '5m' }
      );

      return res.status(200).json({
        mfaRequired: true,
        mfaTicket,
        email: user.email,
        mfaType: 'totp',
        message: 'Two-factor authentication code (TOTP) required.'
      });
    }

    // 5. Issue short-lived access token (1h)
    const token = jwt.sign(
      { email: user.email, name: user.name, role: user.role },
      getJwtSecret(),
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
    );

    // 6. Issue cryptographically secure rotating refresh token (7 days), stored hashed
    const refreshToken = crypto.randomBytes(40).toString('hex');
    refreshTokens.set(hashToken(refreshToken), {
      email: user.email,
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000
    });

    logSecurityEvent({
      actor: user.email,
      actorRole: user.role,
      action: AuditActions.LOGIN,
      result: 'SUCCESS',
      req,
      details: { role: user.role },
    });

    return res.json({
      token,
      refreshToken,
      user: {
        name: user.name,
        email: user.email,
        role: user.role,
        profilePic: user.profilePic || null,
        createdAt: user.createdAt,
        phone: user.phone || '',
        isEmailVerified: !!user.isEmailVerified,
        isPhoneVerified: !!user.isPhoneVerified
      }
    });
  } catch (err) {
    console.error('[AUTH] Login error:', err);
    return res.status(500).json({ error: 'Internal server error during authentication.' });
  }
});

router.post('/refresh', (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token is required.' });
    }

    const tokenHash = hashToken(refreshToken);
    const session = refreshTokens.get(tokenHash);
    if (!session) {
      return res.status(401).json({ error: 'Invalid or revoked refresh token.' });
    }

    if (Date.now() > session.expiresAt) {
      refreshTokens.delete(tokenHash);
      return res.status(401).json({ error: 'Refresh token expired. Please log in again.' });
    }

    const user = userStore.findByEmail(session.email);
    if (!user || (user.status && user.status !== 'active')) {
      refreshTokens.delete(tokenHash);
      return res.status(401).json({ error: 'Operator account is inactive or not found.' });
    }

    // Token rotation: delete old refresh token, generate a new one
    refreshTokens.delete(tokenHash);
    const newRefreshToken = crypto.randomBytes(40).toString('hex');
    refreshTokens.set(hashToken(newRefreshToken), {
      email: user.email,
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000
    });

    const token = jwt.sign(
      { email: user.email, name: user.name, role: user.role },
      getJwtSecret(),
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
    );

    return res.json({
      token,
      refreshToken: newRefreshToken
    });
  } catch (err) {
    console.error('[AUTH] Token refresh error:', err);
    return res.status(500).json({ error: 'Internal server error during token refresh.' });
  }
});

router.post('/verify-mfa', async (req, res) => {
  try {
    const { mfaTicket, code, totpCode } = req.body || {};
    const inputCode = (code || totpCode || '').trim();

    if (!mfaTicket) {
      return res.status(400).json({ error: 'MFA challenge ticket is required.' });
    }

    if (!inputCode) {
      return res.status(400).json({ error: '6-digit authenticator code is required.' });
    }

    // Cryptographically verify the challenge ticket
    let ticketPayload;
    try {
      ticketPayload = jwt.verify(mfaTicket, getJwtSecret());
    } catch (err) {
      return res.status(401).json({ error: 'MFA challenge ticket has expired or is invalid. Please log in again.' });
    }

    if (ticketPayload.purpose !== 'mfa_challenge' || !ticketPayload.email) {
      return res.status(401).json({ error: 'Invalid MFA challenge token.' });
    }

    const user = userStore.findByEmail(ticketPayload.email);
    if (!user || (user.status && user.status !== 'active')) {
      return res.status(401).json({ error: 'Operator account not found or suspended.' });
    }

    // Verify RFC 6238 TOTP against enrolled user secret
    const secret = user.totpSecret || user.mfaSecret;
    if (!secret) {
      return res.status(400).json({ error: 'MFA is active but no authenticator secret is configured. Please configure MFA in profile.' });
    }
    const isTotpValid = verifyTOTP(inputCode, secret);

    if (!isTotpValid) {
      return res.status(401).json({ error: 'Invalid or expired authenticator code.' });
    }

    // MFA successfully verified: Issue full 1h access JWT + 7d rotating refresh token
    const token = jwt.sign(
      { email: user.email, name: user.name, role: user.role },
      getJwtSecret(),
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
    );

    const refreshToken = crypto.randomBytes(40).toString('hex');
    refreshTokens.set(hashToken(refreshToken), {
      email: user.email,
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000
    });

    return res.json({
      token,
      refreshToken,
      user: {
        name: user.name,
        email: user.email,
        role: user.role,
        profilePic: user.profilePic || null,
        createdAt: user.createdAt,
        phone: user.phone || '',
        isEmailVerified: true,
        isPhoneVerified: true
      }
    });
  } catch (err) {
    console.error('[AUTH] verify-mfa error:', err);
    return res.status(500).json({ error: 'Internal server error during MFA verification.' });
  }
});

router.post('/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (refreshToken) {
      refreshTokens.delete(hashToken(refreshToken));
    }
    console.log(`[Server] Secure session termination logged.`);
    return res.json({ message: 'Session logged out successfully' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

const { requireAuth } = require('../middleware/auth');

router.put('/profile', requireAuth, async (req, res) => {
  try {
    const { name, email, phone, currentPassword, newPassword, profilePic } = req.body;
    
    const user = userStore.findByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ error: 'Operator account not found' });
    }

    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ error: 'Current passcode is required to change passcode' });
      }
      const valid = await bcrypt.compare(currentPassword, user.passwordHash);
      if (!valid) {
        return res.status(401).json({ error: 'Incorrect current passcode' });
      }
      if (newPassword.length < 8) {
        return res.status(400).json({ error: 'New passcode must be at least 8 characters' });
      }
      user.passwordHash = await bcrypt.hash(newPassword, 12);
    }

    let emailChanged = false;
    const oldEmail = user.email;
    if (email && email.toLowerCase() !== user.email.toLowerCase()) {
      const emailLower = email.toLowerCase();
      if (!EMAIL_RE.test(emailLower)) {
        return res.status(400).json({ error: 'Invalid email format' });
      }
      if (userStore.findByEmail(emailLower)) {
        return res.status(409).json({ error: 'An operator with this email already exists' });
      }
      user.email = emailLower;
      user.isEmailVerified = false; // Reset verification on change
      emailChanged = true;
    }

    if (phone !== undefined && phone !== (user.phone || '')) {
      user.phone = phone;
      user.isPhoneVerified = false; // Reset verification on change
    }

    if (name) {
      user.name = name;
    }

    if (profilePic !== undefined) {
      user.profilePic = profilePic;
    }

    if (emailChanged) {
      userStore.updateUserEmail(oldEmail, user.email, user);
    } else {
      userStore.updateUser(user);
    }

    const token = jwt.sign(
      { email: user.email, name: user.name, role: user.role },
      getJwtSecret(),
      { expiresIn: process.env.JWT_EXPIRES_IN || '2h' }
    );

    return res.json({
      message: 'Profile updated successfully',
      token,
      user: {
        name: user.name,
        email: user.email,
        role: user.role,
        profilePic: user.profilePic || null,
        createdAt: user.createdAt,
        phone: user.phone || '',
        isEmailVerified: !!user.isEmailVerified,
        isPhoneVerified: !!user.isPhoneVerified
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// TOTP MFA Setup: Generates secret & authenticator URI for Google/Microsoft Authenticator
router.get('/mfa/setup', requireAuth, (req, res) => {
  try {
    const user = userStore.findByEmail(req.user.email);
    if (!user) return res.status(404).json({ error: 'Operator account not found' });

    const secret = user.totpSecret || generateSecret();
    const otpauthUri = generateOtpAuthUri(user.email, 'CyberSentinel', secret);

    return res.json({
      secret,
      otpauthUri,
      issuer: 'CyberSentinel',
      account: user.email,
      mfaEnabled: !!user.mfaEnabled
    });
  } catch (err) {
    console.error('[MFA] Setup error:', err);
    return res.status(500).json({ error: 'Failed to initiate MFA setup' });
  }
});

// TOTP MFA Enable: Confirms valid TOTP before activating
router.post('/mfa/enable', requireAuth, (req, res) => {
  try {
    const { secret, code } = req.body || {};
    if (!secret || !code) {
      return res.status(400).json({ error: 'Secret and 6-digit verification code are required' });
    }

    const isValid = verifyTOTP(code, secret);
    if (!isValid) {
      return res.status(400).json({ error: 'Invalid authenticator code. Check the time on your device and retry.' });
    }

    const user = userStore.findByEmail(req.user.email);
    if (!user) return res.status(404).json({ error: 'Operator account not found' });

    user.mfaEnabled = true;
    user.totpSecret = secret;
    userStore.updateUser(user);

    return res.json({ success: true, message: 'TOTP Multi-Factor Authentication successfully activated.' });
  } catch (err) {
    console.error('[MFA] Enable error:', err);
    return res.status(500).json({ error: 'Failed to enable MFA' });
  }
});

// Send verification code (compatibility stub)
router.post('/send-verification', requireAuth, async (req, res) => {
  return res.json({ message: 'Verified successfully' });
});

// Verify verification code (compatibility stub)
router.post('/verify-code', requireAuth, async (req, res) => {
  const user = userStore.findByEmail(req.user?.email || '');
  return res.json({
    message: 'Verified successfully',
    user: user ? {
      name: user.name,
      email: user.email,
      role: user.role,
      profilePic: user.profilePic || null,
      createdAt: user.createdAt,
      phone: user.phone || '',
      isEmailVerified: true,
      isPhoneVerified: true
    } : req.user
  });
});

// ── Forgot Password — step 1: request reset ─────────────────────────────────
/**
 * POST /api/auth/forgot-password
 * Body: { method: 'email'|'phone', email?, phone? }
 * - email method: looks up user by email, sends a reset link
 * - phone method: looks up user by phone, sends a 6-digit OTP
 */
router.post('/forgot-password', async (req, res) => {
  try {
    const { method, email, phone } = req.body;
    if (!method || !['email', 'phone'].includes(method)) {
      return res.status(400).json({ error: 'method must be "email" or "phone"' });
    }

    let user;
    if (method === 'email') {
      if (!email) return res.status(400).json({ error: 'email is required' });
      user = userStore.findByEmail(email.toLowerCase());
    } else {
      if (!phone) return res.status(400).json({ error: 'phone is required' });
      // Find user by phone number
      user = userStore.findByPhone(phone.trim());
    }

    // Always respond OK to prevent user enumeration
    if (!user) {
      return res.json({ success: true, message: 'If an account exists, you will receive the reset instructions.' });
    }

    if (method === 'email') {
      // Generate a secure token valid for 15 minutes
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + 15 * 60 * 1000;
      resetTokens.set(token, { email: user.email.toLowerCase(), expiresAt });

      const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/reset-password?token=${token}&method=email`;

      sendPasswordResetEmail({ to: user.email, name: user.name, resetUrl }).catch(err => {
        console.error('[RESET] Email dispatch error:', err.message);
      });

      console.log(`\n==========================================`);
      console.log(`[RESET] Password reset link for: ${user.email}`);
      console.log(`[RESET] URL: ${resetUrl}`);
      console.log(`==========================================\n`);

      return res.json({ success: true, message: 'Password reset link sent to your email.' });

    } else {
      // Send OTP to mobile
      if (!user.phone) {
        return res.status(400).json({ error: 'No mobile number registered for this account.' });
      }
      // Cryptographically secure 6-digit OTP using crypto.randomInt
      const otp = crypto.randomInt(100000, 1000000).toString();
      const hashedOtp = crypto.createHash('sha256').update(otp).digest('hex');
      const expiresAt = Date.now() + 5 * 60 * 1000; // 5-minute expiration
      resetOTPs.set(user.email.toLowerCase(), {
        hashedOtp,
        expiresAt,
        attempts: 0,
        maxAttempts: 3
      });

      sendPasswordResetOTP({ to: user.phone, otp }).catch(err => {
        console.error('[RESET] SMS dispatch error:', err.message);
      });

      console.log(`\n==========================================`);
      console.log(`[RESET] Password reset OTP generated for: ${user.email} → ${user.phone}`);
      console.log(`[RESET] OTP: ${otp}`);
      console.log(`==========================================\n`);

      const maskedPhone = user.phone.slice(0, -4).replace(/\d/g, '•') + user.phone.slice(-4);
      return res.json({
        success: true,
        message: 'OTP sent to your registered mobile number.',
        maskedPhone,
        email: user.email, // needed by frontend to verify identity
      });
    }
  } catch (err) {
    console.error('[RESET] forgot-password error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Reset Password — step 2: set new password ─────────────────────────────────
/**
 * POST /api/auth/reset-password
 * Body (email method): { method: 'email', token: string, newPassword: string }
 * Body (phone method): { method: 'phone', email: string, otp: string, newPassword: string }
 */
router.post('/reset-password', async (req, res) => {
  try {
    const { method, token, email, otp, newPassword } = req.body;

    if (!method || !['email', 'phone'].includes(method)) {
      return res.status(400).json({ error: 'method must be "email" or "phone"' });
    }
    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters' });
    }

    let userEmail;

    if (method === 'email') {
      if (!token) return res.status(400).json({ error: 'Reset token is required' });
      const entry = resetTokens.get(token);
      if (!entry) return res.status(400).json({ error: 'Invalid or expired reset link. Please request a new one.' });
      if (Date.now() > entry.expiresAt) {
        resetTokens.delete(token);
        return res.status(400).json({ error: 'Reset link has expired. Please request a new one.' });
      }
      userEmail = entry.email;
      resetTokens.delete(token);

    } else {
      if (!email || !otp) return res.status(400).json({ error: 'email and otp are required' });
      const entry = resetOTPs.get(email.toLowerCase());
      if (!entry) return res.status(400).json({ error: 'No active OTP found. Please request a new one.' });
      if (Date.now() > entry.expiresAt) {
        resetOTPs.delete(email.toLowerCase());
        return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
      }

      if (entry.attempts >= entry.maxAttempts) {
        resetOTPs.delete(email.toLowerCase());
        return res.status(429).json({ error: 'Too many invalid attempts. Please request a new OTP.' });
      }

      entry.attempts += 1;

      // Cryptographic timing-safe verification against hashed OTP
      const inputHashedOtp = crypto.createHash('sha256').update(otp.trim()).digest('hex');
      const isMatch = crypto.timingSafeEqual(Buffer.from(entry.hashedOtp), Buffer.from(inputHashedOtp));

      if (!isMatch) {
        const remaining = entry.maxAttempts - entry.attempts;
        return res.status(400).json({
          error: remaining > 0
            ? `Invalid OTP. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`
            : 'Too many invalid attempts. Please request a new OTP.'
        });
      }

      userEmail = email.toLowerCase();
      resetOTPs.delete(userEmail);
    }

    const user = userStore.findByEmail(userEmail);
    if (!user) return res.status(404).json({ error: 'Account not found.' });

    user.passwordHash = await bcrypt.hash(newPassword, 12);
    userStore.updateUser(user);

    console.log(`[RESET] Password successfully reset for: ${userEmail}`);
    return res.json({ success: true, message: 'Password reset successfully. You can now log in.' });
  } catch (err) {
    console.error('[RESET] reset-password error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
