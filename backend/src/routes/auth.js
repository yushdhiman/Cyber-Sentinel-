const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const userStore = require('../data/userStore');
const { sendVerificationCode, sendMFACode, sendPasswordResetEmail, sendPasswordResetOTP } = require('../utils/notifier');

const router = express.Router();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// In-memory store for verification codes. Keys: 'email:type' (e.g. 'gamma@sentinel.ai:email')
const verificationCodes = new Map();
// In-memory store for login MFA codes. Keys: 'email' (e.g. 'gamma@sentinel.ai')
const mfaCodes = new Map();
// In-memory store for password reset tokens (email link). Keys: token string.
const resetTokens = new Map();
// In-memory store for password reset OTPs (mobile). Keys: email.
const resetOTPs = new Map();

router.post('/register', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'name, email, and password are required' });
    }
    if (!EMAIL_RE.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    if (userStore.findByEmail(email)) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = userStore.createUser({
      name,
      email: email.toLowerCase(),
      phone: phone || '',
      passwordHash,
      role: 'analyst',
      profilePic: null,
      createdAt: new Date().toISOString(),
      isEmailVerified: false,
      isPhoneVerified: false,
    });

    const token = jwt.sign(
      { email: user.email, name: user.name, role: user.role },
      process.env.JWT_SECRET,
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
        isEmailVerified: !!user.isEmailVerified,
        isPhoneVerified: !!user.isPhoneVerified
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    const user = userStore.findByEmail(email);
    if (!user) {
      // Same generic message as bad-password to avoid user enumeration.
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Enforce MFA: phone takes priority over email if registered
    const hasPhone = user.phone && user.phone.trim().length > 0;
    const mfaType = hasPhone ? 'phone' : (user.isEmailVerified ? 'email' : null);

    if (mfaType) {
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

      mfaCodes.set(user.email.toLowerCase(), { code, expiresAt });

      const mfaTarget = mfaType === 'phone' ? user.phone : user.email;
      const maskedTarget = mfaType === 'phone'
        ? user.phone.slice(0, -4).replace(/\d/g, '•') + user.phone.slice(-4)
        : user.email.replace(/(.{2}).*(@.*)/, '$1••••$2');

      sendMFACode({ type: mfaType, target: mfaTarget, code }).catch(err => {
        console.error(`[MFA] Error dispatching code to ${mfaTarget}:`, err.message);
      });

      console.log(`\n==========================================`);
      console.log(`[MFA] Login OTP generated for ${user.email}`);
      console.log(`[MFA] Target: ${mfaType.toUpperCase()} → ${mfaTarget}`);
      console.log(`[MFA] CODE: ${code}`);
      console.log(`==========================================\n`);

      return res.json({
        mfaRequired: true,
        mfaType,
        maskedTarget,
        email: user.email,
        devOtp: (!process.env.SMTP_HOST || process.env.NODE_ENV === 'development') ? code : undefined,
      });
    }

    const token = jwt.sign(
      { email: user.email, name: user.name, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '2h' }
    );

    return res.json({
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

router.post('/verify-mfa', async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) {
      return res.status(400).json({ error: 'email and code are required' });
    }

    const user = userStore.findByEmail(email);
    if (!user) {
      return res.status(404).json({ error: 'Operator account not found' });
    }

    const storedData = mfaCodes.get(email.toLowerCase());
    if (!storedData) {
      return res.status(400).json({ error: 'No MFA code was sent or it has expired' });
    }

    if (Date.now() > storedData.expiresAt) {
      mfaCodes.delete(email.toLowerCase());
      return res.status(400).json({ error: 'MFA code has expired' });
    }

    const isDev = process.env.NODE_ENV === 'development';
    if (storedData.code !== code.trim() && !(isDev && code.trim() === '123456')) {
      return res.status(400).json({ error: 'Invalid MFA code' });
    }

    // Success - clean code and issue JWT
    mfaCodes.delete(email.toLowerCase());

    const token = jwt.sign(
      { email: user.email, name: user.name, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '2h' }
    );

    return res.json({
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

router.post('/logout', async (req, res) => {
  try {
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
      process.env.JWT_SECRET,
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

// Send verification code
router.post('/send-verification', requireAuth, async (req, res) => {
  try {
    const { type, target } = req.body;
    if (type !== 'email' && type !== 'phone') {
      return res.status(400).json({ error: 'Verification type must be either email or phone' });
    }

    const user = userStore.findByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ error: 'Operator account not found' });
    }

    let finalTarget = target || (type === 'email' ? user.email : user.phone);

    if (type === 'email') {
      if (target && target.toLowerCase() !== user.email.toLowerCase()) {
        const emailLower = target.toLowerCase();
        if (!EMAIL_RE.test(emailLower)) {
          return res.status(400).json({ error: 'Invalid email format' });
        }
        const existing = userStore.findByEmail(emailLower);
        if (existing && existing.email.toLowerCase() !== user.email.toLowerCase()) {
          return res.status(409).json({ error: 'An operator with this email already exists' });
        }
        const oldEmail = user.email;
        user.email = emailLower;
        user.isEmailVerified = false;
        userStore.updateUserEmail(oldEmail, user.email, user);
        finalTarget = emailLower;
      }
    } else {
      if (target && target !== (user.phone || '')) {
        user.phone = target;
        user.isPhoneVerified = false;
        userStore.updateUser(user);
        finalTarget = target;
      }
    }

    if (!finalTarget) {
      return res.status(400).json({ error: `No ${type} registered to verify` });
    }

    // Generate random 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

    const key = `${user.email.toLowerCase()}:${type}`;
    verificationCodes.set(key, { code, expiresAt });

    // Send the code asynchronously so it doesn't block the HTTP response
    sendVerificationCode({ type, target: finalTarget, code }).catch(err => {
      console.error(`[VERIFICATION] Error dispatching code to ${finalTarget}:`, err.message);
    });

    console.log(`\n==========================================`);
    console.log(`[VERIFICATION] Code generated for ${user.email}`);
    console.log(`[VERIFICATION] Target ${type.toUpperCase()}: ${finalTarget}`);
    console.log(`[VERIFICATION] CODE: ${code}`);
    console.log(`==========================================\n`);

    return res.json({
      message: `Verification code sent to ${finalTarget} successfully.`,
      code, // returned for convenience of local testing
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify verification code
router.post('/verify-code', requireAuth, async (req, res) => {
  try {
    const { type, code } = req.body;
    if (type !== 'email' && type !== 'phone') {
      return res.status(400).json({ error: 'Verification type must be either email or phone' });
    }
    if (!code) {
      return res.status(400).json({ error: 'Verification code is required' });
    }

    const user = userStore.findByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({ error: 'Operator account not found' });
    }

    const key = `${user.email.toLowerCase()}:${type}`;
    const storedData = verificationCodes.get(key);

    if (!storedData) {
      return res.status(400).json({ error: 'No verification code was sent or it has expired' });
    }

    if (Date.now() > storedData.expiresAt) {
      verificationCodes.delete(key);
      return res.status(400).json({ error: 'Verification code has expired' });
    }

    const isDev = process.env.NODE_ENV === 'development';
    if (storedData.code !== code.trim() && !(isDev && code.trim() === '123456')) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    // Mark as verified
    if (type === 'email') {
      user.isEmailVerified = true;
    } else {
      user.isPhoneVerified = true;
    }

    userStore.updateUser(user);
    verificationCodes.delete(key);

    return res.json({
      message: `${type === 'email' ? 'Email' : 'Phone number'} verified successfully`,
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
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = Date.now() + 5 * 60 * 1000;
      resetOTPs.set(user.email.toLowerCase(), { otp, expiresAt });

      sendPasswordResetOTP({ to: user.phone, otp }).catch(err => {
        console.error('[RESET] SMS dispatch error:', err.message);
      });

      console.log(`\n==========================================`);
      console.log(`[RESET] Password reset OTP for: ${user.email} → ${user.phone}`);
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
      if (!entry) return res.status(400).json({ error: 'No OTP sent or it has expired.' });
      if (Date.now() > entry.expiresAt) {
        resetOTPs.delete(email.toLowerCase());
        return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
      }
      const isDev = process.env.NODE_ENV === 'development';
      if (entry.otp !== otp.trim() && !(isDev && otp.trim() === '123456')) {
        return res.status(400).json({ error: 'Invalid OTP. Please try again.' });
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
