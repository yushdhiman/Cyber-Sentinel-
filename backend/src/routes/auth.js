const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const userStore = require('../data/userStore');
const { sendVerificationCode, sendMFACode } = require('../utils/notifier');

const router = express.Router();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// In-memory store for verification codes. Keys: 'email:type' (e.g. 'gamma@sentinel.ai:email')
const verificationCodes = new Map();
// In-memory store for login MFA codes. Keys: 'email' (e.g. 'gamma@sentinel.ai')
const mfaCodes = new Map();

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

    // Check if email or phone is verified to enforce 2FA/MFA
    if (user.isEmailVerified || user.isPhoneVerified) {
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

      mfaCodes.set(user.email.toLowerCase(), { code, expiresAt });

      const mfaType = user.isEmailVerified ? 'email' : 'phone';
      const mfaTarget = mfaType === 'email' ? user.email : user.phone;

      // Send the code asynchronously so it doesn't block the HTTP response
      sendMFACode({ type: mfaType, target: mfaTarget, code }).catch(err => {
        console.error(`[MFA] Error dispatching code to ${mfaTarget}:`, err.message);
      });

      console.log(`\n==========================================`);
      console.log(`[MFA] Login MFA code generated for ${user.email}`);
      console.log(`[MFA] Target: ${user.isEmailVerified ? 'EMAIL' : 'PHONE'}`);
      console.log(`[MFA] CODE: ${code}`);
      console.log(`==========================================\n`);

      return res.json({
        mfaRequired: true,
        mfaType,
        email: user.email,
        code, // returned for convenience of local testing
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

    if (storedData.code !== code.trim()) {
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

    if (storedData.code !== code.trim()) {
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

module.exports = router;
