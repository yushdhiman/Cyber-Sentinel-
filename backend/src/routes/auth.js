const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const userStore = require('../data/userStore');

const router = express.Router();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

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
      passwordHash,
      role: 'analyst',
      profilePic: null,
      createdAt: new Date().toISOString(),
    });

    const token = jwt.sign(
      { email: user.email, name: user.name, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '2h' }
    );

    return res.status(201).json({ token, user: { name: user.name, email: user.email, role: user.role, profilePic: user.profilePic || null, createdAt: user.createdAt } });
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

    const token = jwt.sign(
      { email: user.email, name: user.name, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '2h' }
    );

    return res.json({ token, user: { name: user.name, email: user.email, role: user.role, profilePic: user.profilePic || null, createdAt: user.createdAt } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

const { requireAuth } = require('../middleware/auth');

router.put('/profile', requireAuth, async (req, res) => {
  try {
    const { name, email, currentPassword, newPassword, profilePic } = req.body;
    
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
      emailChanged = true;
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
      user: { name: user.name, email: user.email, role: user.role, profilePic: user.profilePic || null, createdAt: user.createdAt }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
