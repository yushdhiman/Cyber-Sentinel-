const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required. No token provided.' });
  }

  const token = header.slice(7).trim();
  if (!token) {
    return res.status(401).json({ error: 'Authentication required. Empty token supplied.' });
  }

  try {
    const payload = jwt.verify(
      token,
      process.env.JWT_SECRET || 'cyber-sentinel-prod-secret-fallback-key-1234567890'
    );
    req.user = {
      id: payload.sub || payload.id,
      email: payload.email,
      name: payload.name,
      role: payload.role || 'analyst'
    };
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Authentication session expired. Please log in again.' });
    }
    return res.status(401).json({ error: 'Invalid authentication token.' });
  }
}

/**
 * Server-side RBAC middleware.
 * Roles:
 * - 'admin': Full privileges (system configuration, user management, containment, audit logs)
 * - 'senior_analyst': Triage, incident closure, IP containment, audit logs
 * - 'analyst': Read-only alerts, run scans, inspect telemetry, view intel
 */
function requireRole(allowedRoles = []) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required before checking permissions.' });
    }

    const userRole = (req.user.role || 'analyst').toLowerCase();
    const normalizedAllowed = allowedRoles.map(r => r.toLowerCase());

    if (!normalizedAllowed.includes(userRole) && userRole !== 'admin') {
      return res.status(403).json({
        error: `Access denied. Role '${req.user.role}' is not authorized for this operation. Required: [${allowedRoles.join(', ')}]`,
      });
    }

    next();
  };
}

module.exports = { requireAuth, requireRole, verifyToken: requireAuth };
