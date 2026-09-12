const jwt = require('jsonwebtoken');
const { getJwtSecret } = require('../config/jwt');
const { ROLES, normalizeRole } = require('../constants/roles');

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
    const payload = jwt.verify(token, getJwtSecret());
    req.user = {
      id: payload.sub || payload.id || payload.email,
      email: payload.email,
      name: payload.name,
      role: normalizeRole(payload.role)
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
 * Normalized roles:
 * - 'ADMIN': Full privileges (system configuration, user management, containment, audit logs)
 * - 'SENIOR_ANALYST': Triage, incident closure, IP containment, audit logs
 * - 'ANALYST': Read-only alerts, run scans, inspect telemetry, view intel
 * - 'VIEWER': Read-only observer
 */
function requireRole(allowedRoles = []) {
  const normalizedAllowed = allowedRoles.map(r => normalizeRole(r));

  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required before checking permissions.' });
    }

    const userRole = normalizeRole(req.user.role);

    // ADMIN has superset privileges
    if (userRole === ROLES.ADMIN || normalizedAllowed.includes(userRole)) {
      return next();
    }

    return res.status(403).json({
      error: `Access denied. Role '${userRole}' is not authorized for this operation. Required: [${normalizedAllowed.join(', ')}]`,
    });
  };
}

module.exports = {
  requireAuth,
  requireRole,
  verifyToken: requireAuth,
};
