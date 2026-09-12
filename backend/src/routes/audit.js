/**
 * audit.js
 * Endpoints for querying the immutable security audit log trail.
 * Enforces role-based access control (Admin & Senior Analyst).
 */
const express = require('express');
const router = express.Router();
const { requireAuth, requireRole } = require('../middleware/auth');
const { getAuditLogs } = require('../utils/auditLogger');

// GET /api/audit-logs
router.get('/', requireAuth, requireRole(['admin', 'senior_analyst']), (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const action = req.query.action || null;
    const logs = getAuditLogs(limit, action);
    res.json({
      success: true,
      total: logs.length,
      logs,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
