/**
 * incidents.js
 * Comprehensive incident response management layer.
 * Tracks full incident lifecycle (NEW -> TRIAGED -> INVESTIGATING -> CONTAINED -> CLOSED).
 * Cryptographic SHA-256 evidence integrity preservation.
 */
const express = require('express');
const router = express.Router();
const { requireAuth, requireRole } = require('../middleware/auth');
const {
  getIncidents,
  getIncidentById,
  createIncident,
  updateIncidentStatus,
  addIncidentNote,
} = require('../data/securityStore');
const { logSecurityEvent, AuditActions } = require('../utils/auditLogger');

// GET /api/incidents - List incidents with filtering
router.get('/', requireAuth, (req, res) => {
  try {
    const { status, severity, search } = req.query;
    let incidents = getIncidents(status);

    if (severity && severity !== 'ALL') {
      incidents = incidents.filter(i => i.severity.toUpperCase() === severity.toUpperCase());
    }

    if (search) {
      const q = search.toLowerCase();
      incidents = incidents.filter(i => 
        i.title.toLowerCase().includes(q) ||
        i.id.toLowerCase().includes(q) ||
        i.relatedIps.some(ip => ip.includes(q))
      );
    }

    res.json({
      success: true,
      total: incidents.length,
      incidents,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/incidents/:id - Get full incident details with evidence & timeline
router.get('/:id', requireAuth, (req, res) => {
  try {
    const incident = getIncidentById(req.params.id);
    if (!incident) {
      return res.status(404).json({ success: false, error: 'Incident not found' });
    }
    res.json({ success: true, incident });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/incidents - Manual incident creation by analyst
router.post('/', requireAuth, (req, res) => {
  try {
    const { title, severity, category, description, relatedIps, evidence } = req.body;
    if (!title || !description) {
      return res.status(400).json({ success: false, error: 'Title and description are required.' });
    }

    const incident = createIncident({
      title,
      severity: severity || 'MEDIUM',
      category: category || 'MANUAL_REPORT',
      description,
      relatedIps: relatedIps || [],
      evidence,
      createdBy: `${req.user.name || req.user.email} (${req.user.role})`,
    });

    logSecurityEvent({
      actor: req.user.email,
      actorRole: req.user.role,
      action: AuditActions.INCIDENT_CREATED,
      target: incident.id,
      req,
      details: { title, severity },
    });

    res.status(201).json({ success: true, incident });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// PATCH /api/incidents/:id/status - Transition incident lifecycle
router.patch('/:id/status', requireAuth, requireRole(['admin', 'senior_analyst']), (req, res) => {
  try {
    const { status, note } = req.body;
    if (!status) {
      return res.status(400).json({ success: false, error: 'New status is required.' });
    }

    const incident = updateIncidentStatus(
      req.params.id,
      status,
      `${req.user.name || req.user.email} (${req.user.role})`,
      note
    );

    if (!incident) {
      return res.status(404).json({ success: false, error: 'Incident not found.' });
    }

    logSecurityEvent({
      actor: req.user.email,
      actorRole: req.user.role,
      action: AuditActions.INCIDENT_STATUS_CHANGE,
      target: incident.id,
      req,
      details: { status, note },
    });

    res.json({ success: true, incident });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// POST /api/incidents/:id/notes - Add analyst investigative note
router.post('/:id/notes', requireAuth, (req, res) => {
  try {
    const { note } = req.body;
    if (!note || !note.trim()) {
      return res.status(400).json({ success: false, error: 'Note text cannot be empty.' });
    }

    const incident = addIncidentNote(
      req.params.id,
      `${req.user.name || req.user.email} (${req.user.role})`,
      note.trim()
    );

    if (!incident) {
      return res.status(404).json({ success: false, error: 'Incident not found.' });
    }

    logSecurityEvent({
      actor: req.user.email,
      actorRole: req.user.role,
      action: AuditActions.ANALYST_NOTE_ADDED,
      target: incident.id,
      req,
      details: { noteSnippet: note.slice(0, 100) },
    });

    res.json({ success: true, incident });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
