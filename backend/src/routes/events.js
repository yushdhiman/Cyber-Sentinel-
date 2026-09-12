/**
 * events.js
 * Unified Event Ingestion API.
 * Accepts event streams from endpoint agents, syslog collectors, Windows event logs,
 * and simulations, normalizes them, runs IOC enrichment, and triggers SIEM correlation.
 */
const express = require('express');
const router = express.Router();
const { normalizeEvent, EventTypes } = require('../services/normalizer/eventNormalizer');
const { matchIoc } = require('../services/threatIntel/iocMatcher');
const {
  recordFailedLogin,
  recordWebExploit,
  recordSuspiciousExecution
} = require('../utils/correlationEngine');

// Rolling buffer of recent normalized security events (last 1000)
const eventBuffer = [];

// Helper to access Socket.IO if attached to req.app
function getIo(req) {
  return req.app.get('io') || null;
}

// POST /api/events - Ingest one or multiple events
router.post('/', (req, res) => {
  try {
    const rawPayload = req.body;
    const rawEvents = Array.isArray(rawPayload) ? rawPayload : [rawPayload];

    if (rawEvents.length === 0 || !rawEvents[0]) {
      return res.status(400).json({ success: false, error: 'Empty event payload provided.' });
    }

    const normalizedBatch = [];
    const triggeredIncidents = [];
    const io = getIo(req);

    for (const raw of rawEvents) {
      const event = normalizeEvent(raw);

      // 1. IOC Enrichment
      if (event.sourceIp && event.sourceIp !== '127.0.0.1') {
        const iocMatch = matchIoc(event.sourceIp);
        if (iocMatch.matched) {
          event.iocEnrichment = iocMatch;
          event.severity = 'CRITICAL';
          event.mitreTechnique = iocMatch.mitreTechnique || 'T1071.001 - Application Layer C2 Protocol';
        }
      }

      // 2. Stateful SIEM Correlation Evaluation
      if (event.eventType === EventTypes.AUTH_FAILURE) {
        const inc = recordFailedLogin({
          ip: event.sourceIp,
          email: event.user,
          userAgent: event.details?.userAgent || 'Endpoint Agent',
        });
        if (inc) triggeredIncidents.push(inc);
      } else if (event.eventType === EventTypes.EXPLOIT_PROBE) {
        const inc = recordWebExploit({
          ip: event.sourceIp,
          attackType: event.details?.attackType || 'Web Exploit Probe',
          payload: event.details?.payload || '',
          path: event.details?.path || '/api',
          statusCode: event.details?.statusCode || 200,
        });
        if (inc) triggeredIncidents.push(inc);
      } else if (event.eventType === EventTypes.PROCESS_EXECUTION) {
        const cmd = event.details?.commandLine || '';
        if (cmd.toLowerCase().includes('powershell') || cmd.toLowerCase().includes('-enc') || cmd.includes('certutil')) {
          const inc = recordSuspiciousExecution({
            processName: event.details?.processName || 'powershell.exe',
            commandLine: cmd,
            outboundIp: event.sourceIp,
            pid: event.details?.pid || 1337,
          });
          if (inc) triggeredIncidents.push(inc);
        }
      }

      // Append to rolling buffer
      eventBuffer.unshift(event);
      if (eventBuffer.length > 1000) eventBuffer.pop();

      normalizedBatch.push(event);

      // 3. Real-Time Broadcast
      if (io) {
        io.emit('event:ingested', event);
        if (event.severity === 'CRITICAL' || event.iocEnrichment) {
          io.emit('alert:critical', {
            id: `alt-${Date.now()}`,
            title: `Critical Event [${event.eventType}]: ${event.sourceIp}`,
            severity: 'CRITICAL',
            sourceIp: event.sourceIp,
            timestamp: event.timestamp,
          });
        }
      }
    }

    res.status(202).json({
      success: true,
      processed: normalizedBatch.length,
      incidentsCreated: triggeredIncidents.length,
      incidents: triggeredIncidents,
      events: normalizedBatch.slice(0, 5), // Echo first 5 for confirmation
    });
  } catch (err) {
    console.error('[Events] Ingestion error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/events - Query recent event stream
router.get('/', (req, res) => {
  try {
    const { eventType, severity, source, limit = 50 } = req.query;
    let events = eventBuffer;

    if (eventType && eventType !== 'ALL') {
      events = events.filter(e => e.eventType === eventType.toUpperCase());
    }
    if (severity && severity !== 'ALL') {
      events = events.filter(e => e.severity === severity.toUpperCase());
    }
    if (source && source !== 'ALL') {
      events = events.filter(e => e.source === source);
    }

    const nLimit = Math.min(parseInt(limit, 10) || 50, 200);

    res.json({
      success: true,
      total: events.length,
      events: events.slice(0, nLimit),
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
