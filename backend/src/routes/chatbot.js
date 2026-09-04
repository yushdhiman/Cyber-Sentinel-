const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { respond, clearSession, getSessionStats } = require('../utils/chatbot');

const router = express.Router();
router.use(requireAuth);

// Shared io instance — set by server.js after Socket.IO initializes
let _io = null;
function setIO(io) { _io = io; }

/**
 * POST /api/chatbot/message
 * Body: { message: string, sessionId?: string }
 * Returns: { reply, steps, toolsUsed, sessionId, mode }
 *
 * Streams intermediate agent steps to the client via Socket.IO event:
 *   "agent:step" → { type, content?, tool?, result?, toolsUsed?, iteration }
 */
router.post('/message', async (req, res) => {
  const { message, sessionId: clientSessionId } = req.body;

  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'message (string) is required' });
  }

  // Use provided session ID or generate a stable one per user
  const userId = req.user?.id || req.user?.email || 'anonymous';
  const sessionId = clientSessionId || `user-${userId}`;

  try {
    // Build a Socket.IO emitter for live agent step streaming
    const emitStep = _io
      ? (step) => {
          _io.emit(`agent:step:${sessionId}`, step);
          // Also emit on the generic channel for clients that subscribed globally
          _io.emit('agent:step', { sessionId, ...step });
        }
      : null;

    const { reply, steps, toolsUsed } = await respond(message, sessionId, emitStep);

    const mode = process.env.GEMINI_API_KEY ? 'agentic' : 'offline';

    res.json({
      reply,
      steps,
      toolsUsed,
      sessionId,
      mode,
    });
  } catch (error) {
    console.error('[Chatbot Route] Error:', error);
    res.status(500).json({ error: 'Failed to process message' });
  }
});

/**
 * DELETE /api/chatbot/session/:sessionId
 * Clears the conversation history for a session.
 */
router.delete('/session/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  clearSession(sessionId);
  res.json({ success: true, message: `Session ${sessionId} cleared.` });
});

/**
 * GET /api/chatbot/stats
 * Returns session stats for debugging.
 */
router.get('/stats', (req, res) => {
  res.json(getSessionStats());
});

module.exports = router;
module.exports.setIO = setIO;
