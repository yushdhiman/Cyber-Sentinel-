const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { respond } = require('../utils/chatbot');
const { collectSystemMetrics } = require('../utils/systemMetrics');

const router = express.Router();
router.use(requireAuth);

router.post('/message', async (req, res) => {
  const { message } = req.body;
  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'message (string) is required' });
  }
  try {
    // Generate real-time system context to feed to the chatbot agent
    let systemContext = null;
    try {
      const metrics = global.lastSystemMetrics || collectSystemMetrics();
      const totalAttacksToday = require('../utils/realtimeEngine').getTimeline().reduce((s, b) => s + b.attacks, 0);
      systemContext = {
        threatScore: metrics.threatScore,
        riskLevel: metrics.riskLevel,
        cpuUsage: metrics.cpu.usagePercent,
        memoryUsage: metrics.memory.usagePercent,
        networkHealth: Math.max(0, Math.min(100, 100 - metrics.cpu.usagePercent * 0.4 - metrics.memory.usagePercent * 0.3)),
        hostname: metrics.hostname,
        platform: metrics.platform,
        uptimeDays: metrics.uptimeDays,
        activeDevices: metrics.linkedDevices.filter(d => !d.internal).length,
        findings: metrics.findings,
      };
    } catch (err) {
      console.warn('[Chatbot] Failed to fetch system context:', err.message);
    }

    const reply = await respond(message, systemContext);
    res.json({ reply });
  } catch (error) {
    console.error('Error in chatbot route:', error);
    res.status(500).json({ error: 'Failed to process message' });
  }
});

module.exports = router;

