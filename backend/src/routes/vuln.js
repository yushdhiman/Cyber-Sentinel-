const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { scanConfig } = require('../utils/scanner');

const router = express.Router();
router.use(requireAuth);

router.post('/scan', (req, res) => {
  const config = req.body || {};
  const result = scanConfig(config);
  global.lastScanResult = result; // cache latest scan report globally
  res.json(result);
});

module.exports = router;
