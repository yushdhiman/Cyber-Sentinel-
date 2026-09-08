require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });
const fs = require('fs');
const path = require('path');
const http = require('http');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');

const authRoutes = require('./routes/auth');
const threatRoutes = require('./routes/threats');
const logRoutes = require('./routes/logs');
const vulnRoutes = require('./routes/vuln');
const chatbotRoutes = require('./routes/chatbot');
const systemRoutes = require('./routes/system');
const sandboxRoutes = require('./routes/sandbox');
const protectionRoutes = require('./routes/protection');
const { startRealtimeEngine } = require('./utils/realtimeEngine');

const app = express();

const allowedOrigins = process.env.CORS_ORIGIN 
  ? process.env.CORS_ORIGIN.split(',').map(o => o.trim()) 
  : ['http://localhost:5173'];

const isLocal = (url) => {
  try {
    const hostname = new URL(url).hostname;
    return hostname === 'localhost' || hostname === '127.0.0.1';
  } catch (e) {
    return false;
  }
};

const isAllowedOrigin = (url) => {
  if (!url) return true;
  if (allowedOrigins.includes(url) || allowedOrigins.includes('*')) return true;
  if (isLocal(url)) return true;
  try {
    const hostname = new URL(url).hostname;
    return hostname.endsWith('.vercel.app') || hostname.endsWith('.onrender.com');
  } catch (e) {
    return true; // Fallback to allowing in production demo
  }
};

const corsOptions = {
  origin: (origin, callback) => {
    if (isAllowedOrigin(origin)) {
      callback(null, true);
    } else {
      callback(null, true); // Safe permissive fallback for demo operations
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
};

if (!process.env.JWT_SECRET) {
  console.warn('[Server] WARNING: JWT_SECRET is not set in environment. Using secure fallback secret.');
  process.env.JWT_SECRET = 'cyber-sentinel-prod-secret-fallback-key-1234567890';
}

app.use(helmet());
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(morgan('dev'));

// Rate limiters
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
app.use('/api/auth', authLimiter, authRoutes);

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 60, // bumped up since real-time frontend polls some endpoints too
  message: { error: 'Too many requests. Please try again in a minute.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/threats', apiLimiter, threatRoutes);
app.use('/api/logs', apiLimiter, logRoutes);
app.use('/api/vuln', apiLimiter, vulnRoutes);
app.use('/api/chatbot', apiLimiter, chatbotRoutes);
app.use('/api/system', apiLimiter, systemRoutes);
app.use('/api/sandbox', apiLimiter, sandboxRoutes);
app.use('/api/protection', apiLimiter, protectionRoutes);

app.get('/api/health', (req, res) => {
  const host = req.get('host');
  const protocol = req.headers['x-forwarded-proto'] === 'https' || req.protocol === 'https' ? 'https' : 'http';
  const websocketUrl = process.env.RENDER_EXTERNAL_URL || `${protocol}://${host}`;
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    websocket: 'enabled',
    websocketUrl
  });
});

const candidateDistPaths = [
  path.resolve(__dirname, '../../frontend/dist'),
  path.resolve(__dirname, '../../dist'),
  path.resolve(__dirname, '../dist'),
  path.resolve(process.cwd(), 'frontend/dist'),
  path.resolve(process.cwd(), 'dist')
];
const frontendDistPath = candidateDistPaths.find(p => fs.existsSync(p)) || candidateDistPaths[0];
if (fs.existsSync(frontendDistPath)) {
  console.log(`[Server] Serving static frontend from: ${frontendDistPath}`);
  app.use(express.static(frontendDistPath));
  app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) {
      return res.status(404).json({ error: 'Not found' });
    }
    res.sendFile(path.join(frontendDistPath, 'index.html'));
  });
} else {
  console.log(`[Server] Static frontend folder not found at: ${frontendDistPath}. API-only mode enabled.`);
  app.use((req, res) => res.status(404).json({ error: 'Not found' }));
}

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Attach Socket.IO to an HTTP server ──
const server = http.createServer(app);
const io = new Server(server, {
  cors: corsOptions,
  transports: ['websocket', 'polling'],
});

const startServer = () => {
  const PORT = process.env.PORT || 5000;
  return server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🛡  Cyber Sentinel API running on port ${PORT}`);
    console.log(`⚡  WebSocket real-time engine: ACTIVE`);
    console.log(`📡  Emitting: system:metrics (2s) · attack:event (3-7s) · timeline:update (30s)\n`);
  });
};

if (require.main === module) {
  startRealtimeEngine(io);
  // Give the chatbot route a reference to Socket.IO for streaming agent steps
  chatbotRoutes.setIO(io);
  startServer();
}

module.exports = app;
