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
const incidentRoutes = require('./routes/incidents');
const auditRoutes = require('./routes/audit');
const eventRoutes = require('./routes/events');
const malwareRoutes = require('./routes/malware');
const { startRealtimeEngine } = require('./utils/realtimeEngine');

const app = express();

const allowedOrigins = process.env.CORS_ORIGIN 
  ? process.env.CORS_ORIGIN.split(',').map(o => o.trim()) 
  : ['http://localhost:5173', 'http://localhost:3000', 'http://127.0.0.1:5173'];

const isAllowedOrigin = (origin) => {
  if (!origin) return true; // Allow non-browser agents, CLI tools, server-to-server
  if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) return true;
  // Always allow live deployment domains (Render and Vercel) as well as local development
  if (origin.endsWith('.vercel.app') || origin.endsWith('.onrender.com') || origin.includes('localhost') || origin.includes('127.0.0.1')) {
    return true;
  }
  return false;
};

const corsOptions = {
  origin: (origin, callback) => {
    if (isAllowedOrigin(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS policy violation: Origin '${origin}' is not authorized`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
};

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const { getJwtSecret } = require('./config/jwt');
// Strictly validates JWT_SECRET (throws in production if missing)
getJwtSecret();

app.set('trust proxy', 1);

app.use(helmet());
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(morgan('dev'));

// Assign unique X-Request-ID header to every inbound request for distributed audit tracing
app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || crypto.randomUUID();
  res.setHeader('X-Request-ID', req.id);
  next();
});

// Body-parse error handler: express.json() strict mode rejects bare primitives.
// Without this handler, parse errors fall through to the generic 500 error handler.
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError || err.type === 'entity.parse.failed' || err.status === 400 || err.statusCode === 400) {
    return res.status(400).json({ error: 'Invalid request body: must be a valid JSON object.' });
  }
  next(err);
});

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: (process.env.NODE_ENV === 'test' || process.env.NODE_ENV === 'development') ? 1000 : 50,
  standardHeaders: true,
  legacyHeaders: false
});
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
app.use('/api/incidents', apiLimiter, incidentRoutes);
app.use('/api/audit-logs', apiLimiter, auditRoutes);
app.use('/api/events', apiLimiter, eventRoutes);
app.use('/api/malware', apiLimiter, malwareRoutes);

app.get('/api/health', (req, res) => {
  const host = req.get('host');
  const protocol = req.headers['x-forwarded-proto'] === 'https' || req.protocol === 'https' ? 'https' : 'http';
  const websocketUrl = process.env.RENDER_EXTERNAL_URL || `${protocol}://${host}`;
  const { isPostgresConnected } = require('./data/db');
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    websocket: 'enabled',
    websocketUrl,
    components: {
      database: isPostgresConnected() ? 'connected' : 'offline_file_mode',
      aiCopilot: process.env.GEMINI_API_KEY ? 'agentic' : 'rule_based_offline',
      threatIntel: 'live',
      correlationEngine: 'active',
      realtimeEngine: 'active',
    },
    uptime: process.uptime(),
  });
});

app.get('/api/metrics', (req, res) => {
  const mem = process.memoryUsage();
  const store = require('./data/securityStore');
  const incidentCount = (store.getIncidents ? store.getIncidents() : []).length;
  const blockedIpCount = Object.keys(store.getBlockedIps ? store.getBlockedIps() : {}).length;
  const wsActive = io.engine ? io.engine.clientsCount : 0;

  const metrics = [
    '# HELP cs_uptime_seconds Total process uptime in seconds',
    '# TYPE cs_uptime_seconds gauge',
    `cs_uptime_seconds ${process.uptime().toFixed(2)}`,
    '# HELP cs_memory_heap_used_bytes V8 heap memory used in bytes',
    '# TYPE cs_memory_heap_used_bytes gauge',
    `cs_memory_heap_used_bytes ${mem.heapUsed}`,
    '# HELP cs_memory_heap_total_bytes V8 heap total memory in bytes',
    '# TYPE cs_memory_heap_total_bytes gauge',
    `cs_memory_heap_total_bytes ${mem.heapTotal}`,
    '# HELP cs_ws_connections_active Number of active WebSocket client connections',
    '# TYPE cs_ws_connections_active gauge',
    `cs_ws_connections_active ${wsActive}`,
    '# HELP cs_incidents_total Total number of security incidents recorded',
    '# TYPE cs_incidents_total counter',
    `cs_incidents_total ${incidentCount}`,
    '# HELP cs_firewall_blocked_ips_active Number of actively contained IP addresses',
    '# TYPE cs_firewall_blocked_ips_active gauge',
    `cs_firewall_blocked_ips_active ${blockedIpCount}`,
  ].join('\n');

  res.setHeader('Content-Type', 'text/plain; version=0.0.4');
  res.send(metrics);
});

app.get('/api/health/live', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

app.get('/api/health/ready', async (req, res) => {
  try {
    const { isPostgresConnected, getPool } = require('./data/db');
    let dbStatus = 'offline_file_mode';
    const dbPool = getPool();
    if (dbPool && isPostgresConnected()) {
      await dbPool.query('SELECT 1');
      dbStatus = 'connected';
    }
    return res.json({
      status: 'ready',
      database: dbStatus,
      uptime: process.uptime(),
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    return res.status(503).json({
      status: 'degraded',
      error: err.message,
      timestamp: new Date().toISOString()
    });
  }
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
app.set('io', io);

// Socket.IO authentication middleware: JWT is mandatory — no guest connections allowed
io.use((socket, next) => {
  const rawToken = socket.handshake.auth?.token || socket.handshake.query?.token;
  if (!rawToken) {
    return next(new Error('WS_AUTH_REQUIRED: Authentication token is required to connect'));
  }
  const cleanToken = rawToken.replace(/^Bearer\s+/i, '').trim();
  try {
    const decoded = jwt.verify(cleanToken, getJwtSecret());
    socket.user = decoded;
    // Join role-based room immediately on authentication so RBAC-filtered emits work
    const userRole = (decoded.role || 'ANALYST').toUpperCase();
    socket.join(`role:${userRole}`);
    // All authenticated users receive the shared broadcast room
    socket.join('authenticated');
    return next();
  } catch (err) {
    console.warn(`[RT] Socket rejected — invalid token: ${err.message}`);
    return next(new Error(`WS_AUTH_INVALID: ${err.message}`));
  }
});

const startServer = () => {
  const PORT = process.env.PORT || 5000;
  return server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🛡  Cyber Sentinel API running on port ${PORT}`);
    console.log(`⚡  WebSocket real-time engine: ACTIVE`);
    console.log(`📡  Emitting: system:metrics (2s) · attack:event (3-7s) · timeline:update (30s)\n`);
  });
};

const gracefulShutdown = (signal) => {
  console.log(`\n[Server] Received ${signal}. Shutting down gracefully...`);
  server.close(() => {
    console.log('[Server] HTTP and Socket.IO server closed.');
    const { getPool, closeDb } = require('./data/db');
    const dbPool = getPool();
    if (dbPool) {
      closeDb().then(() => {
        console.log('[Server] PostgreSQL pool closed.');
        process.exit(0);
      }).catch(() => process.exit(0));
    } else {
      process.exit(0);
    }
  });
  setTimeout(() => {
    console.error('[Server] Forced shutdown after timeout.');
    process.exit(1);
  }, 5000).unref();
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

if (require.main === module) {
  startRealtimeEngine(io);
  // Give the chatbot route a reference to Socket.IO for streaming agent steps
  chatbotRoutes.setIO(io);
  startServer();
}

module.exports = app;
