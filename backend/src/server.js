require('dotenv').config();
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

if (!process.env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is not set. Copy .env.example to .env and set a real secret.');
  process.exit(1);
}

app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN || 'http://localhost:5173', credentials: true }));
app.use(express.json({ limit: '1mb' }));
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

app.get('/api/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString(), websocket: 'enabled' }));

app.use((req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Attach Socket.IO to an HTTP server ──
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
    methods: ['GET', 'POST'],
    credentials: true,
  },
  transports: ['websocket', 'polling'],
});

// Start real-time broadcast engine
startRealtimeEngine(io);

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`\n🛡  Cyber Sentinel API running on port ${PORT}`);
  console.log(`⚡  WebSocket real-time engine: ACTIVE`);
  console.log(`📡  Emitting: system:metrics (2s) · attack:event (3-7s) · timeline:update (30s)\n`);
});
