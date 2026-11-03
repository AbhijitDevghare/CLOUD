try {
  require('dotenv').config();
} catch {
  // dotenv optional when environment variables are injected or defaults used
}

const http = require('http');
const express = require('./utils/expressCompat');
const { initDb, getDbMode } = require('./config/db');
const { initRedis, getRedisMode } = require('./config/redis');
const { enforceIpBlocklist } = require('./middleware/auth');

const authRoutes = require('./routes/authRoutes');
const cloudRoutes = require('./routes/cloudRoutes');
const vulnerabilityRoutes = require('./routes/vulnerabilityRoutes');
const threatRoutes = require('./routes/threatRoutes');
const aiSecurityRoutes = require('./routes/aiSecurityRoutes');
const complianceRoutes = require('./routes/complianceRoutes');
const dashboardRoutes = require('./routes/dashboardRoutes');

const app = express();
const server = http.createServer(app);

// Attach Socket.IO if installed, or lightweight event emitter stub
let io;
try {
  const { Server } = require('socket.io');
  io = new Server(server, {
    cors: {
      origin: '*',
      methods: ['GET', 'POST', 'PATCH', 'DELETE']
    }
  });
  io.on('connection', (socket) => {
    socket.emit('system:connected', {
      message: 'Connected to AegisCloud Real-Time Security Telemetry Stream',
      timestamp: new Date().toISOString()
    });
  });
} catch {
  io = {
    emit: () => {}
  };
}

app.set('io', io);

// Optional Helmet, CORS & Rate Limit middlewares if installed
try {
  const helmet = require('helmet');
  app.use(helmet());
} catch {
  // Security headers applied via Nginx or fallback middleware
}

try {
  const cors = require('cors');
  app.use(cors({ origin: '*' }));
} catch {
  app.use((req, res, next) => {
    if (typeof res.setHeader === 'function') {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    }
    next();
  });
}

if (typeof express.json === 'function') {
  app.use(express.json({ limit: '5mb' }));
}

// Active IP Blocklist Enforcement (Module 5)
app.use(enforceIpBlocklist);

// Health Check Endpoint
app.get('/health', async (req, res) => {
  await initDb();
  await initRedis();
  res.json({
    status: 'UP',
    service: 'aegis-cloud-security-backend',
    databaseMode: getDbMode(),
    redisMode: getRedisMode(),
    timestamp: new Date().toISOString()
  });
});

// Mount All 8 Functional Module Routes + Dashboard
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/cloud', cloudRoutes);
app.use('/api/v1/vulnerabilities', vulnerabilityRoutes);
app.use('/api/v1/threats', threatRoutes);
app.use('/api/v1/ai-security', aiSecurityRoutes);
app.use('/api/v1/compliance', complianceRoutes);
app.use('/api/v1/dashboard', dashboardRoutes);

const PORT = Number(process.env.PORT) || 5000;

async function startServer() {
  await initDb();
  await initRedis();
  return new Promise((resolve) => {
    server.listen(PORT, () => {
      console.log(
        `[AegisCloud Backend] Listening on http://localhost:${PORT} (DB: ${getDbMode()}, Cache: ${getRedisMode()})`
      );
      resolve(server);
    });
  });
}

if (require.main === module) {
  startServer();
}

module.exports = { app, server, startServer };
