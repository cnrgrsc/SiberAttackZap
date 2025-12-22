import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';

// Load environment variables from .env.development
dotenv.config({ path: process.env.NODE_ENV === 'development' ? '.env.development' : '.env' });

import { errorHandler } from './middleware/errorHandler';
import { notFoundHandler } from './middleware/notFoundHandler';
import { validateEnv } from './utils/validateEnv';

// Routes
import { createScanRoutes } from './routes/scan.routes';
import { createZapRoutes } from './routes/zap.routes';
import { initializeMobSFRoutes } from './routes/mobsf.routes';
import reportRoutes from './routes/report.routes';
import healthRoutes from './routes/health.routes';
import simpleAuthRoutes from './routes/simple-auth.routes';
import internalRoutes from './routes/internal.routes';
import manualScanRoutes from './routes/manual-scan.routes';
import zapAdvancedRoutes from './routes/zap-advanced.routes';
import cicdRoutes from './routes/cicd.routes';
import adminSettingsRoutes from './routes/admin-settings.routes';
import roleManagementRoutes from './routes/role-management.routes';
import groupManagementRoutes from './routes/group-management.routes';
import userProfileRoutes from './routes/user-profile.routes';
import notificationRoutes from './routes/notifications.routes';
import technologyRoutes from './routes/technology.routes';
import lighthouseRoutes from './routes/lighthouse.routes';
import trivyRoutes from './routes/trivy.routes';
import { settingsService } from './services/settingsService';

// Load environment variables: prefer .env.local (ignored in repo), then fall back to .env
// This ensures deployments that don't have a private .env.local file still pick up values from .env
dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

// Validate environment variables
// validateEnv(); // Temporarily disabled for local testing

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production'
      ? function (origin, callback) {
        // İç ağ IP aralıkları
        const allowedRanges = [
          /^http:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/,     // 10.x.x.x
          /^http:\/\/172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}(:\d+)?$/, // 172.16-31.x.x
          /^http:\/\/192\.168\.\d{1,3}\.\d{1,3}(:\d+)?$/,        // 192.168.x.x
          /^https:\/\/.*\.ibb\.gov\.tr$/,                        // İBB domainleri
          /^http:\/\/localhost(:\d+)?$/                          // localhost
        ];

        if (!origin) return callback(null, true); // Same-origin requests

        const isAllowed = allowedRanges.some(range => range.test(origin));
        callback(null, isAllowed);
      }
      : ['http://localhost:5001', 'http://localhost:5002', 'http://localhost:5003', 'http://localhost:3000', 'http://localhost:3001', 'http://siberzed-frontend:3001', 'http://10.5.63.219:5002'],
    credentials: true
  }
});
const PORT = process.env.PORT || 5001; // Backend port

// İç ağ için optimize edilmiş rate limiting (100 kullanıcı için) - Development için artırıldı
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 dakika
  max: parseInt(process.env.API_RATE_LIMIT || '2000'), // Kullanıcı başına 2000 istek/10dk (Development için artırıldı)
  message: {
    error: 'Çok fazla istek gönderildi. Lütfen 10 dakika sonra tekrar deneyin.',
    code: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false,
  // IP bazlı tracking
  keyGenerator: (req) => {
    return req.ip || req.connection.remoteAddress || 'unknown';
  }
});

// Middleware
app.use(limiter);

// İç ağ için güvenlik headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "fonts.googleapis.com"],
      fontSrc: ["'self'", "fonts.gstatic.com"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "*.ibb.gov.tr"],
      connectSrc: ["'self'", "ws:", "wss:", "*.ibb.gov.tr"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? function (origin, callback) {
      // İç ağ IP aralıkları
      const allowedRanges = [
        /^http:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/,
        /^http:\/\/172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}(:\d+)?$/,
        /^http:\/\/192\.168\.\d{1,3}\.\d{1,3}(:\d+)?$/,
        /^https:\/\/.*\.ibb\.gov\.tr$/,
        /^http:\/\/localhost(:\d+)?$/,
        /^http:\/\/127\.0\.0\.1(:\d+)?$/
      ];

      if (!origin) return callback(null, true);

      const isAllowed = allowedRanges.some(range => range.test(origin));
      callback(null, isAllowed);
    }
    : ['http://localhost:5001', 'http://localhost:5002', 'http://localhost:5003', 'http://localhost:3000', 'http://localhost:3001', 'http://siberzed-frontend:3001', 'http://10.5.63.219:5002', 'http://127.0.0.1:5002', 'http://127.0.0.1:5001', 'http://127.0.0.1:3000'],
  credentials: true
}));
app.use(compression());
app.use(morgan('combined'));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Increase server timeout and header size
server.timeout = 300000; // 5 minutes
server.maxHeadersCount = 0; // No limit

// Health check
app.use('/health', healthRoutes);

// API Routes
app.use('/api/simple-auth', simpleAuthRoutes);
app.use('/api/scans', createScanRoutes(io));
app.use('/api/zap', createZapRoutes(io)); // ZAP service - now enabled for Docker
app.use('/api/zap-advanced', zapAdvancedRoutes); // ZAP advanced service - now enabled for Docker
app.use('/api/mobsf', initializeMobSFRoutes(io)); // MobSF service - now enabled for Docker
app.use('/api/reports', reportRoutes);
app.use('/api/internal', internalRoutes);
app.use('/api/manual-scan', manualScanRoutes);
app.use('/api/cicd', cicdRoutes);
app.use('/api/admin', adminSettingsRoutes);
app.use('/api/admin', roleManagementRoutes); // RBAC: Rol yönetimi
app.use('/api/admin', groupManagementRoutes); // RBAC: Grup yönetimi
app.use('/api/user', userProfileRoutes); // Kullanıcı profil ayarları
app.use('/api/notifications', notificationRoutes); // Bildirimler
app.use('/api/technology', technologyRoutes); // Teknoloji tarayıcısı
app.use('/api/lighthouse', lighthouseRoutes); // Lighthouse tarayıcısı
app.use('/api/trivy', trivyRoutes); // Trivy güvenlik tarayıcısı

// Error handling middleware
app.use(notFoundHandler);
app.use(errorHandler);

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log(`🔌 WebSocket client connected: ${socket.id} from ${socket.handshake.address}`);

  socket.on('disconnect', () => {
    console.log(`🔌 WebSocket client disconnected: ${socket.id}`);
  });

  // Join scan room for real-time updates
  socket.on('join-scan', (scanId) => {
    console.log(`📡 Client ${socket.id} joined scan room: scan-${scanId}`);
    socket.join(`scan-${scanId}`);
  });

  // Leave scan room
  socket.on('leave-scan', (scanId) => {
    console.log(`📡 Client ${socket.id} left scan room: scan-${scanId}`);
    socket.leave(`scan-${scanId}`);
  });
});

// Initialize system settings
settingsService.initializeDefaultSettings();

// 🔧 Cleanup stale RUNNING scans on startup
async function cleanupStaleScans() {
  try {
    const { PrismaClient } = await import('@prisma/client');
    const prisma = new PrismaClient();

    // Find all RUNNING scans
    const runningScans = await prisma.scan.findMany({
      where: { status: 'RUNNING' }
    });

    if (runningScans.length > 0) {

      // Update all RUNNING scans to STOPPED
      const result = await prisma.scan.updateMany({
        where: { status: 'RUNNING' },
        data: {
          status: 'STOPPED',
          completedAt: new Date()
        }
      });

    } else {
    }

    await prisma.$disconnect();
  } catch (error) {
    console.error('❌ Error cleaning up stale scans:', error);
  }
}

// Start server
server.listen(PORT, async () => {
  console.log(`\n🚀 ====================================`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🌐 Server running on port: ${PORT}`);
  console.log(`🔗 Backend API: http://localhost:${PORT}/api`);
  console.log(`🔗 MobSF URL: ${process.env.MOBSF_BASE_URL || 'http://mobsf:8000'}`);
  console.log(`⚙️ System settings initialized`);
  console.log(`🛡️ RBAC routes: /api/admin/roles, /api/admin/groups, /api/admin/permissions`);
  console.log(`====================================\n`);

  // Cleanup stale scans
  await cleanupStaleScans();

  // Initialize Scan Queue Service with Socket.IO
  const { scanQueueService } = await import('./services/scanQueue.service');
  scanQueueService.on('scanQueued', (data: any) => {
    console.log(`📋 Scan queued:`, data);
    io.emit('scanQueued', data);
  });

  scanQueueService.on('scanDequeued', (data: any) => {
    console.log(`▶️ Scan dequeued:`, data);
    io.emit('scanDequeued', data);
  });

  console.log(`📋 Scan Queue Service initialized`);
  console.log(`⚙️ Max concurrent scans: ${scanQueueService.getConfig().maxConcurrentScans}`);
});

export default app;
export { io };
