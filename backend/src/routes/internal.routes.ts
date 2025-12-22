import express from 'express';
import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

const router = express.Router();
const prisma = new PrismaClient();

// İç ağ sistem durumu
router.get('/internal-status', async (req: Request, res: Response) => {
  try {
    const status = {
      timestamp: new Date().toISOString(),
      environment: 'internal-network',
      server: {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        cpu: process.cpuUsage(),
        platform: process.platform,
        nodeVersion: process.version,
        pid: process.pid
      },
      network: {
        hostname: require('os').hostname(),
        networkInterfaces: require('os').networkInterfaces(),
        totalMemory: require('os').totalmem(),
        freeMemory: require('os').freemem(),
        loadAverage: require('os').loadavg()
      },
      database: {
        status: 'connected',
        type: 'PostgreSQL',
        url: process.env.DATABASE_URL ? 'configured' : 'not-configured'
      },
      zap: {
        url: process.env.ZAP_PROXY_URL || 'not-configured',
        status: 'unknown'
      },
      activeConnections: 0,
      maxUsers: 100,
      currentLoad: 0
    };

    res.json({
      success: true,
      data: status
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Internal status check failed',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// İç ağ kullanıcı istatistikleri
router.get('/user-stats', async (req: Request, res: Response) => {
  try {
    // Gerçek kullanıcı verilerini al
    const totalUsers = await prisma.user.count();
    const activeUsers = await prisma.user.count({
      where: { isActive: true }
    });

    const stats = {
      totalUsers,
      maxUsers: 100,
      activeUsers,
      onlineUsers: 0, // Socket bağlantıları ile hesaplanacak
      peakUsage: 0,
      averageUsage: 0,
      departments: {
        'IT': 0,
        'Security': 0,
        'Management': 0,
        'Operations': 0,
        'Other': 0
      },
      dailyLogins: 0,
      weeklyLogins: 0,
      monthlyLogins: 0
    };

    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to get user statistics',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// İç ağ performans metrikleri
router.get('/performance', async (req: Request, res: Response) => {
  try {
    const metrics = {
      responseTime: {
        average: 0,
        p95: 0,
        p99: 0
      },
      throughput: {
        requestsPerSecond: 0,
        scansPerHour: 0,
        reportsGenerated: 0
      },
      resources: {
        cpuUsage: 0,
        memoryUsage: 0,
        diskUsage: 0,
        networkTraffic: 0
      },
      errors: {
        rate: 0,
        total: 0,
        types: {
          'connection': 0,
          'timeout': 0,
          'validation': 0,
          'internal': 0
        }
      }
    };

    res.json({
      success: true,
      data: metrics
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to get performance metrics',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// Test kullanıcısı oluşturma endpoint'i
router.post('/create-test-user', async (req: Request, res: Response) => {
  try {
    // Önce var olan kullanıcıyı kontrol et
    const existingUser = await prisma.user.findUnique({
      where: { username: 'caner.guresci' }
    });

    if (existingUser) {
      return res.json({
        success: true,
        message: 'User already exists',
        user: existingUser
      });
    }

    // Yeni kullanıcı oluştur
    const user = await prisma.user.create({
      data: {
        username: 'caner.guresci',
        firstName: 'Caner',
        lastName: 'Güreşci',
        email: 'caner.guresci@ibb.gov.tr',
        role: 'admin',
        department: 'IT Security',
        isActive: true,
        ldapVerified: false
      }
    });

    res.json({
      success: true,
      message: 'User created successfully',
      user: user
    });

  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to create user',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

export default router;
