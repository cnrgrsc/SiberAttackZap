import { Router, Request, Response } from 'express';
import { ZapProxyService } from '../services/zapProxy.service';
import { PrismaClient } from '@prisma/client';

const router = Router();
const zapService = new ZapProxyService();
const prisma = new PrismaClient();

// GET /health - Health check endpoint
router.get('/', (req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      status: 'OK',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development'
    }
  });
});

// GET /health/zap - ZAP Proxy health check
router.get('/zap', async (req: Request, res: Response) => {
  try {
    const connected = await zapService.checkConnection();
    const status = connected ? await zapService.getStatus() : null;
    
    res.json({
      success: true,
      data: {
        zapConnected: connected,
  zapUrl: process.env.ZAP_PROXY_URL || 'http://zap-api:8080',
        zapStatus: status,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    res.status(502).json({
      success: false,
      error: {
        message: 'ZAP health check failed',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// GET /health/detailed - Detailed system health
router.get('/detailed', async (req: Request, res: Response) => {
  try {
    const zapConnected = await zapService.checkConnection();
    
    res.json({
      success: true,
      data: {
        api: {
          status: 'OK',
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          version: process.env.npm_package_version || '1.0.0'
        },
        zap: {
          connected: zapConnected,
          url: process.env.ZAP_PROXY_URL || 'http://zap-api:8080'
        },
        database: {
          status: 'OK', // Could add actual DB health check here
          type: 'PostgreSQL'
        },
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Health check failed',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// GET /health/db - Basit veritabanı sağlık kontrolü
router.get('/db', async (req: Request, res: Response) => {
  const start = Date.now();
  try {
    // Hafif bir sorgu (Postgres için): SELECT 1
    const sample = await prisma.$queryRaw`SELECT 1 as ok`;
    const duration = Date.now() - start;

    res.json({
      success: true,
      data: {
        connected: true,
        responseTimeMs: duration,
        sample,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    const duration = Date.now() - start;
    res.status(503).json({
      success: false,
      error: {
        message: 'Database connection failed',
        details: error instanceof Error ? error.message : 'Unknown error',
        responseTimeMs: duration,
        timestamp: new Date().toISOString()
      }
    });
  }
});

export default router;

// Note: Prisma client should be disconnected by the app shutdown logic elsewhere (if present).
