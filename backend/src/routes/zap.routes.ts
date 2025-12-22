import { Router, Request, Response } from 'express';
import { ZapProxyService, ScanWorkflowOptions } from '../services/zapProxy.service';
import { v4 as uuidv4 } from 'uuid';
import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken';
import { emailService } from '../services/email.service';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Auth middleware
const requireAuth = (req: any, res: Response, next: any) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ success: false, message: 'Token bulunamadı' });
    }
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Geçersiz token' });
  }
};

export const createZapRoutes = (io?: any) => {
  const router = Router();
  const zapService = new ZapProxyService(io);
  const prisma = new PrismaClient();

  // GET /api/zap/status - Get ZAP Proxy status
  router.get('/status', async (req: Request, res: Response) => {
    try {
      const status = await zapService.getStatus();
      res.json({
        success: true,
        data: status
      });
    } catch (error) {
      res.status(502).json({
        success: false,
        error: {
          message: 'ZAP Proxy service unavailable',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/connection - Check ZAP connection
  router.get('/connection', async (req: Request, res: Response) => {
    try {
      const connected = await zapService.checkConnection();
      res.json({
        success: true,
        data: {
          connected,
          url: process.env.ZAP_PROXY_URL
        }
      });
    } catch (error) {
      res.status(502).json({
        success: false,
        error: {
          message: 'Failed to check ZAP connection',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/alerts - Get all alerts
  router.get('/alerts', async (req: Request, res: Response) => {
    try {
      const { baseUrl } = req.query;
      const alerts = await zapService.getAlerts(baseUrl as string);
      res.json({
        success: true,
        data: alerts
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get alerts',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/spider/start - Start spider scan
  router.post('/spider/start', async (req: Request, res: Response): Promise<void> => {
    try {
      const { targetUrl, maxChildren } = req.body;

      if (!targetUrl) {
        res.status(400).json({
          success: false,
          error: { message: 'Target URL is required' }
        });
        return;
      }

      const scanId = await zapService.startSpider(targetUrl, maxChildren);
      res.json({
        success: true,
        data: { scanId }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to start spider',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/spider/status/:scanId? - Get spider status
  router.get('/spider/status/:scanId?', async (req: Request, res: Response) => {
    try {
      const { scanId } = req.params;
      const status = await zapService.getSpiderStatus(scanId);
      res.json({
        success: true,
        data: status
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get spider status',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/activescan/start - Start active scan
  router.post('/activescan/start', async (req: Request, res: Response): Promise<void> => {
    try {
      const { targetUrl, ...options } = req.body;

      if (!targetUrl) {
        res.status(400).json({
          success: false,
          error: { message: 'Target URL is required' }
        });
        return;
      }

      const scanId = await zapService.startActiveScan(targetUrl, options);
      res.json({
        success: true,
        data: { scanId }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to start active scan',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/activescan/status/:scanId? - Get active scan status
  router.get('/activescan/status/:scanId?', async (req: Request, res: Response) => {
    try {
      const { scanId } = req.params;
      const status = await zapService.getActiveScanStatus(scanId);
      res.json({
        success: true,
        data: status
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get active scan status',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/stop - Stop all scans
  router.post('/stop', async (req: Request, res: Response) => {
    try {
      await zapService.stopAllScans();
      res.json({
        success: true,
        data: { message: 'All scans stopped' }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to stop scans',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/clear - Clear ZAP session
  router.post('/clear', async (req: Request, res: Response) => {
    try {
      await zapService.clearSession();
      res.json({
        success: true,
        data: { message: 'Session cleared' }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to clear session',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // AJAX Spider endpoints
  // POST /api/zap/ajaxspider/start - Start AJAX Spider
  router.post('/ajaxspider/start', async (req: Request, res: Response): Promise<void> => {
    try {
      const { targetUrl, inScope } = req.body;

      if (!targetUrl) {
        res.status(400).json({
          success: false,
          error: { message: 'Target URL is required' }
        });
        return;
      }

      await zapService.startAjaxSpider(targetUrl, inScope);
      res.json({
        success: true,
        data: { message: 'AJAX Spider started successfully' }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to start AJAX spider',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/ajaxspider/status - Get AJAX Spider status
  router.get('/ajaxspider/status', async (req: Request, res: Response) => {
    try {
      const status = await zapService.getAjaxSpiderStatus();
      res.json({
        success: true,
        data: status
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get AJAX spider status',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/ajaxspider/stop - Stop AJAX Spider
  router.post('/ajaxspider/stop', async (req: Request, res: Response) => {
    try {
      await zapService.stopAjaxSpider();
      res.json({
        success: true,
        data: { message: 'AJAX Spider stopped' }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to stop AJAX spider',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // Core endpoints
  // GET /api/zap/core/urls - Get all URLs
  router.get('/core/urls', async (req: Request, res: Response) => {
    try {
      const { baseUrl } = req.query;
      const urls = await zapService.getUrls(baseUrl as string);
      res.json({
        success: true,
        data: { urls }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get URLs',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/core/sites - Get all sites
  router.get('/core/sites', async (req: Request, res: Response) => {
    try {
      const sites = await zapService.getSites();
      res.json({
        success: true,
        data: { sites }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get sites',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/core/hosts - Get all hosts
  router.get('/core/hosts', async (req: Request, res: Response) => {
    try {
      const hosts = await zapService.getHosts();
      res.json({
        success: true,
        data: { hosts }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get hosts',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // Context management
  // GET /api/zap/context/list - Get all contexts
  router.get('/context/list', async (req: Request, res: Response) => {
    try {
      const contexts = await zapService.getContexts();
      res.json({
        success: true,
        data: contexts
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get contexts',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/context/create - Create new context
  router.post('/context/create', async (req: Request, res: Response): Promise<void> => {
    try {
      const { contextName } = req.body;

      if (!contextName) {
        res.status(400).json({
          success: false,
          error: { message: 'Context name is required' }
        });
        return;
      }

      const contextId = await zapService.createContext(contextName);
      res.json({
        success: true,
        data: { contextId, message: 'Context created successfully' }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to create context',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // Advanced configuration endpoints
  // GET /api/zap/pscan/config - Get passive scan configuration
  router.get('/pscan/config', async (req: Request, res: Response) => {
    try {
      const config = await zapService.getPscanConfig();
      res.json({
        success: true,
        data: config
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get passive scan config',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/pscan/enable-all - Enable all passive scan rules
  router.post('/pscan/enable-all', async (req: Request, res: Response) => {
    try {
      await zapService.enableAllPscanRules();
      res.json({
        success: true,
        data: { message: 'All passive scan rules enabled' }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to enable passive scan rules',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/authentication/methods - Get authentication methods
  router.get('/authentication/methods', async (req: Request, res: Response) => {
    try {
      const methods = await zapService.getAuthenticationMethods();
      res.json({
        success: true,
        data: methods
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get authentication methods',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/sessions/http - Get HTTP sessions
  router.get('/sessions/http', async (req: Request, res: Response) => {
    try {
      const sessions = await zapService.getHttpSessions();
      res.json({
        success: true,
        data: sessions
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get HTTP sessions',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/technology/detect - Technology detection (Wappalyzer-like)
  router.post('/technology/detect', async (req: Request, res: Response): Promise<void> => {
    try {
      const { targetUrl } = req.body;

      if (!targetUrl) {
        res.status(400).json({
          success: false,
          error: { message: 'Target URL is required' }
        });
        return;
      }

      const result = await zapService.startTechnologyScan(targetUrl);
      console.log('🔧 Technology scan result from ZAP service:', JSON.stringify(result, null, 2));

      res.json({
        success: true,
        data: result
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to detect technologies',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/quickstart/launch - Quick start launch
  router.post('/quickstart/launch', async (req: Request, res: Response): Promise<void> => {
    try {
      const { url } = req.body;

      if (!url) {
        res.status(400).json({
          success: false,
          error: { message: 'URL is required' }
        });
        return;
      }

      const result = await zapService.quickStartLaunch(url);
      res.json({
        success: true,
        data: result
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to quick start launch',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // ========================================
  // ADVANCED WORKFLOW ENDPOINTS
  // Based on Python FastAPI implementation
  // ========================================

  // POST /api/zap/workflow/start - Start complete automated workflow
  router.post('/workflow/start', requireAuth, async (req: any, res: Response): Promise<void> => {
    try {
      const options: ScanWorkflowOptions = req.body;
      const userId = req.user?.id; // Get user ID from authenticated request

      if (!options.targetUrl) {
        res.status(400).json({
          success: false,
          error: { message: 'Target URL is required' }
        });
        return;
      }

      const workflowId = uuidv4();
      const scanId = uuidv4();

      // Create scan record in database with environment config and creatorId
      const scan = await prisma.scan.create({
        data: {
          id: scanId,
          name: options.targetUrl,
          targetUrl: options.targetUrl,
          scanType: 'AUTOMATED',
          status: 'RUNNING',
          zapSessionId: workflowId,
          environment: options.environment || 'TEST',
          aggressiveness: options.aggressiveness || 'MEDIUM',
          safeMode: options.safeMode || false,
          // 📧 Email bildirimleri için kullanıcı ilişkisi
          ...(userId ? { creator: { connect: { id: userId } } } : {}),
          scanConfig: options as any,
          reportSettings: {
            format: options.reportFormat || 'HTML',
            includeScreenshots: true,
            includeRecommendations: true
          } as any
        }
      });

      console.log(`🎯 Created scan ${scanId} with environment: ${options.environment || 'TEST'}, aggressiveness: ${options.aggressiveness || 'MEDIUM'}`);
      console.log(`📧 Scan creator info: userId=${userId || 'NULL'}, scan.createdBy=${scan.createdBy || 'NULL'}`);

      // Tarama başladığında email gönder
      try {
        await emailService.sendScanStartedEmail(scan.id);
        console.log('📧 Scan started email sent');
      } catch (emailError) {
        console.error('⚠️ Failed to send scan started email:', emailError);
      }

      // Start workflow in background with scanId
      zapService.startCompleteWorkflow(workflowId, options, scan.id).catch(error => {
        console.error(`Workflow ${workflowId} failed:`, error);
        // Update scan status to failed
        prisma.scan.update({
          where: { id: scan.id },
          data: { status: 'FAILED', completedAt: new Date() }
        }).catch(dbError => console.error('Error updating scan status:', dbError));
      });

      res.json({
        success: true,
        data: {
          workflowId,
          scanId: scan.id,
          message: 'Comprehensive security scan workflow started',
          targetUrl: options.targetUrl
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to start workflow',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/workflow/:workflowId/progress - Get workflow progress
  router.get('/workflow/:workflowId/progress', requireAuth, async (req: Request, res: Response) => {
    try {
      const { workflowId } = req.params;
      const progress = await zapService.getWorkflowProgress(workflowId);

      if (!progress) {
        res.status(404).json({
          success: false,
          error: { message: 'Workflow not found' }
        });
        return;
      }

      res.json({
        success: true,
        data: progress
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get workflow progress',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/workflow/:workflowId/stop - Stop workflow
  router.post('/workflow/:workflowId/stop', requireAuth, async (req: Request, res: Response) => {
    try {
      const { workflowId } = req.params;
      await zapService.stopWorkflow(workflowId);

      res.json({
        success: true,
        data: { message: 'Workflow stopped successfully' }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to stop workflow',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/workflow/:workflowId/pause - Pause workflow
  router.post('/workflow/:workflowId/pause', requireAuth, async (req: Request, res: Response) => {
    try {
      const { workflowId } = req.params;
      await zapService.pauseWorkflow(workflowId);

      res.json({
        success: true,
        data: { message: 'Workflow paused successfully' }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to pause workflow',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/workflow/:workflowId/resume - Resume workflow
  router.post('/workflow/:workflowId/resume', requireAuth, async (req: Request, res: Response) => {
    try {
      const { workflowId } = req.params;
      await zapService.resumeWorkflow(workflowId);

      res.json({
        success: true,
        data: { message: 'Workflow resumed successfully' }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to resume workflow',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/scan/stop-all - Stop all ZAP scans
  router.post('/scan/stop-all', requireAuth, async (req: Request, res: Response) => {
    try {
      await zapService.stopAllScans();

      res.json({
        success: true,
        data: { message: 'All scans stopped successfully' }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to stop all scans',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/scan/spider/stop - Stop spider scan
  router.post('/scan/spider/stop', requireAuth, async (req: Request, res: Response) => {
    try {
      const { scanId } = req.body;
      await zapService.stopSpider(scanId);

      res.json({
        success: true,
        data: { message: 'Spider scan stopped successfully' }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to stop spider scan',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/scan/ajax-spider/stop - Stop ajax spider scan
  router.post('/scan/ajax-spider/stop', requireAuth, async (req: Request, res: Response) => {
    try {
      await zapService.stopAjaxSpider();

      res.json({
        success: true,
        data: { message: 'Ajax spider scan stopped successfully' }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to stop ajax spider scan',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/scan/active/stop - Stop active scan
  router.post('/scan/active/stop', requireAuth, async (req: Request, res: Response) => {
    try {
      const { scanId } = req.body;
      await zapService.stopActiveScan(scanId);

      res.json({
        success: true,
        data: { message: 'Active scan stopped successfully' }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to stop active scan',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/scan/active/pause - Pause active scan
  router.post('/scan/active/pause', requireAuth, async (req: Request, res: Response) => {
    try {
      const { scanId } = req.body;
      await zapService.pauseActiveScan(scanId);

      res.json({
        success: true,
        data: { message: 'Active scan paused successfully' }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to pause active scan',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/scan/active/resume - Resume active scan
  router.post('/scan/active/resume', requireAuth, async (req: Request, res: Response) => {
    try {
      const { scanId } = req.body;
      await zapService.resumeActiveScan(scanId);

      res.json({
        success: true,
        data: { message: 'Active scan resumed successfully' }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to resume active scan',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/statistics - Get comprehensive scan statistics
  router.get('/statistics', async (req: Request, res: Response) => {
    try {
      const statistics = await zapService.getScanStatistics();
      res.json({
        success: true,
        data: statistics
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get scan statistics',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/analysis/vulnerability - Advanced vulnerability analysis
  router.get('/analysis/vulnerability', async (req: Request, res: Response) => {
    try {
      const analysis = await zapService.getVulnerabilityAnalysis();
      res.json({
        success: true,
        data: analysis
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get vulnerability analysis',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/alerts/risk/:riskLevel? - Get alerts filtered by risk level
  router.get('/alerts/risk/:riskLevel?', async (req: Request, res: Response) => {
    try {
      const { riskLevel } = req.params;
      const validRisks = ['High', 'Medium', 'Low', 'Informational'];

      if (riskLevel && !validRisks.includes(riskLevel)) {
        res.status(400).json({
          success: false,
          error: { message: 'Invalid risk level. Must be one of: High, Medium, Low, Informational' }
        });
        return;
      }

      const alertsData = await zapService.getAlertsByRisk(riskLevel as any);
      res.json({
        success: true,
        data: alertsData
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get alerts by risk',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/spider/progress/:scanId - Get detailed spider progress
  router.get('/spider/progress/:scanId', async (req: Request, res: Response) => {
    try {
      const { scanId } = req.params;
      const progress = await zapService.getSpiderProgress(scanId);
      res.json({
        success: true,
        data: progress
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get spider progress',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/ajaxspider/progress - Get detailed AJAX spider progress
  router.get('/ajaxspider/progress', async (req: Request, res: Response) => {
    try {
      const progress = await zapService.getAjaxSpiderProgress();
      res.json({
        success: true,
        data: progress
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get AJAX spider progress',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/activescan/progress/:scanId - Get detailed active scan progress
  router.get('/activescan/progress/:scanId', async (req: Request, res: Response) => {
    try {
      const { scanId } = req.params;
      const progress = await zapService.getActiveScanProgress(scanId);
      res.json({
        success: true,
        data: progress
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get active scan progress',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/context/create-with-url - Create context with URL inclusion
  router.post('/context/create-with-url', async (req: Request, res: Response): Promise<void> => {
    try {
      const { url } = req.body;

      if (!url) {
        res.status(400).json({
          success: false,
          error: { message: 'URL is required' }
        });
        return;
      }

      const contextId = await zapService.createContextWithUrl(url);
      res.json({
        success: true,
        data: {
          contextId,
          message: 'Context created with URL inclusion',
          url
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to create context with URL',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/spider/advanced - Start advanced spider with options
  router.post('/spider/advanced', async (req: Request, res: Response): Promise<void> => {
    try {
      const { targetUrl, ...options } = req.body;

      if (!targetUrl) {
        res.status(400).json({
          success: false,
          error: { message: 'Target URL is required' }
        });
        return;
      }

      const scanId = await zapService.startSpiderAdvanced(targetUrl, options);
      res.json({
        success: true,
        data: {
          scanId,
          targetUrl,
          options,
          message: 'Advanced spider started successfully'
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to start advanced spider',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/ajaxspider/advanced - Start advanced AJAX spider
  router.post('/ajaxspider/advanced', async (req: Request, res: Response): Promise<void> => {
    try {
      const { targetUrl, ...options } = req.body;

      if (!targetUrl) {
        res.status(400).json({
          success: false,
          error: { message: 'Target URL is required' }
        });
        return;
      }

      await zapService.startAjaxSpiderAdvanced(targetUrl, options);
      res.json({
        success: true,
        data: {
          targetUrl,
          options,
          message: 'Advanced AJAX spider started successfully'
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to start advanced AJAX spider',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/activescan/advanced - Start advanced active scan
  router.post('/activescan/advanced', async (req: Request, res: Response): Promise<void> => {
    try {
      const { targetUrl, ...options } = req.body;

      if (!targetUrl) {
        res.status(400).json({
          success: false,
          error: { message: 'Target URL is required' }
        });
        return;
      }

      const scanId = await zapService.startActiveScanAdvanced(targetUrl, options);
      res.json({
        success: true,
        data: {
          scanId,
          targetUrl,
          options,
          message: 'Advanced active scan started successfully'
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to start advanced active scan',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/reports/advanced/:format - Generate enhanced reports
  router.get('/reports/advanced/:format', async (req: Request, res: Response) => {
    try {
      const { format } = req.params;
      const validFormats = ['html', 'xml', 'json', 'md'];

      if (!validFormats.includes(format)) {
        res.status(400).json({
          success: false,
          error: { message: 'Invalid format. Must be one of: html, xml, json, md' }
        });
        return;
      }

      const report = await zapService.generateAdvancedReport(format as any);

      // Set appropriate content type
      const contentTypes = {
        html: 'text/html',
        xml: 'application/xml',
        json: 'application/json',
        md: 'text/markdown'
      };

      res.setHeader('Content-Type', contentTypes[format as keyof typeof contentTypes]);

      if (format === 'json') {
        res.json({
          success: true,
          data: report
        });
      } else {
        res.send(report);
      }
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to generate advanced report',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // =============================================================================
  // MANUAL ZAP MANAGEMENT ENDPOINTS
  // =============================================================================

  // POST /api/zap/session/new - Create new ZAP session
  router.post('/session/new', async (req: Request, res: Response) => {
    try {
      await zapService.clearSession();
      res.json({
        success: true,
        message: 'New ZAP session created successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to create new session',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/session/clear - Clear current ZAP session
  router.post('/session/clear', async (req: Request, res: Response) => {
    try {
      await zapService.clearSession();
      res.json({
        success: true,
        message: 'ZAP session cleared successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to clear session',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/session/sync - Sync with GUI session data
  router.post('/session/sync', async (req: Request, res: Response) => {
    try {

      // First check what data is available
      const detection = await zapService.detectGuiSessionData();

      // Try to refresh data using enhanced method
      let refreshedData;
      try {
        refreshedData = await zapService.forceRefreshGuiData();
      } catch (refreshError) {
        refreshedData = await zapService.refreshZapData();
      }

      res.json({
        success: true,
        message: 'Session synchronization completed',
        data: {
          detection,
          refreshedData: {
            sitesCount: refreshedData.sites.length,
            alertsCount: refreshedData.alerts.length,
            urlsCount: refreshedData.urls.length
          },
          sites: refreshedData.sites,
          alerts: refreshedData.alerts,
          urls: refreshedData.urls
        }
      });
    } catch (error) {
      console.error('Session sync error:', error);
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to synchronize session',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/session/data - Get current session data
  router.get('/session/data', async (req: Request, res: Response) => {
    try {
      const data = await zapService.refreshZapData();
      res.json({
        success: true,
        data: {
          sitesCount: data.sites.length,
          alertsCount: data.alerts.length,
          urlsCount: data.urls.length,
          sites: data.sites,
          alerts: data.alerts,
          urls: data.urls
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get session data',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/alerts/count - Get alert count only (lightweight)
  router.get('/alerts/count', async (req: Request, res: Response) => {
    try {
      const status = await zapService.getStatus();
      res.json({
        success: true,
        data: {
          alertCount: status.alerts || 0
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get alert count',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/alerts/optimized - Get alerts with optimization
  router.get('/alerts/optimized', async (req: Request, res: Response) => {
    try {
      const { baseUrl, limit = '100' } = req.query;

      // Force optimized approach with limit
      const alerts = await (zapService as any).getAlertsOptimized(
        baseUrl as string,
        parseInt(limit as string)
      );

      res.json({
        success: true,
        data: alerts,
        meta: {
          total: alerts.length,
          limited: true,
          limit: parseInt(limit as string)
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get optimized alerts',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/scans/stop-all - Stop all running scans
  router.post('/scans/stop-all', async (req: Request, res: Response) => {
    try {
      await zapService.stopAllScans();
      res.json({
        success: true,
        message: 'All scans stopped successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to stop scans',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/system/stats - Get system performance stats
  router.get('/system/stats', async (req: Request, res: Response) => {
    try {
      const stats = await zapService.getScanStatistics();
      res.json({
        success: true,
        data: {
          ...stats,
          timestamp: new Date().toISOString()
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get system stats',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/debug - Debug ZAP connection and history
  router.get('/debug', async (req: Request, res: Response) => {
    try {

      // Check ZAP connection
      let zapConnected = false;
      let zapError = null;
      try {
        const status = await zapService.getStatus();
        zapConnected = true;
      } catch (error) {
        zapConnected = false;
        zapError = error instanceof Error ? error.message : 'Unknown error';
        console.error('❌ ZAP Connection Error:', zapError);
      }

      // Try to get raw history
      let rawHistory = [];
      let historyError = null;
      try {
        rawHistory = await zapService.getHistory(0, 10);
        if (rawHistory.length > 0) {
          console.log('📝 First raw history item:', JSON.stringify(rawHistory[0], null, 2));
        }
      } catch (error) {
        historyError = error instanceof Error ? error.message : 'Unknown error';
        console.error('❌ History Error:', historyError);
      }

      res.json({
        success: true,
        debug: {
          zapConnected,
          zapError,
          rawHistoryCount: rawHistory.length,
          historyError,
          sampleRawItem: rawHistory[0] || null,
          timestamp: new Date().toISOString()
        }
      });
    } catch (error) {
      console.error('❌ Debug endpoint error:', error);
      res.status(500).json({
        success: false,
        error: {
          message: 'Debug endpoint failed',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/history - Get HTTP requests history
  router.get('/history', async (req: Request, res: Response) => {
    try {
      const { start = 0, count = 20 } = req.query; // Daha az sayıda request al

      // First check if ZAP is connected with timeout protection
      let zapStatus: any = { connected: false };
      try {
        const statusPromise = zapService.getStatus();
        const timeoutPromise = new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Status check timeout')), 3000)
        );
        zapStatus = await Promise.race([statusPromise, timeoutPromise]);
      } catch (statusError) {
        // Continue anyway, might still be able to get history
      }

      if (!zapStatus.connected) {
        return res.json({
          success: true,
          data: {
            requests: [],
            total: 0,
            warning: 'ZAP proxy is not connected or temporarily unavailable'
          }
        });
      }

      // Get history with timeout protection
      let history: any[] = [];
      try {
        history = await zapService.getHistory(
          parseInt(start as string),
          parseInt(count as string)
        );
      } catch (historyError) {
        return res.json({
          success: true,
          data: {
            requests: [],
            total: 0,
            warning: 'ZAP history temporarily unavailable - might be processing requests'
          }
        });
      }


      if (history.length === 0) {
        return res.json({
          success: true,
          data: {
            requests: [],
            total: 0,
            info: 'No HTTP requests captured yet. Make sure scanning is active.'
          }
        });
      }

      // Get detailed info for each message - simplified version
      const requests = await Promise.all(
        history.slice(0, 10).map(async (item: any, index: number) => { // Sadece ilk 10 item
          try {
            // Get detailed message info
            const messageDetail = await zapService.getMessage(item.id);

            if (!messageDetail) {
              return null;
            }

            // Parse request header to extract method and URL
            const requestHeader = messageDetail.requestHeader || '';
            const requestLines = requestHeader.split('\r\n');
            const firstLine = requestLines[0] || '';
            const parts = firstLine.split(' ');
            const method = parts[0] || 'GET';
            let url = parts[1] || '';

            // If URL is relative, try to construct full URL
            if (url && !url.startsWith('http')) {
              const hostHeader = requestLines.find((line: string) => line.toLowerCase().startsWith('host:'));
              if (hostHeader) {
                const host = hostHeader.split(':')[1]?.trim();
                if (host) {
                  const protocol = requestHeader.includes('SSL') || requestHeader.includes('TLS') ? 'https' : 'http';
                  url = `${protocol}://${host}${url}`;
                }
              }
            }

            // Parse response header to extract status
            const responseHeader = messageDetail.responseHeader || '';
            const responseLines = responseHeader.split('\r\n');
            const statusLine = responseLines[0] || '';
            const statusMatch = statusLine.match(/HTTP\/[\d.]+\s+(\d+)/);
            const status = statusMatch ? parseInt(statusMatch[1]) : 0;

            // Parse headers - simplified
            const parseHeaders = (headerString: string) => {
              const headers: Record<string, string> = {};
              const lines = headerString.split('\r\n');
              for (let i = 1; i < lines.length && i < 5; i++) { // Sadece ilk 5 header
                const line = lines[i].trim();
                if (line && line.includes(':')) {
                  const [key, ...values] = line.split(':');
                  headers[key.trim().toLowerCase()] = values.join(':').trim().substring(0, 100); // Max 100 char
                }
              }
              return headers;
            };

            const parsedRequest = {
              id: messageDetail.id || `req_${Date.now()}_${index}`,
              method,
              url: url.length > 200 ? url.substring(0, 200) + '...' : url, // URL'i kısalt
              headers: parseHeaders(requestHeader),
              body: (messageDetail.requestBody || '').substring(0, 500), // Body'yi kısalt
              timestamp: messageDetail.timestamp ?
                new Date(parseInt(messageDetail.timestamp)).toISOString() :
                new Date().toISOString(),
              status,
              responseHeaders: parseHeaders(responseHeader),
              responseBody: (messageDetail.responseBody || '').substring(0, 500), // Response body'yi kısalt
              duration: parseInt(messageDetail.rtt) || 0
            };

            return parsedRequest;
          } catch (parseError) {
            return null;
          }
        })
      );

      // Filter out any null/undefined requests
      const validRequests = requests.filter(req => req !== null && req !== undefined);


      res.json({
        success: true,
        data: {
          requests: validRequests,
          total: validRequests.length,
          totalAvailable: history.length,
          metadata: {
            zapConnected: true,
            requestedCount: parseInt(count as string),
            actualCount: validRequests.length,
            fetchedAt: new Date().toISOString(),
            note: 'Results limited for performance'
          }
        }
      });
    } catch (error) {
      console.error('❌ History fetch error:', error);
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get history',
          details: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString()
        }
      });
    }
  });

  // POST /api/zap/hud - Enable/disable HUD
  router.post('/hud', async (req: Request, res: Response) => {
    try {
      const { enabled } = req.body;


      // HUD API call to ZAP
      const zapUrl = process.env.ZAP_PROXY_URL || 'http://zap-api:8080';
      const apiKey = process.env.ZAP_API_KEY || '';

      // HUD'ı aktifleştir/deaktifleştir
      const response = await fetch(`${zapUrl}/JSON/hud/action/setOptionEnabledForDesktop/?enable=${enabled}&apikey=${apiKey}`);

      if (enabled) {
        // HUD file generator'ını da aktifleştir
        await fetch(`${zapUrl}/JSON/hud/action/setOptionFileGenerator/?apikey=${apiKey}`);
      } else {
      }

      res.json({
        success: true,
        data: {
          hudEnabled: enabled,
          message: `HUD ${enabled ? 'enabled' : 'disabled'} successfully`
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to toggle HUD',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/intercept - Enable/disable intercept mode
  router.post('/intercept', async (req: Request, res: Response) => {
    try {
      const { enabled } = req.body;

      // Set break point
      const zapUrl = process.env.ZAP_PROXY_URL || 'http://zap-api:8080';
      const action = enabled ? 'addHttpBreakpoint' : 'removeHttpBreakpoint';

      await fetch(`${zapUrl}/JSON/break/action/${action}/`, {
        method: 'GET',
        headers: {
          'ZAP-API-Key': process.env.ZAP_API_KEY || ''
        }
      });

      res.json({
        success: true,
        data: {
          interceptEnabled: enabled,
          message: `Intercept mode ${enabled ? 'enabled' : 'disabled'}`
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to toggle intercept',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/zap/open-browser - Open browser with ZAP proxy
  router.post('/open-browser', async (req: Request, res: Response) => {
    try {
      const { url } = req.body;

      console.log('🔍 Open browser request received (HTTPS fixed):', { body: req.body, url });

      if (!url) {
        return res.status(400).json({
          success: false,
          error: { message: 'URL is required' }
        });
      }

      const { spawn } = require('child_process');
      const fs = require('fs');
      const path = require('path');

      // Chrome path'lerini kontrol et
      const chromePaths = [
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'
      ];

      // Environment variables ile ek path'ler
      if (process.env.LOCALAPPDATA) {
        chromePaths.push(path.join(process.env.LOCALAPPDATA, 'Google\\Chrome\\Application\\chrome.exe'));
      }
      if (process.env.PROGRAMFILES) {
        chromePaths.push(path.join(process.env.PROGRAMFILES, 'Google\\Chrome\\Application\\chrome.exe'));
      }

      let chromeExePath = '';

      // İlk bulunan Chrome path'ini kullan
      for (const chromePath of chromePaths) {
        try {
          if (fs.existsSync(chromePath)) {
            chromeExePath = chromePath;
            break;
          }
        } catch (error) {
          continue;
        }
      }

      const proxyPort = process.env.ZAP_PROXY_PORT || '8080';

      if (chromeExePath) {
        // Chrome'u ZAP proxy ile başlat - HTTPS proxy desteği ile
        const chromeArgs = [
          `--proxy-server=http://localhost:${proxyPort}`,
          '--proxy-bypass-list=<-loopback>',
          '--ignore-certificate-errors',
          '--ignore-ssl-errors',
          '--ignore-certificate-errors-spki-list',
          '--ignore-certificate-errors-ssl',
          '--allow-running-insecure-content',
          '--disable-web-security',
          '--disable-features=VizDisplayCompositor',
          '--disable-extensions',
          '--disable-plugins',
          '--disable-default-apps',
          '--disable-sync',
          '--disable-translate',
          '--disable-background-timer-throttling',
          '--disable-backgrounding-occluded-windows',
          '--disable-renderer-backgrounding',
          '--disable-field-trial-config',
          '--disable-ipc-flooding-protection',
          '--accept-lang=en-US,en',
          '--disable-component-extensions-with-background-pages',
          '--disable-site-isolation-trials',
          '--disable-features=TranslateUI',
          '--disable-features=Translate',
          '--user-data-dir=' + path.join(require('os').tmpdir(), 'zap-chrome-profile-' + Date.now()),
          '--new-window',
          '--no-first-run',
          '--no-default-browser-check',
          url
        ];

        // ZAP HUD'ı önce aktifleştir ve root CA sertifikasını ayarla
        try {
          const zapUrl = process.env.ZAP_PROXY_URL || 'http://zap-api:8080';
          const apiKey = process.env.ZAP_API_KEY || '';

          // ZAP'in Root CA sertifikasını al
          const rootCaResponse = await fetch(`${zapUrl}/OTHER/core/other/rootcert/?apikey=${apiKey}`);

          if (rootCaResponse.ok) {
            const rootCaCert = await rootCaResponse.text();

            // Geçici sertifika dosyası oluştur
            const tempCertPath = path.join(require('os').tmpdir(), 'zap-root-ca.crt');
            fs.writeFileSync(tempCertPath, rootCaCert);
            console.log(`🔍 Certificate preview: ${rootCaCert.substring(0, 100)}...`);

            // Chrome args'a sertifika yolunu ekle
            chromeArgs.push(`--ca-cert-file=${tempCertPath}`);
          } else {
          }

          // HUD'ı aktifleştir
          await fetch(`${zapUrl}/JSON/hud/action/setOptionEnabledForDesktop/?enable=true&apikey=${apiKey}`);

          // HUD file generator'ını aktifleştir
          await fetch(`${zapUrl}/JSON/hud/action/setOptionFileGenerator/?apikey=${apiKey}`);

          // ZAP'i target URL için hazırla
          await fetch(`${zapUrl}/JSON/core/action/accessUrl/?url=${encodeURIComponent(url)}&apikey=${apiKey}`);

        } catch (hudError) {
        }

        console.log(`🚀 Starting Chrome with ZAP proxy (${proxyPort}) for URL: ${url}`);

        const chromeProcess = spawn(chromeExePath, chromeArgs, {
          detached: true,
          stdio: 'ignore'
        });

        chromeProcess.unref();


        res.json({
          success: true,
          data: {
            message: 'Chrome browser launched with ZAP proxy',
            url,
            proxyPort,
            chromePath: chromeExePath,
            pid: chromeProcess.pid
          }
        });
      } else {
        // Fallback - sistem default browser
        const { exec } = require('child_process');
        exec(`start "" "${url}"`, (error: any) => {
          if (error) {
            console.error('Default browser launch error:', error);
          }
        });

        res.json({
          success: true,
          data: {
            message: 'Default browser launched (Chrome not found)',
            url,
            proxyPort,
            warning: 'Chrome not found, opened with default browser without proxy'
          }
        });
      }

    } catch (error) {
      console.error('Browser launch error:', error);
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to open browser',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // ========================================
  // SCAN HISTORY ENDPOINTS
  // ========================================

  // GET /api/zap/scans - Get all scan history
  router.get('/scans', requireAuth, async (req: Request, res: Response) => {
    try {
      const scans = await prisma.scan.findMany({
        include: {
          vulnerabilities: {
            select: {
              id: true,
              name: true,
              severity: true,
              confidence: true,
              description: true,
              solution: true,
              reference: true,
              affectedUrl: true,
              param: true,
              attack: true,
              evidence: true,
              cweid: true,
              wascid: true
              // cweId removed to avoid duplicate key conflict with cweid
            }
          },
          scanUrls: true,
          _count: {
            select: {
              vulnerabilities: true,
              scanUrls: true
            }
          }
        },
        orderBy: { startedAt: 'desc' }
      });

      res.json({
        success: true,
        data: scans
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to fetch scan history',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/zap/scans/:scanId - Get specific scan details
  router.get('/scans/:scanId', requireAuth, async (req: Request, res: Response) => {
    try {
      const { scanId } = req.params;
      const scan = await prisma.scan.findUnique({
        where: { id: scanId },
        include: {
          vulnerabilities: {
            select: {
              id: true,
              name: true,
              severity: true,
              confidence: true,
              description: true,
              solution: true,
              reference: true,
              affectedUrl: true,
              param: true,
              attack: true,
              evidence: true,
              cweid: true,
              wascid: true
              // cweId removed to avoid duplicate key conflict with cweid
            }
          },
          scanUrls: {
            select: {
              id: true,
              url: true,
              method: true,
              statusCode: true,
              responseTime: true,
              contentType: true,
              size: true,
              timestamp: true
            },
            orderBy: {
              timestamp: 'desc'
            }
          }
        }
      });

      if (!scan) {
        res.status(404).json({
          success: false,
          error: { message: 'Scan not found' }
        });
        return;
      }

      console.log(`   - Vulnerabilities: ${scan.vulnerabilities.length}`);

      res.json({
        success: true,
        data: {
          ...scan,
          vulnerabilities: scan.vulnerabilities,
          scanUrls: scan.scanUrls
        }
      });
    } catch (error) {
      console.error('❌ Error fetching scan details:', error);
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to fetch scan details',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // DELETE /api/zap/scans/:scanId - Delete a scan
  router.delete('/scans/:scanId', requireAuth, async (req: Request, res: Response) => {
    try {
      const { scanId } = req.params;

      await prisma.scan.delete({
        where: { id: scanId }
      });

      res.json({
        success: true,
        data: { message: 'Scan deleted successfully' }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to delete scan',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  return router;
};

export default createZapRoutes;
