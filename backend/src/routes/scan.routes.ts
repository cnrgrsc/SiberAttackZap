import { Router, Request, Response } from 'express';
import Joi from 'joi';
import { ScanService } from '../services/scan.service';
import { ScanRequest } from '../types/api.types';
import { ReportGeneratorService } from '../services/reportGenerator.service';
import { notifyAdmins } from './notifications.routes';

// Validation schemas
// 🎯 TEST/STAGING ORTAMI - Maksimum yeteneklerle kapsamlı test
const testStagingScanSchema = Joi.object({
  name: Joi.string().min(1).max(255).optional(),
  targetUrl: Joi.string().uri().required(),
  scanType: Joi.string().valid('AUTOMATED', 'MANUAL', 'BASELINE', 'FULL', 'API').optional().default('AUTOMATED'),
  environment: Joi.string().valid('TEST_STAGING').required()
});

// 🔒 PRODUCTION ORTAMI - Güvenli, sadece okuma tabanlı testler
const productionScanSchema = Joi.object({
  name: Joi.string().min(1).max(255).optional(),
  targetUrl: Joi.string().uri().required(),
  scanType: Joi.string().valid('AUTOMATED', 'MANUAL', 'BASELINE', 'FULL', 'API').optional().default('AUTOMATED'),
  environment: Joi.string().valid('PRODUCTION').required()
});

// ⚙️ CUSTOM ORTAMI - Kullanıcı tanımlı ayarlar
const customScanSchema = Joi.object({
  name: Joi.string().min(1).max(255).optional(),
  targetUrl: Joi.string().uri().required(),
  scanType: Joi.string().valid('AUTOMATED', 'MANUAL', 'BASELINE', 'FULL', 'API').optional().default('AUTOMATED'),
  environment: Joi.string().valid('CUSTOM').required(),
  customConfig: Joi.object({
    spider: Joi.object({
      enabled: Joi.boolean().required(),
      maxChildren: Joi.number().integer().min(0).optional(),
      maxDepth: Joi.number().integer().min(0).optional(),
      maxDuration: Joi.number().integer().min(0).optional(),
      recurse: Joi.boolean().optional()
    }).optional(),
    ajaxSpider: Joi.object({
      enabled: Joi.boolean().required(),
      maxDuration: Joi.number().integer().min(0).optional(),
      maxCrawlDepth: Joi.number().integer().min(0).optional(),
      browser: Joi.string().valid('firefox', 'chrome', 'htmlunit').optional()
    }).optional(),
    activeScan: Joi.object({
      enabled: Joi.boolean().required(),
      maxDuration: Joi.number().integer().min(0).optional(),
      intensity: Joi.string().valid('LOW', 'MEDIUM', 'HIGH', 'INSANE').optional(),
      recurse: Joi.boolean().optional()
    }).optional(),
    attackTests: Joi.object({
      sqlInjection: Joi.boolean().optional(),
      xss: Joi.boolean().optional(),
      xxe: Joi.boolean().optional(),
      commandInjection: Joi.boolean().optional(),
      pathTraversal: Joi.boolean().optional(),
      wafBypass: Joi.boolean().optional(),
      bruteForce: Joi.boolean().optional(),
      csrf: Joi.boolean().optional(),
      ssrf: Joi.boolean().optional(),
      deserializationAttacks: Joi.boolean().optional()
    }).optional(),
    advanced: Joi.object({
      jsSecurity: Joi.boolean().optional(),
      apiDeepDive: Joi.boolean().optional(),
      forcedBrowse: Joi.boolean().optional(),
      fuzzing: Joi.boolean().optional(),
      customPayloads: Joi.boolean().optional(),
      customWordlists: Joi.boolean().optional()
    }).optional(),
    security: Joi.object({
      safeMode: Joi.boolean().optional(),
      respectRobotsTxt: Joi.boolean().optional(),
      maxAlertsPerRule: Joi.number().integer().min(0).optional()
    }).optional(),
    filters: Joi.object({
      excludeUrls: Joi.array().items(Joi.string()).optional(),
      includeUrls: Joi.array().items(Joi.string()).optional(),
      excludeParams: Joi.array().items(Joi.string()).optional()
    }).optional()
  }).optional()
});

// Unified scan schema - detects environment and validates accordingly
const unifiedScanSchema = Joi.alternatives().conditional('.environment', {
  switch: [
    { is: 'TEST_STAGING', then: testStagingScanSchema },
    { is: 'PRODUCTION', then: productionScanSchema },
    { is: 'CUSTOM', then: customScanSchema }
  ],
  otherwise: Joi.object({
    name: Joi.string().min(1).max(255).optional(),
    targetUrl: Joi.string().uri().required(),
    scanType: Joi.string().valid('AUTOMATED', 'MANUAL', 'BASELINE', 'FULL', 'API').optional(),
    environment: Joi.string().valid('TEST_STAGING', 'PRODUCTION', 'CUSTOM').required()
  })
});

// Factory function to create router with socket.io
export function createScanRoutes(io?: any): Router {
  const router = Router();
  const scanService = new ScanService(io);

  // GET /api/scans/statistics - Get scan statistics
  router.get('/statistics', async (req: Request, res: Response) => {
    try {
      const statistics = await scanService.getScanStatistics();
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

  // GET /api/scans/statistics/overview - Get overview statistics
  router.get('/statistics/overview', async (req: Request, res: Response) => {
    try {
      const statistics = await scanService.getScanStatistics();
      res.json(statistics);
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

  // POST /api/scans/automated - Create and start automated scan with environment selection
  router.post('/automated', async (req: Request, res: Response): Promise<void> => {
    try {
      console.log('🎯 Received automated scan request:', JSON.stringify(req.body, null, 2));
      
      const { environment } = req.body;
      
      // Validate based on environment
      let validationSchema;
      switch (environment) {
        case 'TEST_STAGING':
          validationSchema = testStagingScanSchema;
          break;
        case 'PRODUCTION':
          validationSchema = productionScanSchema;
          break;
        case 'CUSTOM':
          validationSchema = customScanSchema;
          break;
        default:
          res.status(400).json({
            success: false,
            error: {
              message: 'Invalid or missing environment',
              details: 'environment must be one of: TEST_STAGING, PRODUCTION, CUSTOM'
            }
          });
          return;
      }
      
      const { error, value } = validationSchema.validate(req.body);
      if (error) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Validation error',
            details: error.details.map((d: any) => d.message).join(', '),
            receivedData: req.body
          }
        });
        return;
      }

      // Create scan data based on environment
      const scanData: ScanRequest = {
        name: value.name || `${environment} Scan - ${value.targetUrl}`,
        targetUrl: value.targetUrl,
        scanType: value.scanType || 'AUTOMATED',
        environment: environment as any,
        customConfig: value.customConfig
      };

      const scan = await scanService.createScan(scanData);
      
      // Notify admins about new scan
      await notifyAdmins({
        type: 'SCAN_CREATED',
        title: '🎯 Yeni Tarama Başlatıldı',
        message: `${scanData.name} taraması ${scanData.targetUrl} hedefi için başlatıldı (Ortam: ${environment})`,
        scanId: scan.id,
        createdBy: (req as any).user?.id,
        link: `/scan-history?scanId=${scan.id}`,
        metadata: {
          targetUrl: scanData.targetUrl,
          scanType: scanData.scanType,
          environment: environment
        }
      });
      
      // Start the scan immediately
      console.log(`🚀 Starting ${environment} scan for ${scan.id}`);
      const startedScan = await scanService.startAutomatedScan(scan.id);
      
      res.status(201).json({
        success: true,
        data: startedScan,
        message: `${environment} scan started successfully`
      });
    } catch (error) {
      console.error('❌ Failed to create automated scan:', error);
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to create automated scan',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/scans - Get all scans
  router.get('/', async (req: Request, res: Response) => {
    try {
      const scans = await scanService.getAllScans();
      res.json({
        success: true,
        data: scans
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get scans',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // 🔥 GET /api/scans/queue/stats - Get queue statistics
  // MUST be before /:id route to prevent 'queue' being treated as an ID
  router.get('/queue/stats', async (req: Request, res: Response) => {
    try {
      const { scanQueueService } = await import('../services/scanQueue.service');
      const stats = await scanQueueService.getQueueStats();
      
      res.json({
        success: true,
        data: stats
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get queue stats',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/scans/:id - Get scan by ID
  router.get('/:id', async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const scan = await scanService.getScanById(id);
      
      if (!scan) {
        res.status(404).json({
          success: false,
          error: { message: 'Scan not found' }
        });
        return;
      }

      res.json({
        success: true,
        data: scan
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get scan',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/scans - Create new scan (without starting)
  router.post('/', async (req: Request, res: Response): Promise<void> => {
    try {
      const { environment } = req.body;
      
      // Validate based on environment
      let validationSchema;
      switch (environment) {
        case 'TEST_STAGING':
          validationSchema = testStagingScanSchema;
          break;
        case 'PRODUCTION':
          validationSchema = productionScanSchema;
          break;
        case 'CUSTOM':
          validationSchema = customScanSchema;
          break;
        default:
          res.status(400).json({
            success: false,
            error: {
              message: 'Invalid or missing environment',
              details: 'environment must be one of: TEST_STAGING, PRODUCTION, CUSTOM'
            }
          });
          return;
      }
      
      const { error, value } = validationSchema.validate(req.body);
      if (error) {
        res.status(400).json({
          success: false,
          error: {
            message: 'Validation error',
            details: error.details.map((d: any) => d.message).join(', ')
          }
        });
        return;
      }

      // Get userId from request (assuming it's added by auth middleware)
      const userId = (req as any).user?.id;
      
      const scan = await scanService.createScan(value as ScanRequest, userId);
      
      // Check if scan was queued
      if ((scan as any).queued) {
        res.status(202).json({
          success: true,
          data: scan,
          message: `Taramanız sıraya alındı. Sıradaki pozisyon: ${(scan as any).queuePosition}`
        });
        return;
      }
      
      res.status(201).json({
        success: true,
        data: scan
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to create scan',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // POST /api/scans/:id/start - Start scan
  router.post('/:id/start', async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const scan = await scanService.startAutomatedScan(id);
      
      res.json({
        success: true,
        data: scan
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to start scan',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/scans/:id/vulnerabilities - Get scan vulnerabilities
  router.get('/:id/vulnerabilities', async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const vulnerabilities = await scanService.getScanVulnerabilities(id);
      
      res.json({
        success: true,
        data: vulnerabilities
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get vulnerabilities',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // GET /api/scans/:id/data - Get scan data with deduplicated vulnerabilities
  router.get('/:id/data', async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const scan = await scanService.getScanById(id);
      
      if (!scan) {
        res.status(404).json({
          success: false,
          error: { message: 'Scan not found' }
        });
        return;
      }

      // Get all vulnerabilities
      const allVulnerabilities = await scanService.getScanVulnerabilities(id);
      
      // Deduplicate: Group by name and keep only unique ones
      const uniqueVulns = new Map<string, any>();
      allVulnerabilities.forEach(vuln => {
        const key = vuln.name; // Group by vulnerability name only
        if (!uniqueVulns.has(key)) {
          uniqueVulns.set(key, {
            ...vuln,
            affectedUrls: [vuln.url] // Track all affected URLs
          });
        } else {
          // Add URL to existing vulnerability
          const existing = uniqueVulns.get(key);
          if (vuln.url && !existing.affectedUrls.includes(vuln.url)) {
            existing.affectedUrls.push(vuln.url);
          }
        }
      });

      const vulnerabilities = Array.from(uniqueVulns.values());

      // Get scan URLs
      const urls = await scanService.getScanUrls(id);

      res.json({
        success: true,
        data: {
          id: scan.id,
          name: scan.name,
          targetUrl: scan.targetUrl,
          scanType: scan.scanType,
          status: scan.status,
          startedAt: scan.startedAt,
          completedAt: scan.completedAt,
          vulnerabilities: vulnerabilities,
          urlsFound: urls,
          totalVulnerabilities: vulnerabilities.length,
          totalUrls: urls.length
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get scan data',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });
  
  // GET /api/scans/:id/report - Generate and return scan report
  router.get('/:id/report', async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const format = (req.query.format as string) || 'html';
      
      const report = await scanService.generateReport(id, format as any);
      
      // Set appropriate headers
      res.setHeader('Content-Type', format === 'html' ? 'text/html' : 'application/json');
      
      res.send(report);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to generate report',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });
  
  // GET /api/scans/:id/report/download - Download scan report
  router.get('/:id/report/download', async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const format = (req.query.format as string) || 'html';
      
      // Get scan details for filename
      const scan = await scanService.getScanById(id);
      if (!scan) {
        return res.status(404).json({
          success: false,
          error: { message: 'Scan not found' }
        });
      }
      
      const report = await scanService.generateReport(id, format as any);
      
      // Generate standardized filename
      const fileName = format === 'html' 
        ? ReportGeneratorService.generateFilename(scan.scanType, scan.targetUrl)
        : `IBB_GuvenlikTaramasi_${new Date().toISOString().split('T')[0]}_${scan.scanType}.${format}`;
      
      // Set appropriate headers for download
      res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
      res.setHeader('Content-Type', format === 'html' ? 'text/html' : 'application/json');
      
      res.send(report);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to generate report',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // DELETE /api/scans/:id - Delete scan
  router.delete('/:id', async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      await scanService.deleteScan(id);
      
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

  // Get discovered URLs for a scan
  router.get('/:id/urls', async (req: Request, res: Response) => {
    try {
      const scanId = req.params.id;
      
      const urls = await scanService.getScanUrls(scanId);
      res.json({
        success: true,
        data: urls
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get scan URLs',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // PUT /api/scans/:id/status - Update scan status
  router.put('/:id/status', async (req: Request, res: Response) => {
    try {
      const scanId = req.params.id;
      const { status } = req.body;
      
      if (!['COMPLETED', 'FAILED', 'CANCELLED', 'RUNNING', 'STOPPED'].includes(status)) {
        return res.status(400).json({
          success: false,
          error: { message: 'Invalid status. Must be one of: COMPLETED, FAILED, CANCELLED, RUNNING, STOPPED' }
        });
      }
      
      const updatedScan = await scanService.updateScanStatus(scanId, status);
      res.json({
        success: true,
        data: updatedScan
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to update scan status',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // Get scan details (URLs + vulnerabilities)
  router.get('/:id/details', async (req: Request, res: Response) => {
    try {
      const scanId = req.params.id;
      
      const details = await scanService.getScanDetails(scanId);
      res.json({
        success: true,
        data: details
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to get scan details',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  // 🔥 DELETE /api/scans/:id/queue - Remove scan from queue
  router.delete('/:id/queue', async (req: Request, res: Response) => {
    try {
      const scanId = req.params.id;
      const { scanQueueService } = await import('../services/scanQueue.service');
      
      await scanQueueService.removeScan(scanId);
      
      res.json({
        success: true,
        message: 'Scan removed from queue'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: {
          message: 'Failed to remove scan from queue',
          details: error instanceof Error ? error.message : 'Unknown error'
        }
      });
    }
  });

  return router;
}

// Default export for backward compatibility
export default createScanRoutes();
