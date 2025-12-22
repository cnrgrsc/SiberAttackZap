import express, { Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { PrismaClient } from '@prisma/client';
import MobSFService from '../services/mobsf.service';
import { Server } from 'socket.io';

const router = express.Router();
const prisma = new PrismaClient();

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../../uploads/mobile');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage,
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.apk', '.aab', '.ipa', '.zip'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only APK, AAB, IPA, and ZIP files are allowed.'));
    }
  }
});

// Initialize MobSF service with a default instance
let mobsfService: MobSFService = new MobSFService(prisma);

export const initializeMobSFRoutes = (io: Server) => {
  // Re-initialize with Socket.IO if provided
  mobsfService = new MobSFService(prisma, io);
  return router;
};

// Get MobSF status
router.get('/status', async (req: Request, res: Response) => {
  try {
    const status = await mobsfService.checkStatus();
    res.json(status);
  } catch (error: any) {
    console.error('MobSF status error:', error);
    res.status(500).json({ error: 'Failed to get MobSF status', details: error.message });
  }
});

// Upload and scan mobile app
router.post('/upload-scan', upload.single('file'), async (req: Request, res: Response) => {
  try {
    
    if (!req.file) {
      console.error('❌ No file uploaded');
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { scanName } = req.body;
    const filePath = req.file.path;
    const fileName = req.file.originalname;
    
    console.log(`📤 File uploaded: ${fileName} (${req.file.size} bytes)`);

    // Validate MobSF service
    if (!mobsfService) {
      console.error('❌ MobSF service not initialized');
      return res.status(500).json({ 
        error: 'MobSF service not initialized',
        message: 'Internal server error - service not configured'
      });
    }

    // Create scan record
    const scan = await prisma.scan.create({
      data: {
        name: scanName || `Mobile Scan - ${fileName}`,
        targetUrl: fileName,
        scanType: 'MOBILE',
        status: 'RUNNING',
        startedAt: new Date(),
        createdBy: req.body.userId || null,
      }
    });
    

    // Start workflow in background
    mobsfService.runCompleteWorkflow(filePath, fileName, scan.id)
      .then(() => {
        // Clean up uploaded file
        fs.unlink(filePath, (err) => {
          if (err) console.error('⚠️ Error deleting uploaded file:', err);
        });
      })
      .catch(async (error) => {
        console.error('❌ Mobile scan workflow error:', error);
        
        // Detailed error logging
        if (error instanceof Error) {
          console.error('Error details:', {
            name: error.name,
            message: error.message,
            stack: error.stack
          });
        }
        
        await prisma.scan.update({
          where: { id: scan.id },
          data: { status: 'FAILED', completedAt: new Date() }
        });
        
        // Clean up uploaded file
        fs.unlink(filePath, (err) => {
          if (err) console.error('⚠️ Error deleting uploaded file:', err);
        });
      });

    res.json({ 
      message: 'Mobile app uploaded and scan started',
      scanId: scan.id,
      fileName: fileName
    });

  } catch (error: any) {
    console.error('❌ Upload and scan error:', error);
    
    // Detailed error logging
    if (error instanceof Error) {
      console.error('Error details:', {
        name: error.name,
        message: error.message,
        stack: error.stack
      });
    } else {
      console.error('Non-Error object thrown:', JSON.stringify(error, null, 2));
    }
    
    res.status(500).json({ 
      error: 'Failed to upload and scan file', 
      message: error.message || 'Unknown error',
      details: error instanceof Error ? error.stack : String(error)
    });
  }
});

// Get scan results
router.get('/scan/:scanId', async (req: Request, res: Response) => {
  try {
    const { scanId } = req.params;
    
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: {
        vulnerabilities: true,
        mobileAppScan: true,
        reports: true,
      }
    });

    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    res.json(scan);
  } catch (error: any) {
    console.error('Get scan error:', error);
    res.status(500).json({ error: 'Failed to get scan results', details: error.message });
  }
});

// Get mobile scan history
router.get('/scans', async (req: Request, res: Response) => {
  try {
    const { page = 1, limit = 10, status, platform } = req.query;
    
    const where: any = {
      scanType: 'MOBILE'
    };

    if (status) {
      where.status = status;
    }

    if (platform) {
      where.mobileAppScan = {
        platform: platform
      };
    }

    const scans = await prisma.scan.findMany({
      where,
      include: {
        mobileAppScan: true,
        vulnerabilities: {
          select: {
            severity: true,
          }
        },
        creator: {
          select: {
            username: true,
            firstName: true,
            lastName: true,
          }
        }
      },
      orderBy: {
        startedAt: 'desc'
      },
      skip: (Number(page) - 1) * Number(limit),
      take: Number(limit),
    });

    const total = await prisma.scan.count({ where });

    // Add vulnerability counts
    const scansWithCounts = scans.map(scan => ({
      ...scan,
      vulnerabilityCounts: {
        critical: scan.vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
        high: scan.vulnerabilities.filter(v => v.severity === 'HIGH').length,
        medium: scan.vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
        low: scan.vulnerabilities.filter(v => v.severity === 'LOW').length,
        info: scan.vulnerabilities.filter(v => v.severity === 'INFO').length,
      }
    }));

    res.json({
      scans: scansWithCounts,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total,
        pages: Math.ceil(total / Number(limit))
      }
    });
  } catch (error: any) {
    console.error('Get mobile scans error:', error);
    res.status(500).json({ error: 'Failed to get mobile scans', details: error.message });
  }
});

// Delete mobile scan
router.delete('/scan/:scanId', async (req: Request, res: Response) => {
  try {
    const { scanId } = req.params;
    
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: { mobileAppScan: true }
    });

    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    if (scan.scanType !== 'MOBILE') {
      return res.status(400).json({ error: 'Not a mobile scan' });
    }

    // Delete from MobSF if hash exists
    if (scan.mobileAppScan?.hash) {
      try {
        await mobsfService.deleteScan(scan.mobileAppScan.hash);
      } catch (error) {
      }
    }

    // Delete from database (cascade will handle related records)
    await prisma.scan.delete({
      where: { id: scanId }
    });

    res.json({ message: 'Mobile scan deleted successfully' });
  } catch (error: any) {
    console.error('Delete mobile scan error:', error);
    res.status(500).json({ error: 'Failed to delete mobile scan', details: error.message });
  }
});

// Download PDF report
router.get('/scan/:scanId/report/pdf', async (req: Request, res: Response) => {
  try {
    const { scanId } = req.params;
    
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: { mobileAppScan: true }
    });

    if (!scan || !scan.mobileAppScan?.hash) {
      return res.status(404).json({ error: 'Scan or hash not found' });
    }

    const pdfBuffer = await mobsfService.downloadPDFReport(scan.mobileAppScan.hash);
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="mobile-scan-report-${scanId}.pdf"`);
    res.send(pdfBuffer);
  } catch (error: any) {
    console.error('Download PDF error:', error);
    res.status(500).json({ error: 'Failed to download PDF report', details: error.message });
  }
});

// Get Android apps for dynamic analysis
router.get('/dynamic/android-apps', async (req: Request, res: Response) => {
  try {
    const apps = await mobsfService.getAndroidApps();
    res.json(apps);
  } catch (error: any) {
    console.error('Get Android apps error:', error);
    res.status(500).json({ error: 'Failed to get Android apps', details: error.message });
  }
});

// Start dynamic analysis
router.post('/dynamic/start/:scanId', async (req: Request, res: Response) => {
  try {
    const { scanId } = req.params;
    
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: { mobileAppScan: true }
    });

    if (!scan || !scan.mobileAppScan?.hash) {
      return res.status(404).json({ error: 'Scan or hash not found' });
    }

    const result = await mobsfService.startDynamicAnalysis(scan.mobileAppScan.hash);
    
    // Update scan status
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'RUNNING' }
    });

    res.json({ message: 'Dynamic analysis started', result });
  } catch (error: any) {
    console.error('Start dynamic analysis error:', error);
    res.status(500).json({ error: 'Failed to start dynamic analysis', details: error.message });
  }
});

// Stop dynamic analysis
router.post('/dynamic/stop/:scanId', async (req: Request, res: Response) => {
  try {
    const { scanId } = req.params;
    
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: { mobileAppScan: true }
    });

    if (!scan || !scan.mobileAppScan?.hash) {
      return res.status(404).json({ error: 'Scan or hash not found' });
    }

    const result = await mobsfService.stopDynamicAnalysis(scan.mobileAppScan.hash);
    
    // Update scan status
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'COMPLETED', completedAt: new Date() }
    });

    res.json({ message: 'Dynamic analysis stopped', result });
  } catch (error: any) {
    console.error('Stop dynamic analysis error:', error);
    res.status(500).json({ error: 'Failed to stop dynamic analysis', details: error.message });
  }
});

// Get mobile scan statistics
router.get('/statistics', async (req: Request, res: Response) => {
  try {
    const totalScans = await prisma.scan.count({
      where: { scanType: 'MOBILE' }
    });

    const completedScans = await prisma.scan.count({
      where: { scanType: 'MOBILE', status: 'COMPLETED' }
    });

    const failedScans = await prisma.scan.count({
      where: { scanType: 'MOBILE', status: 'FAILED' }
    });

    const runningScans = await prisma.scan.count({
      where: { scanType: 'MOBILE', status: 'RUNNING' }
    });

    // Platform statistics
    const androidScans = await prisma.mobileAppScan.count({
      where: { platform: 'ANDROID' }
    });

    const iosScans = await prisma.mobileAppScan.count({
      where: { platform: 'IOS' }
    });

    // Vulnerability statistics
    const vulnerabilities = await prisma.vulnerability.groupBy({
      by: ['severity'],
      where: {
        scan: {
          scanType: 'MOBILE'
        }
      },
      _count: {
        severity: true
      }
    });

    const vulnStats = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };

    vulnerabilities.forEach(vuln => {
      const severity = vuln.severity.toLowerCase() as keyof typeof vulnStats;
      if (severity in vulnStats) {
        vulnStats[severity] = vuln._count.severity;
      }
    });

    res.json({
      totalScans,
      completedScans,
      failedScans,
      runningScans,
      platformStats: {
        android: androidScans,
        ios: iosScans
      },
      vulnerabilityStats: vulnStats
    });
  } catch (error: any) {
    console.error('Get mobile statistics error:', error);
    res.status(500).json({ error: 'Failed to get mobile statistics', details: error.message });
  }
});

// Download PDF report
router.get('/scan/:scanId/report/pdf', async (req: Request, res: Response) => {
  try {
    const { scanId } = req.params;
    
    // Get scan with mobile app data
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: { mobileAppScan: true }
    });

    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    if (!scan.mobileAppScan?.hash) {
      return res.status(400).json({ error: 'Mobile scan hash not found' });
    }

    // Get PDF from MobSF
    const pdfBuffer = await mobsfService.downloadPDFReport(scan.mobileAppScan.hash);
    
    // Set response headers for PDF download
    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="mobile-scan-report-${scan.name}.pdf"`,
      'Content-Length': pdfBuffer.length.toString()
    });

    res.send(pdfBuffer);
  } catch (error: any) {
    console.error('Download PDF report error:', error);
    res.status(500).json({ error: 'Failed to download PDF report', details: error.message });
  }
});

// GET /api/mobsf/scan/:scanId/report/html - Download standardized HTML report
router.get('/scan/:scanId/report/html', async (req: Request, res: Response) => {
  try {
    const { scanId } = req.params;
    
    // Get scan from database
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: { mobileAppScan: true }
    });

    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    if (!scan.mobileAppScan) {
      return res.status(400).json({ error: 'Not a mobile scan' });
    }

    // Generate HTML report using standardized template
    const htmlReport = await mobsfService.generateHtmlReport(scanId);
    
    // Generate standardized filename
    const { ReportGeneratorService } = await import('../services/reportGenerator.service');
    const fileName = ReportGeneratorService.generateFilename('MOBILE', scan.name);
    
    // Set response headers for HTML download
    res.set({
      'Content-Type': 'text/html',
      'Content-Disposition': `attachment; filename="${fileName}"`,
      'Content-Length': Buffer.byteLength(htmlReport).toString()
    });

    res.send(htmlReport);
  } catch (error: any) {
    console.error('Download HTML report error:', error);
    res.status(500).json({ error: 'Failed to download HTML report', details: error.message });
  }
});

export default router;
