import { Router, Request, Response } from 'express';
import { ZapProxyService } from '../services/zapProxy.service';
import { PrismaClient } from '@prisma/client';
import ZapReportGenerator from '../services/zapReportGenerator.service';
import { ReportGeneratorService } from '../services/reportGenerator.service';

const router = Router();
const zapService = new ZapProxyService();
const prisma = new PrismaClient();
const zapReportGenerator = new ZapReportGenerator();

// GET /api/reports/zap/html - Generate HTML report from current ZAP session
router.get('/zap/html', async (req: Request, res: Response) => {
  try {
    
    // Get data from current ZAP session
    const sessionData = await zapService.forceRefreshGuiData();
    
    // Generate modern HTML report with ZAP data
    const htmlReport = await zapReportGenerator.generateZapSessionReport({
      sites: sessionData.sites,
      alerts: sessionData.alerts,
      urls: sessionData.urls,
      targetUrl: sessionData.sites[0] || 'Unknown Target',
      scanDate: new Date(),
      scanType: 'ZAP_SESSION'
    });
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Content-Disposition', `attachment; filename="SiberZed-ZAP-Report-${timestamp}.html"`);
    res.send(htmlReport);
    
  } catch (error: any) {
    console.error('❌ ZAP session report generation failed:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate ZAP session report',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// GET /api/reports/scan/:scanId/:format - Generate report for specific scan
router.get('/scan/:scanId/:format?', async (req: Request, res: Response) => {
  try {
    const { scanId, format = 'html' } = req.params;
    
    console.log(`🔄 Generating ${format.toUpperCase()} report for scan: ${scanId}`);
    
    // Fetch scan data from database
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: {
        vulnerabilities: true
      }
    });
    
    if (!scan) {
      console.error(`❌ Scan not found: ${scanId}`);
      res.status(404).json({
        success: false,
        message: 'Scan not found'
      });
      return;
    }
    
    
    // Prepare report data based on scan type
    let report: string;
    
    // Use new standardized report generator
    const vulnerabilities = scan.vulnerabilities.map(vuln => ({
      id: vuln.id,
      name: vuln.name,
      severity: vuln.severity as 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
      confidence: vuln.confidence || 'Medium',
      description: vuln.description || '',
      solution: vuln.solution || '',
      reference: vuln.reference || '',
      url: vuln.affectedUrl || vuln.url || '',
      param: vuln.param || '',
      evidence: vuln.evidence || ''
    }));
    
    const scanDuration = scan.completedAt && scan.startedAt 
      ? `${Math.round((new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000 / 60)} dakika`
      : 'Bilinmiyor';
    
    // Prepare additional info including API Deep Dive data
    const additionalInfo: any = {};
    if (scan.apiSecurity && typeof scan.apiSecurity === 'object') {
      console.log('📊 Adding API Deep Dive data to report:', scan.apiSecurity);
      additionalInfo.apiSecurity = scan.apiSecurity;
    }
    
    report = ReportGeneratorService.generateHtmlReport({
      title: scan.name,
      scanType: scan.scanType === 'MOBILE' ? 'MOBIL_TARAMA' : scan.scanType === 'API' ? 'API_TARAMASI' : 'WEB_TARAMASI',
      targetName: new URL(scan.targetUrl).hostname,
      targetUrl: scan.targetUrl,
      scanDate: scan.startedAt || new Date(),
      scanDuration: scanDuration,
      vulnerabilities: vulnerabilities,
      additionalInfo: additionalInfo
    });
    
    // Set response headers based on format
    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json');
      const jsonFilename = ReportGeneratorService.generateFilename(
        scan.scanType,
        new URL(scan.targetUrl).hostname
      ).replace('.html', '.json');
      res.setHeader('Content-Disposition', `attachment; filename="${jsonFilename}"`);
      res.send(JSON.stringify({
        scan: {
          id: scan.id,
          name: scan.name,
          targetUrl: scan.targetUrl,
          scanType: scan.scanType,
          status: scan.status,
          startedAt: scan.startedAt,
          completedAt: scan.completedAt
        },
        vulnerabilities: scan.vulnerabilities
      }, null, 2));
    } else {
      res.setHeader('Content-Type', 'text/html');
      const htmlFilename = ReportGeneratorService.generateFilename(
        scan.scanType,
        new URL(scan.targetUrl).hostname
      );
      res.setHeader('Content-Disposition', `attachment; filename="${htmlFilename}"`);
      res.send(report);
    }
    
    console.log(`✅ ${format.toUpperCase()} report generated successfully for scan: ${scanId}`);
  } catch (error: any) {
    console.error(`❌ Report generation failed for scan ${req.params.scanId}:`, error);
    console.error('Error stack:', error.stack);
    res.status(500).json({
      success: false,
      message: 'Failed to generate scan report',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// POST /api/reports/generate - Generate report for manual scan data
router.post('/generate', async (req: Request, res: Response) => {
  try {
    const { type, data, format = 'html' } = req.body;
    
    console.log(`🔄 Generating ${format.toUpperCase()} report for ${type}...`);
    
    if (type === 'manual-scan') {
      // Manuel scan verileri için HTML raporu oluştur
      const htmlReport = await zapReportGenerator.generateManualScanReport(data);
      
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      
      if (format === 'pdf') {
        // PDF için HTML'i PDF'e çevir (şimdilik HTML döndür)
        res.setHeader('Content-Type', 'text/html');
        res.setHeader('Content-Disposition', `attachment; filename="SiberZed-Manual-Scan-Report-${timestamp}.html"`);
      } else {
        res.setHeader('Content-Type', 'text/html');
        res.setHeader('Content-Disposition', `attachment; filename="SiberZed-Manual-Scan-Report-${timestamp}.html"`);
      }
      
      res.send(htmlReport);
    } else if (type === 'automated-scan') {
      // Otomatik scan verileri için HTML raporu oluştur
      const htmlReport = await zapReportGenerator.generateAutomatedScanReport(data);
      
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      
      res.setHeader('Content-Type', 'text/html');
      res.setHeader('Content-Disposition', `attachment; filename="SiberZed-Automated-Scan-Report-${timestamp}.html"`);
      
      res.send(htmlReport);
    } else {
      throw new Error(`Unsupported report type: ${type}`);
    }
  } catch (error: any) {
    console.error('❌ Manual scan report generation failed:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate manual scan report',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

export default router;
