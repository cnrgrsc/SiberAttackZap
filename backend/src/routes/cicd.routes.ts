import { Router, Request, Response } from 'express';
import { ZapProxyService } from '../services/zapProxy.service';
import { emailService, CiCdScanResult } from '../services/emailService';
import { settingsService } from '../services/settingsService';
import { PrismaClient } from '@prisma/client';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';

const router = Router();
const prisma = new PrismaClient();

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// API Key authentication for CI/CD (more suitable than JWT for automation)
const authenticateApiKey = async (req: any, res: Response, next: any) => {
  try {
    const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
    
    if (!apiKey) {
      return res.status(401).json({ 
        success: false, 
        message: 'API key required. Use X-API-Key header or Authorization: Bearer <key>' 
      });
    }

    // Check if API key is valid using database settings
    const isValid = await settingsService.validateCiCdApiKey(apiKey);
    
    if (!isValid) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid API key' 
      });
    }

    next();
  } catch (error) {
    return res.status(401).json({ 
      success: false, 
      message: 'Authentication failed' 
    });
  }
};

// POST /api/cicd/scan - Start CI/CD security scan
router.post('/scan', authenticateApiKey, async (req: Request, res: Response) => {
  try {
    const {
      targetUrl,
      projectName,
      branch = 'main',
      commitHash = 'unknown',
      recipientEmails = [],
      scanOptions = {}
    } = req.body;

    // Validation
    if (!targetUrl) {
      return res.status(400).json({
        success: false,
        message: 'targetUrl is required'
      });
    }

    if (!projectName) {
      return res.status(400).json({
        success: false,
        message: 'projectName is required'
      });
    }

    console.log(`🚀 Starting CI/CD security scan for ${projectName} (${branch})`);

    // Create scan record
    const scanId = uuidv4();
    const workflowId = uuidv4();
    
    const scan = await prisma.scan.create({
      data: {
        id: scanId,
        name: `CI/CD Scan - ${projectName} (${branch})`,
        targetUrl,
        scanType: 'CICD_AUTOMATED',
        status: 'RUNNING',
        zapScanId: workflowId,
        workflowId,
        metadata: JSON.stringify({
          projectName,
          branch,
          commitHash,
          recipientEmails,
          scanOptions,
          cicdPipeline: true
        })
      }
    });

    // Send initial notification
    if (recipientEmails.length > 0) {
      await emailService.sendPipelineNotification({
        projectName,
        branch,
        commitHash,
        status: 'started',
        recipientEmails,
        scanId
      });
    }

    // Start the scan workflow (don't await - let it run in background)
    const zapService = new ZapProxyService();
    
    // Start workflow in background with completion callback
    zapService.startCompleteWorkflow(workflowId, {
      targetUrl,
      enableSpider: scanOptions.enableSpider !== false,
      enableAjaxSpider: scanOptions.enableAjaxSpider !== false,
      enableActiveScan: scanOptions.enableActiveScan !== false,
      spiderOptions: scanOptions.spiderOptions || { maxChildren: 20 },
      ajaxSpiderOptions: scanOptions.ajaxSpiderOptions || { enabled: true },
      activeScanOptions: scanOptions.activeScanOptions || { enabled: true }
    }, scanId).then(async () => {
      // Scan completed successfully
      
      try {
        // Update scan status
        await prisma.scan.update({
          where: { id: scanId },
          data: { 
            status: 'COMPLETED',
            completedAt: new Date()
          }
        });

        // Send completion notification
        if (recipientEmails.length > 0) {
          await emailService.sendPipelineNotification({
            projectName,
            branch,
            commitHash,
            status: 'completed',
            recipientEmails,
            scanId
          });

          // Generate and send detailed report
          await sendDetailedReport(scanId, projectName, branch, commitHash, recipientEmails);
        }

      } catch (error) {
        console.error('❌ Error in CI/CD scan completion:', error);
      }
    }).catch(async (error) => {
      // Scan failed
      console.error(`❌ CI/CD scan failed for ${projectName}:`, error);
      
      try {
        // Update scan status
        await prisma.scan.update({
          where: { id: scanId },
          data: { 
            status: 'FAILED',
            completedAt: new Date()
          }
        });

        // Send failure notification
        if (recipientEmails.length > 0) {
          await emailService.sendPipelineNotification({
            projectName,
            branch,
            commitHash,
            status: 'failed',
            recipientEmails,
            scanId,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      } catch (dbError) {
        console.error('❌ Error updating failed scan status:', dbError);
      }
    });

    // Return immediate response
    res.json({
      success: true,
      data: {
        scanId,
        workflowId,
        message: 'CI/CD security scan started successfully',
        projectName,
        branch,
        commitHash,
        targetUrl,
        estimatedDuration: '5-15 minutes',
        statusUrl: `/api/cicd/scan/${scanId}/status`
      }
    });

  } catch (error) {
    console.error('❌ CI/CD scan initiation failed:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to start CI/CD scan',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// GET /api/cicd/scan/:scanId/status - Get CI/CD scan status
router.get('/scan/:scanId/status', authenticateApiKey, async (req: Request, res: Response) => {
  try {
    const { scanId } = req.params;
    
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: {
        vulnerabilities: {
          select: {
            severity: true
          }
        }
      }
    });

    if (!scan) {
      return res.status(404).json({
        success: false,
        message: 'Scan not found'
      });
    }

    // Calculate vulnerability counts
    const vulnerabilityCounts = {
      total: scan.vulnerabilities.length,
      critical: scan.vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
      high: scan.vulnerabilities.filter(v => v.severity === 'HIGH').length,
      medium: scan.vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
      low: scan.vulnerabilities.filter(v => v.severity === 'LOW').length,
      info: scan.vulnerabilities.filter(v => v.severity === 'INFO').length
    };

    const metadata = scan.metadata ? JSON.parse(scan.metadata as string) : {};

    res.json({
      success: true,
      data: {
        scanId: scan.id,
        workflowId: scan.workflowId,
        projectName: metadata.projectName,
        branch: metadata.branch,
        commitHash: metadata.commitHash,
        targetUrl: scan.targetUrl,
        status: scan.status,
        startedAt: scan.startedAt,
        completedAt: scan.completedAt,
        vulnerabilities: vulnerabilityCounts,
        progress: scan.status === 'COMPLETED' ? 100 : (scan.status === 'RUNNING' ? 50 : 0)
      }
    });

  } catch (error) {
    console.error('❌ Failed to get CI/CD scan status:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get scan status',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// POST /api/cicd/scan/:scanId/stop - Stop CI/CD scan
router.post('/scan/:scanId/stop', authenticateApiKey, async (req: Request, res: Response) => {
  try {
    const { scanId } = req.params;
    
    const scan = await prisma.scan.findUnique({
      where: { id: scanId }
    });

    if (!scan) {
      return res.status(404).json({
        success: false,
        message: 'Scan not found'
      });
    }

    if (scan.status !== 'RUNNING') {
      return res.status(400).json({
        success: false,
        message: 'Scan is not running'
      });
    }

    // Stop the workflow
    const zapService = new ZapProxyService();
    if (scan.workflowId) {
      await zapService.stopWorkflow(scan.workflowId);
    }

    // Update scan status
    await prisma.scan.update({
      where: { id: scanId },
      data: { 
        status: 'CANCELLED',
        completedAt: new Date()
      }
    });

    res.json({
      success: true,
      data: {
        message: 'CI/CD scan stopped successfully',
        scanId,
        status: 'CANCELLED'
      }
    });

  } catch (error) {
    console.error('❌ Failed to stop CI/CD scan:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to stop scan',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// GET /api/cicd/scan/:scanId/report - Get CI/CD scan report
router.get('/scan/:scanId/report', authenticateApiKey, async (req: Request, res: Response) => {
  try {
    const { scanId } = req.params;
    const { format = 'json' } = req.query;
    
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: {
        vulnerabilities: true,
        scanUrls: true
      }
    });

    if (!scan) {
      return res.status(404).json({
        success: false,
        message: 'Scan not found'
      });
    }

    const metadata = scan.metadata ? JSON.parse(scan.metadata as string) : {};
    
    const reportData = {
      scanId: scan.id,
      projectName: metadata.projectName,
      branch: metadata.branch,
      commitHash: metadata.commitHash,
      targetUrl: scan.targetUrl,
      scanDate: scan.startedAt,
      completedDate: scan.completedAt,
      status: scan.status,
      vulnerabilities: scan.vulnerabilities.map(v => ({
        name: v.name,
        severity: v.severity,
        description: v.description,
        url: v.affectedUrl,
        solution: v.solution
      })),
      vulnerabilityCounts: {
        total: scan.vulnerabilities.length,
        critical: scan.vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
        high: scan.vulnerabilities.filter(v => v.severity === 'HIGH').length,
        medium: scan.vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
        low: scan.vulnerabilities.filter(v => v.severity === 'LOW').length,
        info: scan.vulnerabilities.filter(v => v.severity === 'INFO').length
      },
      urlsFound: scan.scanUrls.length,
      scanDuration: scan.completedAt && scan.startedAt ? 
        scan.completedAt.getTime() - scan.startedAt.getTime() : 0
    };

    if (format === 'html') {
      // Return HTML report
      res.setHeader('Content-Type', 'text/html');
      res.send(generateHtmlReport(reportData));
    } else {
      // Return JSON report
      res.json({
        success: true,
        data: reportData
      });
    }

  } catch (error) {
    console.error('❌ Failed to get CI/CD scan report:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get scan report',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// POST /api/cicd/test-email - Test email configuration
router.post('/test-email', authenticateApiKey, async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'email is required'
      });
    }

    // Test email configuration
    const configTest = await emailService.testEmailConfig();
    if (!configTest.success) {
      return res.status(500).json({
        success: false,
        message: configTest.message
      });
    }

    // Send test email
    const testResult = await emailService.sendEmail({
      to: email,
      subject: '🔧 SiberZed CI/CD Email Test',
      html: `
        <h2>Email Configuration Test</h2>
        <p>This is a test email from SiberZed CI/CD integration.</p>
        <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
        <p>If you received this email, the configuration is working correctly!</p>
      `,
      text: `SiberZed CI/CD Email Test\n\nThis is a test email from SiberZed CI/CD integration.\nTime: ${new Date().toLocaleString()}\n\nIf you received this email, the configuration is working correctly!`
    });

    res.json({
      success: testResult,
      message: testResult ? 'Test email sent successfully' : 'Failed to send test email'
    });

  } catch (error) {
    console.error('❌ Email test failed:', error);
    res.status(500).json({
      success: false,
      message: 'Email test failed',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Helper function to send detailed report
async function sendDetailedReport(
  scanId: string, 
  projectName: string, 
  branch: string, 
  commitHash: string, 
  recipientEmails: string[]
): Promise<void> {
  try {
    
    // Get scan data with vulnerabilities
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: {
        vulnerabilities: true,
        scanUrls: true
      }
    });

    if (!scan) {
      console.error('❌ Scan not found for report generation');
      return;
    }

    // Prepare report data
    const vulnerabilityCounts = {
      total: scan.vulnerabilities.length,
      critical: scan.vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
      high: scan.vulnerabilities.filter(v => v.severity === 'HIGH').length,
      medium: scan.vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
      low: scan.vulnerabilities.filter(v => v.severity === 'LOW').length,
      info: scan.vulnerabilities.filter(v => v.severity === 'INFO').length
    };

    const scanResult: CiCdScanResult = {
      scanId,
      projectName,
      branch,
      commitHash,
      targetUrl: scan.targetUrl,
      vulnerabilities: vulnerabilityCounts,
      scanDuration: scan.completedAt && scan.startedAt ? 
        scan.completedAt.getTime() - scan.startedAt.getTime() : 0,
      scanDate: scan.startedAt.toISOString(),
      reportUrl: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/scan-details/${scanId}`
    };

    // Send detailed report email
    const emailSent = await emailService.sendCiCdScanReport(scanResult, recipientEmails);
    
    if (emailSent) {
    } else {
      console.error('❌ Failed to send detailed report email');
    }

  } catch (error) {
    console.error('❌ Error sending detailed report:', error);
  }
}

// Helper function to generate HTML report
function generateHtmlReport(reportData: any): string {
  const riskLevel = reportData.vulnerabilityCounts.critical > 0 ? 'CRITICAL' :
                   reportData.vulnerabilityCounts.high > 0 ? 'HIGH RISK' :
                   reportData.vulnerabilityCounts.medium > 0 ? 'MEDIUM RISK' :
                   reportData.vulnerabilityCounts.low > 0 ? 'LOW RISK' : 'SECURE';

  return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CI/CD Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .content { padding: 30px; }
        .risk-badge { display: inline-block; padding: 8px 16px; border-radius: 20px; color: white; font-weight: bold; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat { text-align: center; padding: 20px; background: #f8f9fa; border-radius: 8px; }
        .stat-number { font-size: 28px; font-weight: bold; }
        .stat-label { font-size: 14px; color: #666; text-transform: uppercase; margin-top: 5px; }
        .details { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .vulnerability-list { margin-top: 20px; }
        .vulnerability { padding: 15px; margin: 10px 0; border-left: 4px solid #ddd; background: white; border-radius: 4px; }
        .critical { border-left-color: #dc3545; }
        .high { border-left-color: #fd7e14; }
        .medium { border-left-color: #ffc107; }
        .low { border-left-color: #28a745; }
        .info { border-left-color: #17a2b8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 CI/CD Security Scan Report</h1>
            <div class="risk-badge" style="background-color: ${getRiskColor(riskLevel)}">${riskLevel}</div>
        </div>
        
        <div class="content">
            <div class="details">
                <h2>Project Information</h2>
                <p><strong>Project:</strong> ${reportData.projectName}</p>
                <p><strong>Branch:</strong> ${reportData.branch}</p>
                <p><strong>Commit:</strong> ${reportData.commitHash}</p>
                <p><strong>Target URL:</strong> ${reportData.targetUrl}</p>
                <p><strong>Scan Date:</strong> ${new Date(reportData.scanDate).toLocaleString()}</p>
                <p><strong>Duration:</strong> ${Math.round(reportData.scanDuration / 1000)}s</p>
                <p><strong>URLs Found:</strong> ${reportData.urlsFound}</p>
            </div>

            <div class="stats">
                <div class="stat">
                    <div class="stat-number" style="color: #dc3545">${reportData.vulnerabilityCounts.critical}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat">
                    <div class="stat-number" style="color: #fd7e14">${reportData.vulnerabilityCounts.high}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat">
                    <div class="stat-number" style="color: #ffc107">${reportData.vulnerabilityCounts.medium}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat">
                    <div class="stat-number" style="color: #28a745">${reportData.vulnerabilityCounts.low}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat">
                    <div class="stat-number" style="color: #17a2b8">${reportData.vulnerabilityCounts.info}</div>
                    <div class="stat-label">Info</div>
                </div>
            </div>

            ${reportData.vulnerabilities.length > 0 ? `
            <div class="vulnerability-list">
                <h2>Detected Vulnerabilities</h2>
                ${reportData.vulnerabilities.slice(0, 20).map((vuln: any) => `
                <div class="vulnerability ${vuln.severity.toLowerCase()}">
                    <h3>${vuln.name}</h3>
                    <p><strong>Severity:</strong> ${vuln.severity}</p>
                    <p><strong>URL:</strong> ${vuln.url}</p>
                    <p><strong>Description:</strong> ${vuln.description}</p>
                    ${vuln.solution ? `<p><strong>Solution:</strong> ${vuln.solution}</p>` : ''}
                </div>
                `).join('')}
                ${reportData.vulnerabilities.length > 20 ? `<p><em>... and ${reportData.vulnerabilities.length - 20} more vulnerabilities</em></p>` : ''}
            </div>
            ` : '<div class="details"><h2>✅ No Vulnerabilities Found</h2><p>Great! No security issues were detected in this scan.</p></div>'}
        </div>
    </div>
</body>
</html>
  `;
}

// Helper function for risk colors
function getRiskColor(riskLevel: string): string {
  switch (riskLevel) {
    case 'CRITICAL': return '#dc3545';
    case 'HIGH RISK': return '#fd7e14';
    case 'MEDIUM RISK': return '#ffc107';
    case 'LOW RISK': return '#28a745';
    case 'SECURE': return '#28a745';
    default: return '#6c757d';
  }
}

export default router;
