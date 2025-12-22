import nodemailer from 'nodemailer';
import { PrismaClient } from '@prisma/client';
import { settingsService } from './settingsService';

export interface EmailConfig {
  to: string | string[];
  subject: string;
  html?: string;
  text?: string;
  attachments?: Array<{
    filename: string;
    content: Buffer | string;
    contentType?: string;
  }>;
}

export interface CiCdScanResult {
  scanId: string;
  projectName: string;
  branch: string;
  commitHash: string;
  targetUrl: string;
  vulnerabilities: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  scanDuration: number;
  scanDate: string;
  reportUrl?: string;
}

class EmailService {
  private transporter: nodemailer.Transporter | null = null;
  private prisma: PrismaClient;

  constructor() {
    this.prisma = new PrismaClient();
  }

  // Get or create transporter with current settings
  private async getTransporter(): Promise<nodemailer.Transporter | null> {
    try {
      const smtpSettings = await settingsService.getSmtpSettings();
      
      if (!smtpSettings || !smtpSettings.host || !smtpSettings.user) {
        return null;
      }

      // Create new transporter with current settings
      this.transporter = nodemailer.createTransport({
        host: smtpSettings.host,
        port: smtpSettings.port,
        secure: smtpSettings.secure,
        auth: {
          user: smtpSettings.user,
          pass: smtpSettings.pass
        },
        tls: {
          rejectUnauthorized: false // For self-signed certificates
        }
      });

      return this.transporter;
    } catch (error) {
      console.error('❌ Failed to create email transporter:', error);
      return null;
    }
  }

  // Send email
  async sendEmail(config: EmailConfig): Promise<boolean> {
    try {
      
      const transporter = await this.getTransporter();
      if (!transporter) {
        console.error('❌ Email transporter not available - SMTP not configured');
        return false;
      }

      const smtpSettings = await settingsService.getSmtpSettings();
      
      const mailOptions = {
        from: smtpSettings?.from || 'SiberZed Security <security@siberzed.local>',
        to: Array.isArray(config.to) ? config.to.join(', ') : config.to,
        subject: config.subject,
        text: config.text,
        html: config.html,
        attachments: config.attachments
      };

      const result = await transporter.sendMail(mailOptions);
      return true;
    } catch (error) {
      console.error('❌ Failed to send email:', error);
      return false;
    }
  }

  // Generate CI/CD scan report email
  async sendCiCdScanReport(scanResult: CiCdScanResult, recipientEmails: string[]): Promise<boolean> {
    try {
      const { vulnerabilities } = scanResult;
      const riskLevel = this.calculateRiskLevel(vulnerabilities);
      
      const subject = `🔒 Security Scan Report - ${scanResult.projectName} (${riskLevel})`;
      
      const html = this.generateCiCdReportHtml(scanResult);
      const text = this.generateCiCdReportText(scanResult);

      return await this.sendEmail({
        to: recipientEmails,
        subject,
        html,
        text
      });
    } catch (error) {
      console.error('❌ Failed to send CI/CD scan report:', error);
      return false;
    }
  }

  // Calculate overall risk level
  private calculateRiskLevel(vulnerabilities: CiCdScanResult['vulnerabilities']): string {
    if (vulnerabilities.critical > 0) return 'CRITICAL';
    if (vulnerabilities.high > 0) return 'HIGH RISK';
    if (vulnerabilities.medium > 0) return 'MEDIUM RISK';
    if (vulnerabilities.low > 0) return 'LOW RISK';
    return 'SECURE';
  }

  // Generate HTML report
  private generateCiCdReportHtml(scanResult: CiCdScanResult): string {
    const { vulnerabilities } = scanResult;
    const riskLevel = this.calculateRiskLevel(vulnerabilities);
    const riskColor = this.getRiskColor(riskLevel);

    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>SiberZed Security Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
            .content { padding: 30px; }
            .risk-badge { display: inline-block; padding: 8px 16px; border-radius: 20px; color: white; font-weight: bold; background-color: ${riskColor}; }
            .stats { display: flex; justify-content: space-around; margin: 20px 0; }
            .stat { text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px; margin: 0 5px; flex: 1; }
            .stat-number { font-size: 24px; font-weight: bold; color: #333; }
            .stat-label { font-size: 12px; color: #666; text-transform: uppercase; }
            .details { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .footer { background: #333; color: white; padding: 20px; text-align: center; font-size: 12px; }
            .critical { color: #dc3545; }
            .high { color: #fd7e14; }
            .medium { color: #ffc107; }
            .low { color: #28a745; }
            .info { color: #17a2b8; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔒 SiberZed Security Scan Report</h1>
                <div class="risk-badge">${riskLevel}</div>
            </div>
            
            <div class="content">
                <h2>Scan Summary</h2>
                <div class="details">
                    <p><strong>Project:</strong> ${scanResult.projectName}</p>
                    <p><strong>Branch:</strong> ${scanResult.branch}</p>
                    <p><strong>Commit:</strong> ${scanResult.commitHash}</p>
                    <p><strong>Target URL:</strong> ${scanResult.targetUrl}</p>
                    <p><strong>Scan Date:</strong> ${new Date(scanResult.scanDate).toLocaleString()}</p>
                    <p><strong>Duration:</strong> ${Math.round(scanResult.scanDuration / 1000)}s</p>
                </div>

                <h2>Vulnerability Summary</h2>
                <div class="stats">
                    <div class="stat">
                        <div class="stat-number critical">${vulnerabilities.critical}</div>
                        <div class="stat-label">Critical</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number high">${vulnerabilities.high}</div>
                        <div class="stat-label">High</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number medium">${vulnerabilities.medium}</div>
                        <div class="stat-label">Medium</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number low">${vulnerabilities.low}</div>
                        <div class="stat-label">Low</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number info">${vulnerabilities.info}</div>
                        <div class="stat-label">Info</div>
                    </div>
                </div>

                <div class="details">
                    <h3>📊 Total Vulnerabilities: ${vulnerabilities.total}</h3>
                    ${vulnerabilities.critical > 0 ? '<p class="critical">⚠️ <strong>CRITICAL vulnerabilities found!</strong> Immediate action required.</p>' : ''}
                    ${vulnerabilities.high > 0 ? '<p class="high">⚠️ High severity vulnerabilities detected.</p>' : ''}
                    ${vulnerabilities.total === 0 ? '<p class="low">✅ No security vulnerabilities detected!</p>' : ''}
                </div>

                <h2>📋 Recommendations</h2>
                <div class="details">
                    ${this.generateRecommendations(vulnerabilities)}
                </div>

                ${scanResult.reportUrl ? `
                <h2>📄 Detailed Report</h2>
                <div class="details">
                    <p>For detailed vulnerability information, please access the full report:</p>
                    <p><a href="${scanResult.reportUrl}" style="color: #667eea; text-decoration: none; font-weight: bold;">🔗 View Full Report</a></p>
                </div>
                ` : ''}
            </div>
            
            <div class="footer">
                <p>Generated by SiberZed Security Platform | ${new Date().toLocaleString()}</p>
                <p>This is an automated security scan report from your CI/CD pipeline</p>
            </div>
        </div>
    </body>
    </html>
    `;
  }

  // Generate text report
  private generateCiCdReportText(scanResult: CiCdScanResult): string {
    const { vulnerabilities } = scanResult;
    
    return `
SiberZed Security Scan Report
============================

Project: ${scanResult.projectName}
Branch: ${scanResult.branch}
Commit: ${scanResult.commitHash}
Target URL: ${scanResult.targetUrl}
Scan Date: ${new Date(scanResult.scanDate).toLocaleString()}
Duration: ${Math.round(scanResult.scanDuration / 1000)}s

Vulnerability Summary:
- Critical: ${vulnerabilities.critical}
- High: ${vulnerabilities.high}
- Medium: ${vulnerabilities.medium}
- Low: ${vulnerabilities.low}
- Info: ${vulnerabilities.info}
- Total: ${vulnerabilities.total}

Risk Level: ${this.calculateRiskLevel(vulnerabilities)}

${vulnerabilities.critical > 0 ? 'WARNING: CRITICAL vulnerabilities found! Immediate action required.' : ''}
${vulnerabilities.total === 0 ? 'GOOD NEWS: No security vulnerabilities detected!' : ''}

${scanResult.reportUrl ? `Full Report: ${scanResult.reportUrl}` : ''}

---
Generated by SiberZed Security Platform
This is an automated security scan report from your CI/CD pipeline
    `;
  }

  // Generate recommendations based on vulnerability counts
  private generateRecommendations(vulnerabilities: CiCdScanResult['vulnerabilities']): string {
    const recommendations: string[] = [];

    if (vulnerabilities.critical > 0) {
      recommendations.push('<p class="critical">🚨 <strong>CRITICAL:</strong> Block deployment immediately and fix critical vulnerabilities.</p>');
    }

    if (vulnerabilities.high > 0) {
      recommendations.push('<p class="high">⚠️ <strong>HIGH:</strong> Review and fix high severity issues before deployment.</p>');
    }

    if (vulnerabilities.medium > 0) {
      recommendations.push('<p class="medium">⚠️ <strong>MEDIUM:</strong> Schedule fixes for medium severity issues in next sprint.</p>');
    }

    if (vulnerabilities.low > 0) {
      recommendations.push('<p class="low">ℹ️ <strong>LOW:</strong> Address low severity issues when convenient.</p>');
    }

    if (vulnerabilities.total === 0) {
      recommendations.push('<p class="low">✅ <strong>SECURE:</strong> No security issues detected. Safe to deploy!</p>');
    }

    recommendations.push('<p>📋 <strong>Next Steps:</strong></p>');
    recommendations.push('<ul>');
    recommendations.push('<li>Review the detailed report for specific vulnerability details</li>');
    recommendations.push('<li>Prioritize fixes based on severity levels</li>');
    recommendations.push('<li>Re-run security scan after fixes</li>');
    recommendations.push('<li>Consider implementing security gates in your pipeline</li>');
    recommendations.push('</ul>');

    return recommendations.join('\n');
  }

  // Get risk color for styling
  private getRiskColor(riskLevel: string): string {
    switch (riskLevel) {
      case 'CRITICAL': return '#dc3545';
      case 'HIGH RISK': return '#fd7e14';
      case 'MEDIUM RISK': return '#ffc107';
      case 'LOW RISK': return '#28a745';
      case 'SECURE': return '#28a745';
      default: return '#6c757d';
    }
  }

  // Send CI/CD pipeline notification
  async sendPipelineNotification(config: {
    projectName: string;
    branch: string;
    commitHash: string;
    status: 'started' | 'completed' | 'failed';
    recipientEmails: string[];
    scanId?: string;
    error?: string;
  }): Promise<boolean> {
    try {
      const { projectName, branch, commitHash, status, recipientEmails } = config;
      
      let subject: string;
      let html: string;
      
      switch (status) {
        case 'started':
          subject = `🔄 Security Scan Started - ${projectName}`;
          html = `
            <h2>Security Scan Started</h2>
            <p><strong>Project:</strong> ${projectName}</p>
            <p><strong>Branch:</strong> ${branch}</p>
            <p><strong>Commit:</strong> ${commitHash}</p>
            <p><strong>Status:</strong> Scan is now running...</p>
            <p><em>You will receive another email when the scan completes.</em></p>
          `;
          break;
          
        case 'completed':
          subject = `✅ Security Scan Completed - ${projectName}`;
          html = `
            <h2>Security Scan Completed</h2>
            <p><strong>Project:</strong> ${projectName}</p>
            <p><strong>Branch:</strong> ${branch}</p>
            <p><strong>Commit:</strong> ${commitHash}</p>
            <p><strong>Scan ID:</strong> ${config.scanId}</p>
            <p><em>Detailed report will be sent separately.</em></p>
          `;
          break;
          
        case 'failed':
          subject = `❌ Security Scan Failed - ${projectName}`;
          html = `
            <h2>Security Scan Failed</h2>
            <p><strong>Project:</strong> ${projectName}</p>
            <p><strong>Branch:</strong> ${branch}</p>
            <p><strong>Commit:</strong> ${commitHash}</p>
            <p><strong>Error:</strong> ${config.error}</p>
            <p><em>Please check the pipeline logs for more details.</em></p>
          `;
          break;
      }

      return await this.sendEmail({
        to: recipientEmails,
        subject,
        html
      });
    } catch (error) {
      console.error('❌ Failed to send pipeline notification:', error);
      return false;
    }
  }

  // Test email configuration
  async testEmailConfig(): Promise<{ success: boolean; message: string }> {
    try {
      const transporter = await this.getTransporter();
      if (!transporter) {
        return {
          success: false,
          message: 'SMTP settings not configured'
        };
      }

      await transporter.verify();
      return {
        success: true,
        message: 'Email configuration is valid'
      };
    } catch (error) {
      return {
        success: false,
        message: `Email configuration error: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }
}

export const emailService = new EmailService();
export default emailService;
