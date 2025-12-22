import { Router, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { settingsService, SmtpSettings, CiCdSettings } from '../services/settingsService';
import { AuthenticatedRequest } from '../types/api.types';

const router = Router();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Admin authentication middleware
const requireAdmin = (req: AuthenticatedRequest, res: Response, next: any) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ success: false, message: 'Token bulunamadı' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    
    if (decoded.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Admin yetkisi gerekli' });
    }
    
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Geçersiz token' });
  }
};

// GET /api/admin/settings - Get all system settings
router.get('/settings', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const settings = await settingsService.getSettingsForAdmin();
    
    res.json({
      success: true,
      data: settings
    });
  } catch (error) {
    console.error('Failed to get system settings:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get system settings',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// GET /api/admin/settings/smtp - Get SMTP settings
router.get('/settings/smtp', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const smtpSettings = await settingsService.getSmtpSettings();
    
    if (!smtpSettings) {
      return res.json({
        success: true,
        data: {
          host: '',
          port: 587,
          secure: false,
          user: '',
          pass: '',
          from: 'SiberZed Security <security@siberzed.local>'
        }
      });
    }

    // Don't send password to frontend
    res.json({
      success: true,
      data: {
        ...smtpSettings,
        pass: smtpSettings.pass ? '***configured***' : ''
      }
    });
  } catch (error) {
    console.error('Failed to get SMTP settings:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get SMTP settings',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// POST /api/admin/settings/smtp - Save SMTP settings
router.post('/settings/smtp', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { host, port, secure, user, pass, from } = req.body;
    
    // Validation
    if (!host || !user) {
      return res.status(400).json({
        success: false,
        message: 'Host and user are required'
      });
    }

    const smtpSettings: SmtpSettings = {
      host,
      port: parseInt(port) || 587,
      secure: secure === true || secure === 'true',
      user,
      pass: pass || '',
      from: from || `SiberZed Security <${user}>`
    };

    const success = await settingsService.saveSmtpSettings(smtpSettings, req.user?.id);
    
    if (success) {
      res.json({
        success: true,
        message: 'SMTP settings saved successfully'
      });
    } else {
      res.status(500).json({
        success: false,
        message: 'Failed to save SMTP settings'
      });
    }
  } catch (error) {
    console.error('Failed to save SMTP settings:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to save SMTP settings',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// POST /api/admin/settings/smtp/test - Test SMTP connection
router.post('/settings/smtp/test', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { testEmail } = req.body;
    
    if (!testEmail) {
      return res.status(400).json({
        success: false,
        message: 'Test email address is required'
      });
    }

    // Test SMTP connection
    const connectionTest = await settingsService.testSmtpConnection();
    
    if (!connectionTest.success) {
      return res.status(500).json({
        success: false,
        message: connectionTest.message
      });
    }

    // Send test email
    const emailService = require('../services/emailService').default;
    const emailSent = await emailService.sendEmail({
      to: testEmail,
      subject: '🔧 SiberZed SMTP Test',
      html: `
        <h2>SMTP Configuration Test</h2>
        <p>This is a test email from SiberZed Security Platform.</p>
        <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
        <p>If you received this email, your SMTP configuration is working correctly!</p>
        <hr>
        <p><em>SiberZed Security Platform</em></p>
      `,
      text: `SMTP Configuration Test\n\nThis is a test email from SiberZed Security Platform.\nTime: ${new Date().toLocaleString()}\n\nIf you received this email, your SMTP configuration is working correctly!`
    });

    res.json({
      success: emailSent,
      message: emailSent ? 'Test email sent successfully' : 'Failed to send test email'
    });

  } catch (error) {
    console.error('SMTP test failed:', error);
    res.status(500).json({
      success: false,
      message: 'SMTP test failed',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// GET /api/admin/settings/cicd - Get CI/CD settings
router.get('/settings/cicd', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const cicdSettings = await settingsService.getCiCdSettings();
    
    res.json({
      success: true,
      data: {
        ...cicdSettings,
        apiKeys: cicdSettings.apiKeys.map(key => ({
          key: key.substring(0, 20) + '...', // Mask API keys
          fullKey: key // For admin to copy if needed
        }))
      }
    });
  } catch (error) {
    console.error('Failed to get CI/CD settings:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get CI/CD settings',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// POST /api/admin/settings/cicd - Save CI/CD settings
router.post('/settings/cicd', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const {
      apiKeys,
      frontendUrl,
      defaultRecipients,
      securityGates
    } = req.body;

    const cicdSettings: CiCdSettings = {
      apiKeys: Array.isArray(apiKeys) ? apiKeys : [],
      frontendUrl: frontendUrl || 'http://localhost:3000',
      defaultRecipients: Array.isArray(defaultRecipients) ? defaultRecipients : [],
      securityGates: {
        failOnCritical: securityGates?.failOnCritical !== false,
        failOnHighCount: parseInt(securityGates?.failOnHighCount) || 10,
        warnOnMediumCount: parseInt(securityGates?.warnOnMediumCount) || 20
      }
    };

    const success = await settingsService.saveCiCdSettings(cicdSettings, req.user?.id);
    
    if (success) {
      res.json({
        success: true,
        message: 'CI/CD settings saved successfully'
      });
    } else {
      res.status(500).json({
        success: false,
        message: 'Failed to save CI/CD settings'
      });
    }
  } catch (error) {
    console.error('Failed to save CI/CD settings:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to save CI/CD settings',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// POST /api/admin/settings/cicd/api-key - Generate new CI/CD API key
router.post('/settings/cicd/api-key', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { keyName } = req.body;
    
    const result = await settingsService.addCiCdApiKey(keyName || 'New API Key', req.user?.id);
    
    if (result.success) {
      res.json({
        success: true,
        message: 'New API key generated successfully',
        data: {
          apiKey: result.apiKey
        }
      });
    } else {
      res.status(500).json({
        success: false,
        message: 'Failed to generate new API key'
      });
    }
  } catch (error) {
    console.error('Failed to generate API key:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate API key',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// DELETE /api/admin/settings/cicd/api-key - Remove CI/CD API key
router.delete('/settings/cicd/api-key', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { apiKey } = req.body;
    
    if (!apiKey) {
      return res.status(400).json({
        success: false,
        message: 'API key is required'
      });
    }

    const success = await settingsService.removeCiCdApiKey(apiKey, req.user?.id);
    
    if (success) {
      res.json({
        success: true,
        message: 'API key removed successfully'
      });
    } else {
      res.status(500).json({
        success: false,
        message: 'Failed to remove API key'
      });
    }
  } catch (error) {
    console.error('Failed to remove API key:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to remove API key',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// GET /api/admin/settings/status - Get system settings status
router.get('/settings/status', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const [smtpSettings, cicdSettings] = await Promise.all([
      settingsService.getSmtpSettings(),
      settingsService.getCiCdSettings()
    ]);

    const smtpTest = smtpSettings ? await settingsService.testSmtpConnection() : { success: false, message: 'Not configured' };

    res.json({
      success: true,
      data: {
        smtp: {
          configured: !!smtpSettings,
          working: smtpTest.success,
          message: smtpTest.message
        },
        cicd: {
          configured: cicdSettings.apiKeys.length > 0,
          apiKeyCount: cicdSettings.apiKeys.length,
          securityGatesEnabled: cicdSettings.securityGates.failOnCritical
        },
        general: {
          settingsInitialized: true
        }
      }
    });
  } catch (error) {
    console.error('Failed to get settings status:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get settings status',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

export default router;
