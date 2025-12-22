import { PrismaClient } from '@prisma/client';
import crypto from 'crypto';

export interface SystemSetting {
  id: string;
  category: string;
  key: string;
  value: string;
  description?: string;
  isEncrypted: boolean;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
  updatedBy?: string;
}

export interface SmtpSettings {
  host: string;
  port: number;
  secure: boolean;
  user: string;
  pass: string;
  from: string;
}

export interface CiCdSettings {
  apiKeys: string[];
  frontendUrl: string;
  defaultRecipients: string[];
  securityGates: {
    failOnCritical: boolean;
    failOnHighCount: number;
    warnOnMediumCount: number;
  };
}

class SettingsService {
  private prisma: PrismaClient;
  private encryptionKey: string;

  constructor() {
    this.prisma = new PrismaClient();
    this.encryptionKey = process.env.ENCRYPTION_KEY || 'default-encryption-key-change-this';
  }

  // Encrypt sensitive data
  private encrypt(text: string): string {
    // Use AES-256-CBC with an IV and a SHA-256 derived key for compatibility with modern Node.js
    const key = crypto.createHash('sha256').update(this.encryptionKey).digest();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    // Store IV with the ciphertext, separated by a colon
    return iv.toString('hex') + ':' + encrypted;
  }

  // Decrypt sensitive data
  private decrypt(encryptedText: string): string {
    // Guard for environments where crypto.createDecipheriv may be unavailable
    if (typeof (crypto as any).createDecipheriv !== 'function') {
      return encryptedText;
    }
    try {
      // Ensure the value looks like our IV:ciphertext format
      if (!encryptedText.includes(':')) {
        return encryptedText;
      }
      // Encrypted format: <iv_hex>:<ciphertext_hex>
      const [ivHex, data] = encryptedText.split(':');
      const key = crypto.createHash('sha256').update(this.encryptionKey).digest();
      const iv = Buffer.from(ivHex, 'hex');
      const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      let decrypted = decipher.update(data, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (error) {
      console.error('Decryption failed:', error);
      return encryptedText; // Return as-is if decryption fails
    }
  }

  // Get setting by category and key
  async getSetting(category: string, key: string): Promise<string | null> {
    try {
      const setting = await this.prisma.systemSettings.findUnique({
        where: {
          category_key: { category, key }
        }
      });

      if (!setting || !setting.isActive) {
        return null;
      }

      return setting.isEncrypted ? this.decrypt(setting.value) : setting.value;
    } catch (error) {
      console.error(`Error getting setting ${category}.${key}:`, error);
      return null;
    }
  }

  // Set setting
  async setSetting(
    category: string, 
    key: string, 
    value: string, 
    description?: string, 
    isEncrypted: boolean = false,
    updatedBy?: string
  ): Promise<boolean> {
    try {
      const finalValue = isEncrypted ? this.encrypt(value) : value;

      await this.prisma.systemSettings.upsert({
        where: {
          category_key: { category, key }
        },
        update: {
          value: finalValue,
          description,
          isEncrypted,
          updatedBy,
          updatedAt: new Date()
        },
        create: {
          category,
          key,
          value: finalValue,
          description,
          isEncrypted,
          updatedBy
        }
      });

      return true;
    } catch (error) {
      console.error(`❌ Error setting ${category}.${key}:`, error);
      return false;
    }
  }

  // Get all settings by category
  async getSettingsByCategory(category: string): Promise<Record<string, string>> {
    try {
      const settings = await this.prisma.systemSettings.findMany({
        where: {
          category,
          isActive: true
        }
      });

      const result: Record<string, string> = {};
      
      settings.forEach(setting => {
        result[setting.key] = setting.isEncrypted ? 
          this.decrypt(setting.value) : setting.value;
      });

      return result;
    } catch (error) {
      console.error(`Error getting settings for category ${category}:`, error);
      return {};
    }
  }

  // Get SMTP settings
  async getSmtpSettings(): Promise<SmtpSettings | null> {
    try {
      const smtpSettings = await this.getSettingsByCategory('SMTP');
      
      if (!smtpSettings.host || !smtpSettings.user) {
        return null;
      }

      return {
        host: smtpSettings.host,
        port: parseInt(smtpSettings.port || '587'),
        secure: smtpSettings.secure === 'true',
        user: smtpSettings.user,
        pass: smtpSettings.pass || '',
        from: smtpSettings.from || `SiberZed Security <${smtpSettings.user}>`
      };
    } catch (error) {
      console.error('Error getting SMTP settings:', error);
      return null;
    }
  }

  // Get CI/CD settings
  async getCiCdSettings(): Promise<CiCdSettings> {
    try {
      const cicdSettings = await this.getSettingsByCategory('CICD');
      
      return {
        apiKeys: cicdSettings.api_keys ? cicdSettings.api_keys.split(',').filter(Boolean) : [],
        frontendUrl: cicdSettings.frontend_url || 'http://localhost:3000',
        defaultRecipients: cicdSettings.default_recipients ? 
          cicdSettings.default_recipients.split(',').filter(Boolean) : [],
        securityGates: {
          failOnCritical: cicdSettings.fail_on_critical !== 'false',
          failOnHighCount: parseInt(cicdSettings.fail_on_high_count || '10'),
          warnOnMediumCount: parseInt(cicdSettings.warn_on_medium_count || '20')
        }
      };
    } catch (error) {
      console.error('Error getting CI/CD settings:', error);
      return {
        apiKeys: [],
        frontendUrl: 'http://localhost:3000',
        defaultRecipients: [],
        securityGates: {
          failOnCritical: true,
          failOnHighCount: 10,
          warnOnMediumCount: 20
        }
      };
    }
  }

  // Save SMTP settings
  async saveSmtpSettings(settings: SmtpSettings, updatedBy?: string): Promise<boolean> {
    try {
      const updates = [
        this.setSetting('SMTP', 'host', settings.host, 'SMTP Server Host', false, updatedBy),
        this.setSetting('SMTP', 'port', settings.port.toString(), 'SMTP Server Port', false, updatedBy),
        this.setSetting('SMTP', 'secure', settings.secure.toString(), 'Use SSL/TLS', false, updatedBy),
        this.setSetting('SMTP', 'user', settings.user, 'SMTP Username', false, updatedBy),
        this.setSetting('SMTP', 'pass', settings.pass, 'SMTP Password', true, updatedBy), // Encrypted
        this.setSetting('SMTP', 'from', settings.from, 'From Email Address', false, updatedBy)
      ];

      const results = await Promise.all(updates);
      return results.every(result => result);
    } catch (error) {
      console.error('Error saving SMTP settings:', error);
      return false;
    }
  }

  // Save CI/CD settings
  async saveCiCdSettings(settings: CiCdSettings, updatedBy?: string): Promise<boolean> {
    try {
      const updates = [
        this.setSetting('CICD', 'api_keys', settings.apiKeys.join(','), 'CI/CD API Keys', true, updatedBy), // Encrypted
        this.setSetting('CICD', 'frontend_url', settings.frontendUrl, 'Frontend URL for reports', false, updatedBy),
        this.setSetting('CICD', 'default_recipients', settings.defaultRecipients.join(','), 'Default email recipients', false, updatedBy),
        this.setSetting('CICD', 'fail_on_critical', settings.securityGates.failOnCritical.toString(), 'Fail pipeline on critical vulnerabilities', false, updatedBy),
        this.setSetting('CICD', 'fail_on_high_count', settings.securityGates.failOnHighCount.toString(), 'Fail pipeline if high vulnerabilities exceed this count', false, updatedBy),
        this.setSetting('CICD', 'warn_on_medium_count', settings.securityGates.warnOnMediumCount.toString(), 'Warn if medium vulnerabilities exceed this count', false, updatedBy)
      ];

      const results = await Promise.all(updates);
      return results.every(result => result);
    } catch (error) {
      console.error('Error saving CI/CD settings:', error);
      return false;
    }
  }

  // Get all settings for admin panel
  async getAllSettings(): Promise<Record<string, Record<string, any>>> {
    try {
      const settings = await this.prisma.systemSettings.findMany({
        where: { isActive: true },
        orderBy: [
          { category: 'asc' },
          { key: 'asc' }
        ]
      });

      const result: Record<string, Record<string, any>> = {};

      settings.forEach(setting => {
        if (!result[setting.category]) {
          result[setting.category] = {};
        }

        result[setting.category][setting.key] = {
          value: setting.isEncrypted ? '***encrypted***' : setting.value,
          description: setting.description,
          isEncrypted: setting.isEncrypted,
          updatedAt: setting.updatedAt,
          updatedBy: setting.updatedBy
        };
      });

      return result;
    } catch (error) {
      console.error('Error getting all settings:', error);
      return {};
    }
  }

  // Delete setting
  async deleteSetting(category: string, key: string): Promise<boolean> {
    try {
      await this.prisma.systemSettings.update({
        where: {
          category_key: { category, key }
        },
        data: {
          isActive: false
        }
      });

      return true;
    } catch (error) {
      console.error(`❌ Error deleting setting ${category}.${key}:`, error);
      return false;
    }
  }

  // Test SMTP connection
  async testSmtpConnection(): Promise<{ success: boolean; message: string }> {
    try {
      const smtpSettings = await this.getSmtpSettings();
      
      if (!smtpSettings) {
        return {
          success: false,
          message: 'SMTP settings not configured'
        };
      }

      const nodemailer = require('nodemailer');
      const transporter = nodemailer.createTransporter({
        host: smtpSettings.host,
        port: smtpSettings.port,
        secure: smtpSettings.secure,
        auth: {
          user: smtpSettings.user,
          pass: smtpSettings.pass
        }
      });

      await transporter.verify();
      
      return {
        success: true,
        message: 'SMTP connection successful'
      };
    } catch (error) {
      return {
        success: false,
        message: `SMTP connection failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  // Initialize default settings
  async initializeDefaultSettings(): Promise<void> {
    try {
      
      // Default SMTP settings (empty, to be configured by admin)
      const defaultSettings = [
        // SMTP Settings
        { category: 'SMTP', key: 'host', value: '', description: 'SMTP Server Host (e.g., smtp.gmail.com)', isEncrypted: false },
        { category: 'SMTP', key: 'port', value: '587', description: 'SMTP Server Port', isEncrypted: false },
        { category: 'SMTP', key: 'secure', value: 'false', description: 'Use SSL/TLS (true/false)', isEncrypted: false },
        { category: 'SMTP', key: 'user', value: '', description: 'SMTP Username/Email', isEncrypted: false },
        { category: 'SMTP', key: 'pass', value: '', description: 'SMTP Password', isEncrypted: true },
        { category: 'SMTP', key: 'from', value: 'SiberZed Security <security@siberzed.local>', description: 'From Email Address', isEncrypted: false },
        
        // CI/CD Settings
        { category: 'CICD', key: 'api_keys', value: '', description: 'CI/CD API Keys (comma separated)', isEncrypted: true },
        { category: 'CICD', key: 'frontend_url', value: 'http://localhost:3000', description: 'Frontend URL for report links', isEncrypted: false },
        { category: 'CICD', key: 'default_recipients', value: '', description: 'Default email recipients (comma separated)', isEncrypted: false },
        { category: 'CICD', key: 'fail_on_critical', value: 'true', description: 'Fail pipeline on critical vulnerabilities', isEncrypted: false },
        { category: 'CICD', key: 'fail_on_high_count', value: '10', description: 'Fail pipeline if high vulnerabilities exceed this count', isEncrypted: false },
        { category: 'CICD', key: 'warn_on_medium_count', value: '20', description: 'Warn if medium vulnerabilities exceed this count', isEncrypted: false },
        
        // Security Settings
        { category: 'SECURITY', key: 'max_scan_duration', value: '3600000', description: 'Maximum scan duration in milliseconds', isEncrypted: false },
        { category: 'SECURITY', key: 'concurrent_scans_limit', value: '5', description: 'Maximum concurrent scans allowed', isEncrypted: false },
        { category: 'SECURITY', key: 'auto_cleanup_days', value: '30', description: 'Auto cleanup scan data after N days', isEncrypted: false },
        
        // General Settings
        { category: 'GENERAL', key: 'app_name', value: 'SiberZed Security Platform', description: 'Application Name', isEncrypted: false },
        { category: 'GENERAL', key: 'company_name', value: 'Your Company', description: 'Company Name', isEncrypted: false },
        { category: 'GENERAL', key: 'support_email', value: 'support@siberzed.local', description: 'Support Email Address', isEncrypted: false }
      ];

      for (const setting of defaultSettings) {
        await this.prisma.systemSettings.upsert({
          where: {
            category_key: { 
              category: setting.category, 
              key: setting.key 
            }
          },
          update: {}, // Don't update existing settings
          create: {
            category: setting.category,
            key: setting.key,
            value: setting.isEncrypted && setting.value ? this.encrypt(setting.value) : setting.value,
            description: setting.description,
            isEncrypted: setting.isEncrypted
          }
        });
      }

    } catch (error) {
      console.error('❌ Error initializing default settings:', error);
    }
  }

  // Get settings for admin panel display
  async getSettingsForAdmin(): Promise<Record<string, any[]>> {
    try {
      const settings = await this.prisma.systemSettings.findMany({
        where: { isActive: true },
        orderBy: [
          { category: 'asc' },
          { key: 'asc' }
        ]
      });

      const result: Record<string, any[]> = {};

      settings.forEach(setting => {
        if (!result[setting.category]) {
          result[setting.category] = [];
        }

        result[setting.category].push({
          id: setting.id,
          key: setting.key,
          value: setting.isEncrypted ? '' : setting.value, // Don't send encrypted values to frontend
          description: setting.description,
          isEncrypted: setting.isEncrypted,
          updatedAt: setting.updatedAt,
          updatedBy: setting.updatedBy
        });
      });

      return result;
    } catch (error) {
      console.error('Error getting settings for admin:', error);
      return {};
    }
  }

  // Bulk update settings
  async bulkUpdateSettings(
    updates: Array<{
      category: string;
      key: string;
      value: string;
      isEncrypted?: boolean;
    }>,
    updatedBy?: string
  ): Promise<{ success: boolean; updated: number; failed: number }> {
    let updated = 0;
    let failed = 0;

    for (const update of updates) {
      const success = await this.setSetting(
        update.category,
        update.key,
        update.value,
        undefined,
        update.isEncrypted || false,
        updatedBy
      );

      if (success) {
        updated++;
      } else {
        failed++;
      }
    }

    return { success: failed === 0, updated, failed };
  }

  // Validate CI/CD API key
  async validateCiCdApiKey(apiKey: string): Promise<boolean> {
    try {
      const cicdSettings = await this.getCiCdSettings();
      return cicdSettings.apiKeys.includes(apiKey);
    } catch (error) {
      console.error('Error validating CI/CD API key:', error);
      return false;
    }
  }

  // Generate new CI/CD API key
  generateApiKey(): string {
    return `siberZed_${crypto.randomBytes(32).toString('hex')}`;
  }

  // Add new CI/CD API key
  async addCiCdApiKey(keyName: string, updatedBy?: string): Promise<{ success: boolean; apiKey?: string }> {
    try {
      const newApiKey = this.generateApiKey();
      const cicdSettings = await this.getCiCdSettings();
      
      cicdSettings.apiKeys.push(newApiKey);
      
      const success = await this.setSetting(
        'CICD',
        'api_keys',
        cicdSettings.apiKeys.join(','),
        'CI/CD API Keys (comma separated)',
        false, // Disable encryption for now
        updatedBy
      );

      if (success) {
        return { success: true, apiKey: newApiKey };
      } else {
        return { success: false };
      }
    } catch (error) {
      console.error('Error adding CI/CD API key:', error);
      return { success: false };
    }
  }

  // Remove CI/CD API key
  async removeCiCdApiKey(apiKey: string, updatedBy?: string): Promise<boolean> {
    try {
      const cicdSettings = await this.getCiCdSettings();
      const updatedKeys = cicdSettings.apiKeys.filter(key => key !== apiKey);
      
      return await this.setSetting(
        'CICD',
        'api_keys',
        updatedKeys.join(','),
        'CI/CD API Keys (comma separated)',
        false, // Disable encryption for now
        updatedBy
      );
    } catch (error) {
      console.error('Error removing CI/CD API key:', error);
      return false;
    }
  }
}

export const settingsService = new SettingsService();
export default settingsService;
