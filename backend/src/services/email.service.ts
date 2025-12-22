import nodemailer from 'nodemailer';
import { PrismaClient, EmailStatus } from '@prisma/client';

const prisma = new PrismaClient();

interface EmailOptions {
  to: string | string[];
  cc?: string | string[];
  bcc?: string | string[];
  subject: string;
  html: string;
  text?: string;
  template?: string;
  scanId?: string;
  groupId?: string;
  sentBy: string;
}

class EmailService {
  private transporter: nodemailer.Transporter | null = null;
  private smtpConfigured = false;
  private smtpFrom: string = 'İBB Güvenlik Tarama Servisi <gtaramabilgi@ibb.gov.tr>';

  async initializeTransporter() {
    try {
      // Önce ENV'den SMTP ayarlarını kontrol et (öncelikli)
      let config: any = {
        smtp_host: process.env.SMTP_HOST,
        smtp_port: process.env.SMTP_PORT,
        smtp_user: process.env.SMTP_USER,
        smtp_password: process.env.SMTP_PASS,
        smtp_from: process.env.SMTP_FROM,
        smtp_secure: process.env.SMTP_SECURE
      };

      // ENV'de ayar yoksa veritabanından al
      if (!config.smtp_host || !config.smtp_port) {
        console.log('ℹ️ ENV SMTP ayarları bulunamadı, veritabanından kontrol ediliyor...');
        const smtpSettings = await prisma.systemSettings.findMany({
          where: {
            category: 'SMTP',
            isActive: true
          }
        });

        smtpSettings.forEach(setting => {
          config[setting.key] = setting.value;
        });
      }

      if (!config.smtp_host || !config.smtp_port) {
        console.warn('⚠️ SMTP not configured - smtp_host or smtp_port missing');
        this.smtpConfigured = false;
        return;
      }

      // Şifreyi decrypt et (eğer encrypted ise)
      let password = config.smtp_password || '';
      if (password.includes(':')) {
        try {
          const crypto = require('crypto');
          const encryptionKey = process.env.ENCRYPTION_KEY || 'dev-encryption-key-32-characters';
          const [ivHex, data] = password.split(':');
          const key = crypto.createHash('sha256').update(encryptionKey).digest();
          const iv = Buffer.from(ivHex, 'hex');
          const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
          let decrypted = decipher.update(data, 'hex', 'utf8');
          decrypted += decipher.final('utf8');
          password = decrypted;
        } catch (e) {
          console.warn('⚠️ Failed to decrypt SMTP password, using as-is');
        }
      }

      // smtp_from değerini kaydet
      this.smtpFrom = config.smtp_from || `İBB Güvenlik Tarama Servisi <${config.smtp_user}@ibb.gov.tr>`;

      this.transporter = nodemailer.createTransport({
        host: config.smtp_host,
        port: parseInt(config.smtp_port),
        secure: config.smtp_secure === 'true',
        auth: config.smtp_user && password ? {
          user: config.smtp_user,
          pass: password
        } : undefined,
        tls: {
          rejectUnauthorized: false // İç ağ için self-signed sertifika kabul et
        }
      });

      // Test connection
      await this.transporter.verify();
      this.smtpConfigured = true;
      console.log('✅ Email service initialized - SMTP: ' + config.smtp_host + ':' + config.smtp_port);
    } catch (error) {
      console.error('❌ Failed to initialize email service:', error);
      this.smtpConfigured = false;
    }
  }

  async sendEmail(options: EmailOptions): Promise<boolean> {
    if (!this.smtpConfigured || !this.transporter) {
      console.warn('⚠️ Email service not configured, skipping email');
      // Log to database anyway
      await this.logEmail(options, 'FAILED', 'SMTP not configured');
      return false;
    }

    try {
      const toArray = Array.isArray(options.to) ? options.to : [options.to];
      const ccArray = options.cc ? (Array.isArray(options.cc) ? options.cc : [options.cc]) : [];
      const bccArray = options.bcc ? (Array.isArray(options.bcc) ? options.bcc : [options.bcc]) : [];

      // From adresini veritabanından al
      const fromAddress = await this.getSmtpFrom();

      await this.transporter.sendMail({
        from: fromAddress,
        to: toArray.join(', '),
        cc: ccArray.length > 0 ? ccArray.join(', ') : undefined,
        bcc: bccArray.length > 0 ? bccArray.join(', ') : undefined,
        subject: options.subject,
        html: options.html,
        text: options.text
      });

      await this.logEmail(options, 'SENT');
      console.log(`✅ Email sent to ${toArray.join(', ')}`);
      return true;
    } catch (error: any) {
      console.error('❌ Failed to send email:', error);
      await this.logEmail(options, 'FAILED', error.message);
      return false;
    }
  }

  private async logEmail(options: EmailOptions, status: EmailStatus, error?: string) {
    try {
      const toArray = Array.isArray(options.to) ? options.to : [options.to];
      const ccArray = options.cc ? (Array.isArray(options.cc) ? options.cc : [options.cc]) : [];
      const bccArray = options.bcc ? (Array.isArray(options.bcc) ? options.bcc : [options.bcc]) : [];

      await prisma.emailLog.create({
        data: {
          to: toArray,
          cc: ccArray,
          bcc: bccArray,
          subject: options.subject,
          body: options.html,
          template: options.template,
          sentBy: options.sentBy,
          status,
          error,
          scanId: options.scanId,
          groupId: options.groupId
        }
      });
    } catch (logError) {
      console.error('Failed to log email:', logError);
    }
  }

  // Tarama tamamlandığında email gönder
  async sendScanCompletedEmail(scanId: string) {
    try {
      console.log(`📧 sendScanCompletedEmail called for scanId: ${scanId}`);

      const scan = await prisma.scan.findUnique({
        where: { id: scanId },
        include: {
          creator: {
            include: {
              emailPreference: true
            }
          },
          vulnerabilities: true
        }
      });

      console.log(`📧 Scan found: ${!!scan}, Creator found: ${!!scan?.creator}, CreatedBy: ${scan?.createdBy || 'NULL'}`);

      if (!scan) {
        console.warn(`⚠️ Scan ${scanId} not found - skipping completed email`);
        return;
      }

      if (!scan.creator) {
        console.warn(`⚠️ Scan ${scanId} has no creator (createdBy: ${scan.createdBy}) - skipping completed email`);
        return;
      }

      const user = scan.creator;
      const emailPref = user.emailPreference;

      // Email tercihlerini kontrol et
      if (!emailPref?.emailEnabled || !emailPref?.scanCompleted) {
        console.log(`ℹ️ User ${user.email} has disabled scan completed emails`);
        return;
      }

      // Zafiyet sayılarını hesapla
      const vulnCounts = {
        critical: scan.vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
        high: scan.vulnerabilities.filter(v => v.severity === 'HIGH').length,
        medium: scan.vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
        low: scan.vulnerabilities.filter(v => v.severity === 'LOW').length,
        info: scan.vulnerabilities.filter(v => v.severity === 'INFO').length
      };

      const totalVulns = scan.vulnerabilities.length;

      // Email HTML içeriği
      const html = `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #1976d2; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
            .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 5px 5px; }
            .vuln-box { background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #ddd; }
            .critical { border-left-color: #d32f2f; }
            .high { border-left-color: #f57c00; }
            .medium { border-left-color: #fbc02d; }
            .low { border-left-color: #388e3c; }
            .info { border-left-color: #1976d2; }
            .button { display: inline-block; padding: 10px 20px; background: #1976d2; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🔒 Tarama Tamamlandı</h1>
            </div>
            <div class="content">
              <h2>Merhaba ${user.firstName} ${user.lastName},</h2>
              <p><strong>${scan.name}</strong> taramanız tamamlandı.</p>
              
              <div class="vuln-box">
                <h3>Tarama Detayları</h3>
                <p><strong>Hedef URL:</strong> ${scan.targetUrl}</p>
                <p><strong>Tarama Tipi:</strong> ${scan.scanType}</p>
                <p><strong>Başlangıç:</strong> ${scan.startedAt.toLocaleString('tr-TR')}</p>
                <p><strong>Bitiş:</strong> ${scan.completedAt?.toLocaleString('tr-TR')}</p>
              </div>

              ${totalVulns > 0 ? `
              <div class="vuln-box">
                <h3>Bulunan Zafiyetler (${totalVulns})</h3>
                ${vulnCounts.critical > 0 ? `<p class="critical">🔴 <strong>Critical:</strong> ${vulnCounts.critical}</p>` : ''}
                ${vulnCounts.high > 0 ? `<p class="high">🟠 <strong>High:</strong> ${vulnCounts.high}</p>` : ''}
                ${vulnCounts.medium > 0 ? `<p class="medium">🟡 <strong>Medium:</strong> ${vulnCounts.medium}</p>` : ''}
                ${vulnCounts.low > 0 ? `<p class="low">🟢 <strong>Low:</strong> ${vulnCounts.low}</p>` : ''}
                ${vulnCounts.info > 0 ? `<p class="info">🔵 <strong>Info:</strong> ${vulnCounts.info}</p>` : ''}
              </div>
              ` : `
              <div class="vuln-box">
                <p>✅ <strong>Harika!</strong> Hiçbir zafiyet bulunamadı.</p>
              </div>
              `}

              <p style="text-align: center;">
                <a href="${process.env.FRONTEND_URL || 'http://localhost:5003'}/scan-history?scanId=${scanId}" class="button">
                  Raporu Görüntüle
                </a>
              </p>

              <p style="color: #666; font-size: 12px; margin-top: 30px;">
                Bu email otomatik olarak gönderilmiştir. Email tercihlerinizi profil ayarlarınızdan değiştirebilirsiniz.
              </p>
            </div>
          </div>
        </body>
        </html>
      `;

      await this.sendEmail({
        to: user.email,
        subject: `Tarama Tamamlandı: ${scan.name}`,
        html,
        template: 'scan_completed',
        scanId: scan.id,
        sentBy: 'SYSTEM'
      });

    } catch (error) {
      console.error('Error sending scan completed email:', error);
    }
  }

  // Kritik zafiyet bulunduğunda email gönder
  async sendCriticalVulnEmail(scanId: string, vulnerability: any) {
    try {
      const scan = await prisma.scan.findUnique({
        where: { id: scanId },
        include: {
          creator: {
            include: {
              emailPreference: true
            }
          }
        }
      });

      if (!scan || !scan.creator) {
        return;
      }

      const user = scan.creator;
      const emailPref = user.emailPreference;

      // Email tercihlerini kontrol et
      if (!emailPref?.emailEnabled || !emailPref?.vulnCritical) {
        return;
      }

      const html = `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #d32f2f; color: white; padding: 20px; text-align: center; }
            .content { background: #f9f9f9; padding: 20px; }
            .alert { background: #ffebee; border-left: 4px solid #d32f2f; padding: 15px; margin: 15px 0; }
            .button { display: inline-block; padding: 10px 20px; background: #d32f2f; color: white; text-decoration: none; border-radius: 5px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🚨 KRİTİK ZAFİYET BULUNDU</h1>
            </div>
            <div class="content">
              <h2>Merhaba ${user.firstName} ${user.lastName},</h2>
              <p><strong>${scan.name}</strong> taramasında kritik bir zafiyet bulundu!</p>
              
              <div class="alert">
                <h3>⚠️ ${vulnerability.name}</h3>
                <p><strong>Açıklama:</strong> ${vulnerability.description || 'Açıklama yok'}</p>
                <p><strong>URL:</strong> ${vulnerability.url || scan.targetUrl}</p>
                <p><strong>Güven:</strong> ${vulnerability.confidence || 'Belirsiz'}</p>
              </div>

              <p><strong>Öneri Çözüm:</strong></p>
              <p>${vulnerability.solution || 'Çözüm bilgisi mevcut değil'}</p>

              <p style="text-align: center;">
                <a href="${process.env.FRONTEND_URL || 'http://localhost:5003'}/scan-history?scanId=${scanId}" class="button">
                  Detayları Görüntüle
                </a>
              </p>
            </div>
          </div>
        </body>
        </html>
      `;

      await this.sendEmail({
        to: user.email,
        subject: `🚨 KRİTİK ZAFİYET: ${vulnerability.name}`,
        html,
        template: 'critical_vuln',
        scanId: scan.id,
        sentBy: 'SYSTEM'
      });

    } catch (error) {
      console.error('Error sending critical vuln email:', error);
    }
  }

  // Tarama başladığında email gönder
  async sendScanStartedEmail(scanId: string) {
    try {
      console.log(`📧 sendScanStartedEmail called for scanId: ${scanId}`);

      const scan = await prisma.scan.findUnique({
        where: { id: scanId },
        include: {
          creator: {
            include: {
              emailPreference: true
            }
          }
        }
      });

      console.log(`📧 Scan found: ${!!scan}, Creator found: ${!!scan?.creator}, CreatedBy: ${scan?.createdBy || 'NULL'}`);

      if (!scan) {
        console.warn(`⚠️ Scan ${scanId} not found - skipping email`);
        return;
      }

      if (!scan.creator) {
        console.warn(`⚠️ Scan ${scanId} has no creator (createdBy: ${scan.createdBy}) - skipping email`);
        return;
      }

      const user = scan.creator;
      const emailPref = user.emailPreference;

      // Email tercihlerini kontrol et
      if (!emailPref?.emailEnabled || !emailPref?.scanStarted) {
        console.log(`ℹ️ User ${user.email} has disabled scan started emails`);
        return;
      }

      const html = `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #2196f3; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
            .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 5px 5px; }
            .info-box { background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #2196f3; }
            .button { display: inline-block; padding: 10px 20px; background: #2196f3; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🚀 Güvenlik Taraması Başladı</h1>
            </div>
            <div class="content">
              <h2>Merhaba ${user.firstName} ${user.lastName},</h2>
              <p>Güvenlik taramanız başarıyla başlatıldı.</p>
              
              <div class="info-box">
                <h3>Tarama Detayları</h3>
                <p><strong>Tarama Adı:</strong> ${scan.name}</p>
                <p><strong>Hedef URL:</strong> ${scan.targetUrl}</p>
                <p><strong>Tarama Tipi:</strong> ${scan.scanType}</p>
                <p><strong>Başlangıç Zamanı:</strong> ${scan.startedAt.toLocaleString('tr-TR')}</p>
              </div>

              <p>Tarama tamamlandığında size tekrar bildirim gönderilecektir.</p>

              <p style="text-align: center;">
                <a href="${process.env.FRONTEND_URL || 'http://localhost:5002'}/scan-history?scanId=${scanId}" class="button">
                  Taramayı İzle
                </a>
              </p>

              <p style="color: #666; font-size: 12px; margin-top: 30px;">
                Bu email otomatik olarak gönderilmiştir. Email tercihlerinizi profil ayarlarınızdan değiştirebilirsiniz.
              </p>
            </div>
          </div>
        </body>
        </html>
      `;

      await this.sendEmail({
        to: user.email,
        subject: `🚀 Tarama Başladı: ${scan.name}`,
        html,
        template: 'scan_started',
        scanId: scan.id,
        sentBy: 'SYSTEM'
      });

    } catch (error) {
      console.error('Error sending scan started email:', error);
    }
  }

  // Erişim talebi oluşturulduğunda adminlere email gönder
  async sendAccessRequestEmail(accessRequest: {
    firstName: string;
    lastName: string;
    email: string;
    department: string;
    reason: string;
    requestedRole: string;
  }) {
    try {
      // Tüm admin kullanıcılarını bul
      const adminUsers = await prisma.user.findMany({
        where: {
          role: 'admin',
          isActive: true
        },
        include: {
          emailPreference: true
        }
      });

      if (adminUsers.length === 0) {
        console.warn('⚠️ No admin users found to notify about access request');
        return;
      }

      const html = `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #ff9800; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
            .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 5px 5px; }
            .request-box { background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #ff9800; }
            .button { display: inline-block; padding: 10px 20px; background: #ff9800; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🔔 Yeni Erişim Talebi</h1>
            </div>
            <div class="content">
              <p>Sisteme yeni bir erişim talebi oluşturuldu. Lütfen inceleyiniz.</p>
              
              <div class="request-box">
                <h3>Talep Bilgileri</h3>
                <p><strong>Ad Soyad:</strong> ${accessRequest.firstName} ${accessRequest.lastName}</p>
                <p><strong>Email:</strong> ${accessRequest.email}</p>
                <p><strong>Departman:</strong> ${accessRequest.department}</p>
                <p><strong>Talep Edilen Rol:</strong> ${accessRequest.requestedRole}</p>
                <p><strong>Talep Nedeni:</strong> ${accessRequest.reason}</p>
              </div>

              <p style="text-align: center;">
                <a href="${process.env.FRONTEND_URL || 'http://localhost:5002'}/admin-panel" class="button">
                  Admin Paneli'ne Git
                </a>
              </p>

              <p style="color: #666; font-size: 12px; margin-top: 30px;">
                Bu email otomatik olarak gönderilmiştir.
              </p>
            </div>
          </div>
        </body>
        </html>
      `;

      // Her admin'e email gönder (email tercihleri kontrol edilerek)
      for (const admin of adminUsers) {
        if (admin.emailPreference?.emailEnabled !== false && admin.emailPreference?.systemAlerts !== false) {
          await this.sendEmail({
            to: admin.email,
            subject: `🔔 Yeni Erişim Talebi: ${accessRequest.firstName} ${accessRequest.lastName}`,
            html,
            template: 'access_request',
            sentBy: 'SYSTEM'
          });
        }
      }

    } catch (error) {
      console.error('Error sending access request email:', error);
    }
  }

  // SMTP From adresini döndür (cached value kullan)
  async getSmtpFrom(): Promise<string> {
    return this.smtpFrom;
  }

  // Erişim talebi onaylandığında kullanıcıya email gönder
  async sendAccessApprovedEmail(user: {
    email: string;
    firstName: string;
    lastName: string;
    username: string;
    department?: string;
  }) {
    try {
      const html = `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
            .container { max-width: 600px; margin: 20px auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #2e7d32 0%, #4caf50 100%); color: white; padding: 30px; text-align: center; }
            .header h1 { margin: 0; font-size: 24px; }
            .header .icon { font-size: 48px; margin-bottom: 10px; }
            .content { padding: 30px; }
            .success-badge { background: #e8f5e9; border: 2px solid #4caf50; border-radius: 8px; padding: 15px; margin: 20px 0; text-align: center; }
            .success-badge .check { color: #2e7d32; font-size: 32px; }
            .info-box { background: #f5f5f5; border-radius: 8px; padding: 20px; margin: 20px 0; }
            .info-box h3 { margin-top: 0; color: #1976d2; border-bottom: 2px solid #1976d2; padding-bottom: 10px; }
            .info-row { display: flex; margin: 10px 0; }
            .info-label { font-weight: bold; min-width: 140px; color: #555; }
            .info-value { color: #333; }
            .button { display: inline-block; padding: 14px 28px; background: linear-gradient(135deg, #1976d2 0%, #2196f3 100%); color: white !important; text-decoration: none; border-radius: 8px; font-weight: bold; margin: 20px 0; }
            .button:hover { background: linear-gradient(135deg, #1565c0 0%, #1976d2 100%); }
            .footer { background: #f5f5f5; padding: 20px; text-align: center; color: #666; font-size: 12px; border-top: 1px solid #ddd; }
            .footer img { max-height: 40px; margin-bottom: 10px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <div class="icon">✅</div>
              <h1>Erişim Talebiniz Onaylandı!</h1>
            </div>
            <div class="content">
              <p>Merhaba <strong>${user.firstName} ${user.lastName}</strong>,</p>
              
              <div class="success-badge">
                <div class="check">✓</div>
                <p style="margin: 0; font-size: 18px; color: #2e7d32;"><strong>Sisteme erişim yetkiniz tanımlandı</strong></p>
              </div>

              <p>İBB Güvenlik Test Platformu'na erişim talebiniz incelenerek onaylanmıştır. Artık kurumsal kimlik bilgileriniz (LDAP) ile sisteme giriş yapabilirsiniz.</p>

              <div class="info-box">
                <h3>🔐 Giriş Bilgileriniz</h3>
                <div class="info-row">
                  <span class="info-label">Kullanıcı Adı:</span>
                  <span class="info-value"><strong>${user.username}</strong></span>
                </div>
                <div class="info-row">
                  <span class="info-label">Şifre:</span>
                  <span class="info-value">Kurumsal LDAP şifreniz</span>
                </div>
                <div class="info-row">
                  <span class="info-label">Departman:</span>
                  <span class="info-value">${user.department || 'Belirtilmedi'}</span>
                </div>
              </div>

              <p style="text-align: center;">
                <a href="${process.env.FRONTEND_URL || 'http://localhost:5002'}/login" class="button">
                  🚀 Platforma Giriş Yap
                </a>
              </p>

              <p style="color: #666; font-size: 14px;">
                <strong>💡 İpucu:</strong> İlk girişinizde profil ayarlarınızdan email bildirim tercihlerinizi özelleştirebilirsiniz.
              </p>
            </div>
            <div class="footer">
              <p><strong>İBB Güvenlik Test Platformu</strong></p>
              <p>Bu email otomatik olarak gönderilmiştir. Lütfen yanıtlamayınız.</p>
              <p>© ${new Date().getFullYear()} İstanbul Büyükşehir Belediyesi</p>
            </div>
          </div>
        </body>
        </html>
      `;

      await this.sendEmail({
        to: user.email,
        subject: '✅ İBB Güvenlik Test Platformu - Erişim Talebiniz Onaylandı',
        html,
        template: 'access_approved',
        sentBy: 'SYSTEM'
      });

      console.log(`✅ Access approved email sent to ${user.email}`);

    } catch (error) {
      console.error('Error sending access approved email:', error);
    }
  }

  // Erişim talebi reddedildiğinde kullanıcıya email gönder
  async sendAccessRejectedEmail(user: {
    email: string;
    firstName: string;
    lastName: string;
    reason?: string;
  }) {
    try {
      const html = `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
            .container { max-width: 600px; margin: 20px auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #616161 0%, #9e9e9e 100%); color: white; padding: 30px; text-align: center; }
            .header h1 { margin: 0; font-size: 24px; }
            .header .icon { font-size: 48px; margin-bottom: 10px; }
            .content { padding: 30px; }
            .reject-badge { background: #ffebee; border: 2px solid #ef5350; border-radius: 8px; padding: 15px; margin: 20px 0; text-align: center; }
            .reject-badge .icon { color: #c62828; font-size: 32px; }
            .reason-box { background: #fff3e0; border-left: 4px solid #ff9800; border-radius: 0 8px 8px 0; padding: 15px 20px; margin: 20px 0; }
            .reason-box h4 { margin: 0 0 10px 0; color: #e65100; }
            .contact-box { background: #e3f2fd; border-radius: 8px; padding: 20px; margin: 20px 0; }
            .contact-box h3 { margin-top: 0; color: #1565c0; }
            .footer { background: #f5f5f5; padding: 20px; text-align: center; color: #666; font-size: 12px; border-top: 1px solid #ddd; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <div class="icon">📋</div>
              <h1>Erişim Talebi Sonucu</h1>
            </div>
            <div class="content">
              <p>Merhaba <strong>${user.firstName} ${user.lastName}</strong>,</p>
              
              <div class="reject-badge">
                <div class="icon">ℹ️</div>
                <p style="margin: 0; font-size: 16px; color: #c62828;">Erişim talebiniz değerlendirilmiş olup, şu an için onaylanamamıştır.</p>
              </div>

              ${user.reason ? `
              <div class="reason-box">
                <h4>📝 Değerlendirme Notu</h4>
                <p style="margin: 0;">${user.reason}</p>
              </div>
              ` : ''}

              <p>Erişim talebinizin reddedilmesi size kalıcı bir kısıtlama getirmez. Eksiklikleri giderip tekrar başvuruda bulunabilirsiniz.</p>

              <div class="contact-box">
                <h3>📞 İletişim</h3>
                <p>Herhangi bir sorunuz varsa veya durumunuzla ilgili daha fazla bilgi almak istiyorsanız, lütfen sistem yöneticinizle iletişime geçiniz.</p>
                <p><strong>Email:</strong> gtaramabilgi@ibb.gov.tr</p>
              </div>

              <p style="color: #666; font-size: 14px;">
                Yeni bir erişim talebi oluşturmak için lütfen login sayfasını ziyaret ediniz.
              </p>
            </div>
            <div class="footer">
              <p><strong>İBB Güvenlik Test Platformu</strong></p>
              <p>Bu email otomatik olarak gönderilmiştir. Lütfen yanıtlamayınız.</p>
              <p>© ${new Date().getFullYear()} İstanbul Büyükşehir Belediyesi</p>
            </div>
          </div>
        </body>
        </html>
      `;

      await this.sendEmail({
        to: user.email,
        subject: '📋 İBB Güvenlik Test Platformu - Erişim Talebi Sonucu',
        html,
        template: 'access_rejected',
        sentBy: 'SYSTEM'
      });

      console.log(`📧 Access rejected email sent to ${user.email}`);

    } catch (error) {
      console.error('Error sending access rejected email:', error);
    }
  }
}

export const emailService = new EmailService();
// Initialize on startup
emailService.initializeTransporter().catch(console.error);
