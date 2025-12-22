import { PrismaClient } from '@prisma/client';
import crypto from 'crypto';

const prisma = new PrismaClient();

// Encryption key (should match the one in settingsService.ts)
const encryptionKey = process.env.ENCRYPTION_KEY || 'dev-encryption-key-32-characters';

// Encrypt function (same as in settingsService.ts)
function encrypt(text: string): string {
    const key = crypto.createHash('sha256').update(encryptionKey).digest();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

async function main() {
    console.log('📧 SMTP Ayarları Veritabanına Kaydediliyor...\n');

    // SMTP Ayarları - İBB Mail Server
    const smtpSettings = [
        {
            category: 'SMTP',
            key: 'smtp_host',
            value: 'mail.ibb.gov.tr',
            description: 'SMTP Sunucu Adresi',
            isEncrypted: false
        },
        {
            category: 'SMTP',
            key: 'smtp_port',
            value: '25',
            description: 'SMTP Port',
            isEncrypted: false
        },
        {
            category: 'SMTP',
            key: 'smtp_secure',
            value: 'false',
            description: 'SSL/TLS kullanılsın mı (port 25 için false)',
            isEncrypted: false
        },
        {
            category: 'SMTP',
            key: 'smtp_user',
            value: 'gtaramabilgi',
            description: 'SMTP Kullanıcı Adı',
            isEncrypted: false
        },
        {
            category: 'SMTP',
            key: 'smtp_password',
            value: 'CanerGrsc2*25*',
            description: 'SMTP Şifre',
            isEncrypted: true
        },
        {
            category: 'SMTP',
            key: 'smtp_from',
            value: 'İBB Güvenlik Tarama Servisi <gtaramabilgi@ibb.gov.tr>',
            description: 'Gönderen Email Adresi',
            isEncrypted: false
        },
        {
            category: 'SMTP',
            key: 'smtp_email',
            value: 'gtaramabilgi@ibb.gov.tr',
            description: 'Email Adresi',
            isEncrypted: false
        }
    ];

    for (const setting of smtpSettings) {
        const finalValue = setting.isEncrypted ? encrypt(setting.value) : setting.value;

        await prisma.systemSettings.upsert({
            where: {
                category_key: {
                    category: setting.category,
                    key: setting.key
                }
            },
            update: {
                value: finalValue,
                description: setting.description,
                isEncrypted: setting.isEncrypted,
                updatedBy: 'system',
                updatedAt: new Date()
            },
            create: {
                category: setting.category,
                key: setting.key,
                value: finalValue,
                description: setting.description,
                isEncrypted: setting.isEncrypted,
                isActive: true
            }
        });

        console.log(`  ✅ ${setting.key}: ${setting.isEncrypted ? '***encrypted***' : setting.value}`);
    }

    // Email bildirimleri için genel ayarlar
    const emailNotificationSettings = [
        {
            category: 'EMAIL_NOTIFICATIONS',
            key: 'enabled',
            value: 'true',
            description: 'Email bildirimleri aktif mi',
            isEncrypted: false
        },
        {
            category: 'EMAIL_NOTIFICATIONS',
            key: 'admin_email',
            value: 'gtaramabilgi@ibb.gov.tr',
            description: 'Admin bildirimleri için email',
            isEncrypted: false
        },
        {
            category: 'EMAIL_NOTIFICATIONS',
            key: 'notify_on_scan_start',
            value: 'true',
            description: 'Tarama başladığında bildirim gönder',
            isEncrypted: false
        },
        {
            category: 'EMAIL_NOTIFICATIONS',
            key: 'notify_on_scan_complete',
            value: 'true',
            description: 'Tarama tamamlandığında bildirim gönder',
            isEncrypted: false
        },
        {
            category: 'EMAIL_NOTIFICATIONS',
            key: 'notify_on_access_request',
            value: 'true',
            description: 'Erişim talebi oluşturulduğunda bildirim gönder',
            isEncrypted: false
        },
        {
            category: 'EMAIL_NOTIFICATIONS',
            key: 'notify_on_critical_vuln',
            value: 'true',
            description: 'Kritik zafiyet bulunduğunda bildirim gönder',
            isEncrypted: false
        }
    ];

    console.log('\n📧 Email Bildirim Ayarları Kaydediliyor...\n');

    for (const setting of emailNotificationSettings) {
        await prisma.systemSettings.upsert({
            where: {
                category_key: {
                    category: setting.category,
                    key: setting.key
                }
            },
            update: {
                value: setting.value,
                description: setting.description,
                isEncrypted: setting.isEncrypted,
                updatedBy: 'system',
                updatedAt: new Date()
            },
            create: {
                category: setting.category,
                key: setting.key,
                value: setting.value,
                description: setting.description,
                isEncrypted: setting.isEncrypted,
                isActive: true
            }
        });

        console.log(`  ✅ ${setting.key}: ${setting.value}`);
    }

    console.log('\n🎉 SMTP ve Email Bildirim Ayarları Başarıyla Kaydedildi!\n');

    console.log('📊 Özet:');
    console.log('  • SMTP Sunucu: mail.ibb.gov.tr:25');
    console.log('  • Email: gtaramabilgi@ibb.gov.tr');
    console.log('  • Bildirimler: Aktif');
    console.log('\n⚠️ Backend\'i yeniden başlatarak email servisini aktifleştirin.\n');
}

main()
    .then(async () => {
        await prisma.$disconnect();
    })
    .catch(async (e) => {
        console.error('❌ Hata:', e);
        await prisma.$disconnect();
        process.exit(1);
    });
