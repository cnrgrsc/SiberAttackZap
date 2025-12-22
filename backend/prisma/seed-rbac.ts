import { PrismaClient, PermissionCategory } from '@prisma/client';

const prisma = new PrismaClient();

// Tüm izinler
const permissions = [
  // USER_MANAGEMENT
  { name: 'USER_CREATE', category: PermissionCategory.USER_MANAGEMENT, displayName: 'Kullanıcı Oluşturma', description: 'Yeni kullanıcı oluşturabilir' },
  { name: 'USER_READ', category: PermissionCategory.USER_MANAGEMENT, displayName: 'Kullanıcı Görüntüleme', description: 'Kullanıcıları görüntüleyebilir' },
  { name: 'USER_UPDATE', category: PermissionCategory.USER_MANAGEMENT, displayName: 'Kullanıcı Güncelleme', description: 'Kullanıcı bilgilerini güncelleyebilir' },
  { name: 'USER_DELETE', category: PermissionCategory.USER_MANAGEMENT, displayName: 'Kullanıcı Silme', description: 'Kullanıcıları silebilir' },
  { name: 'USER_ACTIVATE', category: PermissionCategory.USER_MANAGEMENT, displayName: 'Kullanıcı Aktifleştirme', description: 'Kullanıcıları aktifleştirebilir' },
  { name: 'USER_DEACTIVATE', category: PermissionCategory.USER_MANAGEMENT, displayName: 'Kullanıcı Deaktifleştirme', description: 'Kullanıcıları deaktifleştirebilir' },
  { name: 'USER_ASSIGN_ROLE', category: PermissionCategory.USER_MANAGEMENT, displayName: 'Rol Atama', description: 'Kullanıcılara rol atayabilir' },

  // ROLE_MANAGEMENT
  { name: 'ROLE_CREATE', category: PermissionCategory.ROLE_MANAGEMENT, displayName: 'Rol Oluşturma', description: 'Yeni rol oluşturabilir' },
  { name: 'ROLE_READ', category: PermissionCategory.ROLE_MANAGEMENT, displayName: 'Rol Görüntüleme', description: 'Rolleri görüntüleyebilir' },
  { name: 'ROLE_UPDATE', category: PermissionCategory.ROLE_MANAGEMENT, displayName: 'Rol Güncelleme', description: 'Rol bilgilerini güncelleyebilir' },
  { name: 'ROLE_DELETE', category: PermissionCategory.ROLE_MANAGEMENT, displayName: 'Rol Silme', description: 'Rolleri silebilir' },
  { name: 'ROLE_ASSIGN_PERMISSIONS', category: PermissionCategory.ROLE_MANAGEMENT, displayName: 'İzin Atama', description: 'Rollere izin atayabilir' },

  // GROUP_MANAGEMENT
  { name: 'GROUP_CREATE', category: PermissionCategory.GROUP_MANAGEMENT, displayName: 'Grup Oluşturma', description: 'Yeni grup oluşturabilir' },
  { name: 'GROUP_READ', category: PermissionCategory.GROUP_MANAGEMENT, displayName: 'Grup Görüntüleme', description: 'Grupları görüntüleyebilir' },
  { name: 'GROUP_UPDATE', category: PermissionCategory.GROUP_MANAGEMENT, displayName: 'Grup Güncelleme', description: 'Grup bilgilerini güncelleyebilir' },
  { name: 'GROUP_DELETE', category: PermissionCategory.GROUP_MANAGEMENT, displayName: 'Grup Silme', description: 'Grupları silebilir' },
  { name: 'GROUP_ADD_MEMBERS', category: PermissionCategory.GROUP_MANAGEMENT, displayName: 'Üye Ekleme', description: 'Gruba üye ekleyebilir' },
  { name: 'GROUP_REMOVE_MEMBERS', category: PermissionCategory.GROUP_MANAGEMENT, displayName: 'Üye Çıkarma', description: 'Gruptan üye çıkarabilir' },

  // SCAN_MANAGEMENT - WEB TARAMA (Otomatik/Manuel)
  { name: 'SCAN_WEB_CREATE', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'Web Tarama Başlatma', description: 'Web uygulaması taraması başlatabilir' },
  { name: 'SCAN_WEB_VIEW', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'Web Tarama Görüntüleme', description: 'Web taramalarını görüntüleyebilir' },
  { name: 'SCAN_WEB_DELETE', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'Web Tarama Silme', description: 'Web taramalarını silebilir' },
  { name: 'SCAN_WEB_CONTROL', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'Web Tarama Kontrolü', description: 'Web taramasını durdur/devam ettir/duraklat' },
  
  // SCAN_MANAGEMENT - MOBİL TARAMA
  { name: 'SCAN_MOBILE_CREATE', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'Mobil Tarama Başlatma', description: 'Mobil uygulama taraması başlatabilir' },
  { name: 'SCAN_MOBILE_VIEW', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'Mobil Tarama Görüntüleme', description: 'Mobil taramalarını görüntüleyebilir' },
  { name: 'SCAN_MOBILE_DELETE', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'Mobil Tarama Silme', description: 'Mobil taramalarını silebilir' },
  
  // SCAN_MANAGEMENT - TARAMA GEÇMİŞİ
  { name: 'SCAN_HISTORY_VIEW_OWN', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'Kendi Geçmişini Görme', description: 'Kendi tarama geçmişini görebilir' },
  { name: 'SCAN_HISTORY_VIEW_ALL', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'Tüm Geçmişi Görme', description: 'Tüm kullanıcıların tarama geçmişini görebilir' },
  
  // SCAN_MANAGEMENT - GENEL
  { name: 'SCAN_UPDATE', category: PermissionCategory.SCAN_MANAGEMENT, displayName: 'Tarama Güncelleme', description: 'Tarama ayarlarını güncelleyebilir' },

  // REPORT_MANAGEMENT
  { name: 'REPORT_VIEW_OWN', category: PermissionCategory.REPORT_MANAGEMENT, displayName: 'Kendi Raporlarını Görme', description: 'Kendi raporlarını görebilir' },
  { name: 'REPORT_VIEW_ALL', category: PermissionCategory.REPORT_MANAGEMENT, displayName: 'Tüm Raporları Görme', description: 'Tüm raporları görebilir' },
  { name: 'REPORT_DOWNLOAD', category: PermissionCategory.REPORT_MANAGEMENT, displayName: 'Rapor İndirme', description: 'Raporları indirebilir' },
  { name: 'REPORT_DELETE', category: PermissionCategory.REPORT_MANAGEMENT, displayName: 'Rapor Silme', description: 'Raporları silebilir' },
  { name: 'REPORT_EXPORT', category: PermissionCategory.REPORT_MANAGEMENT, displayName: 'Rapor Export Etme', description: 'Raporları farklı formatlarda export edebilir' },
  { name: 'REPORT_SHARE', category: PermissionCategory.REPORT_MANAGEMENT, displayName: 'Rapor Paylaşma', description: 'Raporları paylaşabilir' },
  { name: 'REPORT_EMAIL_SEND', category: PermissionCategory.REPORT_MANAGEMENT, displayName: 'Rapor Email Gönderme', description: 'Raporları email ile gönderebilir' },
  { name: 'REPORT_EMAIL_AUTO', category: PermissionCategory.REPORT_MANAGEMENT, displayName: 'Otomatik Email Ayarı', description: 'Otomatik email gönderimini ayarlayabilir' },

  // VULNERABILITY_MANAGEMENT
  { name: 'VULN_VIEW', category: PermissionCategory.VULNERABILITY_MANAGEMENT, displayName: 'Zafiyet Görüntüleme', description: 'Zafiyetleri görüntüleyebilir' },
  { name: 'VULN_UPDATE', category: PermissionCategory.VULNERABILITY_MANAGEMENT, displayName: 'Zafiyet Güncelleme', description: 'Zafiyet bilgilerini güncelleyebilir' },
  { name: 'VULN_DELETE', category: PermissionCategory.VULNERABILITY_MANAGEMENT, displayName: 'Zafiyet Silme', description: 'Zafiyetleri silebilir' },
  { name: 'VULN_ASSIGN', category: PermissionCategory.VULNERABILITY_MANAGEMENT, displayName: 'Zafiyet Atama', description: 'Zafiyetleri kullanıcılara atayabilir' },
  { name: 'VULN_CLOSE', category: PermissionCategory.VULNERABILITY_MANAGEMENT, displayName: 'Zafiyet Kapatma', description: 'Zafiyetleri kapatabilir' },

  // EMAIL_MANAGEMENT
  { name: 'EMAIL_SEND_INDIVIDUAL', category: PermissionCategory.EMAIL_MANAGEMENT, displayName: 'Tekil Email Gönderme', description: 'Tek kişiye email gönderebilir' },
  { name: 'EMAIL_SEND_GROUP', category: PermissionCategory.EMAIL_MANAGEMENT, displayName: 'Grup Email Gönderme', description: 'Gruba email gönderebilir' },
  { name: 'EMAIL_SEND_BROADCAST', category: PermissionCategory.EMAIL_MANAGEMENT, displayName: 'Toplu Email Gönderme', description: 'Tüm kullanıcılara email gönderebilir' },
  { name: 'EMAIL_TEMPLATE_MANAGE', category: PermissionCategory.EMAIL_MANAGEMENT, displayName: 'Email Template Yönetimi', description: 'Email template\'leri yönetebilir' },

  // SYSTEM_MANAGEMENT
  { name: 'SYSTEM_SETTINGS_VIEW', category: PermissionCategory.SYSTEM_MANAGEMENT, displayName: 'Sistem Ayarlarını Görme', description: 'Sistem ayarlarını görebilir' },
  { name: 'SYSTEM_SETTINGS_UPDATE', category: PermissionCategory.SYSTEM_MANAGEMENT, displayName: 'Sistem Ayarlarını Güncelleme', description: 'Sistem ayarlarını güncelleyebilir' },
  { name: 'AUDIT_LOG_VIEW', category: PermissionCategory.SYSTEM_MANAGEMENT, displayName: 'Audit Log Görüntüleme', description: 'Audit logları görebilir' },
  { name: 'AUDIT_LOG_EXPORT', category: PermissionCategory.SYSTEM_MANAGEMENT, displayName: 'Audit Log Export', description: 'Audit logları export edebilir' },

  // API_MANAGEMENT
  { name: 'API_KEY_CREATE', category: PermissionCategory.API_MANAGEMENT, displayName: 'API Key Oluşturma', description: 'API anahtarı oluşturabilir' },
  { name: 'API_KEY_DELETE', category: PermissionCategory.API_MANAGEMENT, displayName: 'API Key Silme', description: 'API anahtarını silebilir' },
  { name: 'API_ACCESS', category: PermissionCategory.API_MANAGEMENT, displayName: 'API Erişimi', description: 'API\'ye erişebilir' },

  // DASHBOARD_MANAGEMENT
  { name: 'DASHBOARD_VIEW_OWN', category: PermissionCategory.DASHBOARD_MANAGEMENT, displayName: 'Kendi Dashboard\'unu Görme', description: 'Kendi dashboard\'unu görebilir' },
  { name: 'DASHBOARD_VIEW_ALL', category: PermissionCategory.DASHBOARD_MANAGEMENT, displayName: 'Tüm Dashboard\'ları Görme', description: 'Tüm dashboard\'ları görebilir' },
  { name: 'DASHBOARD_STATISTICS', category: PermissionCategory.DASHBOARD_MANAGEMENT, displayName: 'İstatistikleri Görme', description: 'Sistem istatistiklerini görebilir' },
];

// Varsayılan roller ve izinleri
const roles = [
  {
    name: 'SUPER_ADMIN',
    displayName: 'Süper Yönetici',
    description: 'Tüm yetkilere sahip süper yönetici',
    isSystem: true,
    permissions: permissions.map(p => p.name), // TÜM İZİNLER
  },
  {
    name: 'ADMIN',
    displayName: 'Yönetici',
    description: 'Sistem yöneticisi - Tüm kullanıcıların taramalarını görebilir',
    isSystem: true,
    permissions: [
      'USER_CREATE', 'USER_READ', 'USER_UPDATE', 'USER_ACTIVATE', 'USER_DEACTIVATE', 'USER_ASSIGN_ROLE',
      'ROLE_READ',
      'GROUP_CREATE', 'GROUP_READ', 'GROUP_UPDATE', 'GROUP_DELETE', 'GROUP_ADD_MEMBERS', 'GROUP_REMOVE_MEMBERS',
      // Web ve Mobil Tarama - Tümü
      'SCAN_WEB_CREATE', 'SCAN_WEB_VIEW', 'SCAN_WEB_DELETE', 'SCAN_WEB_CONTROL',
      'SCAN_MOBILE_CREATE', 'SCAN_MOBILE_VIEW', 'SCAN_MOBILE_DELETE',
      'SCAN_HISTORY_VIEW_ALL', 'SCAN_UPDATE',
      // Raporlar - Tüm yetkiler
      'REPORT_VIEW_ALL', 'REPORT_DOWNLOAD', 'REPORT_DELETE', 'REPORT_EXPORT', 'REPORT_SHARE',
      'REPORT_EMAIL_SEND', 'REPORT_EMAIL_AUTO',
      'VULN_VIEW', 'VULN_UPDATE', 'VULN_ASSIGN', 'VULN_CLOSE',
      'EMAIL_SEND_INDIVIDUAL', 'EMAIL_SEND_GROUP',
      'SYSTEM_SETTINGS_VIEW', 'AUDIT_LOG_VIEW', 'AUDIT_LOG_EXPORT',
      'API_KEY_CREATE', 'API_ACCESS',
      'DASHBOARD_VIEW_ALL', 'DASHBOARD_STATISTICS',
    ],
  },
  {
    name: 'SECURITY_ANALYST',
    displayName: 'Güvenlik Analisti',
    description: 'Web ve Mobil tarama + Tüm raporları görebilir',
    isSystem: true,
    permissions: [
      'USER_READ',
      'GROUP_READ',
      // Web ve Mobil Tarama
      'SCAN_WEB_CREATE', 'SCAN_WEB_VIEW', 'SCAN_WEB_CONTROL',
      'SCAN_MOBILE_CREATE', 'SCAN_MOBILE_VIEW',
      'SCAN_HISTORY_VIEW_ALL', 'SCAN_UPDATE',
      // Raporlar
      'REPORT_VIEW_ALL', 'REPORT_DOWNLOAD', 'REPORT_EXPORT', 'REPORT_EMAIL_SEND',
      'VULN_VIEW', 'VULN_UPDATE', 'VULN_ASSIGN', 'VULN_CLOSE',
      'EMAIL_SEND_INDIVIDUAL',
      'DASHBOARD_VIEW_ALL', 'DASHBOARD_STATISTICS',
    ],
  },
  {
    name: 'WEB_DEVELOPER',
    displayName: 'Web Geliştiricisi',
    description: 'Sadece web taraması yapabilir',
    isSystem: true,
    permissions: [
      // Sadece Web Tarama
      'SCAN_WEB_CREATE', 'SCAN_WEB_VIEW',
      'SCAN_HISTORY_VIEW_OWN',
      // Sadece kendi raporları
      'REPORT_VIEW_OWN', 'REPORT_DOWNLOAD',
      'VULN_VIEW',
      'DASHBOARD_VIEW_OWN',
    ],
  },
  {
    name: 'MOBILE_DEVELOPER',
    displayName: 'Mobil Geliştiricisi',
    description: 'Sadece mobil tarama yapabilir',
    isSystem: true,
    permissions: [
      // Sadece Mobil Tarama
      'SCAN_MOBILE_CREATE', 'SCAN_MOBILE_VIEW',
      'SCAN_HISTORY_VIEW_OWN',
      // Sadece kendi raporları
      'REPORT_VIEW_OWN', 'REPORT_DOWNLOAD',
      'VULN_VIEW',
      'DASHBOARD_VIEW_OWN',
    ],
  },
  {
    name: 'FULL_STACK_DEVELOPER',
    displayName: 'Full Stack Geliştiricisi',
    description: 'Web ve Mobil tarama yapabilir',
    isSystem: true,
    permissions: [
      // Web ve Mobil Tarama
      'SCAN_WEB_CREATE', 'SCAN_WEB_VIEW',
      'SCAN_MOBILE_CREATE', 'SCAN_MOBILE_VIEW',
      'SCAN_HISTORY_VIEW_OWN',
      // Sadece kendi raporları
      'REPORT_VIEW_OWN', 'REPORT_DOWNLOAD', 'REPORT_EXPORT',
      'VULN_VIEW',
      'DASHBOARD_VIEW_OWN',
    ],
  },
  {
    name: 'REPORT_VIEWER',
    displayName: 'Rapor İzleyicisi',
    description: 'Sadece raporları görüntüleyebilir',
    isSystem: true,
    permissions: [
      'SCAN_HISTORY_VIEW_OWN',
      'REPORT_VIEW_OWN', 'REPORT_DOWNLOAD',
      'VULN_VIEW',
      'DASHBOARD_VIEW_OWN',
    ],
  },
];

async function main() {
  console.log('🌱 RBAC Seed başlatılıyor...\n');

  // 1. İzinleri oluştur
  console.log('📝 İzinler oluşturuluyor...');
  const createdPermissions: { [key: string]: string } = {};
  
  for (const perm of permissions) {
    const created = await prisma.permission.upsert({
      where: { name: perm.name },
      update: {},
      create: perm,
    });
    createdPermissions[perm.name] = created.id;
    console.log(`  ✅ ${perm.displayName} (${perm.name})`);
  }
  
  console.log(`\n✅ ${permissions.length} izin oluşturuldu\n`);

  // 2. Rolleri oluştur
  console.log('🛡️ Roller oluşturuluyor...');
  
  // İlk olarak SUPER_ADMIN rolünü oluştur (diğer rolleri oluşturmak için gerekli)
  const superAdminUser = await prisma.user.findFirst({
    where: { role: 'admin' },
  });

  if (!superAdminUser) {
    console.error('❌ HATA: Sistemde hiç admin kullanıcı yok! Önce bir admin kullanıcı oluşturun.');
    return;
  }

  for (const roleData of roles) {
    const role = await prisma.role.upsert({
      where: { name: roleData.name },
      update: {},
      create: {
        name: roleData.name,
        displayName: roleData.displayName,
        description: roleData.description,
        isSystem: roleData.isSystem,
        createdBy: superAdminUser.id,
      },
    });

    console.log(`  🛡️ ${roleData.displayName} (${roleData.name})`);

    // Rollere izinleri ata
    for (const permName of roleData.permissions) {
      const permId = createdPermissions[permName];
      if (permId) {
        await prisma.rolePermission.upsert({
          where: {
            roleId_permissionId: {
              roleId: role.id,
              permissionId: permId,
            },
          },
          update: {},
          create: {
            roleId: role.id,
            permissionId: permId,
            grantedBy: superAdminUser.id,
          },
        });
      }
    }
    
    console.log(`     └─ ${roleData.permissions.length} izin atandı`);
  }

  console.log(`\n✅ ${roles.length} rol oluşturuldu\n`);

  // 3. Mevcut admin kullanıcılarına SUPER_ADMIN rolü ata
  console.log('👤 Mevcut admin kullanıcılarına roller atanıyor...');
  
  const adminUsers = await prisma.user.findMany({
    where: { role: 'admin' },
  });

  const superAdminRole = await prisma.role.findUnique({
    where: { name: 'SUPER_ADMIN' },
  });

  if (superAdminRole) {
    for (const user of adminUsers) {
      await prisma.userRole.upsert({
        where: {
          userId_roleId: {
            userId: user.id,
            roleId: superAdminRole.id,
          },
        },
        update: {},
        create: {
          userId: user.id,
          roleId: superAdminRole.id,
          assignedBy: superAdminUser.id,
        },
      });
      console.log(`  ✅ ${user.email} → SUPER_ADMIN`);
    }
  }

  // 4. Mevcut developer kullanıcılarına DEVELOPER rolü ata
  const developerUsers = await prisma.user.findMany({
    where: { role: 'developer' },
  });

  const developerRole = await prisma.role.findUnique({
    where: { name: 'DEVELOPER' },
  });

  if (developerRole) {
    for (const user of developerUsers) {
      await prisma.userRole.upsert({
        where: {
          userId_roleId: {
            userId: user.id,
            roleId: developerRole.id,
          },
        },
        update: {},
        create: {
          userId: user.id,
          roleId: developerRole.id,
          assignedBy: superAdminUser.id,
        },
      });
      console.log(`  ✅ ${user.email} → DEVELOPER`);
    }
  }

  console.log('\n🎉 RBAC Seed tamamlandı!\n');
  
  console.log('📊 Özet:');
  console.log(`  • ${permissions.length} izin`);
  console.log(`  • ${roles.length} rol`);
  console.log(`  • ${adminUsers.length} SUPER_ADMIN kullanıcı`);
  console.log(`  • ${developerUsers.length} DEVELOPER kullanıcı\n`);
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error('❌ Seed hatası:', e);
    await prisma.$disconnect();
    process.exit(1);
  });
