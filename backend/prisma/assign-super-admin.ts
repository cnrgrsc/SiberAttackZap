import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function assignSuperAdmin() {
  try {
    console.log('🔍 Kullanıcı aranıyor...');
    
    // Kullanıcıyı bul
    const user = await prisma.user.findUnique({
      where: { email: 'caner.guresci@ibb.gov.tr' }
    });

    if (!user) {
      console.error('❌ Kullanıcı bulunamadı!');
      process.exit(1);
    }

    console.log(`✅ Kullanıcı bulundu: ${user.firstName} ${user.lastName}`);
    console.log(`📧 Email: ${user.email}`);
    console.log(`🆔 User ID: ${user.id}`);

    // SUPER_ADMIN rolünü bul
    const superAdminRole = await prisma.role.findUnique({
      where: { name: 'SUPER_ADMIN' }
    });

    if (!superAdminRole) {
      console.error('❌ SUPER_ADMIN rolü bulunamadı!');
      process.exit(1);
    }

    console.log(`✅ SUPER_ADMIN rolü bulundu (ID: ${superAdminRole.id})`);

    // Mevcut rolleri kontrol et
    const existingRoles = await prisma.userRole.findMany({
      where: { userId: user.id },
      include: { role: true }
    });

    console.log(`📋 Mevcut roller: ${existingRoles.map(ur => ur.role.name).join(', ') || 'YOK'}`);

    // Kullanıcıya zaten SUPER_ADMIN rolü var mı?
    const hasSuperAdmin = existingRoles.some(ur => ur.roleId === superAdminRole.id);

    if (hasSuperAdmin) {
      console.log('ℹ️  Kullanıcı zaten SUPER_ADMIN rolüne sahip!');
      process.exit(0);
    }

    // SUPER_ADMIN rolünü ata
    console.log('🔄 SUPER_ADMIN rolü atanıyor...');
    await prisma.userRole.create({
      data: {
        userId: user.id,
        roleId: superAdminRole.id,
        assignedBy: user.id,
        assignedAt: new Date()
      }
    });

    console.log('✅ SUPER_ADMIN rolü başarıyla atandı!');

    // İzin sayısını kontrol et
    const permissionCount = await prisma.rolePermission.count({
      where: { roleId: superAdminRole.id }
    });

    console.log(`� SUPER_ADMIN rolünün toplam izin sayısı: ${permissionCount}`);
    console.log('\n🎉 İşlem tamamlandı!');
    console.log('✨ Kullanıcı artık TÜM izinlere sahip:');
    console.log('  • Tüm web tarama işlemleri');
    console.log('  • Tüm mobil tarama işlemleri');
    console.log('  • Tüm kullanıcı yönetimi');
    console.log('  • Tüm rol ve grup yönetimi');
    console.log('  • Sistem ayarları yönetimi');
    console.log('  • Tüm raporları görüntüleme');
    console.log('  • Email gönderme');
    console.log('  • CI/CD entegrasyonu');
    console.log('  • LDAP yönetimi');

  } catch (error) {
    console.error('❌ Hata oluştu:');
    console.error(error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

assignSuperAdmin();
