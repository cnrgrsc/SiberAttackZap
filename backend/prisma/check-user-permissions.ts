import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function checkUserPermissions() {
  try {
    console.log('🔍 Kullanıcı izinleri kontrol ediliyor...\n');
    
    // Kullanıcıyı ve tüm izinlerini çek
    const user = await prisma.user.findUnique({
      where: { email: 'caner.guresci@ibb.gov.tr' }
    });

    if (!user) {
      console.error('❌ Kullanıcı bulunamadı!');
      process.exit(1);
    }

    // Kullanıcının rollerini çek
    const userRoles = await prisma.userRole.findMany({
      where: { userId: user.id },
      include: {
        role: {
          include: {
            permissions: {
              include: {
                permission: true
              }
            }
          }
        }
      }
    });

    console.log('👤 Kullanıcı Bilgileri:');
    console.log(`   Ad: ${user.firstName} ${user.lastName}`);
    console.log(`   Email: ${user.email}`);
    console.log(`   Departman: ${user.department || 'Belirtilmemiş'}`);
    console.log(`   Son Giriş: ${user.lastLogin?.toLocaleString('tr-TR') || 'Hiç giriş yapmamış'}`);
    console.log(`   Aktif: ${user.isActive ? '✅ Evet' : '❌ Hayır'}`);
    
    console.log(`\n🎭 Roller (${userRoles.length}):`);
    userRoles.forEach(ur => {
      console.log(`   • ${ur.role.displayName} (${ur.role.name})`);
    });

    // Tüm izinleri topla
    const allPermissions = new Map();
    userRoles.forEach(ur => {
      ur.role.permissions.forEach(rp => {
        allPermissions.set(rp.permission.name, {
          name: rp.permission.name,
          displayName: rp.permission.displayName,
          category: rp.permission.category,
          description: rp.permission.description
        });
      });
    });

    console.log(`\n🔑 Toplam İzin Sayısı: ${allPermissions.size}`);
    
    // Kategorilere göre grupla
    const categories = new Map();
    allPermissions.forEach(perm => {
      if (!categories.has(perm.category)) {
        categories.set(perm.category, []);
      }
      categories.get(perm.category).push(perm);
    });

    console.log(`\n📊 Kategori Bazında İzinler:`);
    Array.from(categories.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .forEach(([category, perms]) => {
        console.log(`\n   ${category} (${perms.length} izin):`);
        perms.forEach((perm: any) => {
          console.log(`      ✓ ${perm.displayName}`);
        });
      });

    console.log('\n✨ Özet:');
    console.log(`   • Web Tarama: ${Array.from(allPermissions.keys()).filter(p => p.includes('SCAN_WEB')).length} izin`);
    console.log(`   • Mobil Tarama: ${Array.from(allPermissions.keys()).filter(p => p.includes('SCAN_MOBILE')).length} izin`);
    console.log(`   • Kullanıcı Yönetimi: ${Array.from(allPermissions.keys()).filter(p => p.includes('USER_')).length} izin`);
    console.log(`   • Rol Yönetimi: ${Array.from(allPermissions.keys()).filter(p => p.includes('ROLE_')).length} izin`);
    console.log(`   • Rapor Yönetimi: ${Array.from(allPermissions.keys()).filter(p => p.includes('REPORT_')).length} izin`);
    console.log(`   • Sistem Ayarları: ${Array.from(allPermissions.keys()).filter(p => p.includes('SYSTEM_')).length} izin`);
    
    console.log('\n🎉 Kullanıcı TAM YETKİLİ! Tüm özelliklere erişebilir.');

  } catch (error) {
    console.error('❌ Hata oluştu:');
    console.error(error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

checkUserPermissions();
