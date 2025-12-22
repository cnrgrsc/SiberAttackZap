import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function checkPermissionNames() {
  try {
    console.log('🔍 Checking permission names...\n');
    
    // USER_READ izni var mı?
    const userRead = await prisma.permission.findUnique({
      where: { name: 'USER_READ' }
    });
    
    console.log('USER_READ:', userRead ? '✅ VAR' : '❌ YOK');
    
    // ROLE_READ izni var mı?
    const roleRead = await prisma.permission.findUnique({
      where: { name: 'ROLE_READ' }
    });
    
    console.log('ROLE_READ:', roleRead ? '✅ VAR' : '❌ YOK');
    
    // GROUP_READ izni var mı?
    const groupRead = await prisma.permission.findUnique({
      where: { name: 'GROUP_READ' }
    });
    
    console.log('GROUP_READ:', groupRead ? '✅ VAR' : '❌ YOK');
    
    // SYSTEM_SETTINGS_VIEW izni var mı?
    const systemSettings = await prisma.permission.findUnique({
      where: { name: 'SYSTEM_SETTINGS_VIEW' }
    });
    
    console.log('SYSTEM_SETTINGS_VIEW:', systemSettings ? '✅ VAR' : '❌ YOK');
    
    // Tüm izinleri listele
    console.log('\n📋 Veritabanındaki TÜM İzinler:');
    const allPermissions = await prisma.permission.findMany({
      orderBy: { category: 'asc' },
      select: {
        name: true,
        displayName: true,
        category: true
      }
    });
    
    const grouped = allPermissions.reduce((acc: any, perm) => {
      if (!acc[perm.category]) acc[perm.category] = [];
      acc[perm.category].push(perm.name);
      return acc;
    }, {});
    
    Object.entries(grouped).forEach(([category, perms]: [string, any]) => {
      console.log(`\n${category}:`);
      perms.forEach((p: string) => console.log(`  • ${p}`));
    });
    
    // Kullanıcının izinlerini kontrol et
    console.log('\n👤 caner.guresci kullanıcısının izinleri:');
    const user = await prisma.user.findUnique({
      where: { email: 'caner.guresci@ibb.gov.tr' }
    });
    
    if (!user) {
      console.log('❌ Kullanıcı bulunamadı!');
      return;
    }
    
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
    
    const userPermissions = new Set<string>();
    userRoles.forEach(ur => {
      ur.role.permissions.forEach(rp => {
        userPermissions.add(rp.permission.name);
      });
    });
    
    console.log(`Toplam: ${userPermissions.size} izin`);
    
    // Aranılan 4 izin var mı?
    const requiredPermissions = ['USER_READ', 'ROLE_READ', 'GROUP_READ', 'SYSTEM_SETTINGS_VIEW'];
    console.log('\n🔍 Admin Panel için gerekli izinler:');
    requiredPermissions.forEach(perm => {
      const has = userPermissions.has(perm);
      console.log(`  ${has ? '✅' : '❌'} ${perm}`);
    });
    
  } catch (error) {
    console.error('❌ Hata:', error);
  } finally {
    await prisma.$disconnect();
  }
}

checkPermissionNames();
