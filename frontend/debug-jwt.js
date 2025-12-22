// JWT Token Decoder
// Browser console'da çalıştırın:

const token = localStorage.getItem('siberZed_token');
if (token) {
  // JWT'yi decode et (base64)
  const parts = token.split('.');
  if (parts.length === 3) {
    const payload = JSON.parse(atob(parts[1]));
    console.log('🔑 JWT Payload:', payload);
    console.log('📋 Permissions:', payload.permissions);
    console.log('📊 Permission Count:', payload.permissions ? payload.permissions.length : 0);
    
    // Gerekli izinler var mı kontrol et
    const required = ['USER_READ', 'ROLE_READ', 'GROUP_READ', 'SYSTEM_SETTINGS_VIEW'];
    console.log('\n🔍 Admin Panel İzinleri:');
    required.forEach(perm => {
      const has = payload.permissions && payload.permissions.includes(perm);
      console.log(`  ${has ? '✅' : '❌'} ${perm}`);
    });
  }
} else {
  console.log('❌ Token bulunamadı!');
}

// LocalStorage'daki user objesi
const user = localStorage.getItem('siberZed_user');
if (user) {
  const userData = JSON.parse(user);
  console.log('\n👤 LocalStorage User:', userData);
  console.log('📋 User Permissions:', userData.permissions);
}
