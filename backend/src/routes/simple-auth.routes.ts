import { Router, Request, Response } from 'express';
import * as jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';
import { PrismaClient } from '@prisma/client';
import * as http from 'http';
import * as https from 'https';
import { emailService } from '../services/email.service';

const router = Router();
// Initialize Prisma Client for DB operations
const prisma = new PrismaClient();

// Auth middleware
const requireAuth = (req: any, res: Response, next: any) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ success: false, message: 'Token bulunamadı' });
    }
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Geçersiz token' });
  }
};

const requireAdmin = (req: any, res: Response, next: any) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Yalnızca admin erişimi' });
  }
  next();
};

// In-memory storage for access requests
interface AccessRequestModel {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  department: string;
  reason: string;
  requestedRole: string;
  status: 'pending' | 'approved' | 'rejected';
  requestDate: string;
  processedAt?: string;
  processedBy?: string;
  rejectionReason?: string;
}

const accessRequestsStorage: AccessRequestModel[] = [
  // Gerçek erişim talepleri burada saklanacak
];

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// LDAP Login endpoint - All users use LDAP
router.post('/login', async (req: Request, res: Response): Promise<void> => {
  try {
    const { username, password } = req.body;

    // Step 1: LDAP Authentication FIRST (önce LDAP'a sor)
    console.log('🔐 Calling LDAP service for user:', username);
    const ldapAuth = await callLDAPService(username, password);
    console.log('📡 LDAP auth result:', ldapAuth);

    if (!ldapAuth.success) {
      console.log('❌ LDAP auth failed:', ldapAuth.message);
      res.status(401).json({
        success: false,
        message: ldapAuth.message || 'Kullanıcı adı veya şifre hatalı'
      });
      return;
    }
    console.log('✅ LDAP auth successful');

    // Step 2: Check if user exists in database (LDAP başarılıysa DB'ye bak)
    const dbUser = await prisma.user.findUnique({
      where: { username: username }
    });

    if (!dbUser) {
      res.status(403).json({
        success: false,
        message: 'Bu kullanıcı sisteme kayıtlı değil. Sistem kullanımı için yöneticinizden izin almanız gerekmektedir.',
        requiresPermission: true
      });
      return;
    }

    if (!dbUser.isActive) {
      res.status(403).json({
        success: false,
        message: 'Hesabınız aktif değil'
      });
      return;
    }

    // Step 3: Update user LDAP verification status and last login
    await prisma.user.update({
      where: { username: username },
      data: {
        ldapVerified: true,
        lastLogin: new Date()
      }
    });

    // Step 4: Fetch user permissions from roles
    const userRoles = await prisma.userRole.findMany({
      where: { userId: dbUser.id },
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

    // Collect all unique permissions
    const permissions = new Set<string>();
    userRoles.forEach(ur => {
      ur.role.permissions.forEach(rp => {
        permissions.add(rp.permission.name);
      });
    });

    const permissionArray = Array.from(permissions);
    console.log(`✅ User ${dbUser.username} logged in with ${permissionArray.length} permissions`);

    // Step 5: Generate JWT token with permissions
    const tokenPayload = {
      id: dbUser.id,
      username: dbUser.username,
      role: dbUser.role,
      email: dbUser.email,
      permissions: permissionArray
    };

    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '24h' });
    const refreshToken = jwt.sign(
      { id: dbUser.id, type: 'refresh' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'Giriş başarılı',
      token,
      refreshToken,
      expiresIn: 24 * 60 * 60,
      user: {
        id: dbUser.id,
        username: dbUser.username,
        firstName: dbUser.firstName,
        lastName: dbUser.lastName,
        email: dbUser.email,
        role: dbUser.role,
        department: dbUser.department,
        isActive: dbUser.isActive,
        permissions: permissionArray
      }
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Sunucu hatası'
    });
  }
});

// Real LDAP service call
async function callLDAPService(username: string, password: string): Promise<{ success: boolean; message?: string }> {
  const ldapServiceUrl = process.env.LDAP_SERVICE_URL;

  // LDAP servis URL'i yoksa development mode için geçici bypass
  if (!ldapServiceUrl) {
    // Development için test kullanıcısı
    if (username === 'caner.guresci' && password === 'test123') {
      return { success: true };
    }
    return { success: false, message: 'Kullanıcı adı veya şifre hatalı' };
  }

  try {
    console.log('🌐 LDAP service URL:', ldapServiceUrl);
    console.log('👤 Username:', username);

    // HTTP ve HTTPS agent'ları oluştur
    const httpAgent = new http.Agent({
      keepAlive: false
    });

    const httpsAgent = new https.Agent({
      keepAlive: false,
      rejectUnauthorized: false
    });

    // LDAP servisine POST isteği
    const response = await axios.post(ldapServiceUrl, {
      user: username,
      password: password
    }, {
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      timeout: 30000, // 30 saniye timeout
      httpAgent: httpAgent,
      httpsAgent: httpsAgent
    });

    console.log('📡 LDAP service response data:', JSON.stringify(response.data, null, 2));

    // İBB LDAP servisinin response formatına göre kontrol
    if (response.status === 200) {
      const responseData = response.data;

      // Log all fields for debugging
      console.log('🔍 LDAP Response Fields:', {
        Login: responseData.Login,
        UserOidStatus: responseData.UserOidStatus,
        ErrorMessage: responseData.ErrorMessage,
        Message: responseData.Message,
        allKeys: Object.keys(responseData)
      });

      // İBB LDAP Response Format (Gerçek):
      // Başarılı: {
      //   "Login": true,
      //   "Message": null,  // ← Başarılı durumda null!
      //   "ErrorMessage": "User Bilgileri Oracle İnternet Directory Getirdi" | "User Bilgileri Microsoft ActiveDirectory Getirdi"
      // }
      // Başarısız: {
      //   "Login": false,
      //   "Message": "Kullanıcı bulunamadı" veya "Şifre hatalı"
      // }

      const isLoginSuccess = responseData.Login === true ||
        responseData.Login === 'true' ||
        responseData.Login === 'True';

      const hasSuccessInErrorMessage = responseData.ErrorMessage &&
        (responseData.ErrorMessage.includes('Getirdi') ||
          responseData.ErrorMessage.includes('ActiveDirectory') ||
          responseData.ErrorMessage.includes('Oracle'));

      // Başarı kriteri: Login=true VE ErrorMessage'da "Getirdi" var
      // Message field'ı başarılı durumda null dönüyor!
      if (isLoginSuccess && hasSuccessInErrorMessage) {
        console.log('✅ LDAP authentication successful');
        return { success: true };
      }

      // Login=true ama ErrorMessage'da "Getirdi" yok - yine de başarılı sayalım
      if (isLoginSuccess) {
        console.log('✅ LDAP authentication successful (Login=true)');
        return { success: true };
      }

      // Hata durumları
      console.log('❌ Login failed:', {
        Login: responseData.Login,
        Message: responseData.Message,
        ErrorMessage: responseData.ErrorMessage
      });

      const errorMessage = responseData.Message || 'Kullanıcı adı veya şifre hatalı';
      return { success: false, message: errorMessage };
    } else {
      return { success: false, message: 'LDAP servis yanıtı geçersiz' };
    }

  } catch (error) {
    console.error('❌ LDAP service call failed:', error);
    console.error('❌ Error details:', {
      isAxiosError: axios.isAxiosError(error),
      code: (error as any).code,
      message: (error as any).message,
      response: (error as any).response?.data,
      timeout: (error as any).timeout,
      syscall: (error as any).syscall,
      address: (error as any).address,
      port: (error as any).port
    });

    if (axios.isAxiosError(error)) {
      if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
        return { success: false, message: 'LDAP servisine bağlanılamadı - DNS veya network hatası' };
      } else if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
        console.error('⏱️ Timeout details:', {
          url: ldapServiceUrl,
          timeout: '30000ms',
          timestamp: new Date().toISOString()
        });
        return { success: false, message: 'LDAP servisi zaman aşımı (30 saniye)' };
      } else if (error.response?.status === 401) {
        return { success: false, message: 'Kullanıcı adı veya şifre hatalı' };
      } else if (error.response?.status === 403) {
        return { success: false, message: 'LDAP erişim reddedildi' };
      } else if (error.response?.status) {
        return { success: false, message: `LDAP servis hatası: ${error.response.status}` };
      } else {
        return { success: false, message: `LDAP bağlantı hatası: ${error.code || error.message}` };
      }
    }

    return { success: false, message: 'LDAP servis bağlantı hatası' };
  }
}

// Token validation endpoint
router.get('/validate', async (req: Request, res: Response): Promise<void> => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      res.status(401).json({
        success: false,
        message: 'Token bulunamadı'
      });
      return;
    }

    // JWT token'ı doğrula
    const decoded = jwt.verify(token, JWT_SECRET) as any;

    // Kullanıcıyı veri tabanından al
    const user = await prisma.user.findUnique({
      where: { id: decoded.id }
    });

    if (!user || !user.isActive) {
      res.status(401).json({
        success: false,
        message: 'Geçersiz token veya kullanıcı aktif değil'
      });
      return;
    }

    // Fetch user permissions from roles
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

    // Collect all unique permissions
    const permissions = new Set<string>();
    userRoles.forEach(ur => {
      ur.role.permissions.forEach(rp => {
        permissions.add(rp.permission.name);
      });
    });

    const permissionArray = Array.from(permissions);

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        department: user.department,
        isActive: user.isActive,
        permissions: permissionArray
      }
    });

  } catch (error) {
    console.error('Token validation error:', error);
    res.status(401).json({
      success: false,
      message: 'Token doğrulama hatası'
    });
  }
});

// Token refresh endpoint
router.post('/refresh', async (req: Request, res: Response): Promise<void> => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(401).json({
        success: false,
        message: 'Refresh token bulunamadı'
      });
      return;
    }

    // Refresh token'ı doğrula
    const decoded = jwt.verify(refreshToken, JWT_SECRET) as any;

    if (decoded.type !== 'refresh') {
      res.status(401).json({
        success: false,
        message: 'Geçersiz refresh token'
      });
      return;
    }

    // Kullanıcıyı veri tabanından al
    const user = await prisma.user.findUnique({
      where: { id: decoded.id }
    });

    if (!user || !user.isActive) {
      res.status(401).json({
        success: false,
        message: 'Geçersiz kullanıcı veya kullanıcı aktif değil'
      });
      return;
    }

    // Fetch user permissions from roles
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

    // Collect all unique permissions
    const permissions = new Set<string>();
    userRoles.forEach(ur => {
      ur.role.permissions.forEach(rp => {
        permissions.add(rp.permission.name);
      });
    });

    const permissionArray = Array.from(permissions);

    // Yeni access token oluştur
    const tokenPayload = {
      id: user.id,
      username: user.username,
      role: user.role,
      email: user.email,
      permissions: permissionArray
    };

    const newToken = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      success: true,
      message: 'Token yenilendi',
      token: newToken,
      expiresIn: 24 * 60 * 60,
      user: {
        id: user.id,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        department: user.department,
        isActive: user.isActive,
        permissions: permissionArray
      }
    });

  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(401).json({
      success: false,
      message: 'Token yenileme hatası'
    });
  }
});

// Access request endpoint
router.post('/request-access', async (req: Request, res: Response): Promise<void> => {
  try {
    const { firstName, lastName, email, department, reason, requestedRole } = req.body;

    // Validasyon
    if (!firstName || !lastName || !email || !department || !reason || !requestedRole) {
      res.status(400).json({
        success: false,
        message: 'Tüm alanlar zorunludur'
      });
      return;
    }

    // Email formatı kontrolü
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      res.status(400).json({
        success: false,
        message: 'Geçerli bir email adresi giriniz'
      });
      return;
    }

    // Role kontrolü
    if (!['admin', 'developer'].includes(requestedRole)) {
      res.status(400).json({
        success: false,
        message: 'Geçersiz rol seçimi'
      });
      return;
    }

    // Access request'i hafızada sakla
    const newRequest: AccessRequestModel = {
      id: uuidv4(), firstName, lastName, email, department,
      reason, requestedRole, status: 'pending', requestDate: new Date().toISOString()
    };
    accessRequestsStorage.push(newRequest);

    console.log(`📊 Total access requests: ${accessRequestsStorage.length}`);

    // Adminlere email bildirimi gönder
    try {
      await emailService.sendAccessRequestEmail({
        firstName, lastName, email, department, reason, requestedRole
      });
      console.log('📧 Access request email sent to admins');
    } catch (emailError) {
      console.error('⚠️ Failed to send access request email:', emailError);
    }

    res.json({
      success: true,
      message: 'Erişim talebiniz başarıyla alındı. Talep değerlendirilecek ve size email ile bilgi verilecektir.'
    });

  } catch (error) {
    console.error('❌ Access request error:', error);
    res.status(500).json({
      success: false,
      message: 'Erişim talebi gönderilirken hata oluştu'
    });
  }
});

// Admin için tüm erişim taleplerini getir
router.get('/access-requests', (req: Request, res: Response): void => {
  console.log(`📊 Total requests in storage: ${accessRequestsStorage.length}`);

  // En yeni talepler önce göstermek için kopyayı ters çevir
  const sorted = [...accessRequestsStorage].sort((a, b) => b.requestDate.localeCompare(a.requestDate));

  res.json({ success: true, data: sorted });
});

// Admin için tüm kullanıcıları getir
router.get('/users', async (req: Request, res: Response): Promise<void> => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        username: true,
        firstName: true,
        lastName: true,
        email: true,
        role: true,
        department: true,
        isActive: true,
        lastLogin: true,
        createdAt: true
      }
    });

    res.json({ success: true, users });
  } catch (error: any) {
    console.error('❌ Error fetching users:', error);
    console.error('❌ Error name:', error?.name);
    console.error('❌ Error message:', error?.message);
    console.error('❌ Error code:', error?.code);
    res.status(500).json({ success: false, message: 'Kullanıcılar getirilemedi', error: error?.message });
  }
});

// Admin için audit logları getir
router.get('/audit-logs', (req: Request, res: Response): void => {
  // Şimdilik boş array döndür
  const logs: any[] = [];
  res.json({ success: true, data: { logs } });
});

// Yeni kullanıcı oluştur
router.post('/users', async (req: Request, res: Response): Promise<void> => {
  try {
    const { username, firstName, lastName, email, role, department } = req.body;

    // Validasyon
    if (!username || !firstName || !lastName || !email || !role) {
      res.status(400).json({
        success: false,
        message: 'Tüm zorunlu alanları doldurunuz'
      });
      return;
    }

    // Kullanıcı var mı kontrol et
    const existingUser = await prisma.user.findUnique({
      where: { username }
    });

    if (existingUser) {
      res.status(400).json({
        success: false,
        message: 'Bu kullanıcı adı zaten mevcut'
      });
      return;
    }

    // Yeni kullanıcı oluştur
    const newUser = await prisma.user.create({
      data: {
        username,
        firstName,
        lastName,
        email,
        role: role as 'admin' | 'developer',
        department,
        isActive: true,
        ldapVerified: false
      }
    });

    res.json({
      success: true,
      message: 'Kullanıcı başarıyla oluşturuldu',
      user: {
        id: newUser.id,
        username: newUser.username,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        email: newUser.email,
        role: newUser.role,
        department: newUser.department,
        isActive: newUser.isActive
      }
    });

  } catch (error) {
    console.error('❌ Error creating user:', error);
    res.status(500).json({
      success: false,
      message: 'Kullanıcı oluşturulurken hata oluştu'
    });
  }
});

// Kullanıcı aktif/pasif yap
router.patch('/users/:userId/activate', async (req: Request, res: Response): Promise<void> => {
  try {
    const { userId } = req.params;

    const user = await prisma.user.update({
      where: { id: userId },
      data: { isActive: true }
    });

    res.json({
      success: true,
      message: 'Kullanıcı aktif hale getirildi'
    });

  } catch (error) {
    console.error('❌ Error activating user:', error);
    res.status(500).json({
      success: false,
      message: 'Kullanıcı aktif hale getirilemedi'
    });
  }
});

router.patch('/users/:userId/deactivate', async (req: Request, res: Response): Promise<void> => {
  try {
    const { userId } = req.params;

    const user = await prisma.user.update({
      where: { id: userId },
      data: { isActive: false }
    });

    res.json({
      success: true,
      message: 'Kullanıcı pasif hale getirildi'
    });

  } catch (error) {
    console.error('❌ Error deactivating user:', error);
    res.status(500).json({
      success: false,
      message: 'Kullanıcı pasif hale getirilemedi'
    });
  }
});

// Kullanıcı rolü güncelle
router.patch('/users/:userId/role', async (req: Request, res: Response): Promise<void> => {
  try {
    const { userId } = req.params;
    const { role } = req.body;

    if (!['admin', 'developer'].includes(role)) {
      res.status(400).json({
        success: false,
        message: 'Geçersiz rol'
      });
      return;
    }

    const user = await prisma.user.update({
      where: { id: userId },
      data: { role: role as 'admin' | 'developer' }
    });

    res.json({
      success: true,
      message: 'Kullanıcı rolü güncellendi'
    });

  } catch (error) {
    console.error('❌ Error updating user role:', error);
    res.status(500).json({
      success: false,
      message: 'Kullanıcı rolü güncellenemedi'
    });
  }
});

// Erişim talebi onaylama endpoint'i
router.patch('/access-requests/:id/approve', requireAuth, requireAdmin, async (req: any, res: Response): Promise<void> => {
  try {
    const requestId = req.params.id;

    // Erişim talebini bul
    const requestIndex = accessRequestsStorage.findIndex(r => r.id === requestId);
    if (requestIndex === -1) {
      res.status(404).json({
        success: false,
        message: 'Erişim talebi bulunamadı'
      });
      return;
    }

    const accessRequest = accessRequestsStorage[requestIndex];

    // Kullanıcıyı oluştur
    try {
      // Kullanıcı adını oluştur (küçük harf, türkçe karakter temizleme)
      const username = `${accessRequest.firstName.toLowerCase()}.${accessRequest.lastName.toLowerCase()}`
        .replace(/ğ/g, 'g')
        .replace(/ü/g, 'u')
        .replace(/ş/g, 's')
        .replace(/ı/g, 'i')
        .replace(/ö/g, 'o')
        .replace(/ç/g, 'c');

      // Kullanıcıyı veritabanına kaydet (LDAP authentication için)
      const user = await prisma.user.create({
        data: {
          id: uuidv4(),
          username: username,
          firstName: accessRequest.firstName,
          lastName: accessRequest.lastName,
          email: accessRequest.email,
          role: accessRequest.requestedRole,
          department: accessRequest.department,
          isActive: true,
          ldapVerified: false, // LDAP ile ilk giriş yapana kadar false
          createdAt: new Date(),
          updatedAt: new Date()
        }
      });

      // Default "USER" rolünü ata (RBAC)
      try {
        const defaultRole = await prisma.role.findFirst({
          where: { name: 'USER' }
        });

        if (defaultRole) {
          await prisma.userRole.create({
            data: {
              userId: user.id,
              roleId: defaultRole.id,
              assignedBy: req.user.id, // Admin who approved
            }
          });
          console.log(`✅ Default USER rolü atandı: ${user.username}`);
        } else {
          console.warn('⚠️ Default USER rolü bulunamadı');
        }
      } catch (roleError) {
        console.error('❌ Default rol atama hatası:', roleError);
        // Rol atanamasa bile kullanıcı oluşturulmuş olsun
      }

      // Erişim talebini onayla
      accessRequestsStorage[requestIndex] = {
        ...accessRequest,
        status: 'approved',
        processedAt: new Date().toISOString(),
        processedBy: req.user.id
      };

      console.log(`✅ Access request approved and user created: ${user.username} (LDAP authentication required)`);

      // Kullanıcıya onay emaili gönder
      try {
        await emailService.sendAccessApprovedEmail({
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          username: user.username,
          department: user.department || undefined
        });
      } catch (emailError) {
        console.error('⚠️ Failed to send approval email:', emailError);
        // Email gönderilemese bile işlem başarılı sayılır
      }

      res.json({
        success: true,
        message: `Erişim talebi onaylandı. Kullanıcı: ${username} - LDAP kimlik bilgileri ile giriş yapabilir.`,
        user: {
          id: user.id,
          username: user.username,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          role: user.role,
          department: user.department,
          isActive: user.isActive
        },
        loginInfo: {
          username: username,
          authMethod: 'LDAP',
          message: 'Kullanıcı kurumsal LDAP kimlik bilgileri ile giriş yapabilir'
        }
      });

    } catch (dbError: any) {
      console.error('❌ User creation error:', dbError);
      res.status(500).json({
        success: false,
        message: 'Kullanıcı oluşturulurken hata oluştu'
      });
    }

  } catch (error) {
    console.error('❌ Access request approval error:', error);
    res.status(500).json({
      success: false,
      message: 'Erişim talebi onaylanırken hata oluştu'
    });
  }
});

// Erişim talebi reddetme endpoint'i
router.patch('/access-requests/:id/reject', requireAuth, requireAdmin, async (req: any, res: Response): Promise<void> => {
  try {
    const requestId = req.params.id;
    const { reason } = req.body;

    // Erişim talebini bul
    const requestIndex = accessRequestsStorage.findIndex(r => r.id === requestId);
    if (requestIndex === -1) {
      res.status(404).json({
        success: false,
        message: 'Erişim talebi bulunamadı'
      });
      return;
    }

    // Erişim talebini reddet
    const rejectedRequest = accessRequestsStorage[requestIndex];
    accessRequestsStorage[requestIndex] = {
      ...rejectedRequest,
      status: 'rejected',
      rejectionReason: reason,
      processedAt: new Date().toISOString(),
      processedBy: req.user.id
    };

    // Kullanıcıya red emaili gönder
    try {
      await emailService.sendAccessRejectedEmail({
        email: rejectedRequest.email,
        firstName: rejectedRequest.firstName,
        lastName: rejectedRequest.lastName,
        reason: reason
      });
    } catch (emailError) {
      console.error('⚠️ Failed to send rejection email:', emailError);
      // Email gönderilemese bile işlem başarılı sayılır
    }

    res.json({
      success: true,
      message: 'Erişim talebi reddedildi'
    });

  } catch (error) {
    console.error('❌ Access request rejection error:', error);
    res.status(500).json({
      success: false,
      message: 'Erişim talebi reddedilirken hata oluştu'
    });
  }
});

// User role update endpoint
router.put('/users/:id/role', requireAuth, requireAdmin, async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;
    const { role } = req.body;


    if (!['admin', 'developer'].includes(role)) {
      res.status(400).json({
        success: false,
        message: 'Geçersiz rol'
      });
      return;
    }

    const updatedUser = await prisma.user.update({
      where: { id },
      data: { role }
    });


    res.json({
      success: true,
      message: 'Kullanıcı rolü güncellendi',
      user: updatedUser
    });

  } catch (error) {
    console.error('❌ User role update error:', error);
    res.status(500).json({
      success: false,
      message: 'Kullanıcı rolü güncellenirken hata oluştu'
    });
  }
});

// User activate endpoint
router.put('/users/:id/activate', requireAuth, requireAdmin, async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;


    const updatedUser = await prisma.user.update({
      where: { id },
      data: { isActive: true }
    });


    res.json({
      success: true,
      message: 'Kullanıcı aktif hale getirildi',
      user: updatedUser
    });

  } catch (error) {
    console.error('❌ User activation error:', error);
    res.status(500).json({
      success: false,
      message: 'Kullanıcı aktif hale getirilirken hata oluştu'
    });
  }
});

// User deactivate endpoint
router.put('/users/:id/deactivate', requireAuth, requireAdmin, async (req: Request, res: Response): Promise<void> => {
  try {
    const { id } = req.params;


    const updatedUser = await prisma.user.update({
      where: { id },
      data: { isActive: false }
    });


    res.json({
      success: true,
      message: 'Kullanıcı pasif hale getirildi',
      user: updatedUser
    });

  } catch (error) {
    console.error('❌ User deactivation error:', error);
    res.status(500).json({
      success: false,
      message: 'Kullanıcı pasif hale getirilirken hata oluştu'
    });
  }
});

// Logout endpoint
router.post('/logout', async (req: Request, res: Response): Promise<void> => {
  try {
    // Frontend'de token'ı silecek, backend'de özel bir işlem gerekmiyor
    res.json({
      success: true,
      message: 'Çıkış başarılı'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Çıkış hatası'
    });
  }
});

export default router;
