import express, { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import * as jwt from 'jsonwebtoken';

const router = express.Router();
const prisma = new PrismaClient();

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

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

// ============================================
// KULLANICI PROFİL AYARLARI
// ============================================

// Email tercihlerini getir
router.get('/email-preferences', requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    let preferences = await prisma.emailPreference.findUnique({
      where: { userId }
    });

    // Eğer yoksa default oluştur
    if (!preferences) {
      preferences = await prisma.emailPreference.create({
        data: { userId }
      });
    }

    res.json(preferences);
  } catch (error) {
    console.error('Error fetching email preferences:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Email tercihlerini güncelle (PUT ve PATCH destekli)
const updateEmailPreferences = async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const {
      emailEnabled,
      scanStarted,
      scanCompleted,
      scanFailed,
      scanPaused,
      vulnCritical,
      vulnHigh,
      vulnMedium,
      vulnLow,
      vulnInfo,
      systemAlerts,
      weeklyReport,
      monthlyReport,
      dailyDigest
    } = req.body;

    const preferences = await prisma.emailPreference.upsert({
      where: { userId },
      update: {
        emailEnabled,
        scanStarted,
        scanCompleted,
        scanFailed,
        scanPaused,
        vulnCritical,
        vulnHigh,
        vulnMedium,
        vulnLow,
        vulnInfo,
        systemAlerts,
        weeklyReport,
        monthlyReport,
        dailyDigest
      },
      create: {
        userId,
        emailEnabled,
        scanStarted,
        scanCompleted,
        scanFailed,
        scanPaused,
        vulnCritical,
        vulnHigh,
        vulnMedium,
        vulnLow,
        vulnInfo,
        systemAlerts,
        weeklyReport,
        monthlyReport,
        dailyDigest
      }
    });

    // Audit log
    await prisma.auditLog.create({
      data: {
        userId,
        action: 'EMAIL_PREFERENCES_UPDATED',
        details: { preferences },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      }
    });

    res.json(preferences);
  } catch (error) {
    console.error('Error updating email preferences:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Her iki HTTP metodunu da destekle
router.patch('/email-preferences', requireAuth, updateEmailPreferences);
router.put('/email-preferences', requireAuth, updateEmailPreferences);
// Kullanıcı profilini getir
router.get('/profile', requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        emailPreference: true,
        userRoles: {
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
        },
        groupMemberships: {
          include: {
            group: true
          }
        }
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // İzinleri düzle
    const permissions = new Set<string>();
    user.userRoles.forEach(ur => {
      ur.role.permissions.forEach(rp => {
        permissions.add(rp.permission.name);
      });
    });

    const profileResponse = {
      ...user,
      permissions: Array.from(permissions)
    };

    console.log('✅ Profile response:', {
      userId: profileResponse.id,
      username: profileResponse.username,
      permissionsCount: profileResponse.permissions.length,
      roles: profileResponse.userRoles.map((ur: any) => ur.role?.name)
    });

    res.json(profileResponse);
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Profil güncelleme
router.put('/profile', requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { firstName, lastName, department } = req.body;

    const user = await prisma.user.update({
      where: { id: userId },
      data: {
        firstName,
        lastName,
        department
      }
    });

    // Audit log
    await prisma.auditLog.create({
      data: {
        userId,
        action: 'PROFILE_UPDATED',
        details: { firstName, lastName, department },
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      }
    });

    res.json(user);
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Kullanıcının izinlerini kontrol et
router.get('/permissions', requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const userRoles = await prisma.userRole.findMany({
      where: { userId },
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

    const permissions = new Set<string>();
    const permissionDetails: any[] = [];

    userRoles.forEach(ur => {
      ur.role.permissions.forEach(rp => {
        if (!permissions.has(rp.permission.name)) {
          permissions.add(rp.permission.name);
          permissionDetails.push({
            name: rp.permission.name,
            displayName: rp.permission.displayName,
            category: rp.permission.category,
            description: rp.permission.description
          });
        }
      });
    });

    res.json({
      permissions: Array.from(permissions),
      details: permissionDetails
    });
  } catch (error) {
    console.error('Error fetching permissions:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
