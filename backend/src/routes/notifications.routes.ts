import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import * as jwt from 'jsonwebtoken';

const router = Router();
const prisma = new PrismaClient();

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

// Get notifications for current user
router.get('/', requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.id;

    const notifications = await prisma.notification.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 50, // Last 50 notifications
      include: {
        scan: {
          select: {
            id: true,
            name: true,
            targetUrl: true,
            scanType: true,
            status: true
          }
        }
      }
    });

    res.json({ success: true, notifications });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ success: false, message: 'Bildirimler getirilemedi' });
  }
});

// Get unread notification count
router.get('/unread-count', requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.id;

    const count = await prisma.notification.count({
      where: {
        userId,
        isRead: false
      }
    });

    res.json({ success: true, count });
  } catch (error) {
    console.error('Error fetching unread count:', error);
    res.status(500).json({ success: false, message: 'Okunmamış bildirim sayısı getirilemedi' });
  }
});

// Mark notification as read
router.patch('/:id/read', requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.id;
    const { id } = req.params;

    // Verify ownership
    const notification = await prisma.notification.findFirst({
      where: { id, userId }
    });

    if (!notification) {
      return res.status(404).json({ success: false, message: 'Bildirim bulunamadı' });
    }

    await prisma.notification.update({
      where: { id },
      data: { isRead: true }
    });

    res.json({ success: true, message: 'Bildirim okundu olarak işaretlendi' });
  } catch (error) {
    console.error('Error marking notification as read:', error);
    res.status(500).json({ success: false, message: 'Bildirim güncellenemedi' });
  }
});

// Mark all notifications as read
router.post('/mark-all-read', requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.id;

    await prisma.notification.updateMany({
      where: {
        userId,
        isRead: false
      },
      data: { isRead: true }
    });

    res.json({ success: true, message: 'Tüm bildirimler okundu olarak işaretlendi' });
  } catch (error) {
    console.error('Error marking all notifications as read:', error);
    res.status(500).json({ success: false, message: 'Bildirimler güncellenemedi' });
  }
});

// Delete notification
router.delete('/:id', requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.id;
    const { id } = req.params;

    // Verify ownership
    const notification = await prisma.notification.findFirst({
      where: { id, userId }
    });

    if (!notification) {
      return res.status(404).json({ success: false, message: 'Bildirim bulunamadı' });
    }

    await prisma.notification.delete({
      where: { id }
    });

    res.json({ success: true, message: 'Bildirim silindi' });
  } catch (error) {
    console.error('Error deleting notification:', error);
    res.status(500).json({ success: false, message: 'Bildirim silinemedi' });
  }
});

// Delete all read notifications
router.delete('/cleanup/read', requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.id;

    const result = await prisma.notification.deleteMany({
      where: {
        userId,
        isRead: true
      }
    });

    res.json({ success: true, message: `${result.count} okunmuş bildirim silindi` });
  } catch (error) {
    console.error('Error deleting read notifications:', error);
    res.status(500).json({ success: false, message: 'Bildirimler silinemedi' });
  }
});

// Helper function to create notifications for admins
export async function notifyAdmins(params: {
  type: 'SCAN_CREATED' | 'SCAN_COMPLETED' | 'SCAN_FAILED' | 'SCAN_PAUSED' | 'VULNERABILITY_CRITICAL' | 'VULNERABILITY_HIGH' | 'SYSTEM_ALERT' | 'GROUP_ACTIVITY' | 'USER_ACTIVITY';
  title: string;
  message: string;
  scanId?: string;
  createdBy?: string;
  link?: string;
  metadata?: any;
}) {
  try {
    // Find all admin users
    const adminRoles = await prisma.role.findMany({
      where: {
        name: {
          in: ['super_admin', 'admin', 'security_admin']
        }
      },
      include: {
        users: {
          include: {
            user: true
          }
        }
      }
    });

    const adminUserIds = new Set<string>();
    adminRoles.forEach(role => {
      role.users.forEach(userRole => {
        if (userRole.user.isActive) {
          adminUserIds.add(userRole.user.id);
        }
      });
    });

    // Create notifications for each admin
    const notifications = Array.from(adminUserIds).map(userId => ({
      userId,
      type: params.type,
      title: params.title,
      message: params.message,
      scanId: params.scanId,
      createdBy: params.createdBy,
      link: params.link,
      metadata: params.metadata ? JSON.parse(JSON.stringify(params.metadata)) : undefined
    }));

    if (notifications.length > 0) {
      await prisma.notification.createMany({
        data: notifications
      });
      console.log(`✅ Created ${notifications.length} notifications for admins`);
    }
  } catch (error) {
    console.error('❌ Error creating admin notifications:', error);
  }
}

export default router;
