import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

const router = Router();
const prisma = new PrismaClient();

// ====================================
// ROL CRUD ENDPOİNTLERİ
// ====================================

/**
 * @route   GET /api/admin/roles
 * @desc    Tüm rolleri listele
 * @access  ROLE_READ izni gerekli
 */
router.get('/roles', async (req: Request, res: Response) => {
  try {
    const roles = await prisma.role.findMany({
      include: {
        permissions: {
          include: {
            permission: true,
          },
        },
        users: {
          include: {
            user: {
              select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
              },
            },
          },
        },
        _count: {
          select: {
            users: true,
            permissions: true,
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    // Response formatla
    const formattedRoles = roles.map(role => ({
      id: role.id,
      name: role.name,
      displayName: role.displayName,
      description: role.description,
      isSystem: role.isSystem,
      userCount: role._count.users,
      permissionCount: role._count.permissions,
      permissions: role.permissions.map(rp => ({
        id: rp.permission.id,
        name: rp.permission.name,
        displayName: rp.permission.displayName,
        category: rp.permission.category,
      })),
      createdBy: role.createdBy,
      createdAt: role.createdAt,
      updatedAt: role.updatedAt,
    }));

    res.json({
      success: true,
      data: formattedRoles,
    });
  } catch (error: any) {
    console.error('Roller listelenirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Roller listelenirken bir hata oluştu',
      details: error.message,
    });
  }
});

/**
 * @route   GET /api/admin/roles/:id
 * @desc    Belirli bir rolün detaylarını getir
 * @access  ROLE_READ izni gerekli
 */
router.get('/roles/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    const role = await prisma.role.findUnique({
      where: { id },
      include: {
        permissions: {
          include: {
            permission: true,
          },
        },
        users: {
          include: {
            user: {
              select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                department: true,
              },
            },
          },
        },
        groups: {
          include: {
            group: {
              select: {
                id: true,
                name: true,
                displayName: true,
              },
            },
          },
        },
      },
    });

    if (!role) {
      return res.status(404).json({
        success: false,
        error: 'Rol bulunamadı',
      });
    }

    const formattedRole = {
      id: role.id,
      name: role.name,
      displayName: role.displayName,
      description: role.description,
      isSystem: role.isSystem,
      permissions: role.permissions.map(rp => ({
        id: rp.permission.id,
        name: rp.permission.name,
        displayName: rp.permission.displayName,
        category: rp.permission.category,
        description: rp.permission.description,
        grantedBy: rp.grantedBy,
        grantedAt: rp.grantedAt,
      })),
      users: role.users.map(ur => ({
        ...ur.user,
        assignedBy: ur.assignedBy,
        assignedAt: ur.assignedAt,
        expiresAt: ur.expiresAt,
      })),
      groups: role.groups.map(gr => ({
        ...gr.group,
        assignedBy: gr.assignedBy,
        assignedAt: gr.assignedAt,
      })),
      createdBy: role.createdBy,
      createdAt: role.createdAt,
      updatedAt: role.updatedAt,
    };

    res.json({
      success: true,
      data: formattedRole,
    });
  } catch (error: any) {
    console.error('Rol detayı getirilirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Rol detayı getirilirken bir hata oluştu',
      details: error.message,
    });
  }
});

/**
 * @route   POST /api/admin/roles
 * @desc    Yeni rol oluştur
 * @access  ROLE_CREATE izni gerekli (SADECE SUPER_ADMIN)
 */
router.post('/roles', async (req: Request, res: Response) => {
  try {
    const { name, displayName, description, permissions } = req.body;
    const createdBy = (req as any).user?.id || 'system'; // Auth middleware'den gelecek

    // Validasyon
    if (!name || !displayName) {
      return res.status(400).json({
        success: false,
        error: 'Rol adı ve görünen adı zorunludur',
      });
    }

    // Aynı isimde rol var mı kontrol et
    const existingRole = await prisma.role.findUnique({
      where: { name },
    });

    if (existingRole) {
      return res.status(409).json({
        success: false,
        error: 'Bu isimde bir rol zaten mevcut',
      });
    }

    // Rolü oluştur
    const role = await prisma.role.create({
      data: {
        name,
        displayName,
        description,
        createdBy,
        isSystem: false,
      },
    });

    // İzinleri ata (varsa)
    if (permissions && Array.isArray(permissions) && permissions.length > 0) {
      await Promise.all(
        permissions.map((permissionId: string) =>
          prisma.rolePermission.create({
            data: {
              roleId: role.id,
              permissionId,
              grantedBy: createdBy,
            },
          })
        )
      );
    }

    // Oluşturulan rolü detaylı getir
    const createdRole = await prisma.role.findUnique({
      where: { id: role.id },
      include: {
        permissions: {
          include: {
            permission: true,
          },
        },
      },
    });

    res.status(201).json({
      success: true,
      message: 'Rol başarıyla oluşturuldu',
      data: createdRole,
    });
  } catch (error: any) {
    console.error('Rol oluşturulurken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Rol oluşturulurken bir hata oluştu',
      details: error.message,
    });
  }
});

/**
 * @route   PUT /api/admin/roles/:id
 * @desc    Rolü güncelle
 * @access  ROLE_UPDATE izni gerekli (SADECE SUPER_ADMIN)
 */
router.put('/roles/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { displayName, description } = req.body;

    const role = await prisma.role.findUnique({
      where: { id },
    });

    if (!role) {
      return res.status(404).json({
        success: false,
        error: 'Rol bulunamadı',
      });
    }

    // Sistem rolleri güncellenemez
    if (role.isSystem) {
      return res.status(403).json({
        success: false,
        error: 'Sistem rolleri güncellenemez',
      });
    }

    const updatedRole = await prisma.role.update({
      where: { id },
      data: {
        displayName,
        description,
      },
      include: {
        permissions: {
          include: {
            permission: true,
          },
        },
      },
    });

    res.json({
      success: true,
      message: 'Rol başarıyla güncellendi',
      data: updatedRole,
    });
  } catch (error: any) {
    console.error('Rol güncellenirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Rol güncellenirken bir hata oluştu',
      details: error.message,
    });
  }
});

/**
 * @route   DELETE /api/admin/roles/:id
 * @desc    Rolü sil
 * @access  ROLE_DELETE izni gerekli (SADECE SUPER_ADMIN)
 */
router.delete('/roles/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    const role = await prisma.role.findUnique({
      where: { id },
      include: {
        users: true,
      },
    });

    if (!role) {
      return res.status(404).json({
        success: false,
        error: 'Rol bulunamadı',
      });
    }

    // Sistem rolleri silinemez
    if (role.isSystem) {
      return res.status(403).json({
        success: false,
        error: 'Sistem rolleri silinemez',
      });
    }

    // Kullanıcıları olan roller silinemez
    if (role.users.length > 0) {
      return res.status(409).json({
        success: false,
        error: `Bu rol ${role.users.length} kullanıcı tarafından kullanılıyor. Önce bu kullanıcıların rollerini değiştirin.`,
      });
    }

    await prisma.role.delete({
      where: { id },
    });

    res.json({
      success: true,
      message: 'Rol başarıyla silindi',
    });
  } catch (error: any) {
    console.error('Rol silinirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Rol silinirken bir hata oluştu',
      details: error.message,
    });
  }
});

// ====================================
// ROL-İZİN İLİŞKİSİ ENDPOİNTLERİ
// ====================================

/**
 * @route   POST /api/admin/roles/:id/permissions
 * @desc    Role izin ekle
 * @access  ROLE_ASSIGN_PERMISSIONS izni gerekli
 */
router.post('/roles/:id/permissions', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { permissionIds } = req.body;
    const grantedBy = (req as any).user?.id || 'system';

    if (!permissionIds || !Array.isArray(permissionIds) || permissionIds.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'En az bir izin ID\'si gerekli',
      });
    }

    const role = await prisma.role.findUnique({
      where: { id },
    });

    if (!role) {
      return res.status(404).json({
        success: false,
        error: 'Rol bulunamadı',
      });
    }

    // İzinleri ata
    const createdPermissions = await Promise.all(
      permissionIds.map((permissionId: string) =>
        prisma.rolePermission.upsert({
          where: {
            roleId_permissionId: {
              roleId: id,
              permissionId,
            },
          },
          update: {},
          create: {
            roleId: id,
            permissionId,
            grantedBy,
          },
        })
      )
    );

    res.json({
      success: true,
      message: `${createdPermissions.length} izin başarıyla eklendi`,
      data: createdPermissions,
    });
  } catch (error: any) {
    console.error('İzin eklenirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'İzin eklenirken bir hata oluştu',
      details: error.message,
    });
  }
});

/**
 * @route   DELETE /api/admin/roles/:id/permissions/:permissionId
 * @desc    Rolden izin kaldır
 * @access  ROLE_ASSIGN_PERMISSIONS izni gerekli
 */
router.delete('/roles/:id/permissions/:permissionId', async (req: Request, res: Response) => {
  try {
    const { id, permissionId } = req.params;

    const rolePermission = await prisma.rolePermission.findUnique({
      where: {
        roleId_permissionId: {
          roleId: id,
          permissionId,
        },
      },
    });

    if (!rolePermission) {
      return res.status(404).json({
        success: false,
        error: 'Bu izin bu rolde bulunamadı',
      });
    }

    await prisma.rolePermission.delete({
      where: {
        roleId_permissionId: {
          roleId: id,
          permissionId,
        },
      },
    });

    res.json({
      success: true,
      message: 'İzin başarıyla kaldırıldı',
    });
  } catch (error: any) {
    console.error('İzin kaldırılırken hata:', error);
    res.status(500).json({
      success: false,
      error: 'İzin kaldırılırken bir hata oluştu',
      details: error.message,
    });
  }
});

/**
 * @route   GET /api/admin/roles/:id/permissions
 * @desc    Rolün izinlerini listele
 * @access  ROLE_READ izni gerekli
 */
router.get('/roles/:id/permissions', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    const role = await prisma.role.findUnique({
      where: { id },
      include: {
        permissions: {
          include: {
            permission: true,
          },
        },
      },
    });

    if (!role) {
      return res.status(404).json({
        success: false,
        error: 'Rol bulunamadı',
      });
    }

    res.json({
      success: true,
      data: role.permissions.map(rp => ({
        id: rp.permission.id,
        name: rp.permission.name,
        displayName: rp.permission.displayName,
        category: rp.permission.category,
        description: rp.permission.description,
        grantedBy: rp.grantedBy,
        grantedAt: rp.grantedAt,
      })),
    });
  } catch (error: any) {
    console.error('Rol izinleri listelenirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Rol izinleri listelenirken bir hata oluştu',
      details: error.message,
    });
  }
});

// ====================================
// KULLANICI-ROL İLİŞKİSİ ENDPOİNTLERİ
// ====================================

/**
 * @route   POST /api/admin/users/:userId/roles
 * @desc    Kullanıcıya rol ata
 * @access  USER_ASSIGN_ROLE izni gerekli
 */
router.post('/users/:userId/roles', async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    const { roleId, expiresAt } = req.body;
    const assignedBy = (req as any).user?.id || 'system';

    if (!roleId) {
      return res.status(400).json({
        success: false,
        error: 'Rol ID\'si gerekli',
      });
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'Kullanıcı bulunamadı',
      });
    }

    const role = await prisma.role.findUnique({
      where: { id: roleId },
    });

    if (!role) {
      return res.status(404).json({
        success: false,
        error: 'Rol bulunamadı',
      });
    }

    const userRole = await prisma.userRole.upsert({
      where: {
        userId_roleId: {
          userId,
          roleId,
        },
      },
      update: {
        expiresAt: expiresAt ? new Date(expiresAt) : null,
      },
      create: {
        userId,
        roleId,
        assignedBy,
        expiresAt: expiresAt ? new Date(expiresAt) : null,
      },
    });

    res.json({
      success: true,
      message: 'Rol başarıyla atandı',
      data: userRole,
    });
  } catch (error: any) {
    console.error('Rol atanırken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Rol atanırken bir hata oluştu',
      details: error.message,
    });
  }
});

/**
 * @route   DELETE /api/admin/users/:userId/roles/:roleId
 * @desc    Kullanıcıdan rolü kaldır
 * @access  USER_ASSIGN_ROLE izni gerekli
 */
router.delete('/users/:userId/roles/:roleId', async (req: Request, res: Response) => {
  try {
    const { userId, roleId } = req.params;

    const userRole = await prisma.userRole.findUnique({
      where: {
        userId_roleId: {
          userId,
          roleId,
        },
      },
    });

    if (!userRole) {
      return res.status(404).json({
        success: false,
        error: 'Bu kullanıcıda bu rol bulunamadı',
      });
    }

    await prisma.userRole.delete({
      where: {
        userId_roleId: {
          userId,
          roleId,
        },
      },
    });

    res.json({
      success: true,
      message: 'Rol başarıyla kaldırıldı',
    });
  } catch (error: any) {
    console.error('Rol kaldırılırken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Rol kaldırılırken bir hata oluştu',
      details: error.message,
    });
  }
});

/**
 * @route   GET /api/admin/users/:userId/roles
 * @desc    Kullanıcının rollerini listele
 * @access  USER_READ izni gerekli
 */
router.get('/users/:userId/roles', async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        userRoles: {
          include: {
            role: {
              include: {
                permissions: {
                  include: {
                    permission: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'Kullanıcı bulunamadı',
      });
    }

    res.json({
      success: true,
      data: user.userRoles.map(ur => ({
        id: ur.role.id,
        name: ur.role.name,
        displayName: ur.role.displayName,
        description: ur.role.description,
        permissionCount: ur.role.permissions.length,
        assignedBy: ur.assignedBy,
        assignedAt: ur.assignedAt,
        expiresAt: ur.expiresAt,
      })),
    });
  } catch (error: any) {
    console.error('Kullanıcı rolleri listelenirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Kullanıcı rolleri listelenirken bir hata oluştu',
      details: error.message,
    });
  }
});

// ====================================
// İZİN LİSTESİ ENDPOİNTİ
// ====================================

/**
 * @route   GET /api/admin/permissions
 * @desc    Tüm izinleri listele
 * @access  ROLE_READ izni gerekli
 */
router.get('/permissions', async (req: Request, res: Response) => {
  try {
    const permissions = await prisma.permission.findMany({
      orderBy: [
        { category: 'asc' },
        { displayName: 'asc' },
      ],
    });

    // Kategorilere göre grupla
    const grouped = permissions.reduce((acc: any, perm) => {
      if (!acc[perm.category]) {
        acc[perm.category] = [];
      }
      acc[perm.category].push(perm);
      return acc;
    }, {});

    res.json({
      success: true,
      data: {
        all: permissions,
        grouped,
      },
    });
  } catch (error: any) {
    console.error('İzinler listelenirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'İzinler listelenirken bir hata oluştu',
      details: error.message,
    });
  }
});

// ====================================
// KULLANICI ROL YÖNETİMİ
// ====================================

/**
 * @route   GET /api/admin/users/:userId/roles
 * @desc    Kullanıcının rollerini listele
 * @access  ROLE_READ izni gerekli
 */
router.get('/users/:userId/roles', async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;

    const userRoles = await prisma.userRole.findMany({
      where: { userId },
      include: {
        role: {
          select: {
            id: true,
            name: true,
            displayName: true,
            description: true,
          },
        },
      },
    });

    const roles = userRoles.map(ur => ({
      ...ur.role,
      roleId: ur.roleId,
      assignedBy: ur.assignedBy,
      assignedAt: ur.assignedAt,
    }));

    res.json({
      success: true,
      data: roles,
    });
  } catch (error: any) {
    console.error('Kullanıcı rolleri listelenirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Kullanıcı rolleri listelenirken bir hata oluştu',
      details: error.message,
    });
  }
});

export default router;
