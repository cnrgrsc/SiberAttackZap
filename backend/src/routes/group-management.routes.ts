import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

const router = Router();
const prisma = new PrismaClient();

// ====================================
// GRUP CRUD ENDPOİNTLERİ
// ====================================

/**
 * @route   GET /api/admin/groups
 * @desc    Tüm grupları listele
 * @access  GROUP_READ izni gerekli
 */
router.get('/groups', async (req: Request, res: Response) => {
  try {
    const groups = await prisma.group.findMany({
      include: {
        members: {
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
        roles: {
          include: {
            role: {
              select: {
                id: true,
                name: true,
                displayName: true,
              },
            },
          },
        },
        _count: {
          select: {
            members: true,
            roles: true,
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    const formattedGroups = groups.map((group: any) => ({
      id: group.id,
      name: group.name,
      displayName: group.displayName,
      description: group.description,
      memberCount: group._count.members,
      roleCount: group._count.roles,
      emailEnabled: group.emailEnabled,
      emailOnScanComplete: group.emailOnScanComplete,
      emailOnVulnFound: group.emailOnVulnFound,
      emailOnVulnCritical: group.emailOnVulnCritical,
      emailOnVulnHigh: group.emailOnVulnHigh,
      createdBy: group.createdBy,
      createdAt: group.createdAt,
      updatedAt: group.updatedAt,
    }));

    res.json({
      success: true,
      data: formattedGroups,
    });
  } catch (error: any) {
    console.error('Gruplar listelenirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Gruplar listelenirken bir hata oluştu',
      details: error.message,
    });
  }
});

/**
 * @route   GET /api/admin/groups/:id
 * @desc    Belirli bir grubun detaylarını getir
 * @access  GROUP_READ izni gerekli
 */
router.get('/groups/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    const group = await prisma.group.findUnique({
      where: { id },
      include: {
        members: {
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
        roles: {
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

    if (!group) {
      return res.status(404).json({
        success: false,
        error: 'Grup bulunamadı',
      });
    }

    const formattedGroup = {
      id: group.id,
      name: group.name,
      displayName: group.displayName,
      description: group.description,
      emailEnabled: group.emailEnabled,
      emailOnScanComplete: group.emailOnScanComplete,
      emailOnVulnFound: group.emailOnVulnFound,
      emailOnVulnCritical: group.emailOnVulnCritical,
      emailOnVulnHigh: group.emailOnVulnHigh,
      members: (group.members as any[]).map((gm: any) => ({
        ...gm.user,
        addedBy: gm.addedBy,
        addedAt: gm.addedAt,
      })),
      roles: (group.roles as any[]).map((gr: any) => ({
        ...gr.role,
        permissionCount: gr.role.permissions.length,
        assignedBy: gr.assignedBy,
        assignedAt: gr.assignedAt,
      })),
      createdBy: group.createdBy,
      createdAt: group.createdAt,
      updatedAt: group.updatedAt,
    };

    res.json({
      success: true,
      data: formattedGroup,
    });
  } catch (error: any) {
    console.error('Grup detayı getirilirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Grup detayı getirilirken bir hata oluştu',
      details: error.message,
    });
  }
});

/**
 * @route   POST /api/admin/groups
 * @desc    Yeni grup oluştur
 * @access  GROUP_CREATE izni gerekli
 */
router.post('/groups', async (req: Request, res: Response) => {
  try {
    const {
      name,
      displayName,
      description,
      emailEnabled,
      emailOnScanComplete,
      emailOnVulnFound,
      emailOnVulnCritical,
      emailOnVulnHigh,
    } = req.body;
    const createdBy = (req as any).user?.id || 'system';

    // Validasyon
    if (!name || !displayName) {
      return res.status(400).json({
        success: false,
        error: 'Grup adı ve görünen adı zorunludur',
      });
    }

    // Aynı isimde grup var mı kontrol et
    const existingGroup = await prisma.group.findUnique({
      where: { name },
    });

    if (existingGroup) {
      return res.status(409).json({
        success: false,
        error: 'Bu isimde bir grup zaten mevcut',
      });
    }

    const group = await prisma.group.create({
      data: {
        name,
        displayName,
        description,
        emailEnabled: emailEnabled ?? true,
        emailOnScanComplete: emailOnScanComplete ?? true,
        emailOnVulnFound: emailOnVulnFound ?? false,
        emailOnVulnCritical: emailOnVulnCritical ?? true,
        emailOnVulnHigh: emailOnVulnHigh ?? true,
        createdBy,
      },
    });

    res.status(201).json({
      success: true,
      message: 'Grup başarıyla oluşturuldu',
      data: group,
    });
  } catch (error: any) {
    console.error('Grup oluşturulurken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Grup oluşturulurken bir hata oluştu',
      details: error.message,
    });
  }
});

/**
 * @route   PUT /api/admin/groups/:id
 * @desc    Grubu güncelle
 * @access  GROUP_UPDATE izni gerekli
 */
router.put('/groups/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const {
      displayName,
      description,
      emailEnabled,
      emailOnScanComplete,
      emailOnVulnFound,
      emailOnVulnCritical,
      emailOnVulnHigh,
    } = req.body;

    const group = await prisma.group.findUnique({
      where: { id },
    });

    if (!group) {
      return res.status(404).json({
        success: false,
        error: 'Grup bulunamadı',
      });
    }

    const updatedGroup = await prisma.group.update({
      where: { id },
      data: {
        displayName,
        description,
        emailEnabled,
        emailOnScanComplete,
        emailOnVulnFound,
        emailOnVulnCritical,
        emailOnVulnHigh,
      },
    });

    res.json({
      success: true,
      message: 'Grup başarıyla güncellendi',
      data: updatedGroup,
    });
  } catch (error: any) {
    console.error('Grup güncellenirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Grup güncellenirken bir hata oluştu',
      details: error.message,
    });
  }
});

/**
 * @route   DELETE /api/admin/groups/:id
 * @desc    Grubu sil
 * @access  GROUP_DELETE izni gerekli
 */
router.delete('/groups/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    const group = await prisma.group.findUnique({
      where: { id },
    });

    if (!group) {
      return res.status(404).json({
        success: false,
        error: 'Grup bulunamadı',
      });
    }

    await prisma.group.delete({
      where: { id },
    });

    res.json({
      success: true,
      message: 'Grup başarıyla silindi',
    });
  } catch (error: any) {
    console.error('Grup silinirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Grup silinirken bir hata oluştu',
      details: error.message,
    });
  }
});

// ====================================
// GRUP ÜYE YÖNETİMİ ENDPOİNTLERİ
// ====================================

/**
 * @route   POST /api/admin/groups/:id/members
 * @desc    Gruba üye ekle
 * @access  GROUP_ADD_MEMBERS izni gerekli
 */
router.post('/groups/:id/members', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { userIds } = req.body;
    const addedBy = (req as any).user?.id || 'system';

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'En az bir kullanıcı ID\'si gerekli',
      });
    }

    const group = await prisma.group.findUnique({
      where: { id },
    });

    if (!group) {
      return res.status(404).json({
        success: false,
        error: 'Grup bulunamadı',
      });
    }

    // Üyeleri ekle
    const addedMembers = await Promise.all(
      userIds.map((userId: string) =>
        prisma.groupMember.upsert({
          where: {
            groupId_userId: {
              groupId: id,
              userId,
            },
          },
          update: {},
          create: {
            groupId: id,
            userId,
            addedBy,
          },
        })
      )
    );

    res.json({
      success: true,
      message: `${addedMembers.length} üye başarıyla eklendi`,
      data: addedMembers,
    });
  } catch (error: any) {
    console.error('Üye eklenirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Üye eklenirken bir hata oluştu',
      details: error.message,
    });
  }
});

/**
 * @route   DELETE /api/admin/groups/:id/members/:userId
 * @desc    Gruptan üye çıkar
 * @access  GROUP_REMOVE_MEMBERS izni gerekli
 */
router.delete('/groups/:id/members/:userId', async (req: Request, res: Response) => {
  try {
    const { id, userId } = req.params;

    const groupMember = await prisma.groupMember.findUnique({
      where: {
        groupId_userId: {
          groupId: id,
          userId,
        },
      },
    });

    if (!groupMember) {
      return res.status(404).json({
        success: false,
        error: 'Bu kullanıcı bu grupta bulunamadı',
      });
    }

    await prisma.groupMember.delete({
      where: {
        groupId_userId: {
          groupId: id,
          userId,
        },
      },
    });

    res.json({
      success: true,
      message: 'Üye başarıyla çıkarıldı',
    });
  } catch (error: any) {
    console.error('Üye çıkarılırken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Üye çıkarılırken bir hata oluştu',
      details: error.message,
    });
  }
});

/**
 * @route   GET /api/admin/groups/:id/members
 * @desc    Grup üyelerini listele
 * @access  GROUP_READ izni gerekli
 */
router.get('/groups/:id/members', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    const group = await prisma.group.findUnique({
      where: { id },
      include: {
        members: {
          include: {
            user: {
              select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                department: true,
                isActive: true,
              },
            },
          },
        },
      },
    });

    if (!group) {
      return res.status(404).json({
        success: false,
        error: 'Grup bulunamadı',
      });
    }

    res.json({
      success: true,
      data: (group.members as any[]).map((gm: any) => ({
        ...gm.user,
        addedBy: gm.addedBy,
        addedAt: gm.addedAt,
      })),
    });
  } catch (error: any) {
    console.error('Grup üyeleri listelenirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Grup üyeleri listelenirken bir hata oluştu',
      details: error.message,
    });
  }
});

// ====================================
// GRUP ROL YÖNETİMİ ENDPOİNTLERİ
// ====================================

/**
 * @route   POST /api/admin/groups/:id/roles
 * @desc    Gruba rol ata
 * @access  GROUP_UPDATE izni gerekli
 */
router.post('/groups/:id/roles', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { roleId } = req.body;
    const assignedBy = (req as any).user?.id || 'system';

    if (!roleId) {
      return res.status(400).json({
        success: false,
        error: 'Rol ID\'si gerekli',
      });
    }

    const group = await prisma.group.findUnique({
      where: { id },
    });

    if (!group) {
      return res.status(404).json({
        success: false,
        error: 'Grup bulunamadı',
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

    const groupRole = await prisma.groupRole.upsert({
      where: {
        groupId_roleId: {
          groupId: id,
          roleId,
        },
      },
      update: {},
      create: {
        groupId: id,
        roleId,
        assignedBy,
      },
    });

    res.json({
      success: true,
      message: 'Rol başarıyla atandı',
      data: groupRole,
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
 * @route   DELETE /api/admin/groups/:id/roles/:roleId
 * @desc    Gruptan rolü kaldır
 * @access  GROUP_UPDATE izni gerekli
 */
router.delete('/groups/:id/roles/:roleId', async (req: Request, res: Response) => {
  try {
    const { id, roleId } = req.params;

    const groupRole = await prisma.groupRole.findUnique({
      where: {
        groupId_roleId: {
          groupId: id,
          roleId,
        },
      },
    });

    if (!groupRole) {
      return res.status(404).json({
        success: false,
        error: 'Bu grupta bu rol bulunamadı',
      });
    }

    await prisma.groupRole.delete({
      where: {
        groupId_roleId: {
          groupId: id,
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
 * @route   GET /api/admin/groups/:id/roles
 * @desc    Grup rollerini listele
 * @access  GROUP_READ izni gerekli
 */
router.get('/groups/:id/roles', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    const group = await prisma.group.findUnique({
      where: { id },
      include: {
        roles: {
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

    if (!group) {
      return res.status(404).json({
        success: false,
        error: 'Grup bulunamadı',
      });
    }

    res.json({
      success: true,
      data: (group.roles as any[]).map((gr: any) => ({
        id: gr.role.id,
        name: gr.role.name,
        displayName: gr.role.displayName,
        description: gr.role.description,
        permissionCount: gr.role.permissions.length,
        assignedBy: gr.assignedBy,
        assignedAt: gr.assignedAt,
      })),
    });
  } catch (error: any) {
    console.error('Grup rolleri listelenirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Grup rolleri listelenirken bir hata oluştu',
      details: error.message,
    });
  }
});

// ====================================
// KULLANICI GRUP YÖNETİMİ
// ====================================

/**
 * @route   GET /api/admin/users/:userId/groups
 * @desc    Kullanıcının gruplarını listele
 * @access  GROUP_READ izni gerekli
 */
router.get('/users/:userId/groups', async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;

    const userGroups = await prisma.groupMember.findMany({
      where: { userId },
      include: {
        group: {
          select: {
            id: true,
            name: true,
            displayName: true,
            description: true,
          },
        },
      },
    });

    const groups = userGroups.map(gm => ({
      ...gm.group,
      groupId: gm.groupId,
      addedBy: gm.addedBy,
      addedAt: gm.addedAt,
    }));

    res.json({
      success: true,
      data: groups,
    });
  } catch (error: any) {
    console.error('Kullanıcı grupları listelenirken hata:', error);
    res.status(500).json({
      success: false,
      error: 'Kullanıcı grupları listelenirken bir hata oluştu',
      details: error.message,
    });
  }
});

export default router;
