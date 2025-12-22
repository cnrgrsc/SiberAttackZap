import { Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

/**
 * Kullanıcının belirli bir izne sahip olup olmadığını kontrol eden middleware
 * 
 * @param requiredPermission - Gerekli izin adı (örn: 'SCAN_CREATE', 'USER_DELETE')
 * @returns Express middleware function
 * 
 * @example
 * router.post('/scans', requirePermission('SCAN_CREATE'), createScan);
 * router.delete('/users/:id', requirePermission('USER_DELETE'), deleteUser);
 */
export function requirePermission(requiredPermission: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Auth middleware'den gelen user bilgisi
      const userId = (req as any).user?.id;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Kimlik doğrulaması gerekli',
          code: 'UNAUTHORIZED',
        });
      }

      // Kullanıcının tüm izinlerini getir
      const hasPermission = await checkUserPermission(userId, requiredPermission);

      if (!hasPermission) {
        return res.status(403).json({
          success: false,
          error: 'Bu işlem için yetkiniz bulunmuyor',
          code: 'FORBIDDEN',
          requiredPermission,
        });
      }

      // İzin var, devam et
      next();
    } catch (error: any) {
      console.error('İzin kontrolünde hata:', error);
      return res.status(500).json({
        success: false,
        error: 'İzin kontrolünde bir hata oluştu',
        details: error.message,
      });
    }
  };
}

/**
 * Kullanıcının birden fazla izinden EN AZ BİRİNE sahip olup olmadığını kontrol eder
 * 
 * @param requiredPermissions - Gerekli izinlerden biri (örn: ['SCAN_READ_OWN', 'SCAN_READ_ALL'])
 * @returns Express middleware function
 * 
 * @example
 * router.get('/scans', requireAnyPermission(['SCAN_READ_OWN', 'SCAN_READ_ALL']), getScans);
 */
export function requireAnyPermission(requiredPermissions: string[]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user?.id;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Kimlik doğrulaması gerekli',
          code: 'UNAUTHORIZED',
        });
      }

      // Kullanıcının izinlerinden en az birine sahip mi?
      const hasAnyPermission = await checkUserAnyPermission(userId, requiredPermissions);

      if (!hasAnyPermission) {
        return res.status(403).json({
          success: false,
          error: 'Bu işlem için yetkiniz bulunmuyor',
          code: 'FORBIDDEN',
          requiredPermissions,
        });
      }

      next();
    } catch (error: any) {
      console.error('İzin kontrolünde hata:', error);
      return res.status(500).json({
        success: false,
        error: 'İzin kontrolünde bir hata oluştu',
        details: error.message,
      });
    }
  };
}

/**
 * Kullanıcının TÜM belirtilen izinlere sahip olup olmadığını kontrol eder
 * 
 * @param requiredPermissions - Tüm gerekli izinler (örn: ['USER_CREATE', 'USER_ASSIGN_ROLE'])
 * @returns Express middleware function
 * 
 * @example
 * router.post('/users', requireAllPermissions(['USER_CREATE', 'USER_ASSIGN_ROLE']), createUser);
 */
export function requireAllPermissions(requiredPermissions: string[]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user?.id;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Kimlik doğrulaması gerekli',
          code: 'UNAUTHORIZED',
        });
      }

      // Kullanıcının TÜM izinlere sahip mi?
      const hasAllPermissions = await checkUserAllPermissions(userId, requiredPermissions);

      if (!hasAllPermissions) {
        return res.status(403).json({
          success: false,
          error: 'Bu işlem için tüm yetkilere sahip değilsiniz',
          code: 'FORBIDDEN',
          requiredPermissions,
        });
      }

      next();
    } catch (error: any) {
      console.error('İzin kontrolünde hata:', error);
      return res.status(500).json({
        success: false,
        error: 'İzin kontrolünde bir hata oluştu',
        details: error.message,
      });
    }
  };
}

/**
 * Kullanıcının belirli bir role sahip olup olmadığını kontrol eder
 * 
 * @param requiredRole - Gerekli rol adı (örn: 'SUPER_ADMIN', 'ADMIN')
 * @returns Express middleware function
 * 
 * @example
 * router.post('/roles', requireRole('SUPER_ADMIN'), createRole);
 */
export function requireRole(requiredRole: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req as any).user?.id;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Kimlik doğrulaması gerekli',
          code: 'UNAUTHORIZED',
        });
      }

      const hasRole = await checkUserRole(userId, requiredRole);

      if (!hasRole) {
        return res.status(403).json({
          success: false,
          error: 'Bu işlem için gerekli role sahip değilsiniz',
          code: 'FORBIDDEN',
          requiredRole,
        });
      }

      next();
    } catch (error: any) {
      console.error('Rol kontrolünde hata:', error);
      return res.status(500).json({
        success: false,
        error: 'Rol kontrolünde bir hata oluştu',
        details: error.message,
      });
    }
  };
}

// ====================================
// YARDIMCI FONKSİYONLAR
// ====================================

/**
 * Kullanıcının belirli bir izne sahip olup olmadığını kontrol eder
 */
export async function checkUserPermission(userId: string, permissionName: string): Promise<boolean> {
  try {
    // Kullanıcının rollerini ve izinlerini getir
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
        groupMemberships: {
          include: {
            group: {
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
            },
          },
        },
      },
    });

    if (!user) {
      return false;
    }

    // Kullanıcının aktif olup olmadığını kontrol et
    if (!user.isActive) {
      return false;
    }

    // Kullanıcının direkt atanmış rollerindeki izinleri kontrol et
    for (const userRole of user.userRoles) {
      // Rol süresi dolmuş mu?
      if (userRole.expiresAt && userRole.expiresAt < new Date()) {
        continue;
      }

      for (const rolePermission of userRole.role.permissions) {
        if (rolePermission.permission.name === permissionName) {
          return true;
        }
      }
    }

    // Kullanıcının grup üyeliklerinden gelen izinleri kontrol et
    for (const groupMembership of user.groupMemberships) {
      for (const groupRole of groupMembership.group.roles) {
        for (const rolePermission of groupRole.role.permissions) {
          if (rolePermission.permission.name === permissionName) {
            return true;
          }
        }
      }
    }

    return false;
  } catch (error) {
    console.error('checkUserPermission error:', error);
    return false;
  }
}

/**
 * Kullanıcının belirtilen izinlerden EN AZ BİRİNE sahip olup olmadığını kontrol eder
 */
export async function checkUserAnyPermission(userId: string, permissionNames: string[]): Promise<boolean> {
  for (const permissionName of permissionNames) {
    if (await checkUserPermission(userId, permissionName)) {
      return true;
    }
  }
  return false;
}

/**
 * Kullanıcının TÜM belirtilen izinlere sahip olup olmadığını kontrol eder
 */
export async function checkUserAllPermissions(userId: string, permissionNames: string[]): Promise<boolean> {
  for (const permissionName of permissionNames) {
    if (!(await checkUserPermission(userId, permissionName))) {
      return false;
    }
  }
  return true;
}

/**
 * Kullanıcının belirli bir role sahip olup olmadığını kontrol eder
 */
export async function checkUserRole(userId: string, roleName: string): Promise<boolean> {
  try {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        userRoles: {
          include: {
            role: true,
          },
        },
        groupMemberships: {
          include: {
            group: {
              include: {
                roles: {
                  include: {
                    role: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    if (!user || !user.isActive) {
      return false;
    }

    // Direkt rol kontrolü
    for (const userRole of user.userRoles) {
      if (userRole.expiresAt && userRole.expiresAt < new Date()) {
        continue;
      }
      if (userRole.role.name === roleName) {
        return true;
      }
    }

    // Grup üzerinden rol kontrolü
    for (const groupMembership of user.groupMemberships) {
      for (const groupRole of groupMembership.group.roles) {
        if (groupRole.role.name === roleName) {
          return true;
        }
      }
    }

    return false;
  } catch (error) {
    console.error('checkUserRole error:', error);
    return false;
  }
}

/**
 * Kullanıcının tüm izinlerini döndürür
 */
export async function getUserPermissions(userId: string): Promise<string[]> {
  try {
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
        groupMemberships: {
          include: {
            group: {
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
            },
          },
        },
      },
    });

    if (!user || !user.isActive) {
      return [];
    }

    const permissions = new Set<string>();

    // Direkt rollerden izinler
    for (const userRole of user.userRoles) {
      if (userRole.expiresAt && userRole.expiresAt < new Date()) {
        continue;
      }
      for (const rolePermission of userRole.role.permissions) {
        permissions.add(rolePermission.permission.name);
      }
    }

    // Grup rollerinden izinler
    for (const groupMembership of user.groupMemberships) {
      for (const groupRole of groupMembership.group.roles) {
        for (const rolePermission of groupRole.role.permissions) {
          permissions.add(rolePermission.permission.name);
        }
      }
    }

    return Array.from(permissions);
  } catch (error) {
    console.error('getUserPermissions error:', error);
    return [];
  }
}

/**
 * Kullanıcının tüm rollerini döndürür
 */
export async function getUserRoles(userId: string): Promise<string[]> {
  try {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        userRoles: {
          include: {
            role: true,
          },
        },
        groupMemberships: {
          include: {
            group: {
              include: {
                roles: {
                  include: {
                    role: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    if (!user || !user.isActive) {
      return [];
    }

    const roles = new Set<string>();

    // Direkt roller
    for (const userRole of user.userRoles) {
      if (userRole.expiresAt && userRole.expiresAt < new Date()) {
        continue;
      }
      roles.add(userRole.role.name);
    }

    // Grup rolleri
    for (const groupMembership of user.groupMemberships) {
      for (const groupRole of groupMembership.group.roles) {
        roles.add(groupRole.role.name);
      }
    }

    return Array.from(roles);
  } catch (error) {
    console.error('getUserRoles error:', error);
    return [];
  }
}
