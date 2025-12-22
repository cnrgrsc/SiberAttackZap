import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { permissionService, UserProfile } from '../services/permissionService';
import { authService } from '../services/authService';

interface PermissionContextType {
  profile: UserProfile | null;
  permissions: string[];
  loading: boolean;
  hasPermission: (permission: string) => boolean;
  hasAnyPermission: (...permissions: string[]) => boolean;
  hasAllPermissions: (...permissions: string[]) => boolean;
  canAccessWebScanning: () => boolean;
  canAccessMobileScanning: () => boolean;
  canAccessAdminPanel: () => boolean;
  canViewAllScans: () => boolean;
  canViewAllReports: () => boolean;
  canSendEmail: () => boolean;
  refreshPermissions: () => Promise<void>;
}

const PermissionContext = createContext<PermissionContextType | undefined>(undefined);

interface PermissionProviderProps {
  children: ReactNode;
}

export const PermissionProvider: React.FC<PermissionProviderProps> = ({ children }) => {
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [permissions, setPermissions] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  const loadPermissions = async () => {
    try {
      // AuthService'in init'inin tamamlanmasını bekle (proper way)
      console.log('⏳ PermissionContext: Waiting for AuthService initialization...');
      await authService.waitForInit();
      console.log('✅ PermissionContext: AuthService init complete');
      
      // Kullanıcı giriş yapmış mı kontrol et
      const user = authService.getUser();
      console.log('🔍 PermissionContext: Loading permissions for user:', user);
      
      if (!user) {
        console.log('❌ PermissionContext: No user found');
        setProfile(null);
        setPermissions([]);
        setLoading(false);
        return;
      }

      // Eğer kullanıcıda permissions varsa, hemen kullan (JWT'den gelmiş)
      if (user.permissions && user.permissions.length > 0) {
        console.log('✅ Permissions loaded from JWT:', {
          user: `${user.firstName} ${user.lastName}`,
          permissionCount: user.permissions.length,
          permissions: user.permissions
        });
        setPermissions(user.permissions);
        setLoading(false);
      } else {
        console.warn('⚠️ User object has NO permissions!', user);
        setLoading(false);
      }

      // Ardından backend'den güncel profili çek (async, UI'ı bloklamaz)
      try {
        const userProfile = await permissionService.fetchProfile();
        setProfile(userProfile);
        setPermissions(userProfile.permissions || []);
        
        console.log('✅ Permissions refreshed from backend:', {
          user: `${userProfile.firstName} ${userProfile.lastName}`,
          permissionCount: userProfile.permissions?.length || 0
        });
      } catch (apiError) {
        console.warn('⚠️ Could not fetch profile from API, using JWT permissions:', apiError);
        // JWT'den gelen user bilgilerini profile olarak kullan
        if (user) {
          setProfile({
            id: user.id,
            username: user.username,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            department: user.department,
            isActive: user.isActive,
            permissions: user.permissions || []
          });
        }
      }
    } catch (error) {
      console.error('❌ Failed to load permissions:', error);
      setProfile(null);
      setPermissions([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPermissions();
  }, []);

  const refreshPermissions = async () => {
    setLoading(true);
    await loadPermissions();
  };

  const hasPermission = (permission: string): boolean => {
    return permissions.includes(permission);
  };

  const hasAnyPermission = (...perms: string[]): boolean => {
    return perms.some(p => permissions.includes(p));
  };

  const hasAllPermissions = (...perms: string[]): boolean => {
    return perms.every(p => permissions.includes(p));
  };

  const canAccessWebScanning = (): boolean => {
    return hasAnyPermission('SCAN_WEB_CREATE', 'SCAN_WEB_VIEW');
  };

  const canAccessMobileScanning = (): boolean => {
    return hasAnyPermission('SCAN_MOBILE_CREATE', 'SCAN_MOBILE_VIEW');
  };

  const canAccessAdminPanel = (): boolean => {
    return hasAnyPermission(
      'USER_CREATE', 'USER_READ',
      'ROLE_CREATE', 'ROLE_READ',
      'GROUP_CREATE', 'GROUP_READ',
      'SYSTEM_SETTINGS_VIEW'
    );
  };

  const canViewAllScans = (): boolean => {
    return hasPermission('SCAN_HISTORY_VIEW_ALL');
  };

  const canViewAllReports = (): boolean => {
    return hasPermission('REPORT_VIEW_ALL');
  };

  const canSendEmail = (): boolean => {
    return hasAnyPermission('REPORT_EMAIL_SEND', 'EMAIL_SEND_INDIVIDUAL');
  };

  return (
    <PermissionContext.Provider
      value={{
        profile,
        permissions,
        loading,
        hasPermission,
        hasAnyPermission,
        hasAllPermissions,
        canAccessWebScanning,
        canAccessMobileScanning,
        canAccessAdminPanel,
        canViewAllScans,
        canViewAllReports,
        canSendEmail,
        refreshPermissions
      }}
    >
      {children}
    </PermissionContext.Provider>
  );
};

export const usePermissions = (): PermissionContextType => {
  const context = useContext(PermissionContext);
  if (!context) {
    throw new Error('usePermissions must be used within PermissionProvider');
  }
  return context;
};
