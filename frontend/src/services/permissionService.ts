import api from './api';

export interface Permission {
  name: string;
  displayName: string;
  category: string;
  description?: string;
}

export interface UserProfile {
  id: string;
  username: string;
  firstName: string;
  lastName: string;
  email: string;
  department?: string;
  isActive: boolean;
  permissions?: string[];
  userRoles?: Array<{
    role?: {
      name: string;
      displayName: string;
      description?: string;
    };
  }>;
  groupMemberships?: Array<{
    group?: {
      name: string;
      displayName: string;
    };
  }>;
  emailPreference?: EmailPreference;
}

export interface EmailPreference {
  emailEnabled: boolean;
  scanStarted: boolean;
  scanCompleted: boolean;
  scanFailed: boolean;
  scanPaused: boolean;
  vulnCritical: boolean;
  vulnHigh: boolean;
  vulnMedium: boolean;
  vulnLow: boolean;
  vulnInfo: boolean;
  systemAlerts: boolean;
  weeklyReport: boolean;
  monthlyReport: boolean;
  dailyDigest: boolean;
}

class PermissionService {
  private permissions: Set<string> = new Set();
  private profile: UserProfile | null = null;

  // Profil ve izinleri getir
  async fetchProfile(): Promise<UserProfile> {
    try {
      console.log('🔄 Fetching user profile...');
      const response = await api.get('/user/profile');

      console.log('📦 Raw API response:', {
        status: response.status,
        hasData: !!response.data,
        dataType: typeof response.data,
        dataKeys: response.data ? Object.keys(response.data) : []
      });

      // Backend doğrudan user nesnesini dönüyor, axios bunu response.data'ya sarıyor
      const userData = response.data;

      // Validate the response has expected structure
      if (!userData || typeof userData !== 'object') {
        console.error('❌ Invalid response structure:', {
          userData,
          responseData: response.data,
          fullResponse: response
        });
        throw new Error('Invalid response from server - not an object');
      }

      // Verify required fields exist
      if (!userData.id) {
        console.error('❌ Missing id in response:', {
          hasId: !!userData.id,
          hasUsername: !!userData.username,
          availableKeys: Object.keys(userData)
        });
        throw new Error('Invalid user data - missing id field');
      }

      if (!userData.username) {
        console.error('❌ Missing username in response:', {
          hasId: !!userData.id,
          hasUsername: !!userData.username,
          availableKeys: Object.keys(userData)
        });
        throw new Error('Invalid user data - missing username field');
      }

      this.profile = userData;

      // Get permissions from the response
      const permissions = userData.permissions || [];
      this.permissions = new Set(permissions);

      console.log('✅ User profile loaded successfully:', {
        userId: userData.id,
        username: userData.username,
        user: `${userData.firstName} ${userData.lastName}`,
        roles: userData.userRoles?.map((ur: any) => ur.role?.displayName).filter(Boolean) || [],
        permissionCount: this.permissions.size,
        permissions: Array.from(this.permissions)
      });

      return userData;
    } catch (error: any) {
      console.error('❌ Failed to fetch profile:', {
        error: error.message,
        response: error.response?.data,
        status: error.response?.status
      });
      throw error;
    }
  }

  // İzinleri getir
  async fetchPermissions(): Promise<{ permissions: string[]; details: Permission[] }> {
    try {
      const response = await api.get('/user/permissions');
      this.permissions = new Set(response.data.permissions || []);
      return response.data;
    } catch (error) {
      console.error('❌ Failed to fetch permissions:', error);
      throw error;
    }
  }

  // Tek bir izni kontrol et
  hasPermission(permission: string): boolean {
    return this.permissions.has(permission);
  }

  // Birden fazla izinden herhangi birini kontrol et (OR)
  hasAnyPermission(...permissions: string[]): boolean {
    return permissions.some(p => this.permissions.has(p));
  }

  // Birden fazla izinin hepsini kontrol et (AND)
  hasAllPermissions(...permissions: string[]): boolean {
    return permissions.every(p => this.permissions.has(p));
  }

  // İzinleri temizle (logout)
  clearPermissions(): void {
    this.permissions.clear();
    this.profile = null;
  }

  // Mevcut profili döndür
  getProfile(): UserProfile | null {
    return this.profile;
  }

  // Tüm izinleri döndür
  getPermissions(): string[] {
    return Array.from(this.permissions);
  }

  // Web tarama izni var mı?
  canAccessWebScanning(): boolean {
    return this.hasAnyPermission('SCAN_WEB_CREATE', 'SCAN_WEB_VIEW');
  }

  // Mobil tarama izni var mı?
  canAccessMobileScanning(): boolean {
    return this.hasAnyPermission('SCAN_MOBILE_CREATE', 'SCAN_MOBILE_VIEW');
  }

  // Admin panel erişimi var mı?
  canAccessAdminPanel(): boolean {
    return this.hasAnyPermission(
      'USER_CREATE', 'USER_READ',
      'ROLE_CREATE', 'ROLE_READ',
      'GROUP_CREATE', 'GROUP_READ',
      'SYSTEM_SETTINGS_VIEW'
    );
  }

  // Tüm taramaları görebilir mi?
  canViewAllScans(): boolean {
    return this.hasPermission('SCAN_HISTORY_VIEW_ALL');
  }

  // Tüm raporları görebilir mi?
  canViewAllReports(): boolean {
    return this.hasPermission('REPORT_VIEW_ALL');
  }

  // Email gönderebilir mi?
  canSendEmail(): boolean {
    return this.hasAnyPermission('REPORT_EMAIL_SEND', 'EMAIL_SEND_INDIVIDUAL');
  }
}

export const permissionService = new PermissionService();
