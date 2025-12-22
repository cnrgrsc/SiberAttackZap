import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001'; // Development default
const API_FULL_URL = `${API_BASE_URL}/api`;

export interface User {
  id: string;
  username: string;
  role: 'admin' | 'developer';
  firstName: string;
  lastName: string;
  email: string;
  department?: string;
  isActive: boolean;
  lastLogin?: string;
  createdAt: string;
  permissions?: string[]; // RBAC permissions
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface LoginResponse {
  success: boolean;
  user?: User;
  token?: string;
  message?: string;
}

export interface AccessRequestData {
  firstName: string;
  lastName: string;
  email: string;
  department: string;
  reason: string;
  requestedRole: 'developer' | 'admin';
}

class AuthService {
  private token: string | null = null;
  private user: User | null = null;
  private initPromise: Promise<void> | null = null;

  constructor() {
    // Start async initialization
    this.initPromise = this.loadFromStorage();
  }
  
  private async loadFromStorage(): Promise<void> {
    try {
      const savedToken = localStorage.getItem('siberZed_token');
      const savedUser = localStorage.getItem('siberZed_user');
      const savedRefresh = localStorage.getItem('siberZed_refreshToken');
      
      console.log('📂 AuthService: Loading from localStorage...', {
        hasToken: !!savedToken,
        hasUser: !!savedUser,
        hasRefresh: !!savedRefresh,
        tokenPreview: savedToken ? `${savedToken.substring(0, 20)}...` : 'NULL',
        savedUserRaw: savedUser
      });
      
      // Token VE user varsa normal yükleme
      if (savedToken && savedUser) {
        this.token = savedToken;
        this.user = JSON.parse(savedUser);
        this.setAuthHeader(savedToken);
        
        console.log('✅ AuthService: Loaded user from storage:', {
          username: this.user?.username,
          permissions: this.user?.permissions ? `${this.user.permissions.length} permissions` : 'NO PERMISSIONS',
          userObject: this.user
        });
        return;
      }
      
      // Token yoksa ama user varsa - refresh token'ı dene
      if (!savedToken && savedUser) {
        console.warn('⚠️ Token missing but user exists - attempting refresh if available');
        
        // User'ı bellekte tut (PermissionContext okuyabilsin)
        try {
          this.user = JSON.parse(savedUser);
        } catch (e) {
          console.warn('⚠️ Failed to parse saved user, clearing state');
          this.clearStorage();
          return;
        }
        
        // Refresh token varsa onu kullan
        if (savedRefresh) {
          console.log('🔄 Attempting to refresh token...');
          try {
            const refreshed = await this.refreshToken();
            if (refreshed) {
              console.log('✅ AuthService: Token successfully refreshed during init');
              return;
            } else {
              console.warn('⚠️ AuthService: Refresh token did not produce new token, clearing storage');
              this.clearStorage();
              return;
            }
          } catch (err) {
            console.warn('⚠️ AuthService: Refresh failed during init, clearing storage', err);
            this.clearStorage();
            return;
          }
        } else {
          console.warn('⚠️ No refresh token available, clearing old session');
          this.clearStorage();
          return;
        }
      }
      
      // Token var ama user yok - tutarsız durum, temizle
      if (savedToken && !savedUser) {
        console.warn('⚠️ Token exists but user missing - clearing inconsistent state');
        this.clearStorage();
        return;
      }
      
      // Her ikisi de yok - normal durum (logged out)
      console.log('ℹ️ No saved session found');
    } catch (error) {
      console.error('❌ AuthService: Error loading from storage:', error);
      this.clearAuth();
    }
  }

  private setAuthHeader(token: string) {
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  }

  private clearAuthHeader() {
    delete axios.defaults.headers.common['Authorization'];
  }
  private saveToStorage(token: string, user: User) {
    try {
      console.log('💾 AuthService: Saving to localStorage...', { 
        token: token ? 'EXISTS' : 'NULL', 
        user: user ? `${user.username} (${user.role})` : 'NULL',
        permissions: user?.permissions ? `${user.permissions.length} permissions` : 'NO PERMISSIONS',
        userObject: user
      });
      localStorage.setItem('siberZed_token', token);
      localStorage.setItem('siberZed_user', JSON.stringify(user));
      console.log('✅ Saved user to localStorage:', JSON.parse(localStorage.getItem('siberZed_user') || '{}'));
    } catch (error) {
      // Error saving auth data to storage
    }
  }

  private clearStorage() {
    try {
      localStorage.removeItem('siberZed_token');
      localStorage.removeItem('siberZed_user');
      localStorage.removeItem('siberZed_refreshToken');
      // Instance variables'ı da temizle
      this.token = null;
      this.user = null;
      this.clearAuthHeader();
      console.log('🧹 Cleared storage and auth state');
    } catch (error) {
      // Error clearing auth data from storage
    }
  }
  async login(credentials: LoginCredentials): Promise<LoginResponse> {
    try {
      // Simple auth her ortamda LDAP kullanıyor artık
      const authEndpoint = `${API_FULL_URL}/simple-auth/login`;
      
      const response = await axios.post(authEndpoint, credentials);
      
      if (response.data.success && response.data.token && response.data.user) {
        const token = response.data.token;
        const user = response.data.user;
        const refreshToken = response.data.refreshToken;
        
        this.token = token;
        this.user = user;
        
        this.setAuthHeader(token);
        this.saveToStorage(token, user);
        
        // Refresh token'ı da kaydet
        if (refreshToken) {
          localStorage.setItem('siberZed_refreshToken', refreshToken);
        }
        
        return response.data;      } else {
        return {
          success: false,
          message: response.data.message || 'Giriş başarısız'
        };
      }
    } catch (error: any) {
      console.error('❌ AuthService: Network/API error:', error);
      console.error('❌ AuthService: Error details:', {
        message: error.message,
        status: error.response?.status,
        data: error.response?.data,
        url: error.config?.url
      });
      return {
        success: false,
        message: error.response?.data?.message || 'Kullanıcı adı veya şifre hatalı'
      };
    }
  }

  async logout(): Promise<void> {
    try {
      if (this.token) {
        await axios.post(`${API_FULL_URL}/simple-auth/logout`);
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      this.clearAuth();
    }
  }

  private clearAuth() {
    this.token = null;
    this.user = null;
    this.clearAuthHeader();
    this.clearStorage();
  }

  async requestAccess(accessData: AccessRequestData): Promise<{ success: boolean; message: string }> {
    try {
      await axios.post(`${API_FULL_URL}/simple-auth/request-access`, accessData);
      return {
        success: true,
        message: 'Erişim talebiniz başarıyla gönderildi. Onay sürecini takip edebilirsiniz.'
      };
    } catch (error: any) {
      return {
        success: false,
        message: error.response?.data?.message || 'Erişim talebi gönderilirken hata oluştu'
      };
    }
  }  async validateToken(): Promise<boolean> {
    if (!this.token) {
      return false;
    }

    try {
      const response = await axios.get(`${API_FULL_URL}/simple-auth/validate`);
      
      // Backend'den gelen response'da 'success' field'ı kontrol et
      if (response.data.success && response.data.user) {
        // User bilgilerini güncelle
        this.user = response.data.user;
        if (this.token && this.user) {
          this.saveToStorage(this.token, this.user);
        }
        return true;
      }
      
      return false;
    } catch (error: any) {
      console.error('❌ Token validation error:', error);
      
      // Detailed error logging
      if (error.response) {
        console.error('❌ Response status:', error.response.status);
        console.error('❌ Response data:', error.response.data);
        
        // For 401/403, clear auth and throw error for ProtectedRoute to handle
        if (error.response.status === 401 || error.response.status === 403) {
          this.clearAuth();
          throw error;
        }
      } else {
        // Network error - don't clear auth, throw error for ProtectedRoute to handle gracefully
        throw error;
      }
      
      return false;
    }
  }

  async refreshToken(): Promise<boolean> {
    try {
      const refreshToken = localStorage.getItem('siberZed_refreshToken');
      if (!refreshToken) {
        console.warn('⚠️ No refresh token available');
        return false;
      }

      console.log('🔄 Calling refresh token API...');
      const response = await axios.post(`${API_FULL_URL}/simple-auth/refresh`, {
        refreshToken: refreshToken
      });
      
      if (response.data.success && response.data.token) {
        const token = response.data.token;
        this.token = token;
        this.setAuthHeader(token);
        
        if (response.data.user) {
          this.user = response.data.user;
          if (this.token && this.user) {
            this.saveToStorage(this.token, this.user);
          }
        }
        
        console.log('✅ Token refresh successful');
        return true;
      }
      
      console.warn('⚠️ Refresh response did not contain valid token');
      return false;
    } catch (error: any) {
      console.error('❌ Token refresh error:', error?.response?.data || error?.message || error);
      // ⚠️ IMPORTANT: Don't call clearAuth() here if called from loadFromStorage
      // Let the caller decide what to do with the failure
      return false;
    }
  }

  // Getters - these should wait for init to complete
  async waitForInit(): Promise<void> {
    if (this.initPromise) {
      await this.initPromise;
    }
  }

  getUser(): User | null {
    // Note: This is synchronous for backward compatibility
    // For proper init waiting, use getUserAsync() or call waitForInit() first
    console.log('👤 AuthService.getUser() called:', {
      hasUser: !!this.user,
      username: this.user?.username,
      permissions: this.user?.permissions ? `${this.user.permissions.length} permissions` : 'NO PERMISSIONS',
      fullUser: this.user
    });
    return this.user;
  }

  async getUserAsync(): Promise<User | null> {
    await this.waitForInit();
    return this.user;
  }

  getToken(): string | null {
    return this.token;
  }

  isAuthenticated(): boolean {
    return !!(this.token && this.user);
  }

  hasRole(role: 'admin' | 'developer'): boolean {
    return this.user?.role === role;
  }

  isAdmin(): boolean {
    return this.hasRole('admin');
  }

  isDeveloper(): boolean {
    return this.hasRole('developer');
  }
  canAccess(requiredRole: 'admin' | 'developer'): boolean {
    if (!this.user) return false;
    
    if (requiredRole === 'developer') {
      return this.user.role === 'admin' || this.user.role === 'developer';
    }
    
    if (requiredRole === 'admin') {
      return this.user.role === 'admin';
    }
    
    return false;
  }

  // Admin User Management Methods
  async getAllUsers(): Promise<{ success: boolean; users?: User[]; message?: string }> {
    try {
      const response = await axios.get(`${API_FULL_URL}/simple-auth/users`);
      return {
        success: true,
        users: response.data.users
      };
    } catch (error: any) {
      return {
        success: false,
        message: error.response?.data?.message || 'Kullanıcılar getirilemedi'
      };
    }
  }

  async activateUser(userId: string): Promise<{ success: boolean; message: string }> {
    try {
      const response = await axios.put(`${API_FULL_URL}/simple-auth/users/${userId}/activate`, {}, {
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Content-Type': 'application/json'
        }
      });
      return {
        success: true,
        message: response.data.message
      };
    } catch (error: any) {
      return {
        success: false,
        message: error.response?.data?.message || 'Kullanıcı aktif hale getirilemedi'
      };
    }
  }

  async deactivateUser(userId: string): Promise<{ success: boolean; message: string }> {
    try {
      const response = await axios.put(`${API_FULL_URL}/simple-auth/users/${userId}/deactivate`, {}, {
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Content-Type': 'application/json'
        }
      });
      return {
        success: true,
        message: response.data.message
      };
    } catch (error: any) {
      return {
        success: false,
        message: error.response?.data?.message || 'Kullanıcı pasif hale getirilemedi'
      };
    }
  }

  async updateUserRole(userId: string, role: 'admin' | 'developer'): Promise<{ success: boolean; message: string }> {
    try {
      const response = await axios.put(`${API_FULL_URL}/simple-auth/users/${userId}/role`, { role }, {
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Content-Type': 'application/json'
        }
      });
      return {
        success: true,
        message: response.data.message
      };
    } catch (error: any) {
      return {
        success: false,
        message: error.response?.data?.message || 'Kullanıcı rolü güncellenemedi'
      };
    }
  }

  async createUser(userData: {
    username: string;
    firstName: string;
    lastName: string;
    email: string;
    role: 'admin' | 'developer';
    department?: string;
  }): Promise<{ success: boolean; user?: User; message: string }> {
    try {
      const response = await axios.post(`${API_FULL_URL}/simple-auth/users`, userData);
      return {
        success: true,
        user: response.data.user,
        message: response.data.message
      };
    } catch (error: any) {
      return {
        success: false,
        message: error.response?.data?.message || 'Kullanıcı oluşturulamadı'
      };
    }
  }

  async getAuditLogs(options?: {
    page?: number;
    limit?: number;
    userId?: string;
    action?: string;
  }): Promise<{ success: boolean; data?: any; message?: string }> {
    try {
      const params = new URLSearchParams();
      if (options?.page) params.append('page', options.page.toString());
      if (options?.limit) params.append('limit', options.limit.toString());
      if (options?.userId) params.append('userId', options.userId);
      if (options?.action) params.append('action', options.action);

      const response = await axios.get(`${API_FULL_URL}/simple-auth/audit-logs?${params}`);
      
      // Backend response format: {success: true, logs: []}
      // Frontend expects: {success: true, data: []}
      return {
        success: true,
        data: response.data.logs || response.data.data || []
      };
    } catch (error: any) {
      return {
        success: false,
        message: error.response?.data?.message || 'Audit logları getirilemedi'
      };
    }
  }

  async getAccessRequests(): Promise<{ success: boolean; data?: any[]; message?: string }> {
    try {
      const response = await axios.get(`${API_FULL_URL}/simple-auth/access-requests`);
      
      // Backend response format: {success: true, requests: []}
      // Frontend expects: {success: true, data: []}
      return {
        success: true,
        data: response.data.requests || response.data.data || []
      };
    } catch (error: any) {
      console.error('❌ AuthService: Access requests error:', error);
      return {
        success: false,
        message: error.response?.data?.message || 'Erişim talepleri getirilemedi'
      };
    }
  }

  async approveAccessRequest(requestId: string): Promise<{ success: boolean; message: string }> {
    try {
      const response = await axios.patch(`${API_FULL_URL}/simple-auth/access-requests/${requestId}/approve`);
      return {
        success: true,
        message: response.data.message
      };
    } catch (error: any) {
      return {
        success: false,
        message: error.response?.data?.message || 'Erişim talebi onaylanamadı'
      };
    }
  }

  async rejectAccessRequest(requestId: string, reason?: string): Promise<{ success: boolean; message: string }> {
    try {
      const response = await axios.patch(`${API_FULL_URL}/simple-auth/access-requests/${requestId}/reject`, { reason });
      return {
        success: true,
        message: response.data.message
      };
    } catch (error: any) {
      return {
        success: false,
        message: error.response?.data?.message || 'Erişim talebi reddedilemedi'
      };
    }
  }
}

export const authService = new AuthService();
export default authService;
