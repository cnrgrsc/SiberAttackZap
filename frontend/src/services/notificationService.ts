import { Logger } from '../utils/logger';
import api from './api';

export interface Notification {
  id: string;
  userId?: string;
  type: 'info' | 'warning' | 'error' | 'success' | string;
  title: string;
  message: string;
  timestamp?: Date;
  createdAt?: string;
  read?: boolean;
  isRead?: boolean;
  source?: string;
  link?: string;
  scanId?: string;
  createdBy?: string;
  metadata?: any;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  scan?: {
    id: string;
    name: string;
    targetUrl: string;
    scanType: string;
    status: string;
  };
}

export interface NotificationStats {
  total: number;
  unread: number;
  byType: {
    info: number;
    warning: number;
    error: number;
    success: number;
  };
  bySeverity: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
}

class NotificationService {
  private notifications: Notification[] = [];
  private listeners: Array<(notifications: Notification[]) => void> = [];

  constructor() {
    this.loadFromStorage();
  }

  private loadFromStorage() {
    try {
      const stored = localStorage.getItem('siberZed_notifications');
      if (stored) {
        const parsed = JSON.parse(stored);
        this.notifications = parsed.map((n: any) => ({
          ...n,
          timestamp: new Date(n.timestamp)
        }));
        Logger.info('NotificationService: Loaded notifications from storage', { count: this.notifications.length });
      }
    } catch (error) {
      Logger.error('NotificationService: Error loading from storage', error);
    }
  }

  private saveToStorage() {
    try {
      localStorage.setItem('siberZed_notifications', JSON.stringify(this.notifications));
    } catch (error) {
      Logger.error('NotificationService: Error saving to storage', error);
    }
  }

  subscribe(listener: (notifications: Notification[]) => void) {
    this.listeners.push(listener);
    listener(this.notifications);

    return () => {
      this.listeners = this.listeners.filter(l => l !== listener);
    };
  }

  private notifyListeners() {
    this.listeners.forEach(listener => listener(this.notifications));
  }

  getNotifications(): Notification[] {
    return [...this.notifications].sort((a, b) => {
      const bTime = b.timestamp?.getTime() || new Date(b.createdAt || 0).getTime();
      const aTime = a.timestamp?.getTime() || new Date(a.createdAt || 0).getTime();
      return bTime - aTime;
    });
  }

  getUnreadNotifications(): Notification[] {
    return this.notifications.filter(n => !n.read);
  }

  // API based methods
  async fetchNotifications(): Promise<Notification[]> {
    try {
      const response: any = await api.get('/notifications');
      const apiNotifications = (response.notifications || []).map((n: any) => ({
        ...n,
        timestamp: new Date(n.createdAt),
        read: n.isRead
      }));
      this.notifications = apiNotifications;
      this.notifyListeners();
      return apiNotifications;
    } catch (error) {
      Logger.error('Error fetching notifications from API:', error);
      return this.notifications;
    }
  }

  async getUnreadCount(): Promise<number> {
    try {
      const response: any = await api.get('/notifications/unread-count');
      return response.count || 0;
    } catch (error) {
      Logger.error('Error fetching unread count:', error);
      return this.getUnreadNotifications().length;
    }
  }

  getStats(): NotificationStats {
    const stats: NotificationStats = {
      total: this.notifications.length,
      unread: this.notifications.filter(n => !n.read).length,
      byType: { info: 0, warning: 0, error: 0, success: 0 },
      bySeverity: { low: 0, medium: 0, high: 0, critical: 0 }
    };

    this.notifications.forEach(notification => {
      const type = notification.type as 'info' | 'warning' | 'error' | 'success';
      if (type in stats.byType) {
        stats.byType[type]++;
      }
      if (notification.severity) {
        stats.bySeverity[notification.severity]++;
      }
    });

    return stats;
  }

  addNotification(notification: Omit<Notification, 'id' | 'timestamp' | 'read'>): string {
    const newNotification: Notification = {
      ...notification,
      id: Date.now().toString() + '-' + Math.random().toString(36).substr(2, 9),
      timestamp: new Date(),
      read: false
    };

    this.notifications.unshift(newNotification);
    this.saveToStorage();
    this.notifyListeners();

    Logger.info('NotificationService: Added new notification', {
      id: newNotification.id,
      type: newNotification.type,
      title: newNotification.title
    });

    return newNotification.id;
  }

  async markAsRead(notificationId: string): Promise<boolean> {
    try {
      await api.patch(`/notifications/${notificationId}/read`);
      const notification = this.notifications.find(n => n.id === notificationId);
      if (notification) {
        notification.read = true;
        notification.isRead = true;
        this.notifyListeners();
      }
      return true;
    } catch (error) {
      Logger.error('Error marking notification as read:', error);
      return false;
    }
  }

  async markAllAsRead(): Promise<void> {
    try {
      await api.post('/notifications/mark-all-read');
      this.notifications.forEach(notification => {
        notification.read = true;
        notification.isRead = true;
      });
      this.notifyListeners();
    } catch (error) {
      Logger.error('Error marking all notifications as read:', error);
    }
  }

  async deleteNotification(notificationId: string): Promise<boolean> {
    try {
      await api.delete(`/notifications/${notificationId}`);
      const index = this.notifications.findIndex(n => n.id === notificationId);
      if (index > -1) {
        this.notifications.splice(index, 1);
        this.notifyListeners();
      }
      return true;
    } catch (error) {
      Logger.error('Error deleting notification:', error);
      return false;
    }
  }

  async cleanupReadNotifications(): Promise<void> {
    try {
      await api.delete('/notifications/cleanup/read');
      this.notifications = this.notifications.filter(n => !n.read && !n.isRead);
      this.notifyListeners();
    } catch (error) {
      Logger.error('Error cleaning up read notifications:', error);
    }
  }

  clearAll(): void {
    this.notifications = [];
    this.saveToStorage();
    this.notifyListeners();
    Logger.info('NotificationService: Cleared all notifications');
  }

  // Simulate receiving notifications from scan results
  simulateScanNotification(scanType: 'automated' | 'manual', vulnerabilityCount: number) {
    if (vulnerabilityCount > 0) {
      let type: 'error' | 'warning' | 'info' = 'info';
      let severity: 'low' | 'medium' | 'high' | 'critical' = 'low';

      if (vulnerabilityCount >= 10) {
        type = 'error';
        severity = 'critical';
      } else if (vulnerabilityCount >= 5) {
        type = 'warning';
        severity = 'high';
      } else if (vulnerabilityCount >= 2) {
        type = 'warning';
        severity = 'medium';
      }

      this.addNotification({
        type,
        title: `${scanType === 'automated' ? 'Otomatik' : 'Manuel'} Tarama Tamamlandı`,
        message: `${vulnerabilityCount} güvenlik açığı tespit edildi`,
        source: `${scanType}-scan`,
        severity
      });
    } else {
      this.addNotification({
        type: 'success',
        title: `${scanType === 'automated' ? 'Otomatik' : 'Manuel'} Tarama Tamamlandı`,
        message: 'Herhangi bir güvenlik açığı tespit edilmedi',
        source: `${scanType}-scan`
      });
    }
  }
}

export const notificationService = new NotificationService();
export default notificationService;
