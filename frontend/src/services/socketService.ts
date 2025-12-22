import { io, Socket } from 'socket.io-client';

class SocketService {
  private socket: Socket | null = null;
  private readonly serverUrl = process.env.REACT_APP_API_URL || window.location.origin;

  connect(): Promise<Socket> {
    return new Promise((resolve, reject) => {
      if (this.socket?.connected) {
        resolve(this.socket);
        return;
      }

      this.socket = io(this.serverUrl, {
        transports: ['websocket', 'polling'],
        timeout: 10000,
      });

      this.socket.on('connect', () => {
        resolve(this.socket!);
      });

      this.socket.on('disconnect', () => {
        // Socket disconnected
      });

      this.socket.on('connect_error', (error) => {
        reject(error);
      });
    });
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }

  // Join a scan room for progress updates
  joinScanRoom(scanId: string) {
    if (this.socket) {
      this.socket.emit('join-scan', scanId);
    }
  }

  // Leave a scan room
  leaveScanRoom(scanId: string) {
    if (this.socket) {
      this.socket.emit('leave-scan', scanId);
    }
  }
  // Generic event listener
  on(event: string, callback: (...args: any[]) => void) {
    if (this.socket) {
      this.socket.on(event, callback);
    }
  }

  // Generic event listener removal
  off(event: string, callback?: (...args: any[]) => void) {
    if (this.socket) {
      if (callback) {
        this.socket.off(event, callback);
      } else {
        this.socket.off(event);
      }
    }
  }

  // Emit event
  emit(event: string, ...args: any[]) {
    if (this.socket) {
      this.socket.emit(event, ...args);
    }
  }

  // Listen for scan progress updates
  onScanProgress(callback: (data: any) => void) {
    if (this.socket) {
      this.socket.on('scan-progress', callback);
    }
  }

  // Remove scan progress listener
  offScanProgress() {
    if (this.socket) {
      this.socket.off('scan-progress');
    }
  }

  // Listen for real-time alerts
  onAlertFound(callback: (data: { scanId: string; alert: any; totalAlerts: number }) => void) {
    if (this.socket) {
      this.socket.on('alertFound', callback);
    }
  }

  // Remove alert listener
  offAlertFound() {
    if (this.socket) {
      this.socket.off('alertFound');
    }
  }

  // Listen for real-time URLs
  onUrlFound(callback: (data: { scanId: string; url: string; totalUrls: number }) => void) {
    if (this.socket) {
      this.socket.on('urlFound', callback);
    }
  }

  // Remove URL listener
  offUrlFound() {
    if (this.socket) {
      this.socket.off('urlFound');
    }
  }

  // Listen for real-time scan progress (enhanced with alerts and URLs)
  onRealTimeScanProgress(callback: (data: { 
    scanId: string; 
    alertsFound: number; 
    urlsFound: number; 
    newAlertsCount: number; 
    newUrlsCount: number; 
    timestamp: string 
  }) => void) {
    if (this.socket) {
      this.socket.on('scanProgress', callback);
    }
  }

  // Remove real-time scan progress listener
  offRealTimeScanProgress() {
    if (this.socket) {
      this.socket.off('scanProgress');
    }
  }

  // Get socket instance
  getSocket(): Socket | null {
    return this.socket;
  }

  // Check if connected
  isConnected(): boolean {
    return this.socket?.connected ?? false;
  }
}

// Create singleton instance
const socketService = new SocketService();

export default socketService;
