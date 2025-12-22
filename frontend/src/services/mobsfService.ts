import axios from 'axios';
import socketService from './socketService';

const API_BASE_URL = process.env.REACT_APP_API_URL || window.location.origin;

export interface MobSFStatus {
  isRunning: boolean;
  version?: string;
}

export interface MobileAppScan {
  id: string;
  scanId: string;
  hash: string;
  appName: string;
  packageName: string;
  version: string;
  platform: 'ANDROID' | 'IOS';
  fileSize: number;
  securityScore: number;
  permissions: string[];
  trackers: any[];
  domains: string[];
  urls: string[];
  emails: string[];
  analysisDate: string;
}

export interface MobileScanResult {
  id: string;
  name: string;
  targetUrl: string;
  scanType: string;
  status: string;
  startedAt: string;
  completedAt?: string;
  mobileAppScan?: MobileAppScan;
  vulnerabilities: {
    id: string;
    name: string;
    severity: string;
    description?: string;
  }[];
  vulnerabilityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  creator?: {
    username: string;
    firstName: string;
    lastName: string;
  };
}

export interface MobileScanListResponse {
  scans: MobileScanResult[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

export interface MobileScanStatistics {
  totalScans: number;
  completedScans: number;
  failedScans: number;
  runningScans: number;
  platformStats: {
    android: number;
    ios: number;
  };
  vulnerabilityStats: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

class MobSFService {
  private baseURL: string;

  constructor() {
    this.baseURL = `${API_BASE_URL}/api/mobsf`;
  }

  // Get MobSF status
  async getStatus(): Promise<MobSFStatus> {
    try {
      const response = await axios.get(`${this.baseURL}/status`);
      return {
        isRunning: response.data.connected,
        version: response.data.version
      };
    } catch (error: any) {
      console.error('Failed to get MobSF status:', error);
      return {
        isRunning: false
      };
    }
  }

  // Upload and scan mobile app
  async uploadAndScan(file: File, scanName?: string): Promise<{ scanId: string; fileName: string; message: string }> {
    try {
      const formData = new FormData();
      formData.append('file', file);
      if (scanName) {
        formData.append('scanName', scanName);
      }

      const response = await axios.post(`${this.baseURL}/upload-scan`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        timeout: 300000, // 5 minutes timeout for large files
      });

      return response.data;
    } catch (error: any) {
      console.error('Failed to upload and scan file:', error);
      throw new Error(error.response?.data?.error || 'Failed to upload and scan file');
    }
  }

  // Get scan results
  async getScanResults(scanId: string): Promise<MobileScanResult> {
    try {
      const response = await axios.get(`${this.baseURL}/scan/${scanId}`);
      return response.data;
    } catch (error: any) {
      console.error('Failed to get scan results:', error);
      throw new Error(error.response?.data?.error || 'Failed to get scan results');
    }
  }

  // Get mobile scan history
  async getMobileScans(params?: {
    page?: number;
    limit?: number;
    status?: string;
    platform?: string;
  }): Promise<MobileScanListResponse> {
    try {
      const queryParams = new URLSearchParams();
      if (params?.page) queryParams.append('page', params.page.toString());
      if (params?.limit) queryParams.append('limit', params.limit.toString());
      if (params?.status) queryParams.append('status', params.status);
      if (params?.platform) queryParams.append('platform', params.platform);

      const response = await axios.get(`${this.baseURL}/scans?${queryParams.toString()}`);
      return response.data;
    } catch (error: any) {
      console.error('Failed to get mobile scans:', error);
      throw new Error(error.response?.data?.error || 'Failed to get mobile scans');
    }
  }

  // Delete mobile scan
  async deleteScan(scanId: string): Promise<void> {
    try {
      await axios.delete(`${this.baseURL}/scan/${scanId}`);
    } catch (error: any) {
      console.error('Failed to delete scan:', error);
      throw new Error(error.response?.data?.error || 'Failed to delete scan');
    }
  }

  // Download PDF report
  async downloadPDFReport(scanId: string): Promise<void> {
    try {
      const response = await axios.get(`${this.baseURL}/scan/${scanId}/report/pdf`, {
        responseType: 'blob',
      });

      // Create blob link to download
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `mobile-scan-report-${scanId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error: any) {
      console.error('Failed to download PDF report:', error);
      throw new Error(error.response?.data?.error || 'Failed to download PDF report');
    }
  }

  // Get Android apps for dynamic analysis
  async getAndroidApps(): Promise<any[]> {
    try {
      const response = await axios.get(`${this.baseURL}/dynamic/android-apps`);
      return response.data;
    } catch (error: any) {
      console.error('Failed to get Android apps:', error);
      throw new Error(error.response?.data?.error || 'Failed to get Android apps');
    }
  }

  // Start dynamic analysis
  async startDynamicAnalysis(scanId: string): Promise<any> {
    try {
      const response = await axios.post(`${this.baseURL}/dynamic/start/${scanId}`);
      return response.data;
    } catch (error: any) {
      console.error('Failed to start dynamic analysis:', error);
      throw new Error(error.response?.data?.error || 'Failed to start dynamic analysis');
    }
  }

  // Stop dynamic analysis
  async stopDynamicAnalysis(scanId: string): Promise<any> {
    try {
      const response = await axios.post(`${this.baseURL}/dynamic/stop/${scanId}`);
      return response.data;
    } catch (error: any) {
      console.error('Failed to stop dynamic analysis:', error);
      throw new Error(error.response?.data?.error || 'Failed to stop dynamic analysis');
    }
  }

  // Get mobile scan statistics
  async getStatistics(): Promise<MobileScanStatistics> {
    try {
      const response = await axios.get(`${this.baseURL}/statistics`);
      return response.data;
    } catch (error: any) {
      console.error('Failed to get mobile statistics:', error);
      throw new Error(error.response?.data?.error || 'Failed to get mobile statistics');
    }
  }

  // Subscribe to real-time updates
  subscribeToScanUpdates(scanId: string, callback: (data: any) => void) {
    // Join scan room
    socketService.emit('join-scan', scanId);

    // Listen for MobSF events
    socketService.on('mobsf_workflow', callback);
    socketService.on('mobsf_upload', callback);
    socketService.on('mobsf_scan', callback);
    socketService.on('mobsf_dynamic_analysis', callback);
  }

  // Unsubscribe from real-time updates
  unsubscribeFromScanUpdates(scanId: string, callback: (data: any) => void) {
    // Leave scan room
    socketService.emit('leave-scan', scanId);

    // Remove listeners
    socketService.off('mobsf_workflow', callback);
    socketService.off('mobsf_upload', callback);
    socketService.off('mobsf_scan', callback);
    socketService.off('mobsf_dynamic_analysis', callback);
  }
}

export const mobsfService = new MobSFService();
export default mobsfService;
