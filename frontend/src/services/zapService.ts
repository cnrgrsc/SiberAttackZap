import api from './api';

export interface ZapStatus {
  isRunning: boolean;
  version: string;
  url: string;
}

export interface ScanTarget {
  url: string;
  method?: string;
  data?: string;
}

export interface ScanConfig {
  targetUrl: string;
  scanType: 'AUTOMATED' | 'MANUAL' | 'BASELINE' | 'FULL' | 'API';
  maxChildren?: number;
  recurse?: boolean;
  inScopeOnly?: boolean;
}

export interface ScanResult {
  id: string;
  name: string;
  targetUrl: string;
  scanType: string;
  status: 'PENDING' | 'RUNNING' | 'PAUSED' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  startedAt: string;
  completedAt?: string;
  zapScanId?: string;
  progress?: number;
  workflowId?: string;
}

export interface Vulnerability {
  id: string;
  name: string;
  description: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: string;
  solution: string;
  reference: string;
  url: string;
  param?: string;
  attack?: string;
  evidence?: string;
}

class ZapService {  // ZAP Proxy Status
  async getStatus(): Promise<ZapStatus> {
    try {
      const response = await api.get('/zap/status');

      // Handle backend response format: {success: true, data: {...}}
      const data = response.data || response;

      return {
        isRunning: data.connected || false,
        version: data.version || 'Unknown',
        url: 'http://10.5.63.219:8080'
      };
    } catch (error) {
      return {
        isRunning: false,
        version: 'Unknown',
        url: 'http://10.5.63.219:8080'
      };
    }
  }

  // Spider/Crawling
  async startSpider(targetUrl: string): Promise<{ scanId: string }> {
    return api.post('/zap/spider/start', { targetUrl });
  }

  async getSpiderStatus(scanId: string): Promise<{ status: string; progress: number }> {
    return api.get(`/zap/spider/status/${scanId}`);
  }

  // Active Scanning
  async startActiveScan(targetUrl: string, config?: Partial<ScanConfig>): Promise<{ scanId: string }> {
    return api.post('/zap/ascan/start', { targetUrl, ...config });
  }

  async getActiveScanStatus(scanId: string): Promise<{ status: string; progress: number }> {
    return api.get(`/zap/ascan/status/${scanId}`);
  }

  // Passive Scanning
  async getPassiveScanStatus(): Promise<{ recordsToScan: number }> {
    return api.get('/zap/pscan/status');
  }

  // Alerts/Vulnerabilities
  async getAlerts(baseurl?: string): Promise<Vulnerability[]> {
    const params = baseurl ? { baseurl } : {};
    return api.get('/zap/core/alerts', { params });
  }

  async getAlertsSummary(): Promise<{ [key: string]: number }> {
    return api.get('/zap/core/alerts/summary');
  }

  // Context Management
  async createContext(contextName: string): Promise<{ contextId: string }> {
    return api.post('/zap/context/new', { contextName });
  }

  async includeInContext(contextName: string, regex: string): Promise<void> {
    return api.post('/zap/context/include', { contextName, regex });
  }

  // Session Management
  async newSession(name?: string, overwrite?: boolean): Promise<void> {
    return api.post('/zap/core/newsession', { name, overwrite });
  }

  async saveSession(name: string, overwrite?: boolean): Promise<void> {
    return api.post('/zap/core/savesession', { name, overwrite });
  }

  // Reporting
  async generateHtmlReport(title?: string): Promise<string> {
    return api.get('/zap/core/htmlreport', { params: { title } });
  }

  async generateJsonReport(): Promise<any> {
    return api.get('/zap/core/jsonreport');
  }

  async generateXmlReport(): Promise<string> {
    return api.get('/zap/core/xmlreport');
  }

  // Sites/URLs
  async getSites(): Promise<string[]> {
    return api.get('/zap/core/sites');
  }

  async getUrls(baseurl?: string): Promise<string[]> {
    const params = baseurl ? { baseurl } : {};
    return api.get('/zap/core/urls', { params });
  }

  // Authentication
  async setAuthenticationMethod(contextId: string, authMethodName: string, authMethodConfigParams: string): Promise<void> {
    return api.post('/zap/authentication/setmethod', {
      contextId,
      authMethodName,
      authMethodConfigParams
    });
  }

  // Technology Detection
  async getTechnologies(site: string): Promise<{ [key: string]: string[] }> {
    return api.get('/zap/tech/view/technologies', { params: { site } });
  }

  async detectTechnologies(targetUrl: string): Promise<any> {
    // Updated to use dedicated technology detection service (Wappalyzer)
    const result = await api.post('/technology/detect', { targetUrl });
    console.log('📊 Response type:', typeof result);
    console.log('📋 Response keys:', Object.keys(result || {}));
    return result;
  }

  // Session Management
  async syncSession(): Promise<any> {
    return api.post('/zap/session/sync');
  }

  async getSessionData(): Promise<any> {
    return api.get('/zap/session/data');
  }

  async clearSession(): Promise<void> {
    return api.post('/zap/session/clear');
  }

  // HTTP History/Intercepted Requests
  async getInterceptedRequests(count: number = 20): Promise<any[]> {
    try {
      const response = await api.get('/zap/history', {
        params: { count }
      });
      return response.data?.requests || [];
    } catch (error) {
      console.error('Failed to get intercepted requests:', error);
      return [];
    }
  }

  // HUD Management
  async enableHud(enabled: boolean): Promise<void> {
    return api.post('/zap/hud', { enabled });
  }

  // Browser Management
  async openHudBrowser(url: string): Promise<any> {
    return api.post('/zap/open-browser', { url });
  }

  // Intercept Mode
  async setInterceptMode(enabled: boolean): Promise<void> {
    return api.post('/zap/intercept', { enabled });
  }

  // Scan Control Methods
  async stopAllScans(): Promise<void> {
    return api.post('/zap/scan/stop-all');
  }

  async stopSpider(scanId?: string): Promise<void> {
    return api.post('/zap/scan/spider/stop', { scanId });
  }

  async stopAjaxSpider(): Promise<void> {
    return api.post('/zap/scan/ajax-spider/stop');
  }

  async stopActiveScan(scanId?: string): Promise<void> {
    return api.post('/zap/scan/active/stop', { scanId });
  }

  async pauseActiveScan(scanId: string): Promise<void> {
    return api.post('/zap/scan/active/pause', { scanId });
  }

  async resumeActiveScan(scanId: string): Promise<void> {
    return api.post('/zap/scan/active/resume', { scanId });
  }

  // Lighthouse Scanning
  async runLighthouseScan(targetUrl: string, categories?: string[], formFactor?: 'mobile' | 'desktop'): Promise<any> {
    return api.post('/lighthouse/scan', { targetUrl, categories, formFactor });
  }

  async sendLighthouseEmailReport(scanResult: any, email: string): Promise<any> {
    return api.post('/lighthouse/email-report', { scanResult, email });
  }

  async saveLighthouseScan(scanResult: any, userId?: string): Promise<any> {
    return api.post('/lighthouse/save', { scanResult, userId });
  }

  async getLighthouseHistory(limit: number = 50): Promise<any> {
    return api.get(`/lighthouse/history?limit=${limit}`);
  }

  async getLighthouseScanById(scanId: string): Promise<any> {
    return api.get(`/lighthouse/scan/${scanId}`);
  }

  async deleteLighthouseScan(scanId: string): Promise<any> {
    return api.delete(`/lighthouse/scan/${scanId}`);
  }

  downloadLighthouseReport(scanId: string): void {
    window.open(`${api.defaults.baseURL}/lighthouse/report/${scanId}`, '_blank');
  }

  // ========== Trivy Security Scanner ==========

  async trivyHealthCheck(): Promise<any> {
    return api.get('/trivy/health');
  }

  async scanTrivyImage(imageName: string, severities?: string[], saveToDb?: boolean): Promise<any> {
    return api.post('/trivy/image', { imageName, severities, saveToDb });
  }

  async scanTrivyRepository(repoUrl: string, severities?: string[]): Promise<any> {
    return api.post('/trivy/repository', { repoUrl, severities });
  }

  async scanTrivySecrets(targetPath: string): Promise<any> {
    return api.post('/trivy/secrets', { targetPath });
  }

  async scanTrivyConfig(targetPath: string): Promise<any> {
    return api.post('/trivy/config', { targetPath });
  }

  async scanTrivyLicenses(targetPath: string): Promise<any> {
    return api.post('/trivy/licenses', { targetPath });
  }

  async generateTrivySBOM(target: string, format?: 'cyclonedx' | 'spdx'): Promise<any> {
    return api.post('/trivy/sbom', { target, format });
  }

  async getTrivyHistory(limit: number = 50): Promise<any> {
    return api.get(`/trivy/history?limit=${limit}`);
  }

  async getTrivyScanById(scanId: string): Promise<any> {
    return api.get(`/trivy/scan/${scanId}`);
  }

  downloadTrivyReport(scanId: string): void {
    window.open(`${api.defaults.baseURL}/trivy/report/${scanId}`, '_blank');
  }

  // ========== Trivy Git Repository Management ==========

  async saveGitRepository(
    name: string,
    repoUrl: string,
    username: string,
    password: string,
    branch?: string
  ): Promise<any> {
    return api.post('/trivy/save-repository', { name, repoUrl, username, password, branch });
  }

  async getUserRepositories(): Promise<any> {
    return api.get('/trivy/repositories');
  }

  async scanSavedRepository(repoId: string, severities?: string[]): Promise<any> {
    return api.post(`/trivy/scan-saved-repository/${repoId}`, { severities });
  }

  async scanPrivateRepository(
    repoUrl: string,
    username: string,
    password: string,
    branch?: string,
    severities?: string[]
  ): Promise<any> {
    return api.post('/trivy/private-repository', {
      repoUrl,
      username,
      password,
      branch,
      severities
    });
  }

  async deleteRepository(repoId: string): Promise<any> {
    return api.delete(`/trivy/repository/${repoId}`);
  }

  async updateRepository(
    repoId: string,
    data: { name?: string; username?: string; password?: string; branch?: string }
  ): Promise<any> {
    return api.put(`/trivy/repository/${repoId}`, data);
  }
}

export const zapService = new ZapService();
