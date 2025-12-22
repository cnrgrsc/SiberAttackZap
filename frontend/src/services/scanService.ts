import api from './api';
import { ScanResult, ScanConfig, Vulnerability } from './zapService';

export interface ScanHistoryItem extends ScanResult {
  vulnerabilities?: Vulnerability[];
  createdBy?: string;
}

export interface ScanStatistics {
  totalScans: number;
  activeScans: number;
  completedScans: number;
  totalVulnerabilities: number;
  criticalVulnerabilities: number;
  highVulnerabilities: number;
  mediumVulnerabilities: number;
  lowVulnerabilities: number;
  vulnerabilitySeverity?: {
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    INFO: number;
  };
}

export interface ScanProgress {
  progress: number;
  phase: string;
  details: {
    spider?: { progress: number; status: string };
    ajaxSpider?: { progress: number; status: string };
    activeScan?: { progress: number; status: string };
  };
  isCompleted: boolean;
  error?: string;
  percentage?: number;
  status?: string;
  urlsFound?: number;
  alertsFound?: number;
}

class ScanService {
  // Scan Management
  async createScan(config: ScanConfig): Promise<ScanResult> {
    return api.post('/scans', config);
  }

  async getScans(): Promise<ScanHistoryItem[]> {
    try {
      const response = await api.get('/scans');
      // Backend returns { success: true, data: scans }
      return response.data?.data || response.data || response || [];
    } catch (error) {
      throw error;
    }
  }

  async getScanById(id: string): Promise<ScanResult | null> {
    try {
      const response = await api.get(`/scans/${id}`);
      return response.data || response;
    } catch (error) {
      console.error('Error fetching scan by ID:', error);
      return null;
    }
  }

  async getScanVulnerabilities(id: string): Promise<Vulnerability[]> {
    try {
      const response = await api.get(`/scans/${id}/vulnerabilities`);
      return response.data || response || [];
    } catch (error) {
      console.error('Error fetching scan vulnerabilities:', error);
      return [];
    }
  }

  async getStatistics(): Promise<ScanStatistics> {
    try {
      const response = await api.get('/scans/statistics/overview');
      return response.data || response;
    } catch (error) {
      console.error('Error fetching scan statistics:', error);
      return {
        totalScans: 0,
        activeScans: 0,
        completedScans: 0,
        totalVulnerabilities: 0,
        criticalVulnerabilities: 0,
        highVulnerabilities: 0,
        mediumVulnerabilities: 0,
        lowVulnerabilities: 0,
        vulnerabilitySeverity: {
          HIGH: 0,
          MEDIUM: 0,
          LOW: 0,
          INFO: 0
        }
      };
    }
  }

  async getScan(id: string): Promise<ScanHistoryItem> {
    return api.get(`/scans/${id}`);
  }

  async pauseScan(id: string): Promise<void> {
    return api.post(`/scans/${id}/pause`);
  }

  async resumeScan(id: string): Promise<void> {
    return api.post(`/scans/${id}/resume`);
  }

  async stopScan(id: string): Promise<void> {
    return api.post(`/scans/${id}/stop`);
  }

  async deleteScan(id: string): Promise<void> {
    return api.delete(`/scans/${id}`);
  }

  // Automated Scanning
  async startAutomatedScan(config: {
    targetUrl: string;
    scanName?: string;
    maxChildren?: number;
    recurse?: boolean;
    inScopeOnly?: boolean;
    spiderOptions?: {
      maxChildren?: number;
      recurse?: boolean;
      contextName?: string;
      subtreeOnly?: boolean;
    };
    activeScanOptions?: {
      inScopeOnly?: boolean;
      recurse?: boolean;
      scanPolicyName?: string;
    };
    ajaxSpiderOptions?: {
      enabled?: boolean;
      browser?: string;
      maxCrawlDepth?: number;
      maxCrawlStates?: number;
    };
    authConfig?: {
      type?: 'form' | 'http' | 'script';
      loginUrl?: string;
      username?: string;
      password?: string;
      usernameParam?: string;
      passwordParam?: string;
    };
  }): Promise<ScanResult> {
    const scanData = {
      name: config.scanName || `Automated scan of ${config.targetUrl}`,
      targetUrl: config.targetUrl,
      scanType: 'AUTOMATED',
      config: {
        spiderMaxChildren: config.spiderOptions?.maxChildren || config.maxChildren || 10,
        recurse: config.spiderOptions?.recurse || config.recurse,
        inScopeOnly: config.activeScanOptions?.inScopeOnly || config.inScopeOnly,
        excludeUrls: [],
        includeUrls: []
      }
    };

    return api.post('/scans/automated', scanData);
  }

  async configureScan(config: ScanConfig): Promise<ScanResult> {
    return api.post('/scans/configure', config);
  }

  // Manual Scanning
  async startManualScan(config: {
    targetUrl: string;
    scanName?: string;
    customSettings?: any;
  }): Promise<ScanResult> {
    const scanData = {
      name: config.scanName || `Manual scan of ${config.targetUrl}`,
      targetUrl: config.targetUrl,
      scanType: 'MANUAL',
      config: config.customSettings || {}
    };

    return api.post('/scans/manual', scanData);
  }

  // Spider Configuration
  async configureSpider(config: {
    maxChildren?: number;
    recurse?: boolean;
    subtreeOnly?: boolean;
  }): Promise<any> {
    return api.post('/scans/spider/config', config);
  }

  // Active Scan Configuration
  async configureActiveScan(config: {
    recurse?: boolean;
    inScopeOnly?: boolean;
    scanPolicyName?: string;
  }): Promise<any> {
    return api.post('/scans/active/config', config);
  }

  // Scan Progress
  async getScanProgress(id: string): Promise<ScanProgress> {
    try {
      const response = await api.get(`/scans/${id}/progress`);
      return response.data || response;
    } catch (error) {
      throw error;
    }
  }

  // Reports
  async generateScanReport(scanId: string, format: 'html' | 'json' | 'xml' | 'pdf' = 'html'): Promise<string> {
    return api.get(`/scans/${scanId}/report`, { params: { format } });
  }

  async downloadScanReport(scanId: string, format: 'html' | 'json' | 'xml' | 'pdf' = 'html'): Promise<Blob> {
    const response = await api.get(`/reports/${format}/${scanId}`, {
      responseType: 'blob',
    });
    return response as unknown as Blob;
  }

  // Helper method to download a file
  async downloadReport(scanId: string, format: 'html' | 'json' | 'xml' | 'pdf' = 'html'): Promise<void> {
    try {
      const blob = await this.downloadScanReport(scanId, format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan-report-${scanId}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      throw error;
    }
  }

  // Statistics
  async getScanStatistics(): Promise<ScanStatistics> {
    try {
      const response = await api.get('/scans/statistics');
      return response.data || response;
    } catch (error) {
      throw error;
    }
  }

  // Vulnerability Management
  async getVulnerabilityDetails(scanId: string, vulnerabilityId: string): Promise<Vulnerability> {
    try {
      const response = await api.get(`/scans/${scanId}/vulnerabilities/${vulnerabilityId}`);
      return response.data || response;
    } catch (error) {
      throw error;
    }
  }

  // Real-time Updates
  async subscribeScanUpdates(scanId: string, callback: (update: any) => void): Promise<void> {
    // This will be implemented with WebSocket or SSE
    // TODO: Implement real-time updates
  }

  async unsubscribeScanUpdates(scanId: string): Promise<void> {
    // This will be implemented with WebSocket or SSE
    // TODO: Implement real-time updates cleanup
  }

  // Scan Templates
  async getScanTemplates(): Promise<any[]> {
    try {
      const response = await api.get('/scans/templates');
      return response.data || response;
    } catch (error) {
      throw error;
    }
  }

  async createScanTemplate(template: any): Promise<any> {
    try {
      const response = await api.post('/scans/templates', template);
      return response.data || response;
    } catch (error) {
      throw error;
    }
  }

  async deleteScanTemplate(templateId: string): Promise<void> {
    try {
      await api.delete(`/scans/templates/${templateId}`);
    } catch (error) {
      throw error;
    }
  }

  // Get discovered URLs for a scan
  async getScanUrls(scanId: string): Promise<string[]> {
    try {
      const response = await api.get(`/scans/${scanId}/urls`);
      return response.data || [];
    } catch (error) {
      console.error('Error getting scan URLs:', error);
      return [];
    }
  }

  // Get scan details (URLs + vulnerabilities)
  async getScanDetails(scanId: string): Promise<any> {
    try {
      const response = await api.get(`/scans/${scanId}/details`);
      return response.data || {};
    } catch (error) {
      console.error('Error getting scan details:', error);
      return {};
    }
  }

  // Modern Report Generation
  async downloadModernReport(scanId: string): Promise<void> {
    try {
      const response = await api.get(`/reports/modern/${scanId}`, {
        responseType: 'blob',
      });

      const blob = response as unknown as Blob;
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `SiberZed-Security-Report-${scanId}-${new Date().toISOString().split('T')[0]}.html`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      throw error;
    }
  }

  async getReportData(scanId: string): Promise<any> {
    try {
      const response = await api.get(`/reports/data/${scanId}`);
      return response.data || response;
    } catch (error) {
      throw error;
    }
  }

  // ========================================
  // OPTIMIZED METHODS FOR SYSTEM STABILITY
  // ========================================

  // Get quick summary without heavy ZAP operations
  async getQuickSummary(): Promise<any> {
    try {
      const response = await api.get('/reports/quick-summary');
      return response.data || response;
    } catch (error) {
      console.error('Failed to get quick summary:', error);
      throw error;
    }
  }

  // Get lightweight report for specific scan
  async getLightweightReport(scanId: string): Promise<any> {
    try {
      const response = await api.get(`/reports/lightweight/${scanId}`);
      return response.data || response;
    } catch (error) {
      console.error('Failed to get lightweight report:', error);
      throw error;
    }
  }

  // Manual ZAP session management
  async clearZapSession(): Promise<any> {
    try {
      const response = await api.post('/zap/session/clear');
      return response.data || response;
    } catch (error) {
      console.error('Failed to clear ZAP session:', error);
      throw error;
    }
  }

  async createNewZapSession(): Promise<any> {
    try {
      const response = await api.post('/zap/session/new');
      return response.data || response;
    } catch (error) {
      console.error('Failed to create new ZAP session:', error);
      throw error;
    }
  }

  // Get ZAP alert count only (lightweight)
  async getZapAlertCount(): Promise<number> {
    try {
      const response = await api.get('/zap/alerts/count');
      return response.data?.alertCount || 0;
    } catch (error) {
      console.error('Failed to get ZAP alert count:', error);
      return 0;
    }
  }

  // Get optimized alerts with limit
  async getOptimizedAlerts(limit: number = 100): Promise<any[]> {
    try {
      const response = await api.get(`/zap/alerts/optimized?limit=${limit}`);
      return response.data || [];
    } catch (error) {
      console.error('Failed to get optimized alerts:', error);
      return [];
    }
  }

  // Stop all ZAP scans
  async stopAllZapScans(): Promise<any> {
    try {
      const response = await api.post('/zap/scans/stop-all');
      return response.data || response;
    } catch (error) {
      console.error('Failed to stop all ZAP scans:', error);
      throw error;
    }
  }

  // Get system performance stats
  async getSystemStats(): Promise<any> {
    try {
      const response = await api.get('/zap/system/stats');
      return response.data || response;
    } catch (error) {
      console.error('Failed to get system stats:', error);
      return {
        totalAlerts: 0,
        totalHosts: 0,
        lastUpdate: new Date().toISOString()
      };
    }
  }

  // Safe report download with timeout handling
  async downloadReportSafe(scanId: string, format: 'html' | 'json' | 'xml', timeout: number = 120000): Promise<void> {
    try {
      // Set a timeout for the request
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(`/api/reports/${format}/${scanId}`, {
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

      a.href = url;
      a.download = `security-report-${timestamp}.${format}`;
      document.body.appendChild(a);
      a.click();

      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error: any) {
      if (error.name === 'AbortError') {
        throw new Error('Report download timed out. Try using lightweight reports or clear ZAP session.');
      }
      throw error;
    }
  }

  // =============================================================================
  // MANUAL SCANNING METHODS INTEGRATION
  // =============================================================================

  // Get manual scan tools
  async getManualScanTools(): Promise<any> {
    try {
      const response = await api.get('/manual-scan/tools');
      return response.data;
    } catch (error) {
      console.error('Failed to get manual scan tools:', error);
      throw error;
    }
  }

  // Run manual vulnerability tests
  async runManualSqlInjectionTest(config: any): Promise<any> {
    try {
      const response = await api.post('/manual-scan/attacks/sql-injection', config);
      return response.data;
    } catch (error) {
      console.error('Manual SQL injection test failed:', error);
      throw error;
    }
  }

  async runManualXssTest(config: any): Promise<any> {
    try {
      const response = await api.post('/manual-scan/attacks/xss', config);
      return response.data;
    } catch (error) {
      console.error('Manual XSS test failed:', error);
      throw error;
    }
  }

  async runManualDirectoryTraversalTest(config: any): Promise<any> {
    try {
      const response = await api.post('/manual-scan/attacks/directory-traversal', config);
      return response.data;
    } catch (error) {
      console.error('Manual directory traversal test failed:', error);
      throw error;
    }
  }

  async runManualCommandInjectionTest(config: any): Promise<any> {
    try {
      const response = await api.post('/manual-scan/attacks/command-injection', config);
      return response.data;
    } catch (error) {
      console.error('Manual command injection test failed:', error);
      throw error;
    }
  }

  // Run Kali Linux tools
  async runKaliNmapScan(target: string, options?: any): Promise<any> {
    try {
      const response = await api.post('/manual-scan/kali-tools/nmap', { target, options });
      return response.data;
    } catch (error) {
      console.error('Kali Nmap scan failed:', error);
      throw error;
    }
  }

  async runKaliNiktoScan(targetUrl: string, options?: any): Promise<any> {
    try {
      const response = await api.post('/manual-scan/kali-tools/nikto', { targetUrl, options });
      return response.data;
    } catch (error) {
      console.error('Kali Nikto scan failed:', error);
      throw error;
    }
  }

  async runKaliSqlmapScan(targetUrl: string, options?: any): Promise<any> {
    try {
      const response = await api.post('/manual-scan/kali-tools/sqlmap', { targetUrl, options });
      return response.data;
    } catch (error) {
      console.error('Kali SQLMap scan failed:', error);
      throw error;
    }
  }

  async runKaliGobusterScan(targetUrl: string, wordlist: string, options?: any): Promise<any> {
    try {
      const response = await api.post('/manual-scan/kali-tools/gobuster', { targetUrl, wordlist, options });
      return response.data;
    } catch (error) {
      console.error('Kali Gobuster scan failed:', error);
      throw error;
    }
  }

  // Fuzzing methods
  async runParameterFuzzing(targetUrl: string, parameters?: string[], wordlists?: string[], options?: any): Promise<any> {
    try {
      const response = await api.post('/manual-scan/fuzzing/params', {
        targetUrl,
        parameters,
        wordlists,
        options
      });
      return response.data;
    } catch (error) {
      console.error('Parameter fuzzing failed:', error);
      throw error;
    }
  }

  async runDirectoryFuzzing(targetUrl: string, wordlists?: string[], options?: any): Promise<any> {
    try {
      const response = await api.post('/manual-scan/fuzzing/directories', {
        targetUrl,
        wordlists,
        options
      });
      return response.data;
    } catch (error) {
      console.error('Directory fuzzing failed:', error);
      throw error;
    }
  }

  // Custom requests and interception
  async sendCustomRequest(request: any): Promise<any> {
    try {
      const response = await api.post('/manual-scan/custom-request', request);
      return response.data;
    } catch (error) {
      console.error('Custom request failed:', error);
      throw error;
    }
  }

  async enableRequestInterception(): Promise<any> {
    try {
      const response = await api.post('/manual-scan/intercept/enable');
      return response.data;
    } catch (error) {
      console.error('Failed to enable request interception:', error);
      throw error;
    }
  }

  async disableRequestInterception(): Promise<any> {
    try {
      const response = await api.post('/manual-scan/intercept/disable');
      return response.data;
    } catch (error) {
      console.error('Failed to disable request interception:', error);
      throw error;
    }
  }

  // Payload and wordlist management
  async getManualScanPayloads(type: string): Promise<string[]> {
    try {
      const response = await api.get(`/manual-scan/payloads/${type}`);
      return response.data || [];
    } catch (error) {
      console.error(`Failed to get payloads for ${type}:`, error);
      return [];
    }
  }

  async getManualScanWordlists(): Promise<string[]> {
    try {
      const response = await api.get('/manual-scan/wordlists');
      return response.data || [];
    } catch (error) {
      console.error('Failed to get wordlists:', error);
      return [];
    }
  }

  // Custom spider configuration
  async runCustomSpider(targetUrl: string, options?: any): Promise<any> {
    try {
      const response = await api.post('/manual-scan/spider/custom', { targetUrl, options });
      return response.data;
    } catch (error) {
      console.error('Custom spider failed:', error);
      throw error;
    }
  }

  // Export manual scan results
  exportManualScanResults(results: any, format: 'json' | 'txt' = 'json'): void {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `manual-scan-results-${timestamp}.${format}`;

    let content: string;
    let mimeType: string;

    if (format === 'json') {
      content = JSON.stringify(results, null, 2);
      mimeType = 'application/json';
    } else {
      content = this.formatManualScanResults(results);
      mimeType = 'text/plain';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = window.URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();

    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  }

  private formatManualScanResults(results: any): string {
    let report = `Manual Security Scan Results\n`;
    report += `===============================\n\n`;
    report += `Generated: ${new Date().toISOString()}\n`;
    report += `Total Results: ${Array.isArray(results) ? results.length : 1}\n\n`;

    if (Array.isArray(results)) {
      results.forEach((result, index) => {
        report += this.formatSingleResult(result, index + 1);
      });
    } else {
      report += this.formatSingleResult(results, 1);
    }

    return report;
  }

  private formatSingleResult(result: any, index: number): string {
    let report = `Result ${index}:\n`;
    report += `----------\n`;
    report += `Target: ${result.metadata?.targetUrl || 'N/A'}\n`;
    report += `Scan Type: ${result.metadata?.scanType || 'N/A'}\n`;
    report += `Duration: ${result.metadata?.duration || 0}ms\n`;
    report += `Requests: ${result.metadata?.requestCount || 0}\n`;
    report += `Vulnerabilities Found: ${result.vulnerabilities?.length || 0}\n\n`;

    if (result.vulnerabilities && result.vulnerabilities.length > 0) {
      report += `Vulnerabilities:\n`;
      result.vulnerabilities.forEach((vuln: any, vIndex: number) => {
        report += `  ${vIndex + 1}. ${vuln.type} [${vuln.severity}]\n`;
        if (vuln.parameter) report += `     Parameter: ${vuln.parameter}\n`;
        if (vuln.payload) report += `     Payload: ${vuln.payload}\n`;
        if (vuln.evidence) report += `     Evidence: ${vuln.evidence.substring(0, 100)}...\n`;
        report += `     Time: ${vuln.timestamp}\n\n`;
      });
    }

    if (result.rawOutput) {
      report += `Raw Output:\n${result.rawOutput}\n\n`;
    }

    report += `\n`;
    return report;
  }
}

export default new ScanService();