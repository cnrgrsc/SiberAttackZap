import api from './api';

export interface ManualScanConfig {
  targetUrl: string;
  parameters?: string[];
  payloads?: string[];
  options?: {
    timeout?: number;
    delay?: number;
    threads?: number;
    verbose?: boolean;
  };
}

export interface AttackResult {
  success: boolean;
  vulnerabilities: Vulnerability[];
  requests: Request[];
  responses: Response[];
  metadata: {
    startTime: string;
    endTime: string;
    duration: number;
    requestCount: number;
    targetUrl: string;
    scanType: string;
  };
  rawOutput?: string;
}

export interface Vulnerability {
  type: string;
  parameter?: string;
  payload?: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  url?: string;
  evidence?: string;
  timestamp: string;
  indicator?: string;
}

export interface Request {
  url: string;
  method?: string;
  parameter?: string;
  payload?: string;
  data?: any;
  timestamp: string;
}

export interface Response {
  status: number;
  statusText: string;
  headers: Record<string, any>;
  body: any;
  timestamp: string;
}

export interface CustomRequest {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';
  url: string;
  headers?: Record<string, string>;
  body?: any;
  options?: {
    timeout?: number;
    followRedirects?: boolean;
    validateSSL?: boolean;
  };
}

export interface KaliToolOptions {
  scanType?: string;
  ports?: string;
  timing?: number;
  useSSL?: boolean;
  port?: number;
  format?: string;
  level?: number;
  risk?: number;
  dbms?: string;
  techniques?: string;
  extensions?: string;
  threads?: number;
  timeout?: string;
}

class ManualScanService {
  
  // =============================================================================
  // AVAILABLE TOOLS
  // =============================================================================

  async getAvailableTools(): Promise<any> {
    try {
      const response = await api.get('/manual-scan/tools');
      return response.data;
    } catch (error) {
      console.error('Failed to get available tools:', error);
      throw error;
    }
  }

  // =============================================================================
  // ZAP-BASED ATTACKS
  // =============================================================================

  async runSqlInjectionTest(config: ManualScanConfig): Promise<AttackResult> {
    try {
      const response = await api.post('/manual-scan/attacks/sql-injection', config);
      return response.data;
    } catch (error) {
      console.error('SQL injection test failed:', error);
      throw error;
    }
  }

  async runXssTest(config: ManualScanConfig): Promise<AttackResult> {
    try {
      const response = await api.post('/manual-scan/attacks/xss', config);
      return response.data;
    } catch (error) {
      console.error('XSS test failed:', error);
      throw error;
    }
  }

  async runDirectoryTraversalTest(config: ManualScanConfig): Promise<AttackResult> {
    try {
      const response = await api.post('/manual-scan/attacks/directory-traversal', config);
      return response.data;
    } catch (error) {
      console.error('Directory traversal test failed:', error);
      throw error;
    }
  }

  async runCommandInjectionTest(config: ManualScanConfig): Promise<AttackResult> {
    try {
      const response = await api.post('/manual-scan/attacks/command-injection', config);
      return response.data;
    } catch (error) {
      console.error('Command injection test failed:', error);
      throw error;
    }
  }

  async runCsrfTest(targetUrl: string, options?: any): Promise<AttackResult> {
    try {
      const response = await api.post('/manual-scan/attacks/csrf', { targetUrl, options });
      return response.data;
    } catch (error) {
      console.error('CSRF test failed:', error);
      throw error;
    }
  }

  async runXxeTest(targetUrl: string, xmlPayloads?: string[], options?: any): Promise<AttackResult> {
    try {
      const response = await api.post('/manual-scan/attacks/xxe', { 
        targetUrl, 
        xmlPayloads, 
        options 
      });
      return response.data;
    } catch (error) {
      console.error('XXE test failed:', error);
      throw error;
    }
  }

  // =============================================================================
  // FUZZING ATTACKS
  // =============================================================================

  async runParameterFuzzing(targetUrl: string, parameters?: string[], wordlists?: string[], options?: any): Promise<AttackResult> {
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

  async runDirectoryFuzzing(targetUrl: string, wordlists?: string[], options?: any): Promise<AttackResult> {
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

  // =============================================================================
  // KALI LINUX TOOLS
  // =============================================================================

  async runNmapScan(target: string, options?: KaliToolOptions): Promise<AttackResult> {
    try {
      const response = await api.post('/manual-scan/kali-tools/nmap', {
        target,
        options
      });
      return response.data;
    } catch (error) {
      console.error('Nmap scan failed:', error);
      throw error;
    }
  }

  async runNiktoScan(targetUrl: string, options?: KaliToolOptions): Promise<AttackResult> {
    try {
      const response = await api.post('/manual-scan/kali-tools/nikto', {
        targetUrl,
        options
      });
      return response.data;
    } catch (error) {
      console.error('Nikto scan failed:', error);
      throw error;
    }
  }

  async runSqlmapScan(targetUrl: string, options?: KaliToolOptions): Promise<AttackResult> {
    try {
      const response = await api.post('/manual-scan/kali-tools/sqlmap', {
        targetUrl,
        options
      });
      return response.data;
    } catch (error) {
      console.error('SQLMap scan failed:', error);
      throw error;
    }
  }

  async runGobusterScan(targetUrl: string, wordlist: string, options?: KaliToolOptions): Promise<AttackResult> {
    try {
      const response = await api.post('/manual-scan/kali-tools/gobuster', {
        targetUrl,
        wordlist,
        options
      });
      return response.data;
    } catch (error) {
      console.error('Gobuster scan failed:', error);
      throw error;
    }
  }

  async runWpscanScan(targetUrl: string, options?: KaliToolOptions): Promise<AttackResult> {
    try {
      const response = await api.post('/manual-scan/kali-tools/wpscan', {
        targetUrl,
        options
      });
      return response.data;
    } catch (error) {
      console.error('WPScan failed:', error);
      // Return a mock response if the endpoint doesn't exist yet
      return {
        success: false,
        vulnerabilities: [],
        requests: [],
        responses: [],
        metadata: {
          startTime: new Date().toISOString(),
          endTime: new Date().toISOString(),
          duration: 0,
          requestCount: 0,
          targetUrl,
          scanType: 'wpscan'
        },
        rawOutput: 'WPScan service not implemented yet'
      };
    }
  }

  async runNucleiScan(targetUrl: string, options?: KaliToolOptions): Promise<AttackResult> {
    try {
      const response = await api.post('/manual-scan/kali-tools/nuclei', {
        targetUrl,
        options
      });
      return response.data;
    } catch (error) {
      console.error('Nuclei scan failed:', error);
      // Return a mock response if the endpoint doesn't exist yet
      return {
        success: false,
        vulnerabilities: [],
        requests: [],
        responses: [],
        metadata: {
          startTime: new Date().toISOString(),
          endTime: new Date().toISOString(),
          duration: 0,
          requestCount: 0,
          targetUrl,
          scanType: 'nuclei'
        },
        rawOutput: 'Nuclei service not implemented yet'
      };
    }
  }

  // =============================================================================
  // CUSTOM REQUESTS
  // =============================================================================

  async sendCustomRequest(request: CustomRequest): Promise<any> {
    try {
      const response = await api.post('/manual-scan/custom-request', request);
      return response.data;
    } catch (error) {
      console.error('Custom request failed:', error);
      throw error;
    }
  }

  async runCustomSpider(targetUrl: string, options?: any): Promise<any> {
    try {
      const response = await api.post('/manual-scan/spider/custom', {
        targetUrl,
        options
      });
      return response.data;
    } catch (error) {
      console.error('Custom spider failed:', error);
      throw error;
    }
  }

  // =============================================================================
  // INTERCEPTION
  // =============================================================================

  async enableInterception(): Promise<any> {
    try {
      const response = await api.post('/manual-scan/intercept/enable');
      return response.data;
    } catch (error) {
      console.error('Failed to enable interception:', error);
      throw error;
    }
  }

  async disableInterception(): Promise<any> {
    try {
      const response = await api.post('/manual-scan/intercept/disable');
      return response.data;
    } catch (error) {
      console.error('Failed to disable interception:', error);
      throw error;
    }
  }

  // =============================================================================
  // PAYLOAD AND WORDLIST MANAGEMENT
  // =============================================================================

  async getPayloads(type: string): Promise<string[]> {
    try {
      const response = await api.get(`/manual-scan/payloads/${type}`);
      return response.data || [];
    } catch (error) {
      console.error(`Failed to get payloads for ${type}:`, error);
      return [];
    }
  }

  async getWordlists(): Promise<string[]> {
    try {
      const response = await api.get('/manual-scan/wordlists');
      return response.data || [];
    } catch (error) {
      console.error('Failed to get wordlists:', error);
      return [];
    }
  }

  // =============================================================================
  // UTILITY METHODS
  // =============================================================================

  // Validate URL format
  isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  // Generate random test payloads
  generateRandomPayloads(type: string, count: number = 10): string[] {
    const payloadTemplates: Record<string, string[]> = {
      'sql-injection': [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "admin'--",
        "' OR 1=1--"
      ],
      'xss': [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>"
      ],
      'directory-traversal': [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "../../../../etc/passwd"
      ],
      'command-injection': [
        "; ls -la",
        "| whoami",
        "&& dir",
        "; cat /etc/passwd"
      ]
    };

    const templates = payloadTemplates[type] || [];
    const payloads: string[] = [];

    for (let i = 0; i < count && i < templates.length; i++) {
      payloads.push(templates[i]);
    }

    return payloads;
  }

  // Extract parameters from URL
  extractParametersFromUrl(url: string): string[] {
    try {
      const urlObj = new URL(url);
      return Array.from(urlObj.searchParams.keys());
    } catch {
      return [];
    }
  }

  // Format attack results for display
  formatAttackResults(result: AttackResult): string {
    let report = `Manual Security Test Report\n`;
    report += `==============================\n\n`;
    report += `Target: ${result.metadata.targetUrl}\n`;
    report += `Scan Type: ${result.metadata.scanType}\n`;
    report += `Duration: ${result.metadata.duration}ms\n`;
    report += `Total Requests: ${result.metadata.requestCount}\n\n`;

    if (result.vulnerabilities.length > 0) {
      report += `Vulnerabilities Found (${result.vulnerabilities.length}):\n`;
      report += `----------------------------------------\n`;
      
      result.vulnerabilities.forEach((vuln, index) => {
        report += `${index + 1}. ${vuln.type} [${vuln.severity}]\n`;
        if (vuln.parameter) report += `   Parameter: ${vuln.parameter}\n`;
        if (vuln.payload) report += `   Payload: ${vuln.payload}\n`;
        if (vuln.evidence) report += `   Evidence: ${vuln.evidence.substring(0, 100)}...\n`;
        report += `   Time: ${vuln.timestamp}\n\n`;
      });
    } else {
      report += `No vulnerabilities detected.\n\n`;
    }

    if (result.rawOutput) {
      report += `Raw Tool Output:\n`;
      report += `================\n`;
      report += result.rawOutput;
    }

    return report;
  }

  // Export results to file
  exportResults(result: AttackResult, format: 'json' | 'txt' = 'json'): void {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `manual-scan-${result.metadata.scanType}-${timestamp}.${format}`;

    let content: string;
    let mimeType: string;

    if (format === 'json') {
      content = JSON.stringify(result, null, 2);
      mimeType = 'application/json';
    } else {
      content = this.formatAttackResults(result);
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

  // Get vulnerability severity color
  getSeverityColor(severity: string): string {
    switch (severity.toUpperCase()) {
      case 'HIGH':
        return '#d32f2f';
      case 'MEDIUM':
        return '#f57c00';
      case 'LOW':
        return '#fbc02d';
      case 'INFO':
        return '#1976d2';
      default:
        return '#757575';
    }
  }

  // Get vulnerability severity icon
  getSeverityIcon(severity: string): string {
    switch (severity.toUpperCase()) {
      case 'HIGH':
        return '🔴';
      case 'MEDIUM':
        return '🟠';
      case 'LOW':
        return '🟡';
      case 'INFO':
        return '🔵';
      default:
        return '⚪';
    }
  }

  // Validate attack configuration
  validateConfig(config: ManualScanConfig): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!config.targetUrl) {
      errors.push('Target URL is required');
    } else if (!this.isValidUrl(config.targetUrl)) {
      errors.push('Invalid URL format');
    }

    if (config.options?.timeout && config.options.timeout < 1000) {
      errors.push('Timeout must be at least 1000ms');
    }

    if (config.options?.delay && config.options.delay < 0) {
      errors.push('Delay cannot be negative');
    }

    if (config.options?.threads && config.options.threads < 1) {
      errors.push('Threads must be at least 1');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

export default new ManualScanService();
