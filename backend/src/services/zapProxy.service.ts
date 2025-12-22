import axios, { AxiosInstance } from 'axios';
import { ZapSpiderResponse, ZapActiveScanResponse, ZapAlert } from '../types/api.types';
import { PrismaClient } from '@prisma/client';
import { ZapAdvancedService } from './zapAdvancedService';
import { ApiSecurityDeepDiveService } from './ApiSecurityDeepDiveService';
import { emailService } from './email.service';

export interface ScanWorkflowOptions {
  targetUrl: string;
  enableSpider?: boolean;
  enableAjaxSpider?: boolean;
  enableActiveScan?: boolean;

  // 🔥 NEW: Environment & Security Settings
  environment?: 'TEST' | 'PRODUCTION' | 'CUSTOM';
  aggressiveness?: 'LOW' | 'MEDIUM' | 'HIGH' | 'INSANE';
  safeMode?: boolean; // true = read-only tests only

  spiderOptions?: {
    maxChildren?: number;
    maxDepth?: number;
    maxDuration?: number;
  };
  ajaxSpiderOptions?: {
    enabled?: boolean;
    browser?: string;
    maxCrawlDepth?: number;
    maxDuration?: number;
  };
  activeScanOptions?: {
    enabled?: boolean;
    scanPolicyName?: string;
    maxDuration?: number;
    recurse?: boolean;
    intensity?: 'low' | 'medium' | 'high';
  };

  // ⏱️ Top-level timeout properties for easy access
  spiderMaxDuration?: number;
  ajaxSpiderMaxDuration?: number;
  activeScanMaxDuration?: number;
  forcedBrowseTimeout?: number;

  // 🔥 NEW: Advanced Attack Tests
  advancedTests?: {
    enableSqlInjection?: boolean;
    enableXss?: boolean;
    enableXxe?: boolean;
    enableCommandInjection?: boolean;
    enablePathTraversal?: boolean;
    enableWafBypass?: boolean;
    enableBruteForce?: boolean;
  };

  // 🎯 API Deep Dive Configuration
  apiDeepDive?: {
    enabled?: boolean;
    intensity?: 'standard' | 'comprehensive' | 'full';
  };

  // 📊 Report Settings
  reportFormat?: 'HTML' | 'XML' | 'JSON' | 'MD';
  generateReport?: boolean;
  reportTitle?: string;

  contextName?: string;
  authConfig?: {
    type: 'form' | 'http' | 'script';
    loginUrl?: string;
    username?: string;
    password?: string;
    usernameParam?: string;
    passwordParam?: string;
  };
}

export interface WorkflowProgress {
  phase: 'setup' | 'spider' | 'ajax-spider' | 'active-scan' | 'advanced-analysis' | 'js-security' | 'api-deep-dive' | 'completed' | 'error';
  overall: number;
  spider?: {
    status: string;
    progress: number;
    urlsFound: number;
  };
  ajaxSpider?: {
    status: string;
    results: number;
  };
  activeScan?: {
    status: string;
    progress: number;
    alertsFound: number;
  };
  advancedAnalysis?: {
    status: string;
    dataPoints: number;
  };
  jsSecurity?: {
    status: string;
    librariesFound: number;
    vulnerabilities: number;
  };
  apiDeepDive?: {
    status: string;
    endpointsAnalyzed: number;
    securityScore: number;
  };
  contextId?: string;
  errors?: string[];
}

export interface TechnologyResult {
  name: string;
  type: string;
  confidence: string;
  version?: string;
  details?: any;
}

export interface BaselineResult {
  totalIssues: number;
  highRiskIssues: number;
  mediumRiskIssues: number;
  lowRiskIssues: number;
  alerts: ZapAlert[];
  timestamp: string;
}

export class ZapProxyService {
  private zapClient: AxiosInstance;
  private baseUrl: string;
  private runningWorkflows: Map<string, WorkflowProgress> = new Map();
  private workflowStates: Map<string, any> = new Map();
  private workflowProgress: Map<string, any> = new Map(); // Add missing workflowProgress map
  private stoppedWorkflows: Set<string> = new Set(); // Track stopped workflows
  private pausedWorkflows: Set<string> = new Set(); // Track paused workflows
  private timeoutCompletedWorkflows: Set<string> = new Set(); // Track workflows completed via timeout
  private io: any; // Socket.IO instance
  private prisma: PrismaClient;
  private realTimeMonitors: Map<string, NodeJS.Timeout> = new Map(); // For real-time monitoring
  private zapAdvancedService: ZapAdvancedService; // Advanced ZAP service
  private apiSecurityService: ApiSecurityDeepDiveService; // API security service

  constructor(io?: any) {
    this.baseUrl = process.env.ZAP_PROXY_URL || 'http://zap-api:8080';
    this.io = io;
    this.prisma = new PrismaClient();

    // Create ZAP client with optional API key
    const headers: any = {
      'Content-Type': 'application/json'
    };

    // Add API key if provided in environment
    if (process.env.ZAP_API_KEY) {
      headers['X-ZAP-API-Key'] = process.env.ZAP_API_KEY;
    }

    this.zapClient = axios.create({
      baseURL: this.baseUrl,
      timeout: 300000, // 5 minutes timeout for large scans
      headers
    });

    // Initialize advanced services
    this.zapAdvancedService = new ZapAdvancedService(io);
    this.apiSecurityService = new ApiSecurityDeepDiveService(io);
  }

  // =============================================================================
  // CORE ZAP METHODS
  // =============================================================================

  // Check ZAP connection
  async checkConnection(): Promise<boolean> {
    try {
      const response = await this.zapClient.get('/JSON/core/view/version/');
      return response.status === 200;
    } catch (error) {
      return false;
    }
  }

  // Get ZAP version and status
  async getStatus() {
    try {
      const [version, alerts] = await Promise.all([
        this.zapClient.get('/JSON/core/view/version/'),
        this.zapClient.get('/JSON/core/view/numberOfAlerts/')
      ]);

      let spiderStatus = 'N/A';
      let activeScanStatus = 'N/A';

      try {
        const spider = await this.zapClient.get('/JSON/spider/view/status/');
        spiderStatus = spider.data.status;
      } catch (e) {
        // Spider might not be available
      }

      try {
        const activeScan = await this.zapClient.get('/JSON/ascan/view/status/');
        activeScanStatus = activeScan.data.status;
      } catch (e) {
        // Active scan might not be available
      }

      return {
        version: version.data.version,
        alerts: alerts.data.numberOfAlerts,
        spider: spiderStatus,
        activeScan: activeScanStatus,
        connected: true
      };
    } catch (error) {
      throw new Error(`Failed to get ZAP status: ${error}`);
    }
  }

  // Access URL to trigger passive scanning
  async accessUrl(url: string): Promise<void> {
    try {
      await this.zapClient.get('/JSON/core/action/accessUrl/', {
        params: { url }
      });
    } catch (error) {
      throw new Error(`Failed to access URL: ${error}`);
    }
  }

  // Get sites discovered by ZAP
  async getSites(): Promise<string[]> {
    try {
      const response = await this.zapClient.get('/JSON/core/view/sites/');
      return response.data.sites || [];
    } catch (error) {
      throw new Error(`Failed to get sites: ${error}`);
    }
  }

  // Get URLs discovered by ZAP
  async getUrls(baseUrl?: string): Promise<string[]> {
    try {
      const params = baseUrl ? { baseurl: baseUrl } : {};
      const response = await this.zapClient.get('/JSON/core/view/urls/', { params });
      return response.data.urls || [];
    } catch (error) {
      throw new Error(`Failed to get URLs: ${error}`);
    }
  }

  // Clear ZAP session
  async clearSession(): Promise<void> {
    try {
      await this.zapClient.get('/JSON/core/action/newSession/');
    } catch (error) {
      throw new Error(`Failed to clear session: ${error}`);
    }
  }

  // Save current session to file for GUI synchronization
  async saveSessionToFile(sessionName: string = 'automated_scan_session'): Promise<string> {
    try {
      const sessionPath = `./temp/${sessionName}.session`;
      await this.zapClient.get('/JSON/core/action/saveSession/', {
        params: { name: sessionPath }
      });
      return sessionPath;
    } catch (error) {
      console.error('Failed to save session:', error);
      throw new Error(`Failed to save session: ${error}`);
    }
  }

  // Load session from file (useful for accessing GUI session data)
  async loadSessionFromFile(sessionPath: string): Promise<void> {
    try {
      await this.zapClient.get('/JSON/core/action/loadSession/', {
        params: { name: sessionPath }
      });
    } catch (error) {
      console.error('Failed to load session:', error);
      throw new Error(`Failed to load session: ${error}`);
    }
  }

  // Force refresh ZAP data by accessing sites tree
  async refreshZapData(): Promise<{ sites: any[], alerts: ZapAlert[], urls: string[] }> {
    try {

      // Get all sites in the current session
      const sitesResponse = await this.zapClient.get('/JSON/core/view/sites/');
      const sites = sitesResponse.data.sites || [];

      // If no sites, try to get data from history
      let urls: string[] = [];
      let alerts: ZapAlert[] = [];

      if (sites.length === 0) {

        // Try to get URLs from history
        try {
          const historyResponse = await this.zapClient.get('/JSON/core/view/messages/');
          const messages = historyResponse.data.messages || [];
          urls = messages.map((msg: any) => msg.requestHeader?.split(' ')[1] || '').filter(Boolean);
        } catch (historyError) {
        }
      } else {
        // Get URLs for each site
        for (const site of sites) {
          try {
            const urlsResponse = await this.zapClient.get('/JSON/core/view/urls/', {
              params: { baseurl: site }
            });
            urls.push(...(urlsResponse.data.urls || []));
          } catch (urlError) {
          }
        }
      }

      // Get all alerts
      try {
        alerts = await this.getAlerts();
      } catch (alertError) {
      }

      return { sites, alerts, urls };
    } catch (error) {
      console.error('Failed to refresh ZAP data:', error);
      throw new Error(`Failed to refresh ZAP data: ${error}`);
    }
  }

  // Check if GUI session has data that API can't see
  async detectGuiSessionData(): Promise<{ hasData: boolean, recommendation: string }> {
    try {
      // Try different approaches to detect data
      const checks = await Promise.allSettled([
        this.zapClient.get('/JSON/core/view/sites/'),
        this.zapClient.get('/JSON/core/view/numberOfAlerts/'),
        this.zapClient.get('/JSON/core/view/messages/', { params: { start: 0, count: 1 } }),
        this.zapClient.get('/JSON/spider/view/status/'),
        this.zapClient.get('/JSON/core/view/hosts/'),
        this.zapClient.get('/JSON/core/view/sessionLocation/')
      ]);

      const sites = checks[0].status === 'fulfilled' ? checks[0].value.data.sites || [] : [];
      const alertCount = checks[1].status === 'fulfilled' ? parseInt(checks[1].value.data.numberOfAlerts || '0') : 0;
      const hasHistory = checks[2].status === 'fulfilled' ? (checks[2].value.data.messages || []).length > 0 : false;
      const hosts = checks[4].status === 'fulfilled' ? checks[4].value.data.hosts || [] : [];
      const sessionLocation = checks[5].status === 'fulfilled' ? checks[5].value.data.sessionLocation || '' : '';

      console.log(`📂 Session location: ${sessionLocation}`);

      if (sites.length === 0 && alertCount === 0 && !hasHistory && hosts.length === 0) {
        return {
          hasData: false,
          recommendation: `No data found in current API session. 
          
          If ZAP GUI shows data:
          1. In ZAP GUI, go to File → Persist Session → Save Session As...
          2. Save as 'gui_session.session'
          3. Use the 'Import GUI Session' feature in the frontend
          4. Or restart ZAP and perform the scan through the automated interface
          
          Session location: ${sessionLocation || 'In-memory session'}`
        };
      }

      return {
        hasData: true,
        recommendation: `Found ${sites.length} sites and ${alertCount} alerts in current session.`
      };
    } catch (error) {
      return {
        hasData: false,
        recommendation: `Could not check session data: ${error}`
      };
    }
  }

  // Try to import GUI session data by forcing ZAP to refresh its internal state
  async forceRefreshGuiData(): Promise<{ sites: any[], alerts: ZapAlert[], urls: string[] }> {
    try {

      // Step 1: Try to trigger a data refresh by accessing different endpoints
      const refreshEndpoints = [
        '/JSON/core/view/sites/',
        '/JSON/core/view/hosts/',
        '/JSON/core/view/messages/',
        '/JSON/core/view/numberOfAlerts/',
        '/JSON/core/view/urls/',
        '/JSON/spider/view/status/',
        '/JSON/ascan/view/status/',
        '/JSON/core/view/alerts/'
      ];

      const refreshResults: any = {};

      for (const endpoint of refreshEndpoints) {
        try {
          const response = await this.zapClient.get(endpoint);
          refreshResults[endpoint] = response.data;
          console.log(`✅ Refreshed ${endpoint}:`, Object.keys(response.data));
        } catch (endpointError) {
          refreshResults[endpoint] = null;
        }
      }

      // Step 3: Collect all available data
      const sites = refreshResults['/JSON/core/view/sites/']?.sites || [];
      const hosts = refreshResults['/JSON/core/view/hosts/']?.hosts || [];
      const messages = refreshResults['/JSON/core/view/messages/']?.messages || [];
      const urls = refreshResults['/JSON/core/view/urls/']?.urls || [];
      const alerts = refreshResults['/JSON/core/view/alerts/']?.alerts || [];


      // Format alerts properly
      const formattedAlerts: ZapAlert[] = alerts.map((alert: any) => ({
        alertId: alert.id || alert.alertId || '',
        name: alert.alert || alert.name || 'Unknown Alert',
        description: alert.description || '',
        risk: alert.risk || 'LOW',
        severity: this.mapSeverity(alert.risk || 'LOW'),
        confidence: alert.confidence || 'Medium',
        url: alert.url || '',
        param: alert.param || '',
        attack: alert.attack || '',
        evidence: alert.evidence || '',
        solution: alert.solution || '',
        reference: alert.reference || '',
        cweId: alert.cweid || alert.cweId || 0,
        wascId: alert.wascid || alert.wascId || 0
      }));

      // Extract URLs from messages if direct URLs are empty
      let allUrls = [...urls];
      if (allUrls.length === 0 && messages.length > 0) {
        allUrls = messages
          .map((msg: any) => {
            try {
              const requestHeader = msg.requestHeader || '';
              const urlMatch = requestHeader.match(/^[A-Z]+ (.*?) HTTP/);
              return urlMatch ? urlMatch[1] : null;
            } catch (e) {
              return null;
            }
          })
          .filter(Boolean);
      }

      return {
        sites: [...sites, ...hosts],
        alerts: formattedAlerts,
        urls: allUrls
      };

    } catch (error) {
      console.error('Failed to force refresh GUI data:', error);
      throw new Error(`Failed to force refresh GUI data: ${error}`);
    }
  }

  // =============================================================================
  // SPIDER SCANNING METHODS
  // =============================================================================

  // Start spider scan
  async startSpider(targetUrl: string, options?: {
    maxChildren?: number;
    maxDepth?: number;
    maxDuration?: number;
  }): Promise<string> {
    try {
      const params: any = { url: targetUrl };
      if (options?.maxChildren) params.maxChildren = options.maxChildren;
      if (options?.maxDepth) params.maxDepth = options.maxDepth;
      if (options?.maxDuration) params.maxDuration = options.maxDuration;

      console.log(`🕷️ Starting spider with params:`, params);

      const response = await this.zapClient.get('/JSON/spider/action/scan/', { params });
      return response.data.scan || '0';
    } catch (error) {
      throw new Error(`Failed to start spider: ${error}`);
    }
  }

  // Get spider status
  async getSpiderStatus(scanId?: string): Promise<ZapSpiderResponse> {
    try {
      if (!scanId) {
        const scansResponse = await this.zapClient.get('/JSON/spider/view/scans/');
        const scans = scansResponse.data.scans || [];

        if (scans.length === 0) {
          return {
            scanId: 'none',
            status: 'finished',
            progress: 100,
            urls: []
          };
        }

        scanId = scans[scans.length - 1].toString();
      }

      try {
        const status = await this.zapClient.get('/JSON/spider/view/status/', {
          params: { scanId }
        });

        const spiderStatus = status.data.status;
        const progress = parseInt(spiderStatus) || 0;

        let urls: string[] = [];
        try {
          const sitesResponse = await this.zapClient.get('/JSON/core/view/sites/');
          urls = sitesResponse.data.sites || [];
        } catch (e) {
          urls = [];
        }

        return {
          scanId: scanId || 'none',
          status: progress >= 100 ? 'finished' : 'running',
          progress,
          urls
        };
      } catch (statusError) {
        return {
          scanId: scanId || 'unknown',
          status: 'finished',
          progress: 100,
          urls: []
        };
      }
    } catch (error) {
      throw new Error(`Failed to get spider status: ${error}`);
    }
  }

  // Get spider results
  async getSpiderResults(scanId?: string): Promise<string[]> {
    try {
      const response = await this.zapClient.get('/JSON/spider/view/results/', {
        params: scanId ? { scanId } : {}
      });

      if (response.data && response.data.results) {
        return response.data.results;
      }

      // Fallback to getting sites
      try {
        const sitesResponse = await this.zapClient.get('/JSON/core/view/sites/');
        return sitesResponse.data.sites || [];
      } catch (e) {
        return [];
      }
    } catch (error) {
      console.error('Failed to get spider results:', error);
      return [];
    }
  }


  // =============================================================================
  // AJAX SPIDER METHODS
  // =============================================================================

  // Start AJAX spider
  async startAjaxSpider(targetUrl: string, options?: {
    inScope?: boolean;
    contextName?: string;
    subtreeOnly?: boolean;
    maxDuration?: number;
    maxCrawlDepth?: number;
  }): Promise<void> {
    try {
      const params: any = { url: targetUrl };
      if (options?.inScope !== undefined) params.inScope = options.inScope;
      if (options?.contextName) params.contextName = options.contextName;
      if (options?.subtreeOnly !== undefined) params.subtreeOnly = options.subtreeOnly;
      if (options?.maxDuration) params.maxDuration = options.maxDuration;
      if (options?.maxCrawlDepth) params.maxCrawlDepth = options.maxCrawlDepth;

      console.log(`🌐 Starting AJAX spider with params:`, params);

      await this.zapClient.get('/JSON/ajaxSpider/action/scan/', { params });
    } catch (error) {
      throw new Error(`Failed to start AJAX spider: ${error}`);
    }
  }

  // Get AJAX spider status
  async getAjaxSpiderStatus(): Promise<any> {
    try {
      const response = await this.zapClient.get('/JSON/ajaxSpider/view/status/');
      return {
        status: response.data.status,
        messagesInQueue: response.data.messagesInQueue || 0,
        numberOfResults: response.data.numberOfResults || 0
      };
    } catch (error) {
      throw new Error(`Failed to get AJAX spider status: ${error}`);
    }
  }

  // Get AJAX spider results
  async getAjaxSpiderResults(): Promise<string[]> {
    try {
      const response = await this.zapClient.get('/JSON/ajaxSpider/view/results/');
      return response.data.results || [];
    } catch (error) {
      return [];
    }
  }


  // =============================================================================
  // ACTIVE SCANNING METHODS
  // =============================================================================

  // Start active scan
  async startActiveScan(targetUrl: string, options?: {
    recurse?: boolean;
    inScopeOnly?: boolean;
    scanPolicyName?: string;
    method?: string;
    postData?: string;
    maxScanDurationInMins?: number;
    maxAlertsPerRule?: number;
    threadPerHost?: number;
  }): Promise<string> {
    try {
      // Ensure URL is properly encoded
      const encodedUrl = encodeURI(targetUrl);

      const params: any = { url: encodedUrl };

      // Set default values for critical parameters
      if (options?.recurse !== undefined) {
        params.recurse = String(options.recurse);
      } else {
        params.recurse = 'true'; // Default to recursive scanning
      }

      if (options?.inScopeOnly !== undefined) {
        params.inScopeOnly = String(options.inScopeOnly);
      }

      if (options?.scanPolicyName) params.scanPolicyName = options.scanPolicyName;
      if (options?.method) params.method = options.method;
      if (options?.postData) params.postData = options.postData;
      if (options?.maxScanDurationInMins) params.maxScanDurationInMins = options.maxScanDurationInMins;
      if (options?.maxAlertsPerRule) params.maxAlertsPerRule = options.maxAlertsPerRule;
      if (options?.threadPerHost) params.threadPerHost = options.threadPerHost;

      console.log(`🔍 Starting active scan with params:`, params);

      const response = await this.zapClient.get('/JSON/ascan/action/scan/', { params });

      if (!response.data || !response.data.scan) {
        throw new Error('Invalid response from ZAP: missing scan ID');
      }

      console.log(`✅ Active scan started with ID: ${response.data.scan}`);
      return response.data.scan;
    } catch (error: any) {
      console.error('❌ Failed to start active scan:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });
      throw new Error(`Failed to start active scan: ${error.message || error}`);
    }
  }

  // Get active scan status
  async getActiveScanStatus(scanId?: string): Promise<ZapActiveScanResponse> {
    try {
      const params = scanId ? { scanId } : {};
      const [status, progress, alerts] = await Promise.all([
        this.zapClient.get('/JSON/ascan/view/status/', { params }),
        this.zapClient.get('/JSON/ascan/view/progress/', { params }),
        this.getAlerts()
      ]);

      return {
        scanId: scanId || 'default',
        status: status.data.status === '100' ? 'finished' : 'running',
        progress: parseInt(progress.data.progress),
        alerts
      };
    } catch (error) {
      throw new Error(`Failed to get active scan status: ${error}`);
    }
  }



  // =============================================================================
  // SPECIALIZED SCANNING METHODS
  // =============================================================================

  // Technology Detection
  async startTechnologyScan(targetUrl: string): Promise<{ technologies: TechnologyResult[] }> {
    try {

      // First access the URL to trigger passive scanning
      await this.accessUrl(targetUrl);

      // Wait for passive scan to analyze the page
      await new Promise(resolve => setTimeout(resolve, 5000));

      // Try multiple methods for technology detection
      let technologies: TechnologyResult[] = [];

      // Method 1: Try ZAP's technology detection addon
      try {
        const techResponse = await this.zapClient.get('/JSON/technology/view/getTechnology/', {
          params: { site: targetUrl }
        });

        if (techResponse.data.technology && techResponse.data.technology.length > 0) {
          technologies = techResponse.data.technology;
        }
      } catch (techError) {
      }

      // Method 2: Enhanced fallback - Extract from alerts and headers
      if (technologies.length === 0) {
        const alerts = await this.getAlerts(targetUrl);
        technologies = this.extractTechnologiesFromAlerts(alerts);

        // Also try to get technologies from HTTP headers
        const headerTechnologies = await this.extractTechnologiesFromHeaders(targetUrl);
        technologies = [...technologies, ...headerTechnologies];

      }

      // Remove duplicates and enhance with confidence scores
      const uniqueTechnologies = this.deduplicateAndEnhanceTechnologies(technologies);

      console.log(`✅ Final technology detection result:`, JSON.stringify({ technologies: uniqueTechnologies }, null, 2));
      return { technologies: uniqueTechnologies };
    } catch (error) {
      console.error('❌ Technology detection failed:', error);
      throw new Error(`Failed to perform technology detection: ${error}`);
    }
  }

  // Extract technology information from ZAP alerts
  private extractTechnologiesFromAlerts(alerts: ZapAlert[]): TechnologyResult[] {
    const technologies: TechnologyResult[] = [];
    const techMap = new Map<string, TechnologyResult>();

    alerts.forEach(alert => {
      const desc = alert.description.toLowerCase();
      const name = alert.name.toLowerCase();
      const evidence = alert.evidence?.toLowerCase() || '';
      const url = alert.url?.toLowerCase() || '';

      // Web Servers
      if (desc.includes('apache') || name.includes('apache') || evidence.includes('apache')) {
        techMap.set('Apache', { name: 'Apache HTTP Server', type: 'Web Server', confidence: 'High' });
      }
      if (desc.includes('nginx') || name.includes('nginx') || evidence.includes('nginx')) {
        techMap.set('Nginx', { name: 'Nginx', type: 'Web Server', confidence: 'High' });
      }
      if (desc.includes('iis') || name.includes('iis') || evidence.includes('iis')) {
        techMap.set('IIS', { name: 'Microsoft IIS', type: 'Web Server', confidence: 'High' });
      }

      // Programming Languages & Frameworks
      if (desc.includes('java') || name.includes('java') || evidence.includes('jsessionid') || evidence.includes('.jsp')) {
        techMap.set('Java', { name: 'Java', type: 'Programming Language', confidence: 'Medium' });
      }
      if (desc.includes('php') || name.includes('php') || evidence.includes('.php') || evidence.includes('phpsessid')) {
        techMap.set('PHP', { name: 'PHP', type: 'Programming Language', confidence: 'Medium' });
      }
      if (desc.includes('asp.net') || name.includes('asp.net') || evidence.includes('asp.net') || evidence.includes('.aspx')) {
        techMap.set('ASP.NET', { name: 'ASP.NET', type: 'Web Framework', confidence: 'Medium' });
      }

      // Session Management
      if (desc.includes('session') || evidence.includes('session') || evidence.includes('cookie')) {
        techMap.set('HTTP Sessions', { name: 'HTTP Sessions', type: 'Session Management', confidence: 'Medium' });
      }
    });

    return Array.from(techMap.values());
  }

  // Extract technologies from HTTP headers
  private async extractTechnologiesFromHeaders(targetUrl: string): Promise<TechnologyResult[]> {
    const technologies: TechnologyResult[] = [];

    try {
      // Get sites from ZAP to analyze headers
      const sites = await this.getSites();
      const targetSite = sites.find(site => targetUrl.includes(site));

      if (targetSite) {
        // Try to get messages for this site
        const messages = await this.zapClient.get('/JSON/core/view/messages/', {
          params: { baseurl: targetSite, start: 0, count: 10 }
        });

        if (messages.data.messages) {
          messages.data.messages.forEach((message: any) => {
            const headers = message.responseHeader?.toLowerCase() || '';

            // Server header analysis
            if (headers.includes('server:')) {
              const serverMatch = headers.match(/server:\s*([^\r\n]+)/);
              if (serverMatch) {
                const server = serverMatch[1].trim();
                if (server.includes('apache')) {
                  technologies.push({ name: 'Apache HTTP Server', type: 'Web Server', confidence: 'High' });
                } else if (server.includes('nginx')) {
                  technologies.push({ name: 'Nginx', type: 'Web Server', confidence: 'High' });
                } else if (server.includes('iis')) {
                  technologies.push({ name: 'Microsoft IIS', type: 'Web Server', confidence: 'High' });
                }
              }
            }

            // X-Powered-By header analysis
            if (headers.includes('x-powered-by:')) {
              const poweredByMatch = headers.match(/x-powered-by:\s*([^\r\n]+)/);
              if (poweredByMatch) {
                const poweredBy = poweredByMatch[1].trim();
                if (poweredBy.includes('php')) {
                  technologies.push({ name: 'PHP', type: 'Programming Language', confidence: 'High' });
                } else if (poweredBy.includes('asp.net')) {
                  technologies.push({ name: 'ASP.NET', type: 'Programming Language', confidence: 'High' });
                }
              }
            }
          });
        }
      }
    } catch (error) {
    }

    return technologies;
  }

  // Remove duplicates and enhance technologies
  private deduplicateAndEnhanceTechnologies(technologies: TechnologyResult[]): TechnologyResult[] {
    const techMap = new Map<string, TechnologyResult>();

    technologies.forEach(tech => {
      const key = tech.name.toLowerCase();
      const existing = techMap.get(key);

      if (!existing || (existing.confidence === 'Low' && tech.confidence !== 'Low')) {
        techMap.set(key, tech);
      }
    });

    return Array.from(techMap.values()).sort((a, b) => {
      const confidenceOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };
      return (confidenceOrder[b.confidence as keyof typeof confidenceOrder] || 0) -
        (confidenceOrder[a.confidence as keyof typeof confidenceOrder] || 0);
    });
  }

  // Client Spider
  async startClientSpider(targetUrl: string, options?: {
    clickElements?: boolean;
    randomInputs?: boolean;
    maxDepth?: number;
    maxDuration?: number;
  }): Promise<void> {
    try {
      const params: any = { url: targetUrl };
      if (options?.clickElements !== undefined) params.clickElements = options.clickElements;
      if (options?.randomInputs !== undefined) params.randomInputs = options.randomInputs;
      if (options?.maxDepth) params.maxDepth = options.maxDepth;
      if (options?.maxDuration) params.maxDuration = options.maxDuration;

      await this.zapClient.get('/JSON/clientSpider/action/scan/', { params });
    } catch (error) {
      await this.startSpider(targetUrl, { maxChildren: 50 });
    }
  }

  // Directory/File Brute Force
  async startDirectoryBruteForce(targetUrl: string, options?: {
    wordlist?: string;
    recursive?: boolean;
    maxDepth?: number;
    extensions?: string[];
  }): Promise<void> {
    try {
      // ZAP doesn't have direct directory brute force, use forced browse
      await this.zapClient.get('/JSON/forcedBrowse/action/startForcedBrowse/', {
        params: { url: targetUrl }
      });
    } catch (error) {
      await this.startSpider(targetUrl, { maxChildren: 100 });
    }
  }

  // Forced Browse
  async startForcedBrowse(targetUrl: string): Promise<void> {
    try {
      await this.zapClient.get('/JSON/forcedBrowse/action/startForcedBrowse/', {
        params: { url: targetUrl }
      });
    } catch (error) {
      await this.startSpider(targetUrl, { maxChildren: 100 });
    }
  }

  // Baseline Security Check
  async runBaselineCheck(targetUrl: string): Promise<BaselineResult> {
    try {
      // Access URL and wait for passive scan
      await this.accessUrl(targetUrl);
      await new Promise(resolve => setTimeout(resolve, 5000));

      // Get baseline security alerts
      const alerts = await this.getAlerts(targetUrl);

      const highRiskIssues = alerts.filter(a => a.risk === 'High').length;
      const mediumRiskIssues = alerts.filter(a => a.risk === 'Medium').length;
      const lowRiskIssues = alerts.filter(a => a.risk === 'Low').length;

      return {
        totalIssues: alerts.length,
        highRiskIssues,
        mediumRiskIssues,
        lowRiskIssues,
        alerts,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to run baseline check: ${error}`);
    }
  }

  // API Security Testing
  async runApiScan(targetUrl: string, options?: {
    openApiSpec?: string;
    postmanCollection?: string;
    apiDefinition?: any;
  }): Promise<{ scanId: string; message: string }> {
    try {
      // If OpenAPI spec is provided, import it
      if (options?.openApiSpec) {
        try {
          await this.zapClient.get('/JSON/openapi/action/importUrl/', {
            params: { url: options.openApiSpec }
          });
        } catch (e) {
        }
      }

      // Start API-focused active scan
      const scanId = await this.startActiveScan(targetUrl, {
        recurse: true,
        inScopeOnly: true
      });

      return {
        scanId,
        message: 'API security scan started'
      };
    } catch (error) {
      throw new Error(`Failed to run API scan: ${error}`);
    }
  }

  // =============================================================================
  // ALERT AND REPORTING METHODS
  // =============================================================================

  // Get all alerts with pagination and optimization
  async getAlerts(baseUrl?: string): Promise<ZapAlert[]> {
    try {

      // Try lightweight approach first - get alert count
      let alertCount = 0;
      try {
        const countResponse = await this.zapClient.get('/JSON/core/view/numberOfAlerts/', {
          timeout: 5000 // Quick check
        });
        alertCount = parseInt(countResponse.data.numberOfAlerts || '0');
      } catch (countError) {
      }

      // If too many alerts, use pagination or return limited results
      if (alertCount > 100) {
        return await this.getAlertsOptimized(baseUrl, 100); // Limit to 100 alerts to prevent memory issues
      }

      const params = baseUrl ? { baseurl: baseUrl } : {};

      // Use shorter timeout for normal sized responses
      const alertsResponse = await this.zapClient.get('/JSON/core/view/alerts', {
        params,
        timeout: 20000, // Reduce to 20 seconds timeout
        maxContentLength: 3 * 1024 * 1024, // Reduce to 3MB max response size
        maxBodyLength: 3 * 1024 * 1024, // Reduce to 3MB max body size
        validateStatus: function (status) {
          return status >= 200 && status < 300; // Accept only 2xx responses
        },
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        }
      });


      if (!alertsResponse.data.alerts || !Array.isArray(alertsResponse.data.alerts)) {
        return [];
      }

      return alertsResponse.data.alerts.map((alert: any) => ({
        alertId: alert.id || '',
        name: alert.alert || 'Unknown Alert',
        description: alert.description || '',
        risk: alert.risk || 'LOW',
        severity: this.mapSeverity(alert.risk || 'LOW'), // Add mapped severity
        confidence: alert.confidence || 'Medium',
        url: alert.url || '',
        param: alert.param || '',
        attack: alert.attack || '',
        evidence: alert.evidence || '',
        solution: alert.solution || '',
        reference: alert.reference || ''
      }));
    } catch (error: any) {
      console.error('❌ Error getting alerts from ZAP:', error);

      // If timeout or connection error, try optimized approach
      if (error.code === 'ECONNABORTED' || error.message?.includes('timeout')) {
        try {
          return await this.getAlertsOptimized(baseUrl, 100);
        } catch (optimizedError) {
          console.error('❌ Optimized alerts fetch also failed:', optimizedError);
          return [];
        }
      }

      // For other errors, still return empty array to prevent scan failure
      return [];
    }
  }

  // Get alerts in optimized way with limits (made public for API access)
  async getAlertsOptimized(baseUrl?: string, limit: number = 100): Promise<ZapAlert[]> {
    try {
      console.log(`🔍 Getting alerts optimized (limit: ${limit})...`);

      const params: any = baseUrl ? { baseurl: baseUrl } : {};
      params.start = 0;
      params.count = Math.min(limit, 50); // Max 50 alerts at once to prevent memory issues

      // Use the correct ZAP API endpoint with JSON format
      const alertsResponse = await this.zapClient.get('/JSON/core/view/alerts', {
        params,
        timeout: 15000, // Reduce to 15 seconds timeout
        maxContentLength: 2 * 1024 * 1024, // 2MB max to prevent memory overflow
        maxBodyLength: 2 * 1024 * 1024,
        validateStatus: function (status) {
          return status >= 200 && status < 300; // Accept only 2xx responses
        },
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        }
      });

      const alerts = alertsResponse.data.alerts || [];
      console.log(`✅ Retrieved ${alerts.length} alerts (optimized)`);

      return alerts.slice(0, Math.min(limit, 50)).map((alert: any) => ({
        alertId: alert.id || '',
        name: alert.alert || 'Unknown Alert',
        description: alert.description || '',
        risk: alert.risk || 'LOW',
        severity: this.mapSeverity(alert.risk || 'LOW'), // Add mapped severity
        confidence: alert.confidence || 'Medium',
        url: alert.url || '',
        param: alert.param || '',
        attack: alert.attack || '',
        evidence: alert.evidence || '',
        solution: alert.solution || '',
        reference: alert.reference || ''
      }));
    } catch (error) {
      console.error('❌ Optimized alerts fetch failed:', error);
      return [];
    }
  }

  // Generate HTML report
  async generateHtmlReport(): Promise<string> {
    try {
      const response = await this.zapClient.get('/OTHER/core/other/htmlreport/');
      return response.data;
    } catch (error) {
      throw new Error(`Failed to generate HTML report: ${error}`);
    }
  }

  // Generate JSON report
  async generateJsonReport(): Promise<any> {
    try {
      const response = await this.zapClient.get('/JSON/core/view/alerts/');
      return response.data;
    } catch (error) {
      throw new Error(`Failed to generate JSON report: ${error}`);
    }
  }

  // Generate XML report
  async generateXmlReport(): Promise<string> {
    try {
      const response = await this.zapClient.get('/OTHER/core/other/xmlreport/');
      return response.data;
    } catch (error) {
      throw new Error(`Failed to generate XML report: ${error}`);
    }
  }

  // Get scan summary
  async getScanSummary(): Promise<any> {
    try {
      const [alerts, sites, urls] = await Promise.all([
        this.zapClient.get('/JSON/core/view/alerts/'),
        this.zapClient.get('/JSON/core/view/sites/'),
        this.zapClient.get('/JSON/core/view/urls/')
      ]);

      const alertsByRisk = {
        high: 0,
        medium: 0,
        low: 0,
        informational: 0
      };

      alerts.data.alerts?.forEach((alert: any) => {
        const risk = alert.risk?.toLowerCase();
        if (alertsByRisk.hasOwnProperty(risk)) {
          alertsByRisk[risk as keyof typeof alertsByRisk]++;
        }
      });

      return {
        totalAlerts: alerts.data.alerts?.length || 0,
        alertsByRisk,
        sites: sites.data.sites || [],
        urls: urls.data.urls || [],
        scanDate: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to get scan summary: ${error}`);
    }
  }

  // =============================================================================
  // COMPREHENSIVE SCAN WORKFLOW
  // =============================================================================

  // Monitor spider progress
  async monitorSpiderProgress(scanId: string, maxWaitTime: number = 30000): Promise<void> {
    const startTime = Date.now();

    while (Date.now() - startTime < maxWaitTime) {
      const status = await this.getSpiderStatus(scanId);

      if (status.status === 'finished' || status.progress >= 100) {
        break;
      }

      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }

  // Monitor AJAX spider progress
  async monitorAjaxSpiderProgress(maxWaitTime: number = 20000): Promise<void> {
    const startTime = Date.now();

    while (Date.now() - startTime < maxWaitTime) {
      const status = await this.getAjaxSpiderStatus();

      if (status.status === 'stopped' || status.messagesInQueue === 0) {
        break;
      }

      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }

  // Monitor active scan progress
  async monitorActiveScanProgress(scanId: string, maxWaitTime: number = 120000): Promise<void> {
    const startTime = Date.now();

    while (Date.now() - startTime < maxWaitTime) {
      const status = await this.getActiveScanStatus(scanId);

      if (status.status === 'finished' || status.progress >= 100) {
        break;
      }

      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }

  // Generate PDF report - placeholder implementation
  async generatePdfReport(): Promise<Buffer> {
    // For now, return a simple PDF placeholder
    // In a real implementation, you would generate an actual PDF
    return Buffer.from('PDF Report placeholder content');
  }

  // Get hosts
  async getHosts(): Promise<string[]> {
    try {
      const response = await this.zapClient.get('/JSON/core/view/hosts/');
      return response.data.hosts || [];
    } catch (error) {
      console.error('Error getting hosts:', error);
      return [];
    }
  }

  // Get contexts
  async getContexts(): Promise<any[]> {
    try {
      const response = await this.zapClient.get('/JSON/context/view/contextList/');
      return response.data.contextList || [];
    } catch (error) {
      console.error('Error getting contexts:', error);
      return [];
    }
  }

  // Create context
  async createContext(contextName: string): Promise<string> {
    try {
      const response = await this.zapClient.get('/JSON/context/action/newContext/', {
        params: { contextName }
      });
      return response.data.contextId || '';
    } catch (error) {
      console.error('Error creating context:', error);
      throw error;
    }
  }

  // Get passive scan configuration
  async getPscanConfig(): Promise<any> {
    try {
      const response = await this.zapClient.get('/JSON/pscan/view/scanners/');
      return response.data;
    } catch (error) {
      console.error('Error getting pscan config:', error);
      return {};
    }
  }

  // Enable all passive scan rules
  async enableAllPscanRules(): Promise<void> {
    try {
      await this.zapClient.get('/JSON/pscan/action/enableAllScanners/');
    } catch (error) {
      console.error('Error enabling all pscan rules:', error);
    }
  }

  // Get authentication methods
  async getAuthenticationMethods(): Promise<any[]> {
    try {
      const response = await this.zapClient.get('/JSON/authentication/view/getSupportedAuthenticationMethods/');
      return response.data.supportedAuthenticationMethods || [];
    } catch (error) {
      console.error('Error getting authentication methods:', error);
      return [];
    }
  }

  // Get HTTP sessions
  async getHttpSessions(): Promise<any[]> {
    try {
      const response = await this.zapClient.get('/JSON/httpSessions/view/sessions/');
      return response.data.sessions || [];
    } catch (error) {
      console.error('Error getting HTTP sessions:', error);
      return [];
    }
  }

  // Quick start launch
  async quickStartLaunch(url: string): Promise<any> {
    try {
      const response = await this.zapClient.get('/JSON/core/action/accessUrl/', {
        params: { url }
      });
      return response.data;
    } catch (error) {
      console.error('Error with quick start launch:', error);
      throw error;
    }
  }

  // 🔥 NEW: Configure ZAP based on environment
  private async configureZapForEnvironment(
    workflowId: string,
    environment: 'TEST' | 'PRODUCTION' | 'CUSTOM',
    aggressiveness: 'LOW' | 'MEDIUM' | 'HIGH' | 'INSANE',
    safeMode: boolean,
    options: ScanWorkflowOptions
  ): Promise<void> {

    try {
      console.log(`⚙️ Configuring ZAP for ${environment} environment (${aggressiveness})`);

      // NOTE: setAttackStrength and setAlertThreshold APIs are not working in this ZAP version
      // Skipping these configurations - ZAP will use default settings

      // Configure scan policies based on environment
      if (environment === 'TEST' || (environment === 'CUSTOM' && !safeMode)) {
        // Enable ALL scan policies for aggressive testing
        await this.enableAllScanPolicies();

        // Enable specific attack types based on advancedTests
        if (options.advancedTests) {
          await this.configureAdvancedTests(options.advancedTests, aggressiveness);
        }
      } else {
        // PRODUCTION/Safe mode: Only enable safe policies
        await this.enableSafeScanPolicies();
        console.log(`✅ Safe scan policies enabled (read-only tests)`);
      }

      // Configure for WAF bypass if requested
      if (options.advancedTests?.enableWafBypass && environment === 'TEST') {
        await this.enableWafBypassTechniques();
      }

    } catch (error) {
      console.error(`❌ Error configuring ZAP for ${environment}:`, error);
      // Don't throw - continue with defaults
    }
  }

  // Helper: Get attack strength from aggressiveness level
  private getAttackStrength(aggressiveness: string): 'Low' | 'Medium' | 'High' | 'Insane' {
    switch (aggressiveness) {
      case 'LOW': return 'Low';
      case 'MEDIUM': return 'Medium';
      case 'HIGH': return 'High';
      case 'INSANE': return 'Insane';
      default: return 'Medium';
    }
  }

  // Helper: Set attack strength in ZAP
  private async setAttackStrength(strength: string): Promise<void> {
    try {
      // ZAP API: setOptionAttackStrength requires 'String' with capital S
      await this.zapClient.get('/JSON/ascan/action/setOptionAttackStrength/', {
        params: { String: strength }
      });
      console.log(`✅ Attack strength set to: ${strength}`);
    } catch (error) {
      console.error('⚠️ Error setting attack strength:', error);
      // Non-critical, continue workflow
    }
  }

  // Helper: Set alert threshold in ZAP
  private async setAlertThreshold(threshold: string): Promise<void> {
    try {
      // ZAP API: setOptionAlertThreshold requires 'String' with capital S
      await this.zapClient.get('/JSON/ascan/action/setOptionAlertThreshold/', {
        params: { String: threshold }
      });
      console.log(`✅ Alert threshold set to: ${threshold}`);
    } catch (error) {
      console.error('⚠️ Error setting alert threshold:', error);
      // Non-critical, continue workflow
    }
  }

  // Helper: Enable safe scan policies (read-only)
  public async enableSafeScanPolicies(): Promise<void> {
    try {
      // Disable risky policies
      const riskyPolicies = [
        '40018', // SQL Injection - Don't use INSERT/UPDATE/DELETE
        '90019', // Server Side Code Injection
        '90020', // Remote OS Command Injection
        '40009', // Server Side Include
      ];

      for (const policyId of riskyPolicies) {
        await this.zapClient.get('/JSON/ascan/action/setScannerAttackStrength/', {
          params: { id: policyId, attackStrength: 'Off' }
        });
      }

    } catch (error) {
      console.error('Error configuring safe policies:', error);
    }
  }

  // Helper: Configure advanced tests
  private async configureAdvancedTests(tests: any, aggressiveness: string): Promise<void> {

    const scannerStrength = aggressiveness === 'INSANE' ? 'Insane' : 'High';

    try {
      // SQL Injection
      if (tests.enableSqlInjection) {
        await this.zapClient.get('/JSON/ascan/action/enableScanners/', {
          params: { ids: '40018,40019,40020,40021,40022' } // SQL Injection family
        });
        await this.zapClient.get('/JSON/ascan/action/setScannerAttackStrength/', {
          params: { id: '40018', attackStrength: scannerStrength }
        });
      }

      // XSS
      if (tests.enableXss) {
        await this.zapClient.get('/JSON/ascan/action/enableScanners/', {
          params: { ids: '40012,40014,40016,40017' } // XSS family
        });
      }

      // XXE
      if (tests.enableXxe) {
        await this.zapClient.get('/JSON/ascan/action/enableScanners/', {
          params: { ids: '90019' } // XXE
        });
      }

      // Command Injection
      if (tests.enableCommandInjection) {
        await this.zapClient.get('/JSON/ascan/action/enableScanners/', {
          params: { ids: '90020,90019' } // OS Command Injection
        });
      }

      // Path Traversal
      if (tests.enablePathTraversal) {
        await this.zapClient.get('/JSON/ascan/action/enableScanners/', {
          params: { ids: '6,7' } // Path Traversal
        });
      }

    } catch (error) {
      console.error('Error configuring advanced tests:', error);
    }
  }

  // Helper: Enable WAF bypass techniques
  private async enableWafBypassTechniques(): Promise<void> {
    try {
      // Set maximum scanner threads and requests per second
      await this.zapClient.get('/JSON/ascan/action/setOptionMaxScansInUI/', {
        params: { Integer: 10 }
      });

      await this.zapClient.get('/JSON/ascan/action/setOptionDelayInMs/', {
        params: { Integer: 0 } // No delay between requests
      });

    } catch (error) {
      console.error('Error enabling WAF bypass:', error);
    }
  }

  // Start complete workflow
  async startCompleteWorkflow(workflowId: string, options: ScanWorkflowOptions, scanId?: string): Promise<void> {

    // 🔥 Determine environment settings
    const environment = options.environment || 'TEST';
    const aggressiveness = options.aggressiveness || 'HIGH';
    const safeMode = options.safeMode !== undefined ? options.safeMode : false;


    if (environment === 'PRODUCTION' || safeMode) {
    } else if (environment === 'TEST' && aggressiveness === 'INSANE') {
    }

    try {
      // Store workflow state
      const initialState = {
        workflowId,
        phase: 'INITIALIZING',
        progress: 0,
        status: 'STARTING',
        startTime: new Date(),
        targetUrl: options.targetUrl,
        environment,
        aggressiveness,
        safeMode,
        spiderScanId: null,
        ajaxSpiderScanId: null,
        activeScanId: null
      };

      this.workflowStates.set(workflowId, initialState);
      this.workflowProgress.set(workflowId, initialState); // Also store in workflowProgress map

      // Emit initial status
      this.io?.emit('workflowUpdate', {
        workflowId,
        phase: 'INITIALIZING',
        progress: 0,
        status: 'STARTING',
        environment,
        aggressiveness,
        safeMode
      });

      // Phase 0: Clear ZAP Session & Configure (0-5%)
      await this.updateWorkflowProgress(workflowId, 'INITIALIZING', 2, 'Creating new ZAP session', scanId);

      try {
        // Create a new ZAP session to isolate this scan from previous scans
        await this.clearSession();

        // 🔥 Configure ZAP based on environment
        await this.configureZapForEnvironment(workflowId, environment, aggressiveness, safeMode, options);

      } catch (error) {
        console.error(`⚠️ Workflow ${workflowId}: Failed to configure ZAP, continuing anyway:`, error);
      }

      // Phase 1: Target Setup (5%)
      await this.updateWorkflowProgress(workflowId, 'TARGET_SETUP', 5, 'Setting up target', scanId);

      // Check if workflow was stopped
      if (this.isWorkflowStopped(workflowId)) {
        return;
      }

      // Access target URL with error handling
      try {
        await this.accessUrl(options.targetUrl);
      } catch (error) {
        console.error(`⚠️ Workflow ${workflowId}: Failed to access URL, but continuing:`, error);
        // Continue anyway - spider will try to access the URL
      }

      // Phase 2: Spider Scan (10-40%)
      if (options.enableSpider && !this.isWorkflowStopped(workflowId)) {
        await this.updateWorkflowProgress(workflowId, 'SPIDER_SCAN', 10, 'Starting spider scan', scanId);
        const spiderScanId = await this.startSpider(options.targetUrl);

        // Store spider scan ID in workflow
        const workflow = this.workflowProgress.get(workflowId);
        if (workflow) {
          workflow.spiderScanId = spiderScanId;
          this.workflowProgress.set(workflowId, workflow);
        }

        // ⏱️ Monitor spider progress with REAL timeout protection
        let spiderProgress = 0;
        let attempts = 0;
        const spiderTimeout = options.spiderMaxDuration || 3600; // seconds (default 60 min - UNLIMITED for full scan)
        const pollInterval = 3; // seconds
        const maxAttempts = Math.ceil(spiderTimeout / pollInterval);


        const startTime = Date.now();
        while (spiderProgress < 100 && attempts < maxAttempts && !this.isWorkflowStopped(workflowId)) {
          await new Promise(resolve => setTimeout(resolve, pollInterval * 1000));

          // Check if workflow was stopped during sleep
          if (this.isWorkflowStopped(workflowId)) {
            break;
          }

          // Check timeout
          const elapsedSeconds = (Date.now() - startTime) / 1000;
          if (elapsedSeconds >= spiderTimeout) {
            console.log(`⏱️ Spider timeout reached (${spiderTimeout}s), forcing completion`);
            // Mark workflow as timeout-completed to prevent early exits
            this.timeoutCompletedWorkflows.add(workflowId);
            spiderProgress = 100;
            break;
          }

          try {
            spiderProgress = await this.getSpiderProgress(spiderScanId);
            if (attempts % 5 === 0) { // Log every 15 seconds
              console.log(`📊 Spider progress: ${spiderProgress}% (${Math.floor(elapsedSeconds)}s elapsed)`);
            }
          } catch (error) {
            console.error(`⚠️ Workflow ${workflowId}: Error getting spider progress:`, error);
          }

          const overallProgress = 10 + (spiderProgress * 0.3); // 10% to 40%
          await this.updateWorkflowProgress(workflowId, 'SPIDER_SCAN', overallProgress,
            `Spider scanning: ${spiderProgress}% complete (${Math.floor(elapsedSeconds)}s)`, scanId);

          attempts++;
        }

        // Ensure we reach 40% even if spider timeout
        await this.updateWorkflowProgress(workflowId, 'SPIDER_SCAN', 40, 'Spider scan completed', scanId);
      } else {
        await this.updateWorkflowProgress(workflowId, 'SPIDER_SCAN', 40, 'Spider scan skipped', scanId);
      }

      // Phase 3: Ajax Spider (40-60%)
      if (options.enableAjaxSpider && !this.isWorkflowStopped(workflowId)) {
        await this.updateWorkflowProgress(workflowId, 'AJAX_SPIDER', 45, 'Starting Ajax spider', scanId);
        await this.startAjaxSpider(options.targetUrl);

        // Store ajax spider scan ID in workflow (Ajax spider doesn't return scan ID)
        const workflow = this.workflowProgress.get(workflowId);
        if (workflow) {
          workflow.ajaxSpiderScanId = 'ajax-spider-running';
          this.workflowProgress.set(workflowId, workflow);
        }

        // ⏱️ Monitor Ajax spider progress with REAL timeout protection
        let ajaxProgress = 0;
        let attempts = 0;
        const ajaxTimeout = options.ajaxSpiderMaxDuration || 3600; // seconds (default 60 min - UNLIMITED for full scan)
        const pollInterval = 4; // seconds
        const maxAttempts = Math.ceil(ajaxTimeout / pollInterval);


        const startTime = Date.now();
        while (ajaxProgress < 100 && attempts < maxAttempts && !this.isWorkflowStopped(workflowId)) {
          await new Promise(resolve => setTimeout(resolve, pollInterval * 1000));

          // Check if workflow was stopped during sleep
          if (this.isWorkflowStopped(workflowId)) {
            break;
          }

          // Check timeout
          const elapsedSeconds = (Date.now() - startTime) / 1000;
          if (elapsedSeconds >= ajaxTimeout) {
            console.log(`⏱️ AJAX Spider timeout reached (${ajaxTimeout}s), forcing completion`);
            // Mark workflow as timeout-completed to prevent early exits
            this.timeoutCompletedWorkflows.add(workflowId);
            ajaxProgress = 100;
            break;
          }

          try {
            const progressData = await this.getAjaxSpiderProgress();
            ajaxProgress = progressData.status === 'stopped' ? 100 : progressData.progress || 0;
            if (attempts % 5 === 0) { // Log every 20 seconds
              console.log(`📊 AJAX Spider progress: ${ajaxProgress}% (${Math.floor(elapsedSeconds)}s elapsed)`);
            }
          } catch (error) {
            console.error(`⚠️ Workflow ${workflowId}: Error getting ajax spider progress:`, error);
          }

          const overallProgress = 45 + (ajaxProgress * 0.15); // 45% to 60%
          await this.updateWorkflowProgress(workflowId, 'AJAX_SPIDER', overallProgress,
            `Ajax spider: ${ajaxProgress}% complete (${Math.floor(elapsedSeconds)}s)`, scanId);

          attempts++;
        }

        // Ensure we reach 60% even if ajax spider timeout
        await this.updateWorkflowProgress(workflowId, 'AJAX_SPIDER', 60, 'Ajax spider completed', scanId);
      } else {
        await this.updateWorkflowProgress(workflowId, 'AJAX_SPIDER', 60, 'Ajax spider skipped', scanId);
      }

      // Phase 4: Active Scan (60-90%)
      if (options.enableActiveScan && !this.isWorkflowStopped(workflowId)) {
        await this.updateWorkflowProgress(workflowId, 'ACTIVE_SCAN', 65, 'Preparing active scan', scanId);

        // CRITICAL: Ensure URL is properly registered in ZAP before active scan
        let activeScanUrl = options.targetUrl;

        try {
          console.log(`📍 Preparing ${options.targetUrl} for active scan...`);

          // Step 1: Wait for ZAP to process spider results
          console.log(`⏳ Waiting 5 seconds for ZAP to process spider results...`);
          await new Promise(resolve => setTimeout(resolve, 5000));

          // Step 2: Get all discovered URLs (more reliable than sites tree)
          let discoveredUrls: string[] = [];
          try {
            const urlsResponse = await this.zapClient.get('/JSON/core/view/urls/');
            discoveredUrls = urlsResponse.data.urls || [];
            console.log(`🔍 Total discovered URLs: ${discoveredUrls.length}`);

            // Filter URLs for target domain
            const targetDomain = new URL(options.targetUrl).hostname;
            const targetUrls = discoveredUrls.filter((url: string) => {
              try {
                return new URL(url).hostname === targetDomain;
              } catch {
                return false;
              }
            });
            console.log(`🎯 URLs matching target domain (${targetDomain}): ${targetUrls.length}`);

            if (targetUrls.length > 0) {
              const exactMatch = targetUrls.find((url: string) => url === options.targetUrl);
              activeScanUrl = exactMatch || targetUrls[0];
              console.log(`✅ Using URL for active scan: ${activeScanUrl}`);
            } else {
              console.warn(`⚠️ No URLs found for target domain`);
            }
          } catch (err: any) {
            console.warn(`⚠️ Could not get URLs list:`, err.message);
          }

          // Step 3: Check sites tree
          const sitesResponse = await this.zapClient.get('/JSON/core/view/sites/');
          const sites = sitesResponse.data.sites || [];
          console.log(`🌐 Sites in tree: ${sites.length}`);

          // Step 4: If no URLs, try manual HTTP request
          if (discoveredUrls.length === 0) {
            console.warn(`⚠️ No URLs found. Attempting manual HTTP request...`);

            try {
              const targetUrl = new URL(options.targetUrl);
              const requestStr = `GET ${targetUrl.pathname || '/'} HTTP/1.1\r\nHost: ${targetUrl.hostname}\r\nUser-Agent: Mozilla/5.0\r\n\r\n`;

              console.log(`🌐 Sending manual request...`);
              await this.zapClient.get('/JSON/core/action/sendRequest/', {
                params: { request: requestStr, followRedirects: 'true' }
              });

              await new Promise(resolve => setTimeout(resolve, 3000));

              const newUrlsResponse = await this.zapClient.get('/JSON/core/view/urls/');
              const newUrls = newUrlsResponse.data.urls || [];
              console.log(`🔄 URLs after manual request: ${newUrls.length}`);

              if (newUrls.length > 0) {
                const targetUrls = newUrls.filter((url: string) => {
                  try {
                    return new URL(url).hostname === targetUrl.hostname;
                  } catch {
                    return false;
                  }
                });
                if (targetUrls.length > 0) {
                  activeScanUrl = targetUrls[0];
                  console.log(`✅ Found URL after manual request: ${activeScanUrl}`);
                }
              }
            } catch (manualErr: any) {
              console.error(`❌ Manual request failed:`, manualErr.message);
            }
          }

          // Step 5: Get URLs from sites tree to use for active scan
          try {
            const urlsResponse = await this.zapClient.get('/JSON/core/view/urls/', {
              params: { baseurl: activeScanUrl }
            });
            const urls = urlsResponse.data.urls || [];
            console.log(`� Found ${urls.length} URLs for active scan`);

            if (urls.length === 0) {
              console.warn(`⚠️ No URLs found. Active scan may fail.`);
            }
          } catch (err) {
            console.warn(`⚠️ Could not get URLs list`);
          }

        } catch (error: any) {
          console.error(`❌ Error preparing URL:`, error.message);
          // Continue anyway with original URL
        }

        // Step 6: Start active scan with the best URL we have
        console.log(`🚀 Starting active scan on ${activeScanUrl}...`);
        const activeScanId = await this.startActiveScan(activeScanUrl, {
          recurse: true,
          inScopeOnly: false
        });

        console.log(`✅ Active scan started with ID: ${activeScanId}`);

        // Store active scan ID in workflow
        const workflow = this.workflowProgress.get(workflowId);
        if (workflow) {
          workflow.activeScanId = activeScanId;
          this.workflowProgress.set(workflowId, workflow);
        }

        // ⏱️ Monitor active scan progress with REAL timeout protection
        let activeProgress = 0;
        let attempts = 0;
        // Calculate max attempts based on activeScanMaxDuration (default 30 min = 1800s)
        const activeScanTimeout = options.activeScanMaxDuration || 1800; // seconds
        const pollInterval = 5; // seconds
        const maxAttempts = Math.ceil(activeScanTimeout / pollInterval); // e.g., 1800/5 = 360 attempts


        const startTime = Date.now();
        while (activeProgress < 100 && attempts < maxAttempts && !this.isWorkflowStopped(workflowId)) {
          await new Promise(resolve => setTimeout(resolve, pollInterval * 1000));

          // Check if workflow was stopped during sleep
          if (this.isWorkflowStopped(workflowId)) {
            break;
          }

          // Check timeout
          const elapsedSeconds = (Date.now() - startTime) / 1000;
          if (elapsedSeconds >= activeScanTimeout) {
            console.log(`⏱️ Active scan timeout reached (${activeScanTimeout}s), forcing completion`);
            // Mark workflow as timeout-completed to prevent early exits
            this.timeoutCompletedWorkflows.add(workflowId);
            activeProgress = 100;
            break;
          }

          try {
            activeProgress = await this.getActiveScanProgress(activeScanId);
            console.log(`📊 Active scan progress: ${activeProgress}% (${Math.floor(elapsedSeconds)}s elapsed)`);
          } catch (error) {
            console.error(`⚠️ Workflow ${workflowId}: Error getting active scan progress:`, error);
            // Don't use fallback progress - keep trying
          }

          const overallProgress = 65 + (activeProgress * 0.25); // 65% to 90%
          await this.updateWorkflowProgress(workflowId, 'ACTIVE_SCAN', overallProgress,
            `Active scanning: ${activeProgress}% complete (${Math.floor(elapsedSeconds)}s)`, scanId);

          attempts++;
        }

        // Ensure we reach 90% even if active scan timeout
        await this.updateWorkflowProgress(workflowId, 'ACTIVE_SCAN', 90, 'Active scan completed', scanId);
      } else {
        await this.updateWorkflowProgress(workflowId, 'ACTIVE_SCAN', 90, 'Active scan skipped', scanId);
      }

      // Phase 5: Advanced Data Collection (90-92%)
      let advancedData: any = null;
      if (!this.isWorkflowStopped(workflowId)) {
        try {
          await this.updateWorkflowProgress(workflowId, 'ADVANCED_ANALYSIS', 90, 'Collecting advanced ZAP data...', scanId);

          advancedData = await this.zapAdvancedService.collectAllZapData(options.targetUrl);
          const dataPoints = Object.keys(advancedData.categories || {}).length;

          await this.updateWorkflowProgress(workflowId, 'ADVANCED_ANALYSIS', 92,
            `Advanced analysis complete (${dataPoints} data points collected)`, scanId);
        } catch (error) {
          console.error(`⚠️ Advanced data collection failed:`, error);
          await this.updateWorkflowProgress(workflowId, 'ADVANCED_ANALYSIS', 92, 'Advanced analysis skipped due to error', scanId);
        }
      } else {
        return;
      }

      // Phase 6: JavaScript Security Analysis (92-94%)
      let jsSecurityData: any = null;
      if (!this.isWorkflowStopped(workflowId)) {
        try {
          await this.updateWorkflowProgress(workflowId, 'JS_SECURITY', 92, 'Analyzing JavaScript security...', scanId);

          jsSecurityData = await this.zapAdvancedService.analyzeJavaScriptSecurity(options.targetUrl);
          const libCount = jsSecurityData.libraries?.length || 0;
          const vulnCount = jsSecurityData.vulnerabilities?.length || 0;

          await this.updateWorkflowProgress(workflowId, 'JS_SECURITY', 94,
            `JS security analysis complete (${libCount} libraries, ${vulnCount} issues)`, scanId);
        } catch (error) {
          console.error(`⚠️ JS security analysis failed:`, error);
          await this.updateWorkflowProgress(workflowId, 'JS_SECURITY', 94, 'JS security analysis skipped', scanId);
        }
      } else {
        return;
      }

      // Phase 7: API Security Deep Dive (94-96%)
      let apiSecurityData: any = null;
      const apiDeepDiveEnabled = options.apiDeepDive?.enabled !== false; // Default true
      const apiDeepDiveIntensity = options.apiDeepDive?.intensity || 'comprehensive';

      if (apiDeepDiveEnabled && !this.isWorkflowStopped(workflowId)) {
        try {
          await this.updateWorkflowProgress(workflowId, 'API_DEEP_DIVE', 94,
            `Performing API security deep dive (${apiDeepDiveIntensity} mode)...`, scanId);

          console.log(`🎯 Starting API Deep Dive with intensity: ${apiDeepDiveIntensity}`);
          apiSecurityData = await this.apiSecurityService.performApiSecurityDeepDive(options.targetUrl);

          const endpoints = apiSecurityData.summary?.totalEndpoints || 0;
          const score = apiSecurityData.summary?.securityScore || 0;
          const vulnCount = apiSecurityData.summary?.vulnerabilitiesFound || 0;

          console.log(`✅ API Deep Dive complete: ${endpoints} endpoints, ${vulnCount} vulnerabilities, score: ${score}/100`);

          await this.updateWorkflowProgress(workflowId, 'API_DEEP_DIVE', 96,
            `API deep dive complete (${endpoints} endpoints, ${vulnCount} vulnerabilities, score: ${score}/100)`, scanId);
        } catch (error) {
          console.error(`⚠️ API security deep dive failed:`, error);
          await this.updateWorkflowProgress(workflowId, 'API_DEEP_DIVE', 96, 'API deep dive skipped (error occurred)', scanId);
        }
      } else {
        console.log(`⏭️ API Deep Dive skipped (enabled: ${apiDeepDiveEnabled})`);
        await this.updateWorkflowProgress(workflowId, 'API_DEEP_DIVE', 96, 'API deep dive skipped (disabled)', scanId);
      }

      // Phase 8: Generating Report (96-100%)
      if (!this.isWorkflowStopped(workflowId)) {
        await this.updateWorkflowProgress(workflowId, 'GENERATING_REPORT', 97, 'Generating comprehensive report...', scanId);
      } else {
        return;
      }

      // Get final results with timeout protection
      let alerts: any[] = [];
      let hosts: any[] = [];
      let history: any[] = [];

      try {

        // Use Promise.allSettled to prevent one failure from blocking others
        const results = await Promise.allSettled([
          Promise.race([
            this.getAlerts(),
            new Promise((_, reject) => setTimeout(() => reject(new Error('getAlerts timeout')), 10000))
          ]),
          Promise.race([
            this.getHosts(),
            new Promise((_, reject) => setTimeout(() => reject(new Error('getHosts timeout')), 10000))
          ]),
          Promise.race([
            this.getHistory(),
            new Promise((_, reject) => setTimeout(() => reject(new Error('getHistory timeout')), 10000))
          ])
        ]);

        const allAlerts = results[0].status === 'fulfilled' ? (results[0].value as any[]) : [];
        hosts = results[1].status === 'fulfilled' ? (results[1].value as any[]) : [];
        const allHistory = results[2].status === 'fulfilled' ? (results[2].value as any[]) : [];

        // Filter results based on target URL
        const targetDomain = new URL(options.targetUrl).hostname;

        // Filter alerts
        alerts = allAlerts.filter((alert: any) => {
          try {
            if (!alert.url) return false;
            const alertDomain = new URL(alert.url).hostname;
            return alertDomain === targetDomain;
          } catch {
            return false;
          }
        });

        // Filter history
        history = allHistory.filter((entry: any) => {
          try {
            const url = entry.uri || entry.url || '';
            if (!url) return false;
            const urlDomain = new URL(url).hostname;
            return urlDomain === targetDomain;
          } catch {
            return false;
          }
        });

        console.log(`   - Alerts: ${allAlerts.length} total → ${alerts.length} filtered`);
        console.log(`   - Hosts: ${hosts.length}`);
      } catch (error) {
        console.error(`⚠️ Workflow ${workflowId}: Error fetching final results:`, error);
        // Continue with empty arrays rather than failing the entire workflow
      }

      // Complete workflow
      const finalState = {
        workflowId,
        phase: 'COMPLETED',
        progress: 100,
        status: 'COMPLETED',
        endTime: new Date(),
        vulnerabilities: alerts.slice(0, 50), // Limit to first 50
        urlsFound: history.slice(0, 100).map((entry: any) => ({
          url: entry.uri || entry.url || '',
          method: entry.method || 'GET',
          statusCode: entry.code || entry.statusCode || 200,
          responseTime: entry.responseTimeInMs || entry.responseTime || 0,
          contentType: entry.responseHeaders?.find((h: any) =>
            h.name?.toLowerCase() === 'content-type')?.value || 'text/html',
          size: entry.responseBody?.length || entry.size || 0,
          timestamp: entry.timestamp || new Date().toISOString()
        })), // Convert history to URL format
        summary: {
          totalVulnerabilities: alerts.length,
          totalUrls: history.length,
          highRisk: alerts.filter((alert: any) => alert.risk === 'High').length,
          mediumRisk: alerts.filter((alert: any) => alert.risk === 'Medium').length,
          lowRisk: alerts.filter((alert: any) => alert.risk === 'Low').length
        },
        // Advanced analysis results
        advancedAnalysis: advancedData ? {
          dataPoints: Object.keys(advancedData.categories || {}).length,
          categories: advancedData.categories,
          zapSystemInfo: advancedData.zapSystemInfo
        } : null,
        jsSecurity: jsSecurityData ? {
          libraries: jsSecurityData.libraries,
          vulnerabilities: jsSecurityData.vulnerabilities,
          totalLibraries: jsSecurityData.libraries?.length || 0,
          totalVulnerabilities: jsSecurityData.vulnerabilities?.length || 0
        } : null,
        apiSecurity: apiSecurityData ? {
          totalEndpoints: apiSecurityData.summary?.totalEndpoints || 0,
          vulnerabilitiesFound: apiSecurityData.summary?.vulnerabilitiesFound || 0,
          securityScore: apiSecurityData.summary?.securityScore || 0,
          riskLevel: apiSecurityData.summary?.riskLevel || 'Unknown',
          endpoints: apiSecurityData.endpoints,
          recommendations: apiSecurityData.recommendations
        } : null
      };

      // Save final results to database if scanId is provided
      if (scanId) {
        try {
          // Save vulnerabilities to database
          if (alerts.length > 0) {
            console.log(`🔍 DEBUG: Alert sample:`, alerts[0]);

            await this.prisma.vulnerability.createMany({
              data: alerts.map(alert => ({
                scanId,
                name: alert.name || alert.alert || 'Unknown Vulnerability',
                description: alert.description || alert.desc || '',
                severity: this.mapSeverity(alert.risk || alert.riskdesc || 'Low'),
                confidence: alert.confidence || 'Medium',
                solution: alert.solution || '',
                reference: alert.reference || '',
                zapAlertId: alert.id?.toString() || '',
                affectedUrl: alert.url || '',
                param: alert.param || '',
                attack: alert.attack || '',
                evidence: alert.evidence || '',
                cweid: alert.cweid?.toString() || '',
                wascid: alert.wascid?.toString() || '',
                otherInfo: alert.other || ''
              }))
            });
          }

          // Final URL save (in case any missed during progress updates)
          if (finalState.urlsFound.length > 0) {
            await this.prisma.scanUrl.deleteMany({ where: { scanId } });
            await this.prisma.scanUrl.createMany({
              data: finalState.urlsFound.map(url => ({
                scanId,
                url: url.url,
                method: url.method,
                statusCode: url.statusCode,
                responseTime: url.responseTime,
                contentType: url.contentType,
                size: url.size,
                timestamp: url.timestamp && !isNaN(Date.parse(url.timestamp)) ? new Date(url.timestamp) : new Date()
              }))
            });
          }

          // Helper function to remove null characters from JSON data
          const sanitizeForPostgres = (obj: any): any => {
            if (obj === null || obj === undefined) return obj;
            if (typeof obj === 'string') {
              return obj.replace(/\u0000/g, ''); // Remove null characters
            }
            if (Array.isArray(obj)) {
              return obj.map(sanitizeForPostgres);
            }
            if (typeof obj === 'object') {
              const cleaned: any = {};
              for (const key in obj) {
                cleaned[key] = sanitizeForPostgres(obj[key]);
              }
              return cleaned;
            }
            return obj;
          };

          // Update scan status to completed with advanced analysis data
          console.log(`✅ Updating scan ${scanId} status to COMPLETED`);
          const updatedScan = await this.prisma.scan.update({
            where: { id: scanId },
            data: {
              status: 'COMPLETED',
              completedAt: new Date(),
              // Save advanced analysis results (sanitized)
              advancedAnalysis: sanitizeForPostgres(finalState.advancedAnalysis) as any,
              jsSecurity: sanitizeForPostgres(finalState.jsSecurity) as any,
              apiSecurity: sanitizeForPostgres(finalState.apiSecurity) as any
            }
          });

          console.log(`✅ Scan ${scanId} status updated to COMPLETED successfully`);
          console.log(`   📊 Database confirmation: status="${updatedScan.status}", completedAt="${updatedScan.completedAt}"`);

          // 📧 Tarama tamamlandığında email gönder
          try {
            await emailService.sendScanCompletedEmail(scanId);
            console.log(`   📧 Scan completed email sent for scan ${scanId}`);
          } catch (emailError) {
            console.error(`   ⚠️ Failed to send scan completed email:`, emailError);
          }

          // 🔔 Emit scan completion event AFTER database update is confirmed
          this.io?.emit('scanUpdate', {
            scanId,
            status: 'COMPLETED',
            completedAt: updatedScan.completedAt?.toISOString(),
            timestamp: new Date().toISOString()
          });

          console.log(`   🔔 Socket.IO event emitted: scanUpdate with status=COMPLETED`);

          if (finalState.advancedAnalysis) {
            console.log(`   - Advanced Analysis saved: ${Object.keys(finalState.advancedAnalysis.categories || {}).length} categories`);
          }
          if (finalState.jsSecurity) {
            console.log(`   - JS Security saved: ${finalState.jsSecurity.totalLibraries} libraries, ${finalState.jsSecurity.totalVulnerabilities} vulnerabilities`);
          }
          if (finalState.apiSecurity) {
            console.log(`   - API Security saved: ${finalState.apiSecurity.totalEndpoints} endpoints, score: ${finalState.apiSecurity.securityScore}`);
          }

        } catch (dbError) {
          console.error('❌ Error saving final results to database:', dbError);
        }
      }

      // Final emit with all data including scanId
      const completeState = {
        ...finalState,
        scanId: scanId || undefined, // Add scanId to the emit
        workflowId,
        status: 'COMPLETED'
      };

      this.workflowStates.set(workflowId, completeState);

      // Clean up tracking Sets
      this.timeoutCompletedWorkflows.delete(workflowId);
      this.stoppedWorkflows.delete(workflowId);
      this.pausedWorkflows.delete(workflowId);

      this.io?.emit('workflowUpdate', completeState);
      this.io?.emit('workflowComplete', completeState);

      // Also emit scan-specific update if scanId is available
      if (scanId) {
        this.io?.to(`scan-${scanId}`).emit('scanUpdate', {
          scanId,
          status: 'completed',
          progress: 100,
          phase: 'COMPLETED',
          message: 'Scan completed successfully',
          timestamp: new Date().toISOString()
        });
      }

      console.log(`✅ Workflow ${workflowId} completed successfully (timeout-based: ${this.timeoutCompletedWorkflows.has(workflowId) ? 'YES' : 'NO'})`);

    } catch (error) {
      console.error(`❌ Workflow ${workflowId} failed:`, error);

      const errorState = {
        workflowId,
        phase: 'FAILED',
        progress: 0,
        status: 'FAILED',
        error: error instanceof Error ? error.message : 'Unknown error',
        endTime: new Date(),
        scanId: scanId || undefined // Add scanId to error state
      };

      this.workflowStates.set(workflowId, errorState);
      this.io?.emit('workflowUpdate', errorState);
      this.io?.emit('workflowError', errorState);

      // Also emit scan-specific error if scanId is available
      if (scanId) {
        this.io?.to(`scan-${scanId}`).emit('scanUpdate', {
          scanId,
          status: 'failed',
          progress: 0,
          phase: 'FAILED',
          message: `Scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
          timestamp: new Date().toISOString()
        });

        // Update database scan status to FAILED
        try {
          await this.prisma.scan.update({
            where: { id: scanId },
            data: {
              status: 'FAILED',
              completedAt: new Date()
            }
          });
        } catch (dbError) {
          console.error('❌ Error updating scan status to FAILED:', dbError);
        }
      }

      throw error;
    }
  }

  // Helper method to update workflow progress
  private async updateWorkflowProgress(workflowId: string, phase: string, progress: number, message: string, scanId?: string): Promise<void> {
    const existingState = this.workflowStates.get(workflowId) || {};

    // Try to collect current URLs and vulnerabilities
    let currentUrls: any[] = existingState.urlsFound || [];
    let currentVulnerabilities: any[] = existingState.vulnerabilities || [];

    if (phase.includes('SPIDER') || phase.includes('SCAN')) {
      try {
        // Fetch URLs from history with better error handling
        let history: any[] = [];
        try {
          history = await this.getHistory();
        } catch (historyError) {
          // Continue with empty history instead of failing
          history = [];
        }

        // Get target URL for filtering
        const targetUrl = existingState.targetUrl;
        const targetDomain = targetUrl ? new URL(targetUrl).hostname : null;

        // Map URLs
        const allUrls = history.slice(0, 1000).map((entry: any) => ({
          url: entry.uri || entry.url || '',
          method: entry.method || 'GET',
          statusCode: entry.code || entry.statusCode || 200,
          responseTime: entry.responseTimeInMs || entry.responseTime || 0,
          contentType: entry.responseHeaders?.find((h: any) =>
            h.name?.toLowerCase() === 'content-type')?.value || 'text/html',
          size: entry.responseBody?.length || entry.size || 0,
          timestamp: entry.timestamp || new Date().toISOString()
        }));

        // Filter URLs: only include those matching target domain
        if (targetDomain) {
          currentUrls = allUrls.filter((urlEntry: any) => {
            try {
              if (!urlEntry.url) return false;
              const urlDomain = new URL(urlEntry.url).hostname;
              return urlDomain === targetDomain;
            } catch {
              // If URL parsing fails, exclude this URL
              return false;
            }
          });

        } else {
          currentUrls = allUrls;
        }

        // Fetch vulnerabilities from alerts
        try {
          const alertsResponse = await this.zapClient.get('core/view/alerts/');
          if (alertsResponse.data?.alerts) {
            // Get target URL for filtering
            const targetUrl = existingState.targetUrl;
            const targetDomain = targetUrl ? new URL(targetUrl).hostname : null;

            // Map and filter vulnerabilities to only include those from target URL
            const allVulnerabilities = alertsResponse.data.alerts.map((alert: any) => ({
              id: alert.alertId || alert.id,
              name: alert.alert || alert.name || 'Unknown Alert',
              risk: this.mapSeverity(alert.risk || alert.severity || 'Low'),
              confidence: alert.confidence || 'Medium',
              url: alert.url || '',
              param: alert.param || '',
              attack: alert.attack || '',
              evidence: alert.evidence || '',
              description: alert.description || '',
              solution: alert.solution || '',
              reference: alert.reference || '',
              cweid: alert.cweid || '',
              wascid: alert.wascid || '',
              sourceid: alert.sourceid || ''
            }));

            // Filter vulnerabilities: only include those matching target domain
            if (targetDomain) {
              currentVulnerabilities = allVulnerabilities.filter((vuln: any) => {
                try {
                  if (!vuln.url) return false;
                  const vulnDomain = new URL(vuln.url).hostname;
                  return vulnDomain === targetDomain;
                } catch {
                  // If URL parsing fails, exclude this vulnerability
                  return false;
                }
              });

            } else {
              currentVulnerabilities = allVulnerabilities;
            }
          }
        } catch (alertError) {
        }

        // Save URLs and vulnerabilities to database if scanId is provided
        if (scanId) {
          try {
            // Save URLs if we have any
            if (currentUrls.length > 0) {
              // Delete existing URLs for this scan to avoid duplicates
              await this.prisma.scanUrl.deleteMany({
                where: { scanId }
              });

              // Insert new URLs
              await this.prisma.scanUrl.createMany({
                data: currentUrls.map(url => ({
                  scanId,
                  url: url.url,
                  method: url.method,
                  statusCode: url.statusCode,
                  responseTime: url.responseTime,
                  contentType: url.contentType,
                  size: url.size,
                  timestamp: url.timestamp && !isNaN(Date.parse(url.timestamp)) ? new Date(url.timestamp) : new Date()
                }))
              });

            }

            // Save vulnerabilities - only insert new ones, don't delete existing
            if (currentVulnerabilities.length > 0) {
              // Get existing vulnerability alert IDs to avoid duplicates
              const existingVulns = await this.prisma.vulnerability.findMany({
                where: { scanId },
                select: { zapAlertId: true }
              });

              const existingAlertIds = new Set(existingVulns.map(v => v.zapAlertId).filter(id => id !== null));

              // Filter out vulnerabilities that already exist
              const newVulnerabilities = currentVulnerabilities.filter(vuln =>
                !existingAlertIds.has(vuln.id?.toString() || '')
              );

              // Only insert truly new vulnerabilities
              if (newVulnerabilities.length > 0) {
                await this.prisma.vulnerability.createMany({
                  data: newVulnerabilities.map(vuln => ({
                    scanId,
                    zapAlertId: vuln.id?.toString() || '',
                    name: vuln.name,
                    severity: vuln.risk,
                    confidence: vuln.confidence,
                    affectedUrl: vuln.url,
                    param: vuln.param,
                    attack: vuln.attack,
                    evidence: vuln.evidence,
                    description: vuln.description,
                    solution: vuln.solution,
                    reference: vuln.reference,
                    cweid: vuln.cweid?.toString() || '',
                    wascid: vuln.wascid?.toString() || '',
                    otherInfo: vuln.sourceid?.toString() || ''
                  }))
                });

                console.log(`🔒 Added ${newVulnerabilities.length} new vulnerabilities (total: ${currentVulnerabilities.length}, already had: ${existingAlertIds.size})`);
              } else {
                console.log(`✅ No new vulnerabilities to add (already have ${existingAlertIds.size})`);
              }
            }
          } catch (dbError) {
            console.error('❌ Error saving data to database:', dbError);
          }
        }
      } catch (error) {
      }
    }

    // Determine status based on phase and progress
    let status = 'RUNNING';
    if (phase === 'COMPLETED' || progress >= 100) {
      status = 'COMPLETED';
    } else if (phase === 'FAILED' || phase === 'ERROR') {
      status = 'FAILED';
    } else if (phase === 'STOPPED') {
      status = 'STOPPED';
    }

    const state = {
      ...existingState,
      workflowId,
      phase,
      progress: Math.round(progress),
      status,
      message,
      urlsFound: currentUrls,
      vulnerabilities: currentVulnerabilities,
      timestamp: new Date().toISOString()
    };

    this.workflowStates.set(workflowId, state);
    this.io?.emit('workflowProgress', state);
    this.io?.emit('workflowUpdate', state);

  }

  // Helper method to map ZAP severity to our format
  private mapSeverity(zapSeverity: string): string {
    const severity = zapSeverity.toUpperCase();
    switch (severity) {
      case 'HIGH': return 'HIGH';
      case 'MEDIUM': return 'MEDIUM';
      case 'LOW': return 'LOW';
      case 'INFORMATIONAL':
      case 'INFO': return 'INFO';
      default: return 'LOW';
    }
  }

  // Get workflow progress
  async getWorkflowProgress(workflowId: string): Promise<any> {
    const state = this.workflowStates.get(workflowId);

    if (!state) {
      return {
        workflowId,
        phase: 'NOT_FOUND',
        progress: 0,
        status: 'NOT_FOUND',
        message: 'Workflow not found'
      };
    }

    // Return stored state
    return {
      workflowId: state.workflowId,
      phase: state.phase,
      progress: state.progress || 0,
      status: state.status,
      message: state.message || '',
      vulnerabilities: state.vulnerabilities || [],
      urlsFound: state.urlsFound || [],
      summary: state.summary,
      startTime: state.startTime,
      endTime: state.endTime,
      error: state.error
    };
  }

  // Helper method for ZAP API requests
  private async zapRequest(endpoint: string, params?: any): Promise<any> {
    try {
      const response = await this.zapClient.get(endpoint, { params });
      return response.data;
    } catch (error) {
      console.error(`ZAP API request failed for ${endpoint}:`, error);
      throw error;
    }
  }

  // Check if workflow should stop (but ignore timeout-completed workflows)
  private isWorkflowStopped(workflowId: string): boolean {
    // If workflow completed via timeout, don't treat it as stopped
    if (this.timeoutCompletedWorkflows.has(workflowId)) {
      return false;
    }
    return this.stoppedWorkflows.has(workflowId);
  }

  // Stop all ZAP scans
  async stopAllScans(): Promise<void> {

    try {
      // Stop all active scans
      await this.zapRequest('/JSON/ascan/action/stopAllScans/');

      // Stop spider
      await this.zapRequest('/JSON/spider/action/stopAllScans/');

      // Stop ajax spider
      await this.zapRequest('/JSON/ajaxSpider/action/stop/');

    } catch (error) {
      console.error('❌ Error stopping all scans:', error);
      throw error;
    }
  }

  // Stop spider scan
  async stopSpider(scanId?: string): Promise<void> {

    try {
      if (scanId) {
        await this.zapRequest('/JSON/spider/action/stop/', { scanId });
      } else {
        await this.zapRequest('/JSON/spider/action/stopAllScans/');
      }

    } catch (error) {
      console.error('❌ Error stopping spider scan:', error);
      throw error;
    }
  }

  // Stop ajax spider scan
  async stopAjaxSpider(): Promise<void> {

    try {
      await this.zapRequest('/JSON/ajaxSpider/action/stop/');
    } catch (error) {
      console.error('❌ Error stopping ajax spider scan:', error);
      throw error;
    }
  }

  // Stop active scan
  async stopActiveScan(scanId?: string): Promise<void> {

    try {
      if (scanId) {
        await this.zapRequest('/JSON/ascan/action/stop/', { scanId });
      } else {
        await this.zapRequest('/JSON/ascan/action/stopAllScans/');
      }

    } catch (error) {
      console.error('❌ Error stopping active scan:', error);
      throw error;
    }
  }

  // Pause active scan
  async pauseActiveScan(scanId: string): Promise<void> {

    try {
      await this.zapRequest('/JSON/ascan/action/pause/', { scanId });
    } catch (error) {
      console.error('❌ Error pausing active scan:', error);
      throw error;
    }
  }

  // Resume active scan
  async resumeActiveScan(scanId: string): Promise<void> {

    try {
      await this.zapRequest('/JSON/ascan/action/resume/', { scanId });
    } catch (error) {
      console.error('❌ Error resuming active scan:', error);
      throw error;
    }
  }

  // Stop workflow
  async stopWorkflow(workflowId: string): Promise<void> {

    try {
      // Mark workflow as stopped immediately
      this.stoppedWorkflows.add(workflowId);

      // Get workflow from storage
      const workflow = this.workflowProgress.get(workflowId);
      if (!workflow) {
        // Still try to stop all scans
        await this.stopAllScans();
        return;
      }

      // Mark workflow as stopped
      workflow.status = 'STOPPED';
      workflow.phase = 'STOPPED';
      workflow.message = 'Workflow stopped by user';

      // Stop all active scans
      try {
        // Stop spider if running
        if (workflow.spiderScanId) {
          await this.zapRequest('/JSON/spider/action/stop/', { scanId: workflow.spiderScanId });
        }

        // Stop ajax spider if running
        if (workflow.ajaxSpiderScanId) {
          await this.zapRequest('/JSON/ajaxSpider/action/stop/');
        }

        // Stop active scan if running
        if (workflow.activeScanId) {
          await this.zapRequest('/JSON/ascan/action/stop/', { scanId: workflow.activeScanId });
        }

      } catch (error) {
        console.error(`⚠️ Error stopping scans for workflow ${workflowId}:`, error);
      }

      // Update progress one final time
      await this.updateWorkflowProgress(workflowId, 'STOPPED', workflow.progress, 'Workflow stopped by user');

      // Emit final status update
      if (this.io) {
        this.io.emit('workflowUpdate', {
          workflowId,
          status: 'STOPPED',
          phase: 'STOPPED',
          progress: workflow.progress,
          message: 'Workflow stopped by user',
          timestamp: new Date().toISOString()
        });
      }


    } catch (error) {
      console.error(`❌ Error stopping workflow ${workflowId}:`, error);
      throw error;
    }
  }

  // Pause workflow
  async pauseWorkflow(workflowId: string): Promise<void> {

    try {
      // Mark workflow as paused
      this.pausedWorkflows.add(workflowId);

      // Get workflow from storage
      const workflow = this.workflowProgress.get(workflowId);
      if (!workflow) {
        return;
      }

      // Mark workflow as paused
      workflow.status = 'PAUSED';
      workflow.message = 'Workflow paused by user';

      // Pause all active scans
      try {
        // Pause spider if running
        if (workflow.spiderScanId) {
          await this.zapRequest('/JSON/spider/action/pause/', { scanId: workflow.spiderScanId });
        }

        // Pause ajax spider if running
        if (workflow.ajaxSpiderScanId) {
          await this.zapRequest('/JSON/ajaxSpider/action/stop/'); // ZAP doesn't have pause for AJAX spider, stop instead
        }

        // Pause active scan if running
        if (workflow.activeScanId) {
          await this.zapRequest('/JSON/ascan/action/pause/', { scanId: workflow.activeScanId });
        }

      } catch (error) {
        console.error(`⚠️ Error pausing scans for workflow ${workflowId}:`, error);
      }

      // Update progress
      await this.updateWorkflowProgress(workflowId, 'PAUSED', workflow.progress, 'Workflow paused by user');

      // Emit status update
      if (this.io) {
        this.io.emit('workflowUpdate', {
          workflowId,
          status: 'PAUSED',
          phase: workflow.phase,
          progress: workflow.progress,
          message: 'Workflow paused by user',
          timestamp: new Date().toISOString()
        });
      }


    } catch (error) {
      console.error(`❌ Error pausing workflow ${workflowId}:`, error);
      throw error;
    }
  }

  // Resume workflow
  async resumeWorkflow(workflowId: string): Promise<void> {

    try {
      // Check if workflow was paused
      if (!this.pausedWorkflows.has(workflowId)) {
        return;
      }

      // Remove from paused set
      this.pausedWorkflows.delete(workflowId);

      // Get workflow from storage
      const workflow = this.workflowProgress.get(workflowId);
      if (!workflow) {
        return;
      }

      // Mark workflow as running
      workflow.status = 'RUNNING';
      workflow.message = 'Workflow resumed by user';

      // Resume all paused scans
      try {
        // Resume spider if it was running
        if (workflow.spiderScanId) {
          // Check if spider was paused
          const spiderStatus = await this.zapRequest('/JSON/spider/view/status/', { scanId: workflow.spiderScanId });
          if (spiderStatus.status === 'paused') {
            await this.zapRequest('/JSON/spider/action/resume/', { scanId: workflow.spiderScanId });
          }
        }

        // Resume active scan if it was running
        if (workflow.activeScanId) {
          // Check if scan was paused
          const scanStatus = await this.zapRequest('/JSON/ascan/view/status/', { scanId: workflow.activeScanId });
          if (parseInt(scanStatus.status) < 100) { // Scan was not complete
            await this.zapRequest('/JSON/ascan/action/resume/', { scanId: workflow.activeScanId });
          }
        }

      } catch (error) {
        console.error(`⚠️ Error resuming scans for workflow ${workflowId}:`, error);
      }

      // Update progress
      await this.updateWorkflowProgress(workflowId, workflow.phase, workflow.progress, 'Workflow resumed by user');

      // Emit status update
      if (this.io) {
        this.io.emit('workflowUpdate', {
          workflowId,
          status: 'RUNNING',
          phase: workflow.phase,
          progress: workflow.progress,
          message: 'Workflow resumed by user',
          timestamp: new Date().toISOString()
        });
      }


    } catch (error) {
      console.error(`❌ Error resuming workflow ${workflowId}:`, error);
      throw error;
    }
  }

  // Get scan statistics
  async getScanStatistics(): Promise<any> {
    try {
      const [alerts, hosts] = await Promise.all([
        this.getAlerts(),
        this.getHosts()
      ]);

      return {
        totalAlerts: alerts.length,
        totalHosts: hosts.length,
        lastUpdate: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error getting scan statistics:', error);
      return {
        totalAlerts: 0,
        totalHosts: 0,
        lastUpdate: new Date().toISOString()
      };
    }
  }

  // Get vulnerability analysis
  async getVulnerabilityAnalysis(): Promise<any> {
    try {
      const alerts = await this.getAlerts();
      const riskCounts = { High: 0, Medium: 0, Low: 0, Informational: 0 };

      alerts.forEach((alert: any) => {
        if (riskCounts.hasOwnProperty(alert.risk)) {
          riskCounts[alert.risk as keyof typeof riskCounts]++;
        }
      });

      return {
        totalVulnerabilities: alerts.length,
        riskDistribution: riskCounts,
        lastUpdate: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error getting vulnerability analysis:', error);
      return {
        totalVulnerabilities: 0,
        riskDistribution: { High: 0, Medium: 0, Low: 0, Informational: 0 },
        lastUpdate: new Date().toISOString()
      };
    }
  }

  // Get alerts by risk level
  async getAlertsByRisk(riskLevel: string): Promise<any[]> {
    try {
      const alerts = await this.getAlerts();
      return alerts.filter((alert: any) => alert.risk === riskLevel);
    } catch (error) {
      console.error('Error getting alerts by risk:', error);
      return [];
    }
  }

  // Get AJAX spider progress
  async getAjaxSpiderProgress(): Promise<any> {
    try {
      const status = await this.getAjaxSpiderStatus();
      return {
        status: status.status,
        results: status.numberOfResults || 0,
        messagesInQueue: status.messagesInQueue || 0
      };
    } catch (error) {
      console.error('Error getting AJAX spider progress:', error);
      return { status: 'error', results: 0, messagesInQueue: 0 };
    }
  }

  // Create context with URL
  async createContextWithUrl(url: string): Promise<string> {
    try {
      const contextName = `Context-${Date.now()}`;
      const contextId = await this.createContext(contextName);

      // Include URL in context
      await this.zapClient.get('/JSON/context/action/includeInContext/', {
        params: { contextName, regex: `${url}.*` }
      });

      return contextId;
    } catch (error) {
      console.error('Error creating context with URL:', error);
      throw error;
    }
  }

  // Start spider advanced
  async startSpiderAdvanced(targetUrl: string, options?: any): Promise<string> {
    return this.startSpider(targetUrl, options);
  }

  // Start AJAX spider advanced
  async startAjaxSpiderAdvanced(targetUrl: string, options?: any): Promise<void> {
    await this.startAjaxSpider(targetUrl, options);
  }

  // Start active scan advanced
  async startActiveScanAdvanced(targetUrl: string, options?: any): Promise<string> {
    return this.startActiveScan(targetUrl, options);
  }

  // Generate advanced report
  async generateAdvancedReport(format: 'html' | 'json' | 'xml' | 'pdf' = 'html'): Promise<string | Buffer> {
    switch (format) {
      case 'json':
        return this.generateJsonReport();
      case 'xml':
        return this.generateXmlReport();
      case 'pdf':
        return this.generatePdfReport();
      default:
        return this.generateHtmlReport();
    }
  }

  // =============================================================================
  // COMPREHENSIVE SECURITY TESTING METHODS
  // =============================================================================

  // Enable passive scanning
  async enablePassiveScan(): Promise<void> {
    try {
      await this.zapClient.get('/JSON/pscan/action/setEnabled/', {
        params: { enabled: 'true' }
      });
    } catch (error) {
    }
  }

  // Get passive scan records to scan count
  async getPassiveScanRecordsToScan(): Promise<number> {
    try {
      const response = await this.zapClient.get('/JSON/pscan/view/recordsToScan/');
      return parseInt(response.data.recordsToScan || '0', 10);
    } catch (error) {
      return 0;
    }
  }

  // Wait for passive scan to complete
  async waitForPassiveScan(maxWaitTime: number = 60000): Promise<boolean> {
    const startTime = Date.now();
    const checkInterval = 2000; // Check every 2 seconds

    while (Date.now() - startTime < maxWaitTime) {
      try {
        const recordsToScan = await this.getPassiveScanRecordsToScan();
        if (recordsToScan === 0) {
          return true; // Passive scan completed
        }
        await new Promise(resolve => setTimeout(resolve, checkInterval));
      } catch (error) {
        break;
      }
    }

    return false;
  }

  // Enable all scan policies for comprehensive testing
  async enableAllScanPolicies(): Promise<void> {
    try {
      // Enable all passive scan rules
      await this.enableAllPscanRules();

      // Enable all active scan rules
      await this.zapClient.get('/JSON/ascan/action/enableAllScanners/');

      // Set attack strength to high for comprehensive testing
      await this.zapClient.get('/JSON/ascan/action/setAttackModeStrength/', {
        params: { strength: 'HIGH' }
      });

    } catch (error) {
    }
  }

  // SQL Injection specific tests
  async runSqlInjectionTests(targetUrl: string): Promise<void> {
    try {
      // Enable SQL injection scan rules specifically
      const sqlInjectionRules = [40018, 40019, 40020, 40021, 40022, 40023, 40024, 40025, 40026, 40027];

      for (const ruleId of sqlInjectionRules) {
        try {
          await this.zapClient.get('/JSON/ascan/action/enableScanners/', {
            params: { ids: ruleId.toString() }
          });
        } catch (error) {
          // Continue if specific rule fails
        }
      }

      // Run targeted SQL injection scan
      await this.startActiveScan(targetUrl);

    } catch (error) {
    }
  }

  // XSS (Cross-Site Scripting) specific tests
  async runXssTests(targetUrl: string): Promise<void> {
    try {
      // Enable XSS scan rules specifically
      const xssRules = [40012, 40013, 40014, 40016, 40017];

      for (const ruleId of xssRules) {
        try {
          await this.zapClient.get('/JSON/ascan/action/enableScanners/', {
            params: { ids: ruleId.toString() }
          });
        } catch (error) {
          // Continue if specific rule fails
        }
      }

      // Run targeted XSS scan
      await this.startActiveScan(targetUrl);

    } catch (error) {
    }
  }

  // XXE (XML External Entity) specific tests
  async runXxeTests(targetUrl: string): Promise<void> {
    try {
      // Enable XXE scan rules
      const xxeRules = [90019];

      for (const ruleId of xxeRules) {
        try {
          await this.zapClient.get('/JSON/ascan/action/enableScanners/', {
            params: { ids: ruleId.toString() }
          });
        } catch (error) {
          // Continue if specific rule fails
        }
      }

      // Run targeted XXE scan
      await this.startActiveScan(targetUrl);

    } catch (error) {
    }
  }

  // CSRF (Cross-Site Request Forgery) specific tests
  async runCsrfTests(targetUrl: string): Promise<void> {
    try {
      // Enable CSRF scan rules
      const csrfRules = [20012];

      for (const ruleId of csrfRules) {
        try {
          await this.zapClient.get('/JSON/ascan/action/enableScanners/', {
            params: { ids: ruleId.toString() }
          });
        } catch (error) {
          // Continue if specific rule fails
        }
      }

      // Run targeted CSRF scan
      await this.startActiveScan(targetUrl);

    } catch (error) {
    }
  }

  // Get spider progress with percentage
  async getSpiderProgress(scanId?: string): Promise<number> {
    try {
      // Try with specific scan ID first
      if (scanId) {
        try {
          const response = await this.zapClient.get('/JSON/spider/view/status/', {
            params: { scanId }
          });
          return parseInt(response.data.status) || 0;
        } catch (error) {
        }
      }

      // Fallback: Check if spider is still running
      const statusResponse = await this.zapClient.get('/JSON/spider/view/status/');
      const status = statusResponse.data.status;

      if (status === '100' || status === 100) {
        return 100;
      }

      return parseInt(status) || 100;

    } catch (error) {
      return 100; // Assume completed if we can't get status
    }
  }

  // Get active scan progress with percentage
  async getActiveScanProgress(scanId?: string): Promise<number> {
    try {
      // Try with specific scan ID first
      if (scanId) {
        try {
          const response = await this.zapClient.get('/JSON/ascan/view/status/', {
            params: { scanId }
          });
          return parseInt(response.data.status) || 0;
        } catch (error) {
        }
      }

      // Fallback: Get all active scans and find the first running one
      const allScansResponse = await this.zapClient.get('/JSON/ascan/view/scans/');
      const activeScans = allScansResponse.data.scans || [];

      if (activeScans.length > 0) {
        // Get the most recent scan's progress
        const latestScan = activeScans[activeScans.length - 1];
        return parseInt(latestScan.progress) || 0;
      }

      // If no active scans, assume completed
      return 100;

    } catch (error) {
      return 100; // Assume completed if we can't get status
    }
  }

  // =============================================================================
  // MANUAL PENETRATION TESTING METHODS
  // =============================================================================

  // Break/Intercept functionality
  async setBreakEnabled(enabled: boolean): Promise<void> {
    try {
      await this.zapClient.get('/JSON/break/action/setHttpBreakpoint/', {
        params: {
          string: enabled ? 'on' : 'off',
          location: 'url',
          match: '.*',
          inverse: 'false',
          ignorecase: 'true'
        }
      });
    } catch (error) {
      console.error('Failed to set break enabled:', error);
      throw error;
    }
  }

  // Get intercepted messages
  async getInterceptedMessages(): Promise<any[]> {
    try {
      const response = await this.zapClient.get('/JSON/break/view/httpMessage/');
      return response.data.httpMessage || [];
    } catch (error) {
      console.error('Failed to get intercepted messages:', error);
      return [];
    }
  }

  // Drop intercepted message
  async dropMessage(): Promise<void> {
    try {
      await this.zapClient.get('/JSON/break/action/drop/');
    } catch (error) {
      console.error('Failed to drop message:', error);
      throw error;
    }
  }

  // Continue with intercepted message
  async continueMessage(): Promise<void> {
    try {
      await this.zapClient.get('/JSON/break/action/continue/');
    } catch (error) {
      console.error('Failed to continue message:', error);
      throw error;
    }
  }

  // Modify and continue intercepted message
  async setMessage(message: string): Promise<void> {
    try {
      await this.zapClient.get('/JSON/break/action/setHttpMessage/', {
        params: { httpMessage: message }
      });
    } catch (error) {
      console.error('Failed to set message:', error);
      throw error;
    }
  }

  // Active Scan specific targets
  async activeScanAsUser(targetUrl: string, contextId?: string, userId?: string): Promise<string> {
    try {
      const params: any = { url: targetUrl };
      if (contextId) params.contextId = contextId;
      if (userId) params.userId = userId;

      const response = await this.zapClient.get('/JSON/ascan/action/scanAsUser/', { params });
      return response.data.scan || '';
    } catch (error) {
      console.error('Failed to start active scan as user:', error);
      throw error;
    }
  }

  // Add custom payload to active scan
  async addActiveScanPayload(category: string, payload: string): Promise<void> {
    try {
      await this.zapClient.get('/JSON/ascan/action/addScanPolicy/', {
        params: {
          scanPolicyName: 'Custom',
          alertThreshold: 'MEDIUM',
          attackStrength: 'MEDIUM'
        }
      });
    } catch (error) {
      console.error('Failed to add custom payload:', error);
      throw error;
    }
  }

  // Get site tree for manual exploration
  async getSiteTree(url?: string): Promise<any[]> {
    try {
      const params = url ? { url } : {};
      const response = await this.zapClient.get('/JSON/core/view/sites/', { params });
      return response.data.sites || [];
    } catch (error) {
      console.error('Failed to get site tree:', error);
      return [];
    }
  }

  // Get URLs in site tree
  async getUrlsInSiteTree(site: string): Promise<string[]> {
    try {
      const response = await this.zapClient.get('/JSON/core/view/urls/', {
        params: { baseurl: site }
      });
      return response.data.urls || [];
    } catch (error) {
      console.error('Failed to get URLs in site tree:', error);
      return [];
    }
  }

  // Manual Spider with custom configuration
  async runSpider(targetUrl: string, options: {
    maxChildren?: number;
    recurse?: boolean;
    contextName?: string;
    subtreeOnly?: boolean;
  } = {}): Promise<string> {
    try {
      const params: any = { url: targetUrl };

      if (options.maxChildren) params.maxChildren = options.maxChildren;
      if (options.recurse !== undefined) params.recurse = options.recurse;
      if (options.contextName) params.contextName = options.contextName;
      if (options.subtreeOnly !== undefined) params.subtreeOnly = options.subtreeOnly;

      const response = await this.zapClient.get('/JSON/spider/action/scan/', { params });
      return response.data.scan || '';
    } catch (error) {
      console.error('Failed to run custom spider:', error);
      throw error;
    }
  }

  // Ajax Spider with custom configuration
  async runAjaxSpider(targetUrl: string, options: {
    inScope?: boolean;
    contextName?: string;
    subtreeOnly?: boolean;
    maxDuration?: number;
    maxCrawlDepth?: number;
  } = {}): Promise<void> {
    try {
      const params: any = { url: targetUrl };

      if (options.inScope !== undefined) params.inScope = options.inScope;
      if (options.contextName) params.contextName = options.contextName;
      if (options.subtreeOnly !== undefined) params.subtreeOnly = options.subtreeOnly;
      if (options.maxDuration) params.maxDuration = options.maxDuration;
      if (options.maxCrawlDepth) params.maxCrawlDepth = options.maxCrawlDepth;

      console.log(`🌐 Running AJAX spider with params:`, params);

      await this.zapClient.get('/JSON/ajaxSpider/action/scan/', { params });
    } catch (error) {
      console.error('Failed to run AJAX spider:', error);
      throw error;
    }
  }

  // Get request/response history
  async getHistory(start?: number, count?: number): Promise<any[]> {
    try {
      const params: any = {};
      if (start !== undefined) params.start = start;
      if (count !== undefined) params.count = count;

      // Add timeout to prevent hanging
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

      try {
        const response = await this.zapClient.get('/JSON/core/view/messages/', {
          params,
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        return response.data.messages || [];
      } catch (fetchError: any) {
        clearTimeout(timeoutId);
        if (fetchError.name === 'AbortError' || fetchError.code === 'ECONNABORTED') {
        } else {
        }
        return [];
      }
    } catch (error) {
      console.error('❌ Failed to get history:', error);
      return [];
    }
  }

  // Get specific message by ID
  async getMessage(messageId: string): Promise<any> {
    try {
      const response = await this.zapClient.get('/JSON/core/view/message/', {
        params: { id: messageId }
      });
      return response.data.message || null;
    } catch (error) {
      console.error('Failed to get message:', error);
      return null;
    }
  }

  // Send custom request through ZAP
  async sendRequest(request: string): Promise<any> {
    try {
      const response = await this.zapClient.get('/JSON/core/action/sendRequest/', {
        params: { request }
      });
      return response.data;
    } catch (error) {
      console.error('Failed to send custom request:', error);
      throw error;
    }
  }

  // Manual Active Scan with specific payloads
  async runActiveScanWithPayloads(targetUrl: string, payloads: string[]): Promise<string> {
    try {
      // First create a custom scan policy
      const policyName = `Custom_${Date.now()}`;
      await this.zapClient.get('/JSON/ascan/action/addScanPolicy/', {
        params: {
          scanPolicyName: policyName,
          alertThreshold: 'LOW',
          attackStrength: 'HIGH'
        }
      });

      // Start scan with custom policy
      const response = await this.zapClient.get('/JSON/ascan/action/scan/', {
        params: {
          url: targetUrl,
          scanPolicyName: policyName
        }
      });

      return response.data.scan || '';
    } catch (error) {
      console.error('Failed to run active scan with payloads:', error);
      throw error;
    }
  }

  // Context management for manual testing
  async createContextWithUrls(contextName: string, includeInContext: string[]): Promise<string> {
    try {
      const response = await this.zapClient.get('/JSON/context/action/newContext/', {
        params: { contextName }
      });

      const contextId = response.data.contextId;

      // Add URLs to context
      for (const url of includeInContext) {
        await this.zapClient.get('/JSON/context/action/includeInContext/', {
          params: { contextName, regex: url }
        });
      }

      return contextId;
    } catch (error) {
      console.error('Failed to create context:', error);
      throw error;
    }
  }

  // Authentication configuration
  async setAuthenticationMethod(contextId: string, authMethodName: string, authMethodConfigParams: string): Promise<void> {
    try {
      await this.zapClient.get('/JSON/authentication/action/setAuthenticationMethod/', {
        params: {
          contextId,
          authMethodName,
          authMethodConfigParams
        }
      });
    } catch (error) {
      console.error('Failed to set authentication method:', error);
      throw error;
    }
  }

  // Session management
  async setSessionManagementMethod(contextId: string, methodName: string, methodConfigParams: string): Promise<void> {
    try {
      await this.zapClient.get('/JSON/sessionManagement/action/setSessionManagementMethod/', {
        params: {
          contextId,
          methodName,
          methodConfigParams
        }
      });
    } catch (error) {
      console.error('Failed to set session management method:', error);
      throw error;
    }
  }

  // Scan specific node in site tree
  async scanNode(url: string, method?: string, postData?: string): Promise<string> {
    try {
      const params: any = { url };
      if (method) params.method = method;
      if (postData) params.postData = postData;

      const response = await this.zapClient.get('/JSON/ascan/action/scan/', { params });
      return response.data.scan || '';
    } catch (error) {
      console.error('Failed to scan node:', error);
      throw error;
    }
  }

  // Fuzzing functionality
  async startFuzzer(messageId: string, fuzzLocations: string): Promise<string> {
    try {
      const response = await this.zapClient.get('/JSON/fuzzer/action/addFuzzer/', {
        params: {
          messageId,
          fuzzLocations
        }
      });
      return response.data.fuzzer || '';
    } catch (error) {
      console.error('Failed to start fuzzer:', error);
      throw error;
    }
  }

  // Get fuzzer results
  async getFuzzerResults(fuzzerId: string): Promise<any[]> {
    try {
      const response = await this.zapClient.get('/JSON/fuzzer/view/fuzzerResults/', {
        params: { fuzzerId }
      });
      return response.data.fuzzerResults || [];
    } catch (error) {
      console.error('Failed to get fuzzer results:', error);
      return [];
    }
  }

  // Technology detection
  async getTechnology(site: string): Promise<any[]> {
    try {
      const response = await this.zapClient.get('/JSON/technology/view/technologyList/', {
        params: { url: site }
      });
      return response.data.technology || [];
    } catch (error) {
      console.error('Failed to get technology:', error);
      return [];
    }
  }

  // Passive scan configuration
  async enablePassiveScanTags(enabled: boolean): Promise<void> {
    try {
      await this.zapClient.get('/JSON/pscan/action/setEnabled/', {
        params: { enabled: enabled.toString() }
      });
    } catch (error) {
      console.error('Failed to set passive scan enabled:', error);
      throw error;
    }
  }

  // Set scan mode (Safe, Protected, Standard, Attack)
  async setScanMode(mode: 'Safe' | 'Protected' | 'Standard' | 'Attack'): Promise<void> {
    try {
      await this.zapClient.get('/JSON/core/action/setMode/', {
        params: { mode }
      });
    } catch (error) {
      console.error('Failed to set scan mode:', error);
      throw error;
    }
  }

  // Get scan mode
  async getScanMode(): Promise<string> {
    try {
      const response = await this.zapClient.get('/JSON/core/view/mode/');
      return response.data.mode || 'Standard';
    } catch (error) {
      console.error('Failed to get scan mode:', error);
      return 'Standard';
    }
  }

  // Manual script execution
  async runScript(scriptName: string, scriptType: string = 'standalone', scriptEngine: string = 'ECMAScript', scriptDescription?: string, scriptText?: string): Promise<any> {
    try {
      if (scriptText) {
        // Load script first
        await this.zapClient.get('/JSON/script/action/load/', {
          params: {
            scriptName,
            scriptType,
            scriptEngine,
            scriptDescription: scriptDescription || '',
            scriptText
          }
        });
      }

      // Run script
      const response = await this.zapClient.get('/JSON/script/action/runStandAloneScript/', {
        params: { scriptName }
      });

      return response.data;
    } catch (error) {
      console.error('Failed to run script:', error);
      throw error;
    }
  }

  // Get scripts
  async getScripts(scriptType?: string): Promise<any[]> {
    try {
      const params = scriptType ? { scriptType } : {};
      const response = await this.zapClient.get('/JSON/script/view/scripts/', { params });
      return response.data.scripts || [];
    } catch (error) {
      console.error('Failed to get scripts:', error);
      return [];
    }
  }

  // =============================================================================
  // REAL-TIME MONITORING METHODS
  // =============================================================================

  /**
   * Start real-time monitoring for alerts and URLs during scan
   */
  async startRealTimeMonitoring(scanId: string, targetUrl: string): Promise<void> {
    if (this.realTimeMonitors.has(scanId)) {
      clearInterval(this.realTimeMonitors.get(scanId));
    }


    let lastAlertCount = 0;
    let lastUrlCount = 0;
    let knownUrls = new Set<string>();
    let knownAlerts = new Set<string>();

    const monitor = setInterval(async () => {
      try {
        // Monitor alerts in real-time
        const currentAlerts = await this.getAlertsForTarget(targetUrl);
        const newAlerts = currentAlerts.filter(alert =>
          !knownAlerts.has(alert.alertId || alert.id)
        );

        if (newAlerts.length > 0) {

          // Add to known alerts
          newAlerts.forEach(alert => knownAlerts.add(alert.alertId || alert.id));

          // Emit real-time alert updates
          if (this.io) {
            newAlerts.forEach(alert => {
              this.io.to(`scan-${scanId}`).emit('vulnerabilityFound', {
                scanId,
                alert: {
                  id: alert.alertId || alert.id,
                  name: alert.alert || alert.name,
                  risk: this.mapSeverity(alert.risk || 'Low'),
                  confidence: alert.confidence || 'Medium',
                  url: alert.url,
                  param: alert.param,
                  description: alert.description,
                  timestamp: new Date().toISOString()
                },
                totalAlerts: currentAlerts.length
              });
            });
          }

          // Save new alerts to database
          try {
            await this.saveAlertsToDatabase(scanId, newAlerts);
          } catch (dbError) {
            console.error('Failed to save alerts to database:', dbError);
          }
        }

        // Monitor URLs in real-time
        const currentUrls = await this.getUrlsForTarget(targetUrl);
        const newUrls = currentUrls.filter(url => !knownUrls.has(url));

        if (newUrls.length > 0) {

          // Add to known URLs
          newUrls.forEach(url => knownUrls.add(url));

          // Emit real-time URL updates
          if (this.io) {
            newUrls.forEach(url => {
              this.io.to(`scan-${scanId}`).emit('urlFound', {
                scanId,
                url,
                method: 'GET',
                statusCode: 200,
                timestamp: new Date().toISOString(),
                totalUrls: currentUrls.length
              });
            });
          }

          // Save new URLs to database
          try {
            await this.saveUrlsToDatabase(scanId, newUrls);
          } catch (dbError) {
            console.error('Failed to save URLs to database:', dbError);
          }
        }

        // Update progress with current counts
        if (this.io) {
          this.io.to(`scan-${scanId}`).emit('scanProgress', {
            scanId,
            alertsFound: currentAlerts.length,
            urlsFound: currentUrls.length,
            newAlertsCount: newAlerts.length,
            newUrlsCount: newUrls.length,
            timestamp: new Date().toISOString()
          });
        }

      } catch (error) {
        console.error(`Real-time monitoring error for scan ${scanId}:`, error);
      }
    }, 2000); // Check every 2 seconds

    this.realTimeMonitors.set(scanId, monitor);
  }

  /**
   * Stop real-time monitoring for a scan
   */
  async stopRealTimeMonitoring(scanId: string): Promise<void> {
    const monitor = this.realTimeMonitors.get(scanId);
    if (monitor) {
      clearInterval(monitor);
      this.realTimeMonitors.delete(scanId);
    }
  }

  /**
   * Get alerts specific to a target URL
   */
  private async getAlertsForTarget(targetUrl: string): Promise<any[]> {
    try {
      const response = await this.zapClient.get('/JSON/core/view/alerts/', {
        params: { baseurl: targetUrl }
      });
      return response.data.alerts || [];
    } catch (error) {
      return [];
    }
  }

  /**
   * Get URLs specific to a target
   */
  private async getUrlsForTarget(targetUrl: string): Promise<string[]> {
    try {
      const [historyResponse, sitesResponse] = await Promise.all([
        this.zapClient.get('/JSON/core/view/history/'),
        this.zapClient.get('/JSON/core/view/sites/')
      ]);

      const urls = new Set<string>();

      // Extract URLs from history
      if (historyResponse.data?.history) {
        historyResponse.data.history.forEach((entry: any) => {
          const url = entry.uri || entry.url;
          if (url && url.startsWith(targetUrl)) {
            urls.add(url);
          }
        });
      }

      // Extract URLs from sites
      if (sitesResponse.data?.sites) {
        sitesResponse.data.sites.forEach((site: string) => {
          if (site.startsWith(targetUrl)) {
            urls.add(site);
          }
        });
      }

      return Array.from(urls);
    } catch (error) {
      return [];
    }
  }

  /**
   * Save alerts to database
   */
  private async saveAlertsToDatabase(scanId: string, alerts: any[]): Promise<void> {
    try {
      const vulnerabilities = alerts.map(alert => ({
        scanId,
        name: alert.alert || alert.name || 'Unknown Alert',
        severity: this.mapSeverity(alert.risk || 'Low'),
        confidence: alert.confidence || 'Medium',
        url: alert.url || '',
        parameter: alert.param || '',
        attack: alert.attack || '',
        evidence: alert.evidence || '',
        description: alert.description || '',
        solution: alert.solution || '',
        reference: alert.reference || '',
        cweid: alert.cweid ? alert.cweid.toString() : null,
        wascid: alert.wascid ? alert.wascid.toString() : null,
        sourceid: alert.sourceid?.toString() || ''
      }));

      await this.prisma.vulnerability.createMany({
        data: vulnerabilities,
        skipDuplicates: true
      });

    } catch (error) {
      console.error('Failed to save alerts to database:', error);
    }
  }

  /**
   * Save URLs to database
   */
  private async saveUrlsToDatabase(scanId: string, urls: string[]): Promise<void> {
    try {
      const urlRecords = urls.map(url => ({
        scanId,
        url,
        method: 'GET',
        statusCode: 200,
        responseTime: 0,
        contentType: 'text/html',
        size: 0,
        timestamp: new Date().toISOString()
      }));

      await this.prisma.scanUrl.createMany({
        data: urlRecords,
        skipDuplicates: true
      });

    } catch (error) {
      console.error('Failed to save URLs to database:', error);
    }
  }
}
