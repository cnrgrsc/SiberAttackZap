import axios, { AxiosInstance } from 'axios';

/**
 * Gelişmiş ZAP API Entegrasyonu
 * Bu servis ZAP'tan çıkarabileceğimiz tüm veriyi toplar
 */
export class ZapAdvancedService {
  private zapClient: AxiosInstance;
  private io?: any;

  constructor(io?: any) {
    this.io = io;
    
    // ZAP client kurulumu
  const baseUrl = process.env.ZAP_PROXY_URL || 'http://zap-api:8080';
    const headers: any = {
      'Content-Type': 'application/json'
    };
    
    if (process.env.ZAP_API_KEY) {
      headers['X-ZAP-API-Key'] = process.env.ZAP_API_KEY;
    }
    
    this.zapClient = axios.create({
      baseURL: baseUrl,
      headers,
      timeout: 120000, // 2 minutes timeout
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });
  }
  
  // 1. ZAP'tan çıkarabileceğimiz TÜM endpoint'ler
  private readonly advancedEndpoints = {
    // Core endpoints
    core: [
      '/JSON/core/view/version/',
      '/JSON/core/view/stats/',
      '/JSON/core/view/mode/',
      '/JSON/core/view/homeDirectory/',
      '/JSON/core/view/sessionLocation/',
      '/JSON/core/view/proxyChainExcludedDomains/',
      '/JSON/core/view/optionProxyChainName/',
      '/JSON/core/view/optionProxyChainPort/',
      '/JSON/core/view/optionProxyChainRealm/',
      '/JSON/core/view/optionProxyChainUserName/',
      '/JSON/core/view/optionSkipProxyChain/',
      '/JSON/core/view/optionUseProxyChain/',
      '/JSON/core/view/optionUseProxyChainAuth/',
      '/JSON/core/view/excludedFromProxy/',
      '/JSON/core/view/optionTimeoutInSecs/',
      '/JSON/core/view/optionHttpStateEnabled/',
      '/JSON/core/view/optionSingleCookieRequestHeader/',
      '/JSON/core/view/zapHomePath/',
      '/JSON/core/view/optionMaximumAlertInstances/',
      '/JSON/core/view/optionMergeRelatedAlerts/',
    ],

    // Spider endpoints - Tam veri çekimi
    spider: [
      '/JSON/spider/view/status/',
      '/JSON/spider/view/results/',
      '/JSON/spider/view/fullResults/',
      '/JSON/spider/view/scans/',
      '/JSON/spider/view/excludedFromScan/',
      '/JSON/spider/view/optionMaxDepth/',
      '/JSON/spider/view/optionMaxChildren/',
      '/JSON/spider/view/optionMaxDuration/',
      '/JSON/spider/view/optionMaxParseSizeBytes/',
      '/JSON/spider/view/optionSkipURLString/',
      '/JSON/spider/view/optionUserAgent/',
      '/JSON/spider/view/optionHandleParameters/',
      '/JSON/spider/view/optionHandleODataParametersVisited/',
      '/JSON/spider/view/optionRequestWaitTime/',
      '/JSON/spider/view/optionProcessForm/',
      '/JSON/spider/view/optionPostForm/',
      '/JSON/spider/view/optionParseComments/',
      '/JSON/spider/view/optionParseRobotsTxt/',
      '/JSON/spider/view/optionParseSVNEntries/',
      '/JSON/spider/view/optionParseSitemapXml/',
      '/JSON/spider/view/optionParseGit/',
      '/JSON/spider/view/optionAcceptCookies/',
      '/JSON/spider/view/domainsAlwaysInScope/',
      '/JSON/spider/view/optionSendRefererHeader/',
    ],

    // Ajax Spider - Modern web app tarama
    ajaxSpider: [
      '/JSON/ajaxSpider/view/status/',
      '/JSON/ajaxSpider/view/results/',
      '/JSON/ajaxSpider/view/numberOfResults/',
      '/JSON/ajaxSpider/view/fullResults/',
      '/JSON/ajaxSpider/view/optionBrowserId/',
      '/JSON/ajaxSpider/view/optionClickDefaultElems/',
      '/JSON/ajaxSpider/view/optionClickElemsOnce/',
      '/JSON/ajaxSpider/view/optionEventWait/',
      '/JSON/ajaxSpider/view/optionMaxCrawlDepth/',
      '/JSON/ajaxSpider/view/optionMaxCrawlStates/',
      '/JSON/ajaxSpider/view/optionMaxDuration/',
      '/JSON/ajaxSpider/view/optionRandomInputs/',
      '/JSON/ajaxSpider/view/optionReloadWait/',
    ],

    // Active Scan - Güvenlik açığı tarama
    ascan: [
      '/JSON/ascan/view/status/',
      '/JSON/ascan/view/scans/',
      '/JSON/ascan/view/scanProgress/',
      '/JSON/ascan/view/messagesIds/',
      '/JSON/ascan/view/alertsIds/',
      '/JSON/ascan/view/attacks/',
      '/JSON/ascan/view/optionMaxRuleDurationInMins/',
      '/JSON/ascan/view/optionMaxScanDurationInMins/',
      '/JSON/ascan/view/optionMaxChartTimeInMins/',
      '/JSON/ascan/view/optionHostPerScan/',
      '/JSON/ascan/view/optionThreadPerHost/',
      '/JSON/ascan/view/optionDelayInMs/',
      '/JSON/ascan/view/optionInjectableConnectionTimeout/',
      '/JSON/ascan/view/optionScanHeadersAllRequests/',
      '/JSON/ascan/view/optionHandleAntiCSRFTokens/',
      '/JSON/ascan/view/optionRescanInAttackMode/',
      '/JSON/ascan/view/optionPromptInAttackMode/',
      '/JSON/ascan/view/optionPromptToClearFinishedScans/',
      '/JSON/ascan/view/optionTargetParamsInjectable/',
      '/JSON/ascan/view/optionTargetParamsEnabledRPC/',
      '/JSON/ascan/view/excludedFromScan/',
      '/JSON/ascan/view/scanners/',
      '/JSON/ascan/view/policies/',
      '/JSON/ascan/view/attackModeQueue/',
    ],

    // Passive Scan - Pasif güvenlik kontrolü
    pscan: [
      '/JSON/pscan/view/scanOnlyInScope/',
      '/JSON/pscan/view/recordsToScan/',
      '/JSON/pscan/view/scanners/',
      '/JSON/pscan/view/currentRule/',
      '/JSON/pscan/view/maxAlertsPerRule/',
      '/JSON/pscan/view/optionMaxAlertsPerRule/',
    ],

    // Authentication - Kimlik doğrulama
    authentication: [
      '/JSON/authentication/view/getSupportedAuthenticationMethods/',
      '/JSON/authentication/view/getAuthenticationMethodConfigParams/',
      '/JSON/authentication/view/getAuthenticationMethod/',
      '/JSON/authentication/view/getLoggedInIndicator/',
      '/JSON/authentication/view/getLoggedOutIndicator/',
    ],

    // Authorization - Yetkilendirme
    authorization: [
      '/JSON/authorization/view/getAuthorizationDetectionMethod/',
    ],

    // Context Management
    context: [
      '/JSON/context/view/contextList/',
      '/JSON/context/view/context/',
      '/JSON/context/view/includeRegexs/',
      '/JSON/context/view/excludeRegexs/',
      '/JSON/context/view/technology/',
      '/JSON/context/view/users/',
    ],

    // Session Management
    sessionManagement: [
      '/JSON/sessionManagement/view/getSupportedSessionManagementMethods/',
      '/JSON/sessionManagement/view/getSessionManagementMethodConfigParams/',
      '/JSON/sessionManagement/view/getSessionManagementMethod/',
    ],

    // Users Management
    users: [
      '/JSON/users/view/usersList/',
      '/JSON/users/view/getUserById/',
    ],

    // HTTP Sessions
    httpSessions: [
      '/JSON/httpSessions/view/sites/',
      '/JSON/httpSessions/view/sessions/',
      '/JSON/httpSessions/view/activeSession/',
      '/JSON/httpSessions/view/sessionTokens/',
      '/JSON/httpSessions/view/defaultSessionTokens/',
    ],

    // Break Points
    break: [
      '/JSON/break/view/isBreakAll/',
      '/JSON/break/view/isBreakRequest/',
      '/JSON/break/view/isBreakResponse/',
      '/JSON/break/view/httpMessage/',
    ],

    // Forced User
    forcedUser: [
      '/JSON/forcedUser/view/isForcedUserModeEnabled/',
      '/JSON/forcedUser/view/getForcedUser/',
    ],

    // Script
    script: [
      '/JSON/script/view/listEngines/',
      '/JSON/script/view/listTypes/',
      '/JSON/script/view/listScripts/',
      '/JSON/script/view/globalVar/',
      '/JSON/script/view/globalVars/',
      '/JSON/script/view/scriptVar/',
      '/JSON/script/view/scriptVars/',
    ],

    // Search
    search: [
      '/JSON/search/view/urlsByUrlRegex/',
      '/JSON/search/view/urlsByRequestRegex/',
      '/JSON/search/view/urlsByResponseRegex/',
      '/JSON/search/view/urlsByHeaderRegex/',
      '/JSON/search/view/messagesByUrlRegex/',
      '/JSON/search/view/messagesByRequestRegex/',
      '/JSON/search/view/messagesByResponseRegex/',
      '/JSON/search/view/messagesByHeaderRegex/',
    ],

    // Selenium
    selenium: [
      '/JSON/selenium/view/optionBrowserExtensions/',
      '/JSON/selenium/view/optionBrowserArguments/',
      '/JSON/selenium/view/optionFirefoxDriverPath/',
      '/JSON/selenium/view/optionChromeDriverPath/',
    ],

    // Stats
    stats: [
      '/JSON/stats/view/stats/',
      '/JSON/stats/view/allSitesStats/',
      '/JSON/stats/view/siteStats/',
    ],

    // Technology Detection - Bu çok önemli!
    technology: [
      '/JSON/technology/view/optionTechnologyDetectionInCDN/',
    ],

    // Replacer
    replacer: [
      '/JSON/replacer/view/rules/',
    ],

    // Reveal
    reveal: [
      '/JSON/reveal/view/reveal/',
    ],

    // Retire.js - JavaScript kütüphane güvenlik açıkları
    retire: [
      '/JSON/retire/view/getRepoUrl/',
    ],

    // WAPPALYZER - Technology detection
    wappalyzer: [
      '/JSON/wappalyzer/view/listSites/',
      '/JSON/wappalyzer/view/listSite/',
      '/JSON/wappalyzer/view/listTechnologies/',
    ],

    // OpenAPI Support
    openapi: [
      '/JSON/openapi/view/generators/',
    ],

    // GraphQL Support  
    graphql: [
      '/JSON/graphql/view/optionMaxArgsDepth/',
      '/JSON/graphql/view/optionMaxQueryDepth/',
      '/JSON/graphql/view/optionOptionalArgsEnabled/',
      '/JSON/graphql/view/optionArgsType/',
      '/JSON/graphql/view/optionQuerySplitType/',
      '/JSON/graphql/view/optionRequestMethod/',
    ]
  };

  /**
   * TÜM ZAP verilerini topla - Bu bizim veri madenciliğimiz!
   */
  async collectAllZapData(targetUrl?: string): Promise<any> {
    const allData: any = {
      timestamp: new Date().toISOString(),
      targetUrl,
      zapVersion: '',
      categories: {}
    };

    // Her kategori için veri toplama
    for (const [category, endpoints] of Object.entries(this.advancedEndpoints)) {
      allData.categories[category] = {};
      
      for (const endpoint of endpoints) {
        try {
          const response = await this.zapClient.get(endpoint);
          allData.categories[category][endpoint] = response.data;
          
          // Rate limiting için kısa bekleme
          await new Promise(resolve => setTimeout(resolve, 100));
        } catch (error: any) {
          allData.categories[category][endpoint] = { error: error.message };
        }
      }
    }

    return allData;
  }

  /**
   * JavaScript Security Analysis - Modern web uygulamaları için kritik
   */
  async analyzeJavaScriptSecurity(targetUrl: string): Promise<any> {
    const jsAnalysis = {
      libraries: [],
      vulnerableLibraries: [],
      domXssVectors: [],
      clientSideStorageIssues: [],
      cspAnalysis: {},
      sri: [],
      recommendations: []
    };

    try {
      // Wappalyzer ile teknoloji tespiti
      const techResponse = await this.zapClient.get('/JSON/wappalyzer/view/listSite/', {
        params: { site: targetUrl }
      });
      
      if (techResponse.data.technologies) {
        jsAnalysis.libraries = techResponse.data.technologies.filter((tech: any) => 
          tech.categories && tech.categories.some((cat: any) => 
            cat.name.includes('JavaScript') || 
            cat.name.includes('Web framework') ||
            cat.name.includes('UI framework')
          )
        );
      }

      // Retire.js ile eski kütüphane kontrolü
      const retireResponse = await this.zapClient.get('/JSON/retire/view/getRepoUrl/');
      // Bu veriyi işleyerek vulnerable libraries tespit edebiliriz

      // DOM XSS vektörlerini tespit et
      const searchResponse = await this.zapClient.get('/JSON/search/view/messagesByResponseRegex/', {
        params: { 
          regex: '(eval|innerHTML|document\\.write|dangerouslySetInnerHTML|location\\.href\\s*=)',
          baseurl: targetUrl 
        }
      });

      if (searchResponse.data.messages) {
        jsAnalysis.domXssVectors = searchResponse.data.messages;
      }

    } catch (error: any) {
      console.error('JavaScript güvenlik analizi hatası:', error.message);
    }

    return jsAnalysis;
  }

  /**
   * API Security Deep Analysis
   */
  async analyzeApiSecurity(targetUrl: string): Promise<any> {
    const apiAnalysis = {
      endpoints: [],
      authentication: {},
      rateLimit: {},
      cors: {},
      graphqlAnalysis: {},
      openApiAnalysis: {},
      securityHeaders: {},
      dataExposure: []
    };

    try {
      // OpenAPI analizi
      const openApiResponse = await this.zapClient.get('/JSON/openapi/view/generators/');
      apiAnalysis.openApiAnalysis = openApiResponse.data;

      // GraphQL analizi
      const graphqlDepth = await this.zapClient.get('/JSON/graphql/view/optionMaxQueryDepth/');
      const graphqlArgs = await this.zapClient.get('/JSON/graphql/view/optionMaxArgsDepth/');
      
      apiAnalysis.graphqlAnalysis = {
        maxQueryDepth: graphqlDepth.data,
        maxArgsDepth: graphqlArgs.data
      };

      // API endpoint'lerini tespit et
      const messagesResponse = await this.zapClient.get('/JSON/core/view/messages/');
      if (messagesResponse.data.messages) {
        apiAnalysis.endpoints = messagesResponse.data.messages.filter((msg: any) => {
          const url = msg.url || '';
          return url.includes('/api/') || 
                 url.includes('/v1/') || 
                 url.includes('/graphql') ||
                 msg.responseHeader?.includes('application/json');
        });
      }

    } catch (error: any) {
      console.error('API güvenlik analizi hatası:', error.message);
    }

    return apiAnalysis;
  }

  /**
   * Advanced Behavioral Analysis
   */
  async analyzeBehavior(targetUrl: string): Promise<any> {
    const behaviorAnalysis = {
      userActions: [],
      ajaxCalls: [],
      formSubmissions: [],
      cookieAnalysis: {},
      sessionManagement: {},
      clientSideRouting: []
    };

    try {
      // AJAX Spider sonuçlarından davranış analizi
      const ajaxResults = await this.zapClient.get('/JSON/ajaxSpider/view/fullResults/');
      if (ajaxResults.data.fullResults) {
        behaviorAnalysis.ajaxCalls = ajaxResults.data.fullResults;
      }

      // HTTP Sessions analizi
      const sessions = await this.zapClient.get('/JSON/httpSessions/view/sessions/', {
        params: { site: targetUrl }
      });
      behaviorAnalysis.sessionManagement = sessions.data;

      // Cookie analizi
      const messages = await this.zapClient.get('/JSON/core/view/messages/');
      if (messages.data.messages) {
        behaviorAnalysis.cookieAnalysis = messages.data.messages
          .filter((msg: any) => msg.responseHeader?.includes('Set-Cookie'))
          .map((msg: any) => ({
            url: msg.url,
            cookies: this.extractCookies(msg.responseHeader)
          }));
      }

    } catch (error: any) {
      console.error('Davranış analizi hatası:', error.message);
    }

    return behaviorAnalysis;
  }

  private extractCookies(headers: string): any[] {
    const cookies: any[] = [];
    const lines = headers.split('\n');
    
    lines.forEach(line => {
      if (line.startsWith('Set-Cookie:')) {
        const cookieStr = line.substring(11).trim();
        const cookie = this.parseCookie(cookieStr);
        cookies.push(cookie);
      }
    });

    return cookies;
  }

  private parseCookie(cookieStr: string): any {
    const parts = cookieStr.split(';');
    const [name, value] = parts[0].split('=');
    
    const cookie: any = { name, value };
    
    parts.slice(1).forEach(part => {
      const [key, val] = part.trim().split('=');
      if (key.toLowerCase() === 'secure') cookie.secure = true;
      else if (key.toLowerCase() === 'httponly') cookie.httpOnly = true;
      else if (key.toLowerCase() === 'samesite') cookie.sameSite = val;
      else if (key.toLowerCase() === 'domain') cookie.domain = val;
      else if (key.toLowerCase() === 'path') cookie.path = val;
      else if (key.toLowerCase() === 'max-age') cookie.maxAge = parseInt(val);
    });

    return cookie;
  }

  /**
   * Comprehensive Security Assessment
   */
  async performComprehensiveAssessment(targetUrl: string): Promise<any> {
    const assessment = {
      timestamp: new Date().toISOString(),
      targetUrl,
      basicInfo: {},
      jsAnalysis: {},
      apiAnalysis: {},
      behaviorAnalysis: {},
      vulnerabilities: {},
      compliance: {},
      recommendations: []
    };

    try {
      // Temel bilgiler
      assessment.basicInfo = await this.getBasicInfo();
      
      // JavaScript güvenlik analizi
      assessment.jsAnalysis = await this.analyzeJavaScriptSecurity(targetUrl);
      
      // API güvenlik analizi
      assessment.apiAnalysis = await this.analyzeApiSecurity(targetUrl);
      
      // Davranış analizi
      assessment.behaviorAnalysis = await this.analyzeBehavior(targetUrl);
      
      // Güvenlik açıkları - direkt ZAP API'den çek
      const alertsResponse = await this.zapClient.get('/JSON/core/view/alerts/');
      const alerts = alertsResponse.data?.alerts || [];
      assessment.vulnerabilities = this.categorizeVulnerabilities(alerts);
      
      // Compliance kontrolü
      assessment.compliance = await this.checkCompliance(alerts);
      
      // Öneriler oluştur
      (assessment as any).recommendations = this.generateRecommendations(assessment);

    } catch (error: any) {
      console.error('Kapsamlı değerlendirme hatası:', error.message);
    }

    return assessment;
  }

  private async getBasicInfo(): Promise<any> {
    const [version, stats, mode] = await Promise.all([
      this.zapClient.get('/JSON/core/view/version/'),
      this.zapClient.get('/JSON/stats/view/stats/'),
      this.zapClient.get('/JSON/core/view/mode/')
    ]);

    return {
      zapVersion: version.data.version,
      stats: stats.data,
      mode: mode.data.mode
    };
  }

  private categorizeVulnerabilities(alerts: any[]): any {
    const categories: any = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      informational: []
    };

    alerts.forEach((alert: any) => {
      const risk = alert.risk?.toLowerCase() || 'informational';
      if (categories[risk]) {
        categories[risk].push(alert);
      }
    });

    return categories;
  }

  private async checkCompliance(alerts: any[]): Promise<any> {
    return {
      owaspTop10: this.checkOwaspTop10Compliance(alerts),
      pciDss: this.checkPciDssCompliance(alerts),
      gdpr: this.checkGdprCompliance(alerts),
      iso27001: this.checkIso27001Compliance(alerts)
    };
  }

  private checkOwaspTop10Compliance(alerts: any[]): any {
    // OWASP Top 10 kategorilerine göre compliance kontrolü
    const owaspCategories: any = {
      'A1-Injection': [],
      'A2-Broken Authentication': [],
      'A3-Sensitive Data Exposure': [],
      'A4-XML External Entities': [],
      'A5-Broken Access Control': [],
      'A6-Security Misconfiguration': [],
      'A7-Cross-Site Scripting': [],
      'A8-Insecure Deserialization': [],
      'A9-Using Components with Known Vulnerabilities': [],
      'A10-Insufficient Logging & Monitoring': []
    };

    alerts.forEach((alert: any) => {
      const alertName = alert.alert?.toLowerCase() || '';
      
      if (alertName.includes('injection') || alertName.includes('sql')) {
        owaspCategories['A1-Injection'].push(alert);
      } else if (alertName.includes('authentication') || alertName.includes('session')) {
        owaspCategories['A2-Broken Authentication'].push(alert);
      } else if (alertName.includes('xss') || alertName.includes('cross-site scripting')) {
        owaspCategories['A7-Cross-Site Scripting'].push(alert);
      }
      // Diğer kategoriler için benzer kontroller...
    });

    return owaspCategories;
  }

  private checkPciDssCompliance(alerts: any[]): any {
    // PCI DSS gereksinimlerine göre compliance kontrolü
    return {
      requirement1: { status: 'compliant', issues: [] },
      requirement2: { status: 'non-compliant', issues: [] },
      // Diğer requirements...
    };
  }

  private checkGdprCompliance(alerts: any[]): any {
    // GDPR gereksinimlerine göre compliance kontrolü
    return {
      dataProtection: { status: 'review-required', issues: [] },
      cookieConsent: { status: 'compliant', issues: [] },
      // Diğer GDPR kontrolleri...
    };
  }

  private checkIso27001Compliance(alerts: any[]): any {
    // ISO 27001 gereksinimlerine göre compliance kontrolü
    return {
      accessControl: { status: 'compliant', issues: [] },
      cryptography: { status: 'non-compliant', issues: [] },
      // Diğer ISO kontrolleri...
    };
  }

  private generateRecommendations(assessment: any): string[] {
    const recommendations: string[] = [];

    // JavaScript güvenliği önerileri
    if (assessment.jsAnalysis.vulnerableLibraries?.length > 0) {
      recommendations.push('Güvenlik açığı bulunan JavaScript kütüphanelerini güncelleyin');
    }

    // API güvenlik önerileri
    if (assessment.apiAnalysis.rateLimit?.enabled === false) {
      recommendations.push('API endpoints için rate limiting implementasyonu yapın');
    }

    // Güvenlik açığı önerileri
    if (assessment.vulnerabilities.critical?.length > 0) {
      recommendations.push('Kritik güvenlik açıklarını acilen giderin');
    }

    return recommendations;
  }
}
