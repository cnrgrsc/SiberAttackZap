/**
 * 🎯 Scan Environment Configuration Service
 * 
 * 3 ortam için tarama yapılandırması:
 * 1. TEST_STAGING: Maksimum agresiflik, tüm ZAP yetenekleri
 * 2. PRODUCTION: Güvenli, sadece okuma tabanlı testler
 * 3. CUSTOM: Kullanıcı tanımlı ayarlar
 */

import { ScanRequest } from '../types/api.types';

export interface EnvironmentScanConfig {
  // Spider Configuration
  spider: {
    enabled: boolean;
    maxChildren: number; // 0 = unlimited
    maxDepth: number; // 0 = unlimited
    maxDuration: number; // minutes, 0 = unlimited
    recurse: boolean;
    subtreeOnly: boolean;
    acceptCookies: boolean;
    handleODataParametersVisited: boolean;
    parseComments: boolean;
    parseDsStore: boolean;
    parseGit: boolean;
    parseRobotsTxt: boolean;
    parseSVNEntries: boolean;
    parseSitemapXml: boolean;
    postForm: boolean;
    processForm: boolean;
    requestWaitTime: number;
    sendRefererHeader: boolean;
    threadCount: number;
  };

  // AJAX Spider Configuration
  ajaxSpider: {
    enabled: boolean;
    maxCrawlDepth: number;
    maxCrawlStates: number;
    maxDuration: number; // minutes
    numberOfBrowsers: number;
    inScope: boolean;
    clickDefaultElems: boolean;
    clickElemsOnce: boolean;
    eventWait: number;
    randomInputs: boolean;
    reloadWait: number;
    browserId: string; // 'firefox-headless' | 'chrome-headless' | 'htmlunit'
  };

  // Active Scan Configuration
  activeScan: {
    enabled: boolean;
    maxRuleDurationInMins: number; // 0 = unlimited
    maxScanDurationInMins: number; // 0 = unlimited
    maxAlertsPerRule: number; // 0 = unlimited
    delayInMs: number;
    threadPerHost: number;
    recurse: boolean;
    inScopeOnly: boolean;
    scanHeadersAllRequests: boolean;
    allowAttackOnStart: boolean;
    handleAntiCSRFTokens: boolean;
    injectPluginIdInHeader: boolean;
    scanNullJsonValues: boolean;
    maxChartTimeInMins: number;
    addQueryParam: boolean;
    defaultPolicy: boolean;
    attackMode: 'default' | 'aggressive' | 'insane';
  };

  // Attack Tests - Hangi saldırı türleri aktif?
  attackTests: {
    sqlInjection: boolean;
    xss: boolean; // Cross-Site Scripting
    xxe: boolean; // XML External Entity
    commandInjection: boolean;
    pathTraversal: boolean;
    wafBypass: boolean;
    bruteForce: boolean;
    csrf: boolean; // Cross-Site Request Forgery
    ssrf: boolean; // Server-Side Request Forgery
    deserializationAttacks: boolean;
    bufferOverflow: boolean;
    formatString: boolean;
    integerOverflow: boolean;
    ldapInjection: boolean;
    osCommandInjection: boolean;
    remoteCodeExecution: boolean;
    remoteFileInclusion: boolean;
    sessionFixation: boolean;
    sourceCodeDisclosure: boolean;
    userEnumeration: boolean;
  };

  // Advanced Features
  advanced: {
    jsSecurity: boolean; // JavaScript kütüphane güvenlik analizi
    apiDeepDive: boolean; // API endpoint deep analysis
    forcedBrowse: boolean; // Forced browsing/directory brute force
    fuzzing: boolean; // Input fuzzing
    customPayloads: boolean; // Custom payload kullanımı
    customWordlists: boolean; // Custom wordlist kullanımı
    technologyDetection: boolean; // Teknoloji tespit
    passiveScanning: boolean; // Pasif tarama
    graphQL: boolean; // GraphQL özel testleri
    websocket: boolean; // WebSocket testleri
  };

  // Security & Safety
  security: {
    safeMode: boolean; // true = Sadece okuma tabanlı testler
    respectRobotsTxt: boolean;
    maxRedirects: number;
    connectionTimeout: number;
    readTimeout: number;
    antiCSRFTokens: boolean;
    allowUnsafeRenegotiation: boolean;
    dnsTtlSuccessfulQueries: number;
  };

  // Filters & Scope
  filters: {
    excludeUrls: string[];
    includeUrls: string[];
    excludeParams: string[];
  };

  // Report Settings
  report: {
    format: 'HTML' | 'XML' | 'JSON' | 'MD';
    includeSummary: boolean;
    includePassedTests: boolean;
    includeRiskDescription: boolean;
    includeSolution: boolean;
    includeReference: boolean;
    includeAlertCounts: boolean;
    includeConfidence: boolean;
  };
}

export class ScanEnvironmentConfigService {
  /**
   * 🧪 TEST/STAGING Ortam Yapılandırması
   * - Maksimum agresiflik
   * - Tüm ZAP yetenekleri aktif
   * - Tüm saldırı testleri
   * - Sınırsız tarama süresi
   */
  getTestStagingConfig(): EnvironmentScanConfig {
    return {
      spider: {
        enabled: true,
        maxChildren: 0, // Unlimited
        maxDepth: 0, // Unlimited
        maxDuration: 0, // Unlimited
        recurse: true,
        subtreeOnly: false,
        acceptCookies: true,
        handleODataParametersVisited: true,
        parseComments: true,
        parseDsStore: true,
        parseGit: true,
        parseRobotsTxt: false, // Ignore robots.txt in test
        parseSVNEntries: true,
        parseSitemapXml: true,
        postForm: true,
        processForm: true,
        requestWaitTime: 200,
        sendRefererHeader: true,
        threadCount: 10 // Maximum threads
      },
      ajaxSpider: {
        enabled: true,
        maxCrawlDepth: 10, // Deep crawling
        maxCrawlStates: 0, // Unlimited
        maxDuration: 0, // Unlimited
        numberOfBrowsers: 2,
        inScope: false, // Explore everything
        clickDefaultElems: true,
        clickElemsOnce: false,
        eventWait: 1000,
        randomInputs: true,
        reloadWait: 1000,
        browserId: 'firefox-headless'
      },
      activeScan: {
        enabled: true,
        maxRuleDurationInMins: 0, // Unlimited
        maxScanDurationInMins: 0, // Unlimited
        maxAlertsPerRule: 0, // Unlimited alerts
        delayInMs: 0, // No delay between requests
        threadPerHost: 10, // Maximum threads
        recurse: true,
        inScopeOnly: false,
        scanHeadersAllRequests: true,
        allowAttackOnStart: true,
        handleAntiCSRFTokens: true,
        injectPluginIdInHeader: true,
        scanNullJsonValues: true,
        maxChartTimeInMins: 0,
        addQueryParam: true,
        defaultPolicy: false,
        attackMode: 'insane' // Most aggressive
      },
      attackTests: {
        sqlInjection: true,
        xss: true,
        xxe: true,
        commandInjection: true,
        pathTraversal: true,
        wafBypass: true,
        bruteForce: true,
        csrf: true,
        ssrf: true,
        deserializationAttacks: true,
        bufferOverflow: true,
        formatString: true,
        integerOverflow: true,
        ldapInjection: true,
        osCommandInjection: true,
        remoteCodeExecution: true,
        remoteFileInclusion: true,
        sessionFixation: true,
        sourceCodeDisclosure: true,
        userEnumeration: true
      },
      advanced: {
        jsSecurity: true,
        apiDeepDive: true,
        forcedBrowse: true,
        fuzzing: true,
        customPayloads: true,
        customWordlists: true,
        technologyDetection: true,
        passiveScanning: true,
        graphQL: true,
        websocket: true
      },
      security: {
        safeMode: false, // All attacks enabled
        respectRobotsTxt: false,
        maxRedirects: 100,
        connectionTimeout: 120000,
        readTimeout: 120000,
        antiCSRFTokens: true,
        allowUnsafeRenegotiation: true,
        dnsTtlSuccessfulQueries: -1
      },
      filters: {
        excludeUrls: [],
        includeUrls: [],
        excludeParams: []
      },
      report: {
        format: 'HTML',
        includeSummary: true,
        includePassedTests: true,
        includeRiskDescription: true,
        includeSolution: true,
        includeReference: true,
        includeAlertCounts: true,
        includeConfidence: true
      }
    };
  }

  /**
   * 🔒 PRODUCTION Ortam Yapılandırması
   * - Güvenli mod (Safe Mode)
   * - Sadece okuma tabanlı testler
   * - Veri tabanına yazma yok
   * - Zarar verici testler yok
   */
  getProductionConfig(): EnvironmentScanConfig {
    return {
      spider: {
        enabled: true,
        maxChildren: 50, // Limited
        maxDepth: 5, // Limited depth
        maxDuration: 30, // 30 minutes max
        recurse: true,
        subtreeOnly: true,
        acceptCookies: true,
        handleODataParametersVisited: false,
        parseComments: true,
        parseDsStore: false,
        parseGit: false,
        parseRobotsTxt: true, // Respect robots.txt
        parseSVNEntries: false,
        parseSitemapXml: true,
        postForm: false, // Don't submit forms
        processForm: true, // Only analyze forms
        requestWaitTime: 1000, // Slower requests
        sendRefererHeader: true,
        threadCount: 2 // Low thread count
      },
      ajaxSpider: {
        enabled: true,
        maxCrawlDepth: 3, // Limited depth
        maxCrawlStates: 100,
        maxDuration: 20, // 20 minutes max
        numberOfBrowsers: 1,
        inScope: true,
        clickDefaultElems: false, // Don't click buttons
        clickElemsOnce: true,
        eventWait: 2000,
        randomInputs: false, // No random inputs
        reloadWait: 2000,
        browserId: 'htmlunit' // Lightweight browser
      },
      activeScan: {
        enabled: false, // ❌ NO ACTIVE SCANNING IN PRODUCTION
        maxRuleDurationInMins: 0,
        maxScanDurationInMins: 0,
        maxAlertsPerRule: 0,
        delayInMs: 0,
        threadPerHost: 0,
        recurse: false,
        inScopeOnly: true,
        scanHeadersAllRequests: false,
        allowAttackOnStart: false,
        handleAntiCSRFTokens: false,
        injectPluginIdInHeader: false,
        scanNullJsonValues: false,
        maxChartTimeInMins: 0,
        addQueryParam: false,
        defaultPolicy: true,
        attackMode: 'default'
      },
      attackTests: {
        // ❌ TÜM SALDIRI TESTLERİ KAPALI
        sqlInjection: false,
        xss: false,
        xxe: false,
        commandInjection: false,
        pathTraversal: false,
        wafBypass: false,
        bruteForce: false,
        csrf: false,
        ssrf: false,
        deserializationAttacks: false,
        bufferOverflow: false,
        formatString: false,
        integerOverflow: false,
        ldapInjection: false,
        osCommandInjection: false,
        remoteCodeExecution: false,
        remoteFileInclusion: false,
        sessionFixation: false,
        sourceCodeDisclosure: false,
        userEnumeration: false
      },
      advanced: {
        jsSecurity: true, // ✅ Only safe analysis
        apiDeepDive: false,
        forcedBrowse: false,
        fuzzing: false,
        customPayloads: false,
        customWordlists: false,
        technologyDetection: true, // ✅ Safe technology detection
        passiveScanning: true, // ✅ Only passive scanning
        graphQL: false,
        websocket: false
      },
      security: {
        safeMode: true, // ✅ SAFE MODE ENABLED
        respectRobotsTxt: true,
        maxRedirects: 10,
        connectionTimeout: 30000,
        readTimeout: 30000,
        antiCSRFTokens: false,
        allowUnsafeRenegotiation: false,
        dnsTtlSuccessfulQueries: 30
      },
      filters: {
        excludeUrls: [],
        includeUrls: [],
        excludeParams: []
      },
      report: {
        format: 'HTML',
        includeSummary: true,
        includePassedTests: false, // Only show issues
        includeRiskDescription: true,
        includeSolution: true,
        includeReference: true,
        includeAlertCounts: true,
        includeConfidence: true
      }
    };
  }

  /**
   * ⚙️ CUSTOM Ortam Yapılandırması
   * Kullanıcının seçtiği ayarları uygula
   */
  getCustomConfig(request: ScanRequest): EnvironmentScanConfig {
    const custom = request.customConfig;
    
    // Start with production config as base (safe defaults)
    const config = this.getProductionConfig();

    if (!custom) {
      return config;
    }

    // Override spider settings
    if (custom.spider) {
      config.spider.enabled = custom.spider.enabled;
      if (custom.spider.maxChildren !== undefined) config.spider.maxChildren = custom.spider.maxChildren;
      if (custom.spider.maxDepth !== undefined) config.spider.maxDepth = custom.spider.maxDepth;
      if (custom.spider.maxDuration !== undefined) config.spider.maxDuration = custom.spider.maxDuration;
      if (custom.spider.recurse !== undefined) config.spider.recurse = custom.spider.recurse;
    }

    // Override AJAX spider settings
    if (custom.ajaxSpider) {
      config.ajaxSpider.enabled = custom.ajaxSpider.enabled;
      if (custom.ajaxSpider.maxDuration !== undefined) config.ajaxSpider.maxDuration = custom.ajaxSpider.maxDuration;
      if (custom.ajaxSpider.maxCrawlDepth !== undefined) config.ajaxSpider.maxCrawlDepth = custom.ajaxSpider.maxCrawlDepth;
      if (custom.ajaxSpider.browser) config.ajaxSpider.browserId = custom.ajaxSpider.browser;
    }

    // Override active scan settings
    if (custom.activeScan) {
      config.activeScan.enabled = custom.activeScan.enabled;
      if (custom.activeScan.maxDuration !== undefined) config.activeScan.maxScanDurationInMins = custom.activeScan.maxDuration;
      if (custom.activeScan.intensity) {
        const intensityMap = {
          'LOW': 'default',
          'MEDIUM': 'default',
          'HIGH': 'aggressive',
          'INSANE': 'insane'
        };
        config.activeScan.attackMode = intensityMap[custom.activeScan.intensity] as any;
      }
      if (custom.activeScan.recurse !== undefined) config.activeScan.recurse = custom.activeScan.recurse;
    }

    // Override attack tests
    if (custom.attackTests) {
      Object.keys(custom.attackTests).forEach(key => {
        if (custom.attackTests && key in config.attackTests) {
          (config.attackTests as any)[key] = (custom.attackTests as any)[key];
        }
      });
    }

    // Override advanced features
    if (custom.advanced) {
      Object.keys(custom.advanced).forEach(key => {
        if (custom.advanced && key in config.advanced) {
          (config.advanced as any)[key] = (custom.advanced as any)[key];
        }
      });
    }

    // Override security settings
    if (custom.security) {
      if (custom.security.safeMode !== undefined) config.security.safeMode = custom.security.safeMode;
      if (custom.security.respectRobotsTxt !== undefined) config.security.respectRobotsTxt = custom.security.respectRobotsTxt;
      if (custom.security.maxAlertsPerRule !== undefined) config.activeScan.maxAlertsPerRule = custom.security.maxAlertsPerRule;
    }

    // Override filters
    if (custom.filters) {
      if (custom.filters.excludeUrls) config.filters.excludeUrls = custom.filters.excludeUrls;
      if (custom.filters.includeUrls) config.filters.includeUrls = custom.filters.includeUrls;
      if (custom.filters.excludeParams) config.filters.excludeParams = custom.filters.excludeParams;
    }

    return config;
  }

  /**
   * Get configuration based on environment
   */
  getConfigForEnvironment(request: ScanRequest): EnvironmentScanConfig {
    switch (request.environment) {
      case 'TEST_STAGING':
        console.log('🧪 Using TEST/STAGING configuration - Maximum aggressiveness');
        return this.getTestStagingConfig();
      
      case 'PRODUCTION':
        console.log('🔒 Using PRODUCTION configuration - Safe mode only');
        return this.getProductionConfig();
      
      case 'CUSTOM':
        console.log('⚙️ Using CUSTOM configuration - User defined settings');
        return this.getCustomConfig(request);
      
      default:
        console.warn(`⚠️ Unknown environment: ${request.environment}, defaulting to PRODUCTION`);
        return this.getProductionConfig();
    }
  }

  /**
   * Validate configuration
   */
  validateConfig(config: EnvironmentScanConfig): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check if safe mode is enabled but attack tests are active
    if (config.security.safeMode) {
      const activeAttacks = Object.entries(config.attackTests)
        .filter(([_, enabled]) => enabled)
        .map(([attack, _]) => attack);
      
      if (activeAttacks.length > 0) {
        errors.push(`Safe mode is enabled but following attack tests are active: ${activeAttacks.join(', ')}`);
      }

      if (config.activeScan.enabled) {
        errors.push('Safe mode is enabled but active scanning is enabled');
      }
    }

    // Validate timeouts
    if (config.spider.maxDuration < 0) {
      errors.push('Spider max duration cannot be negative');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Log configuration summary
   */
  logConfigSummary(config: EnvironmentScanConfig, environment: string): void {
    console.log('\n' + '='.repeat(60));
    console.log(`📋 SCAN CONFIGURATION SUMMARY - ${environment}`);
    console.log('='.repeat(60));
    console.log(`🕷️  Spider: ${config.spider.enabled ? 'ENABLED' : 'DISABLED'}`);
    console.log(`🌐 AJAX Spider: ${config.ajaxSpider.enabled ? 'ENABLED' : 'DISABLED'}`);
    console.log(`⚡ Active Scan: ${config.activeScan.enabled ? 'ENABLED' : 'DISABLED'}`);
    console.log(`🔒 Safe Mode: ${config.security.safeMode ? 'ENABLED' : 'DISABLED'}`);
    
    const enabledAttacks = Object.entries(config.attackTests)
      .filter(([_, enabled]) => enabled)
      .map(([attack, _]) => attack);
    
    console.log(`🎯 Attack Tests: ${enabledAttacks.length > 0 ? enabledAttacks.join(', ') : 'NONE'}`);
    
    const enabledAdvanced = Object.entries(config.advanced)
      .filter(([_, enabled]) => enabled)
      .map(([feature, _]) => feature);
    
    console.log(`🚀 Advanced Features: ${enabledAdvanced.length > 0 ? enabledAdvanced.join(', ') : 'NONE'}`);
    console.log('='.repeat(60) + '\n');
  }
}

// Singleton instance
export const scanEnvironmentConfigService = new ScanEnvironmentConfigService();
