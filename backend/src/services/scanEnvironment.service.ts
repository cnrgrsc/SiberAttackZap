/**
 * 🔥 SiberZed Scan Environment Service
 * 
 * Bu servis 3 farklı tarama ortamı için konfigürasyon profillerini yönetir:
 * 
 * 1. TEST/STAGING: Maksimum agresiflik, sınırsız testler, detaylı rapor
 * 2. PRODUCTION (CANLI UYGULAMA): Güvenli modda, DB-friendly, crash prevention
 * 3. CUSTOM (ÖZEL AYARLAR): Kullanıcı tanımlı, adım adım konfigürasyon
 */

export interface ScanEnvironmentConfig {
  environment: 'TEST' | 'PRODUCTION' | 'CUSTOM';
  aggressiveness: 'LOW' | 'MEDIUM' | 'HIGH' | 'INSANE';
  safeMode: boolean;
  
  // Spider configuration
  spider: {
    enabled: boolean;
    maxDepth: number;
    maxChildren: number;
    maxDuration: number; // minutes
    threadCount: number;
  };
  
  // AJAX Spider configuration
  ajaxSpider: {
    enabled: boolean;
    maxDuration: number; // minutes
    maxCrawlDepth: number;
    clickElements: boolean;
  };
  
  // Active Scan configuration
  activeScan: {
    enabled: boolean;
    maxDuration: number; // minutes
    threadCount: number;
    attackStrength: 'Low' | 'Medium' | 'High' | 'Insane';
    alertThreshold: 'Low' | 'Medium' | 'High';
    policies: string[]; // Policy names to enable
  };
  
  // Rate limiting & throttling
  rateLimiting: {
    enabled: boolean;
    requestsPerSecond: number;
    delayBetweenRequests: number; // milliseconds
  };
  
  // Advanced tests
  advancedTests: {
    sqlInjection: boolean;
    xss: boolean;
    xxe: boolean;
    csrf: boolean;
    commandInjection: boolean;
    pathTraversal: boolean;
    wafBypass: boolean;
    bruteForce: boolean;
  };
  
  // Passive scan configuration
  passiveScan: {
    enabled: boolean;
    autoTagScanners: boolean;
  };
  
  // Report configuration
  reportSettings: {
    autoGenerate: boolean;
    formats: ('HTML' | 'JSON' | 'XML' | 'PDF')[];
    emailOnComplete: boolean;
    recipients: string[];
    includeRequestResponse: boolean;
    includeScanMetadata: boolean;
  };
  
  // Timeout & safety limits
  limits: {
    maxTotalDuration: number; // minutes
    maxAlerts: number;
    maxUrlsToScan: number;
    stopOnError: boolean;
  };
}

export class ScanEnvironmentService {
  
  /**
   * 🧪 TEST/STAGING Ortamı
   * 
   * Maksimum agresiflik, tüm testler aktif, sınırsız istek
   * Hedef: Tüm güvenlik açıklarını bul, detaylı rapor üret
   */
  getTestEnvironmentConfig(): ScanEnvironmentConfig {
    return {
      environment: 'TEST',
      aggressiveness: 'INSANE',
      safeMode: false,
      
      spider: {
        enabled: true,
        maxDepth: 10, // Derin tarama
        maxChildren: 0, // Sınırsız
        maxDuration: 30, // 30 dakika
        threadCount: 10 // Maksimum thread
      },
      
      ajaxSpider: {
        enabled: true,
        maxDuration: 20, // 20 dakika
        maxCrawlDepth: 10,
        clickElements: true
      },
      
      activeScan: {
        enabled: true,
        maxDuration: 60, // 60 dakika
        threadCount: 10,
        attackStrength: 'Insane',
        alertThreshold: 'Low', // Her şeyi yakala
        policies: [
          'SQL Injection',
          'Cross Site Scripting (Reflected)',
          'Cross Site Scripting (Persistent)',
          'Path Traversal',
          'Remote File Inclusion',
          'Server Side Include',
          'Script Active Scan Rules',
          'Server Side Code Injection',
          'External Redirect',
          'CRLF Injection',
          'Parameter Tampering',
          'Remote OS Command Injection',
          'Buffer Overflow',
          'Format String Error',
          'Integer Overflow Error',
          'LDAP Injection',
          'XPath Injection',
          'XML External Entity Attack',
          'Generic Padding Oracle',
          'Expression Language Injection'
        ]
      },
      
      rateLimiting: {
        enabled: false, // TEST ortamında rate limiting yok
        requestsPerSecond: 0,
        delayBetweenRequests: 0
      },
      
      advancedTests: {
        sqlInjection: true,
        xss: true,
        xxe: true,
        csrf: true,
        commandInjection: true,
        pathTraversal: true,
        wafBypass: true, // WAF bypass teknikleri aktif
        bruteForce: true
      },
      
      passiveScan: {
        enabled: true,
        autoTagScanners: true
      },
      
      reportSettings: {
        autoGenerate: true,
        formats: ['HTML', 'JSON', 'XML', 'PDF'],
        emailOnComplete: false,
        recipients: [],
        includeRequestResponse: true, // Tüm request/response kayıtları
        includeScanMetadata: true
      },
      
      limits: {
        maxTotalDuration: 120, // 2 saat maksimum
        maxAlerts: 10000, // Sınırsız gibi
        maxUrlsToScan: 0, // Sınırsız
        stopOnError: false
      }
    };
  }
  
  /**
   * 🛡️ PRODUCTION (Canlı Uygulama) Ortamı
   * 
   * Düşük agresiflik, safe mode, rate limiting
   * Hedef: Veritabanını ve uygulamayı çökertmeden güvenlik testi
   */
  getProductionEnvironmentConfig(): ScanEnvironmentConfig {
    return {
      environment: 'PRODUCTION',
      aggressiveness: 'LOW',
      safeMode: true, // Sadece okuma testleri
      
      spider: {
        enabled: true,
        maxDepth: 3, // Sınırlı derinlik
        maxChildren: 50, // Maksimum 50 child
        maxDuration: 10, // 10 dakika
        threadCount: 2 // Az thread
      },
      
      ajaxSpider: {
        enabled: false, // AJAX spider kapalı (ağır)
        maxDuration: 0,
        maxCrawlDepth: 0,
        clickElements: false
      },
      
      activeScan: {
        enabled: true,
        maxDuration: 20, // 20 dakika
        threadCount: 2, // Az thread
        attackStrength: 'Low',
        alertThreshold: 'Medium', // Sadece orta ve yüksek
        policies: [
          // Sadece güvenli (okuma) testleri
          'Cross Site Scripting (Reflected)', // Read-only XSS detection
          'Application Error Disclosure',
          'Cookie No HttpOnly Flag',
          'Cookie Without Secure Flag',
          'Incomplete or No Cache-control and Pragma HTTP Header Set',
          'Content Security Policy (CSP) Header Not Set',
          'X-Frame-Options Header Not Set',
          'X-Content-Type-Options Header Missing',
          'Absence of Anti-CSRF Tokens',
          'Information Disclosure - Suspicious Comments',
          'Loosely Scoped Cookie'
        ]
      },
      
      rateLimiting: {
        enabled: true,
        requestsPerSecond: 2, // Saniyede 2 istek (çok yavaş)
        delayBetweenRequests: 500 // 500ms delay
      },
      
      advancedTests: {
        sqlInjection: false, // KAPALI - DB'yi etkileyebilir
        xss: true, // Sadece detection (injection yok)
        xxe: false, // KAPALI
        csrf: true, // Sadece token kontrolü
        commandInjection: false, // KAPALI
        pathTraversal: false, // KAPALI
        wafBypass: false, // KAPALI
        bruteForce: false // KAPALI
      },
      
      passiveScan: {
        enabled: true, // Pasif tarama her zaman güvenli
        autoTagScanners: true
      },
      
      reportSettings: {
        autoGenerate: true,
        formats: ['HTML', 'JSON'], // Hafif formatlar
        emailOnComplete: true,
        recipients: [],
        includeRequestResponse: false, // Request/response kaydetme (gizlilik)
        includeScanMetadata: true
      },
      
      limits: {
        maxTotalDuration: 30, // 30 dakika maksimum
        maxAlerts: 500, // 500 alert sonrası dur
        maxUrlsToScan: 100, // Maksimum 100 URL tara
        stopOnError: true // Hata durumunda dur
      }
    };
  }
  
  /**
   * ⚙️ CUSTOM (Özel Ayarlar) Ortamı - Başlangıç Değerleri
   * 
   * Kullanıcı bu değerleri frontend'den özelleştirebilir
   */
  getCustomEnvironmentConfig(): ScanEnvironmentConfig {
    return {
      environment: 'CUSTOM',
      aggressiveness: 'MEDIUM',
      safeMode: false,
      
      spider: {
        enabled: true,
        maxDepth: 5,
        maxChildren: 100,
        maxDuration: 15,
        threadCount: 5
      },
      
      ajaxSpider: {
        enabled: true,
        maxDuration: 10,
        maxCrawlDepth: 5,
        clickElements: true
      },
      
      activeScan: {
        enabled: true,
        maxDuration: 30,
        threadCount: 5,
        attackStrength: 'Medium',
        alertThreshold: 'Medium',
        policies: [
          'SQL Injection',
          'Cross Site Scripting (Reflected)',
          'Cross Site Scripting (Persistent)',
          'Path Traversal',
          'Remote OS Command Injection'
        ]
      },
      
      rateLimiting: {
        enabled: false,
        requestsPerSecond: 5,
        delayBetweenRequests: 200
      },
      
      advancedTests: {
        sqlInjection: true,
        xss: true,
        xxe: false,
        csrf: true,
        commandInjection: false,
        pathTraversal: true,
        wafBypass: false,
        bruteForce: false
      },
      
      passiveScan: {
        enabled: true,
        autoTagScanners: true
      },
      
      reportSettings: {
        autoGenerate: true,
        formats: ['HTML', 'JSON'],
        emailOnComplete: false,
        recipients: [],
        includeRequestResponse: false,
        includeScanMetadata: true
      },
      
      limits: {
        maxTotalDuration: 45,
        maxAlerts: 1000,
        maxUrlsToScan: 500,
        stopOnError: false
      }
    };
  }
  
  /**
   * Ortam tipine göre config döndür
   */
  getConfigForEnvironment(environment: 'TEST' | 'PRODUCTION' | 'CUSTOM'): ScanEnvironmentConfig {
    switch (environment) {
      case 'TEST':
        return this.getTestEnvironmentConfig();
      case 'PRODUCTION':
        return this.getProductionEnvironmentConfig();
      case 'CUSTOM':
        return this.getCustomEnvironmentConfig();
      default:
        return this.getTestEnvironmentConfig();
    }
  }
  
  /**
   * Custom config'i merge et (kullanıcı ayarlarıyla)
   */
  mergeCustomConfig(
    baseConfig: ScanEnvironmentConfig,
    customSettings: Partial<ScanEnvironmentConfig>
  ): ScanEnvironmentConfig {
    return {
      ...baseConfig,
      ...customSettings,
      spider: { ...baseConfig.spider, ...(customSettings.spider || {}) },
      ajaxSpider: { ...baseConfig.ajaxSpider, ...(customSettings.ajaxSpider || {}) },
      activeScan: { ...baseConfig.activeScan, ...(customSettings.activeScan || {}) },
      rateLimiting: { ...baseConfig.rateLimiting, ...(customSettings.rateLimiting || {}) },
      advancedTests: { ...baseConfig.advancedTests, ...(customSettings.advancedTests || {}) },
      passiveScan: { ...baseConfig.passiveScan, ...(customSettings.passiveScan || {}) },
      reportSettings: { ...baseConfig.reportSettings, ...(customSettings.reportSettings || {}) },
      limits: { ...baseConfig.limits, ...(customSettings.limits || {}) }
    };
  }
  
  /**
   * Config'i konsola yazdır (debug için)
   */
  logConfig(config: ScanEnvironmentConfig): void {
    console.log(`\n🔧 ====== SCAN CONFIGURATION ======`);
    console.log(`📍 Environment: ${config.environment}`);
    console.log(`⚡ Aggressiveness: ${config.aggressiveness}`);
    console.log(`🛡️ Safe Mode: ${config.safeMode ? 'ENABLED' : 'DISABLED'}`);
    console.log(`🕷️ Spider: ${config.spider.enabled ? 'ON' : 'OFF'} (Depth: ${config.spider.maxDepth})`);
    console.log(`🌐 AJAX Spider: ${config.ajaxSpider.enabled ? 'ON' : 'OFF'}`);
    console.log(`🎯 Active Scan: ${config.activeScan.enabled ? 'ON' : 'OFF'} (${config.activeScan.attackStrength})`);
    console.log(`⏱️ Max Duration: ${config.limits.maxTotalDuration} minutes`);
    console.log(`🚦 Rate Limiting: ${config.rateLimiting.enabled ? 'ENABLED' : 'DISABLED'}`);
    console.log(`📊 Report Formats: ${config.reportSettings.formats.join(', ')}`);
    console.log(`==================================\n`);
  }
}

export const scanEnvironmentService = new ScanEnvironmentService();
