import { Request } from 'express';

export type ScanEnvironment = 'TEST_STAGING' | 'PRODUCTION' | 'CUSTOM';

export interface ScanRequest {
  name: string;
  targetUrl: string;
  scanType: 'AUTOMATED' | 'MANUAL' | 'BASELINE' | 'FULL' | 'API';
  environment: ScanEnvironment; // 🔥 ZORUNLU: Hangi ortam için tarama yapılacak
  
  // TEST_STAGING için otomatik ayarlar
  // PRODUCTION için güvenli ayarlar
  // CUSTOM için kullanıcı tanımlı ayarlar
  customConfig?: {
    // Spider Ayarları
    spider?: {
      enabled: boolean;
      maxChildren?: number;
      maxDepth?: number;
      maxDuration?: number;
      recurse?: boolean;
    };
    
    // AJAX Spider Ayarları
    ajaxSpider?: {
      enabled: boolean;
      maxDuration?: number;
      maxCrawlDepth?: number;
      browser?: string;
    };
    
    // Active Scan Ayarları
    activeScan?: {
      enabled: boolean;
      maxDuration?: number;
      intensity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'INSANE';
      recurse?: boolean;
    };
    
    // Saldırı Testleri
    attackTests?: {
      sqlInjection?: boolean;
      xss?: boolean;
      xxe?: boolean;
      commandInjection?: boolean;
      pathTraversal?: boolean;
      wafBypass?: boolean;
      bruteForce?: boolean;
      csrf?: boolean;
      ssrf?: boolean;
      deserializationAttacks?: boolean;
    };
    
    // Gelişmiş Özellikler
    advanced?: {
      jsSecurity?: boolean; // JavaScript güvenlik analizi
      apiDeepDive?: boolean; // API güvenlik deep dive
      forcedBrowse?: boolean; // Forced browsing
      fuzzing?: boolean; // Fuzzing testleri
      
      // Payload & Wordlist Settings
      customPayloads?: boolean;
      customWordlists?: boolean;
    };
    
    // Güvenlik Ayarları
    security?: {
      safeMode?: boolean; // Sadece okuma tabanlı testler
      respectRobotsTxt?: boolean;
      maxAlertsPerRule?: number;
    };
    
    // Filtreler
    filters?: {
      excludeUrls?: string[];
      includeUrls?: string[];
      excludeParams?: string[];
    };
  };
}

export interface ScanResponse {
  id: string;
  name: string;
  targetUrl: string;
  scanType: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  startedAt: string;
  completedAt?: string;
  zapScanId?: string;
}

export interface VulnerabilityResponse {
  id: string;
  name: string;
  description?: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence?: string;
  solution?: string;
  reference?: string;
  url?: string;
  param?: string;
  attack?: string;
  evidence?: string;
}

export interface ScanProgressUpdate {
  status: 'running' | 'completed' | 'failed';
  phase: string;
  progress: number;
  message: string;
  urlsFound?: number;
  alertsFound?: number;
  technologies?: any[];
  workflow?: {
    currentPhase: string;
    totalPhases: number;
    completedPhases: number;
  };
  subPhaseProgress?: number;
  currentUrl?: string;
  error?: string;
  type?: string;
  alert?: {
    id: string;
    name: string;
    risk: string;
    confidence: string;
    url: string;
    description: string;
    solution: string;
    reference: string;
  };
}

export interface ScanStatistics {
  totalScans: number;
  runningScans: number;
  completedScans: number;
  failedScans: number;
  totalVulnerabilities: number;
  vulnerabilitySeverity: {
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    INFO: number;
  };
  lastUpdate: string;
}

export interface ZapSpiderResponse {
  scanId: string;
  status: 'running' | 'finished';
  progress: number;
  urls: string[];
}

export interface ZapActiveScanResponse {
  scanId: string;
  status: 'running' | 'finished';
  progress: number;
  alerts: ZapAlert[];
}

export interface ZapAlert {
  alertId: string;
  name: string;
  description: string;
  risk: string;
  confidence: string;
  url: string;
  param: string;
  attack: string;
  evidence: string;
  solution: string;
  reference: string;
  cweid?: string;
  wascid?: string;
  otherInfo?: string;
}

// Extended Request interface for authentication
export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    username: string;
    role: string;
    email: string;
  };
}