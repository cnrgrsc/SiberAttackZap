import { PrismaClient } from '@prisma/client';
import { v4 as uuidv4 } from 'uuid';
import { ScanRequest, ScanResponse, VulnerabilityResponse } from '../types/api.types';
import { ZapProxyService } from './zapProxy.service';
import { ReportGeneratorService } from './reportGenerator.service';
import { scanEnvironmentConfigService, EnvironmentScanConfig } from './scanEnvironmentConfig.service';
import { scanQueueService } from './scanQueue.service';

export class ScanService {
  private prisma = new PrismaClient();
  private zapService = new ZapProxyService();
  private io?: any;

  constructor(io?: any) {
    this.io = io;
  }

  private emitScanUpdate(scanId: string, update: any): void {
    if (this.io) {
      this.io.to(`scan-${scanId}`).emit('scanUpdate', { scanId, ...update, timestamp: new Date().toISOString() });
    }
  }

  private mapScanToResponse(scan: any): ScanResponse {
    return {
      id: scan.id,
      name: scan.name,
      targetUrl: scan.targetUrl,
      scanType: scan.scanType,
      status: scan.status,
      startedAt: scan.startedAt?.toISOString() ?? '',
      completedAt: scan.completedAt?.toISOString() ?? '',
      zapScanId: scan.zapScanId
    };
  }

  async createScan(data: ScanRequest, userId?: string): Promise<ScanResponse & { queued?: boolean; queuePosition?: number; estimatedStart?: string }> {
    console.log(`🎯 Creating scan with environment: ${data.environment}`);
    
    // Get configuration for the specified environment
    const envConfig = scanEnvironmentConfigService.getConfigForEnvironment(data);
    
    // Validate configuration
    const validation = scanEnvironmentConfigService.validateConfig(envConfig);
    if (!validation.valid) {
      throw new Error(`Invalid scan configuration: ${validation.errors.join(', ')}`);
    }
    
    // Log configuration summary
    scanEnvironmentConfigService.logConfigSummary(envConfig, data.environment);
    
    const scan = await this.prisma.scan.create({
      data: {
        id: uuidv4(),
        name: data.name,
        targetUrl: data.targetUrl,
        scanType: data.scanType,
        status: 'PENDING',
        createdBy: userId,
        // Store environment and config
        metadata: {
          environment: data.environment,
          scanConfig: envConfig,
          createdAt: new Date().toISOString()
        } as any
      }
    });
    
    console.log(`✅ Scan created successfully: ${scan.id}`);
    
    // 🔥 Queue System Integration
    if (userId) {
      try {
        const queueResult = await scanQueueService.addScan(scan.id, userId);
        
        if (queueResult.queued) {
          console.log(`📋 Scan ${scan.id} added to queue at position ${queueResult.position}`);
          
          return {
            ...this.mapScanToResponse(scan),
            queued: true,
            queuePosition: queueResult.position,
            estimatedStart: queueResult.estimatedStartTime?.toISOString()
          };
        }
      } catch (error: any) {
        // Rate limit veya diğer hatalar
        await this.prisma.scan.delete({ where: { id: scan.id } });
        throw error;
      }
    }
    
    return this.mapScanToResponse(scan);
  }

  async startAutomatedScan(scanId: string): Promise<ScanResponse> {
    try {
      // Get scan details from database
      const scan = await this.prisma.scan.findUnique({ where: { id: scanId } });
      
      if (!scan) {
        throw new Error('Scan not found');
      }

      // Check system resources before starting intensive scan
      const alertCount = await this.zapService.getStatus().then(s => s.alerts).catch(() => 0);
      
      if (alertCount > 1000) {
        console.warn(`⚠️ High alert count detected (${alertCount}), using optimized scan approach`);
        // Clear session to improve performance
        try {
          await this.zapService.clearSession();
        } catch (clearError) {
        }
      }
      if (!scan) {
        throw new Error('Scan not found');
      }

      // Update scan status to RUNNING
      await this.prisma.scan.update({ 
        where: { id: scanId }, 
        data: { 
          status: 'RUNNING',
          startedAt: new Date()
        } 
      });

      this.emitScanUpdate(scanId, { 
        status: 'running', 
        phase: 'initializing', 
        progress: 0, 
        message: 'Starting automated scan...' 
      });

      // Start the automated scan process (run in background without blocking)
      this.runAutomatedScanProcess(scanId, scan.targetUrl, scan.scanType)
        .catch(async (processError) => {
          console.error('❌ Automated scan process failed:', processError);
          // Error handling is already done in runAutomatedScanProcess
        });

      return this.mapScanToResponse(scan);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      console.error('❌ Error starting automated scan:', {
        scanId,
        error: errorMessage,
        stack: error instanceof Error ? error.stack : '',
        timestamp: new Date().toISOString()
      });
      
      await this.prisma.scan.update({ 
        where: { id: scanId }, 
        data: { 
          status: 'FAILED',
          completedAt: new Date(),
          metadata: {
            errorType: 'STARTUP_ERROR',
            errorMessage,
            errorTimestamp: new Date().toISOString()
          }
        } 
      });
      
      this.emitScanUpdate(scanId, { 
        status: 'failed',
        phase: 'FAILED', 
        progress: 0,
        message: `Tarama başlatılamadı: ${errorMessage}`,
        error: {
          type: 'STARTUP_ERROR',
          message: errorMessage
        }
      });
      
      throw error;
    }
  }

  private async runAutomatedScanProcess(scanId: string, targetUrl: string, scanType: string): Promise<void> {
    try {
      // Get scan configuration from database
      const scan = await this.prisma.scan.findUnique({ 
        where: { id: scanId }
      });
      
      if (!scan) {
        throw new Error('Scan not found');
      }
      
      // Extract environment and config from metadata
      const metadata = scan.metadata as any;
      const environment = metadata?.environment || 'TEST_STAGING';
      const config = metadata?.scanConfig as EnvironmentScanConfig;
      
      if (!config) {
        throw new Error('Scan configuration not found in metadata');
      }
      
      console.log(`\n${'='.repeat(60)}`);
      console.log(`🚀 STARTING ${environment} SCAN`);
      console.log(`📝 Scan ID: ${scanId}`);
      console.log(`🎯 Target: ${targetUrl}`);
      console.log(`${'='.repeat(60)}\n`);
      
      // Route to appropriate scan method based on environment
      switch (environment) {
        case 'TEST_STAGING':
          await this.runTestStagingScan(scanId, targetUrl, config);
          break;
        case 'PRODUCTION':
          await this.runProductionScan(scanId, targetUrl, config);
          break;
        case 'CUSTOM':
          await this.runCustomScan(scanId, targetUrl, config);
          break;
        default:
          console.warn(`⚠️ Unknown environment: ${environment}, using TEST_STAGING`);
          await this.runTestStagingScan(scanId, targetUrl, config);
      }
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.error(`❌ Scan process failed for ${scanId}:`, errorMessage);
      
      // Get scan again for metadata
      const failedScan = await this.prisma.scan.findUnique({ 
        where: { id: scanId }
      });
      
      await this.prisma.scan.update({
        where: { id: scanId },
        data: {
          status: 'FAILED',
          completedAt: new Date(),
          metadata: {
            ...(failedScan?.metadata as any || {}),
            error: errorMessage,
            failedAt: new Date().toISOString()
          } as any
        }
      });
      
      this.emitScanUpdate(scanId, {
        status: 'failed',
        phase: 'error',
        progress: 0,
        message: `Scan failed: ${errorMessage}`,
        error: errorMessage
      });
      
      throw error;
    }
  }

  /**
   * 🧪 TEST/STAGING Environment Scan
   * Maximum aggressiveness, all tests enabled, unlimited requests
   */
  private async runTestStagingScan(
    scanId: string, 
    targetUrl: string, 
    config: EnvironmentScanConfig
  ): Promise<void> {
    // Calculate max duration from spider and ajax spider settings (use largest)
    const spiderMaxDuration = config.spider.maxDuration || 0; // 0 = unlimited
    const ajaxSpiderMaxDuration = config.ajaxSpider.maxDuration || 0;
    const activeScanMaxDuration = config.activeScan.maxScanDurationInMins || 0;
    
    // Use the largest timeout (0 means unlimited)
    const maxDurations = [spiderMaxDuration, ajaxSpiderMaxDuration, activeScanMaxDuration].filter(d => d > 0);
    const maxScanDuration = maxDurations.length > 0 
      ? Math.max(...maxDurations) * 60 * 1000 
      : 0; // 0 = unlimited
    
    const scanStartTime = Date.now();
    
    try {
      console.log(`🧪 TEST/STAGING ENVIRONMENT SCAN - Maximum Aggressiveness`);
      console.log(`🚀 Starting comprehensive automated scan for ${targetUrl}`);
      if (maxScanDuration > 0) {
        console.log(`⏱️ Maximum scan duration: ${Math.floor(maxScanDuration / 60000)} minutes`);
      } else {
        console.log(`⏱️ Maximum scan duration: UNLIMITED`);
      }

      // Start real-time monitoring for alerts and URLs
      await this.zapService.startRealTimeMonitoring(scanId, targetUrl);

      // Check if scan should timeout
      const checkTimeout = () => {
        if (maxScanDuration === 0) return; // Unlimited scan
        
        const elapsedMinutes = Math.floor((Date.now() - scanStartTime) / 60000);
        if (Date.now() - scanStartTime > maxScanDuration) {
          console.log(`⏱️ TIMEOUT: Scan exceeded maximum duration of ${Math.floor(maxScanDuration / 60000)} minutes`);
          throw new Error(`Scan timeout: Maximum duration exceeded (${Math.floor(maxScanDuration / 60000)} minutes)`);
        }
        // Log progress every 5 minutes
        if (elapsedMinutes > 0 && elapsedMinutes % 5 === 0) {
          console.log(`⏱️ Scan running for ${elapsedMinutes} minutes...`);
        }
      };

      // Phase 1: Passive Analysis
      this.emitScanUpdate(scanId, { 
        status: 'running', 
        phase: 'passive_analysis', 
        progress: 5, 
        message: 'Starting passive analysis with real-time monitoring...' 
      });
      await this.zapService.enablePassiveScan();
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Phase 2: Spider Scan (Traditional Crawling)
      this.emitScanUpdate(scanId, { 
        status: 'running', 
        phase: 'spider_scan', 
        progress: 15, 
        message: 'Starting traditional spider crawl...' 
      });

      console.log(`🕷️ Spider configuration:`, {
        maxChildren: config.spider.maxChildren,
        maxDepth: config.spider.maxDepth
      });

      const spiderScanId = await this.zapService.startSpider(targetUrl, {
        maxChildren: config.spider.maxChildren,
        maxDepth: config.spider.maxDepth
      });
      
      // Monitor spider progress with stuck detection
      let spiderProgress = 0;
      let spiderRetries = 0;
      const maxSpiderRetries = 20; // Increased from 5 to 20
      let consecutiveZeroProgressSpider = 0;
      let lastSpiderProgress = -1;
      let spiderStuckCounter = 0;
      const maxSpiderStuckIterations = 10; // If stuck for 10 checks (50 seconds), force continue
      
      console.log(`🕷️ Starting spider scan monitoring (Max retries: ${maxSpiderRetries}, Stuck threshold: ${maxSpiderStuckIterations})`);
      
      while (spiderProgress < 100 && spiderRetries < maxSpiderRetries) {
        checkTimeout(); // Check for timeout
        
        try {
          // Try with scan ID first, fallback to general progress check
          spiderProgress = await this.zapService.getSpiderProgress(spiderScanId);
          
          // If we get 0 progress repeatedly, try without scan ID
          if (spiderProgress === 0) {
            consecutiveZeroProgressSpider++;
            if (consecutiveZeroProgressSpider > 3) {
              console.log(`⚠️ Spider getting 0 progress repeatedly, trying without scan ID...`);
              spiderProgress = await this.zapService.getSpiderProgress();
            }
          } else {
            consecutiveZeroProgressSpider = 0;
          }
          
          // 🚨 STUCK DETECTION for spider
          if (spiderProgress === lastSpiderProgress && spiderProgress < 100) {
            spiderStuckCounter++;
            console.log(`⚠️ Spider progress stuck at ${spiderProgress}% (${spiderStuckCounter}/${maxSpiderStuckIterations})`);
            
            if (spiderStuckCounter >= maxSpiderStuckIterations) {
              console.log(`🔥 FORCING SPIDER COMPLETION: Stuck at ${spiderProgress}% for ${maxSpiderStuckIterations} iterations`);
              spiderProgress = 100;
              break;
            }
          } else {
            if (lastSpiderProgress !== spiderProgress) {
              spiderStuckCounter = 0;
            }
            lastSpiderProgress = spiderProgress;
          }
          
          this.emitScanUpdate(scanId, { 
            status: 'running', 
            phase: 'spider_scan', 
            progress: 15 + (spiderProgress * 0.2), // 15% -> 35%
            message: `Spider crawling: ${spiderProgress}% complete`,
            spider: { progress: spiderProgress, status: 'running' }
          });
          
          // Reset retry counter on successful progress check
          spiderRetries = 0;
          
          if (spiderProgress < 100) {
            await new Promise(resolve => setTimeout(resolve, 4000)); // Check every 4 seconds
          }
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          console.log(`⚠️ Spider progress check failed (${spiderRetries + 1}/${maxSpiderRetries}): ${errorMessage}`);
          spiderRetries++;
          
          if (spiderRetries >= maxSpiderRetries) {
            console.log(`❌ Max retries reached for spider progress check. Forcing completion.`);
            spiderProgress = 100;
            break;
          }
          
          // Exponential backoff
          const waitTime = Math.min(3000 + (spiderRetries * 1000), 10000);
          console.log(`⏱️ Waiting ${waitTime / 1000}s before retry...`);
          await new Promise(resolve => setTimeout(resolve, waitTime));
        }
      }
      
      console.log(`✅ Spider scan completed: ${spiderProgress}% (Retries used: ${spiderRetries}/${maxSpiderRetries})`);
      await this.updateScanUrls(scanId);

      // Phase 3: AJAX Spider (Modern Web Apps)
      this.emitScanUpdate(scanId, { 
        status: 'running', 
        phase: 'ajax_spider', 
        progress: 35, 
        message: 'Starting AJAX spider for dynamic content...' 
      });

      console.log(`🌐 AJAX Spider configuration:`, {
        maxCrawlDepth: config.ajaxSpider.maxCrawlDepth
      });

      const ajaxSpiderId = await this.zapService.startAjaxSpider(targetUrl, {
        maxCrawlDepth: config.ajaxSpider.maxCrawlDepth
      });
      
      // Monitor AJAX spider with stuck detection
      let ajaxProgress = 0;
      let ajaxRunning = true;
      let ajaxRetries = 0;
      const maxAjaxRetries = 15;
      let lastAjaxProgress = -1;
      let ajaxStuckCounter = 0;
      const maxAjaxStuckIterations = 12; // If stuck for 12 checks (60 seconds), force continue
      
      console.log(`🌐 Starting AJAX spider monitoring (Max retries: ${maxAjaxRetries}, Stuck threshold: ${maxAjaxStuckIterations})`);
      
      while (ajaxRunning && ajaxProgress < 100 && ajaxRetries < maxAjaxRetries) {
        checkTimeout(); // Check for timeout
        
        try {
          const ajaxStatus = await this.zapService.getAjaxSpiderStatus();
          ajaxRunning = ajaxStatus.status === 'running';
          ajaxProgress = Math.min(ajaxProgress + 10, 100);
          
          // 🚨 STUCK DETECTION for AJAX spider
          if (ajaxProgress === lastAjaxProgress && ajaxProgress < 100 && ajaxRunning) {
            ajaxStuckCounter++;
            console.log(`⚠️ AJAX spider progress stuck at ${ajaxProgress}% (${ajaxStuckCounter}/${maxAjaxStuckIterations})`);
            
            if (ajaxStuckCounter >= maxAjaxStuckIterations) {
              console.log(`🔥 FORCING AJAX SPIDER COMPLETION: Stuck at ${ajaxProgress}% for ${maxAjaxStuckIterations} iterations`);
              ajaxProgress = 100;
              ajaxRunning = false;
              break;
            }
          } else {
            if (lastAjaxProgress !== ajaxProgress) {
              ajaxStuckCounter = 0;
            }
            lastAjaxProgress = ajaxProgress;
          }
          
          this.emitScanUpdate(scanId, { 
            status: 'running', 
            phase: 'ajax_spider', 
            progress: 35 + (ajaxProgress * 0.15), // 35% -> 50%
            message: `AJAX Spider: ${ajaxProgress}% complete`,
            ajaxSpider: { progress: ajaxProgress, status: ajaxRunning ? 'running' : 'completed' }
          });
          
          ajaxRetries = 0; // Reset on success
          
          if (ajaxRunning && ajaxProgress < 100) {
            await new Promise(resolve => setTimeout(resolve, 5000));
          }
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          console.log(`⚠️ AJAX spider check failed (${ajaxRetries + 1}/${maxAjaxRetries}): ${errorMessage}`);
          ajaxRetries++;
          
          if (ajaxRetries >= maxAjaxRetries) {
            console.log(`❌ Max retries reached for AJAX spider. Forcing completion.`);
            ajaxProgress = 100;
            break;
          }
          
          await new Promise(resolve => setTimeout(resolve, 4000));
        }
      }
      
      console.log(`✅ AJAX spider completed: ${ajaxProgress}% (Retries used: ${ajaxRetries}/${maxAjaxRetries})`);
      await this.updateScanUrls(scanId);

      // Phase 4: Forced Browse (Directory Discovery)
      this.emitScanUpdate(scanId, { 
        status: 'running', 
        phase: 'forced_browse', 
        progress: 50, 
        message: 'Starting forced browsing/directory discovery...' 
      });

      await this.zapService.startForcedBrowse(targetUrl);
      await new Promise(resolve => setTimeout(resolve, 8000));
      await this.updateScanUrls(scanId);

      // Phase 4.5: Wait for Passive Scan Completion
      this.emitScanUpdate(scanId, { 
        status: 'running', 
        phase: 'passive_scan', 
        progress: 55, 
        message: 'Waiting for passive analysis to complete...' 
      });

      const passiveScanCompleted = await this.zapService.waitForPassiveScan(60000); // Wait up to 1 minute
      
      if (passiveScanCompleted) {
      } else {
      }

      // Phase 5: Comprehensive Active Vulnerability Scan
      this.emitScanUpdate(scanId, { 
        status: 'running', 
        phase: 'active_scan', 
        progress: 60, 
        message: 'Starting comprehensive vulnerability testing...' 
      });

      // Enable all scan policies for comprehensive testing
      await this.zapService.enableAllScanPolicies();
      
      console.log(`🔍 Active Scan configuration:`, {
        maxAlertsPerRule: config.activeScan.maxAlertsPerRule,
        threadPerHost: config.activeScan.threadPerHost
      });
      
      const activeScanId = await this.zapService.startActiveScan(targetUrl, {
        maxAlertsPerRule: config.activeScan.maxAlertsPerRule,
        threadPerHost: config.activeScan.threadPerHost
      });

      // Monitor active scan progress with stuck detection
      let activeProgress = 0;
      let activeProgressRetries = 0;
      const maxActiveProgressRetries = 30; // Increased from 10 to 30
      let lastAlertCount = 0; // Önceki alert sayısını takip et
      let consecutiveZeroProgress = 0; // Track consecutive zero progress checks
      let lastProgress = -1; // Track last progress value
      let stuckCounter = 0; // Count how many times progress is stuck
      const maxStuckIterations = 15; // If progress stuck for 15 checks (75 seconds), force continue
      
      console.log(`🔍 Starting active scan monitoring (Max retries: ${maxActiveProgressRetries}, Stuck threshold: ${maxStuckIterations})`);
      
      while (activeProgress < 100 && activeProgressRetries < maxActiveProgressRetries) {
        checkTimeout(); // Check for timeout
        
        try {
          // Try with scan ID first, fallback to general progress check
          activeProgress = await this.zapService.getActiveScanProgress(activeScanId);
          
          // If we get 0 progress repeatedly, try without scan ID
          if (activeProgress === 0) {
            consecutiveZeroProgress++;
            if (consecutiveZeroProgress > 3) {
              console.log(`⚠️ Getting 0 progress repeatedly, trying without scan ID...`);
              activeProgress = await this.zapService.getActiveScanProgress();
            }
          } else {
            consecutiveZeroProgress = 0; // Reset counter on non-zero progress
          }
          
          // 🚨 STUCK DETECTION: Check if progress is stuck at same value
          if (activeProgress === lastProgress && activeProgress < 100) {
            stuckCounter++;
            console.log(`⚠️ Active scan progress stuck at ${activeProgress}% (${stuckCounter}/${maxStuckIterations})`);
            
            if (stuckCounter >= maxStuckIterations) {
              console.log(`🔥 FORCING COMPLETION: Active scan stuck at ${activeProgress}% for ${maxStuckIterations} iterations`);
              console.log(`✅ Treating scan as complete and moving to next phase...`);
              activeProgress = 100;
              break;
            }
          } else {
            // Progress changed, reset stuck counter
            if (lastProgress !== activeProgress) {
              stuckCounter = 0;
            }
            lastProgress = activeProgress;
          }
          
          // Canlı alert güncellemesi için yeni alertleri kontrol et
          try {
            const currentAlerts = await this.zapService.getAlerts(targetUrl);
            
            // Sadece yeni alertleri gönder
            if (currentAlerts.length > lastAlertCount) {
              const newAlerts = currentAlerts.slice(lastAlertCount);
              
              // Her yeni alerti ayrı ayrı gönder
              newAlerts.forEach(alert => {
                this.io?.to(`scan-${scanId}`).emit('vulnerabilityFound', { 
                  scanId, 
                  alert, 
                  timestamp: new Date().toISOString() 
                });
              });
              
              lastAlertCount = currentAlerts.length;
            }
            
            this.emitScanUpdate(scanId, { 
              status: 'running', 
              phase: 'active_scan', 
              progress: 60 + (activeProgress * 0.25), // 60% -> 85%
              message: `Active scanning: ${activeProgress}% - Found ${currentAlerts.length} potential issues`,
              activeScan: { 
                progress: activeProgress, 
                status: 'running',
                alertsFound: currentAlerts.length 
              }
            });
          } catch (alertError) {
            // Alert kontrol hatası varsa sadece progress güncelle
            this.emitScanUpdate(scanId, { 
              status: 'running', 
              phase: 'active_scan', 
              progress: 60 + (activeProgress * 0.25),
              message: `Active scanning: ${activeProgress}% - Checking for vulnerabilities...`,
              activeScan: { 
                progress: activeProgress, 
                status: 'running'
              }
            });
          }
          
          // Reset retry counter on successful progress check
          activeProgressRetries = 0;
          
          if (activeProgress < 100) {
            await new Promise(resolve => setTimeout(resolve, 5000)); // Check every 5 seconds (increased from 3)
          }
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          console.log(`⚠️ Active scan progress check failed (${activeProgressRetries + 1}/${maxActiveProgressRetries}): ${errorMessage}`);
          activeProgressRetries++;
          
          if (activeProgressRetries >= maxActiveProgressRetries) {
            console.log(`❌ Max retries reached for active scan progress check. Forcing completion.`);
            activeProgress = 100;
            break;
          }
          
          // Wait longer before retry - exponential backoff
          const waitTime = Math.min(5000 + (activeProgressRetries * 2000), 15000);
          console.log(`⏱️ Waiting ${waitTime / 1000}s before retry...`);
          await new Promise(resolve => setTimeout(resolve, waitTime));
        }
      }
      
      console.log(`✅ Active scan completed: ${activeProgress}% (Retries used: ${activeProgressRetries}/${maxActiveProgressRetries})`);

      // Phase 6: Specialized Attack Tests
      this.emitScanUpdate(scanId, { 
        status: 'running', 
        phase: 'specialized_attacks', 
        progress: 85, 
        message: 'Running specialized attack tests...' 
      });

      // SQL Injection Tests
      await this.zapService.runSqlInjectionTests(targetUrl);
      await new Promise(resolve => setTimeout(resolve, 3000));

      // XSS Tests
      await this.zapService.runXssTests(targetUrl);
      await new Promise(resolve => setTimeout(resolve, 3000));

      // XXE Tests
      await this.zapService.runXxeTests(targetUrl);
      await new Promise(resolve => setTimeout(resolve, 2000));

      // CSRF Tests
      await this.zapService.runCsrfTests(targetUrl);
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Phase 7: Collecting and Processing Results
      this.emitScanUpdate(scanId, { 
        status: 'running', 
        phase: 'collecting_results', 
        progress: 90, 
        message: 'Collecting and analyzing all scan results...' 
      });

      let alerts: any[] = [];
      try {
        
        // Check alert count first to decide collection strategy
        const alertCount = await this.zapService.getStatus().then(s => s.alerts).catch(() => 0);
        
        if (alertCount > 500) {
          alerts = await this.zapService.getAlertsOptimized(targetUrl, 500);
          console.log(`✅ Collected ${alerts.length} alerts (optimized approach)`);
        } else {
          alerts = await this.zapService.getAlerts(targetUrl);
        }
      } catch (error) {
        console.error('❌ Failed to collect alerts:', error);
        // Fallback to optimized approach
        try {
          alerts = await this.zapService.getAlertsOptimized(targetUrl, 200);
        } catch (fallbackError) {
          console.error('❌ Fallback also failed:', fallbackError);
          alerts = [];
        }
      }
      // Emit vulnerability found events for real-time updates
      alerts.forEach(alert => {
        this.io?.to(`scan-${scanId}`).emit('vulnerabilityFound', { scanId, alert, timestamp: new Date().toISOString() });
      });
      
      // Save vulnerabilities to database with batch processing
      let savedVulnerabilities = 0;
      const batchSize = 50; // Process in batches of 50
      
      
      for (let i = 0; i < alerts.length; i += batchSize) {
        const batch = alerts.slice(i, i + batchSize);
        console.log(`📦 Processing batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(alerts.length / batchSize)} (${batch.length} items)`);
        
        try {
          // Process batch with transaction for better performance
          await this.prisma.$transaction(async (tx) => {
            for (const alert of batch) {
              try {
                await tx.vulnerability.create({
                  data: {
                    id: uuidv4(),
                    scanId: scanId,
                    name: alert.name || 'Unknown Vulnerability',
                    description: alert.description || '',
                    severity: (alert.risk || 'LOW').toUpperCase(),
                    affectedUrl: alert.url || '',
                    param: alert.param || '',
                    attack: alert.attack || '',
                    evidence: alert.evidence || '',
                    solution: alert.solution || '',
                    reference: alert.reference || '',
                    confidence: alert.confidence || 'Medium'
                  }
                });
                savedVulnerabilities++;
              } catch (vulnError) {
                console.error('❌ Failed to save vulnerability in batch:', vulnError);
                // Continue with next vulnerability in batch
              }
            }
          });
          
          console.log(`✅ Batch ${Math.floor(i / batchSize) + 1} completed - saved ${batch.length} vulnerabilities`);
          
          // Small delay between batches to prevent overwhelming the system
          if (i + batchSize < alerts.length) {
            await new Promise(resolve => setTimeout(resolve, 100));
          }
          
        } catch (batchError) {
          console.error(`❌ Failed to process batch ${Math.floor(i / batchSize) + 1}:`, batchError);
          // Continue with next batch
        }
      }


      // Final URL update
      await this.updateScanUrls(scanId);

      // Stop real-time monitoring
      await this.zapService.stopRealTimeMonitoring(scanId);

      console.log(`🔥🔥🔥 CRITICAL: About to update scan ${scanId} status to COMPLETED...`);
      console.log(`🔥🔥🔥 Current time: ${new Date().toISOString()}`);
      
      // Complete scan in database - CRITICAL UPDATE
      try {
        const updatedScan = await this.prisma.scan.update({ 
          where: { id: scanId }, 
          data: { 
            status: 'COMPLETED',
            completedAt: new Date()
          } 
        });
        
        console.log(`✅✅✅ SUCCESS: Scan ${scanId} status updated in database:`, {
          status: updatedScan.status,
          completedAt: updatedScan.completedAt,
          scanId: updatedScan.id
        });
      } catch (updateError) {
        console.error(`❌❌❌ CRITICAL ERROR: Failed to update scan ${scanId} status:`, updateError);
        throw updateError; // Re-throw to ensure error handling
      }

      // Emit completion updates
      this.emitScanUpdate(scanId, { 
        status: 'COMPLETED', 
        phase: 'COMPLETED', 
        progress: 100, 
        message: `Comprehensive scan completed! Found ${alerts.length} vulnerabilities across all test categories.` 
      });

      // Global broadcast for all listeners (including scan history page)
      if (this.io) {
        console.log(`📡 Broadcasting scanStatusChanged event for ${scanId}`);
        this.io.emit('scanStatusChanged', {
          scanId,
          status: 'COMPLETED',
          completedAt: new Date().toISOString(),
          vulnerabilityCount: alerts.length
        });
      }


    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      const errorStack = error instanceof Error ? error.stack : '';
      
      console.error('❌ Error in automated scan process:', {
        scanId,
        targetUrl,
        error: errorMessage,
        stack: errorStack,
        timestamp: new Date().toISOString()
      });
      
      // Stop real-time monitoring on error
      try {
        await this.zapService.stopRealTimeMonitoring(scanId);
      } catch (stopError) {
        console.error('Failed to stop real-time monitoring:', stopError);
      }
      
      // Determine error type for better user feedback
      let userMessage = 'Tarama başarısız oldu';
      let errorType = 'UNKNOWN_ERROR';
      
      if (errorMessage.includes('timeout') || errorMessage.includes('Maximum duration exceeded')) {
        userMessage = 'Tarama zaman aşımına uğradı (Maksimum 45 dakika)';
        errorType = 'TIMEOUT';
      } else if (errorMessage.includes('ECONNREFUSED') || errorMessage.includes('connection')) {
        userMessage = 'Hedef URL\'ye bağlanılamadı. Lütfen URL\'yi kontrol edin.';
        errorType = 'CONNECTION_ERROR';
      } else if (errorMessage.includes('ZAP') || errorMessage.includes('proxy')) {
        userMessage = 'ZAP Proxy bağlantı hatası. Sistem yöneticisi ile iletişime geçin.';
        errorType = 'ZAP_ERROR';
      } else if (errorMessage.includes('403') || errorMessage.includes('Forbidden')) {
        userMessage = 'Hedef site taramayı engelledi (403 Forbidden)';
        errorType = 'ACCESS_DENIED';
      } else if (errorMessage.includes('404') || errorMessage.includes('Not Found')) {
        userMessage = 'Hedef URL bulunamadı (404 Not Found)';
        errorType = 'NOT_FOUND';
      } else if (errorMessage.includes('SSL') || errorMessage.includes('certificate')) {
        userMessage = 'SSL sertifika hatası. HTTPS bağlantısı kurulamadı.';
        errorType = 'SSL_ERROR';
      }
      
      await this.prisma.scan.update({ 
        where: { id: scanId }, 
        data: { 
          status: 'FAILED',
          completedAt: new Date(),
          metadata: {
            errorType,
            errorMessage,
            errorTimestamp: new Date().toISOString()
          }
        } 
      });

      this.emitScanUpdate(scanId, { 
        status: 'failed',
        phase: 'FAILED',
        progress: 0,
        message: userMessage,
        error: {
          type: errorType,
          message: userMessage,
          technicalDetails: errorMessage
        },
        endTime: new Date().toISOString()
      });
      
      // Global broadcast for failure
      if (this.io) {
        this.io.emit('scanStatusChanged', {
          scanId,
          status: 'FAILED',
          completedAt: new Date().toISOString(),
          error: {
            type: errorType,
            message: userMessage
          }
        });
      }
    }
  }

  /**
   * 🛡️ PRODUCTION Environment Scan  
   * Low aggressiveness, safe mode, rate limiting, DB-friendly
   */
  private async runProductionScan(
    scanId: string,
    targetUrl: string,
    config: EnvironmentScanConfig
  ): Promise<void> {
    // Calculate max duration from spider settings (production has limited timeouts)
    const spiderMaxDuration = config.spider.maxDuration || 30; // Default 30 min for production
    const ajaxSpiderMaxDuration = config.ajaxSpider.maxDuration || 20; // Default 20 min
    
    const maxScanDuration = Math.max(spiderMaxDuration, ajaxSpiderMaxDuration) * 60 * 1000;
    const scanStartTime = Date.now();
    
    try {
      console.log(`🛡️ PRODUCTION ENVIRONMENT SCAN - Safe Mode`);
      console.log(`🚀 Starting safe automated scan for ${targetUrl}`);
      console.log(`⏱️ Maximum scan duration: ${Math.floor(maxScanDuration / 60000)} minutes`);
      console.log(`⚠️ Safe Mode: Only read-only tests, NO database writes`);
      console.log(`🐌 Thread Count: ${config.spider.threadCount} (Low impact)`);
      
      await this.zapService.startRealTimeMonitoring(scanId, targetUrl);
      
      const checkTimeout = () => {
        if (Date.now() - scanStartTime > maxScanDuration) {
          throw new Error(`Scan timeout: Maximum duration exceeded (${Math.floor(maxScanDuration / 60000)} minutes)`);
        }
      };
      
      // Phase 1: Passive Scan Only (Safe)
      this.emitScanUpdate(scanId, {
        status: 'running',
        phase: 'passive_analysis',
        progress: 10,
        message: 'Başlatılıyor... (Güvenli Mod - Sadece Okuma Testleri)'
      });
      await this.zapService.enablePassiveScan();
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Phase 2: Limited Spider (Shallow crawl)
      this.emitScanUpdate(scanId, {
        status: 'running',
        phase: 'spider_scan',
        progress: 20,
        message: 'Sınırlı site taraması yapılıyor...'
      });
      
      console.log(`🕷️ Production Spider configuration:`, {
        maxChildren: config.spider.maxChildren,
        maxDepth: config.spider.maxDepth
      });
      
      const spiderScanId = await this.zapService.startSpider(targetUrl, {
        maxChildren: config.spider.maxChildren,
        maxDepth: config.spider.maxDepth
      });
      let spiderProgress = 0;
      let spiderRetries = 0;
      
      while (spiderProgress < 100 && spiderRetries < 10) {
        checkTimeout();
        try {
          spiderProgress = await this.zapService.getSpiderProgress(spiderScanId);
          this.emitScanUpdate(scanId, {
            status: 'running',
            phase: 'spider_scan',
            progress: 20 + (spiderProgress * 0.3),
            message: `Site haritası çıkarılıyor: ${spiderProgress}%`
          });
          spiderRetries = 0;
          if (spiderProgress < 100) {
            await new Promise(resolve => setTimeout(resolve, 5000)); // Slower
          }
        } catch {
          spiderRetries++;
          if (spiderRetries >= 10) break;
          await new Promise(resolve => setTimeout(resolve, 5000));
        }
      }
      
      await this.updateScanUrls(scanId);
      
      // Phase 3: Safe Active Scan (Read-only policies)
      this.emitScanUpdate(scanId, {
        status: 'running',
        phase: 'active_scan',
        progress: 50,
        message: 'Güvenli tarama yapılıyor (DB-friendly)...'
      });
      
      // Enable only safe policies
      await this.zapService.enableSafeScanPolicies();
      
      console.log(`🔍 Production Active Scan configuration:`, {
        maxAlertsPerRule: config.activeScan.maxAlertsPerRule || 100,
        threadPerHost: config.activeScan.threadPerHost || 2
      });
      
      const activeScanId = await this.zapService.startActiveScan(targetUrl, {
        maxAlertsPerRule: config.activeScan.maxAlertsPerRule || 100,
        threadPerHost: config.activeScan.threadPerHost || 2
      });
      
      let activeProgress = 0;
      let activeRetries = 0;
      
      while (activeProgress < 100 && activeRetries < 20) {
        checkTimeout();
        try {
          activeProgress = await this.zapService.getActiveScanProgress(activeScanId);
          
          const currentAlerts = await this.zapService.getAlerts(targetUrl);
          this.emitScanUpdate(scanId, {
            status: 'running',
            phase: 'active_scan',
            progress: 50 + (activeProgress * 0.4),
            message: `Güvenlik kontrolleri: ${activeProgress}% - ${currentAlerts.length} sorun bulundu`
          });
          
          activeRetries = 0;
          if (activeProgress < 100) {
            await new Promise(resolve => setTimeout(resolve, 8000)); // Much slower
          }
        } catch {
          activeRetries++;
          if (activeRetries >= 20) break;
          await new Promise(resolve => setTimeout(resolve, 8000));
        }
      }
      
      // Phase 4: Collect Results
      this.emitScanUpdate(scanId, {
        status: 'running',
        phase: 'collecting_results',
        progress: 90,
        message: 'Sonuçlar toplanıyor...'
      });
      
      // Get alerts with limit (use activeScan maxAlertsPerRule or default to 1000)
      const maxAlerts = config.activeScan.maxAlertsPerRule || 1000;
      const alerts = await this.zapService.getAlertsOptimized(targetUrl, maxAlerts);
      
      alerts.forEach(alert => {
        this.io?.to(`scan-${scanId}`).emit('vulnerabilityFound', { scanId, alert, timestamp: new Date().toISOString() });
      });
      
      // Save vulnerabilities
      let savedCount = 0;
      for (const alert of alerts.slice(0, maxAlerts)) {
        try {
          await this.prisma.vulnerability.create({
            data: {
              id: uuidv4(),
              scanId,
              name: alert.name || 'Unknown Vulnerability',
              description: alert.description || '',
              severity: (alert.risk || 'LOW').toUpperCase(),
              affectedUrl: alert.url || '',
              param: alert.param || '',
              solution: alert.solution || '',
              reference: alert.reference || '',
              confidence: alert.confidence || 'Medium'
            }
          });
          savedCount++;
        } catch (e) {
          console.error('Failed to save vulnerability:', e);
        }
      }
      
      console.log(`✅ PRODUCTION scan completed - ${savedCount} vulnerabilities saved`);
      
      // Mark scan as completed
      await this.prisma.scan.update({
        where: { id: scanId },
        data: { status: 'COMPLETED', completedAt: new Date() }
      });
      
      this.emitScanUpdate(scanId, {
        status: 'completed',
        phase: 'completed',
        progress: 100,
        message: `Güvenli tarama tamamlandı! ${savedCount} güvenlik sorunu tespit edildi.`
      });
      
      await this.zapService.stopRealTimeMonitoring(scanId);
      
      // Auto-generate report (always generate for now, can be made configurable later)
      try {
        const reportFormat = (config.report.format || 'HTML').toLowerCase() as 'html' | 'json';
        await this.generateReport(scanId, reportFormat);
        console.log(`✅ Report generated successfully for scan ${scanId}`);
      } catch (reportError) {
        console.warn(`⚠️ Failed to generate report:`, reportError);
      }
      
    } catch (error) {
      await this.handleScanError(scanId, error, config);
    }
  }

  /**
   * ⚙️ CUSTOM Environment Scan
   * User-defined configuration
   */
  private async runCustomScan(
    scanId: string,
    targetUrl: string,
    config: EnvironmentScanConfig
  ): Promise<void> {
    console.log(`⚙️ CUSTOM ENVIRONMENT SCAN - User Configured`);
    console.log(`Spider: ${config.spider.enabled ? 'ENABLED' : 'DISABLED'}`);
    console.log(`AJAX Spider: ${config.ajaxSpider.enabled ? 'ENABLED' : 'DISABLED'}`);
    console.log(`Active Scan: ${config.activeScan.enabled ? 'ENABLED' : 'DISABLED'}`);
    console.log(`Safe Mode: ${config.security.safeMode ? 'ENABLED' : 'DISABLED'}`);
    
    // For now, route to TEST or PRODUCTION based on safeMode and activeScan
    if (config.security.safeMode || !config.activeScan.enabled) {
      console.log(`🔒 Routing to PRODUCTION scan (Safe mode or no active scan)`);
      return this.runProductionScan(scanId, targetUrl, config);
    } else {
      console.log(`🧪 Routing to TEST/STAGING scan (Active scanning enabled)`);
      return this.runTestStagingScan(scanId, targetUrl, config);
    }
  }

  /**
   * Generate reports after scan completion
   */
  private async generateReportsForScan(
    scanId: string,
    targetUrl: string,
    config: EnvironmentScanConfig
  ): Promise<void> {
    try {
      console.log(`📄 Generating reports for scan ${scanId}...`);
      
      // Generate report in configured format (default to HTML)
      const reportFormat = (config.report.format || 'HTML').toLowerCase() as 'html' | 'json';
      
      try {
        await this.generateReport(scanId, reportFormat);
        console.log(`✅ Report generated successfully in ${reportFormat.toUpperCase()} format`);
      } catch (reportError) {
        console.error(`❌ Failed to generate ${reportFormat.toUpperCase()} report:`, reportError);
      }
      
    } catch (error) {
      console.error('❌ Report generation failed:', error);
    }
  }

  /**
   * Centralized error handling for scans
   */
  private async handleScanError(
    scanId: string,
    error: unknown,
    config: EnvironmentScanConfig
  ): Promise<void> {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : '';
    
    console.error('❌ Scan error:', {
      scanId,
      error: errorMessage,
      stack: errorStack
    });
    
    await this.zapService.stopRealTimeMonitoring(scanId).catch(() => {});
    
    let userMessage = 'Tarama başarısız oldu';
    let errorType = 'UNKNOWN_ERROR';
    
    if (errorMessage.includes('timeout') || errorMessage.includes('Maximum duration exceeded')) {
      userMessage = `Tarama zaman aşımına uğradı`;
      errorType = 'TIMEOUT';
    } else if (errorMessage.includes('ECONNREFUSED')) {
      userMessage = 'Hedef URL\'ye bağlanılamadı';
      errorType = 'CONNECTION_ERROR';
    } else if (errorMessage.includes('ZAP')) {
      userMessage = 'ZAP Proxy bağlantı hatası';
      errorType = 'ZAP_ERROR';
    }
    
    await this.prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'FAILED',
        completedAt: new Date(),
        metadata: { errorType, errorMessage, errorTimestamp: new Date().toISOString() }
      }
    });
    
    this.emitScanUpdate(scanId, {
      status: 'failed',
      phase: 'FAILED',
      progress: 0,
      message: userMessage,
      error: { type: errorType, message: userMessage, technicalDetails: errorMessage }
    });
  }

  async getScanById(scanId: string): Promise<ScanResponse | null> {
    const scan = await this.prisma.scan.findUnique({ where: { id: scanId } });
    return scan ? this.mapScanToResponse(scan) : null;
  }

  async getAllScans(): Promise<ScanResponse[]> {
    const scans = await this.prisma.scan.findMany();
    return scans.map(s => this.mapScanToResponse(s));
  }

  async getScanVulnerabilities(scanId: string): Promise<VulnerabilityResponse[]> {
    const vulns = await this.prisma.vulnerability.findMany({ 
      where: { scanId },
      select: {
        id: true,
        name: true,
        severity: true,
        description: true,
        affectedUrl: true,
        param: true,
        attack: true,
        evidence: true,
        solution: true,
        reference: true,
        confidence: true
      }
    });
    return vulns.map(v => ({
      id: v.id,
      name: v.name,
      severity: v.severity as any,
      description: v.description || '',
      url: v.affectedUrl || undefined,
      param: v.param || undefined,
      attack: v.attack || undefined,
      evidence: v.evidence || undefined,
      solution: v.solution || undefined,
      reference: v.reference || undefined,
      confidence: v.confidence || undefined,
      cweId: null,
      cvssScore: null
    }));
  }

  private generateHtmlReport(scan: any, vulnerabilities: VulnerabilityResponse[]): string {
    const severityColors = {
      'HIGH': '#d32f2f',
      'MEDIUM': '#f57c00', 
      'LOW': '#388e3c',
      'INFO': '#1976d2',
      'CRITICAL': '#b71c1c'
    };
    
    const severityStats = {
      HIGH: vulnerabilities.filter(v => v.severity === 'HIGH').length,
      MEDIUM: vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
      LOW: vulnerabilities.filter(v => v.severity === 'LOW').length,
      INFO: vulnerabilities.filter(v => v.severity === 'INFO').length,
      CRITICAL: vulnerabilities.filter(v => v.severity === 'CRITICAL').length
    };

    const reportDate = new Date().toLocaleString('tr-TR');
    const scanDuration = scan.completedAt && scan.startedAt ? 
      `${Math.round((new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000)} saniye` : 
      'Bilinmiyor';

    return `
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Güvenlik Tarama Raporu - ${scan.name}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header p { margin: 10px 0 0 0; opacity: 0.9; }
        .summary { padding: 30px; border-bottom: 1px solid #eee; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .summary-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #2196F3; }
        .summary-card h3 { margin: 0 0 10px 0; color: #333; }
        .summary-card .number { font-size: 2em; font-weight: bold; color: #2196F3; }
        .severity-chart { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 30px 0; }
        .severity-item { text-align: center; padding: 15px; border-radius: 8px; color: white; font-weight: bold; }
        .vulnerabilities { padding: 30px; }
        .vuln-item { margin: 20px 0; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }
        .vuln-header { padding: 15px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
        .vuln-details { padding: 0 15px 15px 15px; background: #f9f9f9; display: none; }
        .vuln-details.show { display: block; }
        .severity-badge { padding: 4px 12px; border-radius: 20px; color: white; font-size: 0.8em; font-weight: bold; }
        .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 15px 0; }
        .info-item { margin: 10px 0; }
        .info-item strong { color: #333; }
        .footer { background: #333; color: white; padding: 20px; text-align: center; }
        .toggle-btn { background: none; border: none; font-size: 1.2em; cursor: pointer; }
        .no-vulns { text-align: center; padding: 40px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Güvenlik Tarama Raporu</h1>
            <p>${scan.name}</p>
            <p>Tarih: ${reportDate}</p>
        </div>

        <div class="summary">
            <h2>📊 Tarama Özeti</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Hedef URL</h3>
                    <div class="number">${scan.targetUrl}</div>
                </div>
                <div class="summary-card">
                    <h3>Tarama Türü</h3>
                    <div class="number">${scan.scanType}</div>
                </div>
                <div class="summary-card">
                    <h3>Toplam Zafiyet</h3>
                    <div class="number">${vulnerabilities.length}</div>
                </div>
                <div class="summary-card">
                    <h3>Tarama Süresi</h3>
                    <div class="number">${scanDuration}</div>
                </div>
            </div>

            <h3>🎯 Zafiyet Dağılımı</h3>
            <div class="severity-chart">
                <div class="severity-item" style="background-color: ${severityColors.CRITICAL};">
                    <div style="font-size: 1.5em;">${severityStats.CRITICAL}</div>
                    <div>KRİTİK</div>
                </div>
                <div class="severity-item" style="background-color: ${severityColors.HIGH};">
                    <div style="font-size: 1.5em;">${severityStats.HIGH}</div>
                    <div>YÜKSEK</div>
                </div>
                <div class="severity-item" style="background-color: ${severityColors.MEDIUM};">
                    <div style="font-size: 1.5em;">${severityStats.MEDIUM}</div>
                    <div>ORTA</div>
                </div>
                <div class="severity-item" style="background-color: ${severityColors.LOW};">
                    <div style="font-size: 1.5em;">${severityStats.LOW}</div>
                    <div>DÜŞÜK</div>
                </div>
                <div class="severity-item" style="background-color: ${severityColors.INFO};">
                    <div style="font-size: 1.5em;">${severityStats.INFO}</div>
                    <div>BİLGİ</div>
                </div>
            </div>
        </div>

        <div class="vulnerabilities">
            <h2>🔍 Tespit Edilen Zafiyetler</h2>
            ${vulnerabilities.length === 0 ? 
                '<div class="no-vulns"><h3>✅ Tebrikler!</h3><p>Bu taramada herhangi bir güvenlik zafiyeti tespit edilmedi.</p></div>' :
                vulnerabilities.map((vuln, index) => `
                <div class="vuln-item">
                    <div class="vuln-header" onclick="toggleDetails(${index})" style="background-color: ${severityColors[vuln.severity as keyof typeof severityColors]}20;">
                        <div>
                            <span class="severity-badge" style="background-color: ${severityColors[vuln.severity as keyof typeof severityColors]};">
                                ${vuln.severity}
                            </span>
                            <strong style="margin-left: 10px;">${vuln.name}</strong>
                        </div>
                        <button class="toggle-btn" id="btn-${index}">▼</button>
                    </div>
                    <div class="vuln-details" id="details-${index}">
                        <div class="info-grid">
                            <div>
                                <div class="info-item">
                                    <strong>Etkilenen URL:</strong><br>
                                    ${vuln.url || 'Belirtilmemiş'}
                                </div>
                                <div class="info-item">
                                    <strong>Parametre:</strong><br>
                                    ${vuln.param || 'Belirtilmemiş'}
                                </div>
                                <div class="info-item">
                                    <strong>Güven Seviyesi:</strong><br>
                                    ${vuln.confidence || 'Belirtilmemiş'}
                                </div>
                            </div>
                            <div>
                                <div class="info-item">
                                    <strong>Açıklama:</strong><br>
                                    ${vuln.description || 'Açıklama mevcut değil'}
                                </div>
                                ${vuln.solution ? `
                                <div class="info-item">
                                    <strong>Çözüm Önerisi:</strong><br>
                                    ${vuln.solution}
                                </div>
                                ` : ''}
                                ${vuln.evidence ? `
                                <div class="info-item">
                                    <strong>Kanıt:</strong><br>
                                    <code style="background: #f0f0f0; padding: 5px; border-radius: 3px; display: block; margin-top: 5px;">${vuln.evidence}</code>
                                </div>
                                ` : ''}
                            </div>
                        </div>
                    </div>
                </div>
                `).join('')
            }
        </div>

        <div class="footer">
            <p>Bu rapor İBB Güvenlik Test Platformu tarafından ${reportDate} tarihinde otomatik olarak oluşturulmuştur.</p>
            <p>© 2025 İstanbul Büyükşehir Belediyesi - Bilgi İşlem Daire Başkanlığı</p>
        </div>
    </div>

    <script>
        function toggleDetails(index) {
            const details = document.getElementById('details-' + index);
            const btn = document.getElementById('btn-' + index);
            
            if (details.classList.contains('show')) {
                details.classList.remove('show');
                btn.textContent = '▼';
            } else {
                details.classList.add('show');
                btn.textContent = '▲';
            }
        }
    </script>
</body>
</html>`;
  }

  async generateReport(scanId: string, format: 'html' | 'json' = 'html'): Promise<string> {
    const scan = await this.prisma.scan.findUnique({ where: { id: scanId } });
    if (!scan) throw new Error('Scan not found');
    
    // Get all vulnerabilities
    const allVulns = await this.getScanVulnerabilities(scanId);
    
    // 🔥 DEDUPLICATION: Group by name and keep only unique ones (same logic as /data endpoint)
    const uniqueVulnsMap = new Map<string, any>();
    allVulns.forEach(vuln => {
      const key = vuln.name; // Group by vulnerability name only
      if (!uniqueVulnsMap.has(key)) {
        uniqueVulnsMap.set(key, {
          ...vuln,
          affectedUrls: [vuln.url] // Track all affected URLs
        });
      } else {
        // Add URL to existing vulnerability
        const existing = uniqueVulnsMap.get(key);
        if (vuln.url && existing.affectedUrls && !existing.affectedUrls.includes(vuln.url)) {
          existing.affectedUrls.push(vuln.url);
        }
      }
    });
    
    const vulns = Array.from(uniqueVulnsMap.values());
    
    console.log(`📊 Report Statistics:`);
    console.log(`   Total vulnerabilities in DB: ${allVulns.length}`);
    console.log(`   Unique vulnerabilities (deduplicated): ${vulns.length}`);
    
    if (format === 'json') {
      return JSON.stringify({ 
        scan: this.mapScanToResponse(scan), 
        vulnerabilities: vulns,
        statistics: {
          total: allVulns.length,
          unique: vulns.length,
          duplicatesRemoved: allVulns.length - vulns.length
        }
      }, null, 2);
    }
    
    // Use new standardized report generator
    const scanDuration = scan.completedAt && scan.startedAt ?
      `${Math.round((new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime()) / 1000 / 60)} dakika` :
      'Bilinmiyor';
    
    return ReportGeneratorService.generateHtmlReport({
      title: scan.name,
      scanType: scan.scanType === 'MOBILE' ? 'MOBIL_TARAMA' : 'WEB_TARAMASI',
      targetName: this.extractTargetName(scan.targetUrl),
      targetUrl: scan.targetUrl,
      scanDate: scan.startedAt || new Date(),
      scanDuration,
      vulnerabilities: vulns
    });
  }
  
  /**
   * Extract clean target name from URL for reporting
   */
  private extractTargetName(url: string): string {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname.replace('www.', '');
    } catch {
      return url.substring(0, 50);
    }
  }

  async deleteScan(scanId: string): Promise<void> {
    await this.prisma.scan.delete({ where: { id: scanId } });
    this.emitScanUpdate(scanId, { status: 'deleted', message: 'Scan deleted' });
  }

  async updateScanStatus(scanId: string, status: string): Promise<ScanResponse> {
    const updatedScan = await this.prisma.scan.update({
      where: { id: scanId },
      data: { 
        status,
        completedAt: ['COMPLETED', 'FAILED', 'CANCELLED', 'STOPPED'].includes(status) ? new Date() : null
      }
    });
    
    console.log(`📊 Scan ${scanId} status updated: ${status}`);
    
    this.emitScanUpdate(scanId, { 
      status: status.toLowerCase(), 
      message: `Scan status updated to ${status}`,
      timestamp: new Date().toISOString()
    });
    
    // Emit global event for scan history refresh
    if (this.io) {
      this.io.emit('scanStatusChanged', {
        scanId,
        status,
        timestamp: new Date().toISOString()
      });
    }
    
    return this.mapScanToResponse(updatedScan);
  }

  async getScanStatistics(): Promise<any> {
    try {
      const [totalScans, runningScans, completedScans, failedScans, totalVulnerabilities] = await Promise.all([
        this.prisma.scan.count(),
        this.prisma.scan.count({ where: { status: 'RUNNING' } }),
        this.prisma.scan.count({ where: { status: 'COMPLETED' } }),
        this.prisma.scan.count({ where: { status: 'FAILED' } }),
        this.prisma.vulnerability.count()
      ]);

      const vulnerabilitySeverity = await this.prisma.vulnerability.groupBy({
        by: ['severity'],
        _count: {
          severity: true
        }
      });

      const severityStats = {
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0
      };

      vulnerabilitySeverity.forEach(item => {
        if (item.severity && severityStats.hasOwnProperty(item.severity)) {
          severityStats[item.severity as keyof typeof severityStats] = item._count.severity;
        }
      });

      return {
        totalScans,
        runningScans,
        completedScans,
        failedScans,
        totalVulnerabilities,
        vulnerabilitySeverity: severityStats,
        lastUpdate: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error getting scan statistics:', error);
      return {
        totalScans: 0,
        runningScans: 0,
        completedScans: 0,
        failedScans: 0,
        totalVulnerabilities: 0,
        vulnerabilitySeverity: {
          HIGH: 0,
          MEDIUM: 0,
          LOW: 0,
          INFO: 0
        },
        lastUpdate: new Date().toISOString()
      };
    }
  }

  // Get discovered URLs for a scan
  async getScanUrls(scanId: string): Promise<any[]> {
    try {
      // Get scan details
      const scan = await this.prisma.scan.findUnique({ where: { id: scanId } });
      if (!scan) {
        return [];
      }

      // First try to get URLs from database (for completed scans)
      const savedUrls = await this.prisma.scanUrl.findMany({
        where: { scanId: scanId },
        select: { 
          url: true,
          method: true,
          statusCode: true,
          responseTime: true,
          contentType: true,
          size: true,
          timestamp: true
        }
      });

      if (savedUrls.length > 0) {
        return savedUrls.map(u => ({
          url: u.url,
          method: u.method || 'GET',
          statusCode: u.statusCode || 200,
          responseTime: u.responseTime || 0,
          contentType: u.contentType || 'text/html',
          size: u.size || 0,
          timestamp: u.timestamp ? u.timestamp.toISOString() : new Date().toISOString()
        }));
      }

      // If no URLs in database, try to get from ZAP (for running scans)
      try {
        const urls = await this.zapService.getUrls(scan.targetUrl);
        return urls.map(url => ({
          url: url,
          method: 'GET',
          statusCode: 200,
          responseTime: 0,
          contentType: 'text/html',
          size: 0,
          timestamp: new Date().toISOString()
        }));
      } catch (zapError) {
        return [];
      }
    } catch (error) {
      console.error('Error getting scan URLs:', error);
      return [];
    }
  }

  // Get scan details including URLs, vulnerabilities, and summary
  async getScanDetails(scanId: string): Promise<any> {
    try {
      const scan = await this.prisma.scan.findUnique({ where: { id: scanId } });
      if (!scan) {
        throw new Error('Scan not found');
      }

      const [urls, vulnerabilities, zapSummary] = await Promise.all([
        this.getScanUrls(scanId),
        this.getScanVulnerabilities(scanId),
        this.zapService.getScanSummary()
      ]);

      // Get additional ZAP details
      const sites = await this.zapService.getSites();
      const alerts = await this.zapService.getAlerts(scan.targetUrl);

      // Group vulnerabilities by severity
      const vulnStats = {
        HIGH: vulnerabilities.filter(v => v.severity === 'HIGH').length,
        MEDIUM: vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
        LOW: vulnerabilities.filter(v => v.severity === 'LOW').length,
        INFO: vulnerabilities.filter(v => v.severity === 'INFO').length
      };

      return {
        scan: this.mapScanToResponse(scan),
        urls: urls,
        sites: sites,
        vulnerabilities: vulnerabilities,
        vulnerabilityStats: vulnStats,
        summary: {
          totalUrls: urls.length,
          totalSites: sites.length,
          totalVulnerabilities: vulnerabilities.length,
          totalAlerts: alerts.length,
          scanDuration: scan.completedAt && scan.startedAt ? 
            new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime() : 0
        },
        lastUpdate: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error getting scan details:', error);
      throw error;
    }
  }

  // Update scan URLs during scanning process
  private async updateScanUrls(scanId: string): Promise<void> {
    try {
      const scan = await this.prisma.scan.findUnique({ where: { id: scanId } });
      if (!scan) return;

      const urls = await this.zapService.getUrls(scan.targetUrl);
      const sites = await this.zapService.getSites();

      // Mevcut URL'leri al, yalnızca yeni olanları gönder
      const existingUrls = await this.prisma.scanUrl.findMany({
        where: { scanId: scanId },
        select: { url: true }
      });
      
      const existingUrlSet = new Set(existingUrls.map(u => u.url));
      const newUrls = urls.filter(url => !existingUrlSet.has(url));

      // Yeni URL'leri canlı olarak gönder
      newUrls.forEach(url => {
        this.io?.to(`scan-${scanId}`).emit('urlFound', { 
          scanId, 
          url, 
          method: 'GET',
          statusCode: 200,
          responseTime: 0,
          contentType: 'text/html',
          size: 0,
          timestamp: new Date().toISOString() 
        });
      });

      if (newUrls.length > 0) {
      }

      // Save URLs to database
      
      // First, clear existing URLs for this scan
      await this.prisma.scanUrl.deleteMany({
        where: { scanId: scanId }
      });

      // Save new URLs in batches
      const batchSize = 50;
      for (let i = 0; i < urls.length; i += batchSize) {
        const batch = urls.slice(i, i + batchSize);
        
        try {
          await this.prisma.$transaction(async (tx) => {
            for (const url of batch) {
              await tx.scanUrl.create({
                data: {
                  scanId: scanId,
                  url: url,
                  method: 'GET', // Default method
                  statusCode: 200, // Default status
                  responseTime: 0, // Will be updated if available
                  contentType: 'text/html', // Default content type
                  size: 0, // Will be updated if available
                  timestamp: new Date()
                }
              });
            }
          });
          
          console.log(`✅ Saved batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(urls.length / batchSize)} to database`);
        } catch (batchError) {
          console.error(`❌ Failed to save URL batch ${Math.floor(i / batchSize) + 1}:`, batchError);
        }
      }

      // Genel güncelleme gönder
      this.emitScanUpdate(scanId, {
        urlsFound: urls.length,
        sitesFound: sites.length,
        newUrlsCount: newUrls.length,
        message: `Toplam ${urls.length} URL keşfedildi${newUrls.length > 0 ? ` (${newUrls.length} yeni)` : ''}`
      });
      
    } catch (error) {
    }
  }
}
