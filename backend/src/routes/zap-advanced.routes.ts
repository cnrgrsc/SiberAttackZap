import { ZapAdvancedService } from '../services/zapAdvancedService';
import { ApiSecurityDeepDiveService } from '../services/ApiSecurityDeepDiveService';
import { Router, Request, Response } from 'express';

const router = Router();

/**
 * 🚀 ADVANCED ZAP API ROUTES
 * Bu route'lar ZAP'tan maksimum veri çekmek için tasarlandı
 */

// Comprehensive data collection endpoint
router.post('/comprehensive-analysis', async (req: Request, res: Response) => {
  try {
    const { targetUrl } = req.body;
    
    if (!targetUrl) {
      return res.status(400).json({ error: 'Target URL is required' });
    }

    const zapAdvanced = new ZapAdvancedService(req.app.get('io'));
    
    
    // ZAP'tan tüm verileri topla
    const allZapData = await zapAdvanced.collectAllZapData(targetUrl);
    
    // JavaScript güvenlik analizi  
    const jsAnalysis = await zapAdvanced.analyzeJavaScriptSecurity(targetUrl);
    
    // API güvenlik analizi
    const apiAnalysis = await zapAdvanced.analyzeApiSecurity(targetUrl);
    
    // Davranış analizi
    const behaviorAnalysis = await zapAdvanced.analyzeBehavior(targetUrl);
    
    // Kapsamlı değerlendirme
    const comprehensiveAssessment = await zapAdvanced.performComprehensiveAssessment(targetUrl);
    
    const response = {
      success: true,
      timestamp: new Date().toISOString(),
      targetUrl,
      analysis: {
        zapData: allZapData,
        javascript: jsAnalysis,
        api: apiAnalysis,
        behavior: behaviorAnalysis,
        comprehensive: comprehensiveAssessment
      },
      summary: {
        totalDataPoints: Object.keys(allZapData.categories).length,
        jsLibraries: jsAnalysis.libraries?.length || 0,
        apiEndpoints: apiAnalysis.endpoints?.length || 0,
        behaviorPatterns: behaviorAnalysis.ajaxCalls?.length || 0,
        recommendations: comprehensiveAssessment.recommendations?.length || 0
      }
    };
    
    console.log(`📊 Data points collected: ${response.summary.totalDataPoints}`);
    
    res.json(response);
    
  } catch (error: any) {
    console.error('❌ Comprehensive analysis error:', error);
    
    // More detailed error response
    const errorResponse = {
      success: false,
      error: 'Analysis failed',
      message: error.message || 'Unknown error occurred',
      timestamp: new Date().toISOString(),
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    };
    
    res.status(500).json(errorResponse);
  }
});

// 🔍 API Security Deep Dive Endpoint
router.post('/api-security-deep-dive', async (req: Request, res: Response) => {
  try {
    const { targetUrl } = req.body;
    
    if (!targetUrl) {
      return res.status(400).json({ error: 'Target URL is required' });
    }

    
    const apiSecurityService = new ApiSecurityDeepDiveService(req.app.get('io'));
    
    // Perform comprehensive API security analysis
    const deepDiveResults = await apiSecurityService.performApiSecurityDeepDive(targetUrl);
    
    const response = {
      success: true,
      timestamp: new Date().toISOString(),
      targetUrl,
      deepDive: deepDiveResults,
      summary: {
        totalEndpoints: deepDiveResults.summary.totalEndpoints,
        vulnerabilitiesFound: deepDiveResults.summary.vulnerabilitiesFound,
        securityScore: deepDiveResults.summary.securityScore,
        riskLevel: deepDiveResults.summary.riskLevel,
        recommendations: deepDiveResults.recommendations?.length || 0
      }
    };
    
    console.log(`🎯 Endpoints analyzed: ${response.summary.totalEndpoints}`);
    console.log(`📊 Security Score: ${response.summary.securityScore}/100`);
    
    res.json(response);
    
  } catch (error: any) {
    console.error('❌ API Security Deep Dive error:', error);
    
    const errorResponse = {
      success: false,
      error: 'API Security Deep Dive failed',
      message: error.message || 'Unknown error occurred',
      timestamp: new Date().toISOString(),
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    };
    
    res.status(500).json(errorResponse);
  }
});

// Get all available ZAP endpoints  
router.get('/available-endpoints', async (req: Request, res: Response) => {
  try {
    const zapAdvanced = new ZapAdvancedService();
    
    // Get all endpoint categories
    const endpointCategories = {
      core: [
        '/JSON/core/view/version/',
        '/JSON/core/view/stats/',
        '/JSON/core/view/mode/',
        '/JSON/core/view/hosts/',
        '/JSON/core/view/sites/',
        '/JSON/core/view/urls/',
        '/JSON/core/view/messages/',
        '/JSON/core/view/numberOfAlerts/',
        '/JSON/core/view/alerts/',
        '/JSON/core/view/sessionLocation/'
      ],
      spider: [
        '/JSON/spider/view/status/',
        '/JSON/spider/view/results/',
        '/JSON/spider/view/fullResults/',
        '/JSON/spider/view/scans/',
        '/JSON/spider/view/optionMaxDepth/',
        '/JSON/spider/view/optionMaxChildren/'
      ],
      ascan: [
        '/JSON/ascan/view/status/',
        '/JSON/ascan/view/scans/',
        '/JSON/ascan/view/scanProgress/',
        '/JSON/ascan/view/policies/',
        '/JSON/ascan/view/scanners/'
      ],
      ajaxSpider: [
        '/JSON/ajaxSpider/view/status/',
        '/JSON/ajaxSpider/view/results/',
        '/JSON/ajaxSpider/view/numberOfResults/',
        '/JSON/ajaxSpider/view/fullResults/'
      ],
      technology: [
        '/JSON/wappalyzer/view/listSites/',
        '/JSON/wappalyzer/view/listTechnologies/',
        '/JSON/technology/view/optionTechnologyDetectionInCDN/'
      ],
      authentication: [
        '/JSON/authentication/view/getSupportedAuthenticationMethods/',
        '/JSON/authentication/view/getAuthenticationMethodConfigParams/'
      ],
      context: [
        '/JSON/context/view/contextList/',
        '/JSON/context/view/includeRegexs/',
        '/JSON/context/view/excludeRegexs/'
      ]
    };

    const totalEndpoints = Object.values(endpointCategories)
      .reduce((total, endpoints) => total + endpoints.length, 0);

    res.json({
      success: true,
      totalCategories: Object.keys(endpointCategories).length,
      totalEndpoints,
      categories: endpointCategories,
      description: "Bu endpoint'ler ZAP'tan maksimum veri çekmek için kullanılacak"
    });

  } catch (error: any) {
    res.status(500).json({ 
      error: 'Failed to get endpoints', 
      message: error.message 
    });
  }  
});

// Test single ZAP endpoint
router.get('/test-endpoint', async (req: Request, res: Response) => {
  try {
    const { endpoint } = req.query;
    
    if (!endpoint || typeof endpoint !== 'string') {
      return res.status(400).json({ error: 'Endpoint parameter is required' });
    }

    const zapAdvanced = new ZapAdvancedService();
    
    // Test the endpoint
    const result = await (zapAdvanced as any).zapClient.get(endpoint);
    
    res.json({
      success: true,
      endpoint,
      data: result.data,
      timestamp: new Date().toISOString()
    });

  } catch (error: any) {
    res.status(500).json({ 
      error: 'Endpoint test failed', 
      endpoint: req.query.endpoint,
      message: error.message 
    });
  }
});

// Enhanced vulnerability analysis
router.post('/enhanced-vulnerability-analysis', async (req: Request, res: Response) => {
  try {
    const { targetUrl, includeAI = false } = req.body;
    
    if (!targetUrl) {
      return res.status(400).json({ error: 'Target URL is required' });
    }

    const zapAdvanced = new ZapAdvancedService(req.app.get('io'));
    
    
    // Comprehensive assessment
    const assessment = await zapAdvanced.performComprehensiveAssessment(targetUrl);
    
    // Add AI analysis if requested
    let aiAnalysis = null;
    if (includeAI) {
      // Future: AI analysis integration
      aiAnalysis = {
        falsePositives: [],
        enhancedSeverity: [],
        smartRecommendations: [],
        confidence: 0.85
      };
    }
    
    const response = {
      success: true,
      targetUrl,
      timestamp: assessment.timestamp,
      vulnerabilities: assessment.vulnerabilities,
      compliance: assessment.compliance,
      recommendations: assessment.recommendations,
      aiAnalysis,
      summary: {
        critical: assessment.vulnerabilities?.critical?.length || 0,
        high: assessment.vulnerabilities?.high?.length || 0,  
        medium: assessment.vulnerabilities?.medium?.length || 0,
        low: assessment.vulnerabilities?.low?.length || 0,
        total: Object.values(assessment.vulnerabilities || {})
          .reduce((sum: number, alerts: any) => sum + (alerts?.length || 0), 0)
      }
    };
    
    console.log(`🎯 Total vulnerabilities found: ${response.summary.total}`);
    
    res.json(response);
    
  } catch (error: any) {
    console.error('Enhanced vulnerability analysis error:', error);
    res.status(500).json({ 
      error: 'Enhanced analysis failed', 
      message: error.message 
    });
  }
});

// Get ZAP system information
router.get('/zap-system-info', async (req: Request, res: Response) => {
  try {
    const zapAdvanced = new ZapAdvancedService();
    
    // Get comprehensive system info
    const systemInfo = {
      zapStatus: 'unknown',
      version: 'unknown',
      availableAddons: [],
      systemCapabilities: {},
      supportedFeatures: []
    };

    try {
      // Test ZAP connection and get version
      const versionResponse = await (zapAdvanced as any).zapClient.get('/JSON/core/view/version/');
      systemInfo.zapStatus = 'connected';
      systemInfo.version = versionResponse.data.version;
      
      // Get available add-ons (if endpoint exists)
      try {
        const addonsResponse = await (zapAdvanced as any).zapClient.get('/JSON/core/view/addons/');
        systemInfo.availableAddons = addonsResponse.data.addons || [];
      } catch {
        // Addon endpoint might not exist
      }
      
      // Test key capabilities
      const capabilities: any = {
        spider: false,
        ajaxSpider: false,
        activeScan: false,
        wappalyzer: false,
        retire: false,
        openapi: false,
        graphql: false
      };
      
      // Test each capability
      const testEndpoints = [
        { name: 'spider', endpoint: '/JSON/spider/view/status/' },
        { name: 'ajaxSpider', endpoint: '/JSON/ajaxSpider/view/status/' },
        { name: 'activeScan', endpoint: '/JSON/ascan/view/status/' },
        { name: 'wappalyzer', endpoint: '/JSON/wappalyzer/view/listSites/' },
        { name: 'retire', endpoint: '/JSON/retire/view/getRepoUrl/' },
        { name: 'openapi', endpoint: '/JSON/openapi/view/generators/' },
        { name: 'graphql', endpoint: '/JSON/graphql/view/optionMaxQueryDepth/' }
      ];
      
      for (const test of testEndpoints) {
        try {
          await (zapAdvanced as any).zapClient.get(test.endpoint);
          capabilities[test.name] = true;
          (systemInfo.supportedFeatures as string[]).push(test.name);
        } catch {
          // Feature not available
        }
      }
      
      systemInfo.systemCapabilities = capabilities;
      
    } catch (error: any) {
      systemInfo.zapStatus = 'disconnected';
      console.error('ZAP connection error:', error.message);
    }

    res.json({
      success: true,
      systemInfo,
      recommendations: [
        systemInfo.zapStatus === 'connected' ? 
          '✅ ZAP connection successful' : 
          '❌ ZAP bağlantısı kurulamadı - ZAP Proxy çalışıyor mu?',
        
        systemInfo.supportedFeatures.length > 3 ? 
          `✅ ${systemInfo.supportedFeatures.length} advanced feature available` :
          '⚠️ Some advanced features may not be available',
          
        (systemInfo.systemCapabilities as any)?.wappalyzer ? 
          '✅ Technology detection ready' :
          '⚠️ Wappalyzer addon recommended for enhanced analysis'
      ]
    });

  } catch (error: any) {
    res.status(500).json({ 
      error: 'System info check failed', 
      message: error.message 
    });
  }
});

export default router;
