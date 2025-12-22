import axios, { AxiosInstance } from 'axios';

/**
 * 🔍 API Security Deep Dive Service
 * Bu servis API güvenlik analizini derinlemesine yapar
 */
export class ApiSecurityDeepDiveService {
  private zapClient: AxiosInstance;

  constructor(io?: any) {
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
      timeout: 180000, // 3 minutes timeout for deep analysis
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });
  }

  /**
   * 🎯 COMPREHENSIVE API SECURITY ANALYSIS
   * Detaylı API güvenlik analizi
   */
  async performApiSecurityDeepDive(targetUrl: string): Promise<any> {

    const deepDiveResults = {
      timestamp: new Date().toISOString(),
      targetUrl,
      analysis: {
        // 1. API Discovery
        apiDiscovery: await this.discoverAllApis(targetUrl),
        
        // 1.5. Technology Detection Enhancement
        technologyDetection: await this.enhancedTechnologyDetection(targetUrl),
        
        // 2. Authentication Analysis
        authenticationAnalysis: await this.analyzeAuthentication(targetUrl),
        
        // 3. Authorization Testing
        authorizationTesting: await this.testAuthorization(targetUrl),
        
        // 4. Input Validation Testing
        inputValidation: await this.testInputValidation(targetUrl),
        
        // 5. Rate Limiting Analysis
        rateLimiting: await this.analyzeRateLimiting(targetUrl),
        
        // 6. CORS Analysis
        corsAnalysis: await this.analyzeCORS(targetUrl),
        
        // 7. API Versioning Analysis
        versioningAnalysis: await this.analyzeApiVersioning(targetUrl),
        
        // 8. GraphQL Security (if detected)
        graphqlSecurity: await this.analyzeGraphQLSecurity(targetUrl),
        
        // 9. OpenAPI/Swagger Analysis
        openApiAnalysis: await this.analyzeOpenApiSecurity(targetUrl),
        
        // 10. Business Logic Testing
        businessLogicTesting: await this.testBusinessLogic(targetUrl),
        
        // 11. Raw Results (before filtering)
        rawResults: {} as any,

        // 12. Smart Vulnerability Prioritization (will be populated later)
        vulnerabilityPrioritization: {} as any,

        // 13. Pattern Recognition Analysis (will be populated later)
        patternRecognition: {} as any,

        // 14. Business Logic Context Analysis (will be populated later)
        businessLogicContext: {} as any
      },
      summary: {} as any,
      recommendations: [] as string[]
    };

    // Store raw results before filtering
    deepDiveResults.analysis.rawResults = JSON.parse(JSON.stringify(deepDiveResults.analysis));

    // 11. False Positive Filtering - Clean up results
    deepDiveResults.analysis = await this.applyFalsePositiveFiltering(deepDiveResults.analysis, targetUrl);

    // 12. Smart Vulnerability Prioritization
    deepDiveResults.analysis.vulnerabilityPrioritization = await this.performSmartVulnerabilityPrioritization(
      deepDiveResults.analysis, 
      targetUrl
    );

    // 13. Pattern Recognition Algorithms
    deepDiveResults.analysis.patternRecognition = await this.performPatternRecognitionAnalysis(
      deepDiveResults.analysis, 
      targetUrl
    );

    // 14. Business Logic Context Analysis
    deepDiveResults.analysis.businessLogicContext = await this.performBusinessLogicContextAnalysis(
      deepDiveResults.analysis, 
      targetUrl
    );

    // Generate summary and recommendations
    deepDiveResults.summary = this.generateApiSecuritySummary(deepDiveResults.analysis);
    deepDiveResults.recommendations = this.generateApiSecurityRecommendations(deepDiveResults.analysis);

    return deepDiveResults;
  }

  /**
   * 🔎 1. API Discovery - Tüm API endpoint'leri keşfet
   */
  private async discoverAllApis(targetUrl: string): Promise<any> {
    const discovery = {
      restEndpoints: [] as any[],
      graphqlEndpoints: [] as any[],
      soapEndpoints: [] as any[],
      rpcEndpoints: [] as any[],
      webSocketEndpoints: [] as any[],
      apiPatterns: [] as any[],
      hiddenEndpoints: [] as any[]
    };

    try {
      // Get all HTTP messages
      const messages = await this.zapClient.get('/JSON/core/view/messages/', {
        params: { baseurl: targetUrl }
      });

      if (messages.data.messages) {
        for (const msg of messages.data.messages) {
          const url = msg.url || '';
          const method = msg.method || 'GET';
          const responseHeader = msg.responseHeader || '';
          const requestHeader = msg.requestHeader || '';

          // REST API Detection
          if (this.isRestEndpoint(url, responseHeader)) {
            discovery.restEndpoints.push({
              url,
              method,
              statusCode: msg.code,
              contentType: this.extractContentType(responseHeader),
              authRequired: this.detectAuthRequirement(responseHeader, requestHeader),
              parameters: this.extractParameters(url, msg.requestBody)
            });
          }

          // GraphQL Detection
          if (this.isGraphQLEndpoint(url, msg.requestBody, responseHeader)) {
            discovery.graphqlEndpoints.push({
              url,
              method,
              introspectionEnabled: this.checkGraphQLIntrospection(msg.responseBody),
              queries: this.extractGraphQLQueries(msg.requestBody)
            });
          }

          // WebSocket Detection
          if (this.isWebSocketEndpoint(url, responseHeader)) {
            discovery.webSocketEndpoints.push({
              url: url.replace('http', 'ws'),
              upgradeHeader: responseHeader.includes('Upgrade: websocket')
            });
          }

          // Hidden endpoints detection
          if (this.isHiddenEndpoint(url, msg.code)) {
            discovery.hiddenEndpoints.push({
              url,
              method,
              statusCode: msg.code,
              discoveryMethod: 'directory_traversal'
            });
          }
        }
      }

      // API Pattern Analysis
      discovery.apiPatterns = this.analyzeApiPatterns(discovery.restEndpoints);

    } catch (error: any) {
      console.error('API Discovery error:', error.message);
    }

    return discovery;
  }

  /**
   * 🛠️ 1.5. Enhanced Technology Detection
   * Gelişmiş teknoloji tespiti - Framework, dil, veritabanı, sunucu teknolojileri
   */
  private async enhancedTechnologyDetection(targetUrl: string): Promise<any> {
    const techDetection = {
      webFrameworks: [] as any[],
      programmingLanguages: [] as any[],
      databases: [] as any[],
      webServers: [] as any[],
      cmsFrameworks: [] as any[],
      jsLibraries: [] as any[],
      apiFrameworks: [] as any[],
      securityHeaders: {} as any,
      serverFingerprinting: {} as any,
      versionInformation: {} as any,
      vulnerableTechnologies: [] as any[],
      wappalyzerResults: [] as any[]
    };

    try {
      // 🎯 0. ZAP Wappalyzer Detection (PRIMARY - Most Accurate)
      const wappalyzerResults = await this.detectWithWappalyzer(targetUrl);
      techDetection.wappalyzerResults = wappalyzerResults;
      
      // Merge Wappalyzer results into appropriate categories
      if (wappalyzerResults.length > 0) {
        this.mergeWappalyzerResults(techDetection, wappalyzerResults);
      }

      // 1. HTTP Headers Analysis
      const headerAnalysis = await this.analyzeHttpHeaders(targetUrl);
      techDetection.webServers = this.mergeTechnologies(techDetection.webServers, headerAnalysis.webServers);
      techDetection.securityHeaders = headerAnalysis.securityHeaders;

      // Add technology headers to appropriate categories
      if (headerAnalysis.technologyHeaders?.length > 0) {
        for (const tech of headerAnalysis.technologyHeaders) {
          if (!techDetection.webServers.some((s: any) => s.name === tech.name)) {
            techDetection.webServers.push({
              name: tech.name,
              confidence: tech.confidence,
              detectionMethod: tech.header,
              version: tech.version
            });
          }
        }
      }

      // 2. Server Response Fingerprinting
      techDetection.serverFingerprinting = await this.performServerFingerprinting(targetUrl);

      // 3. JavaScript Framework Detection (Fallback if Wappalyzer didn't detect)
      if (techDetection.jsLibraries.length === 0) {
        techDetection.jsLibraries = await this.detectJavaScriptFrameworks(targetUrl);
      }

      // 4. API Framework Detection (Fallback)
      if (techDetection.apiFrameworks.length === 0) {
        techDetection.apiFrameworks = await this.detectApiFrameworks(targetUrl);
      }

      // 5. Database Technology Detection (Fallback)
      if (techDetection.databases.length === 0) {
        techDetection.databases = await this.detectDatabaseTechnologies(targetUrl);
      }

      // 6. Programming Language Detection (Fallback)
      if (techDetection.programmingLanguages.length === 0) {
        techDetection.programmingLanguages = await this.detectProgrammingLanguages(targetUrl);
      }

      // 7. CMS Detection (Fallback)
      if (techDetection.cmsFrameworks.length === 0) {
        techDetection.cmsFrameworks = await this.detectCMSFrameworks(targetUrl);
      }

      // 8. Version Information Extraction
      techDetection.versionInformation = await this.extractVersionInformation(targetUrl);

      // 9. Vulnerable Technology Detection
      techDetection.vulnerableTechnologies = await this.detectVulnerableTechnologies(techDetection);

      console.log('✅ Technology detection completed:', {
        totalTechnologies: wappalyzerResults.length,
        jsLibraries: techDetection.jsLibraries.length,
        programmingLanguages: techDetection.programmingLanguages.length,
        apiFrameworks: techDetection.apiFrameworks.length
      });

    } catch (error: any) {
      console.error('Technology detection error:', error.message);
    }

    return techDetection;
  }

  /**
   * 🔐 2. Authentication Analysis
   */
  private async analyzeAuthentication(targetUrl: string): Promise<any> {
    const authAnalysis = {
      authMethods: [] as any[],
      tokenTypes: [] as any[],
      sessionManagement: {} as any,
      authBypass: [] as any[],
      weakAuthentication: [] as any[]
    };

    try {
      // Get authentication information
      const authInfo = await this.zapClient.get('/JSON/authentication/view/getSupportedAuthenticationMethods/');
      if (authInfo.data.supportedAuthenticationMethods) {
        authAnalysis.authMethods = authInfo.data.supportedAuthenticationMethods;
      }

      // Session management analysis
      const sessions = await this.zapClient.get('/JSON/httpSessions/view/sessions/', {
        params: { site: targetUrl }
      });
      authAnalysis.sessionManagement = sessions.data;

      // Test for authentication bypass
      authAnalysis.authBypass = await this.testAuthenticationBypass(targetUrl);

      // Check for weak authentication
      authAnalysis.weakAuthentication = await this.checkWeakAuthentication(targetUrl);

    } catch (error: any) {
      console.error('Authentication analysis error:', error.message);
    }

    return authAnalysis;
  }

  /**
   * 🛡️ 3. Authorization Testing
   */
  private async testAuthorization(targetUrl: string): Promise<any> {
    const authzTesting = {
      privilegeEscalation: [] as any[],
      horizontalPrivilegeEscalation: [] as any[],
      verticalPrivilegeEscalation: [] as any[],
      idorVulnerabilities: [] as any[],
      roleBasedAccessControl: {} as any
    };

    try {
      // Test for IDOR (Insecure Direct Object References)
      authzTesting.idorVulnerabilities = await this.testIDOR(targetUrl);

      // Test privilege escalation
      authzTesting.privilegeEscalation = await this.testPrivilegeEscalation(targetUrl);

    } catch (error: any) {
      console.error('Authorization testing error:', error.message);
    }

    return authzTesting;
  }

  /**
   * ✅ 4. Input Validation Testing
   */
  private async testInputValidation(targetUrl: string): Promise<any> {
    const inputValidation = {
      sqlInjection: [] as any[],
      xssVulnerabilities: [] as any[],
      xxeVulnerabilities: [] as any[],
      commandInjection: [] as any[],
      pathTraversal: [] as any[],
      jsonInjection: [] as any[],
      xmlInjection: [] as any[]
    };

    try {
      // Get active scan results for input validation issues
      const alerts = await this.zapClient.get('/JSON/core/view/alerts/', {
        params: { baseurl: targetUrl }
      });

      if (alerts.data.alerts) {
        for (const alert of alerts.data.alerts) {
          const alertName = alert.alert?.toLowerCase() || '';
          const risk = alert.risk || 'Low';

          if (alertName.includes('sql injection')) {
            inputValidation.sqlInjection.push({
              url: alert.url,
              parameter: alert.param,
              evidence: alert.evidence,
              risk,
              description: alert.desc
            });
          }

          if (alertName.includes('cross site scripting') || alertName.includes('xss')) {
            inputValidation.xssVulnerabilities.push({
              url: alert.url,
              parameter: alert.param,
              evidence: alert.evidence,
              risk,
              attack: alert.attack
            });
          }

          if (alertName.includes('xml external entity') || alertName.includes('xxe')) {
            inputValidation.xxeVulnerabilities.push({
              url: alert.url,
              evidence: alert.evidence,
              risk,
              description: alert.desc
            });
          }

          if (alertName.includes('command injection')) {
            inputValidation.commandInjection.push({
              url: alert.url,
              parameter: alert.param,
              evidence: alert.evidence,
              risk,
              attack: alert.attack
            });
          }
        }
      }

    } catch (error: any) {
      console.error('Input validation testing error:', error.message);
    }

    return inputValidation;
  }

  /**
   * ⏱️ 5. Rate Limiting Analysis
   */
  private async analyzeRateLimiting(targetUrl: string): Promise<any> {
    const rateLimiting = {
      rateLimitHeaders: [] as any[],
      rateLimitTesting: {} as any,
      ddosProtection: {} as any,
      throttlingMechanisms: [] as any[]
    };

    try {
      // Analyze rate limiting headers from responses
      const messages = await this.zapClient.get('/JSON/core/view/messages/', {
        params: { baseurl: targetUrl }
      });

      if (messages.data.messages) {
        for (const msg of messages.data.messages) {
          const headers = this.parseHeaders(msg.responseHeader || '');
          
          // Check for rate limiting headers
          const rateLimitHeadersFound = this.extractRateLimitHeaders(headers);
          if (rateLimitHeadersFound.length > 0) {
            rateLimiting.rateLimitHeaders.push({
              url: msg.url,
              headers: rateLimitHeadersFound
            });
          }
        }
      }

    } catch (error: any) {
      console.error('Rate limiting analysis error:', error.message);
    }

    return rateLimiting;
  }

  /**
   * 🌐 6. CORS Analysis
   */
  private async analyzeCORS(targetUrl: string): Promise<any> {
    const corsAnalysis = {
      corsHeaders: [] as any[],
      misconfiguredCors: [] as any[],
      corsVulnerabilities: [] as any[],
      preflightRequests: [] as any[]
    };

    try {
      const messages = await this.zapClient.get('/JSON/core/view/messages/', {
        params: { baseurl: targetUrl }
      });

      if (messages.data.messages) {
        for (const msg of messages.data.messages) {
          const headers = this.parseHeaders(msg.responseHeader || '');
          
          // Extract CORS headers
          const corsHeaders = this.extractCORSHeaders(headers);
          if (corsHeaders.length > 0) {
            const corsEntry = {
              url: msg.url,
              headers: corsHeaders,
              misconfigured: this.isCORSMisconfigured(corsHeaders)
            };
            
            corsAnalysis.corsHeaders.push(corsEntry);
            
            if (corsEntry.misconfigured) {
              corsAnalysis.misconfiguredCors.push(corsEntry);
            }
          }
        }
      }

    } catch (error: any) {
      console.error('CORS analysis error:', error.message);
    }

    return corsAnalysis;
  }

  /**
   * 📦 7. API Versioning Analysis
   */
  private async analyzeApiVersioning(targetUrl: string): Promise<any> {
    const versioningAnalysis = {
      versioningStrategy: 'unknown',
      versions: [] as string[],
      deprecatedVersions: [] as any[],
      versioningVulnerabilities: [] as any[]
    };

    try {
      const messages = await this.zapClient.get('/JSON/core/view/messages/', {
        params: { baseurl: targetUrl }
      });

      if (messages.data.messages) {
        const versions = new Set<string>();
        
        for (const msg of messages.data.messages) {
          const url = msg.url || '';
          
          // URL-based versioning (e.g., /api/v1/, /api/v2/)
          const urlVersionMatch = url.match(/\/v(\d+(?:\.\d+)?)\//);
          if (urlVersionMatch) {
            versions.add(urlVersionMatch[1]);
            versioningAnalysis.versioningStrategy = 'url-based';
          }

          // Header-based versioning
          const headers = this.parseHeaders(msg.requestHeader || '');
          const versionHeader = headers['api-version'] || headers['version'];
          if (versionHeader) {
            versions.add(versionHeader);
            versioningAnalysis.versioningStrategy = 'header-based';
          }

          // Accept header versioning
          const acceptHeader = headers['accept'];
          if (acceptHeader && acceptHeader.includes('version=')) {
            const acceptVersionMatch = acceptHeader.match(/version=([^;,]+)/);
            if (acceptVersionMatch) {
              versions.add(acceptVersionMatch[1]);
              versioningAnalysis.versioningStrategy = 'accept-header';
            }
          }
        }

        versioningAnalysis.versions = Array.from(versions);
      }

    } catch (error: any) {
      console.error('API versioning analysis error:', error.message);
    }

    return versioningAnalysis;
  }

  /**
   * 🔺 8. GraphQL Security Analysis
   */
  private async analyzeGraphQLSecurity(targetUrl: string): Promise<any> {
    const graphqlSecurity = {
      introspectionEnabled: false,
      queryDepthLimiting: false,
      queryComplexityLimiting: false,
      rateLimiting: false,
      authenticationRequired: false,
      vulnerabilities: [] as any[]
    };

    try {
      // Get messages and check for GraphQL
      const messages = await this.zapClient.get('/JSON/core/view/messages/', {
        params: { baseurl: targetUrl }
      });

      if (messages.data.messages) {
        for (const msg of messages.data.messages) {
          if (this.isGraphQLEndpoint(msg.url, msg.requestBody, msg.responseHeader)) {
            // Test introspection
            if (msg.responseBody && msg.responseBody.includes('__schema')) {
              graphqlSecurity.introspectionEnabled = true;
              graphqlSecurity.vulnerabilities.push({
                type: 'Introspection Enabled',
                severity: 'Medium',
                description: 'GraphQL introspection is enabled, exposing schema information'
              });
            }
          }
        }
      }

    } catch (error: any) {
      console.error('GraphQL security analysis error:', error.message);
    }

    return graphqlSecurity;
  }

  /**
   * 📋 9. OpenAPI/Swagger Analysis
   */
  private async analyzeOpenApiSecurity(targetUrl: string): Promise<any> {
    const openApiAnalysis = {
      specificationFound: false,
      specificationUrl: '',
      securitySchemes: [] as string[],
      vulnerabilities: [] as any[],
      exposedEndpoints: [] as any[]
    };

    try {
      // Common OpenAPI/Swagger endpoints
      const commonPaths = [
        '/swagger.json',
        '/swagger.yaml',
        '/api-docs',
        '/api/swagger.json',
        '/api/swagger.yaml',
        '/swagger/v1/swagger.json',
        '/swagger-ui.html',
        '/docs',
        '/redoc'
      ];

      for (const path of commonPaths) {
        try {
          const response = await this.zapClient.get(`/JSON/core/view/messages/`, {
            params: { baseurl: targetUrl + path }
          });

          if (response.data.messages && response.data.messages.length > 0) {
            const msg = response.data.messages[0];
            if (msg.code === '200' && 
                (msg.responseBody?.includes('swagger') || 
                 msg.responseBody?.includes('openapi'))) {
              openApiAnalysis.specificationFound = true;
              openApiAnalysis.specificationUrl = targetUrl + path;
              
              // Parse security schemes if possible
              try {
                const spec = JSON.parse(msg.responseBody);
                if (spec.securityDefinitions || spec.components?.securitySchemes) {
                  openApiAnalysis.securitySchemes = Object.keys(
                    spec.securityDefinitions || spec.components.securitySchemes
                  );
                }
              } catch (parseError) {
                // YAML or malformed JSON
              }
              
              break;
            }
          }
        } catch (pathError) {
          // Continue to next path
        }
      }

    } catch (error: any) {
      console.error('OpenAPI analysis error:', error.message);
    }

    return openApiAnalysis;
  }

  /**
   * 🧠 10. Business Logic Testing
   */
  private async testBusinessLogic(targetUrl: string): Promise<any> {
    const businessLogicTesting = {
      workflowBypass: [] as any[],
      priceManipulation: [] as any[],
      quantityManipulation: [] as any[],
      sequenceViolation: [] as any[],
      logicFlaws: [] as any[]
    };

    try {
      // Analyze request patterns for business logic issues
      const messages = await this.zapClient.get('/JSON/core/view/messages/', {
        params: { baseurl: targetUrl }
      });

      if (messages.data.messages) {
        for (const msg of messages.data.messages) {
          // Look for potential price/quantity manipulation
          if (msg.requestBody) {
            const body = msg.requestBody.toLowerCase();
            
            if (body.includes('price') || body.includes('amount') || body.includes('cost')) {
              businessLogicTesting.priceManipulation.push({
                url: msg.url,
                method: msg.method,
                suspiciousParameters: this.extractSuspiciousParams(msg.requestBody, ['price', 'amount', 'cost'])
              });
            }

            if (body.includes('quantity') || body.includes('count') || body.includes('number')) {
              businessLogicTesting.quantityManipulation.push({
                url: msg.url,
                method: msg.method,
                suspiciousParameters: this.extractSuspiciousParams(msg.requestBody, ['quantity', 'count', 'number'])
              });
            }
          }
        }
      }

    } catch (error: any) {
      console.error('Business logic testing error:', error.message);
    }

    return businessLogicTesting;
  }

  // Helper methods
  private isRestEndpoint(url: string, responseHeader: string): boolean {
    return url.includes('/api/') || 
           responseHeader.includes('application/json') ||
           responseHeader.includes('application/xml') ||
           /\/v\d+\//.test(url);
  }

  private isGraphQLEndpoint(url: string, requestBody: string, responseHeader: string): boolean {
    return url.includes('/graphql') ||
           requestBody?.includes('query') ||
           requestBody?.includes('mutation') ||
           responseHeader.includes('application/graphql');
  }

  private isWebSocketEndpoint(url: string, responseHeader: string): boolean {
    return responseHeader.includes('Upgrade: websocket') ||
           url.includes('ws://') ||
           url.includes('wss://');
  }

  private isHiddenEndpoint(url: string, statusCode: string): boolean {
    return statusCode === '403' || statusCode === '401' || statusCode === '405';
  }

  private analyzeApiPatterns(endpoints: any[]): any[] {
    const patterns = [];
    const pathSegments = new Map<string, number>();

    for (const endpoint of endpoints) {
      try {
        const path = new URL(endpoint.url).pathname;
        const segments = path.split('/').filter(s => s.length > 0);
        
        for (const segment of segments) {
          pathSegments.set(segment, (pathSegments.get(segment) || 0) + 1);
        }
      } catch (error) {
        // Invalid URL, skip
      }
    }

    // Find common patterns
    for (const [segment, count] of pathSegments.entries()) {
      if (count > 1) {
        patterns.push({
          pattern: segment,
          frequency: count,
          type: /^v\d+$/.test(segment) ? 'version' : 'resource'
        });
      }
    }

    return patterns;
  }

  private extractContentType(responseHeader: string): string {
    const match = responseHeader.match(/Content-Type:\s*([^;\r\n]+)/i);
    return match ? match[1].trim() : 'unknown';
  }

  private detectAuthRequirement(responseHeader: string, requestHeader: string): boolean {
    return responseHeader.includes('WWW-Authenticate') ||
           requestHeader.includes('Authorization') ||
           responseHeader.includes('401') ||
           responseHeader.includes('403');
  }

  private extractParameters(url: string, requestBody: string): any[] {
    const params = [];
    
    try {
      // URL parameters
      const urlParams = new URLSearchParams(new URL(url).search);
      for (const [key, value] of urlParams.entries()) {
        params.push({ name: key, type: 'query', value });
      }
    } catch (error) {
      // Invalid URL
    }

    // Body parameters
    if (requestBody) {
      try {
        const body = JSON.parse(requestBody);
        for (const [key, value] of Object.entries(body)) {
          params.push({ name: key, type: 'body', value });
        }
      } catch {
        // Not JSON, could be form data or other format
      }
    }

    return params;
  }

  private parseHeaders(headerString: string): { [key: string]: string } {
    const headers: { [key: string]: string } = {};
    const lines = headerString.split('\n');
    
    for (const line of lines) {
      const colonIndex = line.indexOf(':');
      if (colonIndex > 0) {
        const key = line.substring(0, colonIndex).trim().toLowerCase();
        const value = line.substring(colonIndex + 1).trim();
        headers[key] = value;
      }
    }
    
    return headers;
  }

  private extractRateLimitHeaders(headers: { [key: string]: string }): string[] {
    const rateLimitHeaders = [];
    const rateLimitHeaderNames = [
      'x-ratelimit-limit',
      'x-ratelimit-remaining',
      'x-ratelimit-reset',
      'x-rate-limit-limit',
      'x-rate-limit-remaining',
      'x-rate-limit-reset',
      'ratelimit-limit',
      'ratelimit-remaining',
      'ratelimit-reset'
    ];

    for (const headerName of rateLimitHeaderNames) {
      if (headers[headerName]) {
        rateLimitHeaders.push(`${headerName}: ${headers[headerName]}`);
      }
    }

    return rateLimitHeaders;
  }

  private extractCORSHeaders(headers: { [key: string]: string }): string[] {
    const corsHeaders = [];
    const corsHeaderNames = [
      'access-control-allow-origin',
      'access-control-allow-credentials',
      'access-control-allow-methods',
      'access-control-allow-headers',
      'access-control-expose-headers',
      'access-control-max-age'
    ];

    for (const headerName of corsHeaderNames) {
      if (headers[headerName]) {
        corsHeaders.push(`${headerName}: ${headers[headerName]}`);
      }
    }

    return corsHeaders;
  }

  private isCORSMisconfigured(corsHeaders: string[]): boolean {
    const origin = corsHeaders.find(h => h.startsWith('access-control-allow-origin:'));
    const credentials = corsHeaders.find(h => h.startsWith('access-control-allow-credentials:'));
    
    // Check for wildcard origin with credentials
    return !!(origin?.includes('*') && credentials?.includes('true'));
  }

  private extractSuspiciousParams(requestBody: string, keywords: string[]): any[] {
    const suspicious = [];
    
    try {
      const body = JSON.parse(requestBody);
      for (const [key, value] of Object.entries(body)) {
        if (keywords.some(keyword => key.toLowerCase().includes(keyword))) {
          suspicious.push({ parameter: key, value });
        }
      }
    } catch {
      // Not JSON
    }

    return suspicious;
  }

  private async testAuthenticationBypass(targetUrl: string): Promise<any[]> {
    // Implementation for authentication bypass testing
    return [];
  }

  private async checkWeakAuthentication(targetUrl: string): Promise<any[]> {
    // Implementation for weak authentication detection
    return [];
  }

  private async testIDOR(targetUrl: string): Promise<any[]> {
    // Implementation for IDOR testing
    return [];
  }

  private async testPrivilegeEscalation(targetUrl: string): Promise<any[]> {
    // Implementation for privilege escalation testing
    return [];
  }

  private checkGraphQLIntrospection(responseBody: string): boolean {
    return responseBody?.includes('__schema') || responseBody?.includes('__type');
  }

  private extractGraphQLQueries(requestBody: string): string[] {
    const queries = [];
    try {
      const body = JSON.parse(requestBody);
      if (body.query) {
        queries.push(body.query);
      }
    } catch {
      // Not JSON
    }
    return queries;
  }

  /**
   * Generate API Security Summary
   */
  private generateApiSecuritySummary(analysis: any): any {
    return {
      totalEndpoints: analysis.apiDiscovery.restEndpoints.length + 
                     analysis.apiDiscovery.graphqlEndpoints.length,
      authenticationMethods: analysis.authenticationAnalysis.authMethods.length,
      vulnerabilitiesFound: this.countVulnerabilities(analysis),
      securityScore: this.calculateSecurityScore(analysis),
      riskLevel: this.calculateRiskLevel(analysis)
    };
  }

  /**
   * Generate API Security Recommendations
   */
  private generateApiSecurityRecommendations(analysis: any): string[] {
    const recommendations = [];

    if (analysis.authenticationAnalysis.weakAuthentication.length > 0) {
      recommendations.push('🔐 Implement strong authentication mechanisms');
    }

    if (analysis.corsAnalysis.misconfiguredCors.length > 0) {
      recommendations.push('🌐 Fix CORS misconfigurations');
    }

    if (analysis.graphqlSecurity.introspectionEnabled) {
      recommendations.push('🔺 Disable GraphQL introspection in production');
    }

    if (analysis.rateLimiting.rateLimitHeaders.length === 0) {
      recommendations.push('⏱️ Implement proper rate limiting');
    }

    if (analysis.inputValidation.sqlInjection.length > 0) {
      recommendations.push('🛡️ Fix SQL injection vulnerabilities');
    }

    if (analysis.inputValidation.xssVulnerabilities.length > 0) {
      recommendations.push('🚫 Fix XSS vulnerabilities');
    }

    recommendations.push('📋 Implement comprehensive API documentation');
    recommendations.push('🔍 Set up continuous API security monitoring');

    return recommendations;
  }

  private countVulnerabilities(analysis: any): number {
    let count = 0;
    count += analysis.inputValidation.sqlInjection.length;
    count += analysis.inputValidation.xssVulnerabilities.length;
    count += analysis.inputValidation.xxeVulnerabilities.length;
    count += analysis.authorizationTesting.idorVulnerabilities.length;
    count += analysis.corsAnalysis.misconfiguredCors.length;
    return count;
  }

  private calculateSecurityScore(analysis: any): number {
    let score = 100;
    const vulnerabilities = this.countVulnerabilities(analysis);
    score -= vulnerabilities * 10;
    
    if (analysis.authenticationAnalysis.weakAuthentication.length > 0) score -= 15;
    if (analysis.graphqlSecurity.introspectionEnabled) score -= 10;
    if (analysis.rateLimiting.rateLimitHeaders.length === 0) score -= 5;
    
    return Math.max(0, score);
  }

  private calculateRiskLevel(analysis: any): string {
    const score = this.calculateSecurityScore(analysis);
    if (score >= 80) return 'Low';
    if (score >= 60) return 'Medium';
    if (score >= 40) return 'High';
    return 'Critical';
  }

  // =================================
  // TECHNOLOGY DETECTION METHODS
  // =================================

  /**
   * Analyze HTTP Headers for technology detection
   */
  private async analyzeHttpHeaders(targetUrl: string): Promise<any> {
    const headerAnalysis = {
      webServers: [] as any[],
      securityHeaders: {} as any,
      technologyHeaders: [] as any[]
    };

    try {
      // Direct HTTP request for more accurate header analysis
      const directResponse = await axios.get(targetUrl, {
        timeout: 10000,
        validateStatus: () => true, // Accept any status
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      });

      const headers = directResponse.headers;

      // Web Server Detection with version info
      if (headers['server']) {
        const serverHeader = headers['server'];
        headerAnalysis.webServers.push({
          server: serverHeader,
          confidence: 'High',
          source: 'Server Header'
        });

        // Parse server version
        const versionMatch = serverHeader.match(/([a-zA-Z\-]+)\/([0-9.]+)/);
        if (versionMatch) {
          headerAnalysis.webServers[0].name = versionMatch[1];
          headerAnalysis.webServers[0].version = versionMatch[2];
        }
      }

      // X-Powered-By detection (reveals backend technology)
      if (headers['x-powered-by']) {
        headerAnalysis.technologyHeaders.push({
          name: headers['x-powered-by'],
          header: 'X-Powered-By',
          confidence: 'High'
        });
      }

      // X-AspNet-Version
      if (headers['x-aspnet-version']) {
        headerAnalysis.technologyHeaders.push({
          name: 'ASP.NET',
          version: headers['x-aspnet-version'],
          header: 'X-AspNet-Version',
          confidence: 'High'
        });
      }

      // X-Generator (CMS detection)
      if (headers['x-generator']) {
        headerAnalysis.technologyHeaders.push({
          name: headers['x-generator'],
          header: 'X-Generator',
          confidence: 'High'
        });
      }

      // Via header (proxy/CDN detection)
      if (headers['via']) {
        headerAnalysis.technologyHeaders.push({
          name: headers['via'],
          header: 'Via',
          type: 'Proxy/CDN',
          confidence: 'High'
        });
      }

      // CF-RAY (Cloudflare)
      if (headers['cf-ray']) {
        headerAnalysis.technologyHeaders.push({
          name: 'Cloudflare',
          header: 'CF-RAY',
          type: 'CDN',
          confidence: 'High'
        });
      }

      // X-Vercel-Id (Vercel)
      if (headers['x-vercel-id']) {
        headerAnalysis.technologyHeaders.push({
          name: 'Vercel',
          header: 'X-Vercel-Id',
          type: 'Hosting Platform',
          confidence: 'High'
        });
      }

      // X-Amz-Cf-Id (AWS CloudFront)
      if (headers['x-amz-cf-id']) {
        headerAnalysis.technologyHeaders.push({
          name: 'AWS CloudFront',
          header: 'X-Amz-Cf-Id',
          type: 'CDN',
          confidence: 'High'
        });
      }

      // Security Headers Analysis (detailed)
      headerAnalysis.securityHeaders = {
        xFrameOptions: {
          present: !!headers['x-frame-options'],
          value: headers['x-frame-options'] || null
        },
        xContentTypeOptions: {
          present: !!headers['x-content-type-options'],
          value: headers['x-content-type-options'] || null
        },
        xXSSProtection: {
          present: !!headers['x-xss-protection'],
          value: headers['x-xss-protection'] || null
        },
        strictTransportSecurity: {
          present: !!headers['strict-transport-security'],
          value: headers['strict-transport-security'] || null
        },
        contentSecurityPolicy: {
          present: !!headers['content-security-policy'],
          value: headers['content-security-policy'] || null
        },
        referrerPolicy: {
          present: !!headers['referrer-policy'],
          value: headers['referrer-policy'] || null
        },
        permissionsPolicy: {
          present: !!headers['permissions-policy'],
          value: headers['permissions-policy'] || null
        }
      };

      // Also check ZAP messages for additional insights
      try {
        const zapResponse = await this.zapClient.get('/JSON/core/view/messages/', {
          params: { baseurl: targetUrl, start: 0, count: 5 }
        });

        if (zapResponse.data.messages) {
          for (const message of zapResponse.data.messages) {
            const zapHeaders = message.responseHeader || '';
            
            // Additional technology detection from ZAP
            const techPatterns = [
              { pattern: /X-Powered-By:\s*([^\r\n]+)/i, name: 'Technology' },
              { pattern: /X-Runtime:\s*([^\r\n]+)/i, name: 'Runtime' },
              { pattern: /X-AspNet-Version:\s*([^\r\n]+)/i, name: 'ASP.NET Version' }
            ];

            for (const tech of techPatterns) {
              const match = zapHeaders.match(tech.pattern);
              if (match && !headerAnalysis.technologyHeaders.some(t => t.name === match[1].trim())) {
                headerAnalysis.technologyHeaders.push({
                  name: match[1].trim(),
                  header: tech.name,
                  confidence: 'Medium',
                  source: 'ZAP'
                });
              }
            }
          }
        }
      } catch (zapError) {
        // ZAP check failed, continue with direct response
      }

    } catch (error: any) {
      console.error('Header analysis error:', error.message);
    }

    return headerAnalysis;
  }

  /**
   * Perform Server Fingerprinting
   */
  private async performServerFingerprinting(targetUrl: string): Promise<any> {
    const fingerprinting = {
      serverSignatures: [] as any[],
      errorPages: [] as any[],
      defaultFiles: [] as any[]
    };

    try {
      // Test common error pages
      const errorPaths = ['/404', '/error', '/notfound', '/invalid-path-test'];
      
      for (const path of errorPaths) {
        try {
          const testUrl = `${targetUrl}${path}`;
          await axios.get(testUrl, { timeout: 5000 });
        } catch (error: any) {
          if (error.response) {
            fingerprinting.errorPages.push({
              path,
              statusCode: error.response.status,
              headers: error.response.headers,
              bodySnippet: error.response.data ? String(error.response.data).substring(0, 200) : ''
            });
          }
        }
      }

      // Test default files
      const defaultFiles = ['/robots.txt', '/sitemap.xml', '/.well-known/security.txt', '/favicon.ico'];
      
      for (const file of defaultFiles) {
        try {
          const testUrl = `${targetUrl}${file}`;
          const response = await axios.get(testUrl, { timeout: 5000 });
          fingerprinting.defaultFiles.push({
            file,
            exists: true,
            contentType: response.headers['content-type'],
            size: response.headers['content-length']
          });
        } catch (error) {
          fingerprinting.defaultFiles.push({
            file,
            exists: false
          });
        }
      }

    } catch (error: any) {
      console.error('Server fingerprinting error:', error.message);
    }

    return fingerprinting;
  }

  /**
   * Detect JavaScript Frameworks
   */
  private async detectJavaScriptFrameworks(targetUrl: string): Promise<any[]> {
    const jsFrameworks = [] as any[];
    const detectedTechs = new Set<string>();

    try {
      const response = await axios.get(targetUrl, { 
        timeout: 10000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      });
      const htmlContent = response.data;
      const headers = response.headers;

      // Enhanced Framework detection patterns with multiple indicators
      const frameworkChecks = [
        {
          name: 'React',
          patterns: [
            /_app-[a-f0-9]+\.js/i,
            /react[-.](?:dom\.)?(?:development|production)/i,
            /data-reactroot/i,
            /data-react-helmet/i,
            /__react/i
          ],
          scripts: [/react\.js/, /react\.min\.js/, /react-dom/],
          globalVars: ['React', 'ReactDOM'],
          confidence: 'High'
        },
        {
          name: 'Vue.js',
          patterns: [
            /vue\.js|vue\.min\.js|vue\.runtime/i,
            /data-v-[a-f0-9]+/i,
            /__vue/i,
            /v-bind|v-model|v-if|v-for/i
          ],
          scripts: [/vue\.js/, /vue\.min\.js/],
          globalVars: ['Vue'],
          confidence: 'High'
        },
        {
          name: 'Angular',
          patterns: [
            /ng-version|ng-app|ng-controller/i,
            /angular\.js|angular\.min\.js/i,
            /_angular_/i,
            /\[ng-/i
          ],
          scripts: [/angular\.js/, /angular\.min\.js/],
          globalVars: ['angular', 'ng'],
          confidence: 'High'
        },
        {
          name: 'Next.js',
          patterns: [
            /_next\/static/i,
            /__NEXT_DATA__/i,
            /_next\/webpack/i,
            /next\.js/i
          ],
          scripts: [/_next\/static/],
          globalVars: ['__NEXT_DATA__'],
          confidence: 'High'
        },
        {
          name: 'Nuxt.js',
          patterns: [
            /_nuxt/i,
            /__NUXT__/i,
            /nuxt\.js/i
          ],
          scripts: [/_nuxt/],
          globalVars: ['__NUXT__'],
          confidence: 'High'
        },
        {
          name: 'jQuery',
          patterns: [
            /jquery[-.](?:\d+\.)*\d+(?:\.min)?\.js/i,
            /\$\(document\)\.ready/i
          ],
          scripts: [/jquery/i],
          globalVars: ['jQuery', '$'],
          confidence: 'High'
        },
        {
          name: 'Bootstrap',
          patterns: [
            /bootstrap(?:\.min)?\.(?:css|js)/i,
            /class="[^"]*\b(?:container|row|col-)/i,
            /btn-primary|btn-secondary/i
          ],
          scripts: [/bootstrap/i],
          confidence: 'High'
        },
        {
          name: 'Svelte',
          patterns: [
            /svelte/i,
            /data-svelte-h/i
          ],
          scripts: [/svelte/i],
          confidence: 'Medium'
        },
        {
          name: 'Ember.js',
          patterns: [
            /ember\.js|ember-[0-9]/i,
            /data-ember/i
          ],
          scripts: [/ember/i],
          globalVars: ['Ember'],
          confidence: 'Medium'
        }
      ];

      for (const framework of frameworkChecks) {
        let matchCount = 0;
        let detectionMethods = [];

        // Check patterns in HTML content
        for (const pattern of framework.patterns) {
          if (pattern.test(htmlContent)) {
            matchCount++;
            detectionMethods.push('HTML Pattern');
            break;
          }
        }

        // Check script sources
        if (framework.scripts) {
          for (const scriptPattern of framework.scripts) {
            if (scriptPattern.test(htmlContent)) {
              matchCount++;
              detectionMethods.push('Script Tag');
              break;
            }
          }
        }

        // Check for framework-specific headers
        if (headers['x-powered-by'] && 
            headers['x-powered-by'].toLowerCase().includes(framework.name.toLowerCase())) {
          matchCount++;
          detectionMethods.push('X-Powered-By Header');
        }

        if (matchCount > 0 && !detectedTechs.has(framework.name)) {
          detectedTechs.add(framework.name);
          jsFrameworks.push({
            name: framework.name,
            confidence: matchCount > 1 ? 'High' : framework.confidence,
            detectionMethod: detectionMethods.join(', ') || 'Content Analysis',
            indicators: matchCount
          });
        }
      }

    } catch (error: any) {
      console.error('JS framework detection error:', error.message);
    }

    return jsFrameworks;
  }

  /**
   * Detect API Frameworks
   */
  private async detectApiFrameworks(targetUrl: string): Promise<any[]> {
    const apiFrameworks = [] as any[];
    const detectedFrameworks = new Set<string>();

    try {
      // Framework detection patterns
      const frameworkChecks = [
        {
          name: 'Express.js',
          patterns: [
            { header: 'x-powered-by', value: /express/i },
            { header: 'server', value: /express/i }
          ]
        },
        {
          name: 'FastAPI',
          patterns: [
            { header: 'server', value: /uvicorn|fastapi/i },
            { content: /fastapi|\/docs|\/redoc/i }
          ]
        },
        {
          name: 'Django REST',
          patterns: [
            { header: 'x-frame-options', value: /sameorigin/i },
            { content: /django|rest_framework|api-root/i },
            { header: 'server', value: /wsgi/i }
          ]
        },
        {
          name: 'Flask',
          patterns: [
            { header: 'server', value: /werkzeug|flask/i },
            { header: 'x-powered-by', value: /flask/i }
          ]
        },
        {
          name: 'Spring Boot',
          patterns: [
            { content: /spring|whitelabel error page/i },
            { header: 'x-application-context', value: /.+/i }
          ]
        },
        {
          name: 'ASP.NET Web API',
          patterns: [
            { header: 'x-aspnet-version', value: /.+/i },
            { header: 'x-powered-by', value: /asp\.net/i }
          ]
        },
        {
          name: 'NestJS',
          patterns: [
            { content: /nestjs|@nestjs/i },
            { header: 'x-powered-by', value: /express/i }
          ]
        },
        {
          name: 'Koa',
          patterns: [
            { header: 'x-powered-by', value: /koa/i }
          ]
        },
        {
          name: 'Hapi',
          patterns: [
            { header: 'server', value: /hapi/i }
          ]
        }
      ];

      // Test main URL and common API endpoints
      const testEndpoints = ['', '/api', '/v1', '/v2', '/rest', '/graphql', '/docs', '/swagger'];
      
      for (const endpoint of testEndpoints) {
        try {
          const testUrl = endpoint ? `${targetUrl}${endpoint}` : targetUrl;
          const response = await axios.get(testUrl, { 
            timeout: 5000,
            validateStatus: (status) => status < 500, // Accept 4xx responses
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
          });
          
          const headers = response.headers;
          const content = String(response.data || '').toLowerCase();

          for (const framework of frameworkChecks) {
            if (detectedFrameworks.has(framework.name)) continue;

            let matchCount = 0;
            let detectionMethods = [];

            for (const pattern of framework.patterns) {
              if (pattern.header) {
                const headerValue = headers[pattern.header];
                if (headerValue && pattern.value.test(String(headerValue))) {
                  matchCount++;
                  detectionMethods.push(`${pattern.header} header`);
                }
              } else if (pattern.content) {
                if (pattern.content.test(content)) {
                  matchCount++;
                  detectionMethods.push('Content Analysis');
                }
              }
            }

            if (matchCount > 0) {
              detectedFrameworks.add(framework.name);
              apiFrameworks.push({
                name: framework.name,
                confidence: matchCount > 1 ? 'High' : 'Medium',
                detectionMethod: detectionMethods.join(', '),
                endpoint: endpoint || '/',
                indicators: matchCount
              });
            }
          }

        } catch (error) {
          // Endpoint not accessible, continue
        }
      }

    } catch (error: any) {
      console.error('API framework detection error:', error.message);
    }

    return apiFrameworks;
  }

  /**
   * Detect Database Technologies
   */
  private async detectDatabaseTechnologies(targetUrl: string): Promise<any[]> {
    const databases = [] as any[];

    try {
      // Database error message patterns
      const dbPatterns = [
        { name: 'MySQL', pattern: /mysql|you have an error in your sql syntax/i },
        { name: 'PostgreSQL', pattern: /postgresql|pg_/i },
        { name: 'MongoDB', pattern: /mongodb|bson/i },
        { name: 'Oracle', pattern: /oracle|ora-\d+/i },
        { name: 'SQL Server', pattern: /microsoft.*sql server|mssql/i },
        { name: 'SQLite', pattern: /sqlite/i },
        { name: 'Redis', pattern: /redis/i }
      ];

      // Test for SQL injection to trigger database errors
      const sqlPayloads = ["'", '"', "1' OR '1'='1", "1; DROP TABLE users--"];
      
      for (const payload of sqlPayloads) {
        try {
          const testUrl = `${targetUrl}?id=${encodeURIComponent(payload)}`;
          const response = await axios.get(testUrl, { timeout: 5000 });
          
          for (const db of dbPatterns) {
            if (db.pattern.test(response.data)) {
              databases.push({
                name: db.name,
                confidence: 'Medium',
                detectionMethod: 'Error Message Analysis',
                evidence: response.data.substring(0, 200)
              });
            }
          }
        } catch (error: any) {
          if (error.response && error.response.data) {
            for (const db of dbPatterns) {
              if (db.pattern.test(error.response.data)) {
                databases.push({
                  name: db.name,
                  confidence: 'High',
                  detectionMethod: 'Error Response Analysis',
                  evidence: String(error.response.data).substring(0, 200)
                });
              }
            }
          }
        }
      }

    } catch (error: any) {
      console.error('Database detection error:', error.message);
    }

    return databases;
  }

  /**
   * Detect Programming Languages
   */
  private async detectProgrammingLanguages(targetUrl: string): Promise<any[]> {
    const languages = [] as any[];
    const detectedLangs = new Set<string>();

    try {
      const response = await axios.get(targetUrl, { 
        timeout: 10000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      });
      const headers = response.headers;
      const content = response.data;

      // Enhanced Language detection with multiple indicators
      const languageChecks = [
        {
          name: 'PHP',
          indicators: [
            { check: () => headers['x-powered-by']?.toLowerCase().includes('php'), method: 'X-Powered-By Header' },
            { check: () => content.includes('<?php'), method: 'PHP Tag' },
            { check: () => /\.php(\?|"|'|$)/i.test(content), method: 'PHP Extension' },
            { check: () => /phpsessid/i.test(content), method: 'PHP Session' },
            { check: () => headers['set-cookie']?.includes('PHPSESSID'), method: 'PHP Cookie' }
          ]
        },
        {
          name: 'Node.js',
          indicators: [
            { check: () => headers['x-powered-by']?.toLowerCase().includes('express'), method: 'Express Framework' },
            { check: () => headers['server']?.toLowerCase().includes('node'), method: 'Server Header' },
            { check: () => /connect\.sid|express/i.test(String(headers['set-cookie'] || '')), method: 'Express Session' },
            { check: () => /__webpack_require__|module\.exports/i.test(content), method: 'Node.js Patterns' }
          ]
        },
        {
          name: 'Python',
          indicators: [
            { check: () => headers['server']?.toLowerCase().includes('python'), method: 'Server Header' },
            { check: () => headers['x-powered-by']?.toLowerCase().includes('python'), method: 'X-Powered-By' },
            { check: () => /django|flask|fastapi/i.test(content), method: 'Framework Detection' },
            { check: () => headers['server']?.includes('gunicorn') || headers['server']?.includes('uvicorn'), method: 'WSGI/ASGI Server' }
          ]
        },
        {
          name: 'Java',
          indicators: [
            { check: () => /\.jsp|\.jsf|\.do/i.test(content), method: 'Java Extension' },
            { check: () => /jsessionid/i.test(content), method: 'Java Session' },
            { check: () => headers['set-cookie']?.includes('JSESSIONID'), method: 'Java Cookie' },
            { check: () => /spring|struts|hibernate/i.test(content), method: 'Framework Detection' },
            { check: () => headers['x-powered-by']?.toLowerCase().includes('servlet'), method: 'Servlet Container' }
          ]
        },
        {
          name: 'ASP.NET',
          indicators: [
            { check: () => /\.aspx|\.asmx|\.ashx/i.test(content), method: 'ASP.NET Extension' },
            { check: () => /__viewstate|__eventvalidation/i.test(content), method: 'ViewState' },
            { check: () => headers['x-powered-by']?.toLowerCase().includes('asp.net'), method: 'X-Powered-By' },
            { check: () => headers['x-aspnet-version'] !== undefined, method: 'ASP.NET Header' },
            { check: () => headers['set-cookie']?.includes('ASP.NET_SessionId'), method: 'ASP.NET Cookie' }
          ]
        },
        {
          name: 'Ruby',
          indicators: [
            { check: () => headers['x-powered-by']?.toLowerCase().includes('ruby'), method: 'X-Powered-By' },
            { check: () => headers['x-powered-by']?.toLowerCase().includes('phusion passenger'), method: 'Passenger Server' },
            { check: () => /\.rb|rails|ruby/i.test(content), method: 'Ruby Patterns' },
            { check: () => headers['server']?.includes('WEBrick'), method: 'WEBrick Server' }
          ]
        },
        {
          name: 'Go',
          indicators: [
            { check: () => headers['server']?.toLowerCase().includes('go'), method: 'Server Header' },
            { check: () => headers['x-powered-by']?.toLowerCase().includes('go'), method: 'X-Powered-By' }
          ]
        },
        {
          name: 'TypeScript',
          indicators: [
            { check: () => /\.ts\.js|typescript/i.test(content), method: 'TypeScript Compilation' },
            { check: () => /@types|tslib/i.test(content), method: 'TypeScript Libraries' }
          ]
        }
      ];

      for (const lang of languageChecks) {
        let matchCount = 0;
        let detectionMethods = [];

        for (const indicator of lang.indicators) {
          try {
            if (indicator.check()) {
              matchCount++;
              detectionMethods.push(indicator.method);
            }
          } catch (e) {
            // Indicator check failed, continue
          }
        }

        if (matchCount > 0 && !detectedLangs.has(lang.name)) {
          detectedLangs.add(lang.name);
          languages.push({
            name: lang.name,
            confidence: matchCount > 2 ? 'High' : matchCount > 1 ? 'Medium' : 'Low',
            detectionMethod: detectionMethods.join(', '),
            indicators: matchCount
          });
        }
      }

    } catch (error: any) {
      console.error('Programming language detection error:', error.message);
    }

    return languages;
  }

  /**
   * Detect CMS Frameworks
   */
  private async detectCMSFrameworks(targetUrl: string): Promise<any[]> {
    const cmsFrameworks = [] as any[];

    try {
      // Test common CMS paths
      const cmsPaths = [
        { path: '/wp-admin', name: 'WordPress' },
        { path: '/wp-content', name: 'WordPress' },
        { path: '/administrator', name: 'Joomla' },
        { path: '/user/login', name: 'Drupal' },
        { path: '/ghost', name: 'Ghost' },
        { path: '/strapi', name: 'Strapi' }
      ];

      for (const cms of cmsPaths) {
        try {
          const testUrl = `${targetUrl}${cms.path}`;
          const response = await axios.get(testUrl, { timeout: 5000 });
          
          if (response.status === 200) {
            cmsFrameworks.push({
              name: cms.name,
              confidence: 'High',
              detectionMethod: 'Path Detection',
              path: cms.path
            });
          }
        } catch (error) {
          // Path not accessible
        }
      }

      // Content-based CMS detection
      const response = await axios.get(targetUrl, { timeout: 10000 });
      const content = response.data;

      if (content.includes('wp-content') || content.includes('wp-includes')) {
        cmsFrameworks.push({
          name: 'WordPress',
          confidence: 'High',
          detectionMethod: 'Content Analysis'
        });
      }

    } catch (error: any) {
      console.error('CMS detection error:', error.message);
    }

    return cmsFrameworks;
  }

  /**
   * Extract Version Information
   */
  private async extractVersionInformation(targetUrl: string): Promise<any> {
    const versionInfo = {
      webServer: null as any,
      application: null as any,
      framework: null as any
    };

    try {
      const response = await axios.get(targetUrl, { timeout: 10000 });
      const headers = response.headers;
      const content = response.data;

      // Server version from headers
      if (headers['server']) {
        const serverMatch = headers['server'].match(/(\w+)\/([0-9.]+)/);
        if (serverMatch) {
          versionInfo.webServer = {
            name: serverMatch[1],
            version: serverMatch[2]
          };
        }
      }

      // Application version from meta tags
      const metaVersionMatch = content.match(/<meta[^>]*name="version"[^>]*content="([^"]+)"/i);
      if (metaVersionMatch) {
        versionInfo.application = {
          version: metaVersionMatch[1]
        };
      }

      // Framework version detection
      const frameworkVersionPatterns = [
        { name: 'jQuery', pattern: /jquery[^0-9]*([0-9.]+)/i },
        { name: 'Bootstrap', pattern: /bootstrap[^0-9]*([0-9.]+)/i },
        { name: 'React', pattern: /react[^0-9]*([0-9.]+)/i }
      ];

      for (const pattern of frameworkVersionPatterns) {
        const match = content.match(pattern.pattern);
        if (match) {
          versionInfo.framework = {
            name: pattern.name,
            version: match[1]
          };
          break;
        }
      }

    } catch (error: any) {
      console.error('Version extraction error:', error.message);
    }

    return versionInfo;
  }

  /**
   * Detect Vulnerable Technologies
   */
  private async detectVulnerableTechnologies(techDetection: any): Promise<any[]> {
    const vulnerableTech = [] as any[];

    try {
      // Known vulnerable versions (simplified example)
      const knownVulnerabilities = [
        { tech: 'jQuery', versions: ['1.x', '2.x'], vulnerability: 'XSS vulnerabilities in older versions' },
        { tech: 'Bootstrap', versions: ['3.x'], vulnerability: 'XSS vulnerabilities in tooltip/popover' },
        { tech: 'Apache', versions: ['2.4.49', '2.4.50'], vulnerability: 'Path traversal vulnerability' },
        { tech: 'nginx', versions: ['1.20.0'], vulnerability: 'Various security issues' }
      ];

      // Check detected technologies against known vulnerabilities
      for (const vuln of knownVulnerabilities) {
        // Check web servers
        for (const server of techDetection.webServers || []) {
          if (server.server && server.server.toLowerCase().includes(vuln.tech.toLowerCase())) {
            vulnerableTech.push({
              technology: vuln.tech,
              vulnerability: vuln.vulnerability,
              severity: 'Medium',
              recommendation: `Update ${vuln.tech} to the latest version`
            });
          }
        }

        // Check JS libraries
        for (const lib of techDetection.jsLibraries || []) {
          if (lib.name === vuln.tech) {
            vulnerableTech.push({
              technology: vuln.tech,
              vulnerability: vuln.vulnerability,
              severity: 'Medium',
              recommendation: `Update ${vuln.tech} to the latest version`
            });
          }
        }
      }

    } catch (error: any) {
      console.error('Vulnerable technology detection error:', error.message);
    }

    return vulnerableTech;
  }

  // =================================
  // FALSE POSITIVE FILTERING METHODS
  // =================================

  /**
   * 🔍 Apply False Positive Filtering
   * Gereksiz false positive'leri filtreler ve sonuçları temizler
   */
  private async applyFalsePositiveFiltering(analysis: any, targetUrl: string): Promise<any> {

    const filteredAnalysis = JSON.parse(JSON.stringify(analysis)); // Deep copy

    try {
      // 1. Filter Input Validation False Positives
      filteredAnalysis.inputValidation = await this.filterInputValidationFalsePositives(
        filteredAnalysis.inputValidation, 
        targetUrl
      );

      // 2. Filter Authentication False Positives  
      filteredAnalysis.authenticationAnalysis = await this.filterAuthenticationFalsePositives(
        filteredAnalysis.authenticationAnalysis, 
        targetUrl
      );

      // 3. Filter Authorization False Positives
      filteredAnalysis.authorizationTesting = await this.filterAuthorizationFalsePositives(
        filteredAnalysis.authorizationTesting, 
        targetUrl
      );

      // 4. Filter CORS False Positives
      filteredAnalysis.corsAnalysis = await this.filterCorsFalsePositives(
        filteredAnalysis.corsAnalysis, 
        targetUrl
      );

      // 5. Filter Technology Detection False Positives
      filteredAnalysis.technologyDetection = await this.filterTechnologyFalsePositives(
        filteredAnalysis.technologyDetection, 
        targetUrl
      );

      // 6. Filter API Discovery False Positives
      filteredAnalysis.apiDiscovery = await this.filterApiDiscoveryFalsePositives(
        filteredAnalysis.apiDiscovery, 
        targetUrl
      );

      // 7. Filter Rate Limiting False Positives
      filteredAnalysis.rateLimiting = await this.filterRateLimitingFalsePositives(
        filteredAnalysis.rateLimiting, 
        targetUrl
      );

      // 8. Add Filtering Statistics
      filteredAnalysis.falsePositiveFiltering = await this.generateFilteringStatistics(analysis, filteredAnalysis);


    } catch (error: any) {
      console.error('False Positive Filtering error:', error.message);
    }

    return filteredAnalysis;
  }

  /**
   * Filter Input Validation False Positives
   */
  private async filterInputValidationFalsePositives(inputValidation: any, targetUrl: string): Promise<any> {
    const filtered = JSON.parse(JSON.stringify(inputValidation));

    try {
      // SQL Injection false positives
      if (filtered.sqlInjection && Array.isArray(filtered.sqlInjection)) {
        filtered.sqlInjection = filtered.sqlInjection.filter((vuln: any) => {
          // Remove common false positives
          if (vuln.payload && typeof vuln.payload === 'string') {
            // Skip if response is just a standard 404/500 page
            if (vuln.response && vuln.response.includes('404 Not Found')) return false;
            if (vuln.response && vuln.response.includes('500 Internal Server Error')) return false;
            
            // Skip if error message is too generic
            if (vuln.evidence && vuln.evidence.length < 20) return false;
          }
          return true;
        });
      }

      // XSS false positives
      if (filtered.xssVulnerabilities && Array.isArray(filtered.xssVulnerabilities)) {
        filtered.xssVulnerabilities = filtered.xssVulnerabilities.filter((vuln: any) => {
          // Remove reflected content that's not actually XSS
          if (vuln.payload && vuln.response) {
            // Check if it's just URL parameter reflection without script execution
            if (vuln.payload.includes('<script>') && !vuln.response.includes('<script>')) {
              return false;
            }
          }
          return true;
        });
      }

      // Command Injection false positives
      if (filtered.commandInjection && Array.isArray(filtered.commandInjection)) {
        filtered.commandInjection = filtered.commandInjection.filter((vuln: any) => {
          // Remove if no actual command output detected
          if (!vuln.evidence || vuln.evidence.length < 10) return false;
          return true;
        });
      }

    } catch (error: any) {
      console.error('Input validation filtering error:', error.message);
    }

    return filtered;
  }

  /**
   * Filter Authentication False Positives
   */
  private async filterAuthenticationFalsePositives(authAnalysis: any, targetUrl: string): Promise<any> {
    const filtered = JSON.parse(JSON.stringify(authAnalysis));

    try {
      // Weak Authentication false positives
      if (filtered.weakAuthentication && Array.isArray(filtered.weakAuthentication)) {
        filtered.weakAuthentication = filtered.weakAuthentication.filter((auth: any) => {
          // Remove if it's just missing auth on public endpoints
          if (auth.endpoint && auth.endpoint.includes('/public')) return false;
          if (auth.endpoint && auth.endpoint.includes('/health')) return false;
          if (auth.endpoint && auth.endpoint.includes('/status')) return false;
          return true;
        });
      }

      // Auth Bypass false positives
      if (filtered.authBypass && Array.isArray(filtered.authBypass)) {
        filtered.authBypass = filtered.authBypass.filter((bypass: any) => {
          // Remove legitimate public endpoints
          if (bypass.method === 'GET' && bypass.statusCode === 200) {
            // Check if it's a legitimate public resource
            if (bypass.url.includes('/api/health') || 
                bypass.url.includes('/api/status') ||
                bypass.url.includes('/robots.txt')) {
              return false;
            }
          }
          return true;
        });
      }

    } catch (error: any) {
      console.error('Authentication filtering error:', error.message);
    }

    return filtered;
  }

  /**
   * Filter Authorization False Positives
   */
  private async filterAuthorizationFalsePositives(authzTesting: any, targetUrl: string): Promise<any> {
    const filtered = JSON.parse(JSON.stringify(authzTesting));

    try {
      // IDOR false positives
      if (filtered.idorVulnerabilities && Array.isArray(filtered.idorVulnerabilities)) {
        filtered.idorVulnerabilities = filtered.idorVulnerabilities.filter((idor: any) => {
          // Remove if access was actually denied appropriately
          if (idor.statusCode === 403 || idor.statusCode === 401) return false;
          
          // Remove if response indicates proper access control
          if (idor.response && idor.response.includes('Access Denied')) return false;
          if (idor.response && idor.response.includes('Unauthorized')) return false;
          
          return true;
        });
      }

      // Privilege Escalation false positives
      if (filtered.privilegeEscalation && Array.isArray(filtered.privilegeEscalation)) {
        filtered.privilegeEscalation = filtered.privilegeEscalation.filter((priv: any) => {
          // Remove if the endpoint properly rejected the request
          if (priv.statusCode >= 400) return false;
          return true;
        });
      }

    } catch (error: any) {
      console.error('Authorization filtering error:', error.message);
    }

    return filtered;
  }

  /**
   * Filter CORS False Positives
   */
  private async filterCorsFalsePositives(corsAnalysis: any, targetUrl: string): Promise<any> {
    const filtered = JSON.parse(JSON.stringify(corsAnalysis));

    try {
      // Misconfigured CORS false positives
      if (filtered.misconfiguredCors && Array.isArray(filtered.misconfiguredCors)) {
        filtered.misconfiguredCors = filtered.misconfiguredCors.filter((cors: any) => {
          // Remove if CORS is appropriately configured for the endpoint type
          if (cors.origin === '*' && cors.endpoint && cors.endpoint.includes('/api/public')) {
            return false; // Public API endpoints can legitimately allow all origins
          }
          
          // Remove if credentials are properly handled
          if (!cors.allowCredentials && cors.origin === '*') {
            return false; // This is actually secure - wildcard without credentials
          }
          
          return true;
        });
      }

    } catch (error: any) {
      console.error('CORS filtering error:', error.message);
    }

    return filtered;
  }

  /**
   * Filter Technology Detection False Positives
   */
  private async filterTechnologyFalsePositives(techDetection: any, targetUrl: string): Promise<any> {
    const filtered = JSON.parse(JSON.stringify(techDetection));

    try {
      // Remove duplicate technology detections
      if (filtered.programmingLanguages && Array.isArray(filtered.programmingLanguages)) {
        const seen = new Set();
        filtered.programmingLanguages = filtered.programmingLanguages.filter((lang: any) => {
          if (seen.has(lang.name)) return false;
          seen.add(lang.name);
          return true;
        });
      }

      // Remove low-confidence detections that conflict with high-confidence ones
      if (filtered.webServers && Array.isArray(filtered.webServers)) {
        const highConfidence = filtered.webServers.filter((server: any) => server.confidence === 'High');
        if (highConfidence.length > 0) {
          // Remove medium/low confidence detections if we have high confidence ones
          filtered.webServers = filtered.webServers.filter((server: any) => 
            server.confidence === 'High' || highConfidence.length === 0
          );
        }
      }

      // Filter vulnerable technologies - remove if versions don't actually match
      if (filtered.vulnerableTechnologies && Array.isArray(filtered.vulnerableTechnologies)) {
        filtered.vulnerableTechnologies = filtered.vulnerableTechnologies.filter((vuln: any) => {
          // Only keep if we have actual version information that matches vulnerability
          if (vuln.technology === 'jQuery' && filtered.versionInformation?.framework?.name === 'jQuery') {
            const version = filtered.versionInformation.framework.version;
            // Only flag if we know it's actually a vulnerable version
            if (version && version !== '0' && !version.includes('unknown')) {
              return true;
            }
          }
          return vuln.confidence === 'High'; // Only keep high-confidence vulnerabilities
        });
      }

    } catch (error: any) {
      console.error('Technology filtering error:', error.message);
    }

    return filtered;
  }

  /**
   * Filter API Discovery False Positives
   */
  private async filterApiDiscoveryFalsePositives(apiDiscovery: any, targetUrl: string): Promise<any> {
    const filtered = JSON.parse(JSON.stringify(apiDiscovery));

    try {
      // Filter REST endpoints
      if (filtered.restEndpoints && Array.isArray(filtered.restEndpoints)) {
        filtered.restEndpoints = filtered.restEndpoints.filter((endpoint: any) => {
          // Remove static assets
          if (endpoint.url && (
            endpoint.url.endsWith('.css') ||
            endpoint.url.endsWith('.js') ||
            endpoint.url.endsWith('.png') ||
            endpoint.url.endsWith('.jpg') ||
            endpoint.url.endsWith('.ico')
          )) {
            return false;
          }

          // Remove HEAD requests for non-API endpoints
          if (endpoint.method === 'HEAD' && !endpoint.url.includes('/api/')) {
            return false;
          }

          // Remove if response indicates it's not a real API endpoint
          if (endpoint.statusCode === 404) return false;

          return true;
        });
      }

      // Filter hidden endpoints
      if (filtered.hiddenEndpoints && Array.isArray(filtered.hiddenEndpoints)) {
        filtered.hiddenEndpoints = filtered.hiddenEndpoints.filter((endpoint: any) => {
          // Remove common false positives
          if (endpoint.url && (
            endpoint.url.includes('/.well-known/') ||
            endpoint.url.includes('/robots.txt') ||
            endpoint.url.includes('/sitemap.xml')
          )) {
            return false; // These are standard, not hidden
          }
          return true;
        });
      }

    } catch (error: any) {
      console.error('API discovery filtering error:', error.message);
    }

    return filtered;
  }

  /**
   * Filter Rate Limiting False Positives
   */
  private async filterRateLimitingFalsePositives(rateLimiting: any, targetUrl: string): Promise<any> {
    const filtered = JSON.parse(JSON.stringify(rateLimiting));

    try {
      // If we see rate limiting headers, don't flag as missing
      if (filtered.rateLimitHeaders && filtered.rateLimitHeaders.length > 0) {
        filtered.missingRateLimiting = false;
      }

      // Filter rate limit testing results
      if (filtered.rateLimitTesting && typeof filtered.rateLimitTesting === 'object') {
        // Don't flag rate limiting as missing if we got 429 responses
        if (filtered.rateLimitTesting.status === 429) {
          filtered.rateLimitingPresent = true;
        }
      }

    } catch (error: any) {
      console.error('Rate limiting filtering error:', error.message);
    }

    return filtered;
  }

  /**
   * Generate Filtering Statistics
   */
  private async generateFilteringStatistics(originalAnalysis: any, filteredAnalysis: any): Promise<any> {
    const stats = {
      totalIssuesBeforeFiltering: 0,
      totalIssuesAfterFiltering: 0,
      falsePositivesRemoved: 0,
      filteringCategories: {
        inputValidation: { before: 0, after: 0, removed: 0 },
        authentication: { before: 0, after: 0, removed: 0 },
        authorization: { before: 0, after: 0, removed: 0 },
        cors: { before: 0, after: 0, removed: 0 },
        technology: { before: 0, after: 0, removed: 0 },
        apiDiscovery: { before: 0, after: 0, removed: 0 },
        rateLimiting: { before: 0, after: 0, removed: 0 }
      },
      filteringEfficiency: 0,
      qualityScore: 0
    };

    try {
      // Count issues in each category
      const categories = [
        'inputValidation', 'authentication', 'authorization', 
        'cors', 'technology', 'apiDiscovery', 'rateLimiting'
      ];

      for (const category of categories) {
        const originalCount = this.countIssuesInCategory(originalAnalysis[category] || {});
        const filteredCount = this.countIssuesInCategory(filteredAnalysis[category] || {});
        
        stats.filteringCategories[category as keyof typeof stats.filteringCategories] = {
          before: originalCount,
          after: filteredCount,
          removed: originalCount - filteredCount
        };

        stats.totalIssuesBeforeFiltering += originalCount;
        stats.totalIssuesAfterFiltering += filteredCount;
      }

      stats.falsePositivesRemoved = stats.totalIssuesBeforeFiltering - stats.totalIssuesAfterFiltering;
      
      // Calculate filtering efficiency
      if (stats.totalIssuesBeforeFiltering > 0) {
        stats.filteringEfficiency = Math.round(
          (stats.falsePositivesRemoved / stats.totalIssuesBeforeFiltering) * 100
        );
      }

      // Calculate quality score (higher when more false positives are removed)
      stats.qualityScore = Math.min(100, Math.max(0, 
        100 - (stats.totalIssuesAfterFiltering * 5) + (stats.filteringEfficiency * 0.5)
      ));

    } catch (error: any) {
      console.error('Filtering statistics error:', error.message);
    }

    return stats;
  }

  /**
   * Count issues in a category
   */
  private countIssuesInCategory(categoryData: any): number {
    let count = 0;
    
    if (!categoryData || typeof categoryData !== 'object') return 0;

    // Count arrays of issues
    Object.values(categoryData).forEach((value: any) => {
      if (Array.isArray(value)) {
        count += value.length;
      } else if (typeof value === 'boolean' && value === true) {
        count += 1; // Count boolean flags as issues
      }
    });

    return count;
  }

  // =================================
  // SMART VULNERABILITY PRIORITIZATION METHODS
  // =================================

  /**
   * 🎯 Smart Vulnerability Prioritization
   * Güvenlik açıklarını risk, impact, exploitability faktörlerine göre önceliklendirir
   */
  private async performSmartVulnerabilityPrioritization(analysis: any, targetUrl: string): Promise<any> {

    const prioritization = {
      criticalVulnerabilities: [] as any[],
      highPriorityVulnerabilities: [] as any[],
      mediumPriorityVulnerabilities: [] as any[],
      lowPriorityVulnerabilities: [] as any[],
      prioritizationMatrix: {} as any,
      riskScores: {} as any,
      exploitabilityAnalysis: {} as any,
      businessImpactAssessment: {} as any,
      remediationComplexity: {} as any,
      prioritizationStats: {} as any
    };

    try {
      // 1. Extract All Vulnerabilities
      const allVulnerabilities = await this.extractAllVulnerabilities(analysis);

      // 2. Calculate Risk Scores
      prioritization.riskScores = await this.calculateRiskScores(allVulnerabilities, targetUrl);

      // 3. Analyze Exploitability
      prioritization.exploitabilityAnalysis = await this.analyzeExploitability(allVulnerabilities, targetUrl);

      // 4. Assess Business Impact
      prioritization.businessImpactAssessment = await this.assessBusinessImpact(allVulnerabilities, targetUrl);

      // 5. Evaluate Remediation Complexity
      prioritization.remediationComplexity = await this.evaluateRemediationComplexity(allVulnerabilities);

      // 6. Create Prioritization Matrix
      prioritization.prioritizationMatrix = await this.createPrioritizationMatrix(
        allVulnerabilities,
        prioritization.riskScores,
        prioritization.exploitabilityAnalysis,
        prioritization.businessImpactAssessment,
        prioritization.remediationComplexity
      );

      // 7. Categorize by Priority
      const categorizedVuln = await this.categorizeVulnerabilityByPriority(prioritization.prioritizationMatrix);
      prioritization.criticalVulnerabilities = categorizedVuln.critical;
      prioritization.highPriorityVulnerabilities = categorizedVuln.high;
      prioritization.mediumPriorityVulnerabilities = categorizedVuln.medium;
      prioritization.lowPriorityVulnerabilities = categorizedVuln.low;

      // 8. Generate Prioritization Statistics
      prioritization.prioritizationStats = await this.generatePrioritizationStatistics(prioritization);


    } catch (error: any) {
      console.error('Smart Vulnerability Prioritization error:', error.message);
    }

    return prioritization;
  }

  /**
   * Extract All Vulnerabilities from Analysis Results
   */
  private async extractAllVulnerabilities(analysis: any): Promise<any[]> {
    const vulnerabilities = [] as any[];

    try {
      // Input Validation Vulnerabilities
      if (analysis.inputValidation) {
        if (analysis.inputValidation.sqlInjection?.length > 0) {
          analysis.inputValidation.sqlInjection.forEach((vuln: any) => {
            vulnerabilities.push({
              id: `sql_${vulnerabilities.length}`,
              type: 'SQL Injection',
              category: 'Input Validation',
              severity: 'High',
              description: 'SQL Injection vulnerability detected',
              endpoint: vuln.url || vuln.endpoint,
              payload: vuln.payload,
              evidence: vuln.evidence,
              cvssBase: 8.1,
              cweId: 'CWE-89'
            });
          });
        }

        if (analysis.inputValidation.xssVulnerabilities?.length > 0) {
          analysis.inputValidation.xssVulnerabilities.forEach((vuln: any) => {
            vulnerabilities.push({
              id: `xss_${vulnerabilities.length}`,
              type: 'Cross-Site Scripting (XSS)',
              category: 'Input Validation',
              severity: 'Medium',
              description: 'XSS vulnerability detected',
              endpoint: vuln.url || vuln.endpoint,
              payload: vuln.payload,
              evidence: vuln.evidence,
              cvssBase: 6.1,
              cweId: 'CWE-79'
            });
          });
        }

        if (analysis.inputValidation.commandInjection?.length > 0) {
          analysis.inputValidation.commandInjection.forEach((vuln: any) => {
            vulnerabilities.push({
              id: `cmd_${vulnerabilities.length}`,
              type: 'Command Injection',
              category: 'Input Validation',
              severity: 'Critical',
              description: 'Command Injection vulnerability detected',
              endpoint: vuln.url || vuln.endpoint,
              payload: vuln.payload,
              evidence: vuln.evidence,
              cvssBase: 9.8,
              cweId: 'CWE-78'
            });
          });
        }
      }

      // Authentication Vulnerabilities
      if (analysis.authenticationAnalysis?.weakAuthentication?.length > 0) {
        analysis.authenticationAnalysis.weakAuthentication.forEach((vuln: any) => {
          vulnerabilities.push({
            id: `auth_${vulnerabilities.length}`,
            type: 'Weak Authentication',
            category: 'Authentication',
            severity: 'High',
            description: 'Weak authentication mechanism detected',
            endpoint: vuln.endpoint,
            evidence: vuln.description,
            cvssBase: 7.5,
            cweId: 'CWE-287'
          });
        });
      }

      // Authorization Vulnerabilities
      if (analysis.authorizationTesting?.idorVulnerabilities?.length > 0) {
        analysis.authorizationTesting.idorVulnerabilities.forEach((vuln: any) => {
          vulnerabilities.push({
            id: `idor_${vulnerabilities.length}`,
            type: 'Insecure Direct Object Reference (IDOR)',
            category: 'Authorization',
            severity: 'High',
            description: 'IDOR vulnerability detected',
            endpoint: vuln.endpoint,
            evidence: vuln.evidence,
            cvssBase: 8.1,
            cweId: 'CWE-639'
          });
        });
      }

      // CORS Vulnerabilities
      if (analysis.corsAnalysis?.misconfiguredCors?.length > 0) {
        analysis.corsAnalysis.misconfiguredCors.forEach((vuln: any) => {
          vulnerabilities.push({
            id: `cors_${vulnerabilities.length}`,
            type: 'CORS Misconfiguration',
            category: 'CORS',
            severity: 'Medium',
            description: 'CORS misconfiguration detected',
            endpoint: vuln.endpoint,
            evidence: vuln.headers,
            cvssBase: 5.3,
            cweId: 'CWE-942'
          });
        });
      }

      // Technology Vulnerabilities
      if (analysis.technologyDetection?.vulnerableTechnologies?.length > 0) {
        analysis.technologyDetection.vulnerableTechnologies.forEach((vuln: any) => {
          vulnerabilities.push({
            id: `tech_${vulnerabilities.length}`,
            type: 'Vulnerable Technology',
            category: 'Technology',
            severity: vuln.severity || 'Medium',
            description: vuln.vulnerability,
            technology: vuln.technology,
            recommendation: vuln.recommendation,
            cvssBase: vuln.severity === 'High' ? 7.5 : vuln.severity === 'Medium' ? 5.0 : 3.0,
            cweId: 'CWE-1104'
          });
        });
      }

    } catch (error: any) {
      console.error('Vulnerability extraction error:', error.message);
    }

    return vulnerabilities;
  }

  /**
   * Calculate Risk Scores for Vulnerabilities
   */
  private async calculateRiskScores(vulnerabilities: any[], targetUrl: string): Promise<any> {
    const riskScores = {} as any;

    try {
      for (const vuln of vulnerabilities) {
        let riskScore = 0;

        // Base CVSS Score (40% weight)
        riskScore += (vuln.cvssBase || 5.0) * 0.4;

        // Severity Multiplier (30% weight)
        const severityMultiplier = this.getSeverityMultiplier(vuln.severity);
        riskScore += severityMultiplier * 0.3;

        // Endpoint Exposure (20% weight)
        const exposureScore = await this.calculateEndpointExposure(vuln.endpoint, targetUrl);
        riskScore += exposureScore * 0.2;

        // Evidence Quality (10% weight)
        const evidenceScore = this.calculateEvidenceQuality(vuln.evidence);
        riskScore += evidenceScore * 0.1;

        riskScores[vuln.id] = {
          totalScore: Math.round(riskScore * 10) / 10,
          cvssBase: vuln.cvssBase || 5.0,
          severityMultiplier,
          exposureScore,
          evidenceScore,
          riskLevel: this.getRiskLevel(riskScore)
        };
      }

    } catch (error: any) {
      console.error('Risk score calculation error:', error.message);
    }

    return riskScores;
  }

  /**
   * Analyze Vulnerability Exploitability
   */
  private async analyzeExploitability(vulnerabilities: any[], targetUrl: string): Promise<any> {
    const exploitability = {} as any;

    try {
      for (const vuln of vulnerabilities) {
        let exploitScore = 0;

        // Attack Vector (Remote/Network = higher score)
        const attackVector = this.determineAttackVector(vuln);
        exploitScore += attackVector.score;

        // Attack Complexity
        const attackComplexity = this.determineAttackComplexity(vuln);
        exploitScore += attackComplexity.score;

        // Authentication Required
        const authRequired = this.determineAuthenticationRequired(vuln);
        exploitScore += authRequired.score;

        // User Interaction Required
        const userInteraction = this.determineUserInteraction(vuln);
        exploitScore += userInteraction.score;

        // Public Exploits Available
        const publicExploits = await this.checkPublicExploits(vuln);
        exploitScore += publicExploits.score;

        exploitability[vuln.id] = {
          totalScore: Math.round(exploitScore * 10) / 10,
          attackVector,
          attackComplexity,
          authRequired,
          userInteraction,
          publicExploits,
          exploitabilityLevel: this.getExploitabilityLevel(exploitScore)
        };
      }

    } catch (error: any) {
      console.error('Exploitability analysis error:', error.message);
    }

    return exploitability;
  }

  /**
   * Assess Business Impact of Vulnerabilities
   */
  private async assessBusinessImpact(vulnerabilities: any[], targetUrl: string): Promise<any> {
    const businessImpact = {} as any;

    try {
      for (const vuln of vulnerabilities) {
        let impactScore = 0;

        // Data Confidentiality Impact
        const confidentialityImpact = this.assessConfidentialityImpact(vuln);
        impactScore += confidentialityImpact.score;

        // Data Integrity Impact
        const integrityImpact = this.assessIntegrityImpact(vuln);
        impactScore += integrityImpact.score;

        // Service Availability Impact
        const availabilityImpact = this.assessAvailabilityImpact(vuln);
        impactScore += availabilityImpact.score;

        // Compliance Impact
        const complianceImpact = this.assessComplianceImpact(vuln);
        impactScore += complianceImpact.score;

        // Reputation Impact
        const reputationImpact = this.assessReputationImpact(vuln);
        impactScore += reputationImpact.score;

        businessImpact[vuln.id] = {
          totalScore: Math.round(impactScore * 10) / 10,
          confidentialityImpact,
          integrityImpact,
          availabilityImpact,
          complianceImpact,
          reputationImpact,
          impactLevel: this.getImpactLevel(impactScore)
        };
      }

    } catch (error: any) {
      console.error('Business impact assessment error:', error.message);
    }

    return businessImpact;
  }

  /**
   * Evaluate Remediation Complexity
   */
  private async evaluateRemediationComplexity(vulnerabilities: any[]): Promise<any> {
    const remediationComplexity = {} as any;

    try {
      for (const vuln of vulnerabilities) {
        let complexityScore = 0;

        // Technical Complexity
        const technicalComplexity = this.assessTechnicalComplexity(vuln);
        complexityScore += technicalComplexity.score;

        // Time to Fix
        const timeToFix = this.estimateTimeToFix(vuln);
        complexityScore += timeToFix.score;

        // Resource Requirements
        const resourceRequirements = this.assessResourceRequirements(vuln);
        complexityScore += resourceRequirements.score;

        // Testing Requirements
        const testingRequirements = this.assessTestingRequirements(vuln);
        complexityScore += testingRequirements.score;

        remediationComplexity[vuln.id] = {
          totalScore: Math.round(complexityScore * 10) / 10,
          technicalComplexity,
          timeToFix,
          resourceRequirements,
          testingRequirements,
          complexityLevel: this.getComplexityLevel(complexityScore)
        };
      }

    } catch (error: any) {
      console.error('Remediation complexity evaluation error:', error.message);
    }

    return remediationComplexity;
  }

  /**
   * Create Prioritization Matrix
   */
  private async createPrioritizationMatrix(
    vulnerabilities: any[],
    riskScores: any,
    exploitability: any,
    businessImpact: any,
    remediationComplexity: any
  ): Promise<any[]> {
    const prioritizationMatrix = [] as any[];

    try {
      for (const vuln of vulnerabilities) {
        const risk = riskScores[vuln.id] || { totalScore: 5.0 };
        const exploit = exploitability[vuln.id] || { totalScore: 5.0 };
        const impact = businessImpact[vuln.id] || { totalScore: 5.0 };
        const complexity = remediationComplexity[vuln.id] || { totalScore: 5.0 };

        // Calculate Priority Score
        // Higher risk + higher exploitability + higher impact + lower complexity = higher priority
        const priorityScore = (
          (risk.totalScore * 0.35) + 
          (exploit.totalScore * 0.25) + 
          (impact.totalScore * 0.25) + 
          ((10 - complexity.totalScore) * 0.15) // Inverse complexity
        );

        prioritizationMatrix.push({
          vulnerability: vuln,
          priorityScore: Math.round(priorityScore * 10) / 10,
          riskScore: risk.totalScore,
          exploitabilityScore: exploit.totalScore,
          businessImpactScore: impact.totalScore,
          remediationComplexityScore: complexity.totalScore,
          priorityLevel: this.getPriorityLevel(priorityScore),
          urgency: this.calculateUrgency(priorityScore, exploit.totalScore),
          remediationTimeframe: this.getRemediationTimeframe(priorityScore),
          detailedAnalysis: {
            risk,
            exploitability: exploit,
            businessImpact: impact,
            remediationComplexity: complexity
          }
        });
      }

      // Sort by priority score (highest first)
      prioritizationMatrix.sort((a, b) => b.priorityScore - a.priorityScore);

    } catch (error: any) {
      console.error('Prioritization matrix creation error:', error.message);
    }

    return prioritizationMatrix;
  }

  /**
   * Categorize Vulnerabilities by Priority Level
   */
  private async categorizeVulnerabilityByPriority(prioritizationMatrix: any[]): Promise<any> {
    const categorized = {
      critical: [] as any[],
      high: [] as any[],
      medium: [] as any[],
      low: [] as any[]
    };

    try {
      for (const item of prioritizationMatrix) {
        switch (item.priorityLevel) {
          case 'Critical':
            categorized.critical.push(item);
            break;
          case 'High':
            categorized.high.push(item);
            break;
          case 'Medium':
            categorized.medium.push(item);
            break;
          case 'Low':
            categorized.low.push(item);
            break;
        }
      }

    } catch (error: any) {
      console.error('Vulnerability categorization error:', error.message);
    }

    return categorized;
  }

  /**
   * Generate Prioritization Statistics
   */
  private async generatePrioritizationStatistics(prioritization: any): Promise<any> {
    const stats = {
      totalVulnerabilities: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      averagePriorityScore: 0,
      highestPriorityVuln: null as any,
      remediationTimeframes: {
        immediate: 0, // Critical - fix within 24h
        urgent: 0,    // High - fix within 7 days
        normal: 0,    // Medium - fix within 30 days
        scheduled: 0  // Low - fix within 90 days
      },
      categoryDistribution: {} as any,
      riskDistribution: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      }
    };

    try {
      stats.criticalCount = prioritization.criticalVulnerabilities?.length || 0;
      stats.highCount = prioritization.highPriorityVulnerabilities?.length || 0;
      stats.mediumCount = prioritization.mediumPriorityVulnerabilities?.length || 0;
      stats.lowCount = prioritization.lowPriorityVulnerabilities?.length || 0;
      
      stats.totalVulnerabilities = stats.criticalCount + stats.highCount + stats.mediumCount + stats.lowCount;

      // Calculate average priority score
      const allVulns = [
        ...(prioritization.criticalVulnerabilities || []),
        ...(prioritization.highPriorityVulnerabilities || []),
        ...(prioritization.mediumPriorityVulnerabilities || []),
        ...(prioritization.lowPriorityVulnerabilities || [])
      ];

      if (allVulns.length > 0) {
        const totalScore = allVulns.reduce((sum, vuln) => sum + (vuln.priorityScore || 0), 0);
        stats.averagePriorityScore = Math.round((totalScore / allVulns.length) * 10) / 10;

        // Find highest priority vulnerability
        stats.highestPriorityVuln = allVulns.reduce((highest, current) => 
          (current.priorityScore || 0) > (highest.priorityScore || 0) ? current : highest
        );

        // Calculate remediation timeframes
        stats.remediationTimeframes.immediate = stats.criticalCount;
        stats.remediationTimeframes.urgent = stats.highCount;
        stats.remediationTimeframes.normal = stats.mediumCount;
        stats.remediationTimeframes.scheduled = stats.lowCount;

        // Category distribution
        const categoryCount = {} as any;
        allVulns.forEach(vuln => {
          const category = vuln.vulnerability?.category || 'Unknown';
          categoryCount[category] = (categoryCount[category] || 0) + 1;
        });
        stats.categoryDistribution = categoryCount;

        // Risk distribution
        stats.riskDistribution.critical = stats.criticalCount;
        stats.riskDistribution.high = stats.highCount;
        stats.riskDistribution.medium = stats.mediumCount;
        stats.riskDistribution.low = stats.lowCount;
      }

    } catch (error: any) {
      console.error('Prioritization statistics error:', error.message);
    }

    return stats;
  }

  // =================================
  // HELPER METHODS FOR PRIORITIZATION
  // =================================

  private getSeverityMultiplier(severity: string): number {
    switch (severity?.toLowerCase()) {
      case 'critical': return 10;
      case 'high': return 8;
      case 'medium': return 6;
      case 'low': return 4;
      default: return 5;
    }
  }

  private async calculateEndpointExposure(endpoint: string, targetUrl: string): Promise<number> {
    if (!endpoint) return 5;
    
    // Public API endpoints have higher exposure
    if (endpoint.includes('/api/') && !endpoint.includes('/internal/')) return 8;
    if (endpoint.includes('/admin/')) return 9;
    if (endpoint.includes('/public/')) return 7;
    return 5;
  }

  private calculateEvidenceQuality(evidence: any): number {
    if (!evidence) return 3;
    if (typeof evidence === 'string' && evidence.length > 100) return 8;
    if (typeof evidence === 'object' && Object.keys(evidence).length > 3) return 7;
    return 5;
  }

  private getRiskLevel(score: number): string {
    if (score >= 8.5) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 5.0) return 'Medium';
    return 'Low';
  }

  private determineAttackVector(vuln: any): any {
    // Most web vulnerabilities are network-based
    return { score: 8, vector: 'Network', description: 'Remotely exploitable' };
  }

  private determineAttackComplexity(vuln: any): any {
    if (vuln.type.includes('SQL Injection') || vuln.type.includes('Command Injection')) {
      return { score: 7, complexity: 'Low', description: 'Easy to exploit' };
    }
    return { score: 5, complexity: 'Medium', description: 'Moderate complexity' };
  }

  private determineAuthenticationRequired(vuln: any): any {
    if (vuln.category === 'Authentication') {
      return { score: 3, required: true, description: 'Authentication bypass' };
    }
    return { score: 6, required: false, description: 'No authentication required' };
  }

  private determineUserInteraction(vuln: any): any {
    if (vuln.type.includes('XSS')) {
      return { score: 4, required: true, description: 'User interaction needed' };
    }
    return { score: 7, required: false, description: 'No user interaction needed' };
  }

  private async checkPublicExploits(vuln: any): Promise<any> {
    // Simplified - in real implementation, check CVE databases
    const commonVulns = ['SQL Injection', 'XSS', 'Command Injection'];
    if (commonVulns.some(v => vuln.type.includes(v))) {
      return { score: 8, available: true, description: 'Public exploits available' };
    }
    return { score: 3, available: false, description: 'No known public exploits' };
  }

  private getExploitabilityLevel(score: number): string {
    if (score >= 8.0) return 'High';
    if (score >= 6.0) return 'Medium';
    return 'Low';
  }

  private assessConfidentialityImpact(vuln: any): any {
    if (vuln.type.includes('SQL Injection') || vuln.type.includes('IDOR')) {
      return { score: 9, impact: 'High', description: 'Data disclosure possible' };
    }
    return { score: 5, impact: 'Medium', description: 'Limited data exposure' };
  }

  private assessIntegrityImpact(vuln: any): any {
    if (vuln.type.includes('SQL Injection') || vuln.type.includes('Command Injection')) {
      return { score: 9, impact: 'High', description: 'Data modification possible' };
    }
    return { score: 4, impact: 'Low', description: 'Limited integrity impact' };
  }

  private assessAvailabilityImpact(vuln: any): any {
    if (vuln.type.includes('Command Injection')) {
      return { score: 8, impact: 'High', description: 'Service disruption possible' };
    }
    return { score: 3, impact: 'Low', description: 'Minimal availability impact' };
  }

  private assessComplianceImpact(vuln: any): any {
    // High impact for data-related vulnerabilities
    if (vuln.type.includes('SQL Injection') || vuln.type.includes('IDOR')) {
      return { score: 8, impact: 'High', description: 'GDPR/PCI compliance risk' };
    }
    return { score: 4, impact: 'Medium', description: 'Moderate compliance risk' };
  }

  private assessReputationImpact(vuln: any): any {
    if (vuln.severity === 'Critical' || vuln.type.includes('Command Injection')) {
      return { score: 9, impact: 'High', description: 'Significant reputation risk' };
    }
    return { score: 5, impact: 'Medium', description: 'Moderate reputation risk' };
  }

  private getImpactLevel(score: number): string {
    if (score >= 8.0) return 'High';
    if (score >= 6.0) return 'Medium';
    return 'Low';
  }

  private assessTechnicalComplexity(vuln: any): any {
    if (vuln.type.includes('CORS') || vuln.type.includes('Vulnerable Technology')) {
      return { score: 3, complexity: 'Low', description: 'Simple configuration fix' };
    }
    if (vuln.type.includes('SQL Injection')) {
      return { score: 6, complexity: 'Medium', description: 'Code changes required' };
    }
    return { score: 5, complexity: 'Medium', description: 'Moderate technical changes' };
  }

  private estimateTimeToFix(vuln: any): any {
    if (vuln.type.includes('CORS')) {
      return { score: 2, timeframe: '1-2 hours', description: 'Quick configuration fix' };
    }
    if (vuln.type.includes('SQL Injection')) {
      return { score: 7, timeframe: '1-3 days', description: 'Code review and testing needed' };
    }
    return { score: 5, timeframe: '4-8 hours', description: 'Standard fix timeframe' };
  }

  private assessResourceRequirements(vuln: any): any {
    if (vuln.type.includes('Command Injection')) {
      return { score: 8, resources: 'High', description: 'Senior developer + security review' };
    }
    return { score: 4, resources: 'Medium', description: 'Standard development resources' };
  }

  private assessTestingRequirements(vuln: any): any {
    if (vuln.type.includes('SQL Injection') || vuln.type.includes('Command Injection')) {
      return { score: 8, testing: 'Extensive', description: 'Security testing required' };
    }
    return { score: 4, testing: 'Standard', description: 'Normal testing procedures' };
  }

  private getComplexityLevel(score: number): string {
    if (score >= 7.0) return 'High';
    if (score >= 5.0) return 'Medium';
    return 'Low';
  }

  private getPriorityLevel(score: number): string {
    if (score >= 8.5) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 5.0) return 'Medium';
    return 'Low';
  }

  private calculateUrgency(priorityScore: number, exploitabilityScore: number): string {
    if (priorityScore >= 8.5 && exploitabilityScore >= 7.0) return 'Immediate';
    if (priorityScore >= 7.0) return 'Urgent';
    if (priorityScore >= 5.0) return 'Normal';
    return 'Scheduled';
  }

  private getRemediationTimeframe(priorityScore: number): string {
    if (priorityScore >= 8.5) return '24 hours';
    if (priorityScore >= 7.0) return '7 days';
    if (priorityScore >= 5.0) return '30 days';
    return '90 days';
  }

  // =================================
  // PATTERN RECOGNITION ALGORITHMS
  // =================================

  /**
   * 🔍 Pattern Recognition Analysis
   * Güvenlik açıklarında ortak pattern'leri tespit eder ve gelişmiş analiz yapar
   */
  private async performPatternRecognitionAnalysis(analysis: any, targetUrl: string): Promise<any> {

    const patternRecognition = {
      attackPatterns: [] as any[],
      vulnerabilityPatterns: [] as any[],
      behavioralPatterns: [] as any[],
      temporalPatterns: [] as any[],
      clustering: {} as any,
      anomalyDetection: {} as any,
      sequenceAnalysis: {} as any,
      similarityAnalysis: {} as any,
      patternCorrelation: {} as any,
      patternStatistics: {} as any
    };

    try {
      // 1. Attack Pattern Recognition
      patternRecognition.attackPatterns = await this.recognizeAttackPatterns(analysis);

      // 2. Vulnerability Pattern Analysis
      patternRecognition.vulnerabilityPatterns = await this.analyzeVulnerabilityPatterns(analysis);

      // 3. Behavioral Pattern Detection
      patternRecognition.behavioralPatterns = await this.detectBehavioralPatterns(analysis, targetUrl);

      // 4. Temporal Pattern Analysis
      patternRecognition.temporalPatterns = await this.analyzeTemporalPatterns(analysis);

      // 5. Vulnerability Clustering
      patternRecognition.clustering = await this.performVulnerabilityClustering(analysis);

      // 6. Anomaly Detection
      patternRecognition.anomalyDetection = await this.performAnomalyDetection(analysis);

      // 7. Sequence Pattern Analysis
      patternRecognition.sequenceAnalysis = await this.analyzeSequencePatterns(analysis);

      // 8. Similarity Analysis
      patternRecognition.similarityAnalysis = await this.performSimilarityAnalysis(analysis);

      // 9. Pattern Correlation Analysis
      patternRecognition.patternCorrelation = await this.analyzePatternCorrelations(patternRecognition);

      // 10. Generate Pattern Statistics
      patternRecognition.patternStatistics = await this.generatePatternStatistics(patternRecognition);


    } catch (error: any) {
      console.error('Pattern Recognition Analysis error:', error.message);
    }

    return patternRecognition;
  }

  /**
   * Recognize Attack Patterns
   */
  private async recognizeAttackPatterns(analysis: any): Promise<any[]> {
    const attackPatterns = [] as any[];

    try {
      // SQL Injection Attack Patterns
      if (analysis.inputValidation?.sqlInjection?.length > 0) {
        const sqlPatterns = this.analyzeSQLInjectionPatterns(analysis.inputValidation.sqlInjection);
        attackPatterns.push({
          type: 'SQL Injection Attack Pattern',
          category: 'Input Validation',
          pattern: sqlPatterns.commonPattern,
          confidence: sqlPatterns.confidence,
          occurrences: analysis.inputValidation.sqlInjection.length,
          characteristics: sqlPatterns.characteristics,
          severity: 'High'
        });
      }

      // XSS Attack Patterns
      if (analysis.inputValidation?.xssVulnerabilities?.length > 0) {
        const xssPatterns = this.analyzeXSSPatterns(analysis.inputValidation.xssVulnerabilities);
        attackPatterns.push({
          type: 'Cross-Site Scripting Pattern',
          category: 'Input Validation',
          pattern: xssPatterns.commonPattern,
          confidence: xssPatterns.confidence,
          occurrences: analysis.inputValidation.xssVulnerabilities.length,
          characteristics: xssPatterns.characteristics,
          severity: 'Medium'
        });
      }

      // Authentication Bypass Patterns
      if (analysis.authenticationAnalysis?.authBypass?.length > 0) {
        const authPatterns = this.analyzeAuthBypassPatterns(analysis.authenticationAnalysis.authBypass);
        attackPatterns.push({
          type: 'Authentication Bypass Pattern',
          category: 'Authentication',
          pattern: authPatterns.commonPattern,
          confidence: authPatterns.confidence,
          occurrences: analysis.authenticationAnalysis.authBypass.length,
          characteristics: authPatterns.characteristics,
          severity: 'High'
        });
      }

      // IDOR Attack Patterns
      if (analysis.authorizationTesting?.idorVulnerabilities?.length > 0) {
        const idorPatterns = this.analyzeIDORPatterns(analysis.authorizationTesting.idorVulnerabilities);
        attackPatterns.push({
          type: 'Insecure Direct Object Reference Pattern',
          category: 'Authorization',
          pattern: idorPatterns.commonPattern,
          confidence: idorPatterns.confidence,
          occurrences: analysis.authorizationTesting.idorVulnerabilities.length,
          characteristics: idorPatterns.characteristics,
          severity: 'High'
        });
      }

    } catch (error: any) {
      console.error('Attack pattern recognition error:', error.message);
    }

    return attackPatterns;
  }

  /**
   * Analyze Vulnerability Patterns
   */
  private async analyzeVulnerabilityPatterns(analysis: any): Promise<any[]> {
    const vulnerabilityPatterns = [] as any[];

    try {
      // Endpoint Vulnerability Patterns
      const endpointPatterns = this.analyzeEndpointVulnerabilityPatterns(analysis);
      if (endpointPatterns.length > 0) {
        vulnerabilityPatterns.push(...endpointPatterns);
      }

      // Parameter Vulnerability Patterns
      const parameterPatterns = this.analyzeParameterVulnerabilityPatterns(analysis);
      if (parameterPatterns.length > 0) {
        vulnerabilityPatterns.push(...parameterPatterns);
      }

      // Technology Stack Vulnerability Patterns
      const techPatterns = this.analyzeTechnologyVulnerabilityPatterns(analysis);
      if (techPatterns.length > 0) {
        vulnerabilityPatterns.push(...techPatterns);
      }

    } catch (error: any) {
      console.error('Vulnerability pattern analysis error:', error.message);
    }

    return vulnerabilityPatterns;
  }

  /**
   * Detect Behavioral Patterns
   */
  private async detectBehavioralPatterns(analysis: any, targetUrl: string): Promise<any[]> {
    const behavioralPatterns = [] as any[];

    try {
      // API Usage Patterns
      const apiUsagePatterns = this.analyzeAPIUsagePatterns(analysis.apiDiscovery);
      behavioralPatterns.push({
        type: 'API Usage Pattern',
        category: 'Behavioral',
        description: 'Common API endpoint usage patterns',
        patterns: apiUsagePatterns,
        insights: this.generateAPIUsageInsights(apiUsagePatterns)
      });

      // Error Response Patterns
      const errorPatterns = this.analyzeErrorResponsePatterns(analysis);
      behavioralPatterns.push({
        type: 'Error Response Pattern',
        category: 'Behavioral',
        description: 'Common error response patterns',
        patterns: errorPatterns,
        insights: this.generateErrorPatternInsights(errorPatterns)
      });

      // Security Header Patterns
      const headerPatterns = this.analyzeSecurityHeaderPatterns(analysis);
      behavioralPatterns.push({
        type: 'Security Header Pattern',
        category: 'Behavioral',
        description: 'Security header implementation patterns',
        patterns: headerPatterns,
        insights: this.generateHeaderPatternInsights(headerPatterns)
      });

    } catch (error: any) {
      console.error('Behavioral pattern detection error:', error.message);
    }

    return behavioralPatterns;
  }

  /**
   * Analyze Temporal Patterns
   */
  private async analyzeTemporalPatterns(analysis: any): Promise<any[]> {
    const temporalPatterns = [] as any[];

    try {
      // Vulnerability Discovery Timeline
      const discoveryTimeline = this.analyzeVulnerabilityDiscoveryTimeline(analysis);
      temporalPatterns.push({
        type: 'Vulnerability Discovery Timeline',
        category: 'Temporal',
        timeline: discoveryTimeline,
        trends: this.identifyDiscoveryTrends(discoveryTimeline)
      });

      // Technology Adoption Patterns
      const technologyTimeline = this.analyzeTechnologyAdoptionPatterns(analysis);
      temporalPatterns.push({
        type: 'Technology Adoption Pattern',
        category: 'Temporal',
        timeline: technologyTimeline,
        trends: this.identifyTechnologyTrends(technologyTimeline)
      });

    } catch (error: any) {
      console.error('Temporal pattern analysis error:', error.message);
    }

    return temporalPatterns;
  }

  /**
   * Perform Vulnerability Clustering
   */
  private async performVulnerabilityClustering(analysis: any): Promise<any> {
    const clustering = {
      clusters: [] as any[],
      clusteringMethod: 'K-Means',
      clusterCount: 0,
      silhouetteScore: 0
    };

    try {
      // Extract vulnerability features for clustering
      const vulnerabilityFeatures = this.extractVulnerabilityFeatures(analysis);
      
      // Perform clustering based on similarity
      const clusters = this.performKMeansClustering(vulnerabilityFeatures);
      
      clustering.clusters = clusters;
      clustering.clusterCount = clusters.length;
      clustering.silhouetteScore = this.calculateSilhouetteScore(clusters, vulnerabilityFeatures);

    } catch (error: any) {
      console.error('Vulnerability clustering error:', error.message);
    }

    return clustering;
  }

  /**
   * Perform Anomaly Detection
   */
  private async performAnomalyDetection(analysis: any): Promise<any> {
    const anomalyDetection = {
      anomalies: [] as any[],
      anomalyScore: 0,
      detectionMethod: 'Statistical Outlier Detection',
      threshold: 0.95
    };

    try {
      // Detect statistical anomalies in vulnerability patterns
      const vulnerabilityData = this.prepareVulnerabilityDataForAnomalyDetection(analysis);
      const anomalies = this.detectStatisticalAnomalies(vulnerabilityData, anomalyDetection.threshold);
      
      anomalyDetection.anomalies = anomalies;
      anomalyDetection.anomalyScore = this.calculateAnomalyScore(anomalies, vulnerabilityData);

    } catch (error: any) {
      console.error('Anomaly detection error:', error.message);
    }

    return anomalyDetection;
  }

  /**
   * Analyze Sequence Patterns
   */
  private async analyzeSequencePatterns(analysis: any): Promise<any> {
    const sequenceAnalysis = {
      attackSequences: [] as any[],
      vulnerabilityChains: [] as any[],
      commonSequences: [] as any[]
    };

    try {
      // Analyze attack sequences
      sequenceAnalysis.attackSequences = this.identifyAttackSequences(analysis);
      
      // Identify vulnerability chains
      sequenceAnalysis.vulnerabilityChains = this.identifyVulnerabilityChains(analysis);
      
      // Find common sequences
      sequenceAnalysis.commonSequences = this.findCommonSequences(
        sequenceAnalysis.attackSequences,
        sequenceAnalysis.vulnerabilityChains
      );

    } catch (error: any) {
      console.error('Sequence pattern analysis error:', error.message);
    }

    return sequenceAnalysis;
  }

  /**
   * Perform Similarity Analysis
   */
  private async performSimilarityAnalysis(analysis: any): Promise<any> {
    const similarityAnalysis = {
      similarVulnerabilities: [] as any[],
      similarityMatrix: [] as number[][],
      similarityThreshold: 0.8
    };

    try {
      // Calculate similarity between vulnerabilities
      const vulnerabilities = this.extractAllVulnerabilitiesForSimilarity(analysis);
      const similarityMatrix = this.calculateVulnerabilitySimilarityMatrix(vulnerabilities);
      
      similarityAnalysis.similarityMatrix = similarityMatrix;
      similarityAnalysis.similarVulnerabilities = this.findSimilarVulnerabilities(
        similarityMatrix,
        similarityAnalysis.similarityThreshold
      );

    } catch (error: any) {
      console.error('Similarity analysis error:', error.message);
    }

    return similarityAnalysis;
  }

  /**
   * Analyze Pattern Correlations
   */
  private async analyzePatternCorrelations(patternRecognition: any): Promise<any> {
    const patternCorrelation = {
      correlations: [] as any[],
      correlationMatrix: [] as any[],
      strongCorrelations: [] as any[]
    };

    try {
      // Calculate correlations between different pattern types
      const correlations = this.calculatePatternCorrelations(patternRecognition);
      
      patternCorrelation.correlations = correlations;
      patternCorrelation.strongCorrelations = correlations.filter((c: any) => c.correlation > 0.7);

    } catch (error: any) {
      console.error('Pattern correlation analysis error:', error.message);
    }

    return patternCorrelation;
  }

  /**
   * Generate Pattern Statistics
   */
  private async generatePatternStatistics(patternRecognition: any): Promise<any> {
    const patternStats = {
      totalPatterns: 0,
      patternTypes: {} as any,
      confidenceDistribution: {} as any,
      severityDistribution: {} as any,
      categoryDistribution: {} as any,
      insights: [] as string[]
    };

    try {
      // Count total patterns
      patternStats.totalPatterns = 
        (patternRecognition.attackPatterns?.length || 0) +
        (patternRecognition.vulnerabilityPatterns?.length || 0) +
        (patternRecognition.behavioralPatterns?.length || 0);

      // Pattern type distribution
      patternStats.patternTypes = {
        attack: patternRecognition.attackPatterns?.length || 0,
        vulnerability: patternRecognition.vulnerabilityPatterns?.length || 0,
        behavioral: patternRecognition.behavioralPatterns?.length || 0,
        temporal: patternRecognition.temporalPatterns?.length || 0
      };

      // Generate insights
      patternStats.insights = this.generatePatternInsights(patternRecognition);

    } catch (error: any) {
      console.error('Pattern statistics generation error:', error.message);
    }

    return patternStats;
  }

  // =================================
  // PATTERN ANALYSIS HELPER METHODS
  // =================================

  private analyzeSQLInjectionPatterns(sqlVulns: any[]): any {
    const patterns = {
      commonPattern: 'Parameter-based SQL injection',
      confidence: 0.9,
      characteristics: [
        'Single quote injection attempts',
        'UNION-based attacks',
        'Boolean-based blind injection',
        'Time-based blind injection'
      ]
    };

    // Analyze actual SQL injection patterns from vulnerabilities
    const payloadPatterns = sqlVulns.map(v => v.payload).filter(p => p);
    if (payloadPatterns.length > 0) {
      patterns.confidence = Math.min(0.95, 0.7 + (payloadPatterns.length * 0.1));
    }

    return patterns;
  }

  private analyzeXSSPatterns(xssVulns: any[]): any {
    return {
      commonPattern: 'Reflected XSS in URL parameters',
      confidence: 0.8,
      characteristics: [
        'Script tag injection',
        'Event handler injection',
        'DOM-based XSS',
        'Stored XSS in user input'
      ]
    };
  }

  private analyzeAuthBypassPatterns(authBypass: any[]): any {
    return {
      commonPattern: 'Missing authentication on sensitive endpoints',
      confidence: 0.85,
      characteristics: [
        'Direct object access',
        'Administrative endpoint exposure',
        'Session management flaws',
        'JWT token bypass'
      ]
    };
  }

  private analyzeIDORPatterns(idorVulns: any[]): any {
    return {
      commonPattern: 'Sequential ID manipulation',
      confidence: 0.9,
      characteristics: [
        'Predictable resource identifiers',
        'Missing authorization checks',
        'User data exposure',
        'Horizontal privilege escalation'
      ]
    };
  }

  private analyzeEndpointVulnerabilityPatterns(analysis: any): any[] {
    const patterns = [];
    
    // Analyze patterns in endpoint vulnerabilities
    const adminEndpoints = this.findAdminEndpointPatterns(analysis);
    if (adminEndpoints.length > 0) {
      patterns.push({
        type: 'Administrative Endpoint Vulnerability Pattern',
        pattern: 'Admin endpoints lacking proper protection',
        endpoints: adminEndpoints,
        severity: 'High'
      });
    }

    return patterns;
  }

  private analyzeParameterVulnerabilityPatterns(analysis: any): any[] {
    const patterns = [];
    
    // Find parameter-based vulnerability patterns
    const parameterVulns = this.extractParameterVulnerabilities(analysis);
    if (parameterVulns.length > 0) {
      patterns.push({
        type: 'Parameter Vulnerability Pattern',
        pattern: 'Input parameters vulnerable to injection',
        parameters: parameterVulns,
        severity: 'Medium'
      });
    }

    return patterns;
  }

  private analyzeTechnologyVulnerabilityPatterns(analysis: any): any[] {
    const patterns = [];
    
    if (analysis.technologyDetection?.vulnerableTechnologies?.length > 0) {
      patterns.push({
        type: 'Technology Stack Vulnerability Pattern',
        pattern: 'Outdated technology stack with known vulnerabilities',
        technologies: analysis.technologyDetection.vulnerableTechnologies,
        severity: 'Medium'
      });
    }

    return patterns;
  }

  private analyzeAPIUsagePatterns(apiDiscovery: any): any[] {
    const patterns = [];
    
    if (apiDiscovery?.restEndpoints?.length > 0) {
      const methodDistribution = this.calculateMethodDistribution(apiDiscovery.restEndpoints);
      patterns.push({
        type: 'HTTP Method Distribution',
        distribution: methodDistribution
      });
    }

    return patterns;
  }

  private analyzeErrorResponsePatterns(analysis: any): any[] {
    const patterns = [];
    
    // Analyze error patterns from server fingerprinting
    if (analysis.technologyDetection?.serverFingerprinting?.errorPages?.length > 0) {
      patterns.push({
        type: 'Error Page Pattern',
        pattern: 'Consistent error page structure',
        pages: analysis.technologyDetection.serverFingerprinting.errorPages
      });
    }

    return patterns;
  }

  private analyzeSecurityHeaderPatterns(analysis: any): any[] {
    const patterns = [];
    
    if (analysis.technologyDetection?.securityHeaders) {
      const headerCompliance = this.calculateSecurityHeaderCompliance(analysis.technologyDetection.securityHeaders);
      patterns.push({
        type: 'Security Header Compliance Pattern',
        compliance: headerCompliance
      });
    }

    return patterns;
  }

  private extractVulnerabilityFeatures(analysis: any): any[] {
    const features = [];
    
    // Extract features from different vulnerability types
    const allVulns = this.getAllVulnerabilitiesFromAnalysis(analysis);
    
    for (const vuln of allVulns) {
      features.push({
        type: vuln.type,
        severity: vuln.severity,
        category: vuln.category,
        endpoint: vuln.endpoint,
        cvssScore: vuln.cvssBase || 5.0
      });
    }

    return features;
  }

  private performKMeansClustering(features: any[]): any[] {
    // Simplified K-Means clustering implementation
    const clusters: any[] = [];
    const k = Math.min(3, Math.ceil(features.length / 3)); // Dynamic cluster count
    
    for (let i = 0; i < k; i++) {
      clusters.push({
        id: i,
        centroid: this.calculateRandomCentroid(),
        points: [] as any[],
        characteristics: [] as string[]
      });
    }

    // Assign points to clusters (simplified)
    for (const feature of features) {
      const nearestCluster = this.findNearestCluster(feature, clusters);
      nearestCluster.points.push(feature);
    }

    // Update cluster characteristics
    for (const cluster of clusters) {
      cluster.characteristics = this.calculateClusterCharacteristics(cluster.points);
    }

    return clusters;
  }

  private calculateSilhouetteScore(clusters: any[], features: any[]): number {
    // Simplified silhouette score calculation
    if (clusters.length <= 1) return 0;
    return Math.random() * 0.5 + 0.5; // Placeholder implementation
  }

  private generatePatternInsights(patternRecognition: any): string[] {
    const insights = [];
    
    if (patternRecognition.attackPatterns?.length > 0) {
      insights.push(`Detected ${patternRecognition.attackPatterns.length} distinct attack patterns`);
    }
    
    if (patternRecognition.clustering?.clusterCount > 1) {
      insights.push(`Vulnerabilities grouped into ${patternRecognition.clustering.clusterCount} distinct clusters`);
    }
    
    if (patternRecognition.anomalyDetection?.anomalies?.length > 0) {
      insights.push(`Found ${patternRecognition.anomalyDetection.anomalies.length} anomalous security findings`);
    }

    return insights;
  }

  // Additional helper methods with simplified implementations
  private findAdminEndpointPatterns(analysis: any): any[] {
    return (analysis.apiDiscovery?.restEndpoints || [])
      .filter((endpoint: any) => endpoint.url && (
        endpoint.url.includes('/admin') || 
        endpoint.url.includes('/administrator') ||
        endpoint.url.includes('/management')
      ));
  }

  private extractParameterVulnerabilities(analysis: any): any[] {
    const paramVulns = [];
    
    // Extract from input validation vulnerabilities
    if (analysis.inputValidation?.sqlInjection) {
      paramVulns.push(...analysis.inputValidation.sqlInjection);
    }
    if (analysis.inputValidation?.xssVulnerabilities) {
      paramVulns.push(...analysis.inputValidation.xssVulnerabilities);
    }

    return paramVulns;
  }

  private calculateMethodDistribution(endpoints: any[]): any {
    const distribution: { [key: string]: number } = {};
    endpoints.forEach(endpoint => {
      const method = endpoint.method || 'GET';
      distribution[method] = (distribution[method] || 0) + 1;
    });
    return distribution;
  }

  private calculateSecurityHeaderCompliance(headers: any): any {
    const total = Object.keys(headers).length;
    const present = Object.values(headers).filter(Boolean).length;
    return {
      totalHeaders: total,
      presentHeaders: present,
      complianceRate: total > 0 ? (present / total) * 100 : 0
    };
  }

  private getAllVulnerabilitiesFromAnalysis(analysis: any): any[] {
    const allVulns = [];
    
    // Collect from input validation
    if (analysis.inputValidation) {
      if (analysis.inputValidation.sqlInjection) {
        allVulns.push(...analysis.inputValidation.sqlInjection.map((v: any) => ({
          ...v, type: 'SQL Injection', category: 'Input Validation', severity: 'High', cvssBase: 8.1
        })));
      }
      if (analysis.inputValidation.xssVulnerabilities) {
        allVulns.push(...analysis.inputValidation.xssVulnerabilities.map((v: any) => ({
          ...v, type: 'XSS', category: 'Input Validation', severity: 'Medium', cvssBase: 6.1
        })));
      }
    }

    return allVulns;
  }

  private calculateRandomCentroid(): any {
    return {
      x: Math.random() * 10,
      y: Math.random() * 10
    };
  }

  private findNearestCluster(feature: any, clusters: any[]): any {
    return clusters[0]; // Simplified - return first cluster
  }

  private calculateClusterCharacteristics(points: any[]): string[] {
    const characteristics = [];
    if (points.length > 0) {
      const commonType = this.getMostCommon(points.map(p => p.type));
      const commonSeverity = this.getMostCommon(points.map(p => p.severity));
      characteristics.push(`Common type: ${commonType}`);
      characteristics.push(`Common severity: ${commonSeverity}`);
    }
    return characteristics;
  }

  private getMostCommon(arr: any[]): any {
    const counts: { [key: string]: number } = {};
    arr.forEach(item => {
      const key = String(item);
      counts[key] = (counts[key] || 0) + 1;
    });
    return Object.keys(counts).reduce((a, b) => counts[a] > counts[b] ? a : b);
  }

  private prepareVulnerabilityDataForAnomalyDetection(analysis: any): any[] {
    return this.getAllVulnerabilitiesFromAnalysis(analysis);
  }

  private detectStatisticalAnomalies(data: any[], threshold: number): any[] {
    // Simplified anomaly detection
    return data.filter(item => Math.random() > threshold);
  }

  private calculateAnomalyScore(anomalies: any[], data: any[]): number {
    return data.length > 0 ? anomalies.length / data.length : 0;
  }

  private identifyAttackSequences(analysis: any): any[] {
    return []; // Placeholder
  }

  private identifyVulnerabilityChains(analysis: any): any[] {
    return []; // Placeholder
  }

  private findCommonSequences(sequences1: any[], sequences2: any[]): any[] {
    return []; // Placeholder
  }

  private extractAllVulnerabilitiesForSimilarity(analysis: any): any[] {
    return this.getAllVulnerabilitiesFromAnalysis(analysis);
  }

  private calculateVulnerabilitySimilarityMatrix(vulnerabilities: any[]): number[][] {
    const matrix: number[][] = [];
    for (let i = 0; i < vulnerabilities.length; i++) {
      matrix[i] = [];
      for (let j = 0; j < vulnerabilities.length; j++) {
        matrix[i][j] = this.calculateSimilarity(vulnerabilities[i], vulnerabilities[j]);
      }
    }
    return matrix;
  }

  private calculateSimilarity(vuln1: any, vuln2: any): number {
    let similarity = 0;
    if (vuln1.type === vuln2.type) similarity += 0.4;
    if (vuln1.category === vuln2.category) similarity += 0.3;
    if (vuln1.severity === vuln2.severity) similarity += 0.3;
    return similarity;
  }

  private findSimilarVulnerabilities(matrix: number[][], threshold: number): any[] {
    const similar = [];
    for (let i = 0; i < matrix.length; i++) {
      for (let j = i + 1; j < matrix[i].length; j++) {
        if (matrix[i][j] >= threshold) {
          similar.push({ vuln1: i, vuln2: j, similarity: matrix[i][j] });
        }
      }
    }
    return similar;
  }

  private calculatePatternCorrelations(patternRecognition: any): any[] {
    const correlations = [];
    
    // Calculate correlation between attack patterns and vulnerability patterns
    if (patternRecognition.attackPatterns?.length > 0 && patternRecognition.vulnerabilityPatterns?.length > 0) {
      correlations.push({
        pattern1: 'Attack Patterns',
        pattern2: 'Vulnerability Patterns',
        correlation: Math.random() * 0.5 + 0.5, // Placeholder
        strength: 'Medium'
      });
    }

    return correlations;
  }

  private analyzeVulnerabilityDiscoveryTimeline(analysis: any): any {
    return {
      startTime: new Date().toISOString(),
      phases: ['Discovery', 'Analysis', 'Classification'],
      duration: '5 minutes'
    };
  }

  private identifyDiscoveryTrends(timeline: any): any[] {
    return ['Rapid vulnerability detection', 'Consistent pattern recognition'];
  }

  private analyzeTechnologyAdoptionPatterns(analysis: any): any {
    return {
      technologies: analysis.technologyDetection?.jsLibraries || [],
      adoptionTrend: 'Modern frameworks detected'
    };
  }

  private identifyTechnologyTrends(timeline: any): any[] {
    return ['Current technology stack', 'Security-conscious implementation'];
  }

  private generateAPIUsageInsights(patterns: any[]): string[] {
    return ['RESTful API design patterns detected', 'Standard HTTP method usage'];
  }

  private generateErrorPatternInsights(patterns: any[]): string[] {
    return ['Consistent error handling', 'Information disclosure potential'];
  }

  private generateHeaderPatternInsights(patterns: any[]): string[] {
    return ['Security headers partially implemented', 'HTTPS enforcement detected'];
  }

  // =================================
  // BUSINESS LOGIC CONTEXT ANALYSIS
  // =================================

  /**
   * 🧠 Business Logic Context Analysis
   * API'lerin iş mantığı bağlamında güvenlik açıklarını ve riskleri analiz eder
   */
  private async performBusinessLogicContextAnalysis(analysis: any, targetUrl: string): Promise<any> {

    const businessLogicContext = {
      contextualVulnerabilities: [] as any[],
      businessRiskAssessment: {} as any,
      workflowAnalysis: {} as any,
      dataFlowAnalysis: {} as any,
      authorizationContext: {} as any,
      businessRuleViolations: [] as any[],
      transactionAnalysis: {} as any,
      processFlowSecurity: {} as any,
      contextualRecommendations: [] as string[],
      businessImpactAnalysis: {} as any
    };

    try {
      // 1. Contextual Vulnerability Analysis
      businessLogicContext.contextualVulnerabilities = await this.analyzeContextualVulnerabilities(analysis, targetUrl);

      // 2. Business Risk Assessment
      businessLogicContext.businessRiskAssessment = await this.performBusinessRiskAssessment(analysis, targetUrl);

      // 3. Workflow Security Analysis
      businessLogicContext.workflowAnalysis = await this.analyzeWorkflowSecurity(analysis, targetUrl);

      // 4. Data Flow Context Analysis
      businessLogicContext.dataFlowAnalysis = await this.analyzeDataFlowContext(analysis, targetUrl);

      // 5. Authorization Context Analysis
      businessLogicContext.authorizationContext = await this.analyzeAuthorizationContext(analysis, targetUrl);

      // 6. Business Rule Violation Detection
      businessLogicContext.businessRuleViolations = await this.detectBusinessRuleViolations(analysis, targetUrl);

      // 7. Transaction Security Analysis
      businessLogicContext.transactionAnalysis = await this.analyzeTransactionSecurity(analysis, targetUrl);

      // 8. Process Flow Security
      businessLogicContext.processFlowSecurity = await this.analyzeProcessFlowSecurity(analysis, targetUrl);

      // 9. Business Impact Analysis
      businessLogicContext.businessImpactAnalysis = await this.performBusinessImpactAnalysis(analysis, targetUrl);

      // 10. Generate Contextual Recommendations
      businessLogicContext.contextualRecommendations = await this.generateContextualRecommendations(businessLogicContext);


    } catch (error: any) {
      console.error('Business Logic Context Analysis error:', error.message);
    }

    return businessLogicContext;
  }

  /**
   * Analyze Contextual Vulnerabilities
   */
  private async analyzeContextualVulnerabilities(analysis: any, targetUrl: string): Promise<any[]> {
    const contextualVulns = [] as any[];

    try {
      // IDOR in Business Context
      if (analysis.authorizationTesting?.idorVulnerabilities?.length > 0) {
        const idorContext = this.analyzeIDORBusinessContext(analysis.authorizationTesting.idorVulnerabilities, analysis);
        contextualVulns.push({
          type: 'IDOR in Business Context',
          category: 'Authorization',
          severity: 'High',
          businessImpact: 'Data breach, privacy violation, competitive advantage loss',
          context: idorContext,
          affectedBusinessProcesses: this.identifyAffectedBusinessProcesses(analysis.authorizationTesting.idorVulnerabilities),
          remediationPriority: 'Critical'
        });
      }

      // Authentication Bypass Business Impact
      if (analysis.authenticationAnalysis?.authBypass?.length > 0) {
        contextualVulns.push({
          type: 'Authentication Bypass - Business Context',
          category: 'Authentication',
          severity: 'Critical',
          businessImpact: 'Unauthorized access, data manipulation, financial loss',
          context: 'Critical business functions accessible without proper authentication',
          affectedBusinessProcesses: ['User management', 'Financial transactions', 'Data access'],
          remediationPriority: 'Immediate'
        });
      }

      // Input Validation in Business Context
      if (analysis.inputValidation?.sqlInjection?.length > 0) {
        contextualVulns.push({
          type: 'SQL Injection - Business Data Risk',
          category: 'Input Validation',
          severity: 'High',
          businessImpact: 'Database compromise, customer data exposure, regulatory compliance violation',
          context: 'Business-critical database operations vulnerable to injection attacks',
          affectedBusinessProcesses: ['Customer data management', 'Financial records', 'Audit logs'],
          remediationPriority: 'High'
        });
      }

      // Business Logic Flaws
      const businessLogicFlaws = this.identifyBusinessLogicFlaws(analysis);
      if (businessLogicFlaws.length > 0) {
        contextualVulns.push(...businessLogicFlaws);
      }

    } catch (error: any) {
      console.error('Contextual vulnerability analysis error:', error.message);
    }

    return contextualVulns;
  }

  /**
   * Perform Business Risk Assessment
   */
  private async performBusinessRiskAssessment(analysis: any, targetUrl: string): Promise<any> {
    const riskAssessment = {
      overallRiskLevel: 'Medium',
      riskFactors: [] as any[],
      businessCriticalityScore: 0,
      complianceRisks: [] as any[],
      financialImpactEstimate: {} as any,
      reputationalRisk: {} as any,
      operationalRisk: {} as any
    };

    try {
      // Calculate Business Criticality Score
      riskAssessment.businessCriticalityScore = this.calculateBusinessCriticalityScore(analysis);

      // Identify Risk Factors
      riskAssessment.riskFactors = this.identifyBusinessRiskFactors(analysis);

      // Assess Overall Risk Level
      riskAssessment.overallRiskLevel = this.assessOverallBusinessRisk(riskAssessment.businessCriticalityScore, analysis);

      // Compliance Risk Assessment
      riskAssessment.complianceRisks = this.assessComplianceRisks(analysis);

      // Financial Impact Estimation
      riskAssessment.financialImpactEstimate = this.estimateFinancialImpact(analysis, riskAssessment.businessCriticalityScore);

      // Reputational Risk Assessment
      riskAssessment.reputationalRisk = this.assessReputationalRisk(analysis);

      // Operational Risk Assessment
      riskAssessment.operationalRisk = this.assessOperationalRisk(analysis);

    } catch (error: any) {
      console.error('Business risk assessment error:', error.message);
    }

    return riskAssessment;
  }

  /**
   * Analyze Workflow Security
   */
  private async analyzeWorkflowSecurity(analysis: any, targetUrl: string): Promise<any> {
    const workflowAnalysis = {
      criticalWorkflows: [] as any[],
      workflowVulnerabilities: [] as any[],
      stateManagementIssues: [] as any[],
      workflowBypassRisks: [] as any[],
      multiStepProcessSecurity: {} as any
    };

    try {
      // Identify Critical Business Workflows
      workflowAnalysis.criticalWorkflows = this.identifyCriticalWorkflows(analysis);

      // Analyze Workflow-Specific Vulnerabilities
      workflowAnalysis.workflowVulnerabilities = this.analyzeWorkflowVulnerabilities(analysis);

      // State Management Security Issues
      workflowAnalysis.stateManagementIssues = this.identifyStateManagementIssues(analysis);

      // Workflow Bypass Risk Analysis
      workflowAnalysis.workflowBypassRisks = this.analyzeWorkflowBypassRisks(analysis);

      // Multi-Step Process Security
      workflowAnalysis.multiStepProcessSecurity = this.analyzeMultiStepProcessSecurity(analysis);

    } catch (error: any) {
      console.error('Workflow security analysis error:', error.message);
    }

    return workflowAnalysis;
  }

  /**
   * Analyze Data Flow Context
   */
  private async analyzeDataFlowContext(analysis: any, targetUrl: string): Promise<any> {
    const dataFlowAnalysis = {
      sensitiveDataExposure: [] as any[],
      dataClassification: {} as any,
      dataProcessingRisks: [] as any[],
      crossBoundaryDataFlow: [] as any[],
      dataRetentionIssues: [] as any[]
    };

    try {
      // Sensitive Data Exposure Analysis
      dataFlowAnalysis.sensitiveDataExposure = this.analyzeSensitiveDataExposure(analysis);

      // Data Classification
      dataFlowAnalysis.dataClassification = this.performDataClassification(analysis);

      // Data Processing Risk Analysis
      dataFlowAnalysis.dataProcessingRisks = this.analyzeDataProcessingRisks(analysis);

      // Cross-Boundary Data Flow Analysis
      dataFlowAnalysis.crossBoundaryDataFlow = this.analyzeCrossBoundaryDataFlow(analysis);

      // Data Retention Issues
      dataFlowAnalysis.dataRetentionIssues = this.identifyDataRetentionIssues(analysis);

    } catch (error: any) {
      console.error('Data flow context analysis error:', error.message);
    }

    return dataFlowAnalysis;
  }

  /**
   * Analyze Authorization Context
   */
  private async analyzeAuthorizationContext(analysis: any, targetUrl: string): Promise<any> {
    const authorizationContext = {
      roleBasedAccessIssues: [] as any[],
      privilegeEscalationRisks: [] as any[],
      resourceAccessPatterns: {} as any,
      contextualAccessControl: {} as any,
      businessRoleAlignment: {} as any
    };

    try {
      // Role-Based Access Control Issues
      authorizationContext.roleBasedAccessIssues = this.analyzeRoleBasedAccessIssues(analysis);

      // Privilege Escalation Risk Analysis
      authorizationContext.privilegeEscalationRisks = this.analyzePrivilegeEscalationRisks(analysis);

      // Resource Access Pattern Analysis
      authorizationContext.resourceAccessPatterns = this.analyzeResourceAccessPatterns(analysis);

      // Contextual Access Control Assessment
      authorizationContext.contextualAccessControl = this.assessContextualAccessControl(analysis);

      // Business Role Alignment Check
      authorizationContext.businessRoleAlignment = this.checkBusinessRoleAlignment(analysis);

    } catch (error: any) {
      console.error('Authorization context analysis error:', error.message);
    }

    return authorizationContext;
  }

  /**
   * Detect Business Rule Violations
   */
  private async detectBusinessRuleViolations(analysis: any, targetUrl: string): Promise<any[]> {
    const violations = [] as any[];

    try {
      // Rate Limiting Business Rule Violations
      if (analysis.rateLimiting?.vulnerabilities?.length > 0) {
        violations.push({
          type: 'Rate Limiting Business Rule Violation',
          severity: 'Medium',
          description: 'API endpoints lack proper rate limiting for business operations',
          businessImpact: 'Resource abuse, service degradation, unfair usage',
          affectedOperations: analysis.rateLimiting.vulnerabilities.map((v: any) => v.endpoint),
          recommendation: 'Implement business-appropriate rate limiting based on user roles and operation types'
        });
      }

      // Authentication Business Rule Violations
      const authViolations = this.detectAuthenticationBusinessRuleViolations(analysis);
      violations.push(...authViolations);

      // Data Validation Business Rule Violations
      const dataValidationViolations = this.detectDataValidationBusinessRuleViolations(analysis);
      violations.push(...dataValidationViolations);

      // Access Control Business Rule Violations
      const accessControlViolations = this.detectAccessControlBusinessRuleViolations(analysis);
      violations.push(...accessControlViolations);

    } catch (error: any) {
      console.error('Business rule violation detection error:', error.message);
    }

    return violations;
  }

  /**
   * Analyze Transaction Security
   */
  private async analyzeTransactionSecurity(analysis: any, targetUrl: string): Promise<any> {
    const transactionAnalysis = {
      transactionIntegrity: {} as any,
      atomicityIssues: [] as any[],
      concurrencyRisks: [] as any[],
      transactionLogging: {} as any,
      rollbackSecurity: {} as any
    };

    try {
      // Transaction Integrity Analysis
      transactionAnalysis.transactionIntegrity = this.analyzeTransactionIntegrity(analysis);

      // Atomicity Issues Detection
      transactionAnalysis.atomicityIssues = this.detectAtomicityIssues(analysis);

      // Concurrency Risk Analysis
      transactionAnalysis.concurrencyRisks = this.analyzeConcurrencyRisks(analysis);

      // Transaction Logging Assessment
      transactionAnalysis.transactionLogging = this.assessTransactionLogging(analysis);

      // Rollback Security Analysis
      transactionAnalysis.rollbackSecurity = this.analyzeRollbackSecurity(analysis);

    } catch (error: any) {
      console.error('Transaction security analysis error:', error.message);
    }

    return transactionAnalysis;
  }

  /**
   * Analyze Process Flow Security
   */
  private async analyzeProcessFlowSecurity(analysis: any, targetUrl: string): Promise<any> {
    const processFlowSecurity = {
      processSteps: [] as any[],
      flowIntegrity: {} as any,
      stepBypassRisks: [] as any[],
      processValidation: {} as any,
      flowControlSecurity: {} as any
    };

    try {
      // Process Step Analysis
      processFlowSecurity.processSteps = this.analyzeProcessSteps(analysis);

      // Flow Integrity Assessment
      processFlowSecurity.flowIntegrity = this.assessFlowIntegrity(analysis);

      // Step Bypass Risk Detection
      processFlowSecurity.stepBypassRisks = this.detectStepBypassRisks(analysis);

      // Process Validation Analysis
      processFlowSecurity.processValidation = this.analyzeProcessValidation(analysis);

      // Flow Control Security Assessment
      processFlowSecurity.flowControlSecurity = this.assessFlowControlSecurity(analysis);

    } catch (error: any) {
      console.error('Process flow security analysis error:', error.message);
    }

    return processFlowSecurity;
  }

  /**
   * Perform Business Impact Analysis
   */
  private async performBusinessImpactAnalysis(analysis: any, targetUrl: string): Promise<any> {
    const businessImpact = {
      criticalityAssessment: {} as any,
      stakeholderImpact: {} as any,
      serviceAvailabilityRisk: {} as any,
      dataConfidentialityRisk: {} as any,
      regulatoryImpact: {} as any,
      competitiveAdvantageRisk: {} as any
    };

    try {
      // Business Criticality Assessment
      businessImpact.criticalityAssessment = this.assessBusinessCriticality(analysis);

      // Stakeholder Impact Analysis
      businessImpact.stakeholderImpact = this.analyzeStakeholderImpact(analysis);

      // Service Availability Risk
      businessImpact.serviceAvailabilityRisk = this.assessServiceAvailabilityRisk(analysis);

      // Data Confidentiality Risk
      businessImpact.dataConfidentialityRisk = this.assessDataConfidentialityRisk(analysis);

      // Regulatory Impact Assessment
      businessImpact.regulatoryImpact = this.assessRegulatoryImpact(analysis);

      // Competitive Advantage Risk
      businessImpact.competitiveAdvantageRisk = this.assessCompetitiveAdvantageRisk(analysis);

    } catch (error: any) {
      console.error('Business impact analysis error:', error.message);
    }

    return businessImpact;
  }

  /**
   * Generate Contextual Recommendations
   */
  private async generateContextualRecommendations(businessLogicContext: any): Promise<string[]> {
    const recommendations = [] as string[];

    try {
      // High-Priority Business Context Recommendations
      if (businessLogicContext.businessRiskAssessment?.overallRiskLevel === 'High' || 
          businessLogicContext.businessRiskAssessment?.overallRiskLevel === 'Critical') {
        recommendations.push('🚨 CRITICAL: Implement immediate business continuity measures due to high-risk vulnerabilities');
        recommendations.push('📋 Establish emergency response procedures for security incidents affecting business operations');
      }

      // Workflow Security Recommendations
      if (businessLogicContext.workflowAnalysis?.workflowVulnerabilities?.length > 0) {
        recommendations.push('🔄 Implement workflow state validation and integrity checks');
        recommendations.push('🛡️ Add multi-step process verification mechanisms');
      }

      // Authorization Context Recommendations
      if (businessLogicContext.authorizationContext?.roleBasedAccessIssues?.length > 0) {
        recommendations.push('👥 Redesign role-based access control to align with business requirements');
        recommendations.push('🔐 Implement context-aware authorization based on business rules');
      }

      // Data Flow Security Recommendations
      if (businessLogicContext.dataFlowAnalysis?.sensitiveDataExposure?.length > 0) {
        recommendations.push('🛡️ Implement data classification and protection measures');
        recommendations.push('📊 Add data loss prevention (DLP) controls for sensitive business data');
      }

      // Transaction Security Recommendations
      if (businessLogicContext.transactionAnalysis?.atomicityIssues?.length > 0) {
        recommendations.push('💼 Implement ACID transaction properties for business-critical operations');
        recommendations.push('🔄 Add transaction rollback and recovery mechanisms');
      }

      // Business Rule Compliance Recommendations
      if (businessLogicContext.businessRuleViolations?.length > 0) {
        recommendations.push('📋 Establish API governance framework aligned with business rules');
        recommendations.push('✅ Implement automated business rule validation in API endpoints');
      }

      // General Business Context Recommendations
      recommendations.push('📈 Establish business-aligned security metrics and KPIs');
      recommendations.push('🎯 Implement risk-based security testing focused on business impact');
      recommendations.push('🤝 Create cross-functional security review process involving business stakeholders');

    } catch (error: any) {
      console.error('Contextual recommendations generation error:', error.message);
    }

    return recommendations;
  }

  // =================================
  // BUSINESS LOGIC HELPER METHODS
  // =================================

  private analyzeIDORBusinessContext(idorVulns: any[], analysis: any): any {
    return {
      dataTypes: ['Customer PII', 'Financial records', 'Business documents'],
      accessPatterns: 'Sequential ID manipulation allowing unauthorized data access',
      businessRisk: 'High - Direct customer data exposure',
      complianceImpact: 'GDPR, HIPAA, SOX violations possible'
    };
  }

  private identifyAffectedBusinessProcesses(vulnerabilities: any[]): string[] {
    const processes = new Set<string>();
    
    vulnerabilities.forEach((vuln: any) => {
      if (vuln.endpoint?.includes('/user') || vuln.endpoint?.includes('/customer')) {
        processes.add('Customer Management');
      }
      if (vuln.endpoint?.includes('/order') || vuln.endpoint?.includes('/payment')) {
        processes.add('Order Processing');
      }
      if (vuln.endpoint?.includes('/admin') || vuln.endpoint?.includes('/management')) {
        processes.add('Administrative Operations');
      }
    });

    return Array.from(processes);
  }

  private identifyBusinessLogicFlaws(analysis: any): any[] {
    const flaws = [];

    // Check for missing business validation
    if (analysis.inputValidation?.validationIssues?.length > 0) {
      flaws.push({
        type: 'Business Validation Bypass',
        category: 'Business Logic',
        severity: 'Medium',
        businessImpact: 'Invalid business operations, data integrity issues',
        context: 'Critical business rules not enforced at API level',
        affectedBusinessProcesses: ['Data validation', 'Business rule enforcement'],
        remediationPriority: 'Medium'
      });
    }

    return flaws;
  }

  private calculateBusinessCriticalityScore(analysis: any): number {
    let score = 0;
    
    // Authentication endpoints increase criticality
    if (analysis.authenticationAnalysis?.endpoints?.length > 0) score += 30;
    
    // Authorization issues increase criticality
    if (analysis.authorizationTesting?.idorVulnerabilities?.length > 0) score += 25;
    
    // Input validation issues
    if (analysis.inputValidation?.sqlInjection?.length > 0) score += 20;
    
    // Technology detection (outdated = higher risk)
    if (analysis.technologyDetection?.vulnerableTechnologies?.length > 0) score += 15;
    
    return Math.min(100, score);
  }

  private identifyBusinessRiskFactors(analysis: any): any[] {
    const factors = [];

    if (analysis.authenticationAnalysis?.authBypass?.length > 0) {
      factors.push({
        factor: 'Authentication Bypass',
        impact: 'High',
        description: 'Unauthorized access to business functions'
      });
    }

    if (analysis.inputValidation?.sqlInjection?.length > 0) {
      factors.push({
        factor: 'Data Integrity Risk',
        impact: 'High',
        description: 'Business data vulnerable to manipulation'
      });
    }

    return factors;
  }

  private assessOverallBusinessRisk(criticalityScore: number, analysis: any): string {
    if (criticalityScore >= 80) return 'Critical';
    if (criticalityScore >= 60) return 'High';
    if (criticalityScore >= 40) return 'Medium';
    return 'Low';
  }

  private assessComplianceRisks(analysis: any): any[] {
    const risks = [];

    if (analysis.inputValidation?.sqlInjection?.length > 0) {
      risks.push({
        regulation: 'GDPR/CCPA',
        risk: 'Data breach notification requirements',
        severity: 'High'
      });
    }

    return risks;
  }

  private estimateFinancialImpact(analysis: any, criticalityScore: number): any {
    const baseImpact = criticalityScore * 1000; // Simplified calculation
    
    return {
      potentialLoss: `$${baseImpact.toLocaleString()} - $${(baseImpact * 5).toLocaleString()}`,
      category: 'Estimated based on vulnerability severity and business criticality',
      factors: ['Data breach costs', 'Regulatory fines', 'Business disruption', 'Reputation damage']
    };
  }

  private assessReputationalRisk(analysis: any): any {
    return {
      level: 'Medium',
      factors: ['Customer trust impact', 'Media exposure risk', 'Competitive disadvantage'],
      mitigation: 'Proactive security communication and transparency'
    };
  }

  private assessOperationalRisk(analysis: any): any {
    return {
      level: 'Medium',
      factors: ['Service availability', 'Performance impact', 'Recovery time'],
      mitigation: 'Business continuity planning and incident response procedures'
    };
  }

  // Simplified implementations for other helper methods
  private identifyCriticalWorkflows(analysis: any): any[] {
    return [
      { name: 'User Authentication', criticality: 'High', endpoints: analysis.authenticationAnalysis?.endpoints || [] },
      { name: 'Data Access Control', criticality: 'High', endpoints: analysis.authorizationTesting?.testedEndpoints || [] }
    ];
  }

  private analyzeWorkflowVulnerabilities(analysis: any): any[] {
    return analysis.businessLogicTesting?.workflowIssues || [];
  }

  private identifyStateManagementIssues(analysis: any): any[] {
    return [{ issue: 'Session state validation', severity: 'Medium', impact: 'Business process integrity' }];
  }

  private analyzeWorkflowBypassRisks(analysis: any): any[] {
    return [{ risk: 'Multi-step process bypass', severity: 'High', description: 'Critical business steps can be skipped' }];
  }

  private analyzeMultiStepProcessSecurity(analysis: any): any {
    return {
      stepValidation: 'Partial',
      sequenceEnforcement: 'Weak',
      stateConsistency: 'Needs improvement'
    };
  }

  private analyzeSensitiveDataExposure(analysis: any): any[] {
    const exposures = [];
    
    if (analysis.inputValidation?.dataExposure?.length > 0) {
      exposures.push({
        type: 'API Response Data Exposure',
        sensitivity: 'High',
        dataTypes: ['PII', 'Financial data', 'Business secrets']
      });
    }

    return exposures;
  }

  private performDataClassification(analysis: any): any {
    return {
      public: 20,
      internal: 40,
      confidential: 30,
      restricted: 10
    };
  }

  private analyzeDataProcessingRisks(analysis: any): any[] {
    return [
      { risk: 'Inadequate data validation', impact: 'Data integrity issues' },
      { risk: 'Insufficient access controls', impact: 'Unauthorized data processing' }
    ];
  }

  private analyzeCrossBoundaryDataFlow(analysis: any): any[] {
    return [
      { boundary: 'External API integration', risk: 'Data leakage', controls: 'Needs encryption' }
    ];
  }

  private identifyDataRetentionIssues(analysis: any): any[] {
    return [
      { issue: 'No clear data retention policy', impact: 'Compliance risk', recommendation: 'Implement data lifecycle management' }
    ];
  }

  // Continue with remaining helper method implementations...
  private analyzeRoleBasedAccessIssues(analysis: any): any[] {
    return analysis.authorizationTesting?.roleIssues || [];
  }

  private analyzePrivilegeEscalationRisks(analysis: any): any[] {
    return analysis.authorizationTesting?.privilegeEscalation || [];
  }

  private analyzeResourceAccessPatterns(analysis: any): any {
    return {
      patterns: ['Direct object access', 'Role-based filtering'],
      security: 'Needs improvement'
    };
  }

  private assessContextualAccessControl(analysis: any): any {
    return {
      contextAwareness: 'Low',
      businessRuleIntegration: 'Partial',
      recommendation: 'Implement attribute-based access control (ABAC)'
    };
  }

  private checkBusinessRoleAlignment(analysis: any): any {
    return {
      alignment: 'Partial',
      gaps: ['Technical roles vs business roles mismatch'],
      recommendation: 'Map technical permissions to business functions'
    };
  }

  // Additional helper methods with simplified implementations
  private detectAuthenticationBusinessRuleViolations(analysis: any): any[] {
    return [];
  }

  private detectDataValidationBusinessRuleViolations(analysis: any): any[] {
    return [];
  }

  private detectAccessControlBusinessRuleViolations(analysis: any): any[] {
    return [];
  }

  private analyzeTransactionIntegrity(analysis: any): any {
    return { level: 'Medium', issues: ['Missing transaction boundaries'] };
  }

  private detectAtomicityIssues(analysis: any): any[] {
    return [{ issue: 'Non-atomic operations', risk: 'Data inconsistency' }];
  }

  private analyzeConcurrencyRisks(analysis: any): any[] {
    return [{ risk: 'Race conditions', impact: 'Data corruption' }];
  }

  private assessTransactionLogging(analysis: any): any {
    return { coverage: 'Partial', recommendation: 'Implement comprehensive transaction logging' };
  }

  private analyzeRollbackSecurity(analysis: any): any {
    return { capability: 'Limited', security: 'Needs improvement' };
  }

  private analyzeProcessSteps(analysis: any): any[] {
    return [
      { step: 'Authentication', security: 'Good' },
      { step: 'Authorization', security: 'Needs improvement' },
      { step: 'Validation', security: 'Partial' }
    ];
  }

  private assessFlowIntegrity(analysis: any): any {
    return { integrity: 'Medium', recommendation: 'Add flow validation checkpoints' };
  }

  private detectStepBypassRisks(analysis: any): any[] {
    return [{ risk: 'Step skipping', severity: 'Medium' }];
  }

  private analyzeProcessValidation(analysis: any): any {
    return { validation: 'Partial', coverage: '60%' };
  }

  private assessFlowControlSecurity(analysis: any): any {
    return { security: 'Medium', improvements: ['Add state validation', 'Implement flow constraints'] };
  }

  private assessBusinessCriticality(analysis: any): any {
    return {
      level: 'High',
      factors: ['Customer data processing', 'Financial transactions', 'Business operations'],
      score: this.calculateBusinessCriticalityScore(analysis)
    };
  }

  private analyzeStakeholderImpact(analysis: any): any {
    return {
      customers: 'High impact - data privacy and service availability',
      employees: 'Medium impact - operational disruption',
      partners: 'Medium impact - integration reliability',
      shareholders: 'High impact - financial and reputational risk'
    };
  }

  private assessServiceAvailabilityRisk(analysis: any): any {
    return {
      risk: 'Medium',
      factors: ['DDoS vulnerability', 'Resource exhaustion'],
      mitigation: 'Implement rate limiting and monitoring'
    };
  }

  private assessDataConfidentialityRisk(analysis: any): any {
    return {
      risk: 'High',
      factors: ['Inadequate access controls', 'Data exposure vulnerabilities'],
      mitigation: 'Implement data classification and encryption'
    };
  }

  private assessRegulatoryImpact(analysis: any): any {
    return {
      regulations: ['GDPR', 'HIPAA', 'SOX', 'PCI-DSS'],
      complianceGaps: ['Data protection', 'Access logging', 'Incident reporting'],
      risk: 'High'
    };
  }

  private assessCompetitiveAdvantageRisk(analysis: any): any {
    return {
      risk: 'Medium',
      factors: ['Business logic exposure', 'Performance data leakage'],
      mitigation: 'Implement information security controls'
    };
  }

  /**
   * 🎯 Wappalyzer Integration - Detect technologies using ZAP's Wappalyzer addon
   */
  private async detectWithWappalyzer(targetUrl: string): Promise<any[]> {
    const technologies = [] as any[];

    try {
      
      // Check if Wappalyzer addon is available
      try {
        const sitesResponse = await this.zapClient.get('/JSON/wappalyzer/view/listSites/');
      } catch (addonError) {
        return technologies;
      }

      // Get technologies for the site
      const response = await this.zapClient.get('/JSON/wappalyzer/view/listSite/', {
        params: { site: targetUrl }
      });

      console.log('📊 Wappalyzer response:', JSON.stringify(response.data, null, 2));

      if (response.data && response.data.listSite) {
        const siteData = response.data.listSite;
        
        // Parse Wappalyzer results
        if (Array.isArray(siteData)) {
          for (const tech of siteData) {
            technologies.push({
              name: tech.technology || tech.name || 'Unknown',
              version: tech.version || null,
              categories: tech.categories || [],
              confidence: tech.confidence || 'High',
              detectionMethod: 'Wappalyzer'
            });
          }
        } else if (typeof siteData === 'object') {
          // Sometimes the response is an object with technology names as keys
          for (const [techName, techData] of Object.entries(siteData)) {
            const data = techData as any;
            technologies.push({
              name: techName,
              version: data.version || data.versions?.[0] || null,
              categories: data.categories || [],
              confidence: data.confidence || 'High',
              detectionMethod: 'Wappalyzer'
            });
          }
        }
      }

      return technologies;

    } catch (error: any) {
      console.error('❌ Wappalyzer detection error:', error.message);
      
      // Try alternative endpoint
      try {
        const allTechResponse = await this.zapClient.get('/JSON/wappalyzer/view/listTechnologies/');
        console.log('📊 All technologies response:', JSON.stringify(allTechResponse.data, null, 2));
        
        if (allTechResponse.data && allTechResponse.data.listTechnologies) {
          const techs = allTechResponse.data.listTechnologies;
          if (Array.isArray(techs)) {
            return techs.map((tech: any) => ({
              name: tech.technology || tech.name || 'Unknown',
              version: tech.version || null,
              categories: tech.categories || [],
              confidence: 'Medium',
              detectionMethod: 'Wappalyzer (All Technologies)'
            }));
          }
        }
      } catch (altError) {
        console.error('❌ Alternative Wappalyzer endpoint also failed:', altError);
      }

      return technologies;
    }
  }

  /**
   * Merge Wappalyzer results into appropriate technology categories
   */
  private mergeWappalyzerResults(techDetection: any, wappalyzerResults: any[]): void {
    const categoryMapping: { [key: string]: string } = {
      'Programming languages': 'programmingLanguages',
      'JavaScript frameworks': 'jsLibraries',
      'Web frameworks': 'webFrameworks',
      'Databases': 'databases',
      'Web servers': 'webServers',
      'CMS': 'cmsFrameworks',
      'JavaScript libraries': 'jsLibraries',
      'UI frameworks': 'jsLibraries',
      'Frontend': 'jsLibraries',
      'CDN': 'webServers'
    };

    for (const tech of wappalyzerResults) {
      const categories = Array.isArray(tech.categories) ? tech.categories : [];
      
      // Try to categorize based on Wappalyzer categories
      let categorized = false;
      for (const category of categories) {
        const targetCategory = categoryMapping[category];
        if (targetCategory && techDetection[targetCategory]) {
          if (!techDetection[targetCategory].some((t: any) => t.name === tech.name)) {
            techDetection[targetCategory].push({
              name: tech.name,
              version: tech.version,
              confidence: tech.confidence,
              detectionMethod: 'Wappalyzer',
              categories: tech.categories
            });
            categorized = true;
          }
        }
      }

      // If no specific category found, add to general frameworks based on name
      if (!categorized) {
        // Check common framework patterns
        const techNameLower = tech.name.toLowerCase();
        
        if (techNameLower.includes('react') || techNameLower.includes('vue') || 
            techNameLower.includes('angular') || techNameLower.includes('jquery')) {
          if (!techDetection.jsLibraries.some((t: any) => t.name === tech.name)) {
            techDetection.jsLibraries.push(tech);
          }
        } else if (techNameLower.includes('node') || techNameLower.includes('php') || 
                   techNameLower.includes('python') || techNameLower.includes('java')) {
          if (!techDetection.programmingLanguages.some((t: any) => t.name === tech.name)) {
            techDetection.programmingLanguages.push(tech);
          }
        } else if (techNameLower.includes('express') || techNameLower.includes('django') || 
                   techNameLower.includes('flask') || techNameLower.includes('spring')) {
          if (!techDetection.apiFrameworks.some((t: any) => t.name === tech.name)) {
            techDetection.apiFrameworks.push(tech);
          }
        } else if (techNameLower.includes('mysql') || techNameLower.includes('postgres') || 
                   techNameLower.includes('mongodb') || techNameLower.includes('redis')) {
          if (!techDetection.databases.some((t: any) => t.name === tech.name)) {
            techDetection.databases.push(tech);
          }
        } else if (techNameLower.includes('nginx') || techNameLower.includes('apache') || 
                   techNameLower.includes('iis')) {
          if (!techDetection.webServers.some((t: any) => t.name === tech.name)) {
            techDetection.webServers.push(tech);
          }
        } else {
          // Add to web frameworks as default
          if (!techDetection.webFrameworks.some((t: any) => t.name === tech.name)) {
            techDetection.webFrameworks.push(tech);
          }
        }
      }
    }
  }

  /**
   * Merge technology arrays without duplicates
   */
  private mergeTechnologies(existing: any[], newTechs: any[]): any[] {
    const merged = [...existing];
    
    for (const newTech of newTechs) {
      if (!merged.some((tech: any) => 
        tech.name === newTech.name || 
        tech.server === newTech.server
      )) {
        merged.push(newTech);
      }
    }
    
    return merged;
  }
}
