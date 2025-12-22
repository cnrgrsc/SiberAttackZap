import { Router, Request, Response } from 'express';
import { ZapProxyService } from '../services/zapProxy.service';
import { ManualScanService } from '../services/manualScan.service';

const router = Router();
const zapService = new ZapProxyService();
const manualScanService = new ManualScanService();

// =============================================================================
// MANUAL PENETRATION TESTING ENDPOINTS
// =============================================================================

// GET /api/manual-scan/tools - Get available manual testing tools
router.get('/tools', async (req: Request, res: Response) => {
  try {
    const tools = await manualScanService.getAvailableTools();
    res.json({
      success: true,
      data: tools
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to get manual tools',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// POST /api/manual-scan/spider/custom - Custom spider configuration
router.post('/spider/custom', async (req: Request, res: Response) => {
  try {
    const { targetUrl, options } = req.body;
    
    if (!targetUrl) {
      return res.status(400).json({
        success: false,
        error: { message: 'Target URL is required' }
      });
    }

    const result = await manualScanService.runCustomSpider(targetUrl, options);
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to run custom spider',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// POST /api/manual-scan/attacks/sql-injection - Manual SQL Injection Testing
router.post('/attacks/sql-injection', async (req: Request, res: Response) => {
  try {
    const { targetUrl, parameters, payloads, options } = req.body;
    
    if (!targetUrl) {
      return res.status(400).json({
        success: false,
        error: { message: 'Target URL is required' }
      });
    }

    const result = await manualScanService.runSqlInjectionTest(targetUrl, {
      parameters,
      payloads,
      options
    });
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to run SQL injection test',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// POST /api/manual-scan/attacks/xss - Manual XSS Testing
router.post('/attacks/xss', async (req: Request, res: Response) => {
  try {
    const { targetUrl, parameters, payloads, options } = req.body;
    
    if (!targetUrl) {
      return res.status(400).json({
        success: false,
        error: { message: 'Target URL is required' }
      });
    }

    const result = await manualScanService.runXssTest(targetUrl, {
      parameters,
      payloads,
      options
    });
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to run XSS test',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// POST /api/manual-scan/attacks/directory-traversal - Directory Traversal Testing
router.post('/attacks/directory-traversal', async (req: Request, res: Response) => {
  try {
    const { targetUrl, parameters, payloads, options } = req.body;
    
    const result = await manualScanService.runDirectoryTraversalTest(targetUrl, {
      parameters,
      payloads,
      options
    });
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to run directory traversal test',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// POST /api/manual-scan/attacks/command-injection - Command Injection Testing
router.post('/attacks/command-injection', async (req: Request, res: Response) => {
  try {
    const { targetUrl, parameters, payloads, options } = req.body;
    
    const result = await manualScanService.runCommandInjectionTest(targetUrl, {
      parameters,
      payloads,
      options
    });
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to run command injection test',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// POST /api/manual-scan/attacks/csrf - CSRF Testing
router.post('/attacks/csrf', async (req: Request, res: Response) => {
  try {
    const { targetUrl, options } = req.body;
    
    const result = await manualScanService.runCsrfTest(targetUrl, options);
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to run CSRF test',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// POST /api/manual-scan/attacks/xxe - XXE Testing
router.post('/attacks/xxe', async (req: Request, res: Response) => {
  try {
    const { targetUrl, xmlPayloads, options } = req.body;
    
    const result = await manualScanService.runXxeTest(targetUrl, {
      xmlPayloads,
      options
    });
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to run XXE test',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// POST /api/manual-scan/fuzzing/params - Parameter Fuzzing
router.post('/fuzzing/params', async (req: Request, res: Response) => {
  try {
    const { targetUrl, parameters, wordlists, options } = req.body;
    
    const result = await manualScanService.runParameterFuzzing(targetUrl, {
      parameters,
      wordlists,
      options
    });
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to run parameter fuzzing',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// POST /api/manual-scan/fuzzing/directories - Directory Fuzzing with wordlists
router.post('/fuzzing/directories', async (req: Request, res: Response) => {
  try {
    const { targetUrl, wordlists, options } = req.body;
    
    const result = await manualScanService.runDirectoryFuzzing(targetUrl, {
      wordlists,
      options
    });
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to run directory fuzzing',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// POST /api/manual-scan/kali-tools/nmap - Nmap scanning
router.post('/kali-tools/nmap', async (req: Request, res: Response) => {
  try {
    const { target, options } = req.body;
    
    const result = await manualScanService.runNmapScan(target, options);
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to run Nmap scan',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// POST /api/manual-scan/kali-tools/nikto - Nikto web vulnerability scanner
router.post('/kali-tools/nikto', async (req: Request, res: Response) => {
  try {
    const { targetUrl, options } = req.body;
    
    const result = await manualScanService.runNiktoScan(targetUrl, options);
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to run Nikto scan',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// POST /api/manual-scan/kali-tools/sqlmap - SQLMap for SQL injection
router.post('/kali-tools/sqlmap', async (req: Request, res: Response) => {
  try {
    const { targetUrl, options } = req.body;
    
    const result = await manualScanService.runSqlmapScan(targetUrl, options);
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to run SQLMap scan',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// POST /api/manual-scan/kali-tools/gobuster - Directory/file brute forcing
router.post('/kali-tools/gobuster', async (req: Request, res: Response) => {
  try {
    const { targetUrl, wordlist, options } = req.body;
    
    const result = await manualScanService.runGobusterScan(targetUrl, wordlist, options);
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to run Gobuster scan',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// GET /api/manual-scan/payloads/:type - Get predefined payloads
router.get('/payloads/:type', async (req: Request, res: Response) => {
  try {
    const { type } = req.params;
    const payloads = await manualScanService.getPayloads(type);
    
    res.json({
      success: true,
      data: payloads
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to get payloads',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// GET /api/manual-scan/wordlists - Get available wordlists
router.get('/wordlists', async (req: Request, res: Response) => {
  try {
    const wordlists = await manualScanService.getWordlists();
    
    res.json({
      success: true,
      data: wordlists
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to get wordlists',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// POST /api/manual-scan/custom-request - Send custom HTTP request
router.post('/custom-request', async (req: Request, res: Response) => {
  try {
    const { method, url, headers, body, options } = req.body;
    
    const result = await manualScanService.sendCustomRequest({
      method,
      url,
      headers,
      body,
      options
    });
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to send custom request',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// GET /api/manual-scan/intercept/enable - Enable request interception
router.post('/intercept/enable', async (req: Request, res: Response) => {
  try {
    const result = await manualScanService.enableInterception();
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to enable interception',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

// GET /api/manual-scan/intercept/disable - Disable request interception
router.post('/intercept/disable', async (req: Request, res: Response) => {
  try {
    const result = await manualScanService.disableInterception();
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        message: 'Failed to disable interception',
        details: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

export default router;
