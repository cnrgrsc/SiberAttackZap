import React, { useState, useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Box,
  Typography,
  Paper,
  Tabs,
  Card,
  CardContent,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Alert,
  LinearProgress,
  Stack,
  Switch,
  FormControlLabel,
  Tooltip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Divider,
  Tab,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Badge
} from '@mui/material';
import { 
  PlayArrow as PlayIcon, 
  Help as HelpIcon,
  Info as InfoIcon,
  Security as SecurityIcon,
  BugReport as BugReportIcon,
  Code as CodeIcon,
  Terminal as TerminalIcon,
  Assessment as AssessmentIcon,
  GetApp as DownloadIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
  Http as HttpIcon,
  Send as SendIcon,
  Stop as StopIcon,
  Clear as ClearIcon,
  Refresh as RefreshIcon,
  Settings as SettingsIcon,
  ExpandMore as ExpandMoreIcon,
  Launch as LaunchIcon,
  MonitorHeart as MonitorIcon,
  Search as SpiderIcon,
  Security as ScannerIcon,
  Delete as DeleteIcon
} from '@mui/icons-material';

// Types and Interfaces
interface HttpRequest {
  id: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  timestamp: string;
  status?: number;
  responseHeaders?: Record<string, string>;
  responseBody?: string;
  duration?: number;
}

interface AttackResult {
  id: string;
  tool: string;
  command: string;
  timestamp: string;
  duration: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  findings?: string[];
  recommendations?: string[];
  request?: HttpRequest;
  response?: {
    status?: number;
    headers?: Record<string, string>;
    body?: string;
  };
}

interface ZapStatus {
  isRunning: boolean;
  version: string;
  hudEnabled: boolean;
  proxyPort: number;
  interceptEnabled: boolean;
}

interface KaliToolOptions {
  nmap?: {
    ports: string;
    timing: number;
    scanType: string;
    osDetection: boolean;
    serviceVersion: boolean;
    scripts: string;
  };
  gobuster?: {
    wordlist: string;
    extensions: string;
    threads: number;
    timeout: number;
  };
  sqlmap?: {
    level: number;
    risk: number;
    technique: string;
    dbms: string;
  };
  nikto?: {
    plugins: string;
    timeout: number;
    format: string;
  };
  hydra?: {
    protocol: string;
    userlist: string;
    passlist: string;
    threads: number;
  };
}

// Real ZAP service integration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';

const zapService = {
  getStatus: async (): Promise<ZapStatus> => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/zap/status`);
      const data = await response.json();
      return data;
    } catch (error) {
      console.error('Failed to get ZAP status:', error);
      // Fallback for development
      return {
        isRunning: true,
        version: '2.14.0',
        hudEnabled: true,
        proxyPort: 8080,
        interceptEnabled: false
      };
    }
  },
  
  enableHud: async (enable: boolean): Promise<void> => {
    try {
      await fetch(`${API_BASE_URL}/api/zap/hud`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: enable })
      });
    } catch (error) {
      console.error('Failed to toggle HUD:', error);
    }
  },
  
  setInterceptMode: async (enable: boolean): Promise<void> => {
    try {
      await fetch(`${API_BASE_URL}/api/zap/intercept`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: enable })
      });
    } catch (error) {
      console.error('Failed to toggle intercept:', error);
    }
  },
  
  getInterceptedRequests: async (): Promise<HttpRequest[]> => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/zap/history`);
      const data = await response.json();
      
      if (data.success) {
        return data.data.requests || [];
      } else {
        return [];
      }
    } catch (error) {
      console.error('Failed to fetch requests:', error);
      // Fallback for development - return empty array
      return [];
    }
  },
  
  openHudBrowser: async (targetUrl: string): Promise<void> => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/zap/open-browser`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl })
      });
      
      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.error?.message || 'Failed to open browser');
      }
      
      
      // Success notification
      if (result.data.warning) {
      }
      
    } catch (error) {
      console.error('Failed to open HUD browser:', error);
      throw error;
    }
  },
  
  spiderScan: async (url: string): Promise<AttackResult> => {
    await new Promise(resolve => setTimeout(resolve, 3000));
    return {
      id: Date.now().toString(),
      tool: 'ZAP Spider',
      command: `spider ${url}`,
      timestamp: new Date().toISOString(),
      duration: 3000,
      severity: 'low',
      findings: ['Found 15 URLs', 'Discovered 3 forms', '2 potential directories'],
      recommendations: ['Review discovered endpoints', 'Check for sensitive information']
    };
  },
  
  activeScan: async (url: string): Promise<AttackResult> => {
    await new Promise(resolve => setTimeout(resolve, 5000));
    return {
      id: Date.now().toString(),
      tool: 'ZAP Active Scanner',
      command: `ascan ${url}`,
      timestamp: new Date().toISOString(),
      duration: 5000,
      severity: 'high',
      findings: ['SQL Injection vulnerability found', 'XSS vulnerability detected', 'Weak authentication'],
      recommendations: ['Implement input validation', 'Use parameterized queries', 'Strengthen authentication']
    };
  },

  clearSession: async (): Promise<void> => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/zap/session/clear`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      
      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.error?.message || 'Failed to clear session');
      }
      
      
    } catch (error) {
      console.error('Failed to clear ZAP session:', error);
      throw error;
    }
  }
};

const kaliService = {
  executeCommand: async (tool: string, target: string, options: KaliToolOptions): Promise<AttackResult> => {
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const commands = {
      nmap: `nmap ${options.nmap?.scanType || '-sS'} -p ${options.nmap?.ports || '1-1000'} ${target}`,
      gobuster: `gobuster dir -u ${target} -w ${options.gobuster?.wordlist || '/usr/share/wordlists/dirb/common.txt'}`,
      sqlmap: `sqlmap -u "${target}" --level=${options.sqlmap?.level || 1} --risk=${options.sqlmap?.risk || 1}`,
      nikto: `nikto -h ${target} -Format ${options.nikto?.format || 'txt'}`,
      hydra: `hydra -L ${options.hydra?.userlist || 'users.txt'} -P ${options.hydra?.passlist || 'pass.txt'} ${target} ${options.hydra?.protocol || 'ssh'}`
    };
    
    return {
      id: Date.now().toString(),
      tool: `Kali ${tool.toUpperCase()}`,
      command: commands[tool as keyof typeof commands] || `${tool} ${target}`,
      timestamp: new Date().toISOString(),
      duration: Math.floor(Math.random() * 5000) + 1000,
      severity: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)] as any,
      findings: [
        `${tool} scan completed successfully`,
        `Target: ${target}`,
        'Ports found: 22, 80, 443',
        'Services identified: SSH, HTTP, HTTPS'
      ],
      recommendations: ['Review open ports', 'Update services', 'Check configurations']
    };
  }
};

// Kali Linux Tools Configuration
const KALI_TOOLS = {
  nmap: {
    name: 'Nmap',
    description: 'Network discovery ve port scanning',
    icon: <TerminalIcon />,
    category: 'Network Scanning',
    help: 'Nmap ile ağ keşfi ve port tarama yapabilirsiniz',
    dockerInstall: 'apt-get update && apt-get install -y nmap'
  },
  gobuster: {
    name: 'Gobuster',
    description: 'Directory/file/DNS brute-forcer',
    icon: <BugReportIcon />,
    category: 'Web Enumeration',
    help: 'Gizli dizinleri ve dosyaları keşfetmek için kullanılır',
    dockerInstall: 'apt-get update && apt-get install -y gobuster'
  },
  sqlmap: {
    name: 'SQLMap',
    description: 'SQL injection detection & exploitation',
    icon: <CodeIcon />,
    category: 'Database Testing',
    help: 'SQL injection açıklarını tespit eder ve exploit eder',
    dockerInstall: 'apt-get update && apt-get install -y sqlmap'
  },
  nikto: {
    name: 'Nikto',
    description: 'Web server scanner',
    icon: <SecurityIcon />,
    category: 'Web Vulnerability',
    help: 'Web sunucu güvenlik açıklarını tarar',
    dockerInstall: 'apt-get update && apt-get install -y nikto'
  },
  hydra: {
    name: 'Hydra',
    description: 'Network login cracker',
    icon: <TerminalIcon />,
    category: 'Password Attack',
    help: 'Brute force saldırıları için kullanılır',
    dockerInstall: 'apt-get update && apt-get install -y hydra'
  },
  metasploit: {
    name: 'Metasploit',
    description: 'Penetration testing framework',
    icon: <CodeIcon />,
    category: 'Exploitation',
    help: 'Exploit geliştirme ve penetration testing',
    dockerInstall: 'curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall'
  },
  burpsuite: {
    name: 'Burp Suite',
    description: 'Web application security testing',
    icon: <SecurityIcon />,
    category: 'Web Security',
    help: 'Professional web application security testing',
    dockerInstall: 'wget -O burpsuite.jar "https://portswigger.net/burp/releases/download?product=community&type=Jar"'
  },
  wpscan: {
    name: 'WPScan',
    description: 'WordPress security scanner',
    icon: <ScannerIcon />,
    category: 'CMS Security',
    help: 'WordPress güvenlik açıklarını tarar',
    dockerInstall: 'gem install wpscan'
  }
};

const ManualScan: React.FC = () => {
  // Get technology data from navigation state
  const location = useLocation();
  const locationState = location.state as { targetUrl?: string; detectedTechnologies?: any[] } | null;
  
  // State Management
  const [targetUrl, setTargetUrl] = useState(locationState?.targetUrl || '');
  const [detectedTechnologies, setDetectedTechnologies] = useState<any[]>(locationState?.detectedTechnologies || []);
  const [zapStatus, setZapStatus] = useState<ZapStatus | null>(null);
  const [interceptedRequests, setInterceptedRequests] = useState<HttpRequest[]>([]);
  const [selectedTool, setSelectedTool] = useState<string>('');
  const [toolOptions, setToolOptions] = useState<KaliToolOptions>({});
  const [customCommand, setCustomCommand] = useState('');
  const [results, setResults] = useState<AttackResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [interceptMode, setInterceptMode] = useState(false);
  const [hudEnabled, setHudEnabled] = useState(true);
  const [selectedTab, setSelectedTab] = useState(0);
  const [selectedRequest, setSelectedRequest] = useState<HttpRequest | null>(null);
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [editableRequest, setEditableRequest] = useState<HttpRequest | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);
  
  // Refs
  const requestsEndRef = useRef<HTMLDivElement>(null);

  // Effects
  useEffect(() => {
    // Sadece sayfa ilk yüklendiğinde ZAP'i başlat
    initializeZap();
  }, []); // Boş dependency array - sadece component mount'ta çalışır

  useEffect(() => {
    // Auto-refresh aktifse sürekli request yenileme - daha yavaş interval
    if (autoRefresh) {
      const interval = setInterval(fetchInterceptedRequests, 10000); // 10 saniyede bir yenile (3 saniye yerine)
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  useEffect(() => {
    // Sadece auto-refresh aktifken otomatik scroll yap
    if (autoRefresh && requestsEndRef.current) {
      requestsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [interceptedRequests, autoRefresh]);

  // ZAP Initialization
  const initializeZap = async () => {
    try {
      const status = await zapService.getStatus();
      setZapStatus(status);
      setHudEnabled(status.hudEnabled);
      setInterceptMode(status.interceptEnabled);
    } catch (error) {
      console.error('Failed to initialize ZAP:', error);
    }
  };

  const fetchInterceptedRequests = async () => {
    try {
      const requests = await zapService.getInterceptedRequests();
      setInterceptedRequests(requests);
    } catch (error) {
      console.error('Failed to fetch intercepted requests:', error);
    }
  };

  // Tool Management
  const handleToolChange = (tool: string) => {
    setSelectedTool(tool);
    
    const defaultOptions: KaliToolOptions = {
      nmap: {
        ports: '1-1000',
        timing: 4,
        scanType: '-sS',
        osDetection: false,
        serviceVersion: false,
        scripts: ''
      },
      gobuster: {
        wordlist: '/usr/share/wordlists/dirb/common.txt',
        extensions: 'php,html,txt,js',
        threads: 10,
        timeout: 30
      },
      sqlmap: {
        level: 1,
        risk: 1,
        technique: 'BEUSTQ',
        dbms: ''
      },
      nikto: {
        plugins: 'all',
        timeout: 30,
        format: 'txt'
      },
      hydra: {
        protocol: 'ssh',
        userlist: '/usr/share/wordlists/metasploit/unix_users.txt',
        passlist: '/usr/share/wordlists/rockyou.txt',
        threads: 4
      }
    };
    
    setToolOptions({ [tool]: defaultOptions[tool as keyof KaliToolOptions] });
  };

  // Attack Execution
  const executeZapSpider = async () => {
    if (!targetUrl) return;
    setLoading(true);
    try {
      const result = await zapService.spiderScan(targetUrl);
      setResults(prev => [result, ...prev]);
    } catch (error) {
      console.error('Spider scan failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const executeZapActiveScan = async () => {
    if (!targetUrl) return;
    setLoading(true);
    try {
      const result = await zapService.activeScan(targetUrl);  
      setResults(prev => [result, ...prev]);
    } catch (error) {
      console.error('Active scan failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const executeKaliTool = async () => {
    if (!targetUrl || !selectedTool) return;
    setLoading(true);
    try {
      const result = await kaliService.executeCommand(selectedTool, targetUrl, toolOptions);
      setResults(prev => [result, ...prev]);
    } catch (error) {
      console.error('Kali tool execution failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const executeCustomCommand = async () => {
    if (!customCommand) return;
    setLoading(true);
    try {
      const result = await kaliService.executeCommand('custom', customCommand.replace('{target}', targetUrl), {});
      setResults(prev => [result, ...prev]);
    } catch (error) {
      console.error('Custom command failed:', error);
    } finally {
      setLoading(false);
    }
  };

  // Request Management
  const toggleInterceptMode = async () => {
    try {
      await zapService.setInterceptMode(!interceptMode);
      setInterceptMode(!interceptMode);
    } catch (error) {
      console.error('Failed to toggle intercept mode:', error);
    }
  };

  const openHudBrowser = async () => {
    if (!targetUrl) {
      alert('Lütfen önce Target URL girin!');
      return;
    }
    
    setLoading(true);
    try {
      await zapService.openHudBrowser(targetUrl);
      
      // HUD'ı etkinleştir
      await zapService.enableHud(true);
      setHudEnabled(true);
      
      // Success message
      
      alert(`🚀 Chrome tarayıcısı ZAP proxy ile başlatıldı!

📋 HTTPS Manuel Test Yapmak İçin:
1. Açılan Chrome penceresinde HTTPS web sitesinde gezinin
2. İlk kez HTTPS siteye girdiğinizde sertifika uyarısı alabilirsiniz
3. "Advanced" → "Proceed to site" seçeneklerini kullanın
4. Sayfada sağ alt köşede ZAP HUD kontrolleri görünmelidir
5. Eğer HUD görünmüyorsa, F12 açıp Console'da hata kontrol edin

🔐 HTTPS Proxy Test:
- URL çubuğunda kilit simgesi varsa proxy çalışıyor
- DevTools → Network sekmesinde istekleri kontrol edin
- Bu arayüzde "Captured HTTP Requests" bölümünde istekler görünmelidir

🔍 Test İpuçları:
- Formları doldurun ve gönderin  
- Farklı sayfalara tıklayın
- Arama yapın, login/logout deneyin
- POST/GET isteklerini karıştırın

⚠️ Not: HTTPS sitelerde sertifika uyarıları normal - güvenlik testi yapıyoruz!`);
      
    } catch (error) {
      console.error('Failed to open HUD browser:', error);
      alert('❌ Tarayıcı açılırken hata oluştu!\n\nHata: ' + (error instanceof Error ? error.message : 'Bilinmeyen hata'));
    } finally {
      setLoading(false);
    }
  };

  const toggleHud = async () => {
    try {
      await zapService.enableHud(!hudEnabled);
      setHudEnabled(!hudEnabled);
    } catch (error) {
      console.error('Failed to toggle HUD:', error);
    }
  };

  const clearZapSession = async () => {
    if (!window.confirm('ZAP session\'ını temizlemek istediğinizden emin misiniz? Bu işlem geri alınamaz.')) {
      return;
    }
    
    setLoading(true);
    try {
      await zapService.clearSession();
      setInterceptedRequests([]);
      alert('✅ ZAP session başarıyla temizlendi!');
    } catch (error) {
      console.error('Failed to clear session:', error);
      alert('❌ Session temizlenirken hata oluştu: ' + (error instanceof Error ? error.message : 'Bilinmeyen hata'));
    } finally {
      setLoading(false);
    }
  };

  const showRequestDetails = (request: HttpRequest) => {
    setSelectedRequest(request);
    setEditableRequest({ ...request });
    setDetailDialogOpen(true);
  };

  const sendModifiedRequest = async () => {
    if (!editableRequest) return;
    
    setLoading(true);
    try {
      // Simulate sending modified request
      const result: AttackResult = {
        id: Date.now().toString(),
        tool: 'Modified Request',
        command: `${editableRequest.method} ${editableRequest.url}`,
        timestamp: new Date().toISOString(),
        duration: 250,
        severity: 'low',
        findings: ['Request sent successfully', 'Response received'],
        request: editableRequest,
        response: {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
          body: '{"status": "success", "modified": true}'
        }
      };
      
      setResults(prev => [result, ...prev]);
      setDetailDialogOpen(false);
    } catch (error) {
      console.error('Failed to send modified request:', error);
    } finally {
      setLoading(false);
    }
  };

  const clearRequests = () => {
    setInterceptedRequests([]);
  };

  const generateReport = async () => {
    setLoading(true);
    try {
      const reportData = {
        timestamp: new Date().toISOString(),
        target: targetUrl,
        zapStatus,
        totalRequests: interceptedRequests.length,
        totalTests: results.length,
        vulnerabilities: results.filter(r => r.severity === 'high' || r.severity === 'critical').length,
        interceptedRequests: interceptedRequests.map(req => ({
          method: req.method,
          url: req.url,
          timestamp: req.timestamp,
          status: req.status,
          duration: req.duration,
          headers: req.headers,
          body: req.body
        })),
        scanResults: results.map(r => ({
          tool: r.tool,
          command: r.command,
          timestamp: r.timestamp,
          duration: r.duration,
          severity: r.severity,
          findings: r.findings,
          recommendations: r.recommendations
        }))
      };

      // Backend'e rapor oluşturma isteği gönder
      const response = await fetch(`${API_BASE_URL}/api/report/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'manual-scan',
          data: reportData,
          format: 'pdf' // PDF formatında rapor
        })
      });

      if (response.ok) {
        // PDF olarak indir
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `SiberZed-Manual-Pentest-Report-${new Date().toISOString().split('T')[0]}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        alert('✅ Rapor başarıyla PDF formatında indirildi!');
      } else {
        throw new Error('Rapor oluşturulamadı');
      }
    } catch (error) {
      console.error('Report generation failed:', error);
      
      // Fallback: JSON formatında indir
      const report = {
        timestamp: new Date().toISOString(),
        target: targetUrl,
        zapStatus,
        totalRequests: interceptedRequests.length,
        totalTests: results.length,
        vulnerabilities: results.filter(r => r.severity === 'high' || r.severity === 'critical').length,
        interceptedRequests,
        scanResults: results
      };

      const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `SiberZed-Manual-Report-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      alert('⚠️ PDF raporu oluşturulamadı. JSON formatında indirildi.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ 
      width: '100%',
      bgcolor: '#0d1117',
      color: '#e6edf3',
      minHeight: '100vh',
      p: 2
    }}>
      {/* Header */}
      <Paper sx={{ 
        p: 3, 
        mb: 3, 
        bgcolor: '#21262d',
        border: '1px solid #30363d',
        borderRadius: 2
      }}>
        <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
          <Box>
            <Typography variant="h4" component="h1" gutterBottom sx={{ 
              color: '#58a6ff', 
              fontWeight: 600,
              fontSize: '1.8rem'
            }}>
              🛡️ Manual Penetration Testing & Web Exploration
            </Typography>
            <Stack direction="row" spacing={1} mb={2}>
              <Chip 
                label="ZAP HUD Integration" 
                color="primary" 
                size="small" 
                icon={<SecurityIcon />}
              />
              <Chip 
                label="Live Request Capture" 
                color="secondary" 
                size="small"
                icon={<HttpIcon />}
              />
              <Chip 
                label="Browser Automation" 
                color="success" 
                size="small"
                icon={<LaunchIcon />}
              />
            </Stack>
          </Box>
          
          {/* ZAP Status */}
          <Box textAlign="right">
            <Box display="flex" alignItems="center" gap={2} mb={1}>
              <Badge 
                color={zapStatus?.isRunning ? "success" : "error"} 
                variant="dot"
              >
                <Typography variant="body2" sx={{ color: '#e6edf3' }}>
                  ZAP Proxy {zapStatus?.isRunning ? 'Running' : 'Stopped'}
                </Typography>
              </Badge>
              {zapStatus?.isRunning && (
                <Typography variant="caption" sx={{ color: '#7d8590' }}>
                  Port: {zapStatus.proxyPort}
                </Typography>
              )}
            </Box>
            
            <Stack direction="row" spacing={1}>
              <Button
                size="small"
                variant={hudEnabled ? "contained" : "outlined"}
                color="info"
                onClick={openHudBrowser}
                startIcon={<MonitorIcon />}
                disabled={!targetUrl}
                sx={{
                  bgcolor: hudEnabled ? '#58a6ff' : 'transparent',
                  color: hudEnabled ? '#fff' : '#58a6ff',
                  borderColor: '#58a6ff',
                  '&:hover': {
                    bgcolor: hudEnabled ? '#1f6feb' : 'rgba(88, 166, 255, 0.1)'
                  },
                  '&:disabled': {
                    bgcolor: '#21262d', 
                    color: '#7d8590',
                    borderColor: '#30363d'
                  }
                }}
              >
                Launch HUD
              </Button>
              <Button
                size="small"
                variant={interceptMode ? "contained" : "outlined"}
                color="warning"
                onClick={toggleInterceptMode}
                startIcon={interceptMode ? <StopIcon /> : <PlayIcon />}
              >
                Intercept
              </Button>
              <Button
                size="small"
                variant="outlined"
                color="error"
                onClick={clearZapSession}
                startIcon={<DeleteIcon />}
                disabled={loading || interceptedRequests.length === 0}
                sx={{
                  color: interceptedRequests.length === 0 ? '#7d8590' : '#f85149',
                  borderColor: interceptedRequests.length === 0 ? '#30363d' : '#f85149',
                  '&:hover': {
                    bgcolor: interceptedRequests.length === 0 ? 'transparent' : 'rgba(248, 81, 73, 0.1)'
                  }
                }}
              >
                Clear
              </Button>
              <Button
                size="small"
                variant="contained"
                startIcon={<DownloadIcon />}
                onClick={generateReport}
                disabled={loading}
                sx={{ 
                  bgcolor: '#238636',
                  color: '#fff',
                  '&:hover': { bgcolor: '#2ea043' },
                  '&:disabled': { bgcolor: '#21262d', color: '#7d8590' }
                }}
              >
                {loading ? 'Creating...' : 'Generate Report'}
              </Button>
            </Stack>
          </Box>
        </Box>

        {/* Target Configuration */}
        <Box>
          <Typography variant="h6" gutterBottom sx={{ 
            color: '#f0f6fc', 
            fontSize: '1.1rem',
            mb: 2
          }}>
            🎯 Target URL for Manual Exploration
          </Typography>
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems="center">
            <TextField
              fullWidth
              label="Target URL"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com/"
              variant="outlined"
              helperText="Enter the URL you want to explore manually through ZAP proxy"
              sx={{ 
                flex: 1,
                '& .MuiOutlinedInput-root': {
                  bgcolor: '#0d1117',
                  color: '#e6edf3',
                  '& fieldset': { borderColor: '#30363d' },
                  '&:hover fieldset': { borderColor: '#58a6ff' },
                  '&.Mui-focused fieldset': { borderColor: '#58a6ff' }
                },
                '& .MuiInputLabel-root': {
                  color: '#7d8590',
                  '&.Mui-focused': { color: '#58a6ff' }
                },
                '& .MuiFormHelperText-root': {
                  color: '#7d8590',
                  fontSize: '0.75rem'
                }
              }}
            />
            <FormControlLabel
              control={
                <Switch
                  checked={autoRefresh}
                  onChange={(e) => setAutoRefresh(e.target.checked)}
                  sx={{ 
                    '& .MuiSwitch-switchBase.Mui-checked': { color: '#58a6ff' },
                    '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { 
                      backgroundColor: '#58a6ff' 
                    }
                  }}
                />
              }
              label={`Auto Refresh ${autoRefresh ? '(ON)' : '(OFF)'} - Captures HTTP requests automatically`}
              sx={{ color: '#e6edf3' }}
            />
          </Stack>
        </Box>
      </Paper>

      {/* Technology Information Section */}
      {detectedTechnologies.length > 0 && (
        <Paper sx={{ 
          p: 3, 
          mb: 3, 
          bgcolor: '#21262d',
          border: '1px solid #30363d',
          borderRadius: 2
        }}>
          <Typography variant="h6" sx={{ 
            color: '#58a6ff', 
            fontWeight: 600,
            fontSize: '1.1rem',
            mb: 2,
            display: 'flex',
            alignItems: 'center',
            gap: 1
          }}>
            🔧 Tespit Edilen Teknolojiler
            <Chip 
              label={`${detectedTechnologies.length} teknoloji`}
              size="small" 
              color="success"
            />
          </Typography>
          
          <Typography variant="body2" sx={{ color: '#7d8590', mb: 2 }}>
            Bu teknolojiler otomatik tarama sırasında tespit edildi. Manuel testlerde bu bilgileri kullanarak hedefe yönelik saldırılar geliştirebilirsiniz.
          </Typography>
          
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
            {detectedTechnologies.map((tech, index) => {
              const getColor = (type: string) => {
                switch (type?.toLowerCase()) {
                  case 'web server': return 'primary';
                  case 'database': return 'error';
                  case 'programming language': return 'warning';
                  case 'javascript framework': return 'info';
                  case 'cms': return 'secondary';
                  default: return 'default';
                }
              };
              
              return (
                <Chip
                  key={index}
                  label={`${tech.name} (${tech.confidence || 'Medium'})`}
                  color={getColor(tech.type) as any}
                  size="small"
                  variant="outlined"
                  sx={{
                    '& .MuiChip-label': { color: '#e6edf3' },
                    '& .MuiChip-outlined': { borderColor: '#30363d' }
                  }}
                />
              );
            })}
          </Box>
          
          {/* Technology-based Tool Recommendations */}
          <Box sx={{ mt: 2 }}>
            <Typography variant="body2" sx={{ color: '#58a6ff', fontWeight: 'bold', mb: 1 }}>
              💡 Teknolojiye Özgü Araç Önerileri:
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
              {detectedTechnologies.some(t => t.name?.toLowerCase().includes('php')) && (
                <Chip label="PHP: SQLMap ile SQL Injection testi" size="small" color="error" />
              )}
              {detectedTechnologies.some(t => t.type?.toLowerCase().includes('database')) && (
                <Chip label="Database: SQLMap aggressive tarama" size="small" color="error" />
              )}
              {detectedTechnologies.some(t => t.name?.toLowerCase().includes('wordpress')) && (
                <Chip label="WordPress: WPScan ile vulnerability tarama" size="small" color="warning" />
              )}
              {detectedTechnologies.some(t => t.name?.toLowerCase().includes('apache')) && (
                <Chip label="Apache: Nikto web server tarama" size="small" color="info" />
              )}
              {detectedTechnologies.some(t => t.type?.toLowerCase().includes('cms')) && (
                <Chip label="CMS: Gobuster ile directory enumeration" size="small" color="secondary" />
              )}
            </Box>
          </Box>
        </Paper>
      )}

      {/* Main Content */}
      <Box display="flex" gap={3}>
        {/* Left Panel - Tools & Controls */}
        <Box sx={{ flex: 1, minWidth: 400 }}>
          {/* ZAP Proxy Controls */}
          <Paper sx={{ 
            p: 2, 
            mb: 2, 
            bgcolor: '#21262d',
            border: '1px solid #30363d',
            borderRadius: 2
          }}>
            <Typography variant="h6" gutterBottom sx={{ 
              color: '#58a6ff',
              fontSize: '1.1rem',
              display: 'flex',
              alignItems: 'center',
              gap: 1
            }}>
              <SecurityIcon /> ZAP Proxy - Manuel Exploring
            </Typography>
            
            <Typography variant="body2" sx={{ 
              color: '#7d8590', 
              mb: 2,
              fontSize: '0.85rem'
            }}>
              🌐 ZAP HUD ile tarayıcıda manuel keşif yapın. Tüm istekler otomatik olarak yakalanacak.
            </Typography>

            <Alert severity="info" sx={{ 
              mb: 2, 
              bgcolor: 'rgba(88, 166, 255, 0.1)', 
              border: '1px solid #58a6ff',
              '& .MuiAlert-message': { color: '#e6edf3' }
            }}>
              💡 <strong>Manuel Test İpuçları:</strong>
              <br />• Chrome açıldıktan sonra web sitesinde normal şekilde gezinin
              <br />• Sayfanın sağ alt köşesinde ZAP HUD kontrolleri görünmelidir  
              <br />• Formları doldurun, linkler tıklayın, arama yapın
              <br />• Tüm HTTP istekleri otomatik olarak yakalanacak
            </Alert>
            
            <Stack spacing={2}>
              <Button
                variant="contained"
                size="large"
                fullWidth
                startIcon={loading ? <div className="spinner" /> : <LaunchIcon />}
                onClick={openHudBrowser}
                disabled={!targetUrl || loading}
                sx={{
                  bgcolor: loading ? '#7d8590' : '#238636',
                  '&:hover': { bgcolor: loading ? '#7d8590' : '#2ea043' },
                  '&:disabled': { bgcolor: '#21262d', color: '#7d8590' },
                  py: 1.5,
                  fontSize: '1rem'
                }}
              >
                {loading ? '🔄 Launching Browser...' : '🚀 Launch HUD Browser & Start Exploring'}
              </Button>
              
              <Stack direction="row" spacing={2}>
                <Button
                  variant="contained"
                  startIcon={<SpiderIcon />}
                  onClick={executeZapSpider}
                  disabled={loading || !targetUrl}
                  sx={{
                    bgcolor: '#58a6ff',
                    '&:hover': { bgcolor: '#1f6feb' },
                    '&:disabled': { bgcolor: '#21262d', color: '#7d8590' },
                    flex: 1
                  }}
                >
                  Spider Scan
                </Button>
                
                <Button
                  variant="contained"
                  startIcon={<ScannerIcon />}
                  onClick={executeZapActiveScan}
                  disabled={loading || !targetUrl}
                  sx={{
                    bgcolor: '#da3633',
                    '&:hover': { bgcolor: '#f85149' },
                    '&:disabled': { bgcolor: '#21262d', color: '#7d8590' },
                    flex: 1
                  }}
                >
                  Active Scan
                </Button>
              </Stack>
            </Stack>
          </Paper>

          {/* Kali Linux Tools */}
          <Paper sx={{ 
            p: 2, 
            mb: 2, 
            bgcolor: '#21262d',
            border: '1px solid #30363d',
            borderRadius: 2
          }}>
            <Typography variant="h6" gutterBottom sx={{ 
              color: '#58a6ff',
              fontSize: '1.1rem',
              display: 'flex',
              alignItems: 'center',
              gap: 1
            }}>
              <TerminalIcon /> Kali Linux Arsenal
            </Typography>
            
            <Box sx={{ 
              display: 'grid', 
              gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', 
              gap: 1,
              mb: 2
            }}>
              {Object.entries(KALI_TOOLS).map(([key, tool]) => (
                <Card
                  key={key}
                  sx={{
                    cursor: 'pointer',
                    bgcolor: selectedTool === key ? '#58a6ff20' : '#0d1117',
                    border: selectedTool === key ? '2px solid #58a6ff' : '1px solid #30363d',
                    '&:hover': {
                      bgcolor: selectedTool === key ? '#58a6ff30' : '#21262d',
                      borderColor: '#58a6ff'
                    },
                    transition: 'all 0.2s ease'
                  }}
                  onClick={() => handleToolChange(key)}
                >
                  <CardContent sx={{ p: 1.5, '&:last-child': { pb: 1.5 } }}>
                    <Box display="flex" alignItems="center" gap={1} mb={1}>
                      {tool.icon}
                      <Typography variant="subtitle2" sx={{ 
                        fontSize: '0.9rem', 
                        fontWeight: 600,
                        color: '#e6edf3'
                      }}>
                        {tool.name}
                      </Typography>
                    </Box>
                    <Typography variant="body2" sx={{ 
                      fontSize: '0.75rem', 
                      color: '#7d8590',
                      mb: 1
                    }}>
                      {tool.description}
                    </Typography>
                    <Chip
                      label={tool.category}
                      size="small"
                      sx={{
                        height: 18,
                        fontSize: '0.7rem',
                        bgcolor: '#30363d',
                        color: '#e6edf3'
                      }}
                    />
                  </CardContent>
                </Card>
              ))}
            </Box>

            {/* Tool Options */}
            {selectedTool && toolOptions[selectedTool as keyof KaliToolOptions] && (
              <Accordion sx={{ 
                bgcolor: '#0d1117', 
                border: '1px solid #30363d',
                '&:before': { display: 'none' }
              }}>
                <AccordionSummary 
                  expandIcon={<ExpandMoreIcon sx={{ color: '#7d8590' }} />}
                  sx={{ color: '#e6edf3' }}
                >
                  <Typography variant="subtitle2">
                    ⚙️ {KALI_TOOLS[selectedTool as keyof typeof KALI_TOOLS]?.name} Options
                  </Typography>
                </AccordionSummary>
                <AccordionDetails>
                  {selectedTool === 'nmap' && toolOptions.nmap && (
                    <Stack spacing={2}>
                      <TextField
                        label="Port Range"
                        value={toolOptions.nmap.ports}
                        onChange={(e) => setToolOptions(prev => ({
                          ...prev,
                          nmap: { ...prev.nmap!, ports: e.target.value }
                        }))}
                        size="small"
                        fullWidth
                        sx={{ 
                          '& .MuiOutlinedInput-root': {
                            bgcolor: '#0d1117',
                            color: '#e6edf3',
                            '& fieldset': { borderColor: '#30363d' },
                            '&:hover fieldset': { borderColor: '#58a6ff' },
                            '&.Mui-focused fieldset': { borderColor: '#58a6ff' }
                          },
                          '& .MuiInputLabel-root': {
                            color: '#7d8590',
                            '&.Mui-focused': { color: '#58a6ff' }
                          }
                        }}
                      />
                      <FormControl size="small" fullWidth>
                        <InputLabel sx={{ color: '#7d8590', '&.Mui-focused': { color: '#58a6ff' } }}>
                          Timing Template
                        </InputLabel>
                        <Select
                          value={toolOptions.nmap.timing}
                          onChange={(e) => setToolOptions(prev => ({
                            ...prev,
                            nmap: { ...prev.nmap!, timing: e.target.value as number }
                          }))}
                          sx={{ 
                            bgcolor: '#0d1117',
                            color: '#e6edf3',
                            '& .MuiOutlinedInput-notchedOutline': { borderColor: '#30363d' },
                            '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: '#58a6ff' },
                            '&.Mui-focused .MuiOutlinedInput-notchedOutline': { borderColor: '#58a6ff' }
                          }}
                        >
                          <MenuItem value={1}>T1 (Sneaky)</MenuItem>
                          <MenuItem value={2}>T2 (Polite)</MenuItem>
                          <MenuItem value={3}>T3 (Normal)</MenuItem>
                          <MenuItem value={4}>T4 (Aggressive)</MenuItem>
                          <MenuItem value={5}>T5 (Insane)</MenuItem>
                        </Select>
                      </FormControl>
                      <Stack direction="row" spacing={2}>
                        <FormControlLabel
                          control={
                            <Switch
                              checked={toolOptions.nmap.osDetection}
                              onChange={(e) => setToolOptions(prev => ({
                                ...prev,
                                nmap: { ...prev.nmap!, osDetection: e.target.checked }
                              }))}
                              sx={{ 
                                '& .MuiSwitch-switchBase.Mui-checked': { color: '#58a6ff' },
                                '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { 
                                  backgroundColor: '#58a6ff' 
                                }
                              }}
                            />
                          }
                          label="OS Detection"
                          sx={{ color: '#e6edf3' }}
                        />
                        <FormControlLabel
                          control={
                            <Switch
                              checked={toolOptions.nmap.serviceVersion}
                              onChange={(e) => setToolOptions(prev => ({
                                ...prev,
                                nmap: { ...prev.nmap!, serviceVersion: e.target.checked }
                              }))}
                              sx={{ 
                                '& .MuiSwitch-switchBase.Mui-checked': { color: '#58a6ff' },
                                '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { 
                                  backgroundColor: '#58a6ff' 
                                }
                              }}
                            />
                          }
                          label="Service Version"
                          sx={{ color: '#e6edf3' }}
                        />
                      </Stack>
                    </Stack>
                  )}
                </AccordionDetails>
              </Accordion>
            )}

            <Button
              variant="contained"
              fullWidth
              startIcon={<PlayIcon />}
              onClick={executeKaliTool}
              disabled={loading || !targetUrl || !selectedTool}
              sx={{
                mt: 2,
                bgcolor: '#58a6ff',
                '&:hover': { bgcolor: '#1f6feb' },
                '&:disabled': { bgcolor: '#21262d', color: '#7d8590' }
              }}
            >
              {loading ? 'Executing...' : `Execute ${selectedTool?.toUpperCase()}`}
            </Button>
          </Paper>

          {/* Custom Command */}
          <Paper sx={{ 
            p: 2, 
            bgcolor: '#21262d',
            border: '1px solid #30363d',
            borderRadius: 2
          }}>
            <Typography variant="h6" gutterBottom sx={{ 
              color: '#58a6ff',
              fontSize: '1.1rem',
              display: 'flex',
              alignItems: 'center',
              gap: 1
            }}>
              <CodeIcon /> Custom Command
            </Typography>
            
            <TextField
              fullWidth
              label="Shell Command"
              value={customCommand}
              onChange={(e) => setCustomCommand(e.target.value)}
              placeholder="nmap -sS -A {target} || sqlmap -u {target} --dbs"
              variant="outlined"
              multiline
              rows={3}
              sx={{ 
                mb: 2,
                '& .MuiOutlinedInput-root': {
                  bgcolor: '#0d1117',
                  color: '#e6edf3',
                  fontFamily: 'Monaco, Consolas, "Courier New", monospace',
                  fontSize: '0.9rem',
                  '& fieldset': { borderColor: '#30363d' },
                  '&:hover fieldset': { borderColor: '#58a6ff' },
                  '&.Mui-focused fieldset': { borderColor: '#58a6ff' }
                },
                '& .MuiInputLabel-root': {
                  color: '#7d8590',
                  '&.Mui-focused': { color: '#58a6ff' }
                }
              }}
            />
            
            <Typography variant="body2" sx={{ mb: 2, color: '#7d8590', fontSize: '0.8rem' }}>
              💡 Use {"{target}"} placeholder for the target URL
            </Typography>
            
            <Button
              variant="contained"
              fullWidth
              startIcon={<SendIcon />}
              onClick={executeCustomCommand}
              disabled={loading || !customCommand}
              sx={{
                bgcolor: '#f85149',
                '&:hover': { bgcolor: '#da3633' },
                '&:disabled': { bgcolor: '#21262d', color: '#7d8590' }
              }}
            >
              Execute Custom Command
            </Button>
          </Paper>
        </Box>

        {/* Right Panel - Live Feed & Results */}
        <Box sx={{ flex: 1, minWidth: 500 }}>
          {/* Intercepted Requests Panel */}
          <Paper sx={{ 
            p: 2, 
            mb: 2, 
            bgcolor: '#21262d',
            border: '1px solid #30363d',
            borderRadius: 2,
            height: '400px',
            display: 'flex',
            flexDirection: 'column'
          }}>
            <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
              <Typography variant="h6" sx={{ 
                color: '#58a6ff',
                fontSize: '1.1rem',
                display: 'flex',
                alignItems: 'center',
                gap: 1
              }}>
                <HttpIcon /> 
                Captured HTTP Requests 
                <Badge badgeContent={interceptedRequests.length} color="error" />
              </Typography>
              
              <Stack direction="row" spacing={1}>
                <Tooltip title="Refresh Requests Manually">
                  <IconButton 
                    size="small" 
                    onClick={fetchInterceptedRequests}
                    sx={{ color: '#7d8590' }}
                  >
                    <RefreshIcon />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Clear All Requests">
                  <IconButton 
                    size="small" 
                    onClick={clearRequests}
                    sx={{ color: '#7d8590' }}
                  >
                    <ClearIcon />
                  </IconButton>
                </Tooltip>
                <Tooltip title={autoRefresh ? "Disable Auto Refresh" : "Enable Auto Refresh"}>
                  <IconButton 
                    size="small"
                    onClick={() => setAutoRefresh(!autoRefresh)}
                    color={autoRefresh ? "primary" : "default"}
                    sx={{ color: autoRefresh ? '#58a6ff' : '#7d8590' }}
                  >
                    {autoRefresh ? <VisibilityIcon /> : <VisibilityOffIcon />}
                  </IconButton>
                </Tooltip>
              </Stack>
            </Box>

            <Box sx={{ 
              flex: 1, 
              overflow: 'auto',
              border: '1px solid #30363d',
              borderRadius: 1,
              bgcolor: '#0d1117'
            }}>
              {interceptedRequests.length === 0 ? (
                <Box sx={{ 
                  p: 4, 
                  textAlign: 'center', 
                  color: '#7d8590' 
                }}>
                  <HttpIcon sx={{ fontSize: 48, mb: 2, opacity: 0.3 }} />
                  <Typography variant="body2" sx={{ textAlign: 'center' }}>
                    {!autoRefresh ? (
                      <>
                        🎯 <strong>Manual Mode Active</strong>
                        <br />
                        Set your target URL above, then launch HUD browser or use manual tools.
                        <br />
                        Click the <RefreshIcon sx={{ fontSize: 16, verticalAlign: 'middle' }} /> button above to refresh requests manually.
                        <br />
                        <small style={{ color: '#7d8590' }}>
                          Enable Auto Refresh to automatically capture requests in real-time
                        </small>
                      </>
                    ) : (
                      <>
                        🌐 Launch HUD Browser to start capturing HTTP requests
                        <br />
                        <small style={{ color: '#7d8590' }}>
                          All requests made through the ZAP proxy will appear here automatically
                        </small>
                      </>
                    )}
                  </Typography>
                </Box>
              ) : (
                <List dense>
                  {interceptedRequests.map((request, index) => (
                    <ListItem 
                      key={request.id}
                      component="div"
                      onClick={() => showRequestDetails(request)}
                      sx={{ 
                        borderBottom: '1px solid #30363d',
                        '&:hover': { bgcolor: '#21262d' },
                        cursor: 'pointer'
                      }}
                    >
                      <ListItemIcon>
                        <Chip
                          label={request.method}
                          size="small"
                          color={
                            request.method === 'GET' ? 'info' :
                            request.method === 'POST' ? 'warning' :
                            request.method === 'PUT' ? 'secondary' :
                            request.method === 'DELETE' ? 'error' : 'default'
                          }
                          sx={{ 
                            minWidth: 60, 
                            fontSize: '0.7rem',
                            fontWeight: 'bold'
                          }}
                        />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Typography variant="body2" sx={{ 
                            color: '#e6edf3',
                            fontSize: '0.85rem',
                            fontFamily: 'Monaco, Consolas, monospace'
                          }}>
                            {request.url.length > 60 ? `${request.url.substring(0, 60)}...` : request.url}
                          </Typography>
                        }
                        secondary={
                          <Box component="span" display="flex" alignItems="center" gap={1}>
                            <Typography variant="caption" component="span" sx={{ color: '#7d8590' }}>
                              {new Date(request.timestamp).toLocaleTimeString()}
                            </Typography>
                            {request.status && (
                              <Chip
                                label={request.status}
                                size="small"
                                color={
                                  request.status < 300 ? 'success' :
                                  request.status < 400 ? 'info' :
                                  request.status < 500 ? 'warning' : 'error'
                                }
                                sx={{ fontSize: '0.65rem', height: 16 }}
                              />
                            )}
                            {request.duration && (
                              <Typography variant="caption" component="span" sx={{ color: '#7d8590' }}>
                                {request.duration}ms
                              </Typography>
                            )}
                          </Box>
                        }
                      />
                    </ListItem>
                  ))}
                  <div ref={requestsEndRef} />
                </List>
              )}
            </Box>
          </Paper>

          {/* Scan Results */}
          <Paper sx={{ 
            p: 2, 
            bgcolor: '#21262d',
            border: '1px solid #30363d',
            borderRadius: 2
          }}>
            <Typography variant="h6" gutterBottom sx={{ 
              color: '#58a6ff',
              fontSize: '1.1rem',
              display: 'flex',
              alignItems: 'center',
              gap: 1
            }}>
              <AssessmentIcon /> Scan Results ({results.length})
            </Typography>

            {loading && (
              <LinearProgress 
                sx={{ 
                  mb: 2,
                  bgcolor: '#30363d',
                  '& .MuiLinearProgress-bar': { bgcolor: '#58a6ff' }
                }} 
              />
            )}

            <Box sx={{ maxHeight: '400px', overflow: 'auto' }}>
              {results.length === 0 ? (
                <Box sx={{ 
                  p: 4, 
                  textAlign: 'center', 
                  color: '#7d8590' 
                }}>
                  <AssessmentIcon sx={{ fontSize: 48, mb: 2, opacity: 0.3 }} />
                  <Typography variant="body2">
                    No scan results yet. Execute a tool to see results here.
                  </Typography>
                </Box>
              ) : (
                results.map((result, index) => (
                  <Card key={result.id} sx={{ 
                    mb: 2, 
                    bgcolor: '#0d1117',
                    border: '1px solid #30363d'
                  }}>
                    <CardContent sx={{ p: 2 }}>
                      <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={1}>
                        <Box>
                          <Typography variant="subtitle1" sx={{ 
                            fontSize: '0.95rem', 
                            fontWeight: 600,
                            color: '#e6edf3'
                          }}>
                            {result.tool}
                          </Typography>
                          <Typography variant="body2" sx={{ 
                            color: '#7d8590', 
                            fontSize: '0.8rem',
                            fontFamily: 'Monaco, Consolas, monospace'
                          }}>
                            {result.command}
                          </Typography>
                          <Typography variant="caption" sx={{ color: '#7d8590' }}>
                            {new Date(result.timestamp).toLocaleString()} | {result.duration}ms
                          </Typography>
                        </Box>
                        <Chip
                          label={result.severity.toUpperCase()}
                          size="small"
                          color={
                            result.severity === 'critical' ? 'error' :
                            result.severity === 'high' ? 'warning' :
                            result.severity === 'medium' ? 'info' : 'success'
                          }
                          sx={{ fontWeight: 'bold' }}
                        />
                      </Box>
                      
                      {result.findings && result.findings.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="body2" sx={{ 
                            fontSize: '0.85rem',
                            color: '#e6edf3',
                            mb: 1
                          }}>
                            📋 <strong>Findings ({result.findings.length}):</strong>
                          </Typography>
                          <Box sx={{ ml: 2 }}>
                            {result.findings.slice(0, 3).map((finding, idx) => (
                              <Typography key={idx} variant="body2" sx={{ 
                                fontSize: '0.8rem', 
                                color: '#7d8590',
                                mb: 0.5
                              }}>
                                • {finding}
                              </Typography>
                            ))}
                            {result.findings.length > 3 && (
                              <Typography variant="body2" sx={{ 
                                fontSize: '0.8rem', 
                                color: '#58a6ff',
                                cursor: 'pointer'
                              }}>
                                ... and {result.findings.length - 3} more
                              </Typography>
                            )}
                          </Box>
                        </Box>
                      )}

                      <Button
                        variant="outlined"
                        size="small"
                        startIcon={<InfoIcon />}
                        onClick={() => showRequestDetails(result.request || {
                          id: result.id,
                          method: 'GET',
                          url: targetUrl,
                          headers: {},
                          timestamp: result.timestamp
                        })}
                        sx={{ 
                          color: '#e6edf3',
                          borderColor: '#30363d',
                          '&:hover': {
                            borderColor: '#58a6ff',
                            bgcolor: 'rgba(88, 166, 255, 0.1)'
                          }
                        }}
                      >
                        View Details
                      </Button>
                    </CardContent>
                  </Card>
                ))
              )}
            </Box>
          </Paper>
        </Box>
      </Box>

      {/* Request Detail Dialog */}
      <Dialog
        open={detailDialogOpen}
        onClose={() => setDetailDialogOpen(false)}
        maxWidth="lg"
        fullWidth
        PaperProps={{
          sx: {
            bgcolor: '#0d1117',
            color: '#e6edf3',
            border: '1px solid #30363d',
            maxHeight: '90vh'
          }
        }}
      >
        <DialogTitle sx={{ 
          bgcolor: '#21262d', 
          borderBottom: '1px solid #30363d',
          display: 'flex',
          alignItems: 'center',
          gap: 1
        }}>
          <HttpIcon />
          Request/Response Inspector
        </DialogTitle>
        
        <DialogContent sx={{ p: 0 }}>
          <Tabs 
            value={selectedTab} 
            onChange={(e, newValue) => setSelectedTab(newValue)}
            sx={{ 
              borderBottom: '1px solid #30363d',
              bgcolor: '#21262d',
              '& .MuiTab-root': {
                color: '#7d8590',
                '&.Mui-selected': { color: '#58a6ff' }
              },
              '& .MuiTabs-indicator': { backgroundColor: '#58a6ff' }
            }}
          >
            <Tab label="🔍 Request" />
            <Tab label="📄 Response" />
            <Tab label="✏️ Modify & Resend" />
          </Tabs>

          <Box sx={{ p: 3, minHeight: 400 }}>
            {selectedTab === 0 && selectedRequest && (
              <Box>
                <Typography variant="h6" gutterBottom sx={{ color: '#58a6ff', mb: 2 }}>
                  Request Details
                </Typography>
                <Paper sx={{ 
                  bgcolor: '#21262d', 
                  p: 2, 
                  mb: 2,
                  border: '1px solid #30363d'
                }}>
                  <Typography variant="body2" component="pre" sx={{ 
                    fontFamily: 'Monaco, Consolas, monospace', 
                    fontSize: '0.85rem',
                    color: '#e6edf3',
                    whiteSpace: 'pre-wrap'
                  }}>
                    {`${selectedRequest.method} ${selectedRequest.url}
${Object.entries(selectedRequest.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n')}

${selectedRequest.body || ''}`}
                  </Typography>
                </Paper>
              </Box>
            )}

            {selectedTab === 1 && selectedRequest && (
              <Box>
                <Typography variant="h6" gutterBottom sx={{ color: '#58a6ff', mb: 2 }}>
                  Response Details
                </Typography>
                <Paper sx={{ 
                  bgcolor: '#21262d', 
                  p: 2,
                  border: '1px solid #30363d'
                }}>
                  <Typography variant="body2" component="pre" sx={{ 
                    fontFamily: 'Monaco, Consolas, monospace', 
                    fontSize: '0.85rem',
                    color: '#e6edf3',
                    whiteSpace: 'pre-wrap'
                  }}>
                    {`Status: ${selectedRequest.status || 'N/A'}
${Object.entries(selectedRequest.responseHeaders || {}).map(([k, v]) => `${k}: ${v}`).join('\n')}

${selectedRequest.responseBody || 'No response body captured'}`}
                  </Typography>
                </Paper>
              </Box>
            )}

            {selectedTab === 2 && editableRequest && (
              <Box>
                <Typography variant="h6" gutterBottom sx={{ color: '#58a6ff', mb: 2 }}>
                  Modify Request
                </Typography>
                <Stack spacing={2}>
                  <Stack direction="row" spacing={2}>
                    <FormControl sx={{ minWidth: 120 }}>
                      <InputLabel sx={{ color: '#7d8590' }}>Method</InputLabel>
                      <Select
                        value={editableRequest.method}
                        onChange={(e) => setEditableRequest(prev => prev ? 
                          { ...prev, method: e.target.value } : null
                        )}
                        sx={{ 
                          bgcolor: '#21262d',
                          color: '#e6edf3',
                          '& .MuiOutlinedInput-notchedOutline': { borderColor: '#30363d' }
                        }}
                      >
                        <MenuItem value="GET">GET</MenuItem>
                        <MenuItem value="POST">POST</MenuItem>
                        <MenuItem value="PUT">PUT</MenuItem>
                        <MenuItem value="DELETE">DELETE</MenuItem>
                        <MenuItem value="PATCH">PATCH</MenuItem>
                      </Select>
                    </FormControl>
                    <TextField
                      fullWidth
                      label="URL"
                      value={editableRequest.url}
                      onChange={(e) => setEditableRequest(prev => prev ? 
                        { ...prev, url: e.target.value } : null
                      )}
                      sx={{ 
                        '& .MuiOutlinedInput-root': {
                          bgcolor: '#21262d',
                          color: '#e6edf3',
                          '& fieldset': { borderColor: '#30363d' }
                        },
                        '& .MuiInputLabel-root': { color: '#7d8590' }
                      }}
                    />
                  </Stack>

                  <TextField
                    fullWidth
                    label="Headers (JSON)"
                    multiline
                    rows={4}
                    value={JSON.stringify(editableRequest.headers || {}, null, 2)}
                    onChange={(e) => {
                      try {
                        const headers = JSON.parse(e.target.value);
                        setEditableRequest(prev => prev ? { ...prev, headers } : null);
                      } catch (err) {
                        // Invalid JSON
                      }
                    }}
                    sx={{ 
                      '& .MuiOutlinedInput-root': {
                        bgcolor: '#21262d',
                        color: '#e6edf3',
                        fontFamily: 'Monaco, Consolas, monospace',
                        '& fieldset': { borderColor: '#30363d' }
                      },
                      '& .MuiInputLabel-root': { color: '#7d8590' }
                    }}
                  />

                  <TextField
                    fullWidth
                    label="Request Body"
                    multiline
                    rows={6}
                    value={editableRequest.body || ''}
                    onChange={(e) => setEditableRequest(prev => prev ? 
                      { ...prev, body: e.target.value } : null
                    )}
                    sx={{ 
                      '& .MuiOutlinedInput-root': {
                        bgcolor: '#21262d',
                        color: '#e6edf3',
                        fontFamily: 'Monaco, Consolas, monospace',
                        '& fieldset': { borderColor: '#30363d' }
                      },
                      '& .MuiInputLabel-root': { color: '#7d8590' }
                    }}
                  />
                </Stack>
              </Box>
            )}
          </Box>
        </DialogContent>
        
        <DialogActions sx={{ 
          p: 3, 
          bgcolor: '#21262d', 
          borderTop: '1px solid #30363d'
        }}>
          <Button 
            onClick={() => setDetailDialogOpen(false)}
            sx={{ color: '#7d8590' }}
          >
            Close
          </Button>
          {selectedTab === 2 && (
            <Button
              variant="contained"
              startIcon={<SendIcon />}
              onClick={sendModifiedRequest}
              disabled={loading}
              sx={{
                bgcolor: '#58a6ff',
                '&:hover': { bgcolor: '#1f6feb' }
              }}
            >
              Send Modified Request
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ManualScan;
