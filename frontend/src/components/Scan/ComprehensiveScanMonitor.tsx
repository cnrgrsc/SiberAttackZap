import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  LinearProgress,
  Chip,
  Tab,
  Tabs,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Collapse,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  ToggleButton,
  ToggleButtonGroup
} from '@mui/material';
import {
  Close as CloseIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Stop as StopIcon,
  TableView as TableViewIcon,
  AccountTree as TreeViewIcon,
  Sync as SyncIcon,
  PlayArrow as PlayIcon
} from '@mui/icons-material';
import socketService from '../../services/socketService';
import { zapService } from '../../services/zapService';
import scanService from '../../services/scanService';
import UrlTreeView from './UrlTreeView';

export {};

interface ComprehensiveScanMonitorProps {
  workflowId: string;
  scanId?: string; // Add scanId prop
  onClose: () => void;
  onScanComplete?: (scan: any) => void;
}

interface ScanProgress {
  phase: string;
  progress: number;
  status: string;
  spider?: { progress: number; status: string; urlsFound: number };
  ajaxSpider?: { progress: number; status: string; urlsFound: number };
  activeScan?: { progress: number; status: string; alertsFound: number };
  details?: any;
}

interface Vulnerability {
  id: string;
  name: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'CRITICAL';
  confidence: string;
  description: string;
  solution: string;
  reference: string;
  url: string;
  param: string;
  attack: string;
  evidence: string;
  otherInfo: string;
  method: string;
  alertRef: string;
  messageId: string;
  pluginId: string;
  cweid: string;
  wascid: string;
  sourceid: string;
  tags: { [key: string]: string };
}

interface UrlEntry {
  url: string;
  method: string;
  statusCode: number;
  responseTime: number;
  contentType: string;
  size: number;
  timestamp: string;
}

const ComprehensiveScanMonitor: React.FC<ComprehensiveScanMonitorProps> = ({
  workflowId,
  scanId,
  onClose,
  onScanComplete
}) => {
  // API Base URL - Use environment variable for flexibility
  const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';
  
  const [scanProgress, setScanProgress] = useState<ScanProgress>({
    phase: 'INITIALIZING',
    progress: 0,
    status: 'STARTING'
  });
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [urlsFound, setUrlsFound] = useState<UrlEntry[]>([]);
  const [currentTab, setCurrentTab] = useState(0);
  const [isScanning, setIsScanning] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [showDetails, setShowDetails] = useState<{[key: string]: boolean}>({});
  const [logs, setLogs] = useState<string[]>([]);
  const [urlViewMode, setUrlViewMode] = useState<'table' | 'tree'>('table');
  const [isSyncing, setIsSyncing] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [elapsedTime, setElapsedTime] = useState(0); // Elapsed time in seconds
  const [startTime, setStartTime] = useState<Date | null>(null);
  const [realTimeAlerts, setRealTimeAlerts] = useState<Vulnerability[]>([]); // Real-time incoming alerts
  const [apiSecurityData, setApiSecurityData] = useState<any>(null); // API Deep Dive results

  const getPhaseLabel = (phase: string): string => {
    const phaseLabels: { [key: string]: string } = {
      'INITIALIZING': '🔧 Başlatılıyor',
      'TARGET_SETUP': '🎯 Hedef Ayarlanıyor',
      'passive_analysis': '🔍 Pasif Analiz - Trafiği İzliyor',
      'spider_scan': '🕷️ Spider Taraması - URL Keşfi',
      'ajax_spider': '⚡ AJAX Spider - Dinamik İçerik Keşfi',
      'forced_browse': '📂 Dizin Keşfi - Gizli Dosyaları Arıyor',
      'passive_scan': '👁️ Pasif Tarama Tamamlanıyor',
      'active_scan': '🔥 Aktif Güvenlik Taraması - Zafiyet Testi',
      'specialized_attacks': '⚔️ Özel Saldırı Testleri (SQL, XSS, XXE, CSRF)',
      'collecting_results': '📊 Sonuçlar Toplanıyor',
      'SPIDER_SCAN': '🕷️ Spider Taraması',
      'AJAX_SPIDER': '⚡ Ajax Spider Taraması',
      'ACTIVE_SCAN': '🔍 Aktif Güvenlik Taraması',
      'ADVANCED_ANALYSIS': '📊 Gelişmiş Veri Toplama',
      'JS_SECURITY': '📜 JavaScript Güvenlik Analizi',
      'API_DEEP_DIVE': '🔌 API Güvenlik Analizi',
      'GENERATING_REPORT': '📄 Rapor Oluşturuluyor',
      'COMPLETED': '✅ Tamamlandı',
      'STOPPED': '🛑 Durduruldu',
      'PAUSED': '⏸️ Duraklatıldı',
      'ERROR': '❌ Hata'
    };
    return phaseLabels[phase] || phase;
  };

  const getPhaseDescription = (phase: string): string => {
    const descriptions: { [key: string]: string } = {
      'passive_analysis': 'Uygulamayı etkilemeden trafik analizi yapıyor',
      'spider_scan': 'Web sitesindeki tüm linkleri ve sayfaları keşfediyor',
      'ajax_spider': 'JavaScript ile yüklenen dinamik içerikleri tarıyor',
      'forced_browse': 'Yaygın dizin ve dosya isimlerini test ediyor (wordlist)',
      'passive_scan': 'Bulunan tüm istekleri güvenlik açısından analiz ediyor',
      'active_scan': 'SQL Injection, XSS, Command Injection gibi aktif testler yapıyor',
      'specialized_attacks': 'Hedefli saldırı simülasyonları: SQL, XSS, XXE, CSRF',
      'collecting_results': 'Tüm bulunan zafiyetleri ve URL\'leri topluyorum'
    };
    return descriptions[phase] || 'Tarama devam ediyor...';
  };

  const getSeverityIcon = (severity: string) => {
    if (!severity) return <InfoIcon />;
    switch (severity.toUpperCase()) {
      case 'HIGH': return <ErrorIcon />;
      case 'MEDIUM': return <WarningIcon />;
      case 'LOW': return <InfoIcon />;
      case 'INFO': return <CheckCircleIcon />;
      case 'CRITICAL': return <ErrorIcon />;
      default: return <InfoIcon />;
    }
  };

  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, `[${timestamp}] ${message}`]);
  };

  // Map ZAP risk values to our severity values
  const mapSeverity = (risk: string): 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'CRITICAL' => {
    if (!risk) return 'INFO';
    const riskUpper = risk.toUpperCase();
    switch (riskUpper) {
      case 'HIGH': return 'HIGH';
      case 'MEDIUM': return 'MEDIUM';
      case 'LOW': return 'LOW';
      case 'INFORMATIONAL': return 'INFO';
      case 'INFO': return 'INFO';
      case 'CRITICAL': return 'CRITICAL';
      default: return 'INFO';
    }
  };

  // Load scan data from database if scanId is provided
  const loadScanData = async (scanId: string, retryCount = 0): Promise<void> => {
    try {
      
      // Load both scan details and URLs
      const [scanResponse, urlsResponse] = await Promise.all([
        fetch(`${API_BASE_URL}/api/zap/scans/${scanId}`, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('siberZed_token') || localStorage.getItem('auth_token')}`,
            'Content-Type': 'application/json'
          }
        }),
        fetch(`${API_BASE_URL}/api/scans/${scanId}/urls`, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('siberZed_token') || localStorage.getItem('auth_token')}`,
            'Content-Type': 'application/json'
          }
        })
      ]);
      
      if (scanResponse.ok) {
        const result = await scanResponse.json();
        const scanData = result.data;
        
        console.log('🔍 DEBUG: Scan data received from database:');
        console.log('  - Status:', scanData.status);
        console.log('  - CompletedAt:', scanData.completedAt);
        console.log('  - Vulnerabilities count:', scanData.vulnerabilities?.length || 0);
        
        // If status is still RUNNING but we expect COMPLETED, retry up to 3 times
        if (scanData.status === 'RUNNING' && retryCount < 3) {
          console.log(`⚠️ Status still RUNNING (attempt ${retryCount + 1}/3), retrying in 2 seconds...`);
          await new Promise(resolve => setTimeout(resolve, 2000));
          return loadScanData(scanId, retryCount + 1);
        }
        
        console.log('🔍 DEBUG: Vulnerabilities count:', scanData.vulnerabilities?.length || 0);
        console.log('🔍 DEBUG: Full scan data:', JSON.stringify(scanData, null, 2));
        
        // Update vulnerabilities state
        if (scanData.vulnerabilities && scanData.vulnerabilities.length > 0) {
          const mappedVulns = scanData.vulnerabilities.map((vuln: any) => {
            // Zafiyet objesinin yapısını kontrol et
            console.log('🔍 DEBUG: Mapping vulnerability:', vuln);
            
            return {
              id: vuln.id || vuln.zapAlertId || String(Date.now() + Math.random()),
              name: vuln.name || vuln.alertName || vuln.alert || 'Unknown Vulnerability',
              severity: mapSeverity(vuln.severity || vuln.riskCode),
              confidence: vuln.confidence || vuln.reliabilityCode || 'Medium',
              description: vuln.description || '',
              solution: vuln.solution || '',
              reference: vuln.reference || '',
              url: vuln.affectedUrl || vuln.url || vuln.uri || '',
              param: vuln.param || '',
              attack: vuln.attack || '',
              evidence: vuln.evidence || '',
              otherInfo: vuln.otherInfo || vuln.other || '',
              method: vuln.method || 'GET',
              alertRef: vuln.zapAlertId || vuln.id || '',
              messageId: vuln.messageId || '',
              pluginId: vuln.pluginId || '',
              cweid: vuln.cweid || '',
              wascid: vuln.wascid || '',
              sourceid: vuln.sourceid || '',
              tags: vuln.tags || {}
            };
          });
          
          console.log(`✅ Mapped ${mappedVulns.length} vulnerabilities`);
          setVulnerabilities(mappedVulns);
          addLog(`Loaded ${mappedVulns.length} vulnerabilities from database`);
        } else {
          console.log('⚠️ No vulnerabilities found in scan data');
          setVulnerabilities([]);
        }
        
        // 📊 Load API Security Data (API Deep Dive)
        if (scanData.apiSecurity) {
          console.log('📊 API Deep Dive data found:', scanData.apiSecurity);
          setApiSecurityData(scanData.apiSecurity);
          addLog(`✅ API Deep Dive: ${scanData.apiSecurity.totalEndpoints || 0} endpoints analyzed`);
        }
      }
      
      // Load URLs from the updated API
      if (urlsResponse.ok) {
        const urlsResult = await urlsResponse.json();
        const urlsData = urlsResult.data;
        
        console.log('🔍 DEBUG: URLs count:', urlsData?.length || 0);
        
        if (urlsData && urlsData.length > 0) {
          // URLs are already in the correct format from backend
          setUrlsFound(urlsData);
          addLog(`Loaded ${urlsData.length} URLs from database`);
        } else {
          setUrlsFound([]);
        }
      } else {
        console.error('Failed to load URLs:', urlsResponse.status, urlsResponse.statusText);
        addLog('Failed to load URLs from server');
      }

      addLog(`Scan data loaded successfully`);
    } catch (error) {
      console.error('Error loading scan data:', error);
      addLog('Error loading persisted scan data');
    }
  };

  // Fetch workflow progress periodically
  useEffect(() => {
    let isScanComplete = false;
    let intervalRef: NodeJS.Timeout | null = null;
    
    const stopPolling = () => {
      if (intervalRef) {
        clearInterval(intervalRef);
        intervalRef = null;
      }
    };
    
    const fetchWorkflowProgress = async () => {
      // Skip fetch if scan is complete
      if (isScanComplete) {
        stopPolling();
        return;
      }
      
      try {
        const response = await fetch(`${API_BASE_URL}/api/zap/workflow/${workflowId}/progress`, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('siberZed_token') || localStorage.getItem('auth_token')}`,
            'Content-Type': 'application/json'
          }
        });
        if (response.ok) {
          const result = await response.json();
          
          // Handle API response format
          const data = result.success ? result.data : result;
          
          setScanProgress(data);
          
          if (data.status === 'COMPLETED') {
            isScanComplete = true;
            setIsScanning(false);
            stopPolling(); // Stop polling immediately
            addLog('✅ Workflow completed successfully - polling stopped');
            
            // Load persisted data from database if scanId is available
            if (scanId) {
              loadScanData(scanId);
            }
            
            // Emit scan completed event to trigger history refresh
            window.dispatchEvent(new CustomEvent('scanCompleted', { 
              detail: { workflowId, scanId } 
            }));
            
            onScanComplete?.(data);
          } else if (data.status === 'STOPPED') {
            isScanComplete = true;
            setIsScanning(false);
            stopPolling(); // Stop polling immediately
            addLog('🛑 Workflow stopped by user - polling stopped');
            
            // Emit scan stopped event to trigger history refresh
            window.dispatchEvent(new CustomEvent('scanCompleted', { 
              detail: { workflowId, scanId, status: 'STOPPED' } 
            }));
          } else if (data.status === 'FAILED') {
            isScanComplete = true;
            setIsScanning(false);
            stopPolling(); // Stop polling immediately
            
            // Extract error details from polling response
            const errorMessage = data.error?.message || data.message || 'Tarama başarısız oldu';
            const errorType = data.error?.type || 'UNKNOWN_ERROR';
            const technicalDetails = data.error?.technicalDetails || '';
            
            const errorIcon = errorType === 'TIMEOUT' ? '⏱️' :
                             errorType === 'CONNECTION_ERROR' ? '🔌' :
                             errorType === 'ZAP_ERROR' ? '🔧' :
                             errorType === 'ACCESS_DENIED' ? '🚫' :
                             errorType === 'NOT_FOUND' ? '🔍' :
                             errorType === 'SSL_ERROR' ? '🔒' : '❌';
            
            addLog(`${errorIcon} Tarama Başarısız: ${errorMessage} - polling stopped`);
            
            if (technicalDetails && technicalDetails !== errorMessage) {
              addLog(`   Teknik Detay: ${technicalDetails}`);
            }
            
            // Emit scan failed event to trigger history refresh
            window.dispatchEvent(new CustomEvent('scanCompleted', { 
              detail: { 
                workflowId, 
                scanId, 
                status: 'FAILED',
                error: {
                  type: errorType,
                  message: errorMessage,
                  technicalDetails
                }
              } 
            }));
          }
          
          if (data.phase) {
            addLog(`Phase: ${data.phase} - ${data.progress || 0}%`);
          }
          
          if (data.vulnerabilities) {
            const mappedVulnerabilities = data.vulnerabilities.map((vuln: any) => ({
              ...vuln,
              severity: mapSeverity(vuln.severity || vuln.risk)
            }));
            setVulnerabilities(mappedVulnerabilities);
          }
          
          if (data.urlsFound && Array.isArray(data.urlsFound)) {
            setUrlsFound(data.urlsFound);
          }
        }
      } catch (error) {
        console.error('Error fetching workflow progress:', error);
      }
    };

    // Initial fetch
    fetchWorkflowProgress();

    // Set up polling interval
    intervalRef = setInterval(fetchWorkflowProgress, 2000);

    // WebSocket event handlers for real-time updates
    const handleScanUpdate = async (data: any) => {
      console.log('🔄 Data keys:', Object.keys(data));
      console.log('🔄 Status:', data.status, 'Progress:', data.progress, 'Phase:', data.phase);
      
      if (data.workflowId === workflowId) {
        if (typeof data.progress === 'number') {
          setScanProgress(data);
        }
        
        const status = data.status?.toString().toUpperCase();
        const phase = data.phase?.toString().toUpperCase();
        const progress = data.progress;
        
        // Tarama %100'e ulaştığında ve status/phase COMPLETED ise bitir
        if (status === 'COMPLETED' || phase === 'COMPLETED' || (progress >= 100 && phase === 'RESULTS_COLLECTION')) {
          isScanComplete = true;
          stopPolling(); // Stop polling on completion
          setIsScanning(false);
          setScanProgress({ ...data, status: 'COMPLETED', progress: 100, phase: 'COMPLETED' });
          addLog('✅ Workflow completed successfully (WebSocket)');
          console.log('🛑 Polling will stop - scan completed (status:', status, 'phase:', phase, 'progress:', progress, ')');
          
          // Load persisted data from database if scanId is available
          // Wait a bit for backend to finish database update
          if (scanId) {
            console.log('📊 Waiting 3 seconds for database update to complete...');
            await new Promise(resolve => setTimeout(resolve, 3000));
            console.log('📊 Loading final scan data from database...');
            await loadScanData(scanId);
          }
          
          // Emit scan completed event to trigger history refresh
          window.dispatchEvent(new CustomEvent('scanCompleted', { 
            detail: { workflowId, scanId } 
          }));
          
          onScanComplete?.(data);
        } else if (status === 'PAUSED') {
          setIsPaused(true);
          addLog('⏸️ Workflow paused by user (WebSocket)');
          console.log('⏸️ Scan paused (from WebSocket)');
        } else if (status === 'RUNNING' && isPaused) {
          setIsPaused(false);
          addLog('▶️ Workflow resumed by user (WebSocket)');
          console.log('▶️ Scan resumed (from WebSocket)');
        } else if (status === 'STOPPED') {
          isScanComplete = true;
          setIsScanning(false);
          addLog('🛑 Workflow stopped by user (WebSocket)');
          console.log('🛑 Polling will stop - scan stopped (from WebSocket)');
          
          // Emit scan stopped event to trigger history refresh
          window.dispatchEvent(new CustomEvent('scanCompleted', { 
            detail: { workflowId, scanId, status: 'STOPPED' } 
          }));
        } else if (status === 'FAILED') {
          isScanComplete = true;
          setIsScanning(false);
          
          // Extract error details
          const errorMessage = data.error?.message || data.message || 'Tarama başarısız oldu';
          const errorType = data.error?.type || 'UNKNOWN_ERROR';
          const technicalDetails = data.error?.technicalDetails || '';
          
          // User-friendly error message with icon
          const errorIcon = errorType === 'TIMEOUT' ? '⏱️' :
                           errorType === 'CONNECTION_ERROR' ? '🔌' :
                           errorType === 'ZAP_ERROR' ? '🔧' :
                           errorType === 'ACCESS_DENIED' ? '🚫' :
                           errorType === 'NOT_FOUND' ? '🔍' :
                           errorType === 'SSL_ERROR' ? '🔒' : '❌';
          
          addLog(`${errorIcon} Tarama Başarısız: ${errorMessage} (WebSocket)`);
          
          if (technicalDetails && technicalDetails !== errorMessage) {
            addLog(`   Teknik Detay: ${technicalDetails}`);
          }
          
          console.log('🛑 Polling will stop - scan failed (from WebSocket)', {
            errorType,
            errorMessage,
            technicalDetails
          });
          
          // Emit scan failed event to trigger history refresh
          window.dispatchEvent(new CustomEvent('scanCompleted', { 
            detail: { 
              workflowId, 
              scanId, 
              status: 'FAILED',
              error: {
                type: errorType,
                message: errorMessage,
                technicalDetails
              }
            } 
          }));
        }

        if (data.phase) {
          addLog(`Phase: ${data.phase} - ${data.progress}%`);
        }

        // Handle vulnerability updates
        if (data.vulnerabilities && Array.isArray(data.vulnerabilities)) {
          const mappedVulnerabilities = data.vulnerabilities.map((vuln: any, index: number) => ({
            id: vuln.id || `${vuln.pluginId || 'vuln'}-${vuln.messageId || index}-${Date.now()}-${index}`,
            name: vuln.name || 'Unknown Vulnerability',
            severity: mapSeverity(vuln.severity || vuln.risk),
            confidence: vuln.confidence || 'Medium',
            description: vuln.description || '',
            solution: vuln.solution || '',
            reference: vuln.reference || '',
            url: vuln.affectedUrl || vuln.url || '',
            param: vuln.param || '',
            attack: vuln.attack || '',
            evidence: vuln.evidence || '',
            otherInfo: vuln.otherInfo || '',
            method: vuln.method || 'GET',
            alertRef: vuln.alertRef || vuln.id,
            messageId: vuln.messageId || '',
            pluginId: vuln.pluginId || '',
            cweid: vuln.cweid || '',
            wascid: vuln.wascid || '',
            sourceid: vuln.sourceid || '',
            tags: vuln.tags || {}
          }));
          setVulnerabilities(prev => {
            // Merge with existing vulnerabilities, avoiding duplicates by NAME (not ID)
            // This prevents duplicate entries like "X-Content-Type-Options Header Missing" for different URLs
            const existingMap = new Map(prev.map((v: Vulnerability) => [v.name, v]));
            
            mappedVulnerabilities.forEach((v: Vulnerability) => {
              if (!existingMap.has(v.name)) {
                existingMap.set(v.name, v);
              }
            });
            
            const updated = Array.from(existingMap.values());
            const newCount = updated.length - prev.length;
            
            // Only log if there are new vulnerabilities
            if (newCount > 0) {
              console.log(`🔍 Vulnerabilities updated: ${updated.length} total (+${newCount} new unique)`);
            }
            return updated;
          });
          addLog(`Updated vulnerabilities: ${mappedVulnerabilities.length} total`);
        }

        // Handle URL updates - check both 'urls' and 'urlsFound' properties
        if ((data.urls && Array.isArray(data.urls)) || (data.urlsFound && Array.isArray(data.urlsFound))) {
          const urlArray = data.urls || data.urlsFound;
          
          const mappedUrls = urlArray.map((url: any) => ({
            url: typeof url === 'string' ? url : url.url,
            method: url.method || 'GET',
            statusCode: url.statusCode || 200,
            responseTime: url.responseTime || 0,
            contentType: url.contentType || 'text/html',
            size: url.size || 0,
            timestamp: url.timestamp || new Date().toISOString()
          }));
          setUrlsFound(prev => {
            // Merge with existing URLs, avoiding duplicates
            const existingUrls = new Set(prev.map((u: UrlEntry) => u.url));
            const newUrls = mappedUrls.filter((u: UrlEntry) => !existingUrls.has(u.url));
            const updated = [...prev, ...newUrls];
            // Only log if there are new URLs
            if (newUrls.length > 0) {
              console.log(`🔍 URLs updated: ${updated.length} total (+${newUrls.length} new)`);
            }
            return updated;
          });
          addLog(`Updated URLs: ${mappedUrls.length} discovered`);
        }

        // Handle URL count updates
        if (typeof data.urlsFound === 'number') {
          addLog(`Total URLs discovered: ${data.urlsFound}`);
        }

        if (data.type === 'vulnerability') {
          // Map ZAP risk values to our severity values
          const mapSeverity = (risk: string): 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'CRITICAL' => {
            if (!risk) return 'INFO';
            const riskUpper = risk.toUpperCase();
            switch (riskUpper) {
              case 'HIGH': return 'HIGH';
              case 'MEDIUM': return 'MEDIUM';
              case 'LOW': return 'LOW';
              case 'INFORMATIONAL': return 'INFO';
              case 'INFO': return 'INFO';
              case 'CRITICAL': return 'CRITICAL';
              default: return 'INFO';
            }
          };

          const newVulnerability = {
            id: data.id || Date.now().toString(),
            name: data.name || 'Unknown Vulnerability',
            severity: mapSeverity(data.severity || data.risk),
            confidence: data.confidence || 'Low',
            description: data.description || '',
            solution: data.solution || '',
            reference: data.reference || '',
            url: data.url || '',
            param: data.param || '',
            attack: data.attack || '',
            evidence: data.evidence || '',
            otherInfo: data.otherInfo || '',
            method: data.method || '',
            alertRef: data.alertRef || '',
            messageId: data.messageId || '',
            pluginId: data.pluginId || '',
            cweid: data.cweid || '',
            wascid: data.wascid || '',
            sourceid: data.sourceid || '',
            tags: data.tags || {}
          };
          setVulnerabilities(prev => [...prev, newVulnerability]);
          addLog(`New vulnerability found: ${newVulnerability.name} (${newVulnerability.severity})`);
        }

        if (data.type === 'url') {
          const newUrl = {
            url: data.url || '',
            method: data.method || 'GET',
            statusCode: data.statusCode || 200,
            responseTime: data.responseTime || 0,
            contentType: data.contentType || 'text/html',
            size: data.size || 0,
            timestamp: new Date().toISOString()
          };
          setUrlsFound(prev => [...prev, newUrl]);
          addLog(`New URL discovered: ${newUrl.method} ${newUrl.url} (${newUrl.statusCode})`);
        }
      }
    };

    // Özel vulnerability handler
    const handleVulnerabilityFound = (data: any) => {
      const alertName = data.alert?.name || data.alert?.alert || 'Bilinmeyen zafiyet';
      const alertRisk = data.alert?.risk || 'Unknown';
      addLog(`🚨 ZAFIYET BULUNDU: ${alertName} [${alertRisk}]`);
      
      if (data.alert) {
        const mapSeverity = (risk: string): 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'CRITICAL' => {
          if (!risk) return 'INFO';
          const riskUpper = risk.toUpperCase();
          switch (riskUpper) {
            case 'HIGH': return 'HIGH';
            case 'MEDIUM': return 'MEDIUM';
            case 'LOW': return 'LOW';
            case 'INFORMATIONAL': return 'INFO';
            case 'INFO': return 'INFO';
            case 'CRITICAL': return 'CRITICAL';
            default: return 'INFO';
          }
        };

        const newVulnerability: Vulnerability = {
          id: data.alert.alertId || data.alert.id || Date.now().toString(),
          name: data.alert.name || data.alert.alert || 'Bilinmeyen Zafiyet',
          severity: mapSeverity(data.alert.risk || data.alert.severity),
          confidence: data.alert.confidence || 'Medium',
          description: data.alert.description || '',
          solution: data.alert.solution || '',
          reference: data.alert.reference || '',
          url: data.alert.url || '',
          param: data.alert.param || '',
          attack: data.alert.attack || '',
          evidence: data.alert.evidence || '',
          otherInfo: data.alert.otherInfo || '',
          method: data.alert.method || 'GET',
          alertRef: data.alert.alertRef || '',
          messageId: data.alert.messageId || '',
          pluginId: data.alert.pluginId || '',
          cweid: data.alert.cweid || '',
          wascid: data.alert.wascid || '',
          sourceid: data.alert.sourceid || '',
          tags: data.alert.tags || {}
        };
        
        setVulnerabilities(prev => {
          // Çifte kayıt önlemek için ID kontrolü
          const exists = prev.some(v => v.id === newVulnerability.id);
          if (!exists) {
            const updated = [...prev, newVulnerability];
            console.log(`✅ [REAL-TIME] Zafiyet eklendi: ${newVulnerability.name} (${newVulnerability.severity}) - Toplam: ${updated.length}`);
            addLog(`📊 Toplam zafiyet sayısı: ${updated.length}`);
            
            // 🔴 Add to real-time alerts (keep last 10)
            setRealTimeAlerts(prevAlerts => {
              const newAlerts = [newVulnerability, ...prevAlerts].slice(0, 10);
              return newAlerts;
            });
            
            return updated;
          } else {
          }
          return prev;
        });
      }
    };

    // Özel URL handler
    const handleUrlFound = (data: any) => {
      addLog(`🌐 URL KEŞFEDİLDİ: ${data.url}`);
      
      if (data.url) {
        const newUrl: UrlEntry = {
          url: data.url,
          method: data.method || 'GET',
          statusCode: data.statusCode || 200,
          responseTime: data.responseTime || 0,
          contentType: data.contentType || 'text/html',
          size: data.size || 0,
          timestamp: data.timestamp || new Date().toISOString()
        };
        
        setUrlsFound(prev => {
          // Çifte kayıt önlemek için URL kontrolü
          const exists = prev.some(u => u.url === newUrl.url);
          if (!exists) {
            const updated = [...prev, newUrl];
            addLog(`📊 Toplam URL sayısı: ${updated.length}`);
            return updated;
          } else {
          }
          return prev;
        });
      }
    };

    // Listen for workflow-related socket events
    socketService.on('workflowUpdate', handleScanUpdate);
    socketService.on('workflowProgress', handleScanUpdate);
    socketService.on('vulnerabilityFound', handleVulnerabilityFound);
    socketService.on('urlFound', handleUrlFound);
    
    // scanUpdate eventini de dinleyelim
    socketService.on('scanUpdate', handleScanUpdate);

    // Socket room'a join ol
    if (scanId) {
      socketService.joinScanRoom(scanId);
      addLog(`📡 Scan room'a bağlandı: ${scanId}`);
    }

    addLog(`Monitoring workflow: ${workflowId}`);
    addLog(`🔍 Canlı zafiyet ve URL güncellemeleri aktif`);

    return () => {
      stopPolling(); // Clear interval on cleanup
      socketService.off('workflowUpdate', handleScanUpdate);
      socketService.off('workflowProgress', handleScanUpdate);
      socketService.off('vulnerabilityFound', handleVulnerabilityFound);
      socketService.off('urlFound', handleUrlFound);
      socketService.off('scanUpdate', handleScanUpdate);
      
      // Socket room'dan ayrıl
      if (scanId) {
        socketService.leaveScanRoom(scanId);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workflowId, scanId]); // API_BASE_URL is constant, loadScanData and onScanComplete are stable

  // Cleanup on component unmount or page close
  // Use ref to track current scanning state to avoid re-running effect
  const isScanningRef = useRef(isScanning);
  const workflowIdRef = useRef(workflowId);
  
  useEffect(() => {
    isScanningRef.current = isScanning;
    workflowIdRef.current = workflowId;
  }, [isScanning, workflowId]);

  useEffect(() => {
    const handleBeforeUnload = (event: BeforeUnloadEvent) => {
      // Only warn the user if a scan is running, but DON'T auto-stop it
      // The scan should continue running in the background on the server
      if (isScanningRef.current && workflowIdRef.current) {
        event.preventDefault();
        event.returnValue = 'Tarama arka planda devam edecek. Dashboard\'dan taramayı takip edebilirsiniz.';
      }
    };

    const handleVisibilityChange = () => {
      // REMOVED: Auto-stop on visibility change
      // Scans should continue even when the tab is hidden/inactive
      if (document.visibilityState === 'hidden' && isScanningRef.current) {
      } else if (document.visibilityState === 'visible' && isScanningRef.current) {
      }
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      
      // REMOVED: Auto-stop on unmount to prevent false stops during re-renders
      // The user should explicitly click the stop button to stop a scan
      // Background scans should continue even if the monitor is closed
    };
  }, [API_BASE_URL]); // Only re-run if API_BASE_URL changes (which should never happen)

  // Load scan data immediately if scanId is provided
  useEffect(() => {
    if (scanId) {
      loadScanData(scanId);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]); // loadScanData is stable and doesn't need to be in deps

  // ⏱️ Timer for elapsed time
  useEffect(() => {
    if (isScanning && !startTime) {
      setStartTime(new Date());
    }

    if (!isScanning) {
      return; // Don't run timer if not scanning
    }

    const interval = setInterval(() => {
      if (startTime) {
        const now = new Date();
        const elapsed = Math.floor((now.getTime() - startTime.getTime()) / 1000);
        setElapsedTime(elapsed);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [isScanning, startTime]);

  // Format elapsed time as HH:MM:SS
  const formatElapsedTime = (seconds: number): string => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  const handlePauseScan = async () => {
    try {
      addLog('⏸️ Tarama duraklatılıyor...');
      
      const authHeaders = {
        'Authorization': `Bearer ${localStorage.getItem('siberZed_token') || localStorage.getItem('auth_token')}`,
        'Content-Type': 'application/json'
      };

      // Pause the workflow
      if (workflowId) {
        const response = await fetch(`${API_BASE_URL}/api/zap/workflow/${workflowId}/pause`, { 
          method: 'POST',
          headers: authHeaders
        });

        if (response.ok) {
          setIsPaused(true);
          addLog('✅ Tarama duraklatıldı');
          
          // Update UI state
          setScanProgress(prev => ({
            ...prev,
            status: 'PAUSED'
          }));
        } else {
          addLog('⚠️ Tarama duraklatılırken sorun oluştu');
        }
      }

    } catch (error) {
      console.error('Error pausing scan:', error);
      addLog('❌ Tarama duraklatılırken hata oluştu');
    }
  };

  const handleResumeScan = async () => {
    try {
      addLog('▶️ Tarama devam ettiriliyor...');
      
      const authHeaders = {
        'Authorization': `Bearer ${localStorage.getItem('siberZed_token') || localStorage.getItem('auth_token')}`,
        'Content-Type': 'application/json'
      };

      // Resume the workflow
      if (workflowId) {
        const response = await fetch(`${API_BASE_URL}/api/zap/workflow/${workflowId}/resume`, { 
          method: 'POST',
          headers: authHeaders
        });

        if (response.ok) {
          setIsPaused(false);
          addLog('✅ Tarama devam ediyor');
          
          // Update UI state
          setScanProgress(prev => ({
            ...prev,
            status: 'RUNNING'
          }));
        } else {
          addLog('⚠️ Tarama devam ettirilemedi');
        }
      }

    } catch (error) {
      console.error('Error resuming scan:', error);
      addLog('❌ Tarama devam ettirilemedi');
    }
  };

  const handleStopScan = async () => {
    // Confirmation dialog
    if (!window.confirm('Taramayı tamamen durdurmak istediğinizden emin misiniz? Bu işlem geri alınamaz.')) {
      return;
    }

    try {
      addLog('🛑 Tarama durdurulyor...');
      setIsScanning(false);
      
      const authHeaders = {
        'Authorization': `Bearer ${localStorage.getItem('siberZed_token') || localStorage.getItem('auth_token')}`,
        'Content-Type': 'application/json'
      };

      // Stop all ZAP scans first
      addLog('🛑 Tüm ZAP taramalarını durduruluyor...');
      
      try {
        const stopAllResponse = await fetch(`${API_BASE_URL}/api/zap/scan/stop-all`, { 
          method: 'POST',
          headers: authHeaders
        });

        if (stopAllResponse.ok) {
          addLog('✅ Tüm ZAP taramaları durduruldu');
        } else {
          addLog('⚠️ ZAP taramalarını durdururken sorun oluştu');
        }
      } catch (error) {
        addLog('⚠️ ZAP taramalarını durdurmada hata');
        console.error('Error stopping ZAP scans:', error);
      }

      // Stop the workflow if workflowId exists
      if (workflowId) {
        addLog('🛑 Workflow durdurulyor...');
        
        const workflowResponse = await fetch(`${API_BASE_URL}/api/zap/workflow/${workflowId}/stop`, { 
          method: 'POST',
          headers: authHeaders
        });

        if (workflowResponse.ok) {
          addLog('✅ Workflow başarıyla durduruldu');
        } else {
          addLog('⚠️ Workflow durdurulurken sorun oluştu');
        }
      }

      // 🔥 UPDATE BACKEND SCAN STATUS TO STOPPED
      if (scanId) {
        addLog('🛑 Veritabanı scan durumu güncelleniyor...');
        
        try {
          const statusUpdateResponse = await fetch(`${API_BASE_URL}/api/scans/${scanId}/status`, { 
            method: 'PUT',
            headers: authHeaders,
            body: JSON.stringify({ status: 'STOPPED' })
          });

          if (statusUpdateResponse.ok) {
            addLog('✅ Scan durumu veritabanında güncellendi (STOPPED)');
          } else {
            addLog('⚠️ Scan durumu güncellenirken sorun oluştu');
          }
        } catch (error) {
          addLog('⚠️ Scan durumu güncellemede hata');
          console.error('Error updating scan status:', error);
        }
      }

      // Update UI state
      setScanProgress(prev => ({
        ...prev,
        status: 'STOPPED',
        phase: 'STOPPED',
        progress: prev.progress
      }));

      addLog('✅ Tarama durdurma işlemi tamamlandı');

      // Emit scan stopped event to trigger history refresh
      window.dispatchEvent(new CustomEvent('scanCompleted', { 
        detail: { workflowId, scanId, status: 'STOPPED' } 
      }));

    } catch (error) {
      console.error('Error stopping scan:', error);
      addLog('❌ Tarama durdurulurken bağlantı hatası oluştu');
      setIsScanning(false);
    }
  };

  const handleSyncWithZapGui = async () => {
    setIsSyncing(true);
    try {
      addLog('🔄 Syncing with ZAP GUI session...');
      const response = await zapService.syncSession();
      
      if (response.data.success) {
        const { refreshedData } = response.data.data;
        addLog(`✅ Sync completed - Found ${refreshedData.sitesCount} sites, ${refreshedData.alertsCount} alerts, ${refreshedData.urlsCount} URLs`);
        
        if (refreshedData.alertsCount === 0 && refreshedData.urlsCount === 0) {
          // Show helpful instructions
          addLog('ℹ️ No data found in API session. This means ZAP GUI and automated scan are using different sessions.');
          addLog('');
          addLog('💡 To see your ZAP GUI data in automated scan:');
          addLog('1. In ZAP GUI: File → Persist Session → Save Session As...');
          addLog('2. Save the session file');
          addLog('3. Restart ZAP and load the saved session');
          addLog('4. Or perform a new automated scan to populate this interface');
          addLog('');
          addLog('🔄 Would you like to start a new automated scan instead?');
        } else {
          // Update the UI with the synced data
          if (refreshedData.alerts && refreshedData.alerts.length > 0) {
            const formattedVulns = refreshedData.alerts.map((alert: any) => ({
              id: alert.alertId || alert.id,
              name: alert.name || alert.alert,
              description: alert.description || '',
              severity: alert.severity || alert.risk,
              confidence: alert.confidence || '',
              solution: alert.solution || '',
              reference: alert.reference || '',
              url: alert.url || '',
              param: alert.param || '',
              attack: alert.attack || '',
              evidence: alert.evidence || ''
            }));
            setVulnerabilities(formattedVulns);
            addLog(`📊 Updated vulnerabilities: ${formattedVulns.length} found`);
          }
          
          if (refreshedData.urls && refreshedData.urls.length > 0) {
            const formattedUrls = refreshedData.urls.map((url: string, index: number) => ({
              id: index.toString(),
              url: url,
              method: 'GET',
              statusCode: 200,
              responseTime: 0,
              timestamp: new Date().toISOString()
            }));
            setUrlsFound(formattedUrls);
            addLog(`🔗 Updated URLs: ${formattedUrls.length} found`);
          }
        }
        
      } else {
        addLog('⚠️ Sync completed but no data found in ZAP session');
      }
    } catch (error) {
      console.error('Error syncing with ZAP GUI:', error);
      addLog('❌ Error syncing with ZAP GUI session');
      addLog('💡 Try starting a new automated scan to populate this interface');
    } finally {
      setIsSyncing(false);
    }
  };

  const handleStartNewScan = async () => {
    try {
      // Ask user for target URL
      const targetUrl = prompt('Enter target URL for new automated scan:');
      if (!targetUrl) return;

      addLog('🚀 Starting new automated scan...');
      const scanConfig = {
        targetUrl: targetUrl,
        enableSpider: true,
        enableActiveScan: true,
        spiderOptions: {
          maxChildren: 100,
          maxDepth: 5
        }
      };

      const newScan = await scanService.startAutomatedScan(scanConfig);
      addLog(`✅ New scan started with ID: ${newScan.id}`);
      addLog('This scan will populate the automated interface with fresh data');
      addLog('Monitor progress in real-time and see vulnerabilities as they are discovered');
      
    } catch (error) {
      console.error('Error starting new scan:', error);
      addLog('❌ Error starting new scan');
    }
  };

  const handleGenerateReport = async () => {
    try {
      addLog('📄 Generating modern security report...');
      
      const response = await fetch(`${API_BASE_URL}/api/reports/scan/${scanId}/html`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (response.ok) {
        // Create download link
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        
        // Extract filename from Content-Disposition header or create default
        const contentDisposition = response.headers.get('Content-Disposition');
        let filename = `SiberZed-Security-Report-${scanId}.html`;
        
        if (contentDisposition) {
          const filenameMatch = contentDisposition.match(/filename="(.+)"/);
          if (filenameMatch) {
            filename = filenameMatch[1];
          }
        }
        
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        
        // Cleanup
        window.URL.revokeObjectURL(url);
        document.body.removeChild(link);
        
        addLog(`✅ Modern security report downloaded: ${filename}`);
      } else {
        addLog('❌ Error generating report: ' + response.statusText);
      }
    } catch (error) {
      console.error('Error generating report:', error);
      addLog('❌ Error generating report');
    }
  };

  const filteredVulnerabilities = vulnerabilities.filter(vuln => {
    const matchesSeverity = filterSeverity === 'all' || vuln.severity === filterSeverity;
    const matchesSearch = vuln.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         vuln.url.toLowerCase().includes(searchTerm.toLowerCase());
    
    // Debug logging removed to reduce console spam
    // Enable only when debugging filter issues
    
    return matchesSeverity && matchesSearch;
  });

  const getProgressColor = (progress: number) => {
    if (progress < 30) return 'error';
    if (progress < 70) return 'warning';
    return 'success';
  };

  const TabPanel = ({ children, value, index }: any) => (
    <div hidden={value !== index}>
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );

  return (
    <>
      {/* CSS Animations */}
      <style>
        {`
          @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.6; }
          }
          
          @keyframes slideIn {
            from {
              transform: translateX(-20px);
              opacity: 0;
            }
            to {
              transform: translateX(0);
              opacity: 1;
            }
          }
        `}
      </style>
      
      <Dialog
      open={true}
      onClose={onClose}
      maxWidth="xl"
      fullWidth
      PaperProps={{
        sx: { 
          height: '90vh', 
          maxHeight: '90vh',
          bgcolor: (theme) => theme.palette.mode === 'dark' ? 'grey.900' : 'background.paper',
          backgroundImage: 'none'
        }
      }}
    >
      <DialogTitle>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Box display="flex" alignItems="center" gap={2}>
            <SecurityIcon color="primary" />
            <Typography variant="h6">
              Comprehensive Security Scan Monitor
            </Typography>
            <Chip
              label={scanProgress.status}
              color={isScanning ? 'warning' : 'success'}
              variant="outlined"
            />
          </Box>
          <Box display="flex" gap={1}>
            {isScanning && (
              <>
                {!isPaused ? (
                  <Button
                    variant="outlined"
                    color="warning"
                    startIcon={<StopIcon />}
                    onClick={handlePauseScan}
                    size="small"
                  >
                    Pause
                  </Button>
                ) : (
                  <Button
                    variant="contained"
                    color="success"
                    startIcon={<PlayIcon />}
                    onClick={handleResumeScan}
                    size="small"
                  >
                    Resume
                  </Button>
                )}
                <Button
                  variant="outlined"
                  color="error"
                  startIcon={<StopIcon />}
                  onClick={handleStopScan}
                  size="small"
                >
                  Stop
                </Button>
              </>
            )}
            <Button
              variant="outlined"
              color="primary"
              startIcon={<SyncIcon />}
              onClick={handleSyncWithZapGui}
              disabled={isSyncing}
              size="small"
            >
              {isSyncing ? 'Syncing...' : 'Sync with ZAP GUI'}
            </Button>
            <Button
              variant="contained"
              color="success"
              startIcon={<PlayIcon />}
              onClick={handleStartNewScan}
              size="small"
            >
              Start New Scan
            </Button>
            {vulnerabilities.length > 0 && (
              <Button
                variant="contained"
                color="info"
                startIcon={<div>📄</div>}
                onClick={handleGenerateReport}
                size="small"
              >
                Generate Report
              </Button>
            )}
            <IconButton onClick={onClose}>
              <CloseIcon />
            </IconButton>
          </Box>
        </Box>
      </DialogTitle>

      <DialogContent dividers>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          {/* Progress Overview */}
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6">
                  Scan Progress
                </Typography>
                {/* ⏱️ Elapsed Time Display */}
                {isScanning && (
                  <Chip 
                    icon={<SecurityIcon />}
                    label={`⏱️ ${formatElapsedTime(elapsedTime)}`}
                    color="primary"
                    variant="outlined"
                    sx={{ 
                      fontWeight: 'bold',
                      fontSize: '1rem',
                      animation: 'pulse 2s infinite'
                    }}
                  />
                )}
              </Box>
              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" color="text.secondary" sx={{ fontWeight: 'bold', fontSize: '0.95rem' }}>
                  {getPhaseLabel(scanProgress.phase)}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5, fontStyle: 'italic' }}>
                  {getPhaseDescription(scanProgress.phase)}
                </Typography>
                <LinearProgress
                  variant="determinate"
                  value={scanProgress.progress}
                  color={getProgressColor(scanProgress.progress)}
                  sx={{ mt: 1, height: 8, borderRadius: 4 }}
                />
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 1 }}>
                  <Typography variant="caption">
                    {scanProgress.progress}% Tamamlandı
                  </Typography>
                  <Typography variant="caption" color="primary">
                    {urlsFound.length} URL | {vulnerabilities.length} Zafiyet Bulundu
                  </Typography>
                </Box>
              </Box>

              {/* Vulnerability Statistics Cards */}
              <Box sx={{ display: 'flex', gap: 2, mt: 3, flexWrap: 'wrap' }}>
                <Card 
                  sx={{ 
                    flex: 1, 
                    bgcolor: '#f5f5f5', 
                    cursor: 'pointer',
                    '&:hover': { bgcolor: '#e0e0e0' },
                    minWidth: 150,
                    border: filterSeverity === 'all' ? '3px solid #1976d2' : '3px solid transparent',
                    transform: filterSeverity === 'all' ? 'scale(1.05)' : 'scale(1)',
                    transition: 'all 0.2s ease-in-out'
                  }}
                  onClick={() => {
                    setFilterSeverity('all');
                    setCurrentTab(0);
                  }}
                >
                  <CardContent sx={{ textAlign: 'center', py: 2 }}>
                    <Typography variant="h3" sx={{ color: '#333', fontWeight: 'bold' }}>
                      {vulnerabilities.length}
                    </Typography>
                    <Typography variant="caption" sx={{ color: '#666' }}>
                      TOTAL<br/>VULNERABILITIES
                    </Typography>
                  </CardContent>
                </Card>

                <Card 
                  sx={{ 
                    flex: 1, 
                    bgcolor: '#ffebee', 
                    cursor: 'pointer',
                    '&:hover': { bgcolor: '#ffcdd2' },
                    minWidth: 150,
                    border: filterSeverity === 'CRITICAL' ? '3px solid #c62828' : '3px solid transparent',
                    transform: filterSeverity === 'CRITICAL' ? 'scale(1.05)' : 'scale(1)',
                    transition: 'all 0.2s ease-in-out'
                  }}
                  onClick={() => {
                    setFilterSeverity('CRITICAL');
                    setCurrentTab(0);
                  }}
                >
                  <CardContent sx={{ textAlign: 'center', py: 2 }}>
                    <Typography variant="h3" sx={{ color: '#c62828', fontWeight: 'bold' }}>
                      {vulnerabilities.filter(v => v.severity === 'CRITICAL').length}
                    </Typography>
                    <Typography variant="caption" sx={{ color: '#666' }}>
                      CRITICAL
                    </Typography>
                  </CardContent>
                </Card>

                <Card 
                  sx={{ 
                    flex: 1, 
                    bgcolor: '#fff3e0', 
                    cursor: 'pointer',
                    '&:hover': { bgcolor: '#ffe0b2' },
                    minWidth: 150,
                    border: filterSeverity === 'HIGH' ? '3px solid #e65100' : '3px solid transparent',
                    transform: filterSeverity === 'HIGH' ? 'scale(1.05)' : 'scale(1)',
                    transition: 'all 0.2s ease-in-out'
                  }}
                  onClick={() => {
                    setFilterSeverity('HIGH');
                    setCurrentTab(0);
                  }}
                >
                  <CardContent sx={{ textAlign: 'center', py: 2 }}>
                    <Typography variant="h3" sx={{ color: '#e65100', fontWeight: 'bold' }}>
                      {vulnerabilities.filter(v => v.severity === 'HIGH').length}
                    </Typography>
                    <Typography variant="caption" sx={{ color: '#666' }}>
                      HIGH
                    </Typography>
                  </CardContent>
                </Card>

                <Card 
                  sx={{ 
                    flex: 1, 
                    bgcolor: '#fff8e1', 
                    cursor: 'pointer',
                    '&:hover': { bgcolor: '#ffecb3' },
                    minWidth: 150,
                    border: filterSeverity === 'MEDIUM' ? '3px solid #f57c00' : '3px solid transparent',
                    transform: filterSeverity === 'MEDIUM' ? 'scale(1.05)' : 'scale(1)',
                    transition: 'all 0.2s ease-in-out'
                  }}
                  onClick={() => {
                    setFilterSeverity('MEDIUM');
                    setCurrentTab(0);
                  }}
                >
                  <CardContent sx={{ textAlign: 'center', py: 2 }}>
                    <Typography variant="h3" sx={{ color: '#f57c00', fontWeight: 'bold' }}>
                      {vulnerabilities.filter(v => v.severity === 'MEDIUM').length}
                    </Typography>
                    <Typography variant="caption" sx={{ color: '#666' }}>
                      MEDIUM
                    </Typography>
                  </CardContent>
                </Card>

                <Card 
                  sx={{ 
                    flex: 1, 
                    bgcolor: '#f3e5f5', 
                    cursor: 'pointer',
                    '&:hover': { bgcolor: '#e1bee7' },
                    minWidth: 150,
                    border: filterSeverity === 'LOW' ? '3px solid #388e3c' : '3px solid transparent',
                    transform: filterSeverity === 'LOW' ? 'scale(1.05)' : 'scale(1)',
                    transition: 'all 0.2s ease-in-out'
                  }}
                  onClick={() => {
                    setFilterSeverity('LOW');
                    setCurrentTab(0);
                  }}
                >
                  <CardContent sx={{ textAlign: 'center', py: 2 }}>
                    <Typography variant="h3" sx={{ color: '#388e3c', fontWeight: 'bold' }}>
                      {vulnerabilities.filter(v => v.severity === 'LOW').length}
                    </Typography>
                    <Typography variant="caption" sx={{ color: '#666' }}>
                      LOW
                    </Typography>
                  </CardContent>
                </Card>

                <Card 
                  sx={{ 
                    flex: 1, 
                    bgcolor: '#e3f2fd', 
                    cursor: 'pointer',
                    '&:hover': { bgcolor: '#bbdefb' },
                    minWidth: 150,
                    border: filterSeverity === 'INFO' ? '3px solid #1976d2' : '3px solid transparent',
                    transform: filterSeverity === 'INFO' ? 'scale(1.05)' : 'scale(1)',
                    transition: 'all 0.2s ease-in-out'
                  }}
                  onClick={() => {
                    setFilterSeverity('INFO');
                    setCurrentTab(0);
                  }}
                >
                  <CardContent sx={{ textAlign: 'center', py: 2 }}>
                    <Typography variant="h3" sx={{ color: '#1976d2', fontWeight: 'bold' }}>
                      {vulnerabilities.filter(v => v.severity === 'INFO').length}
                    </Typography>
                    <Typography variant="caption" sx={{ color: '#666' }}>
                      INFORMATIONAL
                    </Typography>
                  </CardContent>
                </Card>
              </Box>
            </CardContent>
          </Card>

          {/* 🔴 Real-Time Alerts Panel */}
          {isScanning && realTimeAlerts.length > 0 && (
            <Card sx={{ bgcolor: '#1a1a1a', border: '2px solid #ff5722' }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <WarningIcon sx={{ color: '#ff5722', animation: 'pulse 1.5s infinite' }} />
                  <Typography variant="h6" sx={{ color: '#ff5722', fontWeight: 'bold' }}>
                    🔴 Anlık Gelen Alert'ler
                  </Typography>
                  <Chip 
                    label={`${realTimeAlerts.length} yeni`} 
                    size="small" 
                    color="error"
                    sx={{ ml: 'auto' }}
                  />
                </Box>
                <Box sx={{ maxHeight: 300, overflow: 'auto' }}>
                  {realTimeAlerts.map((alert, index) => (
                    <Box 
                      key={alert.id}
                      sx={{ 
                        p: 1.5,
                        mb: 1,
                        bgcolor: '#2a2a2a',
                        borderLeft: `4px solid ${
                          alert.severity === 'CRITICAL' || alert.severity === 'HIGH' ? '#f44336' :
                          alert.severity === 'MEDIUM' ? '#ff9800' :
                          alert.severity === 'LOW' ? '#ffc107' : '#2196f3'
                        }`,
                        borderRadius: 1,
                        animation: index === 0 ? 'slideIn 0.5s ease-out' : 'none'
                      }}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                        <Chip 
                          label={alert.severity} 
                          size="small"
                          color={
                            alert.severity === 'CRITICAL' || alert.severity === 'HIGH' ? 'error' :
                            alert.severity === 'MEDIUM' ? 'warning' :
                            alert.severity === 'LOW' ? 'info' : 'default'
                          }
                        />
                        <Typography variant="body2" sx={{ color: '#fff', fontWeight: 'bold', flex: 1 }}>
                          {alert.name}
                        </Typography>
                      </Box>
                      <Typography variant="caption" sx={{ color: '#9e9e9e', display: 'block', mt: 0.5 }}>
                        {alert.url || 'URL bilgisi yok'}
                      </Typography>
                    </Box>
                  ))}
                </Box>
              </CardContent>
            </Card>
          )}

          {/* 📊 API Deep Dive Results */}
          {apiSecurityData && (
            <Card sx={{ bgcolor: '#e8f5e9', border: '2px solid #4caf50' }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <SecurityIcon sx={{ color: '#4caf50' }} />
                  <Typography variant="h6" sx={{ color: '#2e7d32', fontWeight: 'bold' }}>
                    🔌 API Deep Dive Analiz Sonuçları
                  </Typography>
                  <Chip 
                    label={`${apiSecurityData.totalEndpoints || 0} Endpoint`} 
                    color="success" 
                    sx={{ ml: 'auto' }}
                  />
                </Box>
                
                <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 2, mb: 2 }}>
                  <Box sx={{ p: 2, bgcolor: '#fff', borderRadius: 1, border: '1px solid #c8e6c9' }}>
                    <Typography variant="caption" sx={{ color: '#666', display: 'block' }}>
                      Güvenlik Skoru
                    </Typography>
                    <Typography variant="h4" sx={{ color: '#2e7d32', fontWeight: 'bold' }}>
                      {apiSecurityData.securityScore || 0}/100
                    </Typography>
                  </Box>
                  
                  <Box sx={{ p: 2, bgcolor: '#fff', borderRadius: 1, border: '1px solid #c8e6c9' }}>
                    <Typography variant="caption" sx={{ color: '#666', display: 'block' }}>
                      API Zafiyetleri
                    </Typography>
                    <Typography variant="h4" sx={{ color: apiSecurityData.vulnerabilities?.length > 0 ? '#f44336' : '#4caf50', fontWeight: 'bold' }}>
                      {apiSecurityData.vulnerabilities?.length || 0}
                    </Typography>
                  </Box>
                  
                  <Box sx={{ p: 2, bgcolor: '#fff', borderRadius: 1, border: '1px solid #c8e6c9' }}>
                    <Typography variant="caption" sx={{ color: '#666', display: 'block' }}>
                      HTTP Methodları
                    </Typography>
                    <Typography variant="h4" sx={{ color: '#1976d2', fontWeight: 'bold' }}>
                      {Object.keys(apiSecurityData.endpointsByMethod || {}).length}
                    </Typography>
                  </Box>
                  
                  <Box sx={{ p: 2, bgcolor: '#fff', borderRadius: 1, border: '1px solid #c8e6c9' }}>
                    <Typography variant="caption" sx={{ color: '#666', display: 'block' }}>
                      Parametre Tipi
                    </Typography>
                    <Typography variant="h4" sx={{ color: '#9c27b0', fontWeight: 'bold' }}>
                      {Object.keys(apiSecurityData.parameterTypes || {}).length}
                    </Typography>
                  </Box>
                </Box>

                {/* Top Endpoints */}
                {apiSecurityData.endpoints && apiSecurityData.endpoints.length > 0 && (
                  <Box>
                    <Typography variant="subtitle2" sx={{ color: '#2e7d32', mb: 1, fontWeight: 'bold' }}>
                      📍 Tespit Edilen API Endpoint'leri (İlk 5)
                    </Typography>
                    <Box sx={{ maxHeight: 200, overflow: 'auto' }}>
                      {apiSecurityData.endpoints.slice(0, 5).map((endpoint: any, index: number) => (
                        <Box 
                          key={index}
                          sx={{ 
                            p: 1,
                            mb: 1,
                            bgcolor: '#fff',
                            borderLeft: `3px solid ${
                              endpoint.method === 'GET' ? '#2196f3' :
                              endpoint.method === 'POST' ? '#ff9800' :
                              endpoint.method === 'PUT' ? '#9c27b0' :
                              endpoint.method === 'DELETE' ? '#f44336' : '#757575'
                            }`,
                            borderRadius: 1
                          }}
                        >
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Chip 
                              label={endpoint.method || 'GET'} 
                              size="small"
                              sx={{ fontWeight: 'bold', minWidth: 60 }}
                            />
                            <Typography variant="caption" sx={{ fontFamily: 'monospace', flex: 1 }}>
                              {endpoint.path || endpoint.url}
                            </Typography>
                            {endpoint.parameterCount > 0 && (
                              <Chip 
                                label={`${endpoint.parameterCount} param`} 
                                size="small" 
                                variant="outlined"
                              />
                            )}
                          </Box>
                        </Box>
                      ))}
                    </Box>
                  </Box>
                )}
              </CardContent>
            </Card>
          )}

          {/* Detailed Results */}
          <Card>
            <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Tabs value={currentTab} onChange={(e, newValue) => setCurrentTab(newValue)}>
                <Tab label={`Vulnerabilities (${vulnerabilities.length})`} />
                <Tab label={`URLs Found (${urlsFound.length})`} />
                <Tab label="Logs" />
              </Tabs>
            </Box>

            <TabPanel value={currentTab} index={0}>
              {/* Vulnerability Filters */}
              <Box sx={{ mb: 2, display: 'flex', gap: 2 }}>
                <FormControl size="small" sx={{ minWidth: 150 }}>
                  <InputLabel>Severity Filter</InputLabel>
                  <Select
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    label="Severity Filter"
                  >
                    <MenuItem value="all">All Severities</MenuItem>
                    <MenuItem value="CRITICAL">Critical</MenuItem>
                    <MenuItem value="HIGH">High</MenuItem>
                    <MenuItem value="MEDIUM">Medium</MenuItem>
                    <MenuItem value="LOW">Low</MenuItem>
                    <MenuItem value="INFO">Info</MenuItem>
                  </Select>
                </FormControl>
                <TextField
                  size="small"
                  placeholder="Search vulnerabilities..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  sx={{ minWidth: 250 }}
                />
              </Box>

              <TableContainer component={Paper} sx={{ maxHeight: 400 }}>
                <Table stickyHeader>
                  <TableHead>
                    <TableRow>
                      <TableCell>Severity</TableCell>
                      <TableCell>Name</TableCell>
                      <TableCell>URL</TableCell>
                      <TableCell>Confidence</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {filteredVulnerabilities.map((vuln) => (
                      <React.Fragment key={vuln.id}>
                        <TableRow>
                          <TableCell>
                            <Chip
                              label={vuln.severity}
                              color={vuln.severity === 'HIGH' || vuln.severity === 'CRITICAL' ? 'error' : 
                                     vuln.severity === 'MEDIUM' ? 'warning' : 'info'}
                              size="small"
                              icon={getSeverityIcon(vuln.severity)}
                            />
                          </TableCell>
                          <TableCell>{vuln.name}</TableCell>
                          <TableCell>
                            <Typography variant="body2" sx={{ 
                              maxWidth: 300, 
                              overflow: 'hidden', 
                              textOverflow: 'ellipsis' 
                            }}>
                              {vuln.url}
                            </Typography>
                          </TableCell>
                          <TableCell>{vuln.confidence}</TableCell>
                          <TableCell>
                            <IconButton
                              size="small"
                              onClick={() => setShowDetails(prev => ({
                                ...prev,
                                [vuln.id]: !prev[vuln.id]
                              }))}
                            >
                              {showDetails[vuln.id] ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                            </IconButton>
                          </TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell colSpan={5} sx={{ py: 0 }}>
                            <Collapse in={showDetails[vuln.id]} timeout="auto" unmountOnExit>
                              <Box sx={{ 
                                p: 2, 
                                bgcolor: (theme) => theme.palette.mode === 'dark' ? 'grey.800' : 'grey.50',
                                borderLeft: 3,
                                borderColor: 'primary.main'
                              }}>
                                <Typography variant="subtitle2" gutterBottom color="primary">
                                  Description:
                                </Typography>
                                <Typography variant="body2" paragraph>
                                  {vuln.description || 'No description available'}
                                </Typography>
                                
                                {vuln.solution && (
                                  <>
                                    <Typography variant="subtitle2" gutterBottom color="primary">
                                      Solution:
                                    </Typography>
                                    <Typography variant="body2" paragraph>
                                      {vuln.solution}
                                    </Typography>
                                  </>
                                )}
                                
                                {vuln.evidence && (
                                  <>
                                    <Typography variant="subtitle2" gutterBottom color="primary">
                                      Evidence:
                                    </Typography>
                                    <Typography variant="body2" component="pre" sx={{ 
                                      bgcolor: (theme) => theme.palette.mode === 'dark' ? 'grey.900' : 'grey.100',
                                      color: (theme) => theme.palette.mode === 'dark' ? 'grey.100' : 'grey.800',
                                      p: 1, 
                                      borderRadius: 1,
                                      fontSize: '0.75rem',
                                      border: 1,
                                      borderColor: (theme) => theme.palette.mode === 'dark' ? 'grey.700' : 'grey.300'
                                    }}>
                                      {vuln.evidence}
                                    </Typography>
                                  </>
                                )}
                              </Box>
                            </Collapse>
                          </TableCell>
                        </TableRow>
                      </React.Fragment>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </TabPanel>

            <TabPanel value={currentTab} index={1}>
              <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="body2" color="text.secondary">
                  {urlsFound.length > 0 ? `${urlsFound.length} URLs discovered` : 'No URLs found yet...'}
                </Typography>
                <ToggleButtonGroup
                  value={urlViewMode}
                  exclusive
                  onChange={(e, newMode) => newMode && setUrlViewMode(newMode)}
                  size="small"
                >
                  <ToggleButton value="table">
                    <TableViewIcon />
                  </ToggleButton>
                  <ToggleButton value="tree">
                    <TreeViewIcon />
                  </ToggleButton>
                </ToggleButtonGroup>
              </Box>

              {urlViewMode === 'table' ? (
                <TableContainer component={Paper} sx={{ maxHeight: 400 }}>
                  <Table stickyHeader>
                    <TableHead>
                      <TableRow>
                        <TableCell>Method</TableCell>
                        <TableCell>URL</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Content Type</TableCell>
                        <TableCell>Size</TableCell>
                        <TableCell>Response Time</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {urlsFound.length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={6} align="center">
                            <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                              URLs will appear here as they are discovered during scanning...
                            </Typography>
                          </TableCell>
                        </TableRow>
                      ) : (
                        urlsFound.map((url, index) => (
                          <TableRow key={index}>
                            <TableCell>
                              <Chip label={url.method || 'GET'} size="small" />
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" sx={{ 
                                maxWidth: 400, 
                                overflow: 'hidden', 
                                textOverflow: 'ellipsis' 
                              }}>
                                {url.url || 'N/A'}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Chip 
                                label={url.statusCode || 200}
                                color={(url.statusCode || 200) < 400 ? 'success' : 'error'}
                                size="small"
                              />
                            </TableCell>
                            <TableCell>{url.contentType || 'text/html'}</TableCell>
                            <TableCell>{url.size || 0} bytes</TableCell>
                            <TableCell>{url.responseTime || 0}ms</TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>
                </TableContainer>
              ) : (
                <Box sx={{ maxHeight: 400, overflow: 'auto' }}>
                  <UrlTreeView urls={urlsFound} />
                </Box>
              )}
            </TabPanel>

            <TabPanel value={currentTab} index={2}>
              <Box sx={{ 
                height: 400, 
                overflow: 'auto', 
                bgcolor: (theme) => theme.palette.mode === 'dark' ? '#1a1a1a' : '#000000',
                color: (theme) => theme.palette.mode === 'dark' ? '#00ff00' : '#00ff00', // Terminal green
                p: 2,
                fontFamily: 'monospace',
                fontSize: '0.75rem',
                border: 1,
                borderColor: (theme) => theme.palette.mode === 'dark' ? 'grey.700' : 'grey.400',
                borderRadius: 1
              }}>
                {logs.map((log, index) => (
                  <Typography 
                    key={index} 
                    variant="body2" 
                    sx={{ 
                      mb: 0.5,
                      color: 'inherit',
                      fontFamily: 'inherit'
                    }}
                  >
                    {log}
                  </Typography>
                ))}
              </Box>
            </TabPanel>
          </Card>
        </Box>
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose} variant="contained" color="primary">
          Close
        </Button>
      </DialogActions>
    </Dialog>
    </>
  );
};

export default ComprehensiveScanMonitor;