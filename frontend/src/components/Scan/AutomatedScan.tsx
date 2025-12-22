/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unused-vars */
// @ts-nocheck
import React, { useState, useEffect, ChangeEvent, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  FormControl,
  FormLabel,
  FormGroup,
  FormControlLabel,
  Switch,
  Slider,
  Alert,
  CircularProgress,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Chip,
  Divider,
  Paper,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Tabs,
  Tab,
  Stack,
  Select,
  MenuItem,
  InputLabel,
  Badge,
  Grid,
} from '@mui/material';
import {
  PlayArrow as PlayArrowIcon,
  Security as SecurityIcon,
  Settings as SettingsIcon,
  Launch as LaunchIcon,
  Delete as DeleteIcon,
  Add as AddIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Visibility as VisibilityIcon,
  Http as HttpIcon,
  Clear as ClearIcon,
  VisibilityOff as VisibilityOffIcon,
  Send as SendIcon,
  Info as InfoIcon,
  Link as LinkIcon,
  GetApp as DownloadIcon,
  Computer as ComputerIcon,
  Storage as StorageIcon,
  Code as CodeIcon,
  Web as WebIcon,
  Build as BuildIcon,
  Language as LanguageIcon,
  Refresh as RefreshIcon,
  Api as ApiIcon,
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import scanService from '../../services/scanService';
import { zapService } from '../../services/zapService';
import socketService from '../../services/socketService';
import ScanProgressBar from './ScanProgressBar';
import LiveScanMonitor from './LiveScanMonitor';
import RealTimeScanMonitor from './RealTimeScanMonitor';
import ComprehensiveScanMonitor from './ComprehensiveScanMonitor';

// Ensure module syntax under isolatedModules
export { };

declare global {
  namespace JSX {
    interface IntrinsicElements {
      strong: React.DetailedHTMLProps<React.HTMLAttributes<HTMLElement>, HTMLElement>;
      br: React.DetailedHTMLProps<React.HTMLAttributes<HTMLBRElement>, HTMLBRElement>;
      code: React.DetailedHTMLProps<React.HTMLAttributes<HTMLElement>, HTMLElement>;
    }
  }
}

interface ScanConfig {
  targetUrl: string;
  scanName: string;

  // 🔥 NEW: Environment & Aggressiveness Settings
  environment: 'TEST' | 'PRODUCTION' | 'CUSTOM';
  aggressiveness: 'LOW' | 'MEDIUM' | 'HIGH' | 'INSANE';
  safeMode: boolean; // true = read-only, false = full test

  // Traditional Spider Configuration
  spiderEnabled: boolean;
  maxChildren: number;
  maxDepth: number;
  spiderMaxDuration: number;
  recurse: boolean;

  // AJAX Spider Configuration  
  ajaxSpiderEnabled: boolean;
  ajaxSpiderBrowser: 'firefox' | 'chrome' | 'htmlunit';
  ajaxSpiderMaxDepth: number;
  ajaxSpiderMaxDuration: number;

  // Forced Browse Configuration
  forcedBrowseEnabled: boolean;
  forcedBrowseTimeout: number;

  // Active Scan Configuration
  activeScanEnabled: boolean;
  activeScanPolicy: string;
  activeScanMaxDuration: number;
  activeScanIntensity: 'low' | 'medium' | 'high';

  // Passive Scan Configuration
  passiveScanEnabled: boolean;

  // 🔥 NEW: Advanced Attack Tests
  enableSqlInjection: boolean;
  enableXss: boolean;
  enableXxe: boolean;
  enableCommandInjection: boolean;
  enablePathTraversal: boolean;
  enableWafBypass: boolean;
  enableBruteForce: boolean;

  // 🎯 API Deep Dive Configuration
  enableApiDeepDive: boolean;
  apiDeepDiveIntensity: 'standard' | 'comprehensive' | 'full';

  // Authentication Configuration
  authEnabled: boolean;
  authType: 'form' | 'http' | 'script';
  authLoginUrl: string;
  authUsername: string;
  authPassword: string;
  authUsernameParam: string;
  authPasswordParam: string;

  // Advanced Options
  inScopeOnly: boolean;
  excludeUrls: string[];
  includeCookies: boolean;
  followRedirects: boolean;
  contextName: string;
}

const AutomatedScan: React.FC = () => {
  const navigate = useNavigate();

  // Get technology data from navigation state
  const location = useLocation();
  const locationState = location.state as { targetUrl?: string; detectedTechnologies?: any[] } | null;

  const [activeStep, setActiveStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [newExcludeUrl, setNewExcludeUrl] = useState('');
  const [currentWorkflowId, setCurrentWorkflowId] = useState<string | null>(null);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const [showProgressDialog, setShowProgressDialog] = useState(false);
  const [scanProgress, setScanProgress] = useState<any>(null);
  const [showLiveMonitor, setShowLiveMonitor] = useState(false);
  const [showComprehensiveMonitor, setShowComprehensiveMonitor] = useState(false);
  const [isScanning, setIsScanning] = useState(false);

  // Real-time data states
  const [realTimeAlerts, setRealTimeAlerts] = useState<any[]>([]);
  const [realTimeUrls, setRealTimeUrls] = useState<string[]>([]);
  const [totalAlertsFound, setTotalAlertsFound] = useState(0);
  const [totalUrlsFound, setTotalUrlsFound] = useState(0);
  const [newAlertsCount, setNewAlertsCount] = useState(0);
  const [newUrlsCount, setNewUrlsCount] = useState(0);

  // HTTP Request History states
  const [interceptedRequests, setInterceptedRequests] = useState<any[]>([]);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [selectedRequest, setSelectedRequest] = useState<any>(null);
  const [requestDetailsOpen, setRequestDetailsOpen] = useState(false);
  const [selectedTab, setSelectedTab] = useState(0);
  const [editableRequest, setEditableRequest] = useState<any>(null);

  // Technology Detection states
  const [detectedTechnologies, setDetectedTechnologies] = useState<any[]>([]);
  const [techDetectionLoading, setTechDetectionLoading] = useState(false);
  const [techDetectionError, setTechDetectionError] = useState<string | null>(null);
  const [showTechDetails, setShowTechDetails] = useState(false);
  const [config, setConfig] = useState<ScanConfig>({
    targetUrl: locationState?.targetUrl || '',
    scanName: '',

    // 🔥 NEW: Environment & Security Settings
    environment: 'TEST', // Default to TEST for maximum testing
    aggressiveness: 'HIGH', // Default to HIGH for comprehensive scan
    safeMode: false, // Default to false - full testing mode

    // Traditional Spider
    spiderEnabled: true,
    maxChildren: 10,
    maxDepth: 5,
    spiderMaxDuration: 300, // 5 minutes
    recurse: true,

    // AJAX Spider
    ajaxSpiderEnabled: true,
    ajaxSpiderBrowser: 'firefox',
    ajaxSpiderMaxDepth: 10,
    ajaxSpiderMaxDuration: 300, // 5 minutes

    // Forced Browse
    forcedBrowseEnabled: true,
    forcedBrowseTimeout: 120,

    // Active Scan
    activeScanEnabled: true,
    activeScanPolicy: 'Default Policy',
    activeScanMaxDuration: 0, // No limit
    activeScanIntensity: 'medium',

    // Passive Scan
    passiveScanEnabled: true,

    // 🔥 NEW: Advanced Attack Tests (All enabled for comprehensive scan)
    enableSqlInjection: true,
    enableXss: true,
    enableXxe: true,
    enableCommandInjection: true,
    enablePathTraversal: true,
    enableWafBypass: true,
    enableBruteForce: false, // Disabled by default - can be slow

    // 🎯 API Deep Dive (Enabled by default for API testing)
    enableApiDeepDive: true,
    apiDeepDiveIntensity: 'comprehensive', // standard | comprehensive | full

    // Authentication
    authEnabled: false,
    authType: 'form',
    authLoginUrl: '',
    authUsername: '',
    authPassword: '',
    authUsernameParam: 'username',
    authPasswordParam: 'password',

    // Advanced Options
    inScopeOnly: true,
    excludeUrls: [],
    includeCookies: true,
    followRedirects: true,
    contextName: 'Default Context',
  });

  // Initialize detected technologies from navigation state
  useEffect(() => {
    if (locationState?.detectedTechnologies) {
      setDetectedTechnologies(locationState.detectedTechnologies);
      // Auto-configure based on passed technologies
      autoConfigureBasedOnTechnologies(locationState.detectedTechnologies);
    }
  }, [locationState]);
  const steps = [
    'Target & Context',
    'Spider Configuration',
    'AJAX Spider & Forced Browse',
    'Active Scan & Authentication',
    'Review & Start',
  ];

  const handleNext = () => {
    // 🔥 If TEST or PRODUCTION environment selected, skip directly to Review & Start (step 4)
    if (activeStep === 0 && config.environment !== 'CUSTOM') {
      setActiveStep(4); // Jump to last step (Review & Start)
    } else {
      setActiveStep((prevStep) => prevStep + 1);
    }
  };

  const handleBack = () => {
    // 🔥 If on Review step and environment is not CUSTOM, go back to Target & Context (step 0)
    if (activeStep === 4 && config.environment !== 'CUSTOM') {
      setActiveStep(0); // Jump back to first step
    } else {
      setActiveStep((prevStep) => prevStep - 1);
    }
  };

  const handleConfigChange = (field: keyof ScanConfig, value: any) => {
    setConfig(prev => ({
      ...prev,
      [field]: value
    }));

    // Reset technology detection when URL changes
    if (field === 'targetUrl') {
      setDetectedTechnologies([]);
      setTechDetectionError(null);
      setShowTechDetails(false);
    }
  };

  // Technology Detection function
  const detectTechnologies = async (url: string) => {
    if (!url || !isValidUrl(url)) return;

    setTechDetectionLoading(true);
    setTechDetectionError(null);
    setDetectedTechnologies([]);

    try {
      const result = await zapService.detectTechnologies(url);
      console.log('📊 Result.technologies:', result.technologies);

      if (result.technologies && result.technologies.length > 0) {
        setDetectedTechnologies(result.technologies);

        // Auto-configure scan based on detected technologies
        autoConfigureBasedOnTechnologies(result.technologies);
      } else {
        setDetectedTechnologies([]);
      }
    } catch (error) {
      console.error('❌ Technology detection failed:', error);
      setTechDetectionError('Teknoloji tespiti başarısız oldu. Tarama normal şekilde devam edebilir.');
      setDetectedTechnologies([]);
    } finally {
      setTechDetectionLoading(false);
    }
  };

  // Auto-configure scan based on detected technologies
  const autoConfigureBasedOnTechnologies = (technologies: any[]) => {
    const newConfig = { ...config };

    technologies.forEach(tech => {
      const techName = tech.name?.toLowerCase() || '';
      const techType = tech.type?.toLowerCase() || '';

      // Configure based on detected technologies
      if (techName.includes('apache') || techName.includes('nginx')) {
        newConfig.spiderEnabled = true;
        newConfig.forcedBrowseEnabled = true;
      }

      if (techName.includes('php') || techName.includes('asp') || techName.includes('java')) {
        newConfig.activeScanEnabled = true;
        newConfig.activeScanIntensity = 'high';
      }

      if (techName.includes('javascript') || techName.includes('react') || techName.includes('angular') || techName.includes('vue')) {
        newConfig.ajaxSpiderEnabled = true;
        newConfig.ajaxSpiderBrowser = 'chrome';
      }

      if (techName.includes('mysql') || techName.includes('postgresql') || techName.includes('oracle')) {
        newConfig.activeScanEnabled = true;
      }

      if (techName.includes('wordpress') || techName.includes('drupal') || techName.includes('joomla')) {
        newConfig.forcedBrowseEnabled = true;
        newConfig.spiderMaxDuration = 600; // Longer duration for CMS
      }
    });

    setConfig(newConfig);
  };

  // 🔥 NEW: Environment-based configuration
  const handleEnvironmentChange = (environment: 'TEST' | 'PRODUCTION' | 'CUSTOM') => {
    // Only log if environment actually changed
    if (environment === config.environment) return;

    let newConfig = { ...config, environment };

    switch (environment) {
      case 'TEST':
        // 🧪 TEST/STAGING: Maximum aggressiveness WITH TIMEOUTS
        newConfig = {
          ...newConfig,
          aggressiveness: 'INSANE',
          safeMode: false,
          spiderEnabled: true,
          ajaxSpiderEnabled: true,
          forcedBrowseEnabled: true,
          activeScanEnabled: true,
          passiveScanEnabled: true,
          activeScanIntensity: 'high',
          maxDepth: 10,
          maxChildren: 20,
          recurse: true,
          // ⏱️ IMPORTANT: Set timeouts to prevent infinite scans
          spiderMaxDuration: 600, // 10 minutes max for spider
          ajaxSpiderMaxDuration: 600, // 10 minutes max for AJAX spider
          activeScanMaxDuration: 1800, // 30 minutes max for active scan
          forcedBrowseTimeout: 600, // 10 minutes max for forced browse
          // Enable ALL attack tests
          enableSqlInjection: true,
          enableXss: true,
          enableXxe: true,
          enableCommandInjection: true,
          enablePathTraversal: true,
          enableWafBypass: true,
          enableBruteForce: true,
        };
        break;

      case 'PRODUCTION':
        // 🔒 PRODUCTION: Safe mode - read-only tests WITH SHORT TIMEOUTS
        newConfig = {
          ...newConfig,
          aggressiveness: 'LOW',
          safeMode: true,
          spiderEnabled: true,
          ajaxSpiderEnabled: false, // Disable for safety
          forcedBrowseEnabled: false, // Disable for safety
          activeScanEnabled: true,
          passiveScanEnabled: true,
          activeScanIntensity: 'low',
          maxDepth: 3,
          maxChildren: 5,
          recurse: false,
          // ⏱️ SHORT timeouts for production safety
          spiderMaxDuration: 180, // 3 minutes max for spider
          ajaxSpiderMaxDuration: 0, // Disabled
          activeScanMaxDuration: 300, // 5 minutes max for active scan
          forcedBrowseTimeout: 0, // Disabled
          // Disable risky tests
          enableSqlInjection: true, // Safe read-only tests
          enableXss: true, // Safe alert tests
          enableXxe: false, // Risky
          enableCommandInjection: false, // Very risky
          enablePathTraversal: true, // Safe read-only
          enableWafBypass: false, // Risky
          enableBruteForce: false, // Very risky
        };
        break;

      case 'CUSTOM':
        // ⚡ CUSTOM: User decides manually - reasonable defaults
        newConfig = {
          ...newConfig,
          aggressiveness: 'MEDIUM',
          safeMode: false,
          // ⏱️ Reasonable timeouts for custom mode
          spiderMaxDuration: 300, // 5 minutes default
          ajaxSpiderMaxDuration: 300, // 5 minutes default
          activeScanMaxDuration: 900, // 15 minutes default
          forcedBrowseTimeout: 300, // 5 minutes default
        };
        break;
    }

    setConfig(newConfig);
  };

  const addExcludeUrl = () => {
    if (newExcludeUrl.trim() && !config.excludeUrls.includes(newExcludeUrl.trim())) {
      handleConfigChange('excludeUrls', [...config.excludeUrls, newExcludeUrl.trim()]);
      setNewExcludeUrl('');
    }
  };

  const removeExcludeUrl = (url: string) => {
    handleConfigChange('excludeUrls', config.excludeUrls.filter(u => u !== url));
  };

  // HTTP Request History functions
  const fetchHttpHistory = useCallback(async () => {
    if (!autoRefresh || !isScanning) return;

    try {
      const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';

      const response = await fetch(`${API_BASE_URL}/api/zap/history?count=100&start=0`);

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();

      if (data.success && data.data && data.data.requests) {
        setInterceptedRequests(data.data.requests);
      } else {
        // Fallback - try to get requests from different structure
        if (data.data && Array.isArray(data.data)) {
          setInterceptedRequests(data.data);
        } else if (Array.isArray(data)) {
          setInterceptedRequests(data);
        }
      }
    } catch (error) {
      console.error('❌ Failed to fetch HTTP history:', error);
      // Don't clear existing requests on error, just log it
    }
  }, [autoRefresh, isScanning]);

  const clearRequests = () => {
    setInterceptedRequests([]);
  };

  const generateReport = async (format: 'json' | 'html' = 'html') => {
    setLoading(true);
    try {
      const reportData = {
        timestamp: new Date().toISOString(),
        target: config.targetUrl,
        scanConfig: config,
        totalRequests: interceptedRequests.length,
        totalAlerts: totalAlertsFound,
        realTimeAlerts: realTimeAlerts,
        scanProgress: scanProgress,
        currentWorkflowId: currentWorkflowId,
        currentScanId: currentScanId,
        isScanning: isScanning,
        interceptedRequests: interceptedRequests.map(req => ({
          method: req.method,
          url: req.url,
          timestamp: req.timestamp,
          status: req.status,
          duration: req.duration,
          headers: req.headers,
          responseHeaders: req.responseHeaders
        })),
        vulnerabilities: realTimeAlerts.map(alert => ({
          name: alert.name,
          description: alert.description,
          severity: alert.risk || alert.severity,
          url: alert.url,
          param: alert.param,
          solution: alert.solution,
          reference: alert.reference,
          timestamp: alert.timestamp
        })),
        summary: {
          vulnerabilitiesByRisk: {
            high: realTimeAlerts.filter(a => a.risk === 'High' || a.severity === 'high').length,
            medium: realTimeAlerts.filter(a => a.risk === 'Medium' || a.severity === 'medium').length,
            low: realTimeAlerts.filter(a => a.risk === 'Low' || a.severity === 'low').length,
            informational: realTimeAlerts.filter(a => a.risk === 'Informational' || a.severity === 'info').length
          },
          scanType: config.spiderEnabled ? (config.activeScanEnabled ? 'Full Scan (Spider + Active)' : 'Spider Only') : 'Custom',
          scanDuration: scanProgress?.duration || 'N/A',
          totalUrlsDiscovered: totalUrlsFound,
          scanCompleted: !isScanning && scanProgress?.status === 'completed'
        }
      };

      if (format === 'html') {
        // Backend'e HTML raporu oluşturma isteği gönder
        const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';
        const response = await fetch(`${API_BASE_URL}/api/reports/generate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: 'automated-scan',
            data: reportData,
            format: 'html'
          })
        });

        if (response.ok) {
          // HTML olarak indir
          const blob = await response.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `SiberZed-Automated-Scan-Report-${new Date().toISOString().split('T')[0]}.html`;
          document.body.appendChild(a);
          a.click();
          window.URL.revokeObjectURL(url);
          document.body.removeChild(a);

          alert('✅ HTML raporu başarıyla indirildi!');
        } else {
          throw new Error('HTML raporu oluşturulamadı');
        }
      } else {
        // JSON formatında indir (fallback)
        const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `SiberZed-Automated-Report-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        alert('⚠️ HTML raporu oluşturulamadı. JSON formatında indirildi.');
      }
    } catch (error) {
      console.error('Report generation failed:', error);

      // Fallback: JSON formatında indir
      const reportData = {
        timestamp: new Date().toISOString(),
        target: config.targetUrl,
        scanConfig: config,
        totalRequests: interceptedRequests.length,
        totalAlerts: totalAlertsFound,
        realTimeAlerts: realTimeAlerts,
        scanProgress: scanProgress,
        vulnerabilities: realTimeAlerts,
        summary: {
          vulnerabilitiesByRisk: {
            high: realTimeAlerts.filter(a => a.risk === 'High' || a.severity === 'high').length,
            medium: realTimeAlerts.filter(a => a.risk === 'Medium' || a.severity === 'medium').length,
            low: realTimeAlerts.filter(a => a.risk === 'Low' || a.severity === 'low').length,
            informational: realTimeAlerts.filter(a => a.risk === 'Informational' || a.severity === 'info').length
          }
        }
      };

      const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `SiberZed-Automated-Report-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      alert('❌ HTML raporu oluşturulamadı. JSON formatında indirildi.');
    } finally {
      setLoading(false);
    }
  };

  const debugHttpHistory = async () => {
    try {
      const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';

      const response = await fetch(`${API_BASE_URL}/api/zap/debug`);
      const data = await response.json();

      alert(`Debug Info:\nZAP Connected: ${data.debug?.zapConnected}\nRaw History Count: ${data.debug?.rawHistoryCount}\nCheck console for details`);
    } catch (error) {
      console.error('❌ Debug failed:', error);
      alert('Debug failed - check console for details');
    }
  };

  const showRequestDetails = (request: any) => {
    setSelectedRequest(request);
    setEditableRequest({ ...request });
    setSelectedTab(0);
    setRequestDetailsOpen(true);
  };

  const sendModifiedRequest = async () => {
    if (!editableRequest) return;

    setLoading(true);
    try {
      const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';
      const response = await fetch(`${API_BASE_URL}/api/manual-scan/execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          command: `${editableRequest.method} ${editableRequest.url}`,
          targetUrl: editableRequest.url,
          method: editableRequest.method,
          headers: editableRequest.headers || {},
          body: editableRequest.body || '',
          request: editableRequest,
        })
      });

      const data = await response.json();
      if (data.success) {
        // Refresh HTTP history to show the new request
        fetchHttpHistory();
        setRequestDetailsOpen(false);
      } else {
        setError(data.message || 'Failed to send request');
      }
    } catch (err) {
      setError('Failed to send modified request');
    } finally {
      setLoading(false);
    }
  };

  // Auto-refresh HTTP history during scanning
  useEffect(() => {
    let interval: NodeJS.Timeout | null = null;

    if (autoRefresh && isScanning) {
      fetchHttpHistory(); // Initial fetch
      interval = setInterval(() => {
        fetchHttpHistory();
      }, 2000); // Refresh every 2 seconds for more real-time updates
    } else {
    }

    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [autoRefresh, isScanning, fetchHttpHistory]);

  // Real-time socket listeners for alerts and URLs
  useEffect(() => {
    if (currentScanId && isScanning) {

      // Connect to socket
      socketService.connect().then(() => {
        socketService.joinScanRoom(currentScanId);

        // Listen for real-time alerts
        socketService.onAlertFound((data) => {
          if (data.scanId === currentScanId) {
            setRealTimeAlerts(prev => [...prev, data.alert]);
            setTotalAlertsFound(data.totalAlerts);
            setNewAlertsCount(prev => prev + 1);
          }
        });

        // Listen for real-time URLs
        socketService.onUrlFound((data) => {
          if (data.scanId === currentScanId) {
            setRealTimeUrls(prev => [...prev, data.url]);
            setTotalUrlsFound(data.totalUrls);
            setNewUrlsCount(prev => prev + 1);
          }
        });

        // Listen for enhanced scan progress
        socketService.onRealTimeScanProgress((data) => {
          if (data.scanId === currentScanId) {
            setTotalAlertsFound(data.alertsFound);
            setTotalUrlsFound(data.urlsFound);

            // Update progress dialog if showing
            if (scanProgress) {
              setScanProgress(prev => ({
                ...prev,
                alertsFound: data.alertsFound,
                urlsFound: data.urlsFound,
                lastUpdate: data.timestamp
              }));
            }
          }
        });
      }).catch(error => {
        console.error('Failed to connect to socket:', error);
      });

      return () => {
        // Cleanup listeners
        socketService.offAlertFound();
        socketService.offUrlFound();
        socketService.offRealTimeScanProgress();
        if (currentScanId) {
          socketService.leaveScanRoom(currentScanId);
        }
      };
    }
  }, [currentScanId, isScanning, scanProgress]);

  const validateStep = (step: number): boolean => {
    switch (step) {
      case 0:
        return !!config.targetUrl && isValidUrl(config.targetUrl);
      case 1:
        return config.spiderEnabled; // At least spider should be enabled
      case 2:
        return true; // AJAX Spider and Forced Browse are optional
      case 3:
        return true; // Active Scan and Authentication are optional
      case 4:
        return true; // Review step
      default:
        return false;
    }
  };

  const isValidUrl = (url: string): boolean => {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  };

  // Reset real-time monitoring states
  const resetRealTimeStates = useCallback(() => {
    setRealTimeAlerts([]);
    setRealTimeUrls([]);
    setTotalAlertsFound(0);
    setTotalUrlsFound(0);
    setNewAlertsCount(0);
    setNewUrlsCount(0);
  }, []);

  const startScan = async () => {
    try {
      setLoading(true);
      setError(null);

      // Reset real-time states for new scan
      resetRealTimeStates();

      // Set scanning to true immediately to start HTTP monitoring
      setIsScanning(true);

      // Prepare ZAP workflow options
      const workflowOptions = {
        targetUrl: config.targetUrl,
        enableSpider: true, // Always enable spider
        enableAjaxSpider: config.ajaxSpiderEnabled,
        enableActiveScan: config.activeScanEnabled,
        contextName: config.contextName,

        // 🔥 NEW: Environment & Security Settings
        environment: config.environment,
        aggressiveness: config.aggressiveness,
        safeMode: config.safeMode,

        spiderOptions: {
          maxChildren: config.maxChildren,
          maxDepth: config.maxDepth,
          maxDuration: config.spiderMaxDuration
        },
        ajaxSpiderOptions: {
          enabled: config.ajaxSpiderEnabled,
          browser: config.ajaxSpiderBrowser,
          maxCrawlDepth: config.ajaxSpiderMaxDepth,
          maxDuration: config.ajaxSpiderMaxDuration
        },
        activeScanOptions: {
          enabled: config.activeScanEnabled,
          scanPolicyName: config.activeScanPolicy,
          maxDuration: config.activeScanMaxDuration,
          recurse: config.recurse,
          intensity: config.activeScanIntensity
        },

        // 🔥 NEW: Advanced Attack Tests
        advancedTests: {
          enableSqlInjection: config.enableSqlInjection,
          enableXss: config.enableXss,
          enableXxe: config.enableXxe,
          enableCommandInjection: config.enableCommandInjection,
          enablePathTraversal: config.enablePathTraversal,
          enableWafBypass: config.enableWafBypass,
          enableBruteForce: config.enableBruteForce,
        },

        // 🎯 API Deep Dive
        apiDeepDive: {
          enabled: config.enableApiDeepDive,
          intensity: config.apiDeepDiveIntensity,
        },

        authConfig: config.authEnabled ? {
          type: config.authType,
          loginUrl: config.authLoginUrl,
          username: config.authUsername,
          password: config.authPassword,
          usernameParam: config.authUsernameParam,
          passwordParam: config.authPasswordParam
        } : undefined
      };


      // Start ZAP automated workflow
      const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';
      const token = localStorage.getItem('siberZed_token');
      const response = await fetch(`${API_BASE_URL}/api/zap/workflow/start`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {})
        },
        body: JSON.stringify(workflowOptions)
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();

      if (data.success && data.data.workflowId) {
        const workflowId = data.data.workflowId;
        const scanId = data.data.scanId;
        setCurrentWorkflowId(workflowId);
        setCurrentScanId(scanId);
        setSuccess(true);

        console.log('📊 Scan ID:', scanId);

        // Show comprehensive monitor
        setShowComprehensiveMonitor(true);

        // Reset stepper
        setActiveStep(0);
      } else {
        throw new Error('No workflow ID received from ZAP server');
      }
    } catch (err) {
      console.error('❌ Failed to start ZAP workflow:', err);
      setError(err instanceof Error ? err.message : 'Failed to start ZAP automated scan');
      setIsScanning(false);
    } finally {
      setLoading(false);
    }
  };

  const handleScanComplete = useCallback((workflowId: string) => {
    setIsScanning(false);
    // Keep monitor open to show final results

    // Final snapshot of real-time data

    // Trigger a scan history refresh by emitting a custom event
    window.dispatchEvent(new CustomEvent('scanCompleted', {
      detail: { workflowId, scanId: currentScanId }
    }));
  }, [totalAlertsFound, totalUrlsFound, currentScanId]);

  const handleCloseMonitor = useCallback(() => {
    setShowComprehensiveMonitor(false);
    setShowLiveMonitor(false);
    setCurrentWorkflowId(null);
    setCurrentScanId(null);
    setSuccess(false);
    setIsScanning(false);

    // Reset real-time states when closing monitor
    resetRealTimeStates();
  }, [resetRealTimeStates]);

  const renderTargetConfiguration = () => (
    <Box>
      <Typography variant="h6" gutterBottom>
        Target Configuration
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        Specify the target URL and basic scan parameters
      </Typography>      <TextField
        fullWidth
        label="Target URL"
        placeholder="https://app.ibb.gov.tr"
        value={config.targetUrl}
        onChange={(e) => handleConfigChange('targetUrl', e.target.value)}
        error={Boolean(config.targetUrl && !isValidUrl(config.targetUrl))}
        helperText={
          config.targetUrl && !isValidUrl(config.targetUrl)
            ? 'Lütfen geçerli bir URL girin'
            : 'Test edilecek uygulamanın ana URL\'si'
        }
        sx={{ mb: 2 }}
      />

      {/* Technology Detection Button */}
      {config.targetUrl && isValidUrl(config.targetUrl) && (
        <Box sx={{ mb: 3, display: 'flex', gap: 2 }}>
          <Button
            variant="contained"
            startIcon={<BuildIcon />}
            onClick={() => detectTechnologies(config.targetUrl)}
            disabled={techDetectionLoading}
            color="secondary"
            size="medium"
          >
            {techDetectionLoading ? 'Teknolojiler Tespit Ediliyor...' : '🔍 Teknoloji Gör'}
          </Button>

          {detectedTechnologies.length > 0 && (
            <Button
              variant="outlined"
              startIcon={<VisibilityIcon />}
              onClick={() => setShowTechDetails(!showTechDetails)}
              size="medium"
            >
              {showTechDetails ? 'Detayları Gizle' : 'Detayları Göster'}
            </Button>
          )}
        </Box>
      )}

      <TextField
        fullWidth
        label="Scan Name (Optional)"
        placeholder="İBB Web Uygulaması Güvenlik Taraması"
        value={config.scanName}
        onChange={(e) => handleConfigChange('scanName', e.target.value)}
        helperText="Taramanıza unutulmayacak bir isim verin"
        sx={{ mb: 3 }}
      />

      {/* 🔥 NEW: Environment Selection */}
      <Card variant="outlined" sx={{ mb: 3, p: 2, bgcolor: 'background.default' }}>
        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <SecurityIcon color="primary" />
          Tarama Ortamı Seçin
        </Typography>

        <FormControl component="fieldset" fullWidth>
          <Stack spacing={2} sx={{ mt: 2 }}>
            {/* TEST/STAGING Option */}
            <Paper
              elevation={config.environment === 'TEST' ? 4 : 0}
              sx={{
                p: 2,
                border: 2,
                borderColor: config.environment === 'TEST' ? 'success.main' : 'divider',
                cursor: 'pointer',
                transition: 'all 0.3s',
                '&:hover': { borderColor: 'success.main', bgcolor: 'action.hover' }
              }}
              onClick={() => {
                handleConfigChange('environment', 'TEST');
                handleConfigChange('aggressiveness', 'INSANE');
                handleConfigChange('safeMode', false);
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
                <Box
                  sx={{
                    width: 24,
                    height: 24,
                    borderRadius: '50%',
                    border: 2,
                    borderColor: config.environment === 'TEST' ? 'success.main' : 'divider',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                    mt: 0.5
                  }}
                >
                  {config.environment === 'TEST' && (
                    <Box sx={{ width: 14, height: 14, borderRadius: '50%', bgcolor: 'success.main' }} />
                  )}
                </Box>
                <Box sx={{ flex: 1 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 'bold', color: 'success.main' }}>
                    🧪 TEST / STAGING ORTAMI
                    <Chip label="ÖNERİLEN" size="small" color="success" sx={{ ml: 1 }} />
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                    Maksimum agresiflik • Tüm testler aktif • Sınırsız istek • Detaylı rapor
                  </Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                    ✓ SQL Injection • XSS • XXE • Command Injection • WAF Bypass • Path Traversal
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'warning.main', mt: 0.5, display: 'block' }}>
                    ⚠️ Yoğun testler - Sadece test/staging ortamları için
                  </Typography>
                </Box>
              </Box>
            </Paper>

            {/* PRODUCTION Option */}
            <Paper
              elevation={config.environment === 'PRODUCTION' ? 4 : 0}
              sx={{
                p: 2,
                border: 2,
                borderColor: config.environment === 'PRODUCTION' ? 'primary.main' : 'divider',
                cursor: 'pointer',
                transition: 'all 0.3s',
                '&:hover': { borderColor: 'primary.main', bgcolor: 'action.hover' }
              }}
              onClick={() => {
                handleConfigChange('environment', 'PRODUCTION');
                handleConfigChange('aggressiveness', 'LOW');
                handleConfigChange('safeMode', true);
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
                <Box
                  sx={{
                    width: 24,
                    height: 24,
                    borderRadius: '50%',
                    border: 2,
                    borderColor: config.environment === 'PRODUCTION' ? 'primary.main' : 'divider',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                    mt: 0.5
                  }}
                >
                  {config.environment === 'PRODUCTION' && (
                    <Box sx={{ width: 14, height: 14, borderRadius: '50%', bgcolor: 'primary.main' }} />
                  )}
                </Box>
                <Box sx={{ flex: 1 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 'bold', color: 'primary.main' }}>
                    🛡️ CANLI UYGULAMA (PRODUCTION)
                    <Chip label="GÜVENLİ" size="small" color="primary" sx={{ ml: 1 }} />
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                    Düşük agresiflik • Safe mode • Rate limiting • DB-friendly • Sadece okuma testleri
                  </Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                    ✓ Header kontrolleri • Cookie güvenliği • SSL/TLS kontrol • Pasif tarama
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'success.main', mt: 0.5, display: 'block' }}>
                    ✓ Veritabanını ve uygulamayı çökertmez
                  </Typography>
                </Box>
              </Box>
            </Paper>

            {/* CUSTOM Option */}
            <Paper
              elevation={config.environment === 'CUSTOM' ? 4 : 0}
              sx={{
                p: 2,
                border: 2,
                borderColor: config.environment === 'CUSTOM' ? 'secondary.main' : 'divider',
                cursor: 'pointer',
                transition: 'all 0.3s',
                '&:hover': { borderColor: 'secondary.main', bgcolor: 'action.hover' }
              }}
              onClick={() => {
                handleConfigChange('environment', 'CUSTOM');
                handleConfigChange('aggressiveness', 'MEDIUM');
                handleConfigChange('safeMode', false);
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
                <Box
                  sx={{
                    width: 24,
                    height: 24,
                    borderRadius: '50%',
                    border: 2,
                    borderColor: config.environment === 'CUSTOM' ? 'secondary.main' : 'divider',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                    mt: 0.5
                  }}
                >
                  {config.environment === 'CUSTOM' && (
                    <Box sx={{ width: 14, height: 14, borderRadius: '50%', bgcolor: 'secondary.main' }} />
                  )}
                </Box>
                <Box sx={{ flex: 1 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 'bold', color: 'secondary.main' }}>
                    ⚙️ ÖZEL AYARLAR (CUSTOM)
                    <Chip label="İLERİ SEVİYE" size="small" color="secondary" sx={{ ml: 1 }} />
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                    Manuel kontrol • İleri seviye ayarlar • Adım adım konfigürasyon
                  </Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                    ✓ Spider depth • Scan policies • Attack strength • Test türleri • Timeout ayarları
                  </Typography>
                </Box>
              </Box>
            </Paper>
          </Stack>
        </FormControl>

        {/* Environment Info Alert */}
        {config.environment === 'TEST' && (
          <Alert severity="success" sx={{ mt: 2 }}>
            <Typography variant="body2">
              <strong>TEST Ortamı:</strong> Maksimum 120 dakika, tüm güvenlik testleri aktif, WAF bypass teknikleri dahil.
            </Typography>
          </Alert>
        )}
        {config.environment === 'PRODUCTION' && (
          <Alert severity="info" sx={{ mt: 2 }}>
            <Typography variant="body2">
              <strong>PRODUCTION Ortamı:</strong> Maksimum 30 dakika, sadece güvenli testler, saniyede 2 istek, veritabanı dostu.
            </Typography>
          </Alert>
        )}
        {config.environment === 'CUSTOM' && (
          <Alert severity="warning" sx={{ mt: 2 }}>
            <Typography variant="body2">
              <strong>CUSTOM Ortamı:</strong> Aşağıdaki gelişmiş ayarları kendiniz yapılandırabilirsiniz.
            </Typography>
          </Alert>
        )}
      </Card>

      <Alert severity="info" sx={{ mt: 2 }}>
        <Typography variant="body2">
          <Typography component="span" sx={{ fontWeight: 'bold' }}>Note:</Typography> The automated scan will perform comprehensive security testing including:
        </Typography>
        <List dense sx={{ mt: 1 }}>
          <ListItem sx={{ py: 0 }}>
            <ListItemIcon sx={{ minWidth: 32 }}>
              <CheckCircleIcon color="success" fontSize="small" />
            </ListItemIcon>
            <ListItemText primary="Spider crawling to discover all pages" />
          </ListItem>
          <ListItem sx={{ py: 0 }}>
            <ListItemIcon sx={{ minWidth: 32 }}>
              <CheckCircleIcon color="success" fontSize="small" />
            </ListItemIcon>
            <ListItemText primary="Passive security analysis" />
          </ListItem>
          <ListItem sx={{ py: 0 }}>
            <ListItemIcon sx={{ minWidth: 32 }}>
              <CheckCircleIcon color="success" fontSize="small" />
            </ListItemIcon>
            <ListItemText primary="Active vulnerability scanning" />
          </ListItem>
        </List>
      </Alert>

      {/* Technology Detection Error */}
      {config.targetUrl && isValidUrl(config.targetUrl) && techDetectionError && (
        <Alert severity="warning" sx={{ mt: 2, mb: 3 }}>
          <Typography variant="body2">
            <strong>Teknoloji Tespiti Hatası:</strong> {techDetectionError}
            <br />
            <Button
              size="small"
              onClick={() => detectTechnologies(config.targetUrl)}
              sx={{ mt: 1 }}
              startIcon={<RefreshIcon />}
            >
              Tekrar Dene
            </Button>
          </Typography>
        </Alert>
      )}

      {/* Technology Detection Results */}
      {config.targetUrl && isValidUrl(config.targetUrl) && detectedTechnologies.length > 0 && (
        <Card sx={{ mt: 3, mb: 3 }} variant="outlined">
          <CardContent>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <BuildIcon color="success" />
                <Typography variant="h6" color="success.main">
                  ✅ Teknoloji Tespiti Tamamlandı
                </Typography>
              </Box>
              <Chip
                label={`${detectedTechnologies.length} teknoloji tespit edildi`}
                color="success"
                size="small"
              />
            </Box>

            {/* Technology Summary */}
            <Box sx={{ mb: 3 }}>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Tespit edilen teknolojiler:
              </Typography>

              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
                {detectedTechnologies.slice(0, showTechDetails ? detectedTechnologies.length : 8).map((tech, index) => {
                  const getIcon = (type: string) => {
                    switch (type?.toLowerCase()) {
                      case 'web server': return <ComputerIcon fontSize="small" />;
                      case 'database': return <StorageIcon fontSize="small" />;
                      case 'programming language': return <CodeIcon fontSize="small" />;
                      case 'javascript framework': return <WebIcon fontSize="small" />;
                      case 'cms': return <LanguageIcon fontSize="small" />;
                      default: return <BuildIcon fontSize="small" />;
                    }
                  };

                  const getColor = (confidence: string) => {
                    switch (confidence?.toLowerCase()) {
                      case 'high': return 'success';
                      case 'medium': return 'warning';
                      case 'low': return 'info';
                      default: return 'default';
                    }
                  };

                  return (
                    <Chip
                      key={index}
                      icon={getIcon(tech.type)}
                      label={`${tech.name} (${tech.confidence || 'Medium'})`}
                      color={getColor(tech.confidence) as any}
                      size="small"
                      variant="outlined"
                    />
                  );
                })}
              </Box>

              {detectedTechnologies.length > 8 && (
                <Button
                  size="small"
                  onClick={() => setShowTechDetails(!showTechDetails)}
                  startIcon={showTechDetails ? <VisibilityOffIcon /> : <VisibilityIcon />}
                  sx={{ mb: 2 }}
                >
                  {showTechDetails ? 'Daha az göster' : `${detectedTechnologies.length - 8} teknoloji daha`}
                </Button>
              )}
            </Box>

            {/* Smart Scan Recommendations */}
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 'bold' }}>
                🎯 Akıllı Tarama Önerileri:
              </Typography>

              <Grid container spacing={2}>
                {/* Automated Scan Recommendation */}
                <Grid item xs={12} md={6}>
                  <Card variant="outlined" sx={{ p: 2, height: '100%' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                      <SecurityIcon color="primary" />
                      <Typography variant="subtitle2" color="primary">
                        Otomatik Kapsamlı Tarama
                      </Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      Tespit edilen teknolojilere göre optimize edilmiş tam otomatik güvenlik taraması
                    </Typography>

                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 2 }}>
                      {detectedTechnologies.some(t => t.name?.toLowerCase().includes('javascript') || t.type?.toLowerCase().includes('javascript')) && (
                        <Chip label="AJAX Spider Aktif" size="small" color="info" />
                      )}
                      {detectedTechnologies.some(t => t.type?.toLowerCase().includes('database')) && (
                        <Chip label="Yoğun DB Taraması" size="small" color="warning" />
                      )}
                      {detectedTechnologies.some(t => t.type?.toLowerCase().includes('cms')) && (
                        <Chip label="CMS Optimizasyonu" size="small" color="secondary" />
                      )}
                      <Chip label="Tüm Güvenlik Kontrolleri" size="small" color="success" />
                    </Box>

                    <Button
                      variant="contained"
                      startIcon={<PlayArrowIcon />}
                      fullWidth
                      color="primary"
                      onClick={() => {
                        // Auto-configure and start automated scan
                        autoConfigureBasedOnTechnologies(detectedTechnologies);
                        // You can add navigation to automated scan here if needed
                      }}
                    >
                      Otomatik Tarama Başlat
                    </Button>
                  </Card>
                </Grid>

                {/* Manual Scan Recommendation */}
                <Grid item xs={12} md={6}>
                  <Card variant="outlined" sx={{ p: 2, height: '100%' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                      <SettingsIcon color="secondary" />
                      <Typography variant="subtitle2" color="secondary">
                        Manuel Hedefli Tarama
                      </Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      Tespit edilen teknolojilere özel manuel araçlar ve tekniklerle detaylı inceleme
                    </Typography>

                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 2 }}>
                      {detectedTechnologies.some(t => t.name?.toLowerCase().includes('php')) && (
                        <Chip label="PHP Zafiyetleri" size="small" color="error" />
                      )}
                      {detectedTechnologies.some(t => t.name?.toLowerCase().includes('sql') || t.type?.toLowerCase().includes('database')) && (
                        <Chip label="SQL Injection" size="small" color="error" />
                      )}
                      {detectedTechnologies.some(t => t.type?.toLowerCase().includes('cms')) && (
                        <Chip label="CMS Exploit'ları" size="small" color="warning" />
                      )}
                      <Chip label="Özel Payloadlar" size="small" color="info" />
                    </Box>

                    <Button
                      variant="outlined"
                      startIcon={<SettingsIcon />}
                      fullWidth
                      color="secondary"
                      onClick={() => {
                        // Navigate to manual scan with technology context
                        navigate('/manual-scan', {
                          state: {
                            targetUrl: config.targetUrl,
                            detectedTechnologies: detectedTechnologies
                          }
                        });
                      }}
                    >
                      Manuel Tarama Aç
                    </Button>
                  </Card>
                </Grid>
              </Grid>
            </Box>

            {/* Technology Details */}
            {showTechDetails && (
              <Box>
                <Divider sx={{ my: 2 }} />
                <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 'bold' }}>
                  📋 Detaylı Teknoloji Analizi:
                </Typography>

                {/* Group technologies by type */}
                {['Web Server', 'Programming Language', 'Database', 'JavaScript Framework', 'CMS', 'Session Management'].map(type => {
                  const techsOfType = detectedTechnologies.filter(tech => tech.type === type);
                  if (techsOfType.length === 0) return null;

                  return (
                    <Box key={type} sx={{ mb: 2 }}>
                      <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 1 }}>
                        {type}s:
                      </Typography>
                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, ml: 2 }}>
                        {techsOfType.map((tech, index) => (
                          <Chip
                            key={index}
                            label={`${tech.name} - ${tech.confidence}`}
                            size="small"
                            variant="filled"
                            color={tech.confidence === 'High' ? 'success' : tech.confidence === 'Medium' ? 'warning' : 'info'}
                          />
                        ))}
                      </Box>
                    </Box>
                  );
                })}
              </Box>
            )}
          </CardContent>
        </Card>
      )}
    </Box>
  );

  const renderScanSettings = () => (
    <Box>
      <Typography variant="h6" gutterBottom>
        Advanced Settings
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        Configure scan behavior and limitations
      </Typography>

      <Card variant="outlined" sx={{ mb: 3 }}>        <CardContent>
        <Typography variant="subtitle1" gutterBottom>
          Spider Configuration
        </Typography>

        <FormGroup>
          <FormControlLabel
            control={
              <Switch
                checked={config.spiderEnabled}
                onChange={(e) => handleConfigChange('spiderEnabled', e.target.checked)}
              />
            }
            label="Enable Spider"
            sx={{ mb: 2 }}
          />

          <FormControlLabel
            control={
              <Switch
                checked={config.recurse}
                onChange={(e) => handleConfigChange('recurse', e.target.checked)}
                disabled={!config.spiderEnabled}
              />
            }
            label="Recursive Crawling"
            sx={{ mb: 2 }}
          />
        </FormGroup>

        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          <strong>Spider:</strong> Web sitesindeki tüm sayfaları keşfeder<br />
          <strong>Recursive Crawling:</strong> Alt sayfalardan başka sayfalara geçer
        </Typography><Box sx={{ mb: 2 }}>
          <Typography gutterBottom>
            Max Children: {config.maxChildren}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            Maksimum taranacak alt sayfa sayısı. Küçük sayılar daha hızlı, büyük sayılar daha kapsamlı tarama sağlar.
          </Typography>
          <Slider
            value={config.maxChildren}
            onChange={(_, value) => handleConfigChange('maxChildren', value)}
            min={1}
            max={50}
            marks={[
              { value: 1, label: '1' },
              { value: 10, label: '10' },
              { value: 25, label: '25' },
              { value: 50, label: '50' },
            ]}
            disabled={!config.spiderEnabled}
          />
        </Box>
      </CardContent>
      </Card>

      <Card variant="outlined" sx={{ mb: 3 }}>        <CardContent>
        <Typography variant="subtitle1" gutterBottom>
          Scan Options
        </Typography>

        <FormGroup>
          <FormControlLabel
            control={
              <Switch
                checked={config.activeScanEnabled}
                onChange={(e) => handleConfigChange('activeScanEnabled', e.target.checked)}
              />
            }
            label="Active Scan"
            sx={{ mb: 2 }}
          />

          <FormControlLabel
            control={
              <Switch
                checked={config.passiveScanEnabled}
                onChange={(e) => handleConfigChange('passiveScanEnabled', e.target.checked)}
              />
            }
            label="Passive Scan"
            sx={{ mb: 2 }}
          />

          <FormControlLabel
            control={
              <Switch
                checked={config.inScopeOnly}
                onChange={(e) => handleConfigChange('inScopeOnly', e.target.checked)}
              />
            }
            label="In Scope Only"
            sx={{ mb: 2 }}
          />
        </FormGroup>

        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          <strong>Active Scan:</strong> Güvenlik açıklarını aktif olarak test eder<br />
          <strong>Passive Scan:</strong> Trafiği pasif olarak analiz eder<br />
          <strong>In Scope Only:</strong> Sadece hedef domain'deki sayfaları tarar
        </Typography>
      </CardContent>
      </Card>

      <Card variant="outlined">
        <CardContent>          <Typography variant="subtitle1" gutterBottom>
          Exclude URLs
        </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            Taramadan hariç tutulacak URL'ler (regex desenleri desteklenir)
          </Typography>
          <Alert severity="info" sx={{ mb: 2 }}>
            <Typography variant="body2">
              <strong>Örnek desenler:</strong><br />
              • <code>.*\.css.*</code> - CSS dosyalarını hariç tut<br />
              • <code>.*\.js.*</code> - JavaScript dosyalarını hariç tut<br />
              • <code>.*logout.*</code> - Logout sayfalarını hariç tut<br />
              • <code>.*admin.*</code> - Admin sayfalarını hariç tut
            </Typography>
          </Alert>          <Box display="flex" gap={1} mb={2}>
            <TextField
              fullWidth
              size="small"
              placeholder="Örn: .*\.css.*|.*\.js.*|.*logout.*|.*admin.*"
              value={newExcludeUrl}
              onChange={(e) => setNewExcludeUrl(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && addExcludeUrl()}
              helperText="Enter tuşuna basarak da ekleyebilirsiniz"
            />
            <Button
              variant="outlined"
              startIcon={<AddIcon />}
              onClick={addExcludeUrl}
              disabled={!newExcludeUrl.trim()}
            >
              Ekle
            </Button>
          </Box>

          {config.excludeUrls.length > 0 && (
            <Box>
              {config.excludeUrls.map((url, index) => (
                <Chip
                  key={index}
                  label={url}
                  onDelete={() => removeExcludeUrl(url)}
                  sx={{ mr: 1, mb: 1 }}
                />
              ))}
            </Box>
          )}
        </CardContent>
      </Card>
    </Box>
  );

  const renderReview = () => (
    <Box>
      <Typography variant="h6" gutterBottom>
        Review Configuration
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        Please review your scan configuration before starting
      </Typography>

      <Card variant="outlined" sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom color="primary">
            Target Information
          </Typography>
          <Typography variant="body2" gutterBottom>
            <strong>URL:</strong> {config.targetUrl}
          </Typography>
          <Typography variant="body2" gutterBottom>
            <strong>Name:</strong> {config.scanName || 'Auto-generated'}
          </Typography>
        </CardContent>
      </Card>

      <Card variant="outlined" sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom color="primary">
            Scan Configuration
          </Typography>
          <Box display="flex" flexWrap="wrap" gap={1}>
            {config.spiderEnabled && (
              <Chip label="Spider Enabled" color="primary" variant="outlined" />
            )}
            {config.activeScanEnabled && (
              <Chip label="Active Scan" color="primary" variant="outlined" />
            )}
            {config.passiveScanEnabled && (
              <Chip label="Passive Scan" color="primary" variant="outlined" />
            )}
            {config.recurse && (
              <Chip label="Recursive" color="secondary" variant="outlined" />
            )}
            {config.inScopeOnly && (
              <Chip label="In Scope Only" color="secondary" variant="outlined" />
            )}
          </Box>
          <Typography variant="body2" sx={{ mt: 2 }}>
            <strong>Max Children:</strong> {config.maxChildren}
          </Typography>
        </CardContent>
      </Card>

      {config.excludeUrls.length > 0 && (
        <Card variant="outlined" sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="subtitle1" gutterBottom color="primary">
              Excluded URLs
            </Typography>
            <List dense>
              {config.excludeUrls.map((url, index) => (
                <ListItem key={index} sx={{ py: 0 }}>
                  <ListItemText primary={url} />
                </ListItem>
              ))}
            </List>
          </CardContent>
        </Card>
      )}

      <Alert severity="warning" sx={{ mb: 3 }}>
        <Typography variant="body2">
          <strong>Important:</strong> Automated scans can take significant time depending on the target size.
          You can monitor progress in the Scan History section.
        </Typography>
      </Alert>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}      {success && (
        <Alert severity="success" sx={{ mb: 3 }}>
          Scan started successfully!
          {currentWorkflowId && (
            <Button
              size="small"
              startIcon={<VisibilityIcon />}
              onClick={() => setShowProgressDialog(true)}
              sx={{ ml: 1 }}
            >
              View Progress
            </Button>
          )}
        </Alert>
      )}
    </Box>
  ); const getStepContent = (step: number) => {
    switch (step) {
      case 0:
        // Target & Context Configuration
        return (
          <Card variant="outlined" sx={{ mb: 2 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                🎯 Target & Context Configuration
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Configure the target URL and context for your automated security scan.
              </Typography>

              {/* 🔥 NEW: Environment Selection */}
              <Paper elevation={3} sx={{ p: 3, mb: 3, background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
                <Typography variant="h6" sx={{ color: 'white', mb: 2, fontWeight: 'bold' }}>
                  🛡️ Tarama Ortamı Seçimi
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.9)', mb: 3 }}>
                  Tarama yapacağınız ortamı seçin. Bu seçim taramanın agresiflik seviyesini ve güvenlik ayarlarını belirler.
                </Typography>

                <FormControl fullWidth>
                  <Select
                    value={config.environment}
                    onChange={(e) => handleEnvironmentChange(e.target.value as 'TEST' | 'PRODUCTION' | 'CUSTOM')}
                    renderValue={(value) => {
                      const labels = {
                        'TEST': '🧪 TEST / STAGING ORTAMI',
                        'PRODUCTION': '🔒 CANLI UYGULAMA (PRODUCTION)',
                        'CUSTOM': '⚡ ÖZEL AYARLAR (CUSTOM)'
                      };
                      return <Typography component="span" sx={{ color: '#fff', fontWeight: 'bold' }}>{labels[value as keyof typeof labels]}</Typography>;
                    }}
                    MenuProps={{
                      PaperProps: {
                        sx: {
                          bgcolor: '#1e1e2e',
                          backgroundImage: 'linear-gradient(135deg, #1e1e2e 0%, #2d2d44 100%)',
                          boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
                          border: '1px solid rgba(255,255,255,0.1)',
                          '& .MuiMenuItem-root': {
                            color: '#fff',
                            py: 2,
                            '&:hover': {
                              bgcolor: 'rgba(102, 126, 234, 0.2)',
                              borderLeft: '3px solid #667eea'
                            },
                            '&.Mui-selected': {
                              bgcolor: 'rgba(102, 126, 234, 0.3)',
                              borderLeft: '3px solid #667eea',
                              '&:hover': {
                                bgcolor: 'rgba(102, 126, 234, 0.4)'
                              }
                            }
                          }
                        }
                      }
                    }}
                    sx={{
                      bgcolor: 'rgba(255,255,255,0.15)',
                      backdropFilter: 'blur(10px)',
                      border: '1px solid rgba(255,255,255,0.2)',
                      '& .MuiSelect-select': {
                        py: 2,
                        color: '#fff'
                      },
                      '& .MuiOutlinedInput-notchedOutline': {
                        borderColor: 'rgba(255,255,255,0.3)'
                      },
                      '&:hover .MuiOutlinedInput-notchedOutline': {
                        borderColor: 'rgba(255,255,255,0.5)'
                      },
                      '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
                        borderColor: '#667eea'
                      },
                      '& .MuiSvgIcon-root': {
                        color: '#fff'
                      }
                    }}
                  >
                    <MenuItem value="TEST" sx={{ py: 2 }}>
                      <Box sx={{ display: 'flex', flexDirection: 'column', width: '100%' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                          <Typography component="span" sx={{ fontWeight: 'bold', color: '#fff', fontSize: '1rem' }}>
                            🧪 TEST / STAGING ORTAMI
                          </Typography>
                          <Chip
                            label="ÖNERİLEN"
                            size="small"
                            sx={{
                              bgcolor: '#4caf50',
                              color: '#fff',
                              fontWeight: 'bold'
                            }}
                          />
                        </Box>
                        <Typography component="span" variant="caption" sx={{ color: 'rgba(255,255,255,0.7)', display: 'block', fontSize: '0.85rem' }}>
                          Maksimum agresiflik • Tüm testler aktif • SQL, XSS, Command Injection, WAF Bypass, Brute Force
                        </Typography>
                      </Box>
                    </MenuItem>

                    <MenuItem value="PRODUCTION" sx={{ py: 2 }}>
                      <Box sx={{ display: 'flex', flexDirection: 'column', width: '100%' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                          <Typography component="span" sx={{ fontWeight: 'bold', color: '#fff', fontSize: '1rem' }}>
                            🔒 CANLI UYGULAMA (PRODUCTION)
                          </Typography>
                          <Chip
                            label="GÜVENLİ"
                            size="small"
                            sx={{
                              bgcolor: '#ff9800',
                              color: '#fff',
                              fontWeight: 'bold'
                            }}
                          />
                        </Box>
                        <Typography component="span" variant="caption" sx={{ color: 'rgba(255,255,255,0.7)', display: 'block', fontSize: '0.85rem' }}>
                          Düşük agresiflik • Sadece zararsız testler • Sadece okuma, veri değiştirmez
                        </Typography>
                      </Box>
                    </MenuItem>

                    <MenuItem value="CUSTOM" sx={{ py: 2 }}>
                      <Box sx={{ display: 'flex', flexDirection: 'column', width: '100%' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                          <Typography component="span" sx={{ fontWeight: 'bold', color: '#fff', fontSize: '1rem' }}>
                            ⚡ ÖZEL AYARLAR (CUSTOM)
                          </Typography>
                          <Chip
                            label="İLERİ SEVİYE"
                            size="small"
                            sx={{
                              bgcolor: '#2196f3',
                              color: '#fff',
                              fontWeight: 'bold'
                            }}
                          />
                        </Box>
                        <Typography component="span" variant="caption" sx={{ color: 'rgba(255,255,255,0.7)', display: 'block', fontSize: '0.85rem' }}>
                          Manuel kontrol • Testleri kendiniz seçin • Her ayarı özelleştirin
                        </Typography>
                      </Box>
                    </MenuItem>
                  </Select>
                </FormControl>

                {/* Environment Warning/Info */}
                {config.environment === 'TEST' && (
                  <Alert severity="success" sx={{ mt: 2 }}>
                    <strong>Test Ortamı Seçildi:</strong> Tüm güvenlik testleri maksimum agresiflikte çalışacak.
                    Destructive testler dahil tüm yetenekler aktif. WAF bypass ve brute force testleri yapılacak.
                  </Alert>
                )}

                {config.environment === 'PRODUCTION' && (
                  <Alert severity="warning" sx={{ mt: 2 }}>
                    <strong>Canlı Ortam Seçildi:</strong> Güvenli mod aktif. Sadece okuma işlemleri yapılacak,
                    veri değiştirilmeyecek. Riskli testler devre dışı (Command Injection, XXE, Brute Force kapalı).
                  </Alert>
                )}

                {config.environment === 'CUSTOM' && (
                  <Alert severity="info" sx={{ mt: 2 }}>
                    <strong>Özel Mod Seçildi:</strong> Tüm ayarları sonraki adımlarda manuel olarak
                    yapılandırabilirsiniz. İleri seviye kullanıcılar için önerilir.
                  </Alert>
                )}
              </Paper>

              <TextField
                fullWidth
                label="Target URL"
                value={config.targetUrl}
                onChange={(e) => handleConfigChange('targetUrl', e.target.value)}
                placeholder="https://zamanmakinesi.ibb.gov.tr"
                error={config.targetUrl !== '' && !isValidUrl(config.targetUrl)}
                helperText={config.targetUrl !== '' && !isValidUrl(config.targetUrl) ? 'Please enter a valid URL' : 'The main URL of the application to test'}
                sx={{ mb: 3 }}
              />

              <TextField
                fullWidth
                label="Scan Name (Optional)"
                value={config.scanName}
                onChange={(e) => handleConfigChange('scanName', e.target.value)}
                placeholder="IBB Web Application Security Scan"
                helperText="Give your scan a memorable name"
                sx={{ mb: 3 }}
              />

              <TextField
                fullWidth
                label="Context Name"
                value={config.contextName}
                onChange={(e) => handleConfigChange('contextName', e.target.value)}
                placeholder="Default Context"
                helperText="ZAP context name for organizing scan results"
                sx={{ mb: 2 }}
              />

              <FormControlLabel
                control={
                  <Switch
                    checked={config.inScopeOnly}
                    onChange={(e) => handleConfigChange('inScopeOnly', e.target.checked)}
                  />
                }
                label="In Scope Only - Only scan URLs within the target domain"
                sx={{ mb: 1 }}
              />
            </CardContent>
          </Card>
        );

      case 1:
        // Spider Configuration (CUSTOM MODE ONLY)
        return (
          <Card variant="outlined" sx={{ mb: 2 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                🕷️ Traditional Spider Configuration
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Configure the traditional spider to crawl and discover pages on the website.
              </Typography>

              {/* 🔥 NEW: Aggressiveness Level for CUSTOM mode */}
              <Paper elevation={2} sx={{ p: 2, mb: 3, bgcolor: 'rgba(102, 126, 234, 0.1)' }}>
                <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 'bold' }}>
                  ⚡ Tarama Agresifliği
                </Typography>
                <FormControl fullWidth sx={{ mb: 2 }}>
                  <InputLabel>Aggressiveness Level</InputLabel>
                  <Select
                    value={config.aggressiveness}
                    onChange={(e) => handleConfigChange('aggressiveness', e.target.value)}
                    label="Aggressiveness Level"
                  >
                    <MenuItem value="LOW">
                      <Box>
                        <Typography variant="body2" fontWeight="bold">LOW - Düşük Agresiflik</Typography>
                        <Typography variant="caption" color="text.secondary">Minimum network load, safe for production</Typography>
                      </Box>
                    </MenuItem>
                    <MenuItem value="MEDIUM">
                      <Box>
                        <Typography variant="body2" fontWeight="bold">MEDIUM - Orta Agresiflik</Typography>
                        <Typography variant="caption" color="text.secondary">Balanced testing, suitable for staging</Typography>
                      </Box>
                    </MenuItem>
                    <MenuItem value="HIGH">
                      <Box>
                        <Typography variant="body2" fontWeight="bold">HIGH - Yüksek Agresiflik</Typography>
                        <Typography variant="caption" color="text.secondary">Comprehensive testing, may cause load</Typography>
                      </Box>
                    </MenuItem>
                    <MenuItem value="INSANE">
                      <Box>
                        <Typography variant="body2" fontWeight="bold">INSANE - Maksimum Agresiflik</Typography>
                        <Typography variant="caption" color="text.secondary">⚠️ Maximum testing, heavy load, test environment only!</Typography>
                      </Box>
                    </MenuItem>
                  </Select>
                </FormControl>

                <FormControlLabel
                  control={
                    <Switch
                      checked={config.safeMode}
                      onChange={(e) => handleConfigChange('safeMode', e.target.checked)}
                    />
                  }
                  label="🛡️ Safe Mode (Read-only tests, no data modification)"
                />
              </Paper>

              <FormControlLabel
                control={
                  <Switch
                    checked={config.spiderEnabled}
                    onChange={(e) => handleConfigChange('spiderEnabled', e.target.checked)}
                  />
                }
                label="Enable Traditional Spider"
                sx={{ mb: 3 }}
              />

              {config.spiderEnabled && (
                <Box>
                  <Box sx={{ mb: 3 }}>
                    <Typography gutterBottom>
                      Max Children: {config.maxChildren}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      Maximum number of child pages to crawl from each page
                    </Typography>
                    <Slider
                      value={config.maxChildren}
                      onChange={(_, value) => handleConfigChange('maxChildren', value)}
                      min={1}
                      max={100}
                      marks={[
                        { value: 1, label: '1' },
                        { value: 25, label: '25' },
                        { value: 50, label: '50' },
                        { value: 100, label: '100' },
                      ]}
                    />
                  </Box>

                  <Box sx={{ mb: 3 }}>
                    <Typography gutterBottom>
                      Max Depth: {config.maxDepth}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      Maximum depth to crawl from the starting URL
                    </Typography>
                    <Slider
                      value={config.maxDepth}
                      onChange={(_, value) => handleConfigChange('maxDepth', value)}
                      min={1}
                      max={20}
                      marks={[
                        { value: 1, label: '1' },
                        { value: 5, label: '5' },
                        { value: 10, label: '10' },
                        { value: 20, label: '20' },
                      ]}
                    />
                  </Box>

                  <FormControlLabel
                    control={
                      <Switch
                        checked={config.recurse}
                        onChange={(e) => handleConfigChange('recurse', e.target.checked)}
                      />
                    }
                    label="Recursive Crawling - Follow links found on discovered pages"
                  />
                </Box>
              )}
            </CardContent>
          </Card>
        );

      case 2:
        // AJAX Spider & Forced Browse
        return (
          <Card variant="outlined" sx={{ mb: 2 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                🔍 AJAX Spider & Forced Browse
              </Typography>

              {/* AJAX Spider Section */}
              <Box sx={{ mb: 4 }}>
                <Typography variant="subtitle1" gutterBottom color="primary">
                  AJAX Spider Configuration
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Use a real browser engine to discover dynamic content and AJAX requests.
                </Typography>

                <FormControlLabel
                  control={
                    <Switch
                      checked={config.ajaxSpiderEnabled}
                      onChange={(e) => handleConfigChange('ajaxSpiderEnabled', e.target.checked)}
                    />
                  }
                  label="Enable AJAX Spider"
                  sx={{ mb: 2 }}
                />

                {config.ajaxSpiderEnabled && (
                  <Box>
                    <FormControl sx={{ mb: 2, minWidth: 200 }}>
                      <InputLabel>Browser Engine</InputLabel>
                      <Select
                        value={config.ajaxSpiderBrowser}
                        onChange={(e) => handleConfigChange('ajaxSpiderBrowser', e.target.value)}
                        label="Browser Engine"
                      >
                        <MenuItem value="firefox">Firefox (Recommended)</MenuItem>
                        <MenuItem value="chrome">Chrome Headless</MenuItem>
                        <MenuItem value="htmlunit">HtmlUnit (Lightweight)</MenuItem>
                      </Select>
                    </FormControl>

                    <Box sx={{ mb: 2 }}>
                      <Typography gutterBottom>
                        Max Crawl Depth: {config.ajaxSpiderMaxDepth}
                      </Typography>
                      <Slider
                        value={config.ajaxSpiderMaxDepth}
                        onChange={(_, value) => handleConfigChange('ajaxSpiderMaxDepth', value)}
                        min={1}
                        max={20}
                        marks={[
                          { value: 1, label: '1' },
                          { value: 5, label: '5' },
                          { value: 10, label: '10' },
                          { value: 20, label: '20' },
                        ]}
                      />
                    </Box>
                  </Box>
                )}
              </Box>

              <Divider sx={{ my: 3 }} />

              {/* Forced Browse Section */}
              <Box>
                <Typography variant="subtitle1" gutterBottom color="primary">
                  Forced Browse Configuration
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Brute-force directory and file discovery using common wordlists.
                </Typography>

                <FormControlLabel
                  control={
                    <Switch
                      checked={config.forcedBrowseEnabled}
                      onChange={(e) => handleConfigChange('forcedBrowseEnabled', e.target.checked)}
                    />
                  }
                  label="Enable Forced Browse"
                  sx={{ mb: 2 }}
                />

                {config.forcedBrowseEnabled && (
                  <Box sx={{ mb: 2 }}>
                    <Typography gutterBottom>
                      Timeout: {config.forcedBrowseTimeout} seconds
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      Maximum time to spend on forced browsing
                    </Typography>
                    <Slider
                      value={config.forcedBrowseTimeout}
                      onChange={(_, value) => handleConfigChange('forcedBrowseTimeout', value)}
                      min={30}
                      max={1800}
                      step={30}
                      marks={[
                        { value: 30, label: '30s' },
                        { value: 120, label: '2m' },
                        { value: 300, label: '5m' },
                        { value: 600, label: '10m' },
                        { value: 1800, label: '30m' },
                      ]}
                    />
                  </Box>
                )}
              </Box>
            </CardContent>
          </Card>
        );

      case 3:
        // Active Scan & Authentication
        return (
          <Card variant="outlined" sx={{ mb: 2 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                🛡️ Active Scan & Authentication
              </Typography>

              {/* Active Scan Section */}
              <Box sx={{ mb: 4 }}>
                <Typography variant="subtitle1" gutterBottom color="primary">
                  Active Scan Configuration
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Actively test for vulnerabilities by sending crafted payloads.
                </Typography>

                <FormControlLabel
                  control={
                    <Switch
                      checked={config.activeScanEnabled}
                      onChange={(e) => handleConfigChange('activeScanEnabled', e.target.checked)}
                    />
                  }
                  label="Enable Active Vulnerability Scanning"
                  sx={{ mb: 2 }}
                />

                {config.activeScanEnabled && (
                  <Box>
                    {/* 🔥 NEW: Advanced Test Selection for CUSTOM mode */}
                    <Paper elevation={2} sx={{ p: 2, mb: 3, bgcolor: 'rgba(102, 126, 234, 0.1)' }}>
                      <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 'bold' }}>
                        🎯 Advanced Test Configuration
                      </Typography>
                      <Typography variant="body2" color="text.secondary" paragraph>
                        Seçtiğiniz güvenlik testlerini aktif edin. Test ortamında tüm testler önerilir.
                      </Typography>

                      <Grid container spacing={2}>
                        <Grid item xs={12} sm={6}>
                          <FormControlLabel
                            control={
                              <Switch
                                checked={config.enableSqlInjection}
                                onChange={(e) => handleConfigChange('enableSqlInjection', e.target.checked)}
                              />
                            }
                            label="💉 SQL Injection Testing"
                          />
                        </Grid>
                        <Grid item xs={12} sm={6}>
                          <FormControlLabel
                            control={
                              <Switch
                                checked={config.enableXss}
                                onChange={(e) => handleConfigChange('enableXss', e.target.checked)}
                              />
                            }
                            label="🔓 XSS (Cross-Site Scripting)"
                          />
                        </Grid>
                        <Grid item xs={12} sm={6}>
                          <FormControlLabel
                            control={
                              <Switch
                                checked={config.enableXxe}
                                onChange={(e) => handleConfigChange('enableXxe', e.target.checked)}
                              />
                            }
                            label="📄 XXE (XML External Entity)"
                          />
                        </Grid>
                        <Grid item xs={12} sm={6}>
                          <FormControlLabel
                            control={
                              <Switch
                                checked={config.enableCommandInjection}
                                onChange={(e) => handleConfigChange('enableCommandInjection', e.target.checked)}
                              />
                            }
                            label="⚠️ Command Injection"
                          />
                        </Grid>
                        <Grid item xs={12} sm={6}>
                          <FormControlLabel
                            control={
                              <Switch
                                checked={config.enablePathTraversal}
                                onChange={(e) => handleConfigChange('enablePathTraversal', e.target.checked)}
                              />
                            }
                            label="📂 Path Traversal"
                          />
                        </Grid>
                        <Grid item xs={12} sm={6}>
                          <FormControlLabel
                            control={
                              <Switch
                                checked={config.enableWafBypass}
                                onChange={(e) => handleConfigChange('enableWafBypass', e.target.checked)}
                              />
                            }
                            label="🔥 WAF Bypass Techniques"
                          />
                        </Grid>
                        <Grid item xs={12} sm={6}>
                          <FormControlLabel
                            control={
                              <Switch
                                checked={config.enableBruteForce}
                                onChange={(e) => handleConfigChange('enableBruteForce', e.target.checked)}
                              />
                            }
                            label="🔓 Brute Force Testing"
                          />
                        </Grid>
                      </Grid>
                    </Paper>

                    {/* 🎯 API Deep Dive Section */}
                    <Paper elevation={2} sx={{ p: 2, mb: 2, bgcolor: 'rgba(33, 150, 243, 0.05)' }}>
                      <Box display="flex" alignItems="center" mb={2}>
                        <ApiIcon sx={{ mr: 1, color: 'primary.main' }} />
                        <Typography variant="subtitle1" fontWeight="bold">
                          🔍 API Security Deep Dive
                        </Typography>
                        <Chip
                          label="10 Test Kategorisi"
                          size="small"
                          color="primary"
                          sx={{ ml: 1 }}
                        />
                      </Box>
                      <Typography variant="body2" color="text.secondary" paragraph>
                        Kapsamlı API güvenlik analizi - API Discovery, Authentication, Authorization,
                        Input Validation, Rate Limiting, CORS, GraphQL, OpenAPI ve Business Logic testleri
                      </Typography>
                      <Grid container spacing={2}>
                        <Grid item xs={12}>
                          <FormControlLabel
                            control={
                              <Switch
                                checked={config.enableApiDeepDive}
                                onChange={(e) => handleConfigChange('enableApiDeepDive', e.target.checked)}
                                color="primary"
                              />
                            }
                            label={
                              <Box display="flex" alignItems="center">
                                <Typography>🎯 API Deep Dive Analizi</Typography>
                                <Chip
                                  label={config.enableApiDeepDive ? "Aktif" : "Pasif"}
                                  size="small"
                                  color={config.enableApiDeepDive ? "success" : "default"}
                                  sx={{ ml: 1 }}
                                />
                              </Box>
                            }
                          />
                        </Grid>
                        {config.enableApiDeepDive && (
                          <Grid item xs={12}>
                            <FormControl fullWidth size="small">
                              <InputLabel>Deep Dive Yoğunluğu</InputLabel>
                              <Select
                                value={config.apiDeepDiveIntensity}
                                onChange={(e) => handleConfigChange('apiDeepDiveIntensity', e.target.value)}
                                label="Deep Dive Yoğunluğu"
                              >
                                <MenuItem value="standard">
                                  <Box>
                                    <Typography variant="body2" fontWeight="bold">
                                      ⚡ Standard (Hızlı)
                                    </Typography>
                                    <Typography variant="caption" color="text.secondary">
                                      Temel API güvenlik testleri (~5-10 dk)
                                    </Typography>
                                  </Box>
                                </MenuItem>
                                <MenuItem value="comprehensive">
                                  <Box>
                                    <Typography variant="body2" fontWeight="bold">
                                      🔍 Comprehensive (Önerilen)
                                    </Typography>
                                    <Typography variant="caption" color="text.secondary">
                                      Tüm 10 kategori + False Positive Filtering (~15-25 dk)
                                    </Typography>
                                  </Box>
                                </MenuItem>
                                <MenuItem value="full">
                                  <Box>
                                    <Typography variant="body2" fontWeight="bold">
                                      🚀 Full (Detaylı)
                                    </Typography>
                                    <Typography variant="caption" color="text.secondary">
                                      Tüm testler + Pattern Recognition + Business Logic (~30-45 dk)
                                    </Typography>
                                  </Box>
                                </MenuItem>
                              </Select>
                            </FormControl>
                          </Grid>
                        )}
                      </Grid>
                      {config.enableApiDeepDive && (
                        <Alert severity="info" sx={{ mt: 2 }}>
                          <Typography variant="caption">
                            <strong>Test Edilen Kategoriler:</strong> API Discovery, Technology Detection,
                            Authentication, Authorization (IDOR), Input Validation (SQL/NoSQL/XSS/XXE/Command Injection),
                            Rate Limiting, CORS, API Versioning, GraphQL Security, Business Logic
                          </Typography>
                        </Alert>
                      )}
                    </Paper>

                    <FormControl sx={{ mb: 2, minWidth: 250 }}>
                      <InputLabel>Scan Policy</InputLabel>
                      <Select
                        value={config.activeScanPolicy}
                        onChange={(e) => handleConfigChange('activeScanPolicy', e.target.value)}
                        label="Scan Policy"
                      >
                        <MenuItem value="Default Policy">Default Policy (Recommended)</MenuItem>
                        <MenuItem value="Light">Light (Faster, Less Thorough)</MenuItem>
                        <MenuItem value="Full">Full (Comprehensive, Slower)</MenuItem>
                      </Select>
                    </FormControl>

                    <FormControl sx={{ mb: 2, minWidth: 200 }}>
                      <InputLabel>Scan Intensity</InputLabel>
                      <Select
                        value={config.activeScanIntensity}
                        onChange={(e) => handleConfigChange('activeScanIntensity', e.target.value)}
                        label="Scan Intensity"
                      >
                        <MenuItem value="low">Low (Conservative)</MenuItem>
                        <MenuItem value="medium">Medium (Balanced)</MenuItem>
                        <MenuItem value="high">High (Aggressive)</MenuItem>
                      </Select>
                    </FormControl>
                  </Box>
                )}
              </Box>

              <Divider sx={{ my: 3 }} />

              {/* Authentication Section */}
              <Box>
                <Typography variant="subtitle1" gutterBottom color="primary">
                  Authentication Configuration
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Configure authentication to scan protected areas of the application.
                </Typography>

                <FormControlLabel
                  control={
                    <Switch
                      checked={config.authEnabled}
                      onChange={(e) => handleConfigChange('authEnabled', e.target.checked)}
                    />
                  }
                  label="Enable Authentication"
                  sx={{ mb: 2 }}
                />

                {config.authEnabled && (
                  <Box>
                    <FormControl sx={{ mb: 2, minWidth: 200 }}>
                      <InputLabel>Authentication Type</InputLabel>
                      <Select
                        value={config.authType}
                        onChange={(e) => handleConfigChange('authType', e.target.value)}
                        label="Authentication Type"
                      >
                        <MenuItem value="form">Form-based Authentication</MenuItem>
                        <MenuItem value="http">HTTP Authentication</MenuItem>
                        <MenuItem value="script">Script-based Authentication</MenuItem>
                      </Select>
                    </FormControl>

                    {config.authType === 'form' && (
                      <Box>
                        <TextField
                          fullWidth
                          label="Login URL"
                          value={config.authLoginUrl}
                          onChange={(e) => handleConfigChange('authLoginUrl', e.target.value)}
                          placeholder="https://example.com/login"
                          sx={{ mb: 2 }}
                        />

                        <Stack direction="row" spacing={2} sx={{ mb: 2 }}>
                          <TextField
                            label="Username"
                            value={config.authUsername}
                            onChange={(e) => handleConfigChange('authUsername', e.target.value)}
                            sx={{ flex: 1 }}
                          />
                          <TextField
                            label="Password"
                            type="password"
                            value={config.authPassword}
                            onChange={(e) => handleConfigChange('authPassword', e.target.value)}
                            sx={{ flex: 1 }}
                          />
                        </Stack>

                        <Stack direction="row" spacing={2}>
                          <TextField
                            label="Username Parameter"
                            value={config.authUsernameParam}
                            onChange={(e) => handleConfigChange('authUsernameParam', e.target.value)}
                            placeholder="username"
                            sx={{ flex: 1 }}
                          />
                          <TextField
                            label="Password Parameter"
                            value={config.authPasswordParam}
                            onChange={(e) => handleConfigChange('authPasswordParam', e.target.value)}
                            placeholder="password"
                            sx={{ flex: 1 }}
                          />
                        </Stack>
                      </Box>
                    )}
                  </Box>
                )}
              </Box>
            </CardContent>
          </Card>
        );

      case 4:
        // Review & Start
        return (
          <Card variant="outlined" sx={{ mb: 2 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                📋 Review Configuration & Start Scan
              </Typography>

              {/* 🔥 Environment-specific configuration display */}
              {config.environment !== 'CUSTOM' && (
                <Alert severity={config.environment === 'TEST' ? 'success' : 'warning'} sx={{ mb: 3 }}>
                  <Typography variant="body2">
                    <strong>🛡️ Tarama Ortamı:</strong> {config.environment === 'TEST' ? '🧪 TEST / STAGING' : '🔒 CANLI UYGULAMA (PRODUCTION)'}<br />
                    <strong>🎯 Target:</strong> {config.targetUrl}<br />
                    <strong>📝 Scan Name:</strong> {config.scanName || 'ZAP Automated Security Scan'}<br />
                    <strong>⚡ Aggressiveness:</strong> {config.aggressiveness}<br />
                    <strong>🛡️ Safe Mode:</strong> {config.safeMode ? 'Enabled (Read-only)' : 'Disabled (Full testing)'}<br />
                    <strong>🔍 Active Tests:</strong> {[
                      config.enableSqlInjection && 'SQL Injection',
                      config.enableXss && 'XSS',
                      config.enableXxe && 'XXE',
                      config.enableCommandInjection && 'Command Injection',
                      config.enablePathTraversal && 'Path Traversal',
                      config.enableWafBypass && 'WAF Bypass',
                      config.enableBruteForce && 'Brute Force'
                    ].filter(Boolean).join(', ')}
                  </Typography>
                </Alert>
              )}

              {config.environment === 'CUSTOM' && (
                <Alert severity="info" sx={{ mb: 3 }}>
                  <Typography variant="body2">
                    <strong>⚡ Tarama Ortamı:</strong> ÖZEL AYARLAR (CUSTOM)<br />
                    <strong>🎯 Target:</strong> {config.targetUrl}<br />
                    <strong>📝 Scan Name:</strong> {config.scanName || 'ZAP Automated Security Scan'}<br />
                    <strong>Context:</strong> {config.contextName}<br />
                    <strong>Enabled Phases:</strong> {[
                      config.passiveScanEnabled && 'Passive Analysis',
                      config.spiderEnabled && 'Traditional Spider',
                      config.ajaxSpiderEnabled && 'AJAX Spider',
                      config.forcedBrowseEnabled && 'Forced Browse',
                      config.activeScanEnabled && 'Active Vulnerability Testing'
                    ].filter(Boolean).join(' → ')}
                  </Typography>
                </Alert>
              )}

              <Typography variant="body2" color="text.secondary" paragraph>
                This automated scan will use ZAP's comprehensive workflow to perform all enabled security testing phases in sequence.
                You can monitor the progress in real-time and download detailed reports when complete.
              </Typography>

              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }}>
                {config.passiveScanEnabled && <Chip label="Passive Analysis" color="info" />}
                {config.spiderEnabled && <Chip label="Traditional Spider" color="primary" />}
                {config.ajaxSpiderEnabled && <Chip label="AJAX Spider" color="secondary" />}
                {config.forcedBrowseEnabled && <Chip label="Forced Browse" color="warning" />}
                {config.activeScanEnabled && <Chip label="Active Scan" color="error" />}
                {config.authEnabled && <Chip label="Authenticated" color="success" />}
              </Box>

              <Typography variant="body2" sx={{ mt: 2 }}>
                <strong>Configuration Summary:</strong><br />
                • Spider Max Children: {config.maxChildren} | Max Depth: {config.maxDepth}<br />
                • AJAX Spider Browser: {config.ajaxSpiderBrowser} | Max Duration: {config.ajaxSpiderMaxDuration}s<br />
                • Active Scan Policy: {config.activeScanPolicy} | Intensity: {config.activeScanIntensity}<br />
                • Authentication: {config.authEnabled ? `${config.authType} (${config.authUsername})` : 'Disabled'}<br />
                • Excluded URLs: {config.excludeUrls.length}
              </Typography>

              {error && (
                <Alert severity="error" sx={{ mt: 2 }}>
                  {error}
                </Alert>
              )}
            </CardContent>
          </Card>
        );

      default:
        return null;
    }
  };

  // Initialize WebSocket connection
  useEffect(() => {
    const initializeSocket = async () => {
      try {
        await socketService.connect();
      } catch (error) {
        // Socket connection failed
      }
    };

    initializeSocket();

    return () => {
      socketService.disconnect();
    };
  }, []);

  // Listen for scan progress updates
  useEffect(() => {
    if (currentWorkflowId) {
      socketService.joinScanRoom(currentWorkflowId);

      socketService.onScanProgress((progressData) => {
        setScanProgress(progressData);
      });

      return () => {
        socketService.leaveScanRoom(currentWorkflowId);
        socketService.offScanProgress();
      };
    }
  }, [currentWorkflowId]);

  return (
    <Box>
      {/* Render the full comprehensive scan monitor */}
      {showComprehensiveMonitor && currentWorkflowId && currentScanId && (
        <ComprehensiveScanMonitor
          workflowId={currentWorkflowId}
          scanId={currentScanId}
          onClose={handleCloseMonitor}
          onScanComplete={handleScanComplete}
        />
      )}

      {/* Main scan configuration UI when monitor is closed */}
      {!showComprehensiveMonitor && (
        <>
          <Box sx={{ mb: 4 }}>
            <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              🤖 ZAP Automated Security Scan
            </Typography>
            <Typography variant="subtitle1" color="text.secondary">
              Configure and launch ZAP's comprehensive automated security testing workflow - just like in ZAP's own interface
            </Typography>
          </Box>

          <Paper sx={{ p: 3 }}>
            <Stepper activeStep={activeStep} orientation="vertical">
              {steps.map((label, index) => (
                <Step key={label}>
                  <StepLabel>
                    <Typography variant="h6">{label}</Typography>
                  </StepLabel>
                  <StepContent>
                    <Box sx={{ mb: 3 }}>
                      {getStepContent(index)}
                    </Box>
                    <Box>
                      {index === steps.length - 1 ? (
                        <Stack direction="row" spacing={2}>
                          <Button
                            variant="contained"
                            startIcon={loading ? <CircularProgress size={20} /> : <PlayArrowIcon />}
                            onClick={startScan}
                            disabled={loading || !validateStep(index)}
                            size="large"
                          >
                            {loading ? 'Starting ZAP Workflow...' : 'Start ZAP Automated Scan'}
                          </Button>
                          {(totalAlertsFound > 0 || interceptedRequests.length > 0) && (
                            <Button
                              variant="outlined"
                              startIcon={<DownloadIcon />}
                              onClick={generateReport}
                              size="large"
                              sx={{
                                color: '#58a6ff',
                                borderColor: '#58a6ff',
                                '&:hover': {
                                  borderColor: '#1f6feb',
                                  bgcolor: 'rgba(88, 166, 255, 0.1)'
                                }
                              }}
                            >
                              Generate Report
                            </Button>
                          )}
                        </Stack>
                      ) : (
                        <Button
                          variant="contained"
                          onClick={handleNext}
                          disabled={!validateStep(index)}
                        >
                          Continue
                        </Button>
                      )}
                      {index > 0 && (
                        <Button
                          sx={{ ml: 1 }}
                          onClick={handleBack}
                          disabled={loading}
                        >
                          Back
                        </Button>
                      )}
                    </Box>
                  </StepContent>
                </Step>
              ))}
            </Stepper>
          </Paper>

          {/* HTTP Request History Panel - Show during scanning or when requests exist */}
          {(isScanning || interceptedRequests.length > 0) && (
            <Paper sx={{
              p: 2,
              mt: 3,
              bgcolor: '#21262d',
              border: '1px solid #30363d',
              borderRadius: 2,
              height: '500px', // Increased height
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
                  Live HTTP Requests
                  <Badge badgeContent={interceptedRequests.length} color="error" />
                  {autoRefresh && (
                    <Chip
                      label="Live"
                      size="small"
                      color="success"
                      sx={{ ml: 1, fontSize: '0.7rem' }}
                    />
                  )}
                </Typography>

                <Stack direction="row" spacing={1}>
                  <Button
                    size="small"
                    variant="outlined"
                    onClick={debugHttpHistory}
                    sx={{ color: '#f85149', borderColor: '#f85149' }}
                  >
                    Debug
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    onClick={() => {
                      fetchHttpHistory();
                    }}
                    sx={{ color: '#58a6ff', borderColor: '#58a6ff' }}
                  >
                    Refresh
                  </Button>
                  <IconButton
                    size="small"
                    onClick={clearRequests}
                    sx={{ color: '#7d8590' }}
                    title="Clear requests"
                  >
                    <ClearIcon />
                  </IconButton>
                  <IconButton
                    size="small"
                    onClick={generateReport}
                    sx={{ color: '#58a6ff' }}
                    title="Generate & Download Report"
                    disabled={totalAlertsFound === 0 && interceptedRequests.length === 0}
                  >
                    <DownloadIcon />
                  </IconButton>
                  <IconButton
                    size="small"
                    onClick={() => {
                      setAutoRefresh(!autoRefresh);
                    }}
                    color={autoRefresh ? "primary" : "default"}
                    sx={{ color: autoRefresh ? '#58a6ff' : '#7d8590' }}
                    title={autoRefresh ? "Disable auto-refresh" : "Enable auto-refresh"}
                  >
                    {autoRefresh ? <VisibilityIcon /> : <VisibilityOffIcon />}
                  </IconButton>
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
                      {autoRefresh ? (
                        <>
                          🔍 Capturing HTTP requests from ZAP...
                          <br />
                          <small style={{ color: '#7d8590' }}>
                            Make sure ZAP is running and scanning is active
                          </small>
                        </>
                      ) : (
                        <>
                          📱 Auto-refresh is disabled
                          <br />
                          <small style={{ color: '#7d8590' }}>
                            Enable auto-refresh to see live requests
                          </small>
                        </>
                      )}
                    </Typography>
                  </Box>
                ) : (
                  <List dense>
                    {interceptedRequests.map((request, index) => (
                      <ListItem
                        key={request.id || index}
                        component="div"
                        onClick={() => showRequestDetails(request)}
                        sx={{
                          borderBottom: '1px solid #30363d',
                          '&:hover': { bgcolor: '#21262d' },
                          cursor: 'pointer',
                          py: 1
                        }}
                      >
                        <ListItemIcon sx={{ minWidth: 80 }}>
                          <Chip
                            label={request.method || 'GET'}
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
                              fontFamily: 'Monaco, Consolas, monospace',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap'
                            }}>
                              {request.url || 'Unknown URL'}
                            </Typography>
                          }
                          secondary={
                            <Typography
                              component="div"
                              variant="body2"
                              sx={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: '8px',
                                marginTop: '4px'
                              }}
                            >
                              <Chip
                                label={String(request.status || 'Unknown')}
                                size="small"
                                variant="outlined"
                                color={
                                  !request.status || request.status === 0 ? 'default' :
                                    request.status >= 200 && request.status < 300 ? 'success' :
                                      request.status >= 300 && request.status < 400 ? 'info' :
                                        request.status >= 400 && request.status < 500 ? 'warning' :
                                          request.status >= 500 ? 'error' : 'default'
                                }
                                sx={{
                                  fontSize: '0.6rem',
                                  height: 18
                                }}
                              />
                              <span style={{
                                color: '#7d8590',
                                fontSize: '0.7rem'
                              }}>
                                {request.duration ? `${request.duration}ms` : 'N/A'} • {
                                  request.timestamp ?
                                    new Date(request.timestamp).toLocaleTimeString() :
                                    'Unknown time'
                                }
                              </span>
                            </Typography>
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                )}
              </Box>
            </Paper>
          )}
        </>
      )}

      {/* Request/Response Inspector Dialog */}
      <Dialog
        open={requestDetailsOpen}
        onClose={() => setRequestDetailsOpen(false)}
        maxWidth="xl"
        fullWidth
        maxHeight="90vh"
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
Duration: ${selectedRequest.duration || 'N/A'}ms
Timestamp: ${selectedRequest.timestamp ? new Date(selectedRequest.timestamp).toLocaleString() : 'N/A'}

Response Headers:
${Object.entries(selectedRequest.responseHeaders || {}).map(([k, v]) => `${k}: ${v}`).join('\n')}

Response Body:
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
            onClick={() => setRequestDetailsOpen(false)}
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

      {/* Legacy Real-Time Scan Monitor - kept for backward compatibility */}
      {showLiveMonitor && currentWorkflowId && !showComprehensiveMonitor && (
        <Box sx={{ mt: 4 }}>
          <RealTimeScanMonitor
            scanId={currentWorkflowId}
            onScanComplete={() => {
              setIsScanning(false);
              setShowLiveMonitor(false);
            }}
            onClose={() => {
              setShowLiveMonitor(false);
              navigate('/scan-history');
            }}
          />
        </Box>
      )}

      {/* Progress Dialog - kept for backward compatibility */}
      <Dialog
        open={showProgressDialog}
        onClose={() => setShowProgressDialog(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          <Typography variant="h6">Scan Progress</Typography>
          <Typography variant="body2" color="text.secondary">
            {config.targetUrl}
          </Typography>
        </DialogTitle>
        <DialogContent>
          {currentWorkflowId && (
            <>
              <ScanProgressBar
                scanId={currentWorkflowId}
                onComplete={handleScanComplete}
                onError={(error) => setError(error)}
              />

              {/* Real-time Statistics */}
              <Box sx={{ mt: 3, mb: 2 }}>
                <Grid container spacing={3}>
                  <Grid item xs={6}>
                    <Paper sx={{ p: 2, bgcolor: 'error.main', color: 'error.contrastText' }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <WarningIcon />
                        <Typography variant="h6">
                          {totalAlertsFound}
                        </Typography>
                        <Typography variant="body2">
                          Alerts Found
                        </Typography>
                      </Box>
                      {newAlertsCount > 0 && (
                        <Typography variant="caption" sx={{ fontWeight: 'bold' }}>
                          +{newAlertsCount} new
                        </Typography>
                      )}
                    </Paper>
                  </Grid>
                  <Grid item xs={6}>
                    <Paper sx={{ p: 2, bgcolor: 'info.main', color: 'info.contrastText' }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <LinkIcon />
                        <Typography variant="h6">
                          {totalUrlsFound}
                        </Typography>
                        <Typography variant="body2">
                          URLs Found
                        </Typography>
                      </Box>
                      {newUrlsCount > 0 && (
                        <Typography variant="caption" sx={{ fontWeight: 'bold' }}>
                          +{newUrlsCount} new
                        </Typography>
                      )}
                    </Paper>
                  </Grid>
                </Grid>
              </Box>

              {/* Latest Real-time Alerts Preview */}
              {realTimeAlerts.length > 0 && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="subtitle2" sx={{ mb: 1 }}>
                    Latest Alerts:
                  </Typography>
                  <Box sx={{ maxHeight: 200, overflow: 'auto' }}>
                    {realTimeAlerts.slice(-5).reverse().map((alert, index) => (
                      <Alert
                        key={`${alert.pluginId}-${index}`}
                        severity={
                          alert.risk === 'High' ? 'error' :
                            alert.risk === 'Medium' ? 'warning' :
                              alert.risk === 'Low' ? 'info' : 'success'
                        }
                        sx={{ mb: 1 }}
                      >
                        <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                          {alert.name}
                        </Typography>
                        <Typography variant="caption" display="block">
                          Risk: {alert.risk} | URL: {alert.url}
                        </Typography>
                      </Alert>
                    ))}
                  </Box>
                </Box>
              )}

              {/* Latest Real-time URLs Preview */}
              {realTimeUrls.length > 0 && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="subtitle2" sx={{ mb: 1 }}>
                    Latest URLs Found:
                  </Typography>
                  <Box sx={{ maxHeight: 150, overflow: 'auto' }}>
                    {realTimeUrls.slice(-10).reverse().map((url, index) => (
                      <Chip
                        key={`${url}-${index}`}
                        label={url.length > 50 ? `${url.substring(0, 50)}...` : url}
                        variant="outlined"
                        size="small"
                        sx={{ mr: 1, mb: 1 }}
                      />
                    ))}
                  </Box>
                </Box>
              )}
            </>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowProgressDialog(false)}>
            Run in Background
          </Button>
          <Button
            variant="contained"
            onClick={() => navigate('/scan-history')}
          >
            Go to Scan History
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default AutomatedScan;
