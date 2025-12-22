import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  LinearProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Badge,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Tooltip,
  Grid,
  Divider,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  BugReport as BugReportIcon,
  Speed as SpeedIcon,
  Timeline as TimelineIcon,
  Download as DownloadIcon,
  Visibility as VisibilityIcon,
  Search as SearchIcon,
  NetworkCheck as NetworkCheckIcon,
  CheckCircle as CheckCircleIcon,
  Language as LanguageIcon,
  GetApp as GetAppIcon,
} from '@mui/icons-material';
import socketService from '../../services/socketService';
import scanService from '../../services/scanService';

interface ScanProgress {
  scanId: string;
  status: 'running' | 'completed' | 'failed' | 'stopped';
  phase: 'setup' | 'passive_scan' | 'spider_scan' | 'ajax_spider_scan' | 'forced_browse' | 'active_scan' | 'completed' | 'error';
  progress?: number;
  subPhaseProgress?: number;
  spiderProgress?: number;
  activeScanProgress?: number;
  passiveScanProgress?: number;
  urlsFound: number;
  alertsFound: number;
  currentUrl?: string;
  elapsedTime: number;
  estimatedTimeRemaining?: number;
  message?: string;
  workflow?: {
    currentPhase: string;
    totalPhases: number;
    completedPhases: number;
  };
}

interface Alert {
  id: string;
  name: string;
  risk: 'High' | 'Medium' | 'Low' | 'Informational';
  confidence: 'High' | 'Medium' | 'Low';
  url: string;
  description: string;
  solution?: string;
  reference?: string;
  cweid?: number;
  wascid?: number;
  param?: string;
  attack?: string;
  evidence?: string;
}

interface RealTimeScanMonitorProps {
  scanId: string;
  onScanComplete: (scanId: string) => void;
  onClose: () => void;
}

const RealTimeScanMonitor: React.FC<RealTimeScanMonitorProps> = ({
  scanId,
  onScanComplete,
  onClose,
}) => {  const [progress, setProgress] = useState<ScanProgress>({
    scanId,
    status: 'running',
    phase: 'setup',
    urlsFound: 0,
    alertsFound: 0,
    elapsedTime: 0,
  });
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [urlsDiscovered, setUrlsDiscovered] = useState<string[]>([]);
  const [showAlerts, setShowAlerts] = useState(false);
  const [showUrls, setShowUrls] = useState(false);
  const [startTime] = useState(Date.now());

  useEffect(() => {
    const connectSocket = async () => {
      try {
        await socketService.connect();
        socketService.joinScanRoom(scanId);

        // Listen for scan progress updates
        socketService.on('scan-progress', (data: any) => {
          setProgress(prev => ({
            ...prev,
            ...data,
          }));
        });

        // Listen for new alerts
        socketService.on('scan-alert', (alert: Alert) => {
          setAlerts(prev => [...prev, alert]);
          setProgress(prev => ({
            ...prev,
            alertsFound: prev.alertsFound + 1,
          }));
        });

        // Listen for new URLs discovered
        socketService.on('scan-url-discovered', (data: { url: string, count: number }) => {
          setUrlsDiscovered(prev => [...prev, data.url]);
          setProgress(prev => ({
            ...prev,
            urlsFound: data.count,
          }));
        });

        // Listen for scan completion
        socketService.on('scan-completed', (data: any) => {
          setProgress(prev => ({
            ...prev,
            status: 'completed',
            phase: 'completed',
          }));
          onScanComplete(scanId);
        });

        // Listen for scan errors
        socketService.on('scan-error', (error: any) => {
          setProgress(prev => ({
            ...prev,
            status: 'failed',
          }));
        });

      } catch (error) {
        // Failed to connect to socket
      }
    };

    connectSocket();

    // Update elapsed time every second
    const timer = setInterval(() => {
      setProgress(prev => ({
        ...prev,
        elapsedTime: Math.floor((Date.now() - startTime) / 1000),
      }));
    }, 1000);

    return () => {
      clearInterval(timer);
      socketService.leaveScanRoom(scanId);
    };
  }, [scanId, startTime, onScanComplete]);

  const formatTime = (seconds: number) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    if (hours > 0) {
      return `${hours}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
    return `${minutes}:${secs.toString().padStart(2, '0')}`;
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'High': return 'error';
      case 'Medium': return 'warning';
      case 'Low': return 'info';
      case 'Informational': return 'default';
      default: return 'default';
    }
  };

  const getRiskIcon = (risk: string) => {
    switch (risk) {
      case 'High': return <ErrorIcon />;
      case 'Medium': return <WarningIcon />;
      case 'Low': return <InfoIcon />;
      case 'Informational': return <InfoIcon />;
      default: return <InfoIcon />;
    }
  };

  // Helper functions
  const getPhaseAlertSeverity = (phase: string): 'info' | 'warning' | 'error' | 'success' => {
    switch (phase) {
      case 'setup':
      case 'passive_scan':
        return 'info';
      case 'spider_scan':
      case 'ajax_spider_scan':
      case 'forced_browse':
        return 'warning';
      case 'active_scan':
        return 'error';
      case 'completed':
        return 'success';
      default:
        return 'info';
    }
  };

  const getPhaseIcon = (phase: string) => {
    switch (phase) {
      case 'setup':
        return <CheckCircleIcon />;
      case 'passive_scan':
        return <InfoIcon />;
      case 'spider_scan':
        return <SearchIcon />;
      case 'ajax_spider_scan':
        return <LanguageIcon />;
      case 'forced_browse':
        return <NetworkCheckIcon />;
      case 'active_scan':
        return <SecurityIcon />;
      case 'completed':
        return <CheckCircleIcon color="success" />;
      default:
        return <SpeedIcon />;
    }
  };

  const getPhaseDescription = (phase: string): string => {
    switch (phase) {
      case 'setup':
        return 'Initializing scan environment and passive analysis';
      case 'passive_scan':
        return 'Analyzing content without sending requests';
      case 'spider_scan':
        return 'Crawling website to discover URLs and structure';
      case 'ajax_spider_scan':
        return 'Using browser engine to discover dynamic content';
      case 'forced_browse':
        return 'Brute-forcing directories and files discovery';
      case 'active_scan':
        return 'Testing discovered URLs for vulnerabilities';
      case 'completed':
        return 'Comprehensive security scan completed successfully';
      default:
        return 'Processing...';
    }
  };

  const handleDownloadReport = async () => {
    try {
      await scanService.downloadReport(scanId, 'html');
    } catch (error) {
      // Failed to download report
    }
  };

  const alertsByRisk = alerts.reduce((acc, alert) => {
    acc[alert.risk] = (acc[alert.risk] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5" component="h2" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <TimelineIcon />
          Real-Time Scan Monitor
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          {progress.status === 'completed' && (
            <Button
              variant="contained"
              startIcon={<DownloadIcon />}
              onClick={handleDownloadReport}
              color="primary"
            >
              Download Report
            </Button>
          )}
          <Button variant="outlined" onClick={onClose}>
            Close
          </Button>
        </Box>
      </Box>

      {/* Progress Overview */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            {getPhaseIcon(progress.phase)}
            <Typography variant="h6">
              {progress.phase === 'completed' ? 'Scan Completed' : 'Scanning in Progress'}
            </Typography>
            <Chip 
              label={progress.status} 
              color={progress.status === 'completed' ? 'success' : progress.status === 'failed' ? 'error' : 'primary'}
              variant="outlined"
            />
          </Box>
          
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {getPhaseDescription(progress.phase)}
          </Typography>

          <Box sx={{ display: 'flex', gap: 4, mb: 3 }}>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="h4" color="primary">{progress.urlsFound}</Typography>
              <Typography variant="body2" color="text.secondary">URLs Found</Typography>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="h4" color="error">{progress.alertsFound}</Typography>
              <Typography variant="body2" color="text.secondary">Alerts Found</Typography>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="h4" color="info">{formatTime(progress.elapsedTime)}</Typography>
              <Typography variant="body2" color="text.secondary">Elapsed Time</Typography>
            </Box>
          </Box>          {/* Progress Bars - Enhanced for all phases */}
          
          {/* Overall Workflow Progress */}
          {progress.workflow && (
            <Box sx={{ mb: 3 }}>
              <Typography variant="body2" sx={{ mb: 1 }}>
                Overall Progress: {progress.workflow.currentPhase.replace('_', ' ').toUpperCase()} 
                ({progress.workflow.completedPhases}/{progress.workflow.totalPhases})
              </Typography>
              <LinearProgress 
                variant="determinate"
                value={(progress.workflow.completedPhases / progress.workflow.totalPhases) * 100}
                sx={{ height: 10, borderRadius: 5, mb: 2 }}
              />
            </Box>
          )}

          {/* Phase-specific progress */}
          {(progress.phase === 'spider_scan' || progress.phase === 'ajax_spider_scan') && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="body2" sx={{ mb: 1 }}>
                {progress.phase === 'spider_scan' ? 'Traditional Spider Progress' : 'AJAX Spider Progress'}
              </Typography>
              <LinearProgress 
                variant={progress.subPhaseProgress ? "determinate" : "indeterminate"}
                value={progress.subPhaseProgress || 0}
                sx={{ height: 8, borderRadius: 4 }}
              />
              <Typography variant="caption" color="text.secondary">
                {progress.subPhaseProgress ? `${Math.round(progress.subPhaseProgress)}%` : 'In progress...'}
              </Typography>
            </Box>
          )}

          {progress.phase === 'active_scan' && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="body2" sx={{ mb: 1 }}>Vulnerability Testing Progress</Typography>
              <LinearProgress 
                variant={progress.subPhaseProgress ? "determinate" : "indeterminate"}
                value={progress.subPhaseProgress || 0}
                sx={{ height: 8, borderRadius: 4 }}
              />
              <Typography variant="caption" color="text.secondary">
                {progress.subPhaseProgress ? `${Math.round(progress.subPhaseProgress)}%` : 'Testing for vulnerabilities...'}
              </Typography>
            </Box>
          )}

          {progress.phase === 'forced_browse' && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="body2" sx={{ mb: 1 }}>Forced Browse Progress</Typography>
              <LinearProgress 
                variant={progress.subPhaseProgress ? "determinate" : "indeterminate"}
                value={progress.subPhaseProgress || 0}
                sx={{ height: 8, borderRadius: 4 }}
              />
              <Typography variant="caption" color="text.secondary">
                Discovering hidden directories and files...
              </Typography>
            </Box>
          )}

          {progress.phase === 'passive_scan' && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="body2" sx={{ mb: 1 }}>Passive Analysis Progress</Typography>
              <LinearProgress 
                variant="indeterminate"
                sx={{ height: 8, borderRadius: 4 }}
              />
              <Typography variant="caption" color="text.secondary">
                Analyzing content for passive vulnerabilities...
              </Typography>
            </Box>
          )}

          {/* Current status message */}
          {progress.message && (
            <Box sx={{ mt: 2 }}>
              <Alert severity={getPhaseAlertSeverity(progress.phase)} sx={{ mb: 2 }}>
                <Typography variant="body2">
                  {progress.message}
                </Typography>
              </Alert>
            </Box>
          )}

          {progress.currentUrl && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="body2" color="text.secondary">
                Currently scanning: <code>{progress.currentUrl}</code>
              </Typography>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Alert Summary */}
      {alerts.length > 0 && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">Security Alerts Summary</Typography>
              <Button 
                size="small" 
                onClick={() => setShowAlerts(!showAlerts)}
                startIcon={<VisibilityIcon />}
              >
                {showAlerts ? 'Hide' : 'Show'} Details
              </Button>
            </Box>
            
            <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mb: 2 }}>
              {Object.entries(alertsByRisk).map(([risk, count]) => (
                <Chip
                  key={risk}
                  icon={getRiskIcon(risk)}
                  label={`${risk}: ${count}`}
                  color={getRiskColor(risk) as any}
                  variant="outlined"
                />
              ))}
            </Box>

            {showAlerts && (
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Risk</TableCell>
                      <TableCell>Alert Name</TableCell>
                      <TableCell>URL</TableCell>
                      <TableCell>Confidence</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {alerts.slice(-10).map((alert, index) => (
                      <TableRow key={index}>
                        <TableCell>
                          <Chip
                            size="small"
                            icon={getRiskIcon(alert.risk)}
                            label={alert.risk}
                            color={getRiskColor(alert.risk) as any}
                          />
                        </TableCell>
                        <TableCell>{alert.name}</TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {alert.url}
                          </Typography>
                        </TableCell>
                        <TableCell>{alert.confidence}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </CardContent>
        </Card>
      )}

      {/* Recent URLs */}
      {urlsDiscovered.length > 0 && (
        <Card>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">Recently Discovered URLs</Typography>
              <Button 
                size="small" 
                onClick={() => setShowUrls(!showUrls)}
                startIcon={<VisibilityIcon />}
              >
                {showUrls ? 'Hide' : 'Show'} URLs
              </Button>
            </Box>

            {showUrls && (
              <List sx={{ maxHeight: 300, overflow: 'auto' }}>
                {urlsDiscovered.slice(-20).reverse().map((url, index) => (
                  <ListItem key={index} dense>
                    <ListItemIcon>
                      <SearchIcon fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary={url}
                      primaryTypographyProps={{
                        variant: 'body2',
                        sx: { fontFamily: 'monospace' }
                      }}
                    />
                  </ListItem>
                ))}
              </List>
            )}
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default RealTimeScanMonitor;
