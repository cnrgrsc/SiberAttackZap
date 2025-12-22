import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  LinearProgress,
  Alert,
  IconButton,
  Tooltip,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  CircularProgress,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Speed as SpeedIcon,
  Web as WebIcon,
  BugReport as BugIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';

interface ScanStep {
  name: string;
  description: string;
  status: string;
  progress: number;
  details: {
    urlsFound?: number;
    resultsFound?: number;
    alertsFound?: number;
    phase: string;
  };
}

interface LiveAlert {
  alertId: string;
  name: string;
  risk: string;
  confidence: string;
  url: string;
  description: string;
}

interface HttpRequest {
  url: string;
  method: string;
  status: number;
  timestamp: string;
  responseTime: number;
  size: number;
}

interface LiveScanData {
  steps: ScanStep[];
  scanId: string;
  overallProgress: number;
  alerts: LiveAlert[];
  requests: HttpRequest[];
  summary: {
    total: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
}

interface LiveScanMonitorProps {
  scanId?: string;
  isActive?: boolean;
  onScanStop?: () => void;
}

const LiveScanMonitor: React.FC<LiveScanMonitorProps> = ({ 
  scanId, 
  isActive = false, 
  onScanStop 
}) => {
  const [scanData, setScanData] = useState<LiveScanData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshInterval, setRefreshInterval] = useState<NodeJS.Timeout | null>(null);

  const fetchScanData = useCallback(async () => {
    if (!isActive) return;

    try {
      const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';
      const [stepsResponse, alertsResponse, requestsResponse] = await Promise.allSettled([
        fetch(`${API_BASE_URL}/api/zap/scan/steps/${scanId || ''}`),
        fetch(`${API_BASE_URL}/api/zap/scan/live-alerts`),
        fetch(`${API_BASE_URL}/api/zap/scan/requests/${scanId || ''}?limit=10`)
      ]);

      let steps: ScanStep[] = [];
      let alerts: LiveAlert[] = [];
      let requests: HttpRequest[] = [];
      let summary = { total: 0, high: 0, medium: 0, low: 0, informational: 0 };

      // Process steps data
      if (stepsResponse.status === 'fulfilled' && stepsResponse.value.ok) {
        const stepsData = await stepsResponse.value.json();
        if (stepsData.success) {
          steps = stepsData.data.steps;
        }
      }

      // Process alerts data
      if (alertsResponse.status === 'fulfilled' && alertsResponse.value.ok) {
        const alertsData = await alertsResponse.value.json();
        if (alertsData.success) {
          alerts = alertsData.data.alerts.slice(0, 10); // Last 10 alerts
          summary = alertsData.data.summary;
        }
      }

      // Process requests data
      if (requestsResponse.status === 'fulfilled' && requestsResponse.value.ok) {
        const requestsData = await requestsResponse.value.json();
        if (requestsData.success) {
          requests = requestsData.data.requests;
        }
      }

      setScanData({
        steps,
        scanId: scanId || 'current',
        overallProgress: steps.length > 0 ? Math.round(steps.reduce((sum, step) => sum + step.progress, 0) / steps.length) : 0,
        alerts,
        requests,
        summary
      });

      setError(null);
    } catch (err) {
      console.error('Scan data fetch error:', err);
      setError(err instanceof Error ? err.message : 'Tarama verisi alınamadı');
    } finally {
      setLoading(false);
    }
  }, [scanId, isActive]);

  // Auto-refresh when scan is active
  useEffect(() => {
    if (isActive) {
      fetchScanData();
      
      const interval = setInterval(fetchScanData, 5000); // Refresh every 5 seconds
      setRefreshInterval(interval);
      
      return () => {
        if (interval) clearInterval(interval);
      };
    } else {
      if (refreshInterval) {
        clearInterval(refreshInterval);
        setRefreshInterval(null);
      }
    }
  }, [isActive, fetchScanData]);

  const getSeverityColor = (risk: string) => {
    switch (risk.toLowerCase()) {
      case 'high': return '#d32f2f';
      case 'medium': return '#f57c00';
      case 'low': return '#388e3c';
      case 'informational': return '#1976d2';
      default: return '#666';
    }
  };

  const getSeverityIcon = (risk: string) => {
    switch (risk.toLowerCase()) {
      case 'high': return <ErrorIcon style={{ color: getSeverityColor(risk) }} />;
      case 'medium': return <WarningIcon style={{ color: getSeverityColor(risk) }} />;
      case 'low': return <InfoIcon style={{ color: getSeverityColor(risk) }} />;
      case 'informational': return <SecurityIcon style={{ color: getSeverityColor(risk) }} />;
      default: return <InfoIcon />;
    }
  };

  const getStepIcon = (stepName: string) => {
    if (stepName.includes('Spider')) return <WebIcon />;
    if (stepName.includes('AJAX')) return <SpeedIcon />;
    if (stepName.includes('Active')) return <BugIcon />;
    return <SecurityIcon />;
  };

  if (!isActive) {
    return (
      <Box sx={{ textAlign: 'center', py: 4 }}>
        <SecurityIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
        <Typography variant="h6" gutterBottom>
          Aktif Tarama Bulunmuyor
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Real-time izleme için bir güvenlik taraması başlatın
        </Typography>
      </Box>
    );
  }

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="300px">
        <CircularProgress size={48} />
        <Typography variant="h6" sx={{ ml: 2 }}>
          Tarama verileri yükleniyor...
        </Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h5" gutterBottom display="flex" alignItems="center">
            <TimelineIcon sx={{ mr: 1, color: 'primary.main' }} />
            Canlı Tarama İzleme
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            Scan ID: {scanData?.scanId} - Genel İlerleme: %{scanData?.overallProgress}
          </Typography>
        </Box>
        <Box>
          <Tooltip title="Verileri Yenile">
            <IconButton onClick={fetchScanData} disabled={loading}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          {onScanStop && (
            <Tooltip title="Taramayı Durdur">
              <IconButton onClick={onScanStop} color="error">
                <StopIcon />
              </IconButton>
            </Tooltip>
          )}
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* Scan Steps Progress */}
        <Grid size={{ xs: 12, md: 8 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom display="flex" alignItems="center">
                <PlayIcon sx={{ mr: 1 }} />
                Tarama Adımları
              </Typography>
              
              {scanData?.steps.map((step, index) => (
                <Box key={index} sx={{ mb: 3 }}>
                  <Box display="flex" alignItems="center" justifyContent="space-between" mb={1}>
                    <Box display="flex" alignItems="center">
                      {getStepIcon(step.name)}
                      <Typography variant="subtitle1" sx={{ ml: 1 }}>
                        {step.name}
                      </Typography>
                    </Box>
                    <Chip 
                      label={`%${step.progress}`} 
                      size="small"
                      color={step.progress === 100 ? 'success' : 'primary'}
                    />
                  </Box>
                  
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    {step.description}
                  </Typography>
                  
                  <LinearProgress 
                    variant="determinate" 
                    value={step.progress} 
                    sx={{ height: 8, borderRadius: 4, mb: 1 }}
                  />
                  
                  <Box display="flex" gap={2} flexWrap="wrap">
                    {step.details.urlsFound !== undefined && (
                      <Chip label={`${step.details.urlsFound} URL`} size="small" variant="outlined" />
                    )}
                    {step.details.resultsFound !== undefined && (
                      <Chip label={`${step.details.resultsFound} Sonuç`} size="small" variant="outlined" />
                    )}
                    {step.details.alertsFound !== undefined && (
                      <Chip label={`${step.details.alertsFound} Alert`} size="small" variant="outlined" />
                    )}
                    <Chip 
                      label={step.details.phase} 
                      size="small" 
                      color={step.details.phase === 'completed' ? 'success' : 'warning'}
                    />
                  </Box>
                </Box>
              ))}
            </CardContent>
          </Card>
        </Grid>

        {/* Alert Summary */}
        <Grid size={{ xs: 12, md: 4 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom display="flex" alignItems="center">
                <SecurityIcon sx={{ mr: 1 }} />
                Bulunan Zafiyetler
              </Typography>
              
              <Grid container spacing={1}>
                <Grid size={6}>
                  <Paper sx={{ p: 2, textAlign: 'center', bgcolor: '#ffebee' }}>
                    <Typography variant="h4" sx={{ color: getSeverityColor('high') }}>
                      {scanData?.summary.high || 0}
                    </Typography>
                    <Typography variant="caption">Yüksek</Typography>
                  </Paper>
                </Grid>
                <Grid size={6}>
                  <Paper sx={{ p: 2, textAlign: 'center', bgcolor: '#fff3e0' }}>
                    <Typography variant="h4" sx={{ color: getSeverityColor('medium') }}>
                      {scanData?.summary.medium || 0}
                    </Typography>
                    <Typography variant="caption">Orta</Typography>
                  </Paper>
                </Grid>
                <Grid size={6}>
                  <Paper sx={{ p: 2, textAlign: 'center', bgcolor: '#e8f5e8' }}>
                    <Typography variant="h4" sx={{ color: getSeverityColor('low') }}>
                      {scanData?.summary.low || 0}
                    </Typography>
                    <Typography variant="caption">Düşük</Typography>
                  </Paper>
                </Grid>
                <Grid size={6}>
                  <Paper sx={{ p: 2, textAlign: 'center', bgcolor: '#e3f2fd' }}>
                    <Typography variant="h4" sx={{ color: getSeverityColor('informational') }}>
                      {scanData?.summary.informational || 0}
                    </Typography>
                    <Typography variant="caption">Bilgi</Typography>
                  </Paper>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Alerts */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Son Bulunan Zafiyetler
              </Typography>
              
              <List dense>
                {scanData?.alerts.length ? scanData.alerts.map((alert, index) => (
                  <ListItem key={index} divider>
                    <ListItemIcon>
                      {getSeverityIcon(alert.risk)}
                    </ListItemIcon>
                    <ListItemText
                      primary={alert.name}
                      secondary={
                        <Box>
                          <Typography variant="caption" display="block">
                            Risk: {alert.risk} | Güven: {alert.confidence}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {alert.url}
                          </Typography>
                        </Box>
                      }
                    />
                  </ListItem>
                )) : (
                  <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 2 }}>
                    Henüz zafiyet bulunamadı
                  </Typography>
                )}
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* HTTP Requests */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Son HTTP İstekleri
              </Typography>
              
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Method</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>URL</TableCell>
                      <TableCell>Time</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {scanData?.requests.length ? scanData.requests.map((request, index) => (
                      <TableRow key={index}>
                        <TableCell>
                          <Chip 
                            label={request.method} 
                            size="small" 
                            color={request.method === 'GET' ? 'primary' : 'secondary'}
                          />
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={request.status} 
                            size="small" 
                            color={request.status < 400 ? 'success' : 'error'}
                          />
                        </TableCell>
                        <TableCell>
                          <Tooltip title={request.url}>
                            <Typography variant="caption" noWrap sx={{ maxWidth: 200, display: 'block' }}>
                              {request.url}
                            </Typography>
                          </Tooltip>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">
                            {request.responseTime}ms
                          </Typography>
                        </TableCell>
                      </TableRow>
                    )) : (
                      <TableRow>
                        <TableCell colSpan={4} sx={{ textAlign: 'center' }}>
                          <Typography variant="body2" color="text.secondary">
                            HTTP istekleri yükleniyor...
                          </Typography>
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default LiveScanMonitor;
