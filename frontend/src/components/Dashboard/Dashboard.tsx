import React, { useState, useEffect } from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  Button,
  CircularProgress,
  Alert,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  LinearProgress,
  IconButton,
  Tooltip,
  Tabs,
  Tab,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Build as BuildIcon,
  TrendingUp as TrendingUpIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  PlayArrow as PlayArrowIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  Launch as LaunchIcon,
  PhoneAndroid as MobileIcon,
  GetApp as DownloadIcon,
  Computer as ComputerIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import scanService from '../../services/scanService';
import { ScanStatistics } from '../../services/scanService';
import MobileScanPanel from '../Scan/MobileScanPanel';
import ZapAdvancedAnalysis from '../Scan/ZapAdvancedAnalysis';
import ApiSecurityDeepDive from '../Scan/ApiSecurityDeepDive';
import QueueStatusWidget from './QueueStatusWidget';
import api, { API_BASE_URL } from '../../services/api';

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [statistics, setStatistics] = useState<ScanStatistics | null>(null);
  const [recentScans, setRecentScans] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [currentTab, setCurrentTab] = useState(0);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);

      const [statsData, scansData] = await Promise.allSettled([
        scanService.getScanStatistics(),
        scanService.getScans(),
      ]);

      if (statsData.status === 'fulfilled') {
        setStatistics(statsData.value);
      }

      if (scansData.status === 'fulfilled') {
        setRecentScans(scansData.value.slice(0, 5));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const downloadZapReport = async () => {
    try {
      setLoading(true);
      const response = await api.get('/reports/zap/html', {
        responseType: 'blob'
      });

      const blob = new Blob([response.data], { type: 'text/html' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `SiberZed-ZAP-Session-Report-${new Date().toISOString().split('T')[0]}.html`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error: any) {
      console.error('ZAP report download failed:', error);
      alert('❌ ZAP raporu indirilemedi. ZAP proxy çalışıyor ve oturum var mı kontrol edin.');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f57c00';
      case 'medium': return '#fbc02d';
      case 'low': return '#388e3c';
      default: return '#1976d2';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'COMPLETED': return <CheckCircleIcon color="success" />;
      case 'RUNNING': return <CircularProgress size={20} />;
      case 'FAILED': return <ErrorIcon color="error" />;
      case 'CANCELLED': return <StopIcon color="disabled" />;
      default: return <WarningIcon color="warning" />;
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress size={48} />
        <Typography variant="h6" sx={{ ml: 2 }}>
          Loading Dashboard...
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1 }}>
      {error && (
        <Alert
          severity="error"
          sx={{ mb: 3 }}
          action={
            <IconButton color="inherit" size="small" onClick={loadDashboardData}>
              <RefreshIcon />
            </IconButton>
          }
        >
          {error}
        </Alert>
      )}

      {/* Welcome Section */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom>
          İBB Güvenlik Platformuna Hoş Geldiniz
        </Typography>
        <Typography variant="subtitle1" color="text.secondary" paragraph>
          OWASP ZAP ile desteklenen kapsamlı web uygulaması güvenlik taraması
        </Typography>
      </Box>

      {/* Tab Navigation */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={currentTab} onChange={(e, newValue) => setCurrentTab(newValue)}>
          <Tab label="Dashboard Özeti" />
          <Tab label="Mobil Güvenlik" />
        </Tabs>
      </Box>

      {/* Tab Content */}
      {currentTab === 0 && (
        <Box>
          <Box sx={{ display: 'flex', gap: 2, mb: 4 }}>
            <Button
              variant="contained"
              startIcon={<SecurityIcon />}
              onClick={() => navigate('/automated-scan')}
              size="large"
            >
              Otomatik Tarama Başlat
            </Button>
            <Button
              variant="outlined"
              startIcon={<BuildIcon />}
              onClick={() => navigate('/manual-scan')}
              size="large"
            >
              Manuel Tarama
            </Button>
            <Button
              variant="outlined"
              startIcon={<MobileIcon />}
              onClick={() => navigate('/mobile-scan')}
              size="large"
              sx={{
                borderColor: '#ff9800',
                color: '#ff9800',
                '&:hover': {
                  borderColor: '#f57c00',
                  backgroundColor: 'rgba(255, 152, 0, 0.04)'
                }
              }}
            >
              Mobil Tarama
            </Button>
            <Button
              variant="outlined"
              startIcon={<ComputerIcon />}
              onClick={() => navigate('/technology-scanner')}
              size="large"
              sx={{
                borderColor: '#9c27b0',
                color: '#9c27b0',
                '&:hover': {
                  borderColor: '#7b1fa2',
                  backgroundColor: 'rgba(156, 39, 176, 0.04)'
                }
              }}
            >
              Technology Scanner
            </Button>
          </Box>

          <Grid container spacing={3}>
            {/* Queue Status Widget - NEW */}
            <Grid size={{ xs: 12, md: 3 }}>
              <QueueStatusWidget />
            </Grid>

            {/* Statistics Cards */}
            <Grid size={{ xs: 12, md: 3 }}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" justifyContent="space-between">
                    <Typography color="text.secondary" gutterBottom>
                      Total Scans
                    </Typography>
                    <TrendingUpIcon color="primary" />
                  </Box>
                  <Typography variant="h4" component="div">
                    {statistics?.totalScans || 0}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {statistics?.activeScans || 0} currently active
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid size={{ xs: 12, md: 3 }}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" justifyContent="space-between">
                    <Typography color="text.secondary" gutterBottom>
                      Critical Issues
                    </Typography>
                    <ErrorIcon sx={{ color: getSeverityColor('critical') }} />
                  </Box>
                  <Typography variant="h4" component="div">
                    {statistics?.criticalVulnerabilities || 0}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Require immediate attention
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid size={{ xs: 12, md: 3 }}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" justifyContent="space-between">
                    <Typography color="text.secondary" gutterBottom>
                      High Priority
                    </Typography>
                    <WarningIcon sx={{ color: getSeverityColor('high') }} />
                  </Box>
                  <Typography variant="h4" component="div">
                    {statistics?.highVulnerabilities || 0}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Should be fixed soon
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            {/* Vulnerability Overview */}
            <Grid size={{ xs: 12, md: 6 }}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Vulnerability Overview
                  </Typography>

                  {statistics && (
                    <Box sx={{ mt: 2 }}>
                      <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                        <Typography variant="body2">Critical</Typography>
                        <Chip
                          label={statistics.criticalVulnerabilities}
                          size="small"
                          sx={{ backgroundColor: getSeverityColor('critical'), color: 'white' }}
                        />
                      </Box>
                      <LinearProgress
                        variant="determinate"
                        value={(statistics.criticalVulnerabilities / Math.max(statistics.totalVulnerabilities, 1)) * 100}
                        sx={{ mb: 2, height: 6, backgroundColor: 'rgba(211, 47, 47, 0.2)' }}
                      />

                      <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                        <Typography variant="body2">High</Typography>
                        <Chip
                          label={statistics.highVulnerabilities}
                          size="small"
                          sx={{ backgroundColor: getSeverityColor('high'), color: 'white' }}
                        />
                      </Box>
                      <LinearProgress
                        variant="determinate"
                        value={(statistics.highVulnerabilities / Math.max(statistics.totalVulnerabilities, 1)) * 100}
                        sx={{ mb: 2, height: 6, backgroundColor: 'rgba(245, 124, 0, 0.2)' }}
                      />

                      <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                        <Typography variant="body2">Medium</Typography>
                        <Chip
                          label={statistics.mediumVulnerabilities}
                          size="small"
                          sx={{ backgroundColor: getSeverityColor('medium'), color: 'black' }}
                        />
                      </Box>
                      <LinearProgress
                        variant="determinate"
                        value={(statistics.mediumVulnerabilities / Math.max(statistics.totalVulnerabilities, 1)) * 100}
                        sx={{ mb: 2, height: 6, backgroundColor: 'rgba(251, 192, 45, 0.2)' }}
                      />

                      <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                        <Typography variant="body2">Low</Typography>
                        <Chip
                          label={statistics.lowVulnerabilities}
                          size="small"
                          sx={{ backgroundColor: getSeverityColor('low'), color: 'white' }}
                        />
                      </Box>
                      <LinearProgress
                        variant="determinate"
                        value={(statistics.lowVulnerabilities / Math.max(statistics.totalVulnerabilities, 1)) * 100}
                        sx={{ height: 6, backgroundColor: 'rgba(56, 142, 60, 0.2)' }}
                      />
                    </Box>
                  )}
                </CardContent>
              </Card>
            </Grid>        {/* Recent Scans */}
            <Grid size={{ xs: 12, md: 6 }}>
              <Card>
                <CardContent>
                  <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                    <Typography variant="h6">
                      Recent Scans
                    </Typography>
                    <Button
                      size="small"
                      endIcon={<LaunchIcon />}
                      onClick={() => navigate('/scan-history')}
                    >
                      View All
                    </Button>
                  </Box>

                  <List dense>
                    {recentScans.length === 0 ? (
                      <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 2 }}>
                        No scans found. Start your first scan!
                      </Typography>
                    ) : (
                      recentScans.map((scan, index) => (
                        <React.Fragment key={scan.id}>
                          <ListItem sx={{ px: 0 }}>
                            <ListItemIcon>
                              {getStatusIcon(scan.status)}
                            </ListItemIcon>
                            <ListItemText
                              primary={scan.name || scan.targetUrl}
                              secondary={
                                <React.Fragment>
                                  <Typography variant="caption" component="span" display="block">
                                    {scan.targetUrl}
                                  </Typography>
                                  <Typography variant="caption" component="span" display="block" color="text.secondary">
                                    {new Date(scan.startedAt).toLocaleDateString()} - {scan.status}
                                  </Typography>
                                </React.Fragment>
                              }
                            />
                            <Chip
                              label={scan.scanType}
                              size="small"
                              variant="outlined"
                            />
                          </ListItem>                      {index < recentScans.length - 1 && <Divider />}
                        </React.Fragment>
                      ))
                    )}
                  </List>            </CardContent>
              </Card>
            </Grid>

            {/* Quick Actions section removed - moved Technology Scanner to top buttons */}
          </Grid>
        </Box>
      )}

      {/* Mobil Güvenlik Tab */}
      {currentTab === 1 && (
        <MobileScanPanel />
      )}

      {/* Advanced ZAP Analysis Tab */}
      {currentTab === 3 && (
        <ZapAdvancedAnalysis />
      )}

      {/* API Security Deep Dive Tab */}
      {currentTab === 4 && (
        <ApiSecurityDeepDive />
      )}

    </Box>
  );
};

export default Dashboard;
