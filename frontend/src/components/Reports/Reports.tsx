import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Alert,
  Button,
  Grid,
  CircularProgress,
  Chip,
  Paper,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  IconButton,
  Tooltip,
  LinearProgress,
} from '@mui/material';
import {
  Assessment as AssessmentIcon,
  Download as DownloadIcon,
  PictureAsPdf as PdfIcon,
  Code as JsonIcon,
  Description as HtmlIcon,
  DataObject as XmlIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Delete as DeleteIcon,
  GetApp as GetAppIcon,
} from '@mui/icons-material';
import api from '../../services/api';

interface ScanSummary {
  totalAlerts: number;
  alertsByRisk: {
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
  sites: string[];
  urls: string[];
  scanDate: string;
  error?: string;
}

interface SavedReport {
  id: string;
  type: string;
  format: string;
  createdAt: string;
  filePath: string;
}

interface GroupedReports {
  [scanId: string]: {
    scanInfo: {
      name: string;
      targetUrl: string;
      completedAt: string;
      status: string;
    };
    reports: SavedReport[];
  };
}

const Reports: React.FC = () => {
  const [searchParams] = useSearchParams();
  const scanId = searchParams.get('scanId'); // Get scanId from URL params
  
  const [scanSummary, setScanSummary] = useState<ScanSummary | null>(null);
  const [savedReports, setSavedReports] = useState<GroupedReports>({});
  const [loading, setLoading] = useState(true);
  const [reportsLoading, setReportsLoading] = useState(true);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (scanId) {
      loadScanSummaryFromBackend(scanId);
    } else {
      loadScanSummary();
    }
    loadSavedReports();
  }, [scanId]);  // Load scan summary from backend by scanId
  const loadScanSummaryFromBackend = async (scanId: string) => {
    try {
      setLoading(true);
      setError(null);
      
      const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';
      
      // Fetch scan data from backend with deduplicated vulnerabilities
      const response = await fetch(`${API_BASE_URL}/api/scans/${scanId}/data`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (!response.ok) {
        throw new Error('Failed to load scan data');
      }

      const result = await response.json();
      const scanData = result.data || result; // Handle both {data: ...} and direct response

      // Parse vulnerabilities from scan data
      const vulnerabilities = scanData.vulnerabilities || [];
      
      // Count by severity (risk level)
      const alertsByRisk = {
        high: vulnerabilities.filter((v: any) => 
          v.risk === 'High' || v.risk === 'HIGH' || 
          v.severity === 'HIGH' || v.severity === 'CRITICAL'
        ).length,
        medium: vulnerabilities.filter((v: any) => 
          v.risk === 'Medium' || v.risk === 'MEDIUM' || 
          v.severity === 'MEDIUM'
        ).length,
        low: vulnerabilities.filter((v: any) => 
          v.risk === 'Low' || v.risk === 'LOW' || 
          v.severity === 'LOW'
        ).length,
        informational: vulnerabilities.filter((v: any) => 
          v.risk === 'Informational' || v.risk === 'INFORMATIONAL' || 
          v.severity === 'INFO' || v.severity === 'INFORMATIONAL'
        ).length
      };

      setScanSummary({
        totalAlerts: vulnerabilities.length,
        alertsByRisk,
        sites: [scanData.targetUrl],
        urls: scanData.urlsFound || [],
        scanDate: scanData.completedAt || scanData.startedAt || new Date().toISOString()
      });
    } catch (err) {
      console.error('❌ Failed to load scan summary:', err);
      setError(err instanceof Error ? err.message : 'Failed to load scan data');
      
      // Fallback: Load from ZAP directly
      loadScanSummary();
    } finally {
      setLoading(false);
    }
  };

  // Load scan summary directly from ZAP (for general view without specific scanId)
  const loadScanSummary = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Backend API üzerinden ZAP'den veri al (CORS sorunu olmadan)
      const alertsResponse = await api.get('/zap/alerts');
      const alertsResult = alertsResponse.data;
      
      if (!alertsResult.success) {
        throw new Error(alertsResult.error?.message || 'Failed to fetch alerts');
      }
      
      const alerts = alertsResult.data || [];
      
      // Risk seviyelerine göre grupla
      const alertsByRisk = {
        high: alerts.filter((alert: any) => alert.risk === 'High').length,
        medium: alerts.filter((alert: any) => alert.risk === 'Medium').length,
        low: alerts.filter((alert: any) => alert.risk === 'Low').length,
        informational: alerts.filter((alert: any) => alert.risk === 'Informational').length
      };

      // Sites verilerini al
      const sitesResponse = await api.get('/zap/core/sites');
      const sitesResult = sitesResponse.data;
      
      if (!sitesResult.success) {
        throw new Error(sitesResult.error?.message || 'Failed to fetch sites');
      }
      
      const sites = sitesResult.data?.sites || [];

      setScanSummary({
        totalAlerts: alerts.length,
        alertsByRisk,
        sites,
        urls: sites,
        scanDate: new Date().toISOString()
      });
    } catch (err) {
      console.error('ZAP bağlantı hatası:', err);
      
      // ZAP bağlanamıyorsa örnek veri göster
      setScanSummary({
        totalAlerts: 0,
        alertsByRisk: {
          high: 0,
          medium: 0,
          low: 0,
          informational: 0
        },
        sites: [],
        urls: [],
        scanDate: new Date().toISOString(),
        error: 'ZAP Proxy\'ye bağlanılamadı - Backend servisinin çalıştığından emin olun'
      });
    } finally {
      setLoading(false);
    }
  };  const downloadReport = async (format: 'html' | 'json' | 'xml' | 'pdf') => {
    try {
      setDownloading(format);
      setError(null);
      
      console.log(`🔄 ${format.toUpperCase()} raporu indiriliyor...`);
      
      // Backend API'sinden rapor al
      const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';
      
      // If scanId exists, download specific scan report; otherwise download general report
      const apiUrl = scanId 
        ? `${API_BASE_URL}/api/reports/scan/${scanId}/${format}`
        : `${API_BASE_URL}/api/reports/download/${format}`;
      
      
      const response = await fetch(apiUrl, {
        method: 'GET',
        headers: {
          'Accept': format === 'json' ? 'application/json' : format === 'xml' ? 'application/xml' : format === 'pdf' ? 'application/pdf' : 'text/html',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: 'Network error' }));
        throw new Error(errorData.error?.message || `${format.toUpperCase()} raporu indirilemedi`);
      }

      // Get filename from response headers
      const contentDisposition = response.headers.get('content-disposition');
      let filename = `zap-guvenlik-raporu-${new Date().toISOString().replace(/[:.]/g, '-')}.${format}`;
      
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="(.+)"/);
        if (filenameMatch) {
          filename = filenameMatch[1];
        }
      }

      // Handle different response types
      let blob;
      if (format === 'json') {
        const jsonData = await response.json();
        blob = new Blob([JSON.stringify(jsonData, null, 2)], { type: 'application/json' });
      } else {
        blob = await response.blob();
      }
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      console.log(`✅ ${format.toUpperCase()} raporu başarıyla indirildi: ${filename}`);
      
    } catch (err) {
      console.error(`❌ ${format.toUpperCase()} report download error:`, err);
      setError(err instanceof Error ? err.message : `${format.toUpperCase()} raporu indirilemedi - Backend bağlantısını kontrol edin`);
    } finally {
      setDownloading(null);
    }
  };
  const loadSavedReports = async () => {
    try {
      setReportsLoading(true);
      // Backend olmadığı için boş veri döndür
      setSavedReports({});
    } catch (err) {
      console.error('Saved reports loading error:', err);
      setSavedReports({});
    } finally {
      setReportsLoading(false);
    }
  };

  const downloadSavedReport = async (reportId: string, reportType: string) => {
    try {
      setDownloading(reportId);
      const response = await fetch(`/api/reports/download/${reportId}`);
      
      if (!response.ok) {
        throw new Error('Rapor indirilemedi');
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      
      // Get filename from response headers or create default
      const contentDisposition = response.headers.get('content-disposition');
      let filename = `guvenlik-raporu-${reportType.toLowerCase()}.${reportType.toLowerCase()}`;
      
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="(.+)"/);
        if (filenameMatch) {
          filename = filenameMatch[1];
        }
      }
      
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Rapor indirilemedi');
    } finally {
      setDownloading(null);
    }
  };

  const deleteSavedReport = async (reportId: string) => {
    if (!window.confirm('Bu raporu silmek istediğinizden emin misiniz?')) {
      return;
    }

    try {
      const response = await fetch(`/api/reports/${reportId}`, {
        method: 'DELETE'
      });
      
      if (!response.ok) {
        throw new Error('Rapor silinemedi');
      }

      // Refresh saved reports
      await loadSavedReports();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Rapor silinemedi');
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high': return '#d32f2f';
      case 'medium': return '#f57c00';
      case 'low': return '#388e3c';
      case 'informational': return '#1976d2';
      default: return '#666';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high': return <ErrorIcon />;
      case 'medium': return <WarningIcon />;
      case 'low': return <InfoIcon />;
      case 'informational': return <SecurityIcon />;
      default: return <InfoIcon />;
    }
  };
  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress size={48} />
        <Typography variant="h6" sx={{ ml: 2 }}>
          Tarama özeti yükleniyor...
        </Typography>
      </Box>
    );
  }

  return (
    <Box>      <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h4" gutterBottom>
            Güvenlik Raporları
          </Typography>          <Typography variant="subtitle1" color="text.secondary">
            Kapsamlı güvenlik analizi ve zafiyet raporları
          </Typography>
        </Box>
        <Tooltip title="Özeti Yenile">
          <IconButton onClick={loadScanSummary} disabled={loading}>
            <RefreshIcon />
          </IconButton>
        </Tooltip>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Saved Reports Section */}
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6" gutterBottom>
              Kaydedilen Raporlar
            </Typography>
            <Button
              startIcon={<RefreshIcon />}
              onClick={loadSavedReports}
              disabled={reportsLoading}
              size="small"
            >
              Yenile
            </Button>
          </Box>

          {reportsLoading ? (
            <Box display="flex" justifyContent="center" py={2}>
              <CircularProgress size={32} />
            </Box>
          ) : Object.keys(savedReports).length > 0 ? (
            <Grid container spacing={2}>
              {Object.entries(savedReports).map(([scanId, scanData]) => (
                <Grid size={{ xs: 12 }} key={scanId}>
                  <Paper sx={{ p: 2, mb: 2 }}>
                    <Typography variant="subtitle1" gutterBottom>
                      <SecurityIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                      {scanData.scanInfo.name}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" gutterBottom>
                      Hedef: {scanData.scanInfo.targetUrl}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" gutterBottom>
                      Tamamlanma: {new Date(scanData.scanInfo.completedAt).toLocaleString('tr-TR')}
                    </Typography>
                    
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Mevcut Raporlar ({scanData.reports.length} adet):
                      </Typography>
                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                        {scanData.reports.map((report) => (
                          <Chip
                            key={report.id}
                            label={report.type}
                            color="primary"
                            variant="outlined"
                            icon={
                              report.type === 'PDF' ? <PdfIcon /> :
                              report.type === 'HTML' ? <HtmlIcon /> :
                              report.type === 'XML' ? <XmlIcon /> :
                              report.type === 'JSON' ? <JsonIcon /> : <GetAppIcon />
                            }
                            onClick={() => downloadSavedReport(report.id, report.type)}
                            onDelete={() => deleteSavedReport(report.id)}
                            deleteIcon={<DeleteIcon />}
                            sx={{ 
                              cursor: 'pointer',
                              '& .MuiChip-deleteIcon': {
                                fontSize: '16px'
                              }
                            }}
                          />
                        ))}
                      </Box>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          ) : (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <AssessmentIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 1 }} />
              <Typography variant="body2" color="text.secondary">
                Henüz kaydedilmiş rapor bulunmuyor
              </Typography>
            </Box>
          )}
        </CardContent>
      </Card>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {scanSummary ? (
        <Grid container spacing={3}>
          {/* Summary Cards */}
          <Grid size={{ xs: 12, md: 8 }}>            <Paper sx={{ p: 3, mb: 3 }}>
              <Typography variant="h6" gutterBottom>
                Tarama Özeti
              </Typography>
              <Grid container spacing={2}>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Card sx={{ textAlign: 'center', bgcolor: getSeverityColor('high') + '11' }}>
                    <CardContent sx={{ pb: '16px !important' }}>
                      <Typography variant="h4" sx={{ color: getSeverityColor('high') }}>
                        {scanSummary.alertsByRisk.high}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Yüksek Risk
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Card sx={{ textAlign: 'center', bgcolor: getSeverityColor('medium') + '11' }}>
                    <CardContent sx={{ pb: '16px !important' }}>
                      <Typography variant="h4" sx={{ color: getSeverityColor('medium') }}>
                        {scanSummary.alertsByRisk.medium}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Orta Risk
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Card sx={{ textAlign: 'center', bgcolor: getSeverityColor('low') + '11' }}>
                    <CardContent sx={{ pb: '16px !important' }}>
                      <Typography variant="h4" sx={{ color: getSeverityColor('low') }}>
                        {scanSummary.alertsByRisk.low}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Düşük Risk
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Card sx={{ textAlign: 'center', bgcolor: getSeverityColor('informational') + '11' }}>
                    <CardContent sx={{ pb: '16px !important' }}>
                      <Typography variant="h4" sx={{ color: getSeverityColor('informational') }}>
                        {scanSummary.alertsByRisk.informational}
                      </Typography>                      <Typography variant="body2" color="text.secondary">
                        Bilgi
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
              
              <Box sx={{ mt: 3 }}>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Toplam Bulunan Zafiyet: {scanSummary.totalAlerts}
                </Typography>
                <LinearProgress 
                  variant="determinate" 
                  value={scanSummary.totalAlerts > 0 ? 100 : 0}
                  sx={{ height: 8, borderRadius: 4 }}
                />
              </Box>
              
              <Box sx={{ mt: 2 }}>
                <Typography variant="body2" color="text.secondary">
                  Son Tarama: {new Date(scanSummary.scanDate).toLocaleString('tr-TR')}
                </Typography>
              </Box>
            </Paper>
          </Grid>

          {/* Download Options */}
          <Grid size={{ xs: 12, md: 4 }}>
            <Card>              <CardContent>
                <Typography variant="h6" gutterBottom display="flex" alignItems="center">
                  <DownloadIcon sx={{ mr: 1 }} />
                  Rapor İndir
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Detaylı güvenlik raporlarını çeşitli formatlarda indirin
                </Typography>                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <Button
                    variant="outlined"
                    startIcon={downloading === 'html' ? <CircularProgress size={20} /> : <HtmlIcon />}
                    onClick={() => downloadReport('html')}
                    disabled={downloading === 'html' || !!downloading}
                    fullWidth
                    color="primary"
                  >
                    HTML Raporu (Detaylı)
                  </Button>
                  
                  <Button
                    variant="outlined"
                    startIcon={downloading === 'json' ? <CircularProgress size={20} /> : <JsonIcon />}
                    onClick={() => downloadReport('json')}
                    disabled={downloading === 'json' || !!downloading}
                    fullWidth
                    color="info"
                  >
                    JSON Raporu (API Format)
                  </Button>
                  
                  <Button
                    variant="outlined"
                    startIcon={downloading === 'xml' ? <CircularProgress size={20} /> : <XmlIcon />}
                    onClick={() => downloadReport('xml')}
                    disabled={downloading === 'xml' || !!downloading}
                    fullWidth
                    color="secondary"
                  >
                    XML Raporu (Standart)
                  </Button>
                  
                  <Button
                    variant="outlined"
                    startIcon={downloading === 'pdf' ? <CircularProgress size={20} /> : <PdfIcon />}
                    onClick={() => downloadReport('pdf')}
                    disabled={downloading === 'pdf' || !!downloading}
                    fullWidth
                    color="warning"
                  >
                    PDF Raporu (Beta)
                  </Button>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          {/* Scan Details */}
          <Grid size={{ xs: 12 }}>            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                Tarama Detayları
              </Typography>
              
              <Grid container spacing={3}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Taranan Siteler
                  </Typography>
                  <List dense>
                    {scanSummary.sites.map((site, index) => (
                      <ListItem key={index} sx={{ py: 0.5 }}>
                        <ListItemIcon>
                          <SecurityIcon color="primary" />
                        </ListItemIcon>
                        <ListItemText primary={site} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
                
                <Grid size={{ xs: 12, md: 6 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Risk Dağılımı
                  </Typography>
                  <List dense>
                    {Object.entries(scanSummary.alertsByRisk).map(([risk, count]) => (
                      <ListItem key={risk} sx={{ py: 0.5 }}>
                        <ListItemIcon>
                          {getSeverityIcon(risk)}
                        </ListItemIcon>
                        <ListItemText 
                          primary={
                            <Box display="flex" justifyContent="space-between" alignItems="center">
                              <Typography sx={{ textTransform: 'capitalize' }}>
                                {risk === 'high' ? 'Yüksek' : 
                                 risk === 'medium' ? 'Orta' : 
                                 risk === 'low' ? 'Düşük' : 
                                 risk === 'informational' ? 'Bilgi' : risk}
                              </Typography>
                              <Chip 
                                label={count} 
                                size="small" 
                                sx={{ bgcolor: getSeverityColor(risk), color: 'white' }}
                              />
                            </Box>
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
        </Grid>
      ) : (        <Card>
          <CardContent>
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <AssessmentIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                Tarama Verisi Bulunamadı
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Henüz tamamlanmış güvenlik taraması bulunmuyor. Rapor oluşturmak için bir tarama başlatın.
              </Typography>
              <Button variant="contained" href="/automated-scan">
                İlk Taramayı Başlat
              </Button>
            </Box>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default Reports;
