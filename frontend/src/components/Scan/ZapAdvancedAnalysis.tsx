import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  TextField,
  Tabs,
  Tab,
  Alert,
  CircularProgress,
  Chip,
  List,
  ListItem,
  ListItemText,
  LinearProgress
} from '@mui/material';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

const ZapAdvancedAnalysis: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [tabValue, setTabValue] = useState(0);
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<any>(null);
  const [systemInfo, setSystemInfo] = useState<any>(null);

  useEffect(() => {
    loadSystemInfo();
  }, []);

  const loadSystemInfo = async () => {
    try {
      const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';
      const response = await fetch(`${API_BASE_URL}/api/zap-advanced/zap-system-info`);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      setSystemInfo(data);
    } catch (error) {
      console.error('Sistem bilgileri yüklenemedi:', error);
      // Don't show alert for system info failure, just log it
    }
  };

  const handleComprehensiveAnalysis = async () => {
    if (!targetUrl.trim()) {
      alert('Hedef URL giriniz');
      return;
    }

    setLoading(true);
    try {
      const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';
      const response = await fetch(`${API_BASE_URL}/api/zap-advanced/comprehensive-analysis`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ targetUrl: targetUrl.trim() }),
      });

      // Check if response is ok
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status} - ${response.statusText}`);
      }

      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        const text = await response.text();
        throw new Error(`Response is not JSON. Content-Type: ${contentType}. Body: ${text.substring(0, 200)}...`);
      }

      const data = await response.json();
      
      if (data.success) {
        setAnalysisResult(data);
        setTabValue(1);
      } else {
        alert('Analiz başarısız: ' + (data.message || data.error || 'Bilinmeyen hata'));
      }
    } catch (error) {
      console.error('Analiz hatası:', error);
      let errorMessage = 'Analiz sırasında hata oluştu';
      
      if (error instanceof Error) {
        if (error.message.includes('431')) {
          errorMessage = 'Request header çok büyük. Daha kısa URL deneyin.';
        } else if (error.message.includes('NetworkError') || error.message.includes('Failed to fetch')) {
          errorMessage = 'Backend bağlantısı kurulamadı. Lütfen backend\'in çalıştığını kontrol edin.';
        } else {
          errorMessage = error.message;
        }
      }
      
      alert(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  return (
    <Box sx={{ width: '100%', p: 3 }}>
      <Typography variant="h4" gutterBottom sx={{ mb: 3, fontWeight: 'bold' }}>
        🚀 SiberZed Advanced Security Analysis
      </Typography>
      
      <Typography variant="subtitle1" color="text.secondary" sx={{ mb: 3 }}>
        ZAP API'den maksimum veri çekerek kapsamlı güvenlik analizi
      </Typography>

      {/* ZAP Status Card */}
      {systemInfo && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              🔧 ZAP System Status
            </Typography>
            <Box display="flex" alignItems="center" gap={1} mb={2}>
              <Chip 
                label={systemInfo.systemInfo?.zapStatus === 'connected' ? 'Connected' : 'Disconnected'}
                color={systemInfo.systemInfo?.zapStatus === 'connected' ? 'success' : 'error'}
                variant="filled"
              />
              <Typography variant="body2">
                Version: {systemInfo.systemInfo?.version || 'Unknown'}
              </Typography>
            </Box>
            <Box display="flex" gap={1} flexWrap="wrap" mb={2}>
              {systemInfo.systemInfo?.supportedFeatures?.map((feature: string) => (
                <Chip key={feature} label={feature} size="small" color="primary" />
              ))}
            </Box>
            {systemInfo.recommendations?.map((rec: string, index: number) => (
              <Alert key={index} severity={rec.includes('✅') ? 'success' : 'warning'} sx={{ mt: 1 }}>
                {rec}
              </Alert>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Main Analysis Card */}
      <Card>
        <CardContent>
          <Tabs value={tabValue} onChange={handleTabChange}>
            <Tab label="🎯 Start Analysis" />
            <Tab label="📊 Results" disabled={!analysisResult} />
            <Tab label="🧠 JavaScript" disabled={!analysisResult} />
            <Tab label="🔌 API Security" disabled={!analysisResult} />
          </Tabs>

          {/* Tab 0: Start Analysis */}
          <TabPanel value={tabValue} index={0}>
            <Box>
              <Typography variant="h6" gutterBottom>
                🎯 Comprehensive Security Analysis
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                Bu analiz ZAP API'den 500+ farklı veri noktası toplayarak kapsamlı güvenlik değerlendirmesi yapar
              </Typography>

              <TextField
                fullWidth
                label="Target URL"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://example.com"
                sx={{ mb: 3 }}
                helperText="Analiz edilecek web uygulamasının URL'sini girin"
              />

              <Button
                variant="contained"
                onClick={handleComprehensiveAnalysis}
                disabled={loading || !targetUrl.trim()}
                size="large"
                sx={{ mb: 2 }}
              >
                {loading ? 'Analyzing...' : 'Start Comprehensive Analysis'}
              </Button>

              {loading && (
                <Box sx={{ mt: 3 }}>
                  <Typography variant="body2" gutterBottom>
                    ZAP API'den veri toplanıyor...
                  </Typography>
                  <LinearProgress />
                </Box>
              )}

              {/* Features Preview */}
              <Box sx={{ mt: 4 }}>
                <Typography variant="h6" gutterBottom>
                  📋 Analysis Features
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
                  <Card sx={{ p: 2, minWidth: 200 }}>
                    <Typography variant="h6">500+ Data Points</Typography>
                    <Typography variant="body2" color="text.secondary">
                      ZAP API'den kapsamlı veri toplama
                    </Typography>
                  </Card>
                  <Card sx={{ p: 2, minWidth: 200 }}>
                    <Typography variant="h6">JS Security</Typography>
                    <Typography variant="body2" color="text.secondary">
                      React/Vue/Angular güvenlik analizi
                    </Typography>
                  </Card>
                  <Card sx={{ p: 2, minWidth: 200 }}>
                    <Typography variant="h6">API Security</Typography>
                    <Typography variant="body2" color="text.secondary">
                      REST/GraphQL endpoint analizi
                    </Typography>
                  </Card>
                </Box>
              </Box>
            </Box>
          </TabPanel>

          {/* Tab 1: Results */}
          <TabPanel value={tabValue} index={1}>
            {analysisResult && (
              <Box>
                <Typography variant="h6" gutterBottom>
                  📊 Analysis Results for {analysisResult.targetUrl}
                </Typography>

                {/* Summary */}
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, mb: 3 }}>
                  <Card sx={{ p: 2, minWidth: 150 }}>
                    <Typography variant="h4" color="primary">
                      {analysisResult.summary?.totalDataPoints || 0}
                    </Typography>
                    <Typography variant="body2">Data Points</Typography>
                  </Card>
                  <Card sx={{ p: 2, minWidth: 150 }}>
                    <Typography variant="h4" color="info.main">
                      {analysisResult.summary?.jsLibraries || 0}
                    </Typography>
                    <Typography variant="body2">JS Libraries</Typography>
                  </Card>
                  <Card sx={{ p: 2, minWidth: 150 }}>
                    <Typography variant="h4" color="warning.main">
                      {analysisResult.summary?.apiEndpoints || 0}
                    </Typography>
                    <Typography variant="body2">API Endpoints</Typography>
                  </Card>
                  <Card sx={{ p: 2, minWidth: 150 }}>
                    <Typography variant="h4" color="success.main">
                      {analysisResult.summary?.recommendations || 0}
                    </Typography>
                    <Typography variant="body2">Recommendations</Typography>
                  </Card>
                </Box>

                {/* Comprehensive Assessment */}
                {analysisResult.analysis?.comprehensive && (
                  <Box>
                    <Typography variant="h6" gutterBottom>
                      🔍 Comprehensive Assessment
                    </Typography>
                    
                    {/* Vulnerabilities */}
                    {analysisResult.analysis.comprehensive.vulnerabilities && (
                      <Box sx={{ mb: 3 }}>
                        <Typography variant="h6" gutterBottom>
                          🚨 Vulnerabilities by Severity
                        </Typography>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
                          {Object.entries(analysisResult.analysis.comprehensive.vulnerabilities).map(([severity, alerts]: [string, any]) => (
                            <Card key={severity} sx={{ p: 2, minWidth: 120 }}>
                              <Typography variant="h5">
                                {alerts?.length || 0}
                              </Typography>
                              <Chip 
                                label={severity.toUpperCase()} 
                                color={severity === 'critical' || severity === 'high' ? 'error' : 
                                       severity === 'medium' ? 'warning' : 'default'}
                                size="small"
                              />
                            </Card>
                          ))}
                        </Box>
                      </Box>
                    )}

                    {/* Recommendations */}
                    {analysisResult.analysis.comprehensive.recommendations && (
                      <Box>
                        <Typography variant="h6" gutterBottom>
                          💡 AI Recommendations
                        </Typography>
                        <List>
                          {analysisResult.analysis.comprehensive.recommendations.map((rec: string, index: number) => (
                            <ListItem key={index}>
                              <ListItemText primary={rec} />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    )}
                  </Box>
                )}
              </Box>
            )}
          </TabPanel>

          {/* Tab 2: JavaScript Analysis */}
          <TabPanel value={tabValue} index={2}>
            {analysisResult?.analysis?.javascript && (
              <Box>
                <Typography variant="h6" gutterBottom>
                  🧠 JavaScript Security Analysis
                </Typography>

                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
                  <Card sx={{ p: 2, minWidth: 300 }}>
                    <Typography variant="h6" gutterBottom>
                      📚 Detected Libraries
                    </Typography>
                    {analysisResult.analysis.javascript.libraries?.length > 0 ? (
                      <List dense>
                        {analysisResult.analysis.javascript.libraries.slice(0, 5).map((lib: any, index: number) => (
                          <ListItem key={index}>
                            <ListItemText 
                              primary={lib.name || 'Unknown Library'}
                              secondary={lib.version || lib.type || 'No version info'}
                            />
                          </ListItem>
                        ))}
                      </List>
                    ) : (
                      <Typography color="text.secondary">
                        No JavaScript libraries detected
                      </Typography>
                    )}
                  </Card>

                  <Card sx={{ p: 2, minWidth: 300 }}>
                    <Typography variant="h6" gutterBottom color="error">
                      ⚠️ Vulnerable Libraries
                    </Typography>
                    {analysisResult.analysis.javascript.vulnerableLibraries?.length > 0 ? (
                      <List dense>
                        {analysisResult.analysis.javascript.vulnerableLibraries.map((lib: any, index: number) => (
                          <ListItem key={index}>
                            <ListItemText 
                              primary={lib.name}
                              secondary={lib.vulnerability || 'Security issue detected'}
                            />
                          </ListItem>
                        ))}
                      </List>
                    ) : (
                      <Alert severity="success">
                        No vulnerable libraries detected
                      </Alert>
                    )}
                  </Card>
                </Box>
              </Box>
            )}
          </TabPanel>

          {/* Tab 3: API Security */}
          <TabPanel value={tabValue} index={3}>
            {analysisResult?.analysis?.api && (
              <Box>
                <Typography variant="h6" gutterBottom>
                  🔌 API Security Analysis
                </Typography>

                {/* API Endpoints */}
                {analysisResult.analysis.api.endpoints?.length > 0 && (
                  <Card sx={{ mb: 3 }}>
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        🎯 Detected API Endpoints ({analysisResult.analysis.api.endpoints.length})
                      </Typography>
                      <List>
                        {analysisResult.analysis.api.endpoints.slice(0, 10).map((endpoint: any, index: number) => (
                          <ListItem key={index} divider>
                            <ListItemText 
                              primary={endpoint.url || endpoint.uri}
                              secondary={`Method: ${endpoint.method || 'GET'} | Status: ${endpoint.code || 'Unknown'}`}
                            />
                          </ListItem>
                        ))}
                      </List>
                      {analysisResult.analysis.api.endpoints.length > 10 && (
                        <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                          ... and {analysisResult.analysis.api.endpoints.length - 10} more endpoints
                        </Typography>
                      )}
                    </CardContent>
                  </Card>
                )}

                {/* GraphQL Analysis */}
                {analysisResult.analysis.api.graphqlAnalysis && (
                  <Card>
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        🔺 GraphQL Analysis
                      </Typography>
                      <Typography variant="body2">
                        Max Query Depth: {analysisResult.analysis.api.graphqlAnalysis.maxQueryDepth || 'Unknown'}
                      </Typography>
                      <Typography variant="body2">
                        Max Args Depth: {analysisResult.analysis.api.graphqlAnalysis.maxArgsDepth || 'Unknown'}
                      </Typography>
                    </CardContent>
                  </Card>
                )}
              </Box>
            )}
          </TabPanel>
        </CardContent>
      </Card>
    </Box>
  );
};

export default ZapAdvancedAnalysis;
