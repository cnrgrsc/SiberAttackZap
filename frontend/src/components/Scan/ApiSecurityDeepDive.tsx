import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  TextField,
  Alert,
  AlertTitle,
  CircularProgress,
  Chip,
  List,
  ListItem,
  ListItemText,
  LinearProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Tooltip,
  Divider
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  Api as ApiIcon,
  Shield as ShieldIcon,
  Lock as LockIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Speed as SpeedIcon,
  Visibility as VisibilityIcon,
  VpnLock as VpnLockIcon,
  Code as CodeIcon,
  Assessment as AssessmentIcon,
  FilterList as FilterListIcon,
  TrendingUp as TrendingUpIcon,
  CleaningServices as CleaningServicesIcon,
  PriorityHigh as PriorityHighIcon,
  Timeline as TimelineIcon,
  Assignment as AssignmentIcon,
  BugReport as BugReportIcon
} from '@mui/icons-material';

const ApiSecurityDeepDive: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [deepDiveResult, setDeepDiveResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const handleDeepDive = async () => {
    if (!targetUrl.trim()) {
      setError('Hedef URL giriniz');
      return;
    }

    setLoading(true);
    setError(null);
    
    try {
      const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';
      const response = await fetch(`${API_BASE_URL}/api/zap-advanced/api-security-deep-dive`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ targetUrl: targetUrl.trim() }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status} - ${response.statusText}`);
      }

      const data = await response.json();
      
      if (data.success) {
        setDeepDiveResult(data);
      } else {
        setError(data.message || 'Deep dive analizi başarısız');
      }
    } catch (err) {
      console.error('API Security Deep Dive error:', err);
      setError(err instanceof Error ? err.message : 'Analiz sırasında hata oluştu');
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk?.toLowerCase()) {
      case 'critical': return 'error';
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getSecurityScoreColor = (score: number) => {
    if (score >= 80) return 'success';
    if (score >= 60) return 'warning';
    return 'error';
  };

  return (
    <Box sx={{ width: '100%', p: 3 }}>
      <Typography variant="h4" gutterBottom sx={{ mb: 3, fontWeight: 'bold' }}>
        🔍 API Security Deep Dive
      </Typography>
      
      <Typography variant="subtitle1" color="text.secondary" sx={{ mb: 3 }}>
        Kapsamlı API güvenlik analizi - 10 farklı güvenlik kategorisin derinlemesine incelemesi
      </Typography>

      {/* Analysis Input */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-end' }}>
            <TextField
              fullWidth
              label="Target URL"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://api.example.com"
              helperText="Analiz edilecek API'nin base URL'sini girin"
              disabled={loading}
            />
            
            <Button
              variant="contained"
              onClick={handleDeepDive}
              disabled={loading || !targetUrl.trim()}
              startIcon={loading ? <CircularProgress size={20} /> : <SecurityIcon />}
              sx={{ minWidth: 200, height: 56 }}
            >
              {loading ? 'Analyzing...' : 'Start Deep Dive'}
            </Button>
          </Box>

          {loading && (
            <Box sx={{ mt: 3 }}>
              <Typography variant="body2" gutterBottom>
                API güvenlik analizi devam ediyor...
              </Typography>
              <LinearProgress />
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                Bu işlem birkaç dakika sürebilir
              </Typography>
            </Box>
          )}

          {error && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {error}
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Deep Dive Results */}
      {deepDiveResult && (
        <Box>
          {/* Summary Cards */}
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, mb: 3 }}>
            <Card sx={{ minWidth: 200, flex: 1 }}>
              <CardContent sx={{ textAlign: 'center' }}>
                <ApiIcon color="primary" sx={{ fontSize: 40, mb: 1 }} />
                <Typography variant="h4" color="primary">
                  {deepDiveResult.summary?.totalEndpoints || 0}
                </Typography>
                <Typography variant="body2">API Endpoints</Typography>
              </CardContent>
            </Card>

            <Card sx={{ minWidth: 200, flex: 1 }}>
              <CardContent sx={{ textAlign: 'center' }}>
                <ErrorIcon color="error" sx={{ fontSize: 40, mb: 1 }} />
                <Typography variant="h4" color="error">
                  {deepDiveResult.summary?.vulnerabilitiesFound || 0}
                </Typography>
                <Typography variant="body2">Vulnerabilities</Typography>
              </CardContent>
            </Card>

            <Card sx={{ minWidth: 200, flex: 1 }}>
              <CardContent sx={{ textAlign: 'center' }}>
                <AssessmentIcon 
                  color={getSecurityScoreColor(deepDiveResult.summary?.securityScore || 0)} 
                  sx={{ fontSize: 40, mb: 1 }} 
                />
                <Typography 
                  variant="h4" 
                  color={getSecurityScoreColor(deepDiveResult.summary?.securityScore || 0) + '.main'}
                >
                  {deepDiveResult.summary?.securityScore || 0}/100
                </Typography>
                <Typography variant="body2">Security Score</Typography>
              </CardContent>
            </Card>

            <Card sx={{ minWidth: 200, flex: 1 }}>
              <CardContent sx={{ textAlign: 'center' }}>
                <Chip 
                  label={deepDiveResult.summary?.riskLevel || 'Unknown'}
                  color={getRiskColor(deepDiveResult.summary?.riskLevel)}
                  sx={{ fontSize: '1.1rem', p: 2, height: 40 }}
                />
                <Typography variant="body2" sx={{ mt: 1 }}>Risk Level</Typography>
              </CardContent>
            </Card>
          </Box>

          {/* Deep Dive Analysis Results */}
          <Typography variant="h5" gutterBottom sx={{ mt: 4, mb: 2 }}>
            🔍 Deep Dive Analysis Results
          </Typography>

          {/* 1. API Discovery */}
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <ApiIcon color="primary" />
                <Typography variant="h6">
                  🔎 API Discovery ({deepDiveResult.deepDive?.analysis?.apiDiscovery?.restEndpoints?.length || 0} endpoints)
                </Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              {deepDiveResult.deepDive?.analysis?.apiDiscovery && (
                <Box>
                  <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                    <Chip label={`REST: ${deepDiveResult.deepDive.analysis.apiDiscovery.restEndpoints?.length || 0}`} color="primary" />
                    <Chip label={`GraphQL: ${deepDiveResult.deepDive.analysis.apiDiscovery.graphqlEndpoints?.length || 0}`} color="secondary" />
                    <Chip label={`WebSocket: ${deepDiveResult.deepDive.analysis.apiDiscovery.webSocketEndpoints?.length || 0}`} color="info" />
                    <Chip label={`Hidden: ${deepDiveResult.deepDive.analysis.apiDiscovery.hiddenEndpoints?.length || 0}`} color="warning" />
                  </Box>

                  {/* REST Endpoints Table */}
                  {deepDiveResult.deepDive.analysis.apiDiscovery.restEndpoints?.length > 0 && (
                    <TableContainer component={Paper} sx={{ mt: 2 }}>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>URL</TableCell>
                            <TableCell>Method</TableCell>
                            <TableCell>Status</TableCell>
                            <TableCell>Content Type</TableCell>
                            <TableCell>Auth Required</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {deepDiveResult.deepDive.analysis.apiDiscovery.restEndpoints.slice(0, 10).map((endpoint: any, index: number) => (
                            <TableRow key={index}>
                              <TableCell sx={{ wordBreak: 'break-all', maxWidth: 300 }}>
                                {endpoint.url}
                              </TableCell>
                              <TableCell>
                                <Chip label={endpoint.method} size="small" color="primary" />
                              </TableCell>
                              <TableCell>{endpoint.statusCode}</TableCell>
                              <TableCell>{endpoint.contentType}</TableCell>
                              <TableCell>
                                {endpoint.authRequired ? (
                                  <CheckCircleIcon color="success" />
                                ) : (
                                  <ErrorIcon color="error" />
                                )}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  )}
                </Box>
              )}
            </AccordionDetails>
          </Accordion>

          {/* 1.5. Technology Detection Enhancement */}
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <CodeIcon color="info" />
                <Typography variant="h6">
                  🛠️ Technology Detection Enhancement
                </Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              {deepDiveResult.deepDive?.analysis?.technologyDetection && (
                <Box>
                  {/* Technology Overview */}
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 3 }}>
                    {deepDiveResult.deepDive.analysis.technologyDetection.webServers?.length > 0 && (
                      <Chip label={`Web Servers: ${deepDiveResult.deepDive.analysis.technologyDetection.webServers.length}`} color="primary" size="small" />
                    )}
                    {deepDiveResult.deepDive.analysis.technologyDetection.programmingLanguages?.length > 0 && (
                      <Chip label={`Languages: ${deepDiveResult.deepDive.analysis.technologyDetection.programmingLanguages.length}`} color="secondary" size="small" />
                    )}
                    {deepDiveResult.deepDive.analysis.technologyDetection.databases?.length > 0 && (
                      <Chip label={`Databases: ${deepDiveResult.deepDive.analysis.technologyDetection.databases.length}`} color="info" size="small" />
                    )}
                    {deepDiveResult.deepDive.analysis.technologyDetection.jsLibraries?.length > 0 && (
                      <Chip label={`JS Libraries: ${deepDiveResult.deepDive.analysis.technologyDetection.jsLibraries.length}`} color="success" size="small" />
                    )}
                    {deepDiveResult.deepDive.analysis.technologyDetection.vulnerableTechnologies?.length > 0 && (
                      <Chip label={`Vulnerable: ${deepDiveResult.deepDive.analysis.technologyDetection.vulnerableTechnologies.length}`} color="error" size="small" />
                    )}
                  </Box>

                  <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 2 }}>
                    {/* Web Servers */}
                    {deepDiveResult.deepDive.analysis.technologyDetection.webServers?.length > 0 && (
                      <Card variant="outlined">
                        <CardContent>
                          <Typography variant="subtitle1" gutterBottom>
                            🌐 Web Servers
                          </Typography>
                          <List dense>
                            {deepDiveResult.deepDive.analysis.technologyDetection.webServers.map((server: any, index: number) => (
                              <ListItem key={index}>
                                <ListItemText 
                                  primary={server.server}
                                  secondary={`Confidence: ${server.confidence}`}
                                />
                                <Chip 
                                  label={server.confidence} 
                                  size="small" 
                                  color={server.confidence === 'High' ? 'success' : 'warning'} 
                                />
                              </ListItem>
                            ))}
                          </List>
                        </CardContent>
                      </Card>
                    )}

                    {/* Programming Languages */}
                    {deepDiveResult.deepDive.analysis.technologyDetection.programmingLanguages?.length > 0 && (
                      <Card variant="outlined">
                        <CardContent>
                          <Typography variant="subtitle1" gutterBottom>
                            💻 Programming Languages
                          </Typography>
                          <List dense>
                            {deepDiveResult.deepDive.analysis.technologyDetection.programmingLanguages.map((lang: any, index: number) => (
                              <ListItem key={index}>
                                <ListItemText 
                                  primary={lang.name}
                                  secondary={`Method: ${lang.detectionMethod}`}
                                />
                                <Chip 
                                  label={lang.confidence} 
                                  size="small" 
                                  color={lang.confidence === 'High' ? 'success' : 'warning'} 
                                />
                              </ListItem>
                            ))}
                          </List>
                        </CardContent>
                      </Card>
                    )}

                    {/* Databases */}
                    {deepDiveResult.deepDive.analysis.technologyDetection.databases?.length > 0 && (
                      <Card variant="outlined">
                        <CardContent>
                          <Typography variant="subtitle1" gutterBottom>
                            🗄️ Databases
                          </Typography>
                          <List dense>
                            {deepDiveResult.deepDive.analysis.technologyDetection.databases.map((db: any, index: number) => (
                              <ListItem key={index}>
                                <ListItemText 
                                  primary={db.name}
                                  secondary={`Method: ${db.detectionMethod}`}
                                />
                                <Chip 
                                  label={db.confidence} 
                                  size="small" 
                                  color={db.confidence === 'High' ? 'error' : 'warning'} 
                                />
                              </ListItem>
                            ))}
                          </List>
                        </CardContent>
                      </Card>
                    )}

                    {/* JavaScript Libraries */}
                    {deepDiveResult.deepDive.analysis.technologyDetection.jsLibraries?.length > 0 && (
                      <Card variant="outlined">
                        <CardContent>
                          <Typography variant="subtitle1" gutterBottom>
                            📚 JavaScript Libraries
                          </Typography>
                          <List dense>
                            {deepDiveResult.deepDive.analysis.technologyDetection.jsLibraries.map((lib: any, index: number) => (
                              <ListItem key={index}>
                                <ListItemText 
                                  primary={lib.name}
                                  secondary={`Method: ${lib.detectionMethod}`}
                                />
                                <Chip 
                                  label={lib.confidence} 
                                  size="small" 
                                  color={lib.confidence === 'High' ? 'success' : 'info'} 
                                />
                              </ListItem>
                            ))}
                          </List>
                        </CardContent>
                      </Card>
                    )}

                    {/* Version Information */}
                    {deepDiveResult.deepDive.analysis.technologyDetection.versionInformation && (
                      <Card variant="outlined">
                        <CardContent>
                          <Typography variant="subtitle1" gutterBottom>
                            📋 Version Information
                          </Typography>
                          <List dense>
                            {deepDiveResult.deepDive.analysis.technologyDetection.versionInformation.webServer && (
                              <ListItem>
                                <ListItemText 
                                  primary={`${deepDiveResult.deepDive.analysis.technologyDetection.versionInformation.webServer.name} ${deepDiveResult.deepDive.analysis.technologyDetection.versionInformation.webServer.version}`}
                                  secondary="Web Server"
                                />
                              </ListItem>
                            )}
                            {deepDiveResult.deepDive.analysis.technologyDetection.versionInformation.framework && (
                              <ListItem>
                                <ListItemText 
                                  primary={`${deepDiveResult.deepDive.analysis.technologyDetection.versionInformation.framework.name} ${deepDiveResult.deepDive.analysis.technologyDetection.versionInformation.framework.version}`}
                                  secondary="Framework"
                                />
                              </ListItem>
                            )}
                          </List>
                        </CardContent>
                      </Card>
                    )}

                    {/* Vulnerable Technologies */}
                    {deepDiveResult.deepDive.analysis.technologyDetection.vulnerableTechnologies?.length > 0 && (
                      <Card variant="outlined" sx={{ border: '2px solid', borderColor: 'error.main' }}>
                        <CardContent>
                          <Typography variant="subtitle1" gutterBottom color="error">
                            ⚠️ Vulnerable Technologies
                          </Typography>
                          <List dense>
                            {deepDiveResult.deepDive.analysis.technologyDetection.vulnerableTechnologies.map((vuln: any, index: number) => (
                              <ListItem key={index}>
                                <ListItemText 
                                  primary={vuln.technology}
                                  secondary={
                                    <Box>
                                      <Typography variant="body2" color="error">
                                        {vuln.vulnerability}
                                      </Typography>
                                      <Typography variant="caption" color="text.secondary">
                                        {vuln.recommendation}
                                      </Typography>
                                    </Box>
                                  }
                                />
                                <Chip 
                                  label={vuln.severity} 
                                  size="small" 
                                  color="error" 
                                />
                              </ListItem>
                            ))}
                          </List>
                        </CardContent>
                      </Card>
                    )}
                  </Box>

                  {/* Security Headers Status */}
                  {deepDiveResult.deepDive.analysis.technologyDetection.securityHeaders && (
                    <Card variant="outlined" sx={{ mt: 2 }}>
                      <CardContent>
                        <Typography variant="subtitle1" gutterBottom>
                          🔒 Security Headers Analysis
                        </Typography>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                          {Object.entries(deepDiveResult.deepDive.analysis.technologyDetection.securityHeaders).map(([header, present]: [string, any]) => (
                            <Chip 
                              key={header}
                              label={header.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                              color={present ? 'success' : 'error'}
                              size="small"
                              icon={present ? <CheckCircleIcon /> : <ErrorIcon />}
                            />
                          ))}
                        </Box>
                      </CardContent>
                    </Card>
                  )}
                </Box>
              )}
            </AccordionDetails>
          </Accordion>

          {/* 2. Input Validation */}
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <ShieldIcon color="warning" />
                <Typography variant="h6">
                  🛡️ Input Validation Vulnerabilities
                </Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              {deepDiveResult.deepDive?.analysis?.inputValidation && (
                <Box>
                  <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap' }}>
                    <Chip 
                      label={`SQL Injection: ${deepDiveResult.deepDive.analysis.inputValidation.sqlInjection?.length || 0}`} 
                      color={deepDiveResult.deepDive.analysis.inputValidation.sqlInjection?.length > 0 ? 'error' : 'success'}
                    />
                    <Chip 
                      label={`XSS: ${deepDiveResult.deepDive.analysis.inputValidation.xssVulnerabilities?.length || 0}`} 
                      color={deepDiveResult.deepDive.analysis.inputValidation.xssVulnerabilities?.length > 0 ? 'error' : 'success'}
                    />
                    <Chip 
                      label={`XXE: ${deepDiveResult.deepDive.analysis.inputValidation.xxeVulnerabilities?.length || 0}`} 
                      color={deepDiveResult.deepDive.analysis.inputValidation.xxeVulnerabilities?.length > 0 ? 'error' : 'success'}
                    />
                    <Chip 
                      label={`Command Injection: ${deepDiveResult.deepDive.analysis.inputValidation.commandInjection?.length || 0}`} 
                      color={deepDiveResult.deepDive.analysis.inputValidation.commandInjection?.length > 0 ? 'error' : 'success'}
                    />
                  </Box>

                  {/* Vulnerability Details */}
                  {(deepDiveResult.deepDive.analysis.inputValidation.sqlInjection?.length > 0 ||
                    deepDiveResult.deepDive.analysis.inputValidation.xssVulnerabilities?.length > 0) && (
                    <Alert severity="error" sx={{ mt: 2 }}>
                      Critical input validation vulnerabilities detected! Immediate action required.
                    </Alert>
                  )}
                </Box>
              )}
            </AccordionDetails>
          </Accordion>

          {/* 3. CORS Analysis */}
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <VpnLockIcon color="info" />
                <Typography variant="h6">
                  🌐 CORS Configuration Analysis
                </Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              {deepDiveResult.deepDive?.analysis?.corsAnalysis && (
                <Box>
                  <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                    <Chip 
                      label={`CORS Headers: ${deepDiveResult.deepDive.analysis.corsAnalysis.corsHeaders?.length || 0}`} 
                      color="info"
                    />
                    <Chip 
                      label={`Misconfigurations: ${deepDiveResult.deepDive.analysis.corsAnalysis.misconfiguredCors?.length || 0}`} 
                      color={deepDiveResult.deepDive.analysis.corsAnalysis.misconfiguredCors?.length > 0 ? 'error' : 'success'}
                    />
                  </Box>

                  {deepDiveResult.deepDive.analysis.corsAnalysis.misconfiguredCors?.length > 0 && (
                    <Alert severity="warning" sx={{ mt: 2 }}>
                      CORS misconfigurations detected. This may allow unauthorized cross-origin access.
                    </Alert>
                  )}
                </Box>
              )}
            </AccordionDetails>
          </Accordion>

          {/* 4. GraphQL Security */}
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <CodeIcon color="secondary" />
                <Typography variant="h6">
                  🔺 GraphQL Security Analysis
                </Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              {deepDiveResult.deepDive?.analysis?.graphqlSecurity && (
                <Box>
                  <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap' }}>
                    <Chip 
                      label={`Introspection: ${deepDiveResult.deepDive.analysis.graphqlSecurity.introspectionEnabled ? 'Enabled' : 'Disabled'}`} 
                      color={deepDiveResult.deepDive.analysis.graphqlSecurity.introspectionEnabled ? 'error' : 'success'}
                    />
                    <Chip 
                      label={`Vulnerabilities: ${deepDiveResult.deepDive.analysis.graphqlSecurity.vulnerabilities?.length || 0}`} 
                      color={deepDiveResult.deepDive.analysis.graphqlSecurity.vulnerabilities?.length > 0 ? 'error' : 'success'}
                    />
                  </Box>

                  {deepDiveResult.deepDive.analysis.graphqlSecurity.introspectionEnabled && (
                    <Alert severity="warning" sx={{ mt: 2 }}>
                      GraphQL introspection is enabled. Consider disabling it in production.
                    </Alert>
                  )}
                </Box>
              )}
            </AccordionDetails>
          </Accordion>

          {/* 5. Rate Limiting */}
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <SpeedIcon color="warning" />
                <Typography variant="h6">
                  ⏱️ Rate Limiting Analysis
                </Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              {deepDiveResult.deepDive?.analysis?.rateLimiting && (
                <Box>
                  <Chip 
                    label={`Rate Limit Headers: ${deepDiveResult.deepDive.analysis.rateLimiting.rateLimitHeaders?.length || 0}`} 
                    color={deepDiveResult.deepDive.analysis.rateLimiting.rateLimitHeaders?.length > 0 ? 'success' : 'warning'}
                  />

                  {deepDiveResult.deepDive.analysis.rateLimiting.rateLimitHeaders?.length === 0 && (
                    <Alert severity="warning" sx={{ mt: 2 }}>
                      No rate limiting headers detected. Consider implementing rate limiting to prevent abuse.
                    </Alert>
                  )}
                </Box>
              )}
            </AccordionDetails>
          </Accordion>

          {/* 11. False Positive Filtering */}
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <FilterListIcon color="success" />
                <Typography variant="h6">
                  🧹 False Positive Filtering Results
                </Typography>
                {deepDiveResult.deepDive?.analysis?.falsePositiveFiltering && (
                  <Chip 
                    label={`${deepDiveResult.deepDive.analysis.falsePositiveFiltering.falsePositivesRemoved} removed`}
                    color="success" 
                    size="small"
                  />
                )}
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              {deepDiveResult.deepDive?.analysis?.falsePositiveFiltering && (
                <Box>
                  {/* Filtering Overview */}
                  <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 2, mb: 3 }}>
                    <Card variant="outlined">
                      <CardContent sx={{ textAlign: 'center' }}>
                        <Typography variant="h4" color="error">
                          {deepDiveResult.deepDive.analysis.falsePositiveFiltering.totalIssuesBeforeFiltering}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Issues Before Filtering
                        </Typography>
                      </CardContent>
                    </Card>
                    
                    <Card variant="outlined">
                      <CardContent sx={{ textAlign: 'center' }}>
                        <Typography variant="h4" color="warning.main">
                          {deepDiveResult.deepDive.analysis.falsePositiveFiltering.totalIssuesAfterFiltering}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Issues After Filtering
                        </Typography>
                      </CardContent>
                    </Card>
                    
                    <Card variant="outlined">
                      <CardContent sx={{ textAlign: 'center' }}>
                        <Typography variant="h4" color="success.main">
                          {deepDiveResult.deepDive.analysis.falsePositiveFiltering.falsePositivesRemoved}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          False Positives Removed
                        </Typography>
                      </CardContent>
                    </Card>
                    
                    <Card variant="outlined">
                      <CardContent sx={{ textAlign: 'center' }}>
                        <Typography variant="h4" color="primary">
                          {deepDiveResult.deepDive.analysis.falsePositiveFiltering.filteringEfficiency}%
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Filtering Efficiency
                        </Typography>
                      </CardContent>
                    </Card>
                  </Box>

                  {/* Quality Score */}
                  <Card variant="outlined" sx={{ mb: 3 }}>
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                        <TrendingUpIcon color="primary" />
                        <Typography variant="h6">
                          Result Quality Score
                        </Typography>
                        <Chip 
                          label={`${deepDiveResult.deepDive.analysis.falsePositiveFiltering.qualityScore}/100`}
                          color={
                            deepDiveResult.deepDive.analysis.falsePositiveFiltering.qualityScore >= 80 ? 'success' :
                            deepDiveResult.deepDive.analysis.falsePositiveFiltering.qualityScore >= 60 ? 'warning' : 'error'
                          }
                          size="medium"
                        />
                      </Box>
                      <LinearProgress 
                        variant="determinate" 
                        value={deepDiveResult.deepDive.analysis.falsePositiveFiltering.qualityScore} 
                        sx={{ height: 10, borderRadius: 5 }}
                        color={
                          deepDiveResult.deepDive.analysis.falsePositiveFiltering.qualityScore >= 80 ? 'success' :
                          deepDiveResult.deepDive.analysis.falsePositiveFiltering.qualityScore >= 60 ? 'warning' : 'error'
                        }
                      />
                      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                        Higher scores indicate better filtering accuracy and fewer false positives
                      </Typography>
                    </CardContent>
                  </Card>

                  {/* Category-wise Filtering Results */}
                  <Typography variant="h6" gutterBottom sx={{ mt: 3, mb: 2 }}>
                    📊 Category-wise Filtering Results
                  </Typography>
                  
                  <TableContainer component={Paper}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell><strong>Category</strong></TableCell>
                          <TableCell align="center"><strong>Before</strong></TableCell>
                          <TableCell align="center"><strong>After</strong></TableCell>
                          <TableCell align="center"><strong>Removed</strong></TableCell>
                          <TableCell align="center"><strong>Efficiency</strong></TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {Object.entries(deepDiveResult.deepDive.analysis.falsePositiveFiltering.filteringCategories).map(([category, stats]: [string, any]) => (
                          <TableRow key={category}>
                            <TableCell>
                              <Typography variant="body2" sx={{ textTransform: 'capitalize' }}>
                                {category.replace(/([A-Z])/g, ' $1').trim()}
                              </Typography>
                            </TableCell>
                            <TableCell align="center">
                              <Chip label={stats.before} size="small" color="error" />
                            </TableCell>
                            <TableCell align="center">
                              <Chip label={stats.after} size="small" color="warning" />
                            </TableCell>
                            <TableCell align="center">
                              <Chip label={stats.removed} size="small" color="success" />
                            </TableCell>
                            <TableCell align="center">
                              <Typography variant="body2">
                                {stats.before > 0 ? Math.round((stats.removed / stats.before) * 100) : 0}%
                              </Typography>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>

                  {/* Filtering Benefits */}
                  <Card variant="outlined" sx={{ mt: 3, border: '2px solid', borderColor: 'success.main' }}>
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                        <CleaningServicesIcon color="success" />
                        <Typography variant="h6" color="success.main">
                          Filtering Benefits
                        </Typography>
                      </Box>
                      <List dense>
                        <ListItem>
                          <ListItemText 
                            primary="Improved Accuracy"
                            secondary={`Removed ${deepDiveResult.deepDive.analysis.falsePositiveFiltering.falsePositivesRemoved} false positive findings`}
                          />
                          <CheckCircleIcon color="success" />
                        </ListItem>
                        <ListItem>
                          <ListItemText 
                            primary="Reduced Noise"
                            secondary="Filtered out common false positives and irrelevant findings"
                          />
                          <CheckCircleIcon color="success" />
                        </ListItem>
                        <ListItem>
                          <ListItemText 
                            primary="Enhanced Reliability"
                            secondary="Higher confidence in remaining security findings"
                          />
                          <CheckCircleIcon color="success" />
                        </ListItem>
                        <ListItem>
                          <ListItemText 
                            primary="Time Savings"
                            secondary="Security teams can focus on genuine vulnerabilities"
                          />
                          <CheckCircleIcon color="success" />
                        </ListItem>
                      </List>
                    </CardContent>
                  </Card>

                  {/* Filtering Applied */}
                  <Card variant="outlined" sx={{ mt: 2 }}>
                    <CardContent>
                      <Typography variant="subtitle1" gutterBottom>
                        🔧 Applied Filters
                      </Typography>
                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                        <Chip label="SQL Injection FP Removal" size="small" color="primary" />
                        <Chip label="XSS Reflection Filtering" size="small" color="primary" />
                        <Chip label="Auth Bypass Public Endpoints" size="small" color="primary" />
                        <Chip label="CORS Legitimate Configs" size="small" color="primary" />
                        <Chip label="Technology Duplicate Removal" size="small" color="primary" />
                        <Chip label="API Static Asset Filtering" size="small" color="primary" />
                        <Chip label="Rate Limiting False Flags" size="small" color="primary" />
                      </Box>
                    </CardContent>
                  </Card>
                </Box>
              )}
            </AccordionDetails>
          </Accordion>

          {/* 12. Smart Vulnerability Prioritization */}
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <PriorityHighIcon color="error" />
                <Typography variant="h6">
                  🎯 Smart Vulnerability Prioritization
                </Typography>
                {deepDiveResult.deepDive?.analysis?.vulnerabilityPrioritization && (
                  <Chip 
                    label={`${deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.totalVulnerabilities || 0} vulnerabilities`}
                    color="warning" 
                    size="small"
                  />
                )}
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              {deepDiveResult.deepDive?.analysis?.vulnerabilityPrioritization && (
                <Box>
                  {/* Prioritization Overview */}
                  <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 2, mb: 3 }}>
                    <Card variant="outlined" sx={{ border: '2px solid', borderColor: 'error.main' }}>
                      <CardContent sx={{ textAlign: 'center' }}>
                        <Typography variant="h3" color="error">
                          {deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.criticalCount || 0}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Critical Priority
                        </Typography>
                        <Typography variant="caption" display="block">
                          Fix within 24h
                        </Typography>
                      </CardContent>
                    </Card>
                    
                    <Card variant="outlined" sx={{ border: '2px solid', borderColor: 'warning.main' }}>
                      <CardContent sx={{ textAlign: 'center' }}>
                        <Typography variant="h3" color="warning.main">
                          {deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.highCount || 0}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          High Priority
                        </Typography>
                        <Typography variant="caption" display="block">
                          Fix within 7 days
                        </Typography>
                      </CardContent>
                    </Card>
                    
                    <Card variant="outlined" sx={{ border: '2px solid', borderColor: 'info.main' }}>
                      <CardContent sx={{ textAlign: 'center' }}>
                        <Typography variant="h3" color="info.main">
                          {deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.mediumCount || 0}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Medium Priority
                        </Typography>
                        <Typography variant="caption" display="block">
                          Fix within 30 days
                        </Typography>
                      </CardContent>
                    </Card>
                    
                    <Card variant="outlined" sx={{ border: '2px solid', borderColor: 'success.main' }}>
                      <CardContent sx={{ textAlign: 'center' }}>
                        <Typography variant="h3" color="success.main">
                          {deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.lowCount || 0}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Low Priority
                        </Typography>
                        <Typography variant="caption" display="block">
                          Fix within 90 days
                        </Typography>
                      </CardContent>
                    </Card>
                  </Box>

                  {/* Average Priority Score */}
                  <Card variant="outlined" sx={{ mb: 3 }}>
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                        <AssessmentIcon color="primary" />
                        <Typography variant="h6">
                          Overall Priority Score
                        </Typography>
                        <Chip 
                          label={`${deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.averagePriorityScore || 0}/10`}
                          color={
                            (deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.averagePriorityScore || 0) >= 8.5 ? 'error' :
                            (deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.averagePriorityScore || 0) >= 7.0 ? 'warning' : 
                            (deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.averagePriorityScore || 0) >= 5.0 ? 'info' : 'success'
                          }
                          size="medium"
                        />
                      </Box>
                      <LinearProgress 
                        variant="determinate" 
                        value={(deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.averagePriorityScore || 0) * 10} 
                        sx={{ height: 10, borderRadius: 5 }}
                        color={
                          (deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.averagePriorityScore || 0) >= 8.5 ? 'error' :
                          (deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.averagePriorityScore || 0) >= 7.0 ? 'warning' : 
                          (deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.averagePriorityScore || 0) >= 5.0 ? 'info' : 'success'
                        }
                      />
                      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                        Higher scores indicate more urgent vulnerabilities requiring immediate attention
                      </Typography>
                    </CardContent>
                  </Card>

                  {/* Critical Vulnerabilities */}
                  {deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.criticalVulnerabilities?.length > 0 && (
                    <Card variant="outlined" sx={{ mb: 3, border: '2px solid', borderColor: 'error.main' }}>
                      <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                          <ErrorIcon color="error" />
                          <Typography variant="h6" color="error">
                            🚨 Critical Priority Vulnerabilities
                          </Typography>
                          <Chip label="IMMEDIATE ACTION REQUIRED" color="error" size="small" />
                        </Box>
                        <TableContainer component={Paper}>
                          <Table size="small">
                            <TableHead>
                              <TableRow>
                                <TableCell><strong>Vulnerability</strong></TableCell>
                                <TableCell align="center"><strong>Priority Score</strong></TableCell>
                                <TableCell align="center"><strong>Risk Level</strong></TableCell>
                                <TableCell align="center"><strong>Urgency</strong></TableCell>
                                <TableCell align="center"><strong>Fix By</strong></TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.criticalVulnerabilities.slice(0, 5).map((vuln: any, index: number) => (
                                <TableRow key={index}>
                                  <TableCell>
                                    <Box>
                                      <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                                        {vuln.vulnerability?.type}
                                      </Typography>
                                      <Typography variant="caption" color="text.secondary">
                                        {vuln.vulnerability?.endpoint}
                                      </Typography>
                                    </Box>
                                  </TableCell>
                                  <TableCell align="center">
                                    <Chip 
                                      label={vuln.priorityScore}
                                      color="error" 
                                      size="small"
                                    />
                                  </TableCell>
                                  <TableCell align="center">
                                    <Chip 
                                      label={vuln.priorityLevel}
                                      color="error" 
                                      size="small"
                                    />
                                  </TableCell>
                                  <TableCell align="center">
                                    <Chip 
                                      label={vuln.urgency}
                                      color={vuln.urgency === 'Immediate' ? 'error' : 'warning'} 
                                      size="small"
                                    />
                                  </TableCell>
                                  <TableCell align="center">
                                    <Typography variant="body2" color="error">
                                      {vuln.remediationTimeframe}
                                    </Typography>
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </CardContent>
                    </Card>
                  )}

                  {/* High Priority Vulnerabilities */}
                  {deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.highPriorityVulnerabilities?.length > 0 && (
                    <Card variant="outlined" sx={{ mb: 3, border: '2px solid', borderColor: 'warning.main' }}>
                      <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                          <WarningIcon color="warning" />
                          <Typography variant="h6" color="warning.main">
                            ⚠️ High Priority Vulnerabilities
                          </Typography>
                        </Box>
                        <TableContainer component={Paper}>
                          <Table size="small">
                            <TableHead>
                              <TableRow>
                                <TableCell><strong>Vulnerability</strong></TableCell>
                                <TableCell align="center"><strong>Priority Score</strong></TableCell>
                                <TableCell align="center"><strong>Exploitability</strong></TableCell>
                                <TableCell align="center"><strong>Business Impact</strong></TableCell>
                                <TableCell align="center"><strong>Fix Complexity</strong></TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.highPriorityVulnerabilities.slice(0, 5).map((vuln: any, index: number) => (
                                <TableRow key={index}>
                                  <TableCell>
                                    <Box>
                                      <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                                        {vuln.vulnerability?.type}
                                      </Typography>
                                      <Typography variant="caption" color="text.secondary">
                                        {vuln.vulnerability?.category}
                                      </Typography>
                                    </Box>
                                  </TableCell>
                                  <TableCell align="center">
                                    <Chip 
                                      label={vuln.priorityScore}
                                      color="warning" 
                                      size="small"
                                    />
                                  </TableCell>
                                  <TableCell align="center">
                                    <Typography variant="body2">
                                      {vuln.exploitabilityScore}/10
                                    </Typography>
                                  </TableCell>
                                  <TableCell align="center">
                                    <Typography variant="body2">
                                      {vuln.businessImpactScore}/10
                                    </Typography>
                                  </TableCell>
                                  <TableCell align="center">
                                    <Chip 
                                      label={vuln.detailedAnalysis?.remediationComplexity?.complexityLevel || 'Medium'}
                                      color={
                                        vuln.detailedAnalysis?.remediationComplexity?.complexityLevel === 'High' ? 'error' :
                                        vuln.detailedAnalysis?.remediationComplexity?.complexityLevel === 'Low' ? 'success' : 'warning'
                                      }
                                      size="small"
                                    />
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </CardContent>
                    </Card>
                  )}

                  {/* Remediation Timeline */}
                  <Card variant="outlined" sx={{ mb: 3 }}>
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                        <TimelineIcon color="primary" />
                        <Typography variant="h6">
                          📅 Remediation Timeline
                        </Typography>
                      </Box>
                      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 2 }}>
                        <Card variant="outlined">
                          <CardContent sx={{ textAlign: 'center' }}>
                            <ErrorIcon color="error" sx={{ fontSize: 40, mb: 1 }} />
                            <Typography variant="h6" color="error">
                              {deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.remediationTimeframes?.immediate || 0}
                            </Typography>
                            <Typography variant="body2">
                              Immediate (24h)
                            </Typography>
                          </CardContent>
                        </Card>
                        
                        <Card variant="outlined">
                          <CardContent sx={{ textAlign: 'center' }}>
                            <WarningIcon color="warning" sx={{ fontSize: 40, mb: 1 }} />
                            <Typography variant="h6" color="warning.main">
                              {deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.remediationTimeframes?.urgent || 0}
                            </Typography>
                            <Typography variant="body2">
                              Urgent (7 days)
                            </Typography>
                          </CardContent>
                        </Card>
                        
                        <Card variant="outlined">
                          <CardContent sx={{ textAlign: 'center' }}>
                            <InfoIcon color="info" sx={{ fontSize: 40, mb: 1 }} />
                            <Typography variant="h6" color="info.main">
                              {deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.remediationTimeframes?.normal || 0}
                            </Typography>
                            <Typography variant="body2">
                              Normal (30 days)
                            </Typography>
                          </CardContent>
                        </Card>
                        
                        <Card variant="outlined">
                          <CardContent sx={{ textAlign: 'center' }}>
                            <CheckCircleIcon color="success" sx={{ fontSize: 40, mb: 1 }} />
                            <Typography variant="h6" color="success.main">
                              {deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.remediationTimeframes?.scheduled || 0}
                            </Typography>
                            <Typography variant="body2">
                              Scheduled (90 days)
                            </Typography>
                          </CardContent>
                        </Card>
                      </Box>
                    </CardContent>
                  </Card>

                  {/* Category Distribution */}
                  {deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats?.categoryDistribution && (
                    <Card variant="outlined" sx={{ mb: 3 }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>
                          📊 Vulnerability Category Distribution
                        </Typography>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                          {Object.entries(deepDiveResult.deepDive.analysis.vulnerabilityPrioritization.prioritizationStats.categoryDistribution).map(([category, count]: [string, any]) => (
                            <Chip 
                              key={category}
                              label={`${category}: ${count}`}
                              color="primary" 
                              size="small"
                            />
                          ))}
                        </Box>
                      </CardContent>
                    </Card>
                  )}

                  {/* Prioritization Benefits */}
                  <Card variant="outlined" sx={{ border: '2px solid', borderColor: 'success.main' }}>
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                        <BugReportIcon color="success" />
                        <Typography variant="h6" color="success.main">
                          Smart Prioritization Benefits
                        </Typography>
                      </Box>
                      <List dense>
                        <ListItem>
                          <ListItemText 
                            primary="Risk-Based Prioritization"
                            secondary="Vulnerabilities prioritized by actual risk impact and exploitability"
                          />
                          <CheckCircleIcon color="success" />
                        </ListItem>
                        <ListItem>
                          <ListItemText 
                            primary="Resource Optimization"
                            secondary="Focus security efforts on highest priority vulnerabilities first"
                          />
                          <CheckCircleIcon color="success" />
                        </ListItem>
                        <ListItem>
                          <ListItemText 
                            primary="Business Impact Assessment"
                            secondary="Considers compliance, reputation, and operational impact"
                          />
                          <CheckCircleIcon color="success" />
                        </ListItem>
                        <ListItem>
                          <ListItemText 
                            primary="Remediation Planning"
                            secondary="Clear timeframes and complexity assessments for fixes"
                          />
                          <CheckCircleIcon color="success" />
                        </ListItem>
                      </List>
                    </CardContent>
                  </Card>
                </Box>
              )}
            </AccordionDetails>
          </Accordion>

          {/* 13. Pattern Recognition Algorithms */}
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <Box
                  sx={{
                    backgroundColor: 'warning.main',
                    color: 'white',
                    borderRadius: '50%',
                    width: 24,
                    height: 24,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '0.8rem',
                    fontWeight: 'bold'
                  }}
                >
                  13
                </Box>
                <Box>
                  <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                    🔍 Pattern Recognition Analysis
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Advanced pattern detection and analysis algorithms
                  </Typography>
                </Box>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              {deepDiveResult.deepDive.analysis.patternRecognition && (
                <Box>
                  {/* Pattern Statistics Overview */}
                  <Card variant="outlined" sx={{ mb: 3, border: '2px solid', borderColor: 'warning.main' }}>
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Box
                            sx={{
                              width: 12,
                              height: 12,
                              borderRadius: '50%',
                              backgroundColor: 'warning.main'
                            }}
                          />
                          <Typography variant="h6" sx={{ fontWeight: 'bold', color: 'warning.main' }}>
                            Pattern Analysis Overview
                          </Typography>
                        </Box>
                      </Box>
                      
                      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 2, mb: 3 }}>
                        <Card variant="outlined">
                          <CardContent sx={{ textAlign: 'center' }}>
                            <Typography variant="h4" color="warning.main" sx={{ fontWeight: 'bold' }}>
                              {deepDiveResult.deepDive.analysis.patternRecognition.patternStatistics?.totalPatterns || 0}
                            </Typography>
                            <Typography variant="body2">
                              Total Patterns Detected
                            </Typography>
                          </CardContent>
                        </Card>
                        
                        <Card variant="outlined">
                          <CardContent sx={{ textAlign: 'center' }}>
                            <Typography variant="h4" color="error.main" sx={{ fontWeight: 'bold' }}>
                              {deepDiveResult.deepDive.analysis.patternRecognition.patternStatistics?.patternTypes?.attack || 0}
                            </Typography>
                            <Typography variant="body2">
                              Attack Patterns
                            </Typography>
                          </CardContent>
                        </Card>
                        
                        <Card variant="outlined">
                          <CardContent sx={{ textAlign: 'center' }}>
                            <Typography variant="h4" color="info.main" sx={{ fontWeight: 'bold' }}>
                              {deepDiveResult.deepDive.analysis.patternRecognition.patternStatistics?.patternTypes?.vulnerability || 0}
                            </Typography>
                            <Typography variant="body2">
                              Vulnerability Patterns
                            </Typography>
                          </CardContent>
                        </Card>
                        
                        <Card variant="outlined">
                          <CardContent sx={{ textAlign: 'center' }}>
                            <Typography variant="h4" color="success.main" sx={{ fontWeight: 'bold' }}>
                              {deepDiveResult.deepDive.analysis.patternRecognition.patternStatistics?.patternTypes?.behavioral || 0}
                            </Typography>
                            <Typography variant="body2">
                              Behavioral Patterns
                            </Typography>
                          </CardContent>
                        </Card>
                      </Box>
                    </CardContent>
                  </Card>

                  {/* Attack Patterns */}
                  {deepDiveResult.deepDive.analysis.patternRecognition.attackPatterns?.length > 0 && (
                    <Card variant="outlined" sx={{ mb: 3 }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          🎯 Attack Patterns
                          <Chip label={deepDiveResult.deepDive.analysis.patternRecognition.attackPatterns.length} color="error" size="small" />
                        </Typography>
                        {deepDiveResult.deepDive.analysis.patternRecognition.attackPatterns.map((pattern: any, index: number) => (
                          <Card key={index} variant="outlined" sx={{ mb: 2, border: '1px solid', borderColor: 'error.light' }}>
                            <CardContent>
                              <Box sx={{ display: 'flex', justifyContent: 'between', alignItems: 'flex-start', mb: 2 }}>
                                <Typography variant="subtitle1" sx={{ fontWeight: 'bold', color: 'error.main' }}>
                                  {pattern.type}
                                </Typography>
                                <Box sx={{ display: 'flex', gap: 1 }}>
                                  <Chip label={pattern.severity} color="error" size="small" />
                                  <Chip label={`${Math.round(pattern.confidence * 100)}% confidence`} color="primary" size="small" />
                                </Box>
                              </Box>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                <strong>Category:</strong> {pattern.category}
                              </Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                <strong>Pattern:</strong> {pattern.pattern}
                              </Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                                <strong>Occurrences:</strong> {pattern.occurrences}
                              </Typography>
                              {pattern.characteristics && (
                                <Box>
                                  <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 1 }}>
                                    Characteristics:
                                  </Typography>
                                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                    {pattern.characteristics.map((char: string, idx: number) => (
                                      <Chip key={idx} label={char} size="small" variant="outlined" />
                                    ))}
                                  </Box>
                                </Box>
                              )}
                            </CardContent>
                          </Card>
                        ))}
                      </CardContent>
                    </Card>
                  )}

                  {/* Vulnerability Patterns */}
                  {deepDiveResult.deepDive.analysis.patternRecognition.vulnerabilityPatterns?.length > 0 && (
                    <Card variant="outlined" sx={{ mb: 3 }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          🔐 Vulnerability Patterns
                          <Chip label={deepDiveResult.deepDive.analysis.patternRecognition.vulnerabilityPatterns.length} color="warning" size="small" />
                        </Typography>
                        {deepDiveResult.deepDive.analysis.patternRecognition.vulnerabilityPatterns.map((pattern: any, index: number) => (
                          <Card key={index} variant="outlined" sx={{ mb: 2, border: '1px solid', borderColor: 'warning.light' }}>
                            <CardContent>
                              <Typography variant="subtitle1" sx={{ fontWeight: 'bold', color: 'warning.main', mb: 1 }}>
                                {pattern.type}
                              </Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                <strong>Pattern:</strong> {pattern.pattern}
                              </Typography>
                              <Typography variant="body2" color="text.secondary">
                                <strong>Severity:</strong> {pattern.severity}
                              </Typography>
                            </CardContent>
                          </Card>
                        ))}
                      </CardContent>
                    </Card>
                  )}

                  {/* Behavioral Patterns */}
                  {deepDiveResult.deepDive.analysis.patternRecognition.behavioralPatterns?.length > 0 && (
                    <Card variant="outlined" sx={{ mb: 3 }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          📊 Behavioral Patterns
                          <Chip label={deepDiveResult.deepDive.analysis.patternRecognition.behavioralPatterns.length} color="info" size="small" />
                        </Typography>
                        {deepDiveResult.deepDive.analysis.patternRecognition.behavioralPatterns.map((pattern: any, index: number) => (
                          <Card key={index} variant="outlined" sx={{ mb: 2, border: '1px solid', borderColor: 'info.light' }}>
                            <CardContent>
                              <Typography variant="subtitle1" sx={{ fontWeight: 'bold', color: 'info.main', mb: 1 }}>
                                {pattern.type}
                              </Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                {pattern.description}
                              </Typography>
                              {pattern.insights && (
                                <Box sx={{ mt: 2 }}>
                                  <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 1 }}>
                                    Insights:
                                  </Typography>
                                  <List dense>
                                    {pattern.insights.map((insight: string, idx: number) => (
                                      <ListItem key={idx}>
                                        <ListItemText primary={insight} />
                                      </ListItem>
                                    ))}
                                  </List>
                                </Box>
                              )}
                            </CardContent>
                          </Card>
                        ))}
                      </CardContent>
                    </Card>
                  )}

                  {/* Clustering Analysis */}
                  {deepDiveResult.deepDive.analysis.patternRecognition.clustering?.clusters?.length > 0 && (
                    <Card variant="outlined" sx={{ mb: 3 }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          🎯 Vulnerability Clustering
                          <Chip label={`${deepDiveResult.deepDive.analysis.patternRecognition.clustering.clusterCount} clusters`} color="secondary" size="small" />
                        </Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                          Method: {deepDiveResult.deepDive.analysis.patternRecognition.clustering.clusteringMethod}
                          {deepDiveResult.deepDive.analysis.patternRecognition.clustering.silhouetteScore && (
                            <span> | Silhouette Score: {deepDiveResult.deepDive.analysis.patternRecognition.clustering.silhouetteScore.toFixed(2)}</span>
                          )}
                        </Typography>
                        {deepDiveResult.deepDive.analysis.patternRecognition.clustering.clusters.map((cluster: any, index: number) => (
                          <Card key={index} variant="outlined" sx={{ mb: 2, border: '1px solid', borderColor: 'secondary.light' }}>
                            <CardContent>
                              <Typography variant="subtitle1" sx={{ fontWeight: 'bold', color: 'secondary.main', mb: 1 }}>
                                Cluster {cluster.id + 1}
                              </Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                <strong>Vulnerabilities in cluster:</strong> {cluster.points?.length || 0}
                              </Typography>
                              {cluster.characteristics?.length > 0 && (
                                <Box>
                                  <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 1 }}>
                                    Common Characteristics:
                                  </Typography>
                                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                    {cluster.characteristics.map((char: string, idx: number) => (
                                      <Chip key={idx} label={char} size="small" color="secondary" variant="outlined" />
                                    ))}
                                  </Box>
                                </Box>
                              )}
                            </CardContent>
                          </Card>
                        ))}
                      </CardContent>
                    </Card>
                  )}

                  {/* Anomaly Detection */}
                  {deepDiveResult.deepDive.analysis.patternRecognition.anomalyDetection?.anomalies?.length > 0 && (
                    <Card variant="outlined" sx={{ mb: 3 }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          ⚠️ Anomaly Detection
                          <Chip label={`${deepDiveResult.deepDive.analysis.patternRecognition.anomalyDetection.anomalies.length} anomalies`} color="warning" size="small" />
                        </Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                          Method: {deepDiveResult.deepDive.analysis.patternRecognition.anomalyDetection.detectionMethod}
                          | Threshold: {(deepDiveResult.deepDive.analysis.patternRecognition.anomalyDetection.threshold * 100).toFixed(0)}%
                          | Anomaly Score: {(deepDiveResult.deepDive.analysis.patternRecognition.anomalyDetection.anomalyScore * 100).toFixed(1)}%
                        </Typography>
                        <Alert severity="warning" sx={{ mb: 2 }}>
                          <AlertTitle>Anomalous Security Findings Detected</AlertTitle>
                          {deepDiveResult.deepDive.analysis.patternRecognition.anomalyDetection.anomalies.length} security findings 
                          appear to be statistical outliers and may indicate advanced attack patterns or unique vulnerabilities.
                        </Alert>
                      </CardContent>
                    </Card>
                  )}

                  {/* Pattern Recognition Insights */}
                  {deepDiveResult.deepDive.analysis.patternRecognition.patternStatistics?.insights?.length > 0 && (
                    <Card variant="outlined" sx={{ border: '2px solid', borderColor: 'success.main' }}>
                      <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Box
                              sx={{
                                width: 12,
                                height: 12,
                                borderRadius: '50%',
                                backgroundColor: 'success.main'
                              }}
                            />
                            <Typography variant="h6" sx={{ fontWeight: 'bold', color: 'success.main' }}>
                              Pattern Recognition Insights
                            </Typography>
                          </Box>
                        </Box>
                        <List>
                          {deepDiveResult.deepDive.analysis.patternRecognition.patternStatistics.insights.map((insight: string, index: number) => (
                            <ListItem key={index}>
                              <ListItemText 
                                primary={insight}
                                sx={{ color: 'success.main' }}
                              />
                              <CheckCircleIcon color="success" />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  )}
                </Box>
              )}
            </AccordionDetails>
          </Accordion>

          {/* 14. Business Logic Context Analysis */}
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <Box
                  sx={{
                    backgroundColor: 'purple',
                    color: 'white',
                    borderRadius: '50%',
                    width: 24,
                    height: 24,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '0.8rem',
                    fontWeight: 'bold'
                  }}
                >
                  14
                </Box>
                <Box>
                  <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                    🧠 Business Logic Context Analysis
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Business context security analysis and risk assessment
                  </Typography>
                </Box>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              {deepDiveResult.deepDive.analysis.businessLogicContext && (
                <Box>
                  {/* Business Risk Assessment Overview */}
                  <Card variant="outlined" sx={{ mb: 3, border: '2px solid', borderColor: 'purple' }}>
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Box
                            sx={{
                              width: 12,
                              height: 12,
                              borderRadius: '50%',
                              backgroundColor: 'purple'
                            }}
                          />
                          <Typography variant="h6" sx={{ fontWeight: 'bold', color: 'purple' }}>
                            Business Risk Assessment
                          </Typography>
                        </Box>
                      </Box>
                      
                      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 2, mb: 3 }}>
                        <Card variant="outlined">
                          <CardContent sx={{ textAlign: 'center' }}>
                            <Typography variant="h5" color="error.main" sx={{ fontWeight: 'bold' }}>
                              {deepDiveResult.deepDive.analysis.businessLogicContext.businessRiskAssessment?.overallRiskLevel || 'Medium'}
                            </Typography>
                            <Typography variant="body2">
                              Overall Business Risk Level
                            </Typography>
                          </CardContent>
                        </Card>
                        
                        <Card variant="outlined">
                          <CardContent sx={{ textAlign: 'center' }}>
                            <Typography variant="h5" color="warning.main" sx={{ fontWeight: 'bold' }}>
                              {deepDiveResult.deepDive.analysis.businessLogicContext.businessRiskAssessment?.businessCriticalityScore || 0}
                            </Typography>
                            <Typography variant="body2">
                              Business Criticality Score
                            </Typography>
                          </CardContent>
                        </Card>
                        
                        <Card variant="outlined">
                          <CardContent sx={{ textAlign: 'center' }}>
                            <Typography variant="h5" color="info.main" sx={{ fontWeight: 'bold' }}>
                              {deepDiveResult.deepDive.analysis.businessLogicContext.contextualVulnerabilities?.length || 0}
                            </Typography>
                            <Typography variant="body2">
                              Contextual Vulnerabilities
                            </Typography>
                          </CardContent>
                        </Card>
                        
                        <Card variant="outlined">
                          <CardContent sx={{ textAlign: 'center' }}>
                            <Typography variant="h5" color="secondary.main" sx={{ fontWeight: 'bold' }}>
                              {deepDiveResult.deepDive.analysis.businessLogicContext.businessRuleViolations?.length || 0}
                            </Typography>
                            <Typography variant="body2">
                              Business Rule Violations
                            </Typography>
                          </CardContent>
                        </Card>
                      </Box>
                    </CardContent>
                  </Card>

                  {/* Contextual Vulnerabilities */}
                  {deepDiveResult.deepDive.analysis.businessLogicContext.contextualVulnerabilities?.length > 0 && (
                    <Card variant="outlined" sx={{ mb: 3 }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          🎯 Contextual Vulnerabilities
                          <Chip label={deepDiveResult.deepDive.analysis.businessLogicContext.contextualVulnerabilities.length} color="error" size="small" />
                        </Typography>
                        {deepDiveResult.deepDive.analysis.businessLogicContext.contextualVulnerabilities.map((vuln: any, index: number) => (
                          <Card key={index} variant="outlined" sx={{ mb: 2, border: '1px solid', borderColor: 'error.light' }}>
                            <CardContent>
                              <Box sx={{ display: 'flex', justifyContent: 'between', alignItems: 'flex-start', mb: 2 }}>
                                <Typography variant="subtitle1" sx={{ fontWeight: 'bold', color: 'error.main' }}>
                                  {vuln.type}
                                </Typography>
                                <Box sx={{ display: 'flex', gap: 1 }}>
                                  <Chip label={vuln.severity} color="error" size="small" />
                                  <Chip label={vuln.remediationPriority} color="warning" size="small" />
                                </Box>
                              </Box>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                <strong>Business Impact:</strong> {vuln.businessImpact}
                              </Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                <strong>Context:</strong> {vuln.context}
                              </Typography>
                              {vuln.affectedBusinessProcesses && (
                                <Box sx={{ mt: 2 }}>
                                  <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 1 }}>
                                    Affected Business Processes:
                                  </Typography>
                                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                    {vuln.affectedBusinessProcesses.map((process: string, idx: number) => (
                                      <Chip key={idx} label={process} size="small" color="error" variant="outlined" />
                                    ))}
                                  </Box>
                                </Box>
                              )}
                            </CardContent>
                          </Card>
                        ))}
                      </CardContent>
                    </Card>
                  )}

                  {/* Business Impact Analysis */}
                  {deepDiveResult.deepDive.analysis.businessLogicContext.businessImpactAnalysis && (
                    <Card variant="outlined" sx={{ mb: 3 }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>
                          📊 Business Impact Analysis
                        </Typography>
                        
                        {/* Criticality Assessment */}
                        {deepDiveResult.deepDive.analysis.businessLogicContext.businessImpactAnalysis.criticalityAssessment && (
                          <Card variant="outlined" sx={{ mb: 2 }}>
                            <CardContent>
                              <Typography variant="subtitle1" sx={{ fontWeight: 'bold', mb: 1 }}>
                                Business Criticality Assessment
                              </Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                <strong>Level:</strong> {deepDiveResult.deepDive.analysis.businessLogicContext.businessImpactAnalysis.criticalityAssessment.level}
                              </Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                <strong>Score:</strong> {deepDiveResult.deepDive.analysis.businessLogicContext.businessImpactAnalysis.criticalityAssessment.score}/100
                              </Typography>
                              {deepDiveResult.deepDive.analysis.businessLogicContext.businessImpactAnalysis.criticalityAssessment.factors && (
                                <Box sx={{ mt: 1 }}>
                                  <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 1 }}>
                                    Critical Factors:
                                  </Typography>
                                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                    {deepDiveResult.deepDive.analysis.businessLogicContext.businessImpactAnalysis.criticalityAssessment.factors.map((factor: string, idx: number) => (
                                      <Chip key={idx} label={factor} size="small" color="primary" variant="outlined" />
                                    ))}
                                  </Box>
                                </Box>
                              )}
                            </CardContent>
                          </Card>
                        )}

                        {/* Stakeholder Impact */}
                        {deepDiveResult.deepDive.analysis.businessLogicContext.businessImpactAnalysis.stakeholderImpact && (
                          <Card variant="outlined" sx={{ mb: 2 }}>
                            <CardContent>
                              <Typography variant="subtitle1" sx={{ fontWeight: 'bold', mb: 2 }}>
                                Stakeholder Impact Assessment
                              </Typography>
                              <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 2 }}>
                                {Object.entries(deepDiveResult.deepDive.analysis.businessLogicContext.businessImpactAnalysis.stakeholderImpact).map(([stakeholder, impact]: [string, any]) => (
                                  <Card key={stakeholder} variant="outlined">
                                    <CardContent>
                                      <Typography variant="subtitle2" sx={{ fontWeight: 'bold', textTransform: 'capitalize', mb: 1 }}>
                                        {stakeholder}
                                      </Typography>
                                      <Typography variant="body2" color="text.secondary">
                                        {impact}
                                      </Typography>
                                    </CardContent>
                                  </Card>
                                ))}
                              </Box>
                            </CardContent>
                          </Card>
                        )}
                      </CardContent>
                    </Card>
                  )}

                  {/* Workflow Analysis */}
                  {deepDiveResult.deepDive.analysis.businessLogicContext.workflowAnalysis && (
                    <Card variant="outlined" sx={{ mb: 3 }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>
                          🔄 Workflow Security Analysis
                        </Typography>
                        
                        {/* Critical Workflows */}
                        {deepDiveResult.deepDive.analysis.businessLogicContext.workflowAnalysis.criticalWorkflows?.length > 0 && (
                          <Box sx={{ mb: 3 }}>
                            <Typography variant="subtitle1" sx={{ fontWeight: 'bold', mb: 2 }}>
                              Critical Business Workflows
                            </Typography>
                            {deepDiveResult.deepDive.analysis.businessLogicContext.workflowAnalysis.criticalWorkflows.map((workflow: any, index: number) => (
                              <Card key={index} variant="outlined" sx={{ mb: 1 }}>
                                <CardContent sx={{ py: 1 }}>
                                  <Box sx={{ display: 'flex', justifyContent: 'between', alignItems: 'center' }}>
                                    <Typography variant="body1" sx={{ fontWeight: 'bold' }}>
                                      {workflow.name}
                                    </Typography>
                                    <Chip 
                                      label={workflow.criticality} 
                                      color={workflow.criticality === 'High' ? 'error' : 'warning'} 
                                      size="small" 
                                    />
                                  </Box>
                                  <Typography variant="body2" color="text.secondary">
                                    Endpoints: {workflow.endpoints?.length || 0}
                                  </Typography>
                                </CardContent>
                              </Card>
                            ))}
                          </Box>
                        )}

                        {/* Workflow Vulnerabilities */}
                        {deepDiveResult.deepDive.analysis.businessLogicContext.workflowAnalysis.workflowVulnerabilities?.length > 0 && (
                          <Box>
                            <Typography variant="subtitle1" sx={{ fontWeight: 'bold', mb: 2 }}>
                              Workflow Vulnerabilities
                            </Typography>
                            <Alert severity="warning" sx={{ mb: 2 }}>
                              <AlertTitle>Workflow Security Issues Detected</AlertTitle>
                              {deepDiveResult.deepDive.analysis.businessLogicContext.workflowAnalysis.workflowVulnerabilities.length} workflow-related 
                              security vulnerabilities found that could impact business processes.
                            </Alert>
                          </Box>
                        )}
                      </CardContent>
                    </Card>
                  )}

                  {/* Business Rule Violations */}
                  {deepDiveResult.deepDive.analysis.businessLogicContext.businessRuleViolations?.length > 0 && (
                    <Card variant="outlined" sx={{ mb: 3 }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          ⚖️ Business Rule Violations
                          <Chip label={deepDiveResult.deepDive.analysis.businessLogicContext.businessRuleViolations.length} color="warning" size="small" />
                        </Typography>
                        {deepDiveResult.deepDive.analysis.businessLogicContext.businessRuleViolations.map((violation: any, index: number) => (
                          <Card key={index} variant="outlined" sx={{ mb: 2, border: '1px solid', borderColor: 'warning.light' }}>
                            <CardContent>
                              <Typography variant="subtitle1" sx={{ fontWeight: 'bold', color: 'warning.main', mb: 1 }}>
                                {violation.type}
                              </Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                <strong>Description:</strong> {violation.description}
                              </Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                <strong>Business Impact:</strong> {violation.businessImpact}
                              </Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                                <strong>Recommendation:</strong> {violation.recommendation}
                              </Typography>
                              <Chip label={violation.severity} color="warning" size="small" />
                            </CardContent>
                          </Card>
                        ))}
                      </CardContent>
                    </Card>
                  )}

                  {/* Financial Impact */}
                  {deepDiveResult.deepDive.analysis.businessLogicContext.businessRiskAssessment?.financialImpactEstimate && (
                    <Card variant="outlined" sx={{ mb: 3 }}>
                      <CardContent>
                        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          💰 Financial Impact Estimate
                        </Typography>
                        <Typography variant="h5" color="error.main" sx={{ fontWeight: 'bold', mb: 2 }}>
                          {deepDiveResult.deepDive.analysis.businessLogicContext.businessRiskAssessment.financialImpactEstimate.potentialLoss}
                        </Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                          {deepDiveResult.deepDive.analysis.businessLogicContext.businessRiskAssessment.financialImpactEstimate.category}
                        </Typography>
                        {deepDiveResult.deepDive.analysis.businessLogicContext.businessRiskAssessment.financialImpactEstimate.factors && (
                          <Box>
                            <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 1 }}>
                              Impact Factors:
                            </Typography>
                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                              {deepDiveResult.deepDive.analysis.businessLogicContext.businessRiskAssessment.financialImpactEstimate.factors.map((factor: string, idx: number) => (
                                <Chip key={idx} label={factor} size="small" color="error" variant="outlined" />
                              ))}
                            </Box>
                          </Box>
                        )}
                      </CardContent>
                    </Card>
                  )}

                  {/* Contextual Recommendations */}
                  {deepDiveResult.deepDive.analysis.businessLogicContext.contextualRecommendations?.length > 0 && (
                    <Card variant="outlined" sx={{ border: '2px solid', borderColor: 'success.main' }}>
                      <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Box
                              sx={{
                                width: 12,
                                height: 12,
                                borderRadius: '50%',
                                backgroundColor: 'success.main'
                              }}
                            />
                            <Typography variant="h6" sx={{ fontWeight: 'bold', color: 'success.main' }}>
                              Business Context Recommendations
                            </Typography>
                          </Box>
                        </Box>
                        <List>
                          {deepDiveResult.deepDive.analysis.businessLogicContext.contextualRecommendations.map((recommendation: string, index: number) => (
                            <ListItem key={index}>
                              <ListItemText 
                                primary={recommendation}
                                sx={{ color: 'success.main' }}
                              />
                              <CheckCircleIcon color="success" />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  )}
                </Box>
              )}
            </AccordionDetails>
          </Accordion>

          {/* Recommendations */}
          <Card sx={{ mt: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                💡 Security Recommendations
              </Typography>
              <List>
                {deepDiveResult.deepDive?.recommendations?.map((rec: string, index: number) => (
                  <ListItem key={index}>
                    <ListItemText primary={rec} />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>
        </Box>
      )}
    </Box>
  );
};

export default ApiSecurityDeepDive;
