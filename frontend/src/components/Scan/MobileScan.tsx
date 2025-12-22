import React, { useState } from 'react';
import {
  Box,
  Typography,
  Button,
  Alert,
  Paper,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  LinearProgress,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material';
import {
  CloudUpload as UploadIcon,
  Android as AndroidIcon,
  Apple as AppleIcon,
  PlayArrow as PlayIcon,
  GetApp as DownloadIcon,
  Refresh as RefreshIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { mobsfService, MobileScanResult } from '../../services/mobsfService';

const steps = [
  'Mobil Uygulama Seç',
  'Tarama Türünü Belirle',
  'Taramayı Başlat',
  'Sonuçları Görüntüle'
];

const MobileScan: React.FC = () => {
  const navigate = useNavigate();
  const [activeStep, setActiveStep] = useState(0);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [scanName, setScanName] = useState('');
  const [scanType, setScanType] = useState('static'); // static, dynamic, both
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [currentScan, setCurrentScan] = useState<MobileScanResult | null>(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [progressMessage, setProgressMessage] = useState('');

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const allowedTypes = ['.apk', '.aab', '.ipa', '.zip'];
      const fileExtension = '.' + file.name.split('.').pop()?.toLowerCase();
      
      if (allowedTypes.includes(fileExtension)) {
        setSelectedFile(file);
        setScanName(`Mobile Scan - ${file.name}`);
        setError(null);
      } else {
        setError('Geçersiz dosya türü. Sadece APK, AAB, IPA ve ZIP dosyaları kabul edilir.');
        setSelectedFile(null);
      }
    }
  };

  const handleNext = () => {
    if (activeStep === 0 && !selectedFile) {
      setError('Lütfen bir dosya seçin');
      return;
    }
    if (activeStep === 1 && !scanType) {
      setError('Lütfen tarama türünü seçin');
      return;
    }
    setActiveStep((prevStep) => prevStep + 1);
    setError(null);
  };

  const handleBack = () => {
    setActiveStep((prevStep) => prevStep - 1);
  };

  const handleReset = () => {
    setActiveStep(0);
    setSelectedFile(null);
    setScanName('');
    setScanType('static');
    setCurrentScan(null);
    setScanProgress(0);
    setProgressMessage('');
    setError(null);
    setSuccess(null);
  };

  const startScan = async () => {
    if (!selectedFile) return;

    try {
      setLoading(true);
      setError(null);
      setScanProgress(10);
      setProgressMessage('Dosya yükleniyor...');

      const result = await mobsfService.uploadAndScan(selectedFile, scanName);
      
      setScanProgress(30);
      setProgressMessage('Statik analiz başlatılıyor...');
      
      // Poll for scan completion
      const scanId = result.scanId;
      let attempts = 0;
      const maxAttempts = 60; // 5 minutes max
      
      const pollScan = async () => {
        try {
          const scanResult = await mobsfService.getScanResults(scanId);
          setCurrentScan(scanResult);
          
          if (scanResult.status === 'COMPLETED') {
            setScanProgress(100);
            setProgressMessage('Tarama tamamlandı!');
            setSuccess('Mobil uygulama taraması başarıyla tamamlandı!');
            setActiveStep(3);
          } else if (scanResult.status === 'FAILED') {
            setError('Tarama başarısız oldu');
            setScanProgress(0);
          } else if (scanResult.status === 'RUNNING') {
            setScanProgress(Math.min(50 + (attempts * 2), 90));
            setProgressMessage('Tarama devam ediyor...');
            
            if (attempts < maxAttempts) {
              attempts++;
              setTimeout(pollScan, 5000); // Check every 5 seconds
            } else {
              setError('Tarama zaman aşımına uğradı');
            }
          }
        } catch (err: any) {
          setError('Tarama durumu kontrol edilemedi: ' + err.message);
        }
      };

      // Start polling after initial delay
      setTimeout(pollScan, 2000);
      
    } catch (err: any) {
      setError('Tarama başlatılamadı: ' + err.message);
      setScanProgress(0);
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = async () => {
    if (!currentScan) return;
    
    try {
      await mobsfService.downloadPDFReport(currentScan.id);
      setSuccess('Rapor başarıyla indirildi!');
    } catch (err: any) {
      setError('Rapor indirilemedi: ' + err.message);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f57c00';
      case 'medium': return '#fbc02d';
      case 'low': return '#388e3c';
      case 'info': return '#1976d2';
      default: return '#1976d2';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return <ErrorIcon sx={{ color: getSeverityColor(severity) }} />;
      case 'high': return <WarningIcon sx={{ color: getSeverityColor(severity) }} />;
      case 'medium': return <WarningIcon sx={{ color: getSeverityColor(severity) }} />;
      case 'low': return <InfoIcon sx={{ color: getSeverityColor(severity) }} />;
      case 'info': return <InfoIcon sx={{ color: getSeverityColor(severity) }} />;
      default: return <InfoIcon sx={{ color: getSeverityColor(severity) }} />;
    }
  };

  const getPlatformFromFileName = (fileName: string): 'ANDROID' | 'IOS' => {
    const ext = fileName.toLowerCase().split('.').pop();
    return (ext === 'apk' || ext === 'aab') ? 'ANDROID' : 'IOS';
  };

  const getCurrentPlatform = (): 'ANDROID' | 'IOS' => {
    if (currentScan?.mobileAppScan?.platform) {
      return currentScan.mobileAppScan.platform as 'ANDROID' | 'IOS';
    }
    if (currentScan?.targetUrl) {
      return getPlatformFromFileName(currentScan.targetUrl);
    }
    if (selectedFile) {
      return getPlatformFromFileName(selectedFile.name);
    }
    return 'ANDROID';
  };

  const getStepContent = (step: number) => {
    switch (step) {
      case 0:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Mobil Uygulama Dosyasını Seçin
            </Typography>
            <Typography variant="body2" color="text.secondary" paragraph>
              Analiz edilecek mobil uygulamayı yükleyin. Android APK/AAB veya iOS IPA dosyalarını destekliyoruz.
            </Typography>
            
            <input
              type="file"
              accept=".apk,.aab,.ipa,.zip"
              onChange={handleFileUpload}
              style={{ display: 'none' }}
              id="mobile-file-upload"
            />
            <label htmlFor="mobile-file-upload">
              <Button
                variant="outlined"
                component="span"
                startIcon={<UploadIcon />}
                fullWidth
                sx={{ mb: 2, py: 2 }}
              >
                Dosya Seç (APK, AAB, IPA, ZIP)
              </Button>
            </label>
            
            {selectedFile && (
              <Alert severity="success" sx={{ mb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  {selectedFile.name.endsWith('.apk') || selectedFile.name.endsWith('.aab') ? (
                    <AndroidIcon sx={{ mr: 1, color: '#a4c639' }} />
                  ) : (
                    <AppleIcon sx={{ mr: 1, color: '#000' }} />
                  )}
                  <Box>
                    <Typography variant="subtitle2">
                      {selectedFile.name}
                    </Typography>
                    <Typography variant="caption">
                      Boyut: {(selectedFile.size / 1024 / 1024).toFixed(2)} MB
                    </Typography>
                  </Box>
                </Box>
              </Alert>
            )}

            <TextField
              label="Tarama Adı"
              value={scanName}
              onChange={(e) => setScanName(e.target.value)}
              fullWidth
              sx={{ mb: 2 }}
              helperText="Tarama için açıklayıcı bir isim girin"
            />
          </Box>
        );

      case 1:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Tarama Türünü Seçin
            </Typography>
            <Typography variant="body2" color="text.secondary" paragraph>
              Yapmak istediğiniz analiz türünü belirleyin.
            </Typography>

            <FormControl fullWidth sx={{ mb: 3 }}>
              <InputLabel>Tarama Türü</InputLabel>
              <Select
                value={scanType}
                label="Tarama Türü"
                onChange={(e) => setScanType(e.target.value)}
              >
                <MenuItem value="static">
                  <Box>
                    <Typography variant="subtitle2">Statik Analiz</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Kod analizi, izinler, güvenlik açıkları
                    </Typography>
                  </Box>
                </MenuItem>
                <MenuItem value="dynamic">
                  <Box>
                    <Typography variant="subtitle2">Dinamik Analiz</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Çalışma zamanı davranış analizi
                    </Typography>
                  </Box>
                </MenuItem>
                <MenuItem value="both">
                  <Box>
                    <Typography variant="subtitle2">Kapsamlı Analiz</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Hem statik hem dinamik analiz
                    </Typography>
                  </Box>
                </MenuItem>
              </Select>
            </FormControl>

            <Alert severity="info">
              <Typography variant="body2">
                <strong>Statik Analiz:</strong> Uygulama kodunu ve kaynaklarını analiz eder (Hızlı)
                <br />
                <strong>Dinamik Analiz:</strong> Uygulamayı çalıştırarak davranışını analiz eder (Yavaş)
                <br />
                <strong>Kapsamlı Analiz:</strong> En detaylı analiz, her iki yöntemi birleştirir
              </Typography>
            </Alert>
          </Box>
        );

      case 2:
        return (
          <Box>
            <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
              <PlayIcon sx={{ mr: 1, color: 'primary.main' }} />
              Taramayı Başlat
            </Typography>
            <Typography variant="body2" color="text.secondary" paragraph>
              Seçilen ayarlarla taramayı başlatın. Bu işlem birkaç dakika sürebilir.
            </Typography>

            {/* Tarama Özeti */}
            <Paper sx={{ p: 3, mb: 3, bgcolor: 'background.paper', border: '1px solid', borderColor: 'divider' }}>
              <Typography variant="h6" gutterBottom sx={{ color: 'primary.main', display: 'flex', alignItems: 'center' }}>
                <SecurityIcon sx={{ mr: 1 }} />
                Tarama Özeti
              </Typography>
              
              <Box sx={{ display: 'grid', gap: 2 }}>
                <Box sx={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  p: 1, 
                  bgcolor: 'action.hover', 
                  borderRadius: 1 
                }}>
                  {selectedFile?.name.endsWith('.apk') || selectedFile?.name.endsWith('.aab') ? (
                    <AndroidIcon sx={{ mr: 2, fontSize: 32, color: '#a4c639' }} />
                  ) : (
                    <AppleIcon sx={{ mr: 2, fontSize: 32, color: '#555' }} />
                  )}
                  <Box>
                    <Typography variant="subtitle1" fontWeight="medium" sx={{ color: 'text.primary' }}>
                      {selectedFile?.name}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Boyut: {selectedFile ? (selectedFile.size / 1024 / 1024).toFixed(2) : '0'} MB
                    </Typography>
                  </Box>
                </Box>

                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', p: 1 }}>
                  <Typography variant="body2" color="text.secondary">Tarama Türü:</Typography>
                  <Chip 
                    label={
                      scanType === 'static' ? 'Statik Analiz' :
                      scanType === 'dynamic' ? 'Dinamik Analiz' : 'Kapsamlı Analiz'
                    }
                    color="primary"
                    variant="outlined"
                  />
                </Box>

                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', p: 1 }}>
                  <Typography variant="body2" color="text.secondary">Tarama Adı:</Typography>
                  <Typography variant="body2" fontWeight="medium" sx={{ color: 'text.primary' }}>
                    {scanName || 'Varsayılan Tarama'}
                  </Typography>
                </Box>
              </Box>
            </Paper>

            {/* İlerleme Göstergesi */}
            {scanProgress > 0 && (
              <Paper sx={{ p: 3, mb: 3, bgcolor: 'info.50', border: '1px solid', borderColor: 'info.200' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  <RefreshIcon sx={{ mr: 1, animation: 'spin 1s linear infinite', '@keyframes spin': { from: { transform: 'rotate(0deg)' }, to: { transform: 'rotate(360deg)' } } }} />
                  <Typography variant="h6" color="info.main">Tarama Devam Ediyor</Typography>
                </Box>
                
                <Typography variant="body2" sx={{ mb: 2 }}>
                  {progressMessage || 'İşlem yapılıyor...'}
                </Typography>
                
                <LinearProgress 
                  variant="determinate" 
                  value={scanProgress}
                  sx={{ 
                    height: 10, 
                    borderRadius: 5,
                    bgcolor: 'grey.200',
                    '& .MuiLinearProgress-bar': {
                      borderRadius: 5,
                    }
                  }}
                />
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 1 }}>
                  <Typography variant="caption" color="text.secondary">
                    İlerleme
                  </Typography>
                  <Typography variant="caption" fontWeight="bold">
                    %{scanProgress}
                  </Typography>
                </Box>
              </Paper>
            )}

            {/* Tarama Başlat Butonu */}
            <Box sx={{ textAlign: 'center' }}>
              <Button
                variant="contained"
                onClick={startScan}
                disabled={loading || scanProgress > 0 || !selectedFile}
                startIcon={loading ? <RefreshIcon /> : <PlayIcon />}
                size="large"
                sx={{ 
                  px: 4, 
                  py: 1.5, 
                  fontSize: '1.1rem',
                  boxShadow: 3,
                  '&:hover': {
                    boxShadow: 6,
                  }
                }}
              >
                {loading ? 'Tarama Başlatılıyor...' : 'Taramayı Başlat'}
              </Button>
              
              {!selectedFile && (
                <Typography variant="caption" color="error" sx={{ display: 'block', mt: 1 }}>
                  Taramaya başlamadan önce bir dosya seçmelisiniz
                </Typography>
              )}
            </Box>

            {/* Bilgi Notları */}
            {!loading && scanProgress === 0 && (
              <Alert severity="info" sx={{ mt: 3 }}>
                <Typography variant="body2">
                  <strong>Tarama Süreci Hakkında:</strong>
                  <br />• Dosya yükleme 1-2 dakika sürebilir
                  <br />• Statik analiz 3-5 dakika sürer
                  <br />• Dinamik analiz 10-15 dakika sürebilir
                  <br />• Sonuçlar otomatik olarak görüntülenecektir
                </Typography>
              </Alert>
            )}
          </Box>
        );

      case 3:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Tarama Sonuçları
            </Typography>
            
            {currentScan && (
              <Box>
                {/* App Info */}
                <Paper sx={{ p: 2, mb: 3 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    {getCurrentPlatform() === 'ANDROID' ? (
                      <AndroidIcon sx={{ mr: 2, fontSize: 40, color: '#a4c639' }} />
                    ) : (
                      <AppleIcon sx={{ mr: 2, fontSize: 40, color: '#000' }} />
                    )}
                    <Box>
                      <Typography variant="h6">
                        {currentScan.mobileAppScan?.appName || currentScan.name}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {currentScan.mobileAppScan?.packageName}
                      </Typography>
                      <Typography variant="caption">
                        Versiyon: {currentScan.mobileAppScan?.version || 'N/A'}
                      </Typography>
                    </Box>
                  </Box>

                  {currentScan.mobileAppScan?.securityScore && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="body2" gutterBottom>
                        Güvenlik Skoru: {currentScan.mobileAppScan.securityScore}/100
                      </Typography>
                      <LinearProgress
                        variant="determinate"
                        value={currentScan.mobileAppScan.securityScore}
                        sx={{ height: 8, borderRadius: 4 }}
                        color={
                          currentScan.mobileAppScan.securityScore >= 80 ? 'success' :
                          currentScan.mobileAppScan.securityScore >= 60 ? 'warning' : 'error'
                        }
                      />
                    </Box>
                  )}
                </Paper>

                {/* Vulnerability Summary */}
                <Paper sx={{ p: 2, mb: 3 }}>
                  <Typography variant="h6" gutterBottom>Güvenlik Açıkları</Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
                    {currentScan?.vulnerabilityCounts && Object.entries(currentScan.vulnerabilityCounts).map(([severity, count]) => (
                      count > 0 && (
                        <Box key={severity} sx={{ minWidth: 120, textAlign: 'center' }}>
                          <Box sx={{ textAlign: 'center' }}>
                            {getSeverityIcon(severity)}
                            <Typography variant="h4" sx={{ color: getSeverityColor(severity) }}>
                              {count}
                            </Typography>
                            <Typography variant="caption" sx={{ textTransform: 'capitalize' }}>
                              {severity === 'critical' ? 'Kritik' :
                               severity === 'high' ? 'Yüksek' :
                               severity === 'medium' ? 'Orta' :
                               severity === 'low' ? 'Düşük' : 'Bilgi'}
                            </Typography>
                          </Box>
                        </Box>
                      )
                    ))}
                  </Box>
                </Paper>

                {/* Detailed Vulnerabilities */}
                {currentScan?.vulnerabilities && currentScan.vulnerabilities.length > 0 && (
                  <Paper sx={{ p: 2, mb: 3 }}>
                    <Typography variant="h6" gutterBottom>Detaylı Güvenlik Açıkları</Typography>
                    <List>
                      {currentScan.vulnerabilities.slice(0, 5).map((vuln, index) => (
                        <ListItem key={index} divider>
                          <ListItemIcon>
                            {getSeverityIcon(vuln.severity)}
                          </ListItemIcon>
                          <ListItemText
                            primary={vuln.name}
                            secondary={vuln.description}
                          />
                          <Chip
                            label={vuln.severity}
                            size="small"
                            sx={{
                              backgroundColor: getSeverityColor(vuln.severity),
                              color: vuln.severity === 'medium' ? 'black' : 'white'
                            }}
                          />
                        </ListItem>
                      ))}
                    </List>
                    {currentScan.vulnerabilities.length > 5 && (
                      <Typography variant="caption" color="text.secondary">
                        Ve {currentScan.vulnerabilities.length - 5} adet daha...
                      </Typography>
                    )}
                  </Paper>
                )}

                {/* Actions */}
                <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                  <Button
                    variant="contained"
                    startIcon={<DownloadIcon />}
                    onClick={downloadReport}
                  >
                    PDF Rapor İndir
                  </Button>
                  <Button
                    variant="outlined"
                    onClick={() => navigate('/dashboard')}
                  >
                    Dashboard'a Dön
                  </Button>
                </Box>
              </Box>
            )}
          </Box>
        );

      default:
        return 'Bilinmeyen adım';
    }
  };

  return (
    <Box sx={{ maxWidth: 1000, mx: 'auto', p: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom>
          Mobil Uygulama Güvenlik Taraması
        </Typography>
        <Typography variant="subtitle1" color="text.secondary">
          Android ve iOS uygulamalarınızı kapsamlı güvenlik taramasından geçirin
        </Typography>
      </Box>

      {/* Error/Success Messages */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mb: 3 }} onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      )}

      {/* Stepper */}
      <Paper sx={{ p: 3 }}>
        <Stepper activeStep={activeStep} orientation="vertical">
          {steps.map((label, index) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
              <StepContent>
                {getStepContent(index)}
                <Box sx={{ mb: 2, mt: 2 }}>
                  <div>
                    {index !== 0 && index !== 3 && (
                      <Button
                        disabled={loading}
                        onClick={handleBack}
                        sx={{ mr: 1 }}
                      >
                        Geri
                      </Button>
                    )}
                    {index < steps.length - 1 && index !== 2 && (
                      <Button
                        variant="contained"
                        onClick={handleNext}
                        disabled={loading}
                      >
                        İleri
                      </Button>
                    )}
                    {index === steps.length - 1 && (
                      <Button
                        onClick={handleReset}
                        variant="outlined"
                      >
                        Yeni Tarama
                      </Button>
                    )}
                  </div>
                </Box>
              </StepContent>
            </Step>
          ))}
        </Stepper>
      </Paper>
    </Box>
  );
};

export default MobileScan;
