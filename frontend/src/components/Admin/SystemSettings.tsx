import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Tabs,
  Tab,
  Alert,
  Switch,
  FormControlLabel,
  Divider,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Grid
} from '@mui/material';
import {
  Save as SaveIcon,
  Send as TestIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
  Email as EmailIcon,
  Security as SecurityIcon,
  Settings as SettingsIcon,
  ContentCopy as CopyIcon
} from '@mui/icons-material';
import api from '../../services/api';

interface SmtpSettings {
  host: string;
  port: number;
  secure: boolean;
  user: string;
  pass: string;
  from: string;
}

interface CiCdSettings {
  apiKeys: Array<{ key: string; fullKey: string }>;
  frontendUrl: string;
  defaultRecipients: string[];
  securityGates: {
    failOnCritical: boolean;
    failOnHighCount: number;
    warnOnMediumCount: number;
  };
}

interface GeneralSettings {
  appName: string;
  companyName: string;
  companyUrl: string;
  supportEmail: string;
  timezone: string;
  language: string;
  maxScanDuration: number; // dakika
  maxConcurrentScans: number;
  sessionTimeout: number; // dakika
  enableRegistration: boolean;
  enableLdap: boolean;
  ldapServer: string;
  ldapBaseDn: string;
}

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
      id={`settings-tabpanel-${index}`}
      aria-labelledby={`settings-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

const SystemSettings: React.FC = () => {
  const [tabValue, setTabValue] = useState(0);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  
  // SMTP Settings
  const [smtpSettings, setSmtpSettings] = useState<SmtpSettings>({
    host: '',
    port: 587,
    secure: false,
    user: '',
    pass: '',
    from: 'SiberZed Security <security@siberzed.local>'
  });
  const [showSmtpPassword, setShowSmtpPassword] = useState(false);
  const [testEmail, setTestEmail] = useState('');

  // CI/CD Settings
  const [cicdSettings, setCicdSettings] = useState<CiCdSettings>({
    apiKeys: [],
    frontendUrl: 'http://10.5.63.219:5001',
    defaultRecipients: [],
    securityGates: {
      failOnCritical: true,
      failOnHighCount: 10,
      warnOnMediumCount: 20
    }
  });
  const [newApiKeyDialog, setNewApiKeyDialog] = useState(false);
  const [newRecipientEmail, setNewRecipientEmail] = useState('');

  // General Settings
  const [generalSettings, setGeneralSettings] = useState<GeneralSettings>({
    appName: 'İBB Güvenlik Test Platformu',
    companyName: 'İstanbul Büyükşehir Belediyesi',
    companyUrl: 'https://www.ibb.istanbul',
    supportEmail: 'security@ibb.gov.tr',
    timezone: 'Europe/Istanbul',
    language: 'tr',
    maxScanDuration: 120,
    maxConcurrentScans: 5,
    sessionTimeout: 30,
    enableRegistration: false,
    enableLdap: true,
    ldapServer: 'ldap://ldap.ibb.local',
    ldapBaseDn: 'dc=ibb,dc=local'
  });

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      setLoading(true);
      
      const [smtpResponse, cicdResponse, generalResponse] = await Promise.all([
        api.get('/admin/settings/smtp'),
        api.get('/admin/settings/cicd'),
        api.get('/admin/settings/general').catch(() => ({ success: false }))
      ]);

      // API interceptor returns response.data directly
      if ((smtpResponse as any)?.success) {
        setSmtpSettings((smtpResponse as any).data);
      }

      if ((cicdResponse as any)?.success) {
        setCicdSettings((cicdResponse as any).data);
      }

      if ((generalResponse as any)?.success) {
        setGeneralSettings((generalResponse as any).data);
      }

    } catch (error) {
      console.error('Failed to load settings:', error);
      setMessage({ type: 'error', text: 'Ayarlar yüklenirken hata oluştu' });
    } finally {
      setLoading(false);
    }
  };

  const saveSmtpSettings = async () => {
    try {
      setLoading(true);
      const response = await api.post('/admin/settings/smtp', smtpSettings);
      
      if ((response as any)?.success) {
        setMessage({ type: 'success', text: 'SMTP ayarları başarıyla kaydedildi' });
      } else {
        setMessage({ type: 'error', text: 'SMTP ayarları kaydedilemedi' });
      }
    } catch (error) {
      console.error('Failed to save SMTP settings:', error);
      setMessage({ type: 'error', text: 'SMTP ayarları kaydedilirken hata oluştu' });
    } finally {
      setLoading(false);
    }
  };

  const testSmtpConnection = async () => {
    if (!testEmail) {
      setMessage({ type: 'error', text: 'Test email adresi girin' });
      return;
    }

    try {
      setLoading(true);
      const response = await api.post('/admin/settings/smtp/test', { testEmail });
      
      if ((response as any)?.success) {
        setMessage({ type: 'success', text: `Test emaili ${testEmail} adresine gönderildi` });
      } else {
        setMessage({ type: 'error', text: 'Test emaili gönderilemedi' });
      }
    } catch (error) {
      console.error('SMTP test failed:', error);
      setMessage({ type: 'error', text: 'SMTP test başarısız' });
    } finally {
      setLoading(false);
    }
  };

  const saveCicdSettings = async () => {
    try {
      setLoading(true);
      const response = await api.post('/admin/settings/cicd', cicdSettings);
      
      if ((response as any)?.success) {
        setMessage({ type: 'success', text: 'CI/CD ayarları başarıyla kaydedildi' });
      } else {
        setMessage({ type: 'error', text: 'CI/CD ayarları kaydedilemedi' });
      }
    } catch (error) {
      console.error('Failed to save CI/CD settings:', error);
      setMessage({ type: 'error', text: 'CI/CD ayarları kaydedilirken hata oluştu' });
    } finally {
      setLoading(false);
    }
  };

  const saveGeneralSettings = async () => {
    try {
      setLoading(true);
      const response = await api.post('/admin/settings/general', generalSettings);
      
      if ((response as any)?.success) {
        setMessage({ type: 'success', text: 'Genel ayarlar başarıyla kaydedildi' });
      } else {
        setMessage({ type: 'error', text: 'Genel ayarlar kaydedilemedi' });
      }
    } catch (error) {
      console.error('Failed to save general settings:', error);
      setMessage({ type: 'error', text: 'Genel ayarlar kaydedilirken hata oluştu' });
    } finally {
      setLoading(false);
    }
  };

  const generateNewApiKey = async () => {
    try {
      setLoading(true);
      const response = await api.post('/admin/settings/cicd/api-key', {
        keyName: 'Pipeline API Key'
      });
      
      if ((response as any)?.success) {
        setMessage({ type: 'success', text: 'Yeni API key oluşturuldu' });
        await loadSettings(); // Reload to get updated keys
        setNewApiKeyDialog(false);
      } else {
        setMessage({ type: 'error', text: 'API key oluşturulamadı' });
      }
    } catch (error) {
      console.error('Failed to generate API key:', error);
      setMessage({ type: 'error', text: 'API key oluşturulurken hata oluştu' });
    } finally {
      setLoading(false);
    }
  };

  const removeApiKey = async (apiKey: string) => {
    if (!window.confirm('Bu API key\'i silmek istediğinizden emin misiniz?')) {
      return;
    }

    try {
      setLoading(true);
      const response = await api.delete('/admin/settings/cicd/api-key', {
        data: { apiKey }
      });
      
      if ((response as any)?.success) {
        setMessage({ type: 'success', text: 'API key silindi' });
        await loadSettings();
      } else {
        setMessage({ type: 'error', text: 'API key silinemedi' });
      }
    } catch (error) {
      console.error('Failed to remove API key:', error);
      setMessage({ type: 'error', text: 'API key silinirken hata oluştu' });
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setMessage({ type: 'success', text: 'Panoya kopyalandı' });
  };

  const addRecipientEmail = () => {
    if (newRecipientEmail && !cicdSettings.defaultRecipients.includes(newRecipientEmail)) {
      setCicdSettings(prev => ({
        ...prev,
        defaultRecipients: [...prev.defaultRecipients, newRecipientEmail]
      }));
      setNewRecipientEmail('');
    }
  };

  const removeRecipientEmail = (email: string) => {
    setCicdSettings(prev => ({
      ...prev,
      defaultRecipients: prev.defaultRecipients.filter(e => e !== email)
    }));
  };

  return (
    <Box sx={{ width: '100%' }}>
      <Typography variant="h4" gutterBottom>
        ⚙️ Sistem Ayarları
      </Typography>

      {message && (
        <Alert 
          severity={message.type} 
          onClose={() => setMessage(null)}
          sx={{ mb: 2 }}
        >
          {message.text}
        </Alert>
      )}

      <Card>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={tabValue} onChange={(e, newValue) => setTabValue(newValue)}>
            <Tab icon={<EmailIcon />} label="SMTP Ayarları" />
            <Tab icon={<SecurityIcon />} label="CI/CD Ayarları" />
            <Tab icon={<SettingsIcon />} label="Genel Ayarlar" />
          </Tabs>
        </Box>

        {/* SMTP Settings Tab */}
        <TabPanel value={tabValue} index={0}>
          <Typography variant="h6" gutterBottom>
            📧 Email (SMTP) Konfigürasyonu
          </Typography>
          
          <Grid container spacing={3}>
            <Grid size={{ xs: 12, md: 6 }}>
              <TextField
                fullWidth
                label="SMTP Host"
                value={smtpSettings.host}
                onChange={(e) => setSmtpSettings(prev => ({ ...prev, host: e.target.value }))}
                placeholder="smtp.gmail.com"
                margin="normal"
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <TextField
                fullWidth
                label="Port"
                type="number"
                value={smtpSettings.port}
                onChange={(e) => setSmtpSettings(prev => ({ ...prev, port: parseInt(e.target.value) }))}
                margin="normal"
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <TextField
                fullWidth
                label="Username/Email"
                value={smtpSettings.user}
                onChange={(e) => setSmtpSettings(prev => ({ ...prev, user: e.target.value }))}
                placeholder="your-email@gmail.com"
                margin="normal"
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <TextField
                fullWidth
                label="Password"
                type={showSmtpPassword ? 'text' : 'password'}
                value={smtpSettings.pass}
                onChange={(e) => setSmtpSettings(prev => ({ ...prev, pass: e.target.value }))}
                placeholder={smtpSettings.pass ? '***configured***' : 'your-password'}
                margin="normal"
                InputProps={{
                  endAdornment: (
                    <IconButton onClick={() => setShowSmtpPassword(!showSmtpPassword)}>
                      {showSmtpPassword ? <VisibilityOffIcon /> : <VisibilityIcon />}
                    </IconButton>
                  )
                }}
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <TextField
                fullWidth
                label="From Address"
                value={smtpSettings.from}
                onChange={(e) => setSmtpSettings(prev => ({ ...prev, from: e.target.value }))}
                placeholder="SiberZed Security <security@company.com>"
                margin="normal"
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={smtpSettings.secure}
                    onChange={(e) => setSmtpSettings(prev => ({ ...prev, secure: e.target.checked }))}
                  />
                }
                label="SSL/TLS Kullan (Port 465 için true, 587 için false)"
              />
            </Grid>
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>
            🧪 Email Test
          </Typography>
          
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', mb: 2 }}>
            <TextField
              label="Test Email Adresi"
              value={testEmail}
              onChange={(e) => setTestEmail(e.target.value)}
              placeholder="test@company.com"
              sx={{ flexGrow: 1 }}
            />
            <Button
              variant="outlined"
              startIcon={<TestIcon />}
              onClick={testSmtpConnection}
              disabled={loading || !testEmail}
            >
              Test Gönder
            </Button>
          </Box>

          <Box sx={{ display: 'flex', gap: 2, mt: 3 }}>
            <Button
              variant="contained"
              startIcon={<SaveIcon />}
              onClick={saveSmtpSettings}
              disabled={loading}
            >
              SMTP Ayarlarını Kaydet
            </Button>
          </Box>
        </TabPanel>

        {/* CI/CD Settings Tab */}
        <TabPanel value={tabValue} index={1}>
          <Typography variant="h6" gutterBottom>
            🔐 CI/CD API Keys
          </Typography>
          
          <Box sx={{ mb: 3 }}>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={() => setNewApiKeyDialog(true)}
              sx={{ mb: 2 }}
            >
              Yeni API Key Oluştur
            </Button>
            
            <List>
              {cicdSettings.apiKeys.map((apiKey, index) => (
                <ListItem key={index} divider>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="body1" component="span">
                          {apiKey.key}
                        </Typography>
                        <IconButton 
                          size="small" 
                          onClick={() => copyToClipboard(apiKey.fullKey)}
                          title="Full key'i kopyala"
                        >
                          <CopyIcon fontSize="small" />
                        </IconButton>
                      </Box>
                    }
                    secondary={`Oluşturulma: ${new Date().toLocaleDateString()}`}
                  />
                  <ListItemSecondaryAction>
                    <IconButton
                      edge="end"
                      onClick={() => removeApiKey(apiKey.fullKey)}
                      color="error"
                    >
                      <DeleteIcon />
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
              ))}
              {cicdSettings.apiKeys.length === 0 && (
                <ListItem>
                  <ListItemText
                    primary="Henüz API key oluşturulmamış"
                    secondary="CI/CD entegrasyonu için en az bir API key gerekli"
                  />
                </ListItem>
              )}
            </List>
          </Box>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>
            🌐 Genel Ayarlar
          </Typography>
          
          <Grid container spacing={3}>
            <Grid size={{ xs: 12 }}>
              <TextField
                fullWidth
                label="Frontend URL"
                value={cicdSettings.frontendUrl}
                onChange={(e) => setCicdSettings(prev => ({ ...prev, frontendUrl: e.target.value }))}
                placeholder="http://10.5.63.219:5001"
                margin="normal"
                helperText="Rapor linklerinde kullanılacak frontend URL'si"
              />
            </Grid>
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>
            📧 Varsayılan Email Alıcıları
          </Typography>
          
          <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
            <TextField
              label="Email Adresi"
              value={newRecipientEmail}
              onChange={(e) => setNewRecipientEmail(e.target.value)}
              placeholder="security@company.com"
              sx={{ flexGrow: 1 }}
            />
            <Button
              variant="outlined"
              startIcon={<AddIcon />}
              onClick={addRecipientEmail}
              disabled={!newRecipientEmail}
            >
              Ekle
            </Button>
          </Box>

          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 3 }}>
            {cicdSettings.defaultRecipients.map((email, index) => (
              <Chip
                key={index}
                label={email}
                onDelete={() => removeRecipientEmail(email)}
                color="primary"
                variant="outlined"
              />
            ))}
          </Box>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>
            🛡️ Güvenlik Kapıları
          </Typography>
          
          <Grid container spacing={3}>
            <Grid size={{ xs: 12 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={cicdSettings.securityGates.failOnCritical}
                    onChange={(e) => setCicdSettings(prev => ({
                      ...prev,
                      securityGates: {
                        ...prev.securityGates,
                        failOnCritical: e.target.checked
                      }
                    }))}
                  />
                }
                label="Critical vulnerability bulunduğunda pipeline'ı durdur"
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <TextField
                fullWidth
                label="High Vulnerability Limiti"
                type="number"
                value={cicdSettings.securityGates.failOnHighCount}
                onChange={(e) => setCicdSettings(prev => ({
                  ...prev,
                  securityGates: {
                    ...prev.securityGates,
                    failOnHighCount: parseInt(e.target.value) || 10
                  }
                }))}
                margin="normal"
                helperText="Bu sayıdan fazla high vulnerability bulunursa pipeline durdurulur"
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <TextField
                fullWidth
                label="Medium Vulnerability Uyarı Limiti"
                type="number"
                value={cicdSettings.securityGates.warnOnMediumCount}
                onChange={(e) => setCicdSettings(prev => ({
                  ...prev,
                  securityGates: {
                    ...prev.securityGates,
                    warnOnMediumCount: parseInt(e.target.value) || 20
                  }
                }))}
                margin="normal"
                helperText="Bu sayıdan fazla medium vulnerability bulunursa uyarı verilir"
              />
            </Grid>
          </Grid>

          <Box sx={{ display: 'flex', gap: 2, mt: 3 }}>
            <Button
              variant="contained"
              startIcon={<SaveIcon />}
              onClick={saveCicdSettings}
              disabled={loading}
            >
              CI/CD Ayarlarını Kaydet
            </Button>
          </Box>
        </TabPanel>

        {/* General Settings Tab */}
        <TabPanel value={tabValue} index={2}>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <SettingsIcon /> Genel Sistem Ayarları
          </Typography>
          
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {/* Uygulama Bilgileri */}
            <Box>
              <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                📱 Uygulama Bilgileri
              </Typography>
              <Divider sx={{ mb: 2 }} />
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                  <TextField
                    sx={{ flex: '1 1 300px' }}
                    label="Uygulama Adı"
                    value={generalSettings.appName}
                    onChange={(e) => setGeneralSettings({ ...generalSettings, appName: e.target.value })}
                    helperText="Platformun ana başlığı"
                  />
                  <TextField
                    sx={{ flex: '1 1 300px' }}
                    label="Şirket Adı"
                    value={generalSettings.companyName}
                    onChange={(e) => setGeneralSettings({ ...generalSettings, companyName: e.target.value })}
                    helperText="Organizasyon adı"
                  />
                </Box>
                <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                  <TextField
                    sx={{ flex: '1 1 300px' }}
                    label="Şirket Web Sitesi"
                    value={generalSettings.companyUrl}
                    onChange={(e) => setGeneralSettings({ ...generalSettings, companyUrl: e.target.value })}
                    helperText="https://www.example.com"
                  />
                  <TextField
                    sx={{ flex: '1 1 300px' }}
                    label="Destek E-posta"
                    value={generalSettings.supportEmail}
                    onChange={(e) => setGeneralSettings({ ...generalSettings, supportEmail: e.target.value })}
                    helperText="Teknik destek için e-posta"
                  />
                </Box>
              </Box>
            </Box>

            {/* Bölgesel Ayarlar */}
            <Box>
              <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                🌍 Bölgesel Ayarlar
              </Typography>
              <Divider sx={{ mb: 2 }} />
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                <TextField
                  sx={{ flex: '1 1 300px' }}
                  label="Saat Dilimi"
                  value={generalSettings.timezone}
                  onChange={(e) => setGeneralSettings({ ...generalSettings, timezone: e.target.value })}
                  helperText="Örn: Europe/Istanbul"
                />
                <TextField
                  sx={{ flex: '1 1 300px' }}
                  label="Dil"
                  value={generalSettings.language}
                  onChange={(e) => setGeneralSettings({ ...generalSettings, language: e.target.value })}
                  helperText="Varsayılan dil kodu (tr, en)"
                />
              </Box>
            </Box>

            {/* Tarama Limitleri */}
            <Box>
              <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                ⚙️ Tarama Limitleri
              </Typography>
              <Divider sx={{ mb: 2 }} />
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                <TextField
                  sx={{ flex: '1 1 250px' }}
                  type="number"
                  label="Maksimum Tarama Süresi (dk)"
                  value={generalSettings.maxScanDuration}
                  onChange={(e) => setGeneralSettings({ ...generalSettings, maxScanDuration: parseInt(e.target.value) || 0 })}
                  helperText="Bir taramanın maksimum süresi"
                />
                <TextField
                  sx={{ flex: '1 1 250px' }}
                  type="number"
                  label="Maksimum Eşzamanlı Tarama"
                  value={generalSettings.maxConcurrentScans}
                  onChange={(e) => setGeneralSettings({ ...generalSettings, maxConcurrentScans: parseInt(e.target.value) || 0 })}
                  helperText="Aynı anda çalışabilecek tarama sayısı"
                />
                <TextField
                  sx={{ flex: '1 1 250px' }}
                  type="number"
                  label="Oturum Zaman Aşımı (dk)"
                  value={generalSettings.sessionTimeout}
                  onChange={(e) => setGeneralSettings({ ...generalSettings, sessionTimeout: parseInt(e.target.value) || 0 })}
                  helperText="Kullanıcı oturumu zaman aşımı"
                />
              </Box>
            </Box>

            {/* Güvenlik Ayarları */}
            <Box>
              <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                🔐 Güvenlik ve Kimlik Doğrulama
              </Typography>
              <Divider sx={{ mb: 2 }} />
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <Box sx={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  <Box>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={generalSettings.enableRegistration}
                          onChange={(e) => setGeneralSettings({ ...generalSettings, enableRegistration: e.target.checked })}
                        />
                      }
                      label="Kullanıcı Kaydına İzin Ver"
                    />
                    <Typography variant="caption" color="text.secondary" display="block">
                      Yeni kullanıcıların kendilerini kaydetmesine izin verir
                    </Typography>
                  </Box>

                  <Box>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={generalSettings.enableLdap}
                          onChange={(e) => setGeneralSettings({ ...generalSettings, enableLdap: e.target.checked })}
                        />
                      }
                      label="LDAP Kimlik Doğrulamayı Etkinleştir"
                    />
                    <Typography variant="caption" color="text.secondary" display="block">
                      Active Directory / LDAP ile kimlik doğrulama
                    </Typography>
                  </Box>
                </Box>

                {generalSettings.enableLdap && (
                  <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                    <TextField
                      sx={{ flex: '1 1 300px' }}
                      label="LDAP Sunucu Adresi"
                      value={generalSettings.ldapServer}
                      onChange={(e) => setGeneralSettings({ ...generalSettings, ldapServer: e.target.value })}
                      helperText="Örn: ldap://ldap.example.com"
                    />
                    <TextField
                      sx={{ flex: '1 1 300px' }}
                      label="LDAP Base DN"
                      value={generalSettings.ldapBaseDn}
                      onChange={(e) => setGeneralSettings({ ...generalSettings, ldapBaseDn: e.target.value })}
                      helperText="Örn: dc=example,dc=com"
                    />
                  </Box>
                )}
              </Box>
            </Box>

            {/* Kaydet Butonu */}
            <Box>
              <Button
                variant="contained"
                startIcon={<SaveIcon />}
                onClick={saveGeneralSettings}
                disabled={loading}
                size="large"
              >
                Genel Ayarları Kaydet
              </Button>
            </Box>
          </Box>
        </TabPanel>
      </Card>

      {/* New API Key Dialog */}
      <Dialog open={newApiKeyDialog} onClose={() => setNewApiKeyDialog(false)}>
        <DialogTitle>🔐 Yeni CI/CD API Key Oluştur</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ mb: 2 }}>
            Yeni bir API key oluşturulacak. Bu key'i CI/CD pipeline'larınızda kullanabilirsiniz.
          </Typography>
          <Alert severity="warning" sx={{ mb: 2 }}>
            <strong>Önemli:</strong> API key'i sadece bir kez gösterilecek. Güvenli bir yerde saklayın.
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNewApiKeyDialog(false)}>İptal</Button>
          <Button 
            variant="contained" 
            onClick={generateNewApiKey}
            disabled={loading}
          >
            Oluştur
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default SystemSettings;
