import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Switch,
  FormControlLabel,
  FormGroup,
  Divider,
  Alert,
  CircularProgress,
  Button
} from '@mui/material';
import { Email as EmailIcon, Save as SaveIcon } from '@mui/icons-material';
import api from '../../services/api';

interface EmailPreferences {
  emailEnabled: boolean;
  scanStarted: boolean;
  scanCompleted: boolean;
  scanFailed: boolean;
  scanPaused: boolean;
  vulnCritical: boolean;
  vulnHigh: boolean;
  vulnMedium: boolean;
  vulnLow: boolean;
  vulnInfo: boolean;
  systemAlerts: boolean;
  weeklyReport: boolean;
  monthlyReport: boolean;
  dailyDigest: boolean;
}

const EmailPreferences: React.FC = () => {
  const [preferences, setPreferences] = useState<EmailPreferences>({
    emailEnabled: true,
    scanStarted: false,
    scanCompleted: true,
    scanFailed: true,
    scanPaused: false,
    vulnCritical: true,
    vulnHigh: true,
    vulnMedium: false,
    vulnLow: false,
    vulnInfo: false,
    systemAlerts: true,
    weeklyReport: true,
    monthlyReport: false,
    dailyDigest: false
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchPreferences();
  }, []);

  const fetchPreferences = async () => {
    try {
      // API interceptor already returns response.data, so we use response directly
      const response = await api.get('/user/email-preferences') as any;
      if (response) {
        // Ensure all fields are present with defaults
        setPreferences({
          emailEnabled: response.emailEnabled ?? true,
          scanStarted: response.scanStarted ?? false,
          scanCompleted: response.scanCompleted ?? true,
          scanFailed: response.scanFailed ?? true,
          scanPaused: response.scanPaused ?? false,
          vulnCritical: response.vulnCritical ?? true,
          vulnHigh: response.vulnHigh ?? true,
          vulnMedium: response.vulnMedium ?? false,
          vulnLow: response.vulnLow ?? false,
          vulnInfo: response.vulnInfo ?? false,
          systemAlerts: response.systemAlerts ?? true,
          weeklyReport: response.weeklyReport ?? true,
          monthlyReport: response.monthlyReport ?? false,
          dailyDigest: response.dailyDigest ?? false
        });
      }
    } catch (err) {
      console.error('Failed to fetch email preferences:', err);
      setError('Email tercihleri yüklenemedi');
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (field: keyof EmailPreferences) => (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    setPreferences(prev => ({
      ...prev,
      [field]: event.target.checked
    }));
    setSuccess(false);
  };

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    setSuccess(false);

    try {
      await api.put('/user/email-preferences', preferences);
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      console.error('Failed to save email preferences:', err);
      setError('Kaydetme başarısız oldu');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" p={4}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Box display="flex" alignItems="center" mb={3}>
        <EmailIcon sx={{ fontSize: 32, mr: 2, color: 'primary.main' }} />
        <Typography variant="h5">Email Tercihleri</Typography>
      </Box>

      {success && (
        <Alert severity="success" sx={{ mb: 2 }}>
          Email tercihleri başarıyla kaydedildi
        </Alert>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Box display="flex" flexWrap="wrap" gap={3}>
        {/* Genel Ayarlar */}
        <Box flex="1 1 45%" minWidth="300px">
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              Genel Ayarlar
            </Typography>
            <Divider sx={{ mb: 2 }} />
            <FormGroup>
              <FormControlLabel
                control={
                  <Switch
                    checked={preferences.emailEnabled}
                    onChange={handleChange('emailEnabled')}
                    color="primary"
                  />
                }
                label="Email bildirimlerini etkinleştir"
              />
            </FormGroup>
          </Paper>
        </Box>

        {/* Tarama Bildirimleri */}
        <Box flex="1 1 45%" minWidth="300px">
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              Tarama Bildirimleri
            </Typography>
            <Divider sx={{ mb: 2 }} />
            <FormGroup>
              <FormControlLabel
                control={
                  <Switch
                    checked={preferences.scanStarted}
                    onChange={handleChange('scanStarted')}
                    disabled={!preferences.emailEnabled}
                  />
                }
                label="Tarama başladığında"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={preferences.scanCompleted}
                    onChange={handleChange('scanCompleted')}
                    disabled={!preferences.emailEnabled}
                    color="success"
                  />
                }
                label="Tarama tamamlandığında ✅"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={preferences.scanFailed}
                    onChange={handleChange('scanFailed')}
                    disabled={!preferences.emailEnabled}
                    color="error"
                  />
                }
                label="Tarama başarısız olduğunda"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={preferences.scanPaused}
                    onChange={handleChange('scanPaused')}
                    disabled={!preferences.emailEnabled}
                  />
                }
                label="Tarama duraklatıldığında"
              />
            </FormGroup>
          </Paper>
        </Box>

        {/* Zafiyet Bildirimleri */}
        <Box flex="1 1 45%" minWidth="300px">
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              Zafiyet Bildirimleri
            </Typography>
            <Divider sx={{ mb: 2 }} />
            <FormGroup>
              <FormControlLabel
                control={
                  <Switch
                    checked={preferences.vulnCritical}
                    onChange={handleChange('vulnCritical')}
                    disabled={!preferences.emailEnabled}
                    color="error"
                  />
                }
                label="🔴 Kritik zafiyetler"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={preferences.vulnHigh}
                    onChange={handleChange('vulnHigh')}
                    disabled={!preferences.emailEnabled}
                    color="warning"
                  />
                }
                label="🟠 Yüksek zafiyetler"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={preferences.vulnMedium}
                    onChange={handleChange('vulnMedium')}
                    disabled={!preferences.emailEnabled}
                  />
                }
                label="🟡 Orta seviye zafiyetler"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={preferences.vulnLow}
                    onChange={handleChange('vulnLow')}
                    disabled={!preferences.emailEnabled}
                  />
                }
                label="🟢 Düşük zafiyetler"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={preferences.vulnInfo}
                    onChange={handleChange('vulnInfo')}
                    disabled={!preferences.emailEnabled}
                  />
                }
                label="🔵 Bilgilendirme"
              />
            </FormGroup>
          </Paper>
        </Box>

        {/* Periyodik Raporlar */}
        <Box flex="1 1 45%" minWidth="300px">
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              Periyodik Raporlar
            </Typography>
            <Divider sx={{ mb: 2 }} />
            <FormGroup>
              <FormControlLabel
                control={
                  <Switch
                    checked={preferences.dailyDigest}
                    onChange={handleChange('dailyDigest')}
                    disabled={!preferences.emailEnabled}
                  />
                }
                label="Günlük özet"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={preferences.weeklyReport}
                    onChange={handleChange('weeklyReport')}
                    disabled={!preferences.emailEnabled}
                  />
                }
                label="Haftalık rapor"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={preferences.monthlyReport}
                    onChange={handleChange('monthlyReport')}
                    disabled={!preferences.emailEnabled}
                  />
                }
                label="Aylık rapor"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={preferences.systemAlerts}
                    onChange={handleChange('systemAlerts')}
                    disabled={!preferences.emailEnabled}
                  />
                }
                label="Sistem uyarıları"
              />
            </FormGroup>
          </Paper>
        </Box>
      </Box>

      <Box display="flex" justifyContent="flex-end" mt={3}>
        <Button
          variant="contained"
          startIcon={saving ? <CircularProgress size={20} /> : <SaveIcon />}
          onClick={handleSave}
          disabled={saving}
          size="large"
        >
          {saving ? 'Kaydediliyor...' : 'Kaydet'}
        </Button>
      </Box>
    </Box>
  );
};

export default EmailPreferences;
