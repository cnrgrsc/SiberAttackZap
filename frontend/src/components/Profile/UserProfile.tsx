import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Paper,
  Typography,
  TextField,
  Button,
  Avatar,
  Divider,
  Chip,
  Alert,
  CircularProgress,
  Switch,
  FormControlLabel,
  FormGroup,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Stack
} from '@mui/material';
import {
  Person,
  Email,
  Business,
  Badge,
  Group,
  ExpandMore,
  Save,
  Cancel,
  Edit,
  Notifications
} from '@mui/icons-material';
import { usePermissions } from '../../contexts/PermissionContext';
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

export const UserProfile: React.FC = () => {
  const { profile, refreshPermissions } = usePermissions();
  const [loading, setLoading] = useState(false);
  const [editMode, setEditMode] = useState(false);
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');

  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    department: ''
  });

  const [emailPrefs, setEmailPrefs] = useState<EmailPreferences>({
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
    weeklyReport: false,
    monthlyReport: false,
    dailyDigest: false
  });

  useEffect(() => {
    if (profile) {
      setFormData({
        firstName: profile.firstName || '',
        lastName: profile.lastName || '',
        department: profile.department || ''
      });

      if (profile.emailPreference) {
        setEmailPrefs(profile.emailPreference);
      }
    }
  }, [profile]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleEmailPrefChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setEmailPrefs({
      ...emailPrefs,
      [e.target.name]: e.target.checked
    });
  };

  const handleSaveProfile = async () => {
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      await api.put('/user/profile', formData);
      setSuccess('Profil bilgileriniz güncellendi');
      setEditMode(false);
      await refreshPermissions();
    } catch (err: any) {
      setError(err.response?.data?.message || 'Profil güncellenirken hata oluştu');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveEmailPrefs = async () => {
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      await api.patch('/user/email-preferences', emailPrefs);
      setSuccess('E-posta tercihleri güncellendi');
      await refreshPermissions();
    } catch (err: any) {
      setError(err.response?.data?.message || 'E-posta tercihleri güncellenirken hata oluştu');
    } finally {
      setLoading(false);
    }
  };

  if (!profile) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="60vh">
        <CircularProgress />
      </Box>
    );
  }

  const initials = `${profile.firstName?.[0] || ''}${profile.lastName?.[0] || ''}`.toUpperCase();

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Typography variant="h4" gutterBottom sx={{ mb: 3, display: 'flex', alignItems: 'center', gap: 1 }}>
        <Person /> Kullanıcı Profili
      </Typography>

      {success && (
        <Alert severity="success" onClose={() => setSuccess('')} sx={{ mb: 2 }}>
          {success}
        </Alert>
      )}

      {error && (
        <Alert severity="error" onClose={() => setError('')} sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Box display="flex" gap={3} flexDirection={{ xs: 'column', md: 'row' }}>
        {/* Sol Panel - Profil Özeti */}
        <Box flex="0 0 350px">
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Avatar sx={{ width: 120, height: 120, margin: '0 auto', bgcolor: 'primary.main', fontSize: '3rem', mb: 2 }}>
              {initials}
            </Avatar>
            <Typography variant="h5" gutterBottom>
              {profile.firstName} {profile.lastName}
            </Typography>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              @{profile.username}
            </Typography>
            <Chip label={profile.isActive ? 'Aktif' : 'Pasif'} color={profile.isActive ? 'success' : 'default'} size="small" sx={{ mt: 1 }} />

            <Divider sx={{ my: 2 }} />

            <Stack spacing={1} alignItems="flex-start">
              <Box display="flex" alignItems="center" gap={1}>
                <Email fontSize="small" color="action" />
                <Typography variant="body2">{profile.email}</Typography>
              </Box>
              {profile.department && (
                <Box display="flex" alignItems="center" gap={1}>
                  <Business fontSize="small" color="action" />
                  <Typography variant="body2">{profile.department}</Typography>
                </Box>
              )}
            </Stack>
          </Paper>

          {/* Roller ve Gruplar */}
          <Paper sx={{ p: 3, mt: 2 }}>
            <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Badge /> Roller
            </Typography>
            <Stack spacing={1}>
              {profile.userRoles?.map((ur, index) => (
                <Chip key={index} label={ur.role?.displayName || 'N/A'} color="primary" variant="outlined" size="small" />
              )) || (
                <Typography variant="body2" color="text.secondary">
                  Henüz bir role sahip değilsiniz
                </Typography>
              )}
            </Stack>

            <Divider sx={{ my: 2 }} />

            <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Group /> Gruplar
            </Typography>
            <Stack spacing={1}>
              {profile.groupMemberships && profile.groupMemberships.length > 0 ? (
                profile.groupMemberships.map((gm, index) => (
                  <Chip key={index} label={gm.group?.displayName || 'N/A'} color="secondary" variant="outlined" size="small" />
                ))
              ) : (
                <Typography variant="body2" color="text.secondary">
                  Henüz bir gruba dahil değilsiniz
                </Typography>
              )}
            </Stack>
          </Paper>
        </Box>

        {/* Sağ Panel - Düzenlenebilir Bilgiler */}
        <Box flex={1}>
          {/* Kişisel Bilgiler */}
          <Paper sx={{ p: 3, mb: 2 }}>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
              <Typography variant="h6">Kişisel Bilgiler</Typography>
              {!editMode ? (
                <Button startIcon={<Edit />} variant="outlined" size="small" onClick={() => setEditMode(true)}>
                  Düzenle
                </Button>
              ) : (
                <Box>
                  <Button startIcon={<Cancel />} size="small" onClick={() => setEditMode(false)} sx={{ mr: 1 }}>
                    İptal
                  </Button>
                  <Button startIcon={<Save />} variant="contained" size="small" onClick={handleSaveProfile} disabled={loading}>
                    Kaydet
                  </Button>
                </Box>
              )}
            </Box>

            <Stack spacing={2}>
              <Box display="flex" gap={2} flexDirection={{ xs: 'column', sm: 'row' }}>
                <TextField fullWidth label="Ad" name="firstName" value={formData.firstName} onChange={handleInputChange} disabled={!editMode} />
                <TextField fullWidth label="Soyad" name="lastName" value={formData.lastName} onChange={handleInputChange} disabled={!editMode} />
              </Box>
              <TextField fullWidth label="Departman" name="department" value={formData.department} onChange={handleInputChange} disabled={!editMode} />
            </Stack>
          </Paper>

          {/* E-posta Bildirimleri */}
          <Paper sx={{ p: 3, mb: 2 }}>
            <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Notifications /> E-posta Bildirimleri
            </Typography>

            <FormControlLabel
              control={<Switch checked={emailPrefs.emailEnabled} onChange={handleEmailPrefChange} name="emailEnabled" color="primary" />}
              label="E-posta bildirimlerini etkinleştir"
              sx={{ mb: 2 }}
            />

            <Accordion disabled={!emailPrefs.emailEnabled}>
              <AccordionSummary expandIcon={<ExpandMore />}>
                <Typography>Tarama Bildirimleri</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <FormGroup>
                  <FormControlLabel control={<Switch checked={emailPrefs.scanStarted} onChange={handleEmailPrefChange} name="scanStarted" />} label="Tarama başladığında" />
                  <FormControlLabel control={<Switch checked={emailPrefs.scanCompleted} onChange={handleEmailPrefChange} name="scanCompleted" />} label="Tarama tamamlandığında" />
                  <FormControlLabel control={<Switch checked={emailPrefs.scanFailed} onChange={handleEmailPrefChange} name="scanFailed" />} label="Tarama başarısız olduğunda" />
                  <FormControlLabel control={<Switch checked={emailPrefs.scanPaused} onChange={handleEmailPrefChange} name="scanPaused" />} label="Tarama duraklatıldığında" />
                </FormGroup>
              </AccordionDetails>
            </Accordion>

            <Accordion disabled={!emailPrefs.emailEnabled}>
              <AccordionSummary expandIcon={<ExpandMore />}>
                <Typography>Zafiyet Bildirimleri</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <FormGroup>
                  <FormControlLabel control={<Switch checked={emailPrefs.vulnCritical} onChange={handleEmailPrefChange} name="vulnCritical" />} label="Kritik zafiyet bulunduğunda" />
                  <FormControlLabel control={<Switch checked={emailPrefs.vulnHigh} onChange={handleEmailPrefChange} name="vulnHigh" />} label="Yüksek zafiyet bulunduğunda" />
                  <FormControlLabel control={<Switch checked={emailPrefs.vulnMedium} onChange={handleEmailPrefChange} name="vulnMedium" />} label="Orta zafiyet bulunduğunda" />
                  <FormControlLabel control={<Switch checked={emailPrefs.vulnLow} onChange={handleEmailPrefChange} name="vulnLow" />} label="Düşük zafiyet bulunduğunda" />
                  <FormControlLabel control={<Switch checked={emailPrefs.vulnInfo} onChange={handleEmailPrefChange} name="vulnInfo" />} label="Bilgi seviyesi bulgu için" />
                </FormGroup>
              </AccordionDetails>
            </Accordion>

            <Accordion disabled={!emailPrefs.emailEnabled}>
              <AccordionSummary expandIcon={<ExpandMore />}>
                <Typography>Periyodik Raporlar</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <FormGroup>
                  <FormControlLabel control={<Switch checked={emailPrefs.dailyDigest} onChange={handleEmailPrefChange} name="dailyDigest" />} label="Günlük özet raporu" />
                  <FormControlLabel control={<Switch checked={emailPrefs.weeklyReport} onChange={handleEmailPrefChange} name="weeklyReport" />} label="Haftalık rapor" />
                  <FormControlLabel control={<Switch checked={emailPrefs.monthlyReport} onChange={handleEmailPrefChange} name="monthlyReport" />} label="Aylık rapor" />
                  <FormControlLabel control={<Switch checked={emailPrefs.systemAlerts} onChange={handleEmailPrefChange} name="systemAlerts" />} label="Sistem uyarıları" />
                </FormGroup>
              </AccordionDetails>
            </Accordion>

            <Box mt={2} display="flex" justifyContent="flex-end">
              <Button variant="contained" startIcon={<Save />} onClick={handleSaveEmailPrefs} disabled={loading || !emailPrefs.emailEnabled}>
                E-posta Tercihlerini Kaydet
              </Button>
            </Box>
          </Paper>

          {/* İzinler */}
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Sahip Olduğunuz İzinler ({profile.permissions?.length || 0})
            </Typography>
            <Box display="flex" flexWrap="wrap" gap={1}>
              {profile.permissions && profile.permissions.length > 0 ? (
                profile.permissions.map((perm, index) => (
                  <Chip key={index} label={perm} size="small" variant="outlined" color="default" />
                ))
              ) : (
                <Typography variant="body2" color="text.secondary">
                  Henüz izin atanmamış
                </Typography>
              )}
            </Box>
          </Paper>
        </Box>
      </Box>
    </Container>
  );
};
