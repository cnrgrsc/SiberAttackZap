import React, { useState, useEffect } from 'react';
import {
  Box,
  CardContent,
  TextField,
  Button,
  Typography,
  Alert,
  InputAdornment,
  IconButton,
  Divider,
  Paper,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import {
  Visibility,
  VisibilityOff,
  Security as SecurityIcon,
  Person as PersonIcon,
  Lock as LockIcon,
  Email as EmailIcon,
  Business as BusinessIcon,
  Description as DescriptionIcon,
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import authService, { LoginCredentials, AccessRequestData } from '../../services/authService';
import ibbLogo from '../../assets/ibb-logo.jpg';
import { usePermissions } from '../../contexts/PermissionContext';

const Login = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const routeError = (location.state as any)?.error;
  const { refreshPermissions } = usePermissions();

  // Login form state
  const [credentials, setCredentials] = useState<LoginCredentials>({
    username: '',
    password: ''
  });

  // UI state
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Access request dialog state
  const [showAccessRequest, setShowAccessRequest] = useState(false);
  const [accessRequestData, setAccessRequestData] = useState<AccessRequestData>({
    firstName: '',
    lastName: '',
    email: '',
    department: '',
    reason: '',
    requestedRole: 'developer'
  });
  const [accessRequestLoading, setAccessRequestLoading] = useState(false);  // Check if already authenticated - only run once
  useEffect(() => {
    // Route'dan gelen hata mesajını kontrol et - sadece ilk yüklemede
    if (routeError && !error) {
      setError(routeError);
    }
  }, [routeError, error]); // Separate useEffect for route error

  useEffect(() => {
    const checkInitialAuth = () => {
      if (authService.isAuthenticated()) {
        const user = authService.getUser();
        const redirectPath = user?.role === 'admin' ? '/admin' : '/dashboard';
        navigate(redirectPath, { replace: true });
      } else {
      }
    };

    checkInitialAuth();
  }, []); // Empty dependency - only run once on mount

  const handleInputChange = (field: keyof LoginCredentials) => (event: React.ChangeEvent<HTMLInputElement>) => {
    setCredentials(prev => ({
      ...prev,
      [field]: event.target.value
    }));
    setError(null);
  };

  const handleAccessRequestChange = (field: keyof AccessRequestData) => (event: any) => {
    setAccessRequestData(prev => ({
      ...prev,
      [field]: event.target.value
    }));
  };
  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();

    if (!credentials.username.trim() || !credentials.password.trim()) {
      setError('Kullanıcı adı ve şifre gereklidir');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const result = await authService.login(credentials);
      console.log('✅ AuthService response:', result); if (result.success && result.user) {
        setSuccess('Giriş başarılı! Yönlendiriliyorsunuz...');

        // Clear any previous errors
        setError(null);

        // ÖNEMLI: Permissions'ı refresh et ÖNCE!
        console.log('🔄 Refreshing permissions before navigation...');
        await refreshPermissions();
        console.log('✅ Permissions refreshed, now navigating...');

        // Determine redirect path
        const redirectPath = result.user.role === 'admin' ? '/admin' : '/dashboard';

        // Navigate after permissions are loaded
        navigate(redirectPath, { replace: true });
      } else {
        setError(result.message || 'Giriş başarısız');
      }
    } catch (error) {
      console.error('❌ Login error:', error);
      setError('Bir hata oluştu. Lütfen tekrar deneyiniz.');
    } finally {
      setLoading(false);
    }
  };

  const handleAccessRequest = async () => {
    if (!accessRequestData.firstName.trim() || !accessRequestData.lastName.trim() ||
      !accessRequestData.email.trim() || !accessRequestData.department.trim() ||
      !accessRequestData.reason.trim()) {
      setError('Tüm alanları doldurunuz');
      return;
    }

    setAccessRequestLoading(true);
    setError(null);

    try {
      const result = await authService.requestAccess(accessRequestData);

      if (result.success) {
        setSuccess(result.message);
        // Dialog'u kapat ve formu temizle
        setShowAccessRequest(false);
        setAccessRequestData({
          firstName: '',
          lastName: '',
          email: '',
          department: '',
          reason: '',
          requestedRole: 'developer'
        });
        // Error state'i de temizle
        setError(null);
      } else {
        setError(result.message);
        // Error durumunda dialog'u açık bırak
      }
    } catch (error) {
      console.error('❌ Access request error:', error);
      setError('Erişim talebi gönderilirken hata oluştu');
      // Error durumunda dialog'u açık bırak
    } finally {
      setAccessRequestLoading(false);
    }
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  }; return (
    <Box
      sx={{
        minHeight: '100vh',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 2,
      }}
    >
      <Paper
        elevation={24}
        sx={{
          width: '100%',
          maxWidth: 480,
          borderRadius: 3,
          overflow: 'hidden',
        }}
      >        {/* Header */}
        <Box
          sx={{
            background: 'linear-gradient(45deg, #2196F3 30%, #21CBF3 90%)',
            color: 'white',
            padding: 4,
            textAlign: 'center',
          }}
        >
          <Box
            component="img"
            src={ibbLogo}
            alt="İBB Logo"
            sx={{
              height: 80,
              width: 'auto',
              mb: 2,
              borderRadius: 2,
              backgroundColor: 'rgba(255, 255, 255, 0.9)',
              padding: 1,
            }}
          />
          <Typography variant="h4" component="h1" gutterBottom fontWeight="bold">
            İBB Güvenlik Platformu
          </Typography>
          <Typography variant="subtitle1" sx={{ opacity: 0.9 }}>
            Siber Güvenlik Test Sistemi
          </Typography>
        </Box>

        {/* Login Form */}
        <CardContent sx={{ padding: 4 }}>
          {error && (
            <Alert severity="error" sx={{ mb: 3 }}>
              {error}
            </Alert>
          )}

          {success && (
            <Alert severity="success" sx={{ mb: 3 }}>
              {success}
            </Alert>
          )}

          <Box component="form" onSubmit={handleSubmit}>
            <TextField
              fullWidth
              label="Kullanıcı Adı"
              variant="outlined"
              value={credentials.username}
              onChange={handleInputChange('username')}
              disabled={loading}
              sx={{ mb: 3 }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <PersonIcon color="primary" />
                  </InputAdornment>
                ),
              }}
              autoComplete="username"
              autoFocus
            />

            <TextField
              fullWidth
              label="Şifre"
              type={showPassword ? 'text' : 'password'}
              variant="outlined"
              value={credentials.password}
              onChange={handleInputChange('password')}
              disabled={loading}
              sx={{ mb: 4 }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <LockIcon color="primary" />
                  </InputAdornment>
                ),
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton
                      onClick={togglePasswordVisibility}
                      edge="end"
                      disabled={loading}
                    >
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
              autoComplete="current-password"
            />

            <Button
              type="submit"
              fullWidth
              variant="contained"
              size="large"
              disabled={loading}
              sx={{
                mb: 3,
                height: 56,
                background: 'linear-gradient(45deg, #2196F3 30%, #21CBF3 90%)',
                '&:hover': {
                  background: 'linear-gradient(45deg, #1976D2 30%, #0288D1 90%)',
                },
              }}
            >
              {loading ? (
                <CircularProgress size={24} color="inherit" />
              ) : (
                'Giriş Yap'
              )}
            </Button>
          </Box>

          <Divider sx={{ my: 3 }}>
            <Typography variant="body2" color="text.secondary">
              VEYA
            </Typography>
          </Divider>

          <Button
            fullWidth
            variant="outlined"
            size="large"
            onClick={() => setShowAccessRequest(true)}
            sx={{
              height: 56,
              borderColor: '#2196F3',
              color: '#2196F3',
              '&:hover': {
                borderColor: '#1976D2',
                backgroundColor: 'rgba(33, 150, 243, 0.04)',
              },
            }}
          >
            Erişim Talebi Gönder
          </Button>

          <Box sx={{ mt: 3, textAlign: 'center' }}>
            <Typography variant="body2" color="text.secondary">
              Sistem yöneticisinden yetki almanız gerekmektedir
            </Typography>
          </Box>
        </CardContent>
      </Paper>

      {/* Access Request Dialog */}
      <Dialog
        open={showAccessRequest}
        onClose={() => setShowAccessRequest(false)}
        maxWidth="sm"
        fullWidth
      >        <DialogTitle>
          <Box display="flex" alignItems="center">
            <SecurityIcon sx={{ mr: 1, color: 'primary.main' }} />
            İBB Güvenlik Platformu Erişim Talebi
          </Box>
        </DialogTitle>

        <DialogContent>
          <Typography variant="body2" color="text.secondary" paragraph>
            İBB Güvenlik Test Platformuna erişim için aşağıdaki bilgileri doldurunuz.
            Talebiniz sistem yöneticisi tarafından değerlendirilecektir.
          </Typography><Box sx={{ mt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <Box sx={{ display: 'flex', gap: 2, flexDirection: { xs: 'column', sm: 'row' } }}>
              <TextField
                fullWidth
                label="Ad"
                value={accessRequestData.firstName}
                onChange={handleAccessRequestChange('firstName')}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <PersonIcon />
                    </InputAdornment>
                  ),
                }}
              />
              <TextField
                fullWidth
                label="Soyad"
                value={accessRequestData.lastName}
                onChange={handleAccessRequestChange('lastName')}
              />
            </Box>

            <TextField
              fullWidth
              label="E-posta"
              type="email"
              value={accessRequestData.email}
              onChange={handleAccessRequestChange('email')}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <EmailIcon />
                  </InputAdornment>
                ),
              }}
            />

            <TextField
              fullWidth
              label="Departman"
              value={accessRequestData.department}
              onChange={handleAccessRequestChange('department')}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <BusinessIcon />
                  </InputAdornment>
                ),
              }}
            />

            <Alert severity="info" sx={{ mt: 1 }}>
              <Typography variant="body2">
                <strong>Not:</strong> Kayıt olduğunuzda size otomatik olarak temel kullanıcı rolü atanacaktır.
                Admin, gerekli rolleri ve yetkileri daha sonra tanımlayacaktır.
              </Typography>
            </Alert>

            <TextField
              fullWidth
              label="Erişim Gerekçesi"
              multiline
              rows={3}
              value={accessRequestData.reason}
              onChange={handleAccessRequestChange('reason')}
              placeholder="Sisteme neden erişim ihtiyacınız olduğunu açıklayınız..."
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start" sx={{ alignSelf: 'flex-start', mt: 1 }}>
                    <DescriptionIcon />
                  </InputAdornment>
                ),
              }}
            />
          </Box>
        </DialogContent>

        <DialogActions sx={{ p: 3 }}>
          <Button
            onClick={() => setShowAccessRequest(false)}
            disabled={accessRequestLoading}
          >
            İptal
          </Button>
          <Button
            variant="contained"
            onClick={handleAccessRequest}
            disabled={accessRequestLoading}
            startIcon={accessRequestLoading ? <CircularProgress size={16} /> : <SecurityIcon />}
          >
            {accessRequestLoading ? 'Gönderiliyor...' : 'Talep Gönder'}
          </Button>        </DialogActions>
      </Dialog>    </Box>
  );
};

export default Login;
