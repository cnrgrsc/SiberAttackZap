import React from 'react';
import { usePermissions } from '../contexts/PermissionContext';
import { Box, CircularProgress, Typography, Paper } from '@mui/material';
import LockIcon from '@mui/icons-material/Lock';

interface ProtectedRouteProps {
  children: React.ReactElement;
  requiredPermissions?: string[];
  requireAll?: boolean; // true = AND, false = OR (default)
  fallbackPath?: string;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  requiredPermissions = [],
  requireAll = false,
  fallbackPath = '/'
}) => {
  const { loading, hasAnyPermission, hasAllPermissions } = usePermissions();

  // Yükleniyor
  if (loading) {
    return (
      <Box
        display="flex"
        justifyContent="center"
        alignItems="center"
        minHeight="100vh"
        bgcolor="background.default"
      >
        <Box textAlign="center">
          <CircularProgress size={60} />
          <Typography variant="h6" sx={{ mt: 2 }}>
            Yetki kontrolü yapılıyor...
          </Typography>
        </Box>
      </Box>
    );
  }

  // İzin kontrolü
  if (requiredPermissions.length > 0) {
    const hasAccess = requireAll
      ? hasAllPermissions(...requiredPermissions)
      : hasAnyPermission(...requiredPermissions);

    if (!hasAccess) {
      console.warn('🚫 Access denied. Required permissions:', requiredPermissions);

      // Yetkisiz erişim sayfası
      return (
        <Box
          display="flex"
          justifyContent="center"
          alignItems="center"
          minHeight="100vh"
          bgcolor="background.default"
          p={3}
        >
          <Paper
            elevation={3}
            sx={{
              p: 4,
              maxWidth: 500,
              textAlign: 'center',
              bgcolor: 'background.paper'
            }}
          >
            <LockIcon sx={{ fontSize: 80, color: 'error.main', mb: 2 }} />
            <Typography variant="h4" gutterBottom color="error">
              Yetkisiz Erişim
            </Typography>
            <Typography variant="body1" color="text.secondary" paragraph>
              Bu sayfaya erişim yetkiniz bulunmamaktadır.
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Gerekli izinler: {requiredPermissions.join(', ')}
            </Typography>
            <Box mt={3}>
              <Typography variant="caption" color="text.disabled">
                Yetki gerektiren bir sayfaya erişmeye çalıştınız. Lütfen sistem yöneticinizle iletişime geçin.
              </Typography>
            </Box>
          </Paper>
        </Box>
      );
    }
  }

  return children;
};

// Permission Guard - Bileşen seviyesinde izin kontrolü
interface PermissionGuardProps {
  children: React.ReactNode;
  requiredPermissions?: string[];
  requireAll?: boolean;
  fallback?: React.ReactNode;
}

export const PermissionGuard: React.FC<PermissionGuardProps> = ({
  children,
  requiredPermissions = [],
  requireAll = false,
  fallback = null
}) => {
  const { hasAnyPermission, hasAllPermissions } = usePermissions();

  if (requiredPermissions.length === 0) {
    return <>{children}</>;
  }

  const hasAccess = requireAll
    ? hasAllPermissions(...requiredPermissions)
    : hasAnyPermission(...requiredPermissions);

  if (!hasAccess) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
};
