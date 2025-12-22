import React, { useEffect, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { Box, CircularProgress, Typography } from '@mui/material';
import authService from '../../services/authService';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: 'admin' | 'developer';
  fallbackPath?: string;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  requiredRole,
  fallbackPath = '/login'
}) => {
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [hasPermission, setHasPermission] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const location = useLocation();

  useEffect(() => {
    let isMounted = true;
    let authCheckCompleted = false;
    
    const checkAuth = async () => {
      // Prevent multiple simultaneous auth checks
      if (authCheckCompleted) return;
      authCheckCompleted = true;
      
      try {
        
        // Quick local check first
        const authenticated = authService.isAuthenticated();
        
        if (!isMounted) return;
        
        if (!authenticated) {
          setIsAuthenticated(false);
          setLoading(false);
          return;
        }        // Only validate token if locally authenticated
        try {
          const tokenValid = await authService.validateToken();
          
          if (!isMounted) return;
          
          if (!tokenValid) {
            authService.logout(); // Clear invalid token
            setError('Oturum süresi doldu, lütfen tekrar giriş yapın');
            setIsAuthenticated(false);
            setLoading(false);
            return;
          }
          
        } catch (validationError: any) {
          console.error('❌ ProtectedRoute: Token validation error:', validationError);
          
          if (!isMounted) return;
          
          // Handle specific validation errors
          if (validationError.response?.status === 401) {
            authService.logout(); // Clear invalid token
            setError('Hesabınız aktif değil veya oturum süresi dolmuş');
          } else if (validationError.response?.status === 403) {
            authService.logout(); // Clear forbidden token
            setError('Erişim reddedildi');
          } else {
            // For network errors, don't clear auth, just continue
            setIsAuthenticated(true);
            setHasPermission(requiredRole ? authService.canAccess(requiredRole) : true);
            setLoading(false);
            return;
          }
          
          setIsAuthenticated(false);
          setLoading(false);
          return;
        }

        // Authentication successful
        setIsAuthenticated(true);

        // Check role permissions
        if (requiredRole) {
          const hasRole = authService.canAccess(requiredRole);
          setHasPermission(hasRole);
        } else {
          setHasPermission(true);
        }

      } catch (error) {
        console.error('❌ ProtectedRoute: Unexpected auth error:', error);
        if (isMounted) {
          setError('Beklenmeyen bir hata oluştu');
          setIsAuthenticated(false);
          setHasPermission(false);
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    // Run auth check only once
    checkAuth();
    
    return () => {
      isMounted = false;
    };
  }, []); // Empty dependency array - run only once on mount

  if (loading) {
    return (
      <Box
        display="flex"
        flexDirection="column"
        alignItems="center"
        justifyContent="center"
        minHeight="100vh"
      >
        <CircularProgress size={48} />
        <Typography variant="h6" sx={{ mt: 2 }}>
          Yetki kontrol ediliyor...
        </Typography>
      </Box>
    );
  }  if (!isAuthenticated) {
    if (error) {
      return <Navigate to={fallbackPath} state={{ from: location, error: error }} replace />;
    }
    return <Navigate to={fallbackPath} state={{ from: location }} replace />;
  }

  if (requiredRole && !hasPermission) {
    const user = authService.getUser();
    
    if (user?.role === 'developer' && requiredRole === 'admin') {
      return <Navigate to="/dashboard" replace />;
    }
    
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
};

export default ProtectedRoute;
