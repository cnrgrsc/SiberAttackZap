import React, { useEffect, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { Box, CircularProgress, Typography } from '@mui/material';
import authService from '../../services/authService';

const RoleBasedRedirect: React.FC = () => {
  const location = useLocation();
  const [loading, setLoading] = useState(true);
  const [redirectTo, setRedirectTo] = useState<string | null>(null);
  useEffect(() => {
    
    const checkAuthAndRedirect = async () => {
      try {
        const isAuthenticated = authService.isAuthenticated();
        
        if (!isAuthenticated) {
          setRedirectTo('/login');
          setLoading(false);
          return;
        }

        const user = authService.getUser();
        
        if (user) {
          const redirectPath = user.role === 'admin' ? '/admin' : '/dashboard';
          setRedirectTo(redirectPath);
        } else {
          setRedirectTo('/login');
        }
      } catch (error) {
        console.error('❌ RoleBasedRedirect: Error during auth check:', error);
        setRedirectTo('/login');
      } finally {
        setLoading(false);
      }
    };

    // Immediate execution without delay
    checkAuthAndRedirect();
  }, []);

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
          Yönlendiriliyor...
        </Typography>
      </Box>
    );
  }

  if (redirectTo) {
    return <Navigate to={redirectTo} state={{ from: location }} replace />;
  }

  // Fallback
  return <Navigate to="/login" state={{ from: location }} replace />;
};

export default RoleBasedRedirect;
