import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Chip,
  Tooltip,
  IconButton,
  CircularProgress,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  CheckCircle as ConnectedIcon,
  Error as DisconnectedIcon,
  PhoneAndroid as MobileIcon,
} from '@mui/icons-material';
import mobsfService from '../../services/mobsfService';

const MobSFStatusIndicator: React.FC = () => {
  const [status, setStatus] = useState<{ isRunning: boolean; version?: string }>({ isRunning: false });
  const [loading, setLoading] = useState(true);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);

  const checkStatus = async () => {
    try {
      setLoading(true);
      const statusData = await mobsfService.getStatus();
      setStatus(statusData);
      setLastChecked(new Date());
    } catch (error) {
      console.error('Failed to get MobSF status:', error);
      setStatus({ isRunning: false });
      setLastChecked(new Date());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkStatus();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(checkStatus, 30000);
    
    return () => clearInterval(interval);
  }, []);

  const getStatusColor = () => {
    if (loading) return 'default';
    return status.isRunning ? 'success' : 'error';
  };

  const getStatusIcon = () => {
    if (loading) return <CircularProgress size={16} />;
    return status.isRunning ? <ConnectedIcon /> : <DisconnectedIcon />;
  };

  const getStatusText = () => {
    if (loading) return 'Checking...';
    return status.isRunning ? 'Connected' : 'Disconnected';
  };

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      <MobileIcon sx={{ fontSize: 20, color: 'text.secondary' }} />
      <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
        <Typography variant="caption" color="text.secondary">
          MobSF Status
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Chip
            icon={getStatusIcon()}
            label={getStatusText()}
            color={getStatusColor() as any}
            size="small"
            variant="outlined"
          />
          <Tooltip title="Refresh MobSF Status">
            <IconButton 
              size="small" 
              onClick={checkStatus}
              disabled={loading}
            >
              <RefreshIcon sx={{ fontSize: 16 }} />
            </IconButton>
          </Tooltip>
        </Box>
        {status.version && (
          <Typography variant="caption" color="text.secondary">
            {status.version}
          </Typography>
        )}
        {lastChecked && (
          <Typography variant="caption" color="text.secondary">
            Last checked: {lastChecked.toLocaleTimeString()}
          </Typography>
        )}
      </Box>
    </Box>
  );
};

export default MobSFStatusIndicator;
