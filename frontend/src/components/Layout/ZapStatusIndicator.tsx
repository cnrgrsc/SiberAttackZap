import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Chip,
  CircularProgress,
  IconButton,
  Tooltip,
  Alert,
} from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Refresh as RefreshIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import { zapService } from '../../services/zapService';

interface ZapStatus {
  isRunning: boolean;
  version?: string;
  url?: string;
  lastChecked: Date;
  error?: string;
}

const ZapStatusIndicator: React.FC = () => {
  const [status, setStatus] = useState<ZapStatus>({
    isRunning: false,
    lastChecked: new Date(),
  });
  const [loading, setLoading] = useState(true);

  const checkZapStatus = async () => {
    setLoading(true);
    try {
      const response = await zapService.getStatus();
      setStatus({
        isRunning: true,
        version: response.version,
        url: response.url,
        lastChecked: new Date(),
        error: undefined,
      });
    } catch (error) {
      setStatus({
        isRunning: false,
        lastChecked: new Date(),
        error: error instanceof Error ? error.message : 'Connection failed',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkZapStatus();
    // Check status every 30 seconds
    const interval = setInterval(checkZapStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  const getStatusColor = () => {
    if (loading) return 'default';
    return status.isRunning ? 'success' : 'error';
  };

  const getStatusIcon = () => {
    if (loading) return <CircularProgress size={16} />;
    return status.isRunning ? <CheckCircleIcon /> : <ErrorIcon />;
  };

  const getStatusText = () => {
    if (loading) return 'Checking...';
    return status.isRunning ? 'ZAP Connected' : 'ZAP Disconnected';
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
        <Typography variant="subtitle2" color="text.secondary">
          ZAP Proxy Status
        </Typography>
        <Tooltip title="Refresh Status">
          <IconButton size="small" onClick={checkZapStatus} disabled={loading}>
            <RefreshIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      
      <Chip
        icon={getStatusIcon()}
        label={getStatusText()}
        color={getStatusColor()}
        variant="outlined"
        size="small"
        sx={{ width: '100%', justifyContent: 'flex-start' }}
      />
      
      {status.version && (
        <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
          Version: {status.version}
        </Typography>
      )}
      
      {status.error && (
        <Alert 
          severity="warning" 
          icon={<WarningIcon fontSize="inherit" />}
          sx={{ mt: 1, py: 0.5 }}
        >
          <Typography variant="caption">
            {status.error}
          </Typography>
        </Alert>
      )}
      
      <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
        Last checked: {status.lastChecked.toLocaleTimeString()}
      </Typography>
    </Box>
  );
};

export default ZapStatusIndicator;
