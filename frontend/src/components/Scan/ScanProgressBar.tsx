import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  LinearProgress,
  Chip,
  Alert,
  CircularProgress,
  Paper,
  Fade,
  Collapse,
} from '@mui/material';
import {
  PlayArrow as PlayArrowIcon,
  Search as SearchIcon,
  Security as SecurityIcon,
  CheckCircle as CheckCircleIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import scanService from '../../services/scanService';
import socketService from '../../services/socketService';

interface ScanProgressData {
  progress: number;
  phase: string;
  details: {
    spider?: { progress: number; status: string };
    ajaxSpider?: { progress: number; status: string };
    activeScan?: { progress: number; status: string };
  };
  isCompleted: boolean;
  error?: string;
}

interface ScanProgressProps {
  scanId: string;
  onComplete?: () => void;
  onError?: (error: string) => void;
  refreshInterval?: number;
  realTimeUpdates?: boolean; // New prop for WebSocket updates
}

const ScanProgressBar: React.FC<ScanProgressProps> = ({
  scanId,
  onComplete,
  onError,
  refreshInterval = 2000,
  realTimeUpdates = true, // Enable by default
}) => {
  const [progressData, setProgressData] = useState<ScanProgressData>({
    progress: 0,
    phase: 'Initializing',
    details: {},
    isCompleted: false,
  });
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // WebSocket real-time updates
  useEffect(() => {
    if (realTimeUpdates && scanId) {
      // Join scan room for real-time updates
      socketService.joinScanRoom(scanId);

      // Listen for progress updates
      socketService.onScanProgress((data) => {
        setProgressData(prev => ({
          ...prev,
          ...data,
        }));
        setIsLoading(false);
      });

      return () => {
        socketService.leaveScanRoom(scanId);
        socketService.offScanProgress();
      };
    }
  }, [scanId, realTimeUpdates]);

  const fetchProgress = async () => {
    try {
      const data = await scanService.getScanProgress(scanId);
      // Use type assertion for production build
      setProgressData(data as any);
      setError(null);

      if ((data as any).isCompleted) {
        onComplete?.();
      } else if ((data as any).error) {
        setError((data as any).error);
        onError?.((data as any).error);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch progress';
      setError(errorMessage);
      onError?.(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (!realTimeUpdates) {
      fetchProgress();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, refreshInterval, progressData?.isCompleted, error]);

  const getPhaseIcon = (phase: string) => {
    switch (phase.toLowerCase()) {
      case 'setup':
        return <RefreshIcon color="primary" />;
      case 'spider':
        return <SearchIcon color="primary" />;
      case 'ajax-spider':
        return <SearchIcon color="secondary" />;
      case 'active-scan':
        return <SecurityIcon color="warning" />;
      case 'completed':
        return <CheckCircleIcon color="success" />;
      default:
        return <PlayArrowIcon color="primary" />;
    }
  };

  const getPhaseColor = (phase: string) => {
    switch (phase.toLowerCase()) {
      case 'setup':
        return 'info';
      case 'spider':
        return 'primary';
      case 'ajax-spider':
        return 'secondary';
      case 'active-scan':
        return 'warning';
      case 'completed':
        return 'success';
      default:
        return 'default';
    }
  };

  const getProgressColor = (progress: number) => {
    if (progress >= 100) return 'success';
    if (progress >= 75) return 'info';
    if (progress >= 50) return 'primary';
    if (progress >= 25) return 'secondary';
    return 'inherit';
  };

  if (isLoading) {
    return (
      <Card>
        <CardContent>
          <Box display="flex" alignItems="center" justifyContent="center" py={3}>
            <CircularProgress />
            <Typography variant="body1" sx={{ ml: 2 }}>
              Loading scan progress...
            </Typography>
          </Box>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ mb: 2 }}>
        <Typography variant="body2">
          Failed to load scan progress: {error}
        </Typography>
      </Alert>
    );
  }

  if (!progressData) {
    return null;
  }

  return (
    <Fade in={true}>
      <Card>
        <CardContent>
          <Box sx={{ mb: 3 }}>
            <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
              <Typography variant="h6" component="div">
                Scan Progress
              </Typography>
              <Chip
                icon={getPhaseIcon(progressData.phase)}
                label={progressData.phase.replace(/-/g, ' ').toUpperCase()}
                color={getPhaseColor(progressData.phase) as any}
                variant={progressData.isCompleted ? 'filled' : 'outlined'}
              />
            </Box>

            <Box sx={{ mb: 2 }}>
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                <Typography variant="body2" color="text.secondary">
                  Overall Progress
                </Typography>
                <Typography variant="body2" fontWeight="bold">
                  {Math.round(progressData.progress)}%
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={progressData.progress}
                color={getProgressColor(progressData.progress)}
                sx={{ height: 8, borderRadius: 4 }}
              />
            </Box>
          </Box>

          <Collapse in={Object.keys(progressData.details).length > 0}>            <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
            <Typography variant="subtitle2" gutterBottom>
              Detailed Progress
            </Typography>
            <Box display="flex" flexDirection="column" gap={2}>
              {progressData.details.spider && (
                <Box>
                  <Box display="flex" alignItems="center" mb={1}>
                    <SearchIcon fontSize="small" sx={{ mr: 1 }} />
                    <Typography variant="body2" fontWeight="medium">
                      Spider Crawl
                    </Typography>
                  </Box>
                  <LinearProgress
                    variant="determinate"
                    value={progressData.details.spider.progress}
                    color="primary"
                    sx={{ mb: 1, height: 6, borderRadius: 3 }}
                  />
                  <Typography variant="caption" color="text.secondary">
                    {progressData.details.spider.status} - {Math.round(progressData.details.spider.progress)}%
                  </Typography>
                </Box>
              )}

              {progressData.details.ajaxSpider && (
                <Box>
                  <Box display="flex" alignItems="center" mb={1}>
                    <SearchIcon fontSize="small" sx={{ mr: 1 }} />
                    <Typography variant="body2" fontWeight="medium">
                      AJAX Spider
                    </Typography>
                  </Box>
                  <LinearProgress
                    variant="determinate"
                    value={progressData.details.ajaxSpider.progress}
                    color="secondary"
                    sx={{ mb: 1, height: 6, borderRadius: 3 }}
                  />
                  <Typography variant="caption" color="text.secondary">
                    {progressData.details.ajaxSpider.status} - {Math.round(progressData.details.ajaxSpider.progress)}%
                  </Typography>
                </Box>
              )}

              {progressData.details.activeScan && (
                <Box>
                  <Box display="flex" alignItems="center" mb={1}>
                    <SecurityIcon fontSize="small" sx={{ mr: 1 }} />
                    <Typography variant="body2" fontWeight="medium">
                      Active Scan
                    </Typography>
                  </Box>
                  <LinearProgress
                    variant="determinate"
                    value={progressData.details.activeScan.progress}
                    color="warning"
                    sx={{ mb: 1, height: 6, borderRadius: 3 }}
                  />
                  <Typography variant="caption" color="text.secondary">
                    {progressData.details.activeScan.status} - {Math.round(progressData.details.activeScan.progress)}%
                  </Typography>
                </Box>
              )}
            </Box>
          </Paper>
          </Collapse>

          {progressData.isCompleted && (
            <Alert severity="success">
              <Typography variant="body2">
                Scan completed successfully! You can now view the results in the scan history.
              </Typography>
            </Alert>
          )}

          {progressData.error && (
            <Alert severity="error">
              <Typography variant="body2">
                Scan error: {progressData.error}
              </Typography>
            </Alert>
          )}
        </CardContent>
      </Card>
    </Fade>
  );
};

export default ScanProgressBar;
