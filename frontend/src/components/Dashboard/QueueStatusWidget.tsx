import React, { useState, useEffect } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  LinearProgress,
  List,
  ListItem,
  Chip,
  Divider,
  IconButton,
  Tooltip,
  Alert,
} from '@mui/material';
import {
  HourglassEmpty as QueueIcon,
  Person as PersonIcon,
  Schedule as ScheduleIcon,
  Refresh as RefreshIcon,
  CheckCircle as SuccessIcon,
} from '@mui/icons-material';
import api from '../../services/api';

interface QueueStats {
  activeScans: number;
  queuedScans: number;
  availableSlots: number;
  queueItems: Array<{
    scanId: string;
    position: number;
    priority: number;
    estimatedStart: string;
    userName: string;
    targetUrl: string;
  }>;
}

const QueueStatusWidget: React.FC = () => {
  const [stats, setStats] = useState<QueueStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchQueueStats = async () => {
    try {
      setLoading(true);
      const response = await api.get('/scans/queue/stats');
      setStats(response.data.data);
      setError(null);
    } catch (err) {
      console.error('Error fetching queue stats:', err);
      setError('Kuyruk bilgileri yüklenemedi');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchQueueStats();
    // Her 10 saniyede bir güncelle
    const interval = setInterval(fetchQueueStats, 10000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) {
    return (
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="center" p={2}>
            <LinearProgress sx={{ width: '100%' }} />
          </Box>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card elevation={3}>
        <CardContent>
          <Box display="flex" alignItems="center" gap={1} mb={2}>
            <QueueIcon color="primary" />
            <Typography variant="h6">Tarama Kuyruğu</Typography>
          </Box>
          <Alert severity="error">{error}</Alert>
          <Box mt={2} display="flex" justifyContent="center">
            <IconButton size="small" onClick={fetchQueueStats} color="primary">
              <RefreshIcon />
            </IconButton>
          </Box>
        </CardContent>
      </Card>
    );
  }

  if (!stats) {
    return (
      <Card elevation={3}>
        <CardContent>
          <Box display="flex" alignItems="center" gap={1} mb={2}>
            <QueueIcon color="primary" />
            <Typography variant="h6">Tarama Kuyruğu</Typography>
          </Box>
          <Alert severity="info">Kuyruk bilgisi yükleniyor...</Alert>
        </CardContent>
      </Card>
    );
  }

  const maxScans = 3; // From backend config
  const usagePercentage = (stats.activeScans / maxScans) * 100;

  return (
    <Card elevation={3}>
      <CardContent>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Box display="flex" alignItems="center" gap={1}>
            <QueueIcon color="primary" />
            <Typography variant="h6">Tarama Kuyruğu</Typography>
          </Box>
          <Tooltip title="Yenile">
            <IconButton size="small" onClick={fetchQueueStats}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Box>

        {/* System Load */}
        <Box mb={3}>
          <Box display="flex" justifyContent="space-between" mb={1}>
            <Typography variant="body2" color="text.secondary">
              Sistem Yükü
            </Typography>
            <Typography variant="body2" fontWeight="bold">
              {stats.activeScans} / {maxScans}
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={usagePercentage}
            sx={{
              height: 8,
              borderRadius: 4,
              backgroundColor: 'rgba(0,0,0,0.1)',
              '& .MuiLinearProgress-bar': {
                borderRadius: 4,
                backgroundColor:
                  usagePercentage >= 100
                    ? '#f44336'
                    : usagePercentage >= 66
                      ? '#ff9800'
                      : '#4caf50',
              },
            }}
          />
        </Box>

        {/* Stats Grid */}
        <Box display="grid" gridTemplateColumns="repeat(3, 1fr)" gap={2} mb={2}>
          <Box textAlign="center">
            <Typography variant="h4" color="success.main">
              {stats.activeScans}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Aktif
            </Typography>
          </Box>
          <Box textAlign="center">
            <Typography variant="h4" color="warning.main">
              {stats.queuedScans}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Sırada
            </Typography>
          </Box>
          <Box textAlign="center">
            <Typography variant="h4" color="primary.main">
              {stats.availableSlots}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Boş Slot
            </Typography>
          </Box>
        </Box>

        {/* Status Message */}
        {stats.availableSlots === 0 && stats.queuedScans > 0 && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            <Typography variant="body2">
              ⚠️ Sistem dolu! Yeni taramalar sıraya alınacak.
            </Typography>
          </Alert>
        )}

        {stats.availableSlots > 0 && (
          <Alert severity="success" sx={{ mb: 2 }} icon={<SuccessIcon />}>
            <Typography variant="body2">
              ✅ {stats.availableSlots} slot müsait - Hemen tarama başlatabilirsiniz!
            </Typography>
          </Alert>
        )}

        {/* Queue List */}
        {stats.queuedScans > 0 && (
          <>
            <Divider sx={{ my: 2 }} />
            <Typography variant="subtitle2" gutterBottom>
              Kuyrukta Bekleyen Taramalar
            </Typography>
            <List dense sx={{ maxHeight: 300, overflow: 'auto' }}>
              {stats.queueItems.map((item, index) => (
                <ListItem
                  key={item.scanId}
                  sx={{
                    bgcolor: index % 2 === 0 ? 'rgba(0,0,0,0.02)' : 'transparent',
                    borderRadius: 1,
                    mb: 0.5,
                  }}
                >
                  <Box sx={{ width: '100%' }}>
                    <Box display="flex" justifyContent="space-between" alignItems="center">
                      <Box display="flex" alignItems="center" gap={1}>
                        <Chip
                          label={`#${item.position}`}
                          size="small"
                          color={item.position === 1 ? 'success' : 'default'}
                          sx={{ minWidth: 40 }}
                        />
                        <Box>
                          <Typography variant="body2" fontWeight="bold">
                            {item.targetUrl.length > 30
                              ? item.targetUrl.substring(0, 30) + '...'
                              : item.targetUrl}
                          </Typography>
                          <Box display="flex" alignItems="center" gap={1}>
                            <PersonIcon fontSize="small" sx={{ fontSize: 14 }} />
                            <Typography variant="caption" color="text.secondary">
                              {item.userName}
                            </Typography>
                          </Box>
                        </Box>
                      </Box>
                      <Box textAlign="right">
                        <Chip
                          label={`P${item.priority}`}
                          size="small"
                          variant="outlined"
                          color={
                            item.priority === 1
                              ? 'error'
                              : item.priority <= 3
                                ? 'warning'
                                : 'default'
                          }
                        />
                        <Box display="flex" alignItems="center" gap={0.5} mt={0.5}>
                          <ScheduleIcon sx={{ fontSize: 14 }} color="action" />
                          <Typography variant="caption" color="text.secondary">
                            {formatEstimatedTime(item.estimatedStart)}
                          </Typography>
                        </Box>
                      </Box>
                    </Box>
                  </Box>
                </ListItem>
              ))}
            </List>
          </>
        )}

        {stats.queuedScans === 0 && stats.activeScans === 0 && (
          <Box textAlign="center" py={3}>
            <Typography variant="body2" color="text.secondary">
              🎉 Hiç tarama yok - Sistem boşta!
            </Typography>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

// Helper function to format estimated time
function formatEstimatedTime(isoString: string): string {
  const date = new Date(isoString);
  const now = new Date();
  const diffMs = date.getTime() - now.getTime();
  const diffMins = Math.floor(diffMs / 60000);

  if (diffMins < 1) return 'Birazdan';
  if (diffMins < 60) return `~${diffMins} dk`;
  const hours = Math.floor(diffMins / 60);
  const mins = diffMins % 60;
  return `~${hours}s ${mins}dk`;
}

export default QueueStatusWidget;
