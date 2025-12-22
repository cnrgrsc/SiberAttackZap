import React, { useState, useEffect } from 'react';
import {
  IconButton,
  Badge,
  Menu,
  MenuItem,
  Box,
  Typography,
  Divider,
  Chip,
  Button,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Tooltip,
  Alert,
} from '@mui/material';
import {
  NotificationsActive as NotificationsIcon,
  Info as InfoIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as SuccessIcon,
  MarkEmailRead as MarkReadIcon,
  Delete as DeleteIcon,
  ClearAll as ClearAllIcon,
} from '@mui/icons-material';
import notificationService, { Notification, NotificationStats } from '../../services/notificationService';
import { Logger } from '../../utils/logger';

const NotificationDropdown: React.FC = () => {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [stats, setStats] = useState<NotificationStats>({
    total: 0,
    unread: 0,
    byType: { info: 0, warning: 0, error: 0, success: 0 },
    bySeverity: { low: 0, medium: 0, high: 0, critical: 0 }
  });

  const open = Boolean(anchorEl);

  useEffect(() => {
    Logger.info('NotificationDropdown: Subscribing to notification service');
    
    const unsubscribe = notificationService.subscribe((updatedNotifications) => {
      setNotifications(updatedNotifications.slice(0, 10)); // Show latest 10
      setStats(notificationService.getStats());
    });

    return unsubscribe;
  }, []);

  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleMarkAsRead = (notificationId: string) => {
    notificationService.markAsRead(notificationId);
  };

  const handleMarkAllAsRead = () => {
    notificationService.markAllAsRead();
  };

  const handleDelete = (notificationId: string) => {
    notificationService.deleteNotification(notificationId);
  };

  const handleClearAll = () => {
    notificationService.clearAll();
    handleClose();
  };

  const getNotificationIcon = (type: string) => {
    switch (type) {
      case 'info': return <InfoIcon color="info" />;
      case 'warning': return <WarningIcon color="warning" />;
      case 'error': return <ErrorIcon color="error" />;
      case 'success': return <SuccessIcon color="success" />;
      default: return <InfoIcon />;
    }
  };

  const getSeverityColor = (severity?: string) => {
    switch (severity) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f57c00';
      case 'medium': return '#fbc02d';
      case 'low': return '#388e3c';
      default: return '#1976d2';
    }
  };

  const formatTimestamp = (timestamp: Date) => {
    const now = new Date();
    const diff = now.getTime() - timestamp.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);

    if (days > 0) return `${days}g önce`;
    if (hours > 0) return `${hours}s önce`;
    if (minutes > 0) return `${minutes}dk önce`;
    return 'Şimdi';
  };

  return (
    <>
      <Tooltip title="Bildirimler">
        <IconButton 
          color="inherit" 
          onClick={handleClick}
          sx={{
            '&:hover': {
              backgroundColor: 'rgba(255, 255, 255, 0.1)',
            }
          }}
        >
          <Badge 
            badgeContent={stats.unread} 
            color="error"
            sx={{
              '& .MuiBadge-badge': {
                backgroundColor: '#f44336',
                color: 'white',
                fontSize: '0.75rem',
                minWidth: '20px',
                height: '20px',
                borderRadius: '10px',
              }
            }}
          >
            <NotificationsIcon />
          </Badge>
        </IconButton>
      </Tooltip>

      <Menu
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
        PaperProps={{
          sx: {
            width: 400,
            maxHeight: 600,
            backgroundColor: '#1e1e1e',
            border: '1px solid #333',
          }
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
      >
        {/* Header */}
        <Box sx={{ p: 2, borderBottom: '1px solid #333' }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
            <Typography variant="h6" sx={{ fontWeight: 600 }}>
              Bildirimler
            </Typography>
            <Box sx={{ display: 'flex', gap: 1 }}>
              {stats.unread > 0 && (
                <Tooltip title="Tümünü okundu işaretle">
                  <IconButton size="small" onClick={handleMarkAllAsRead}>
                    <MarkReadIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
              )}
              {stats.total > 0 && (
                <Tooltip title="Tümünü temizle">
                  <IconButton size="small" onClick={handleClearAll}>
                    <ClearAllIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
              )}
            </Box>
          </Box>
          
          {/* Stats */}
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
            <Chip 
              label={`${stats.total} Toplam`} 
              size="small" 
              variant="outlined"
            />
            {stats.unread > 0 && (
              <Chip 
                label={`${stats.unread} Okunmamış`} 
                size="small" 
                color="error"
              />
            )}
            {stats.bySeverity.critical > 0 && (
              <Chip 
                label={`${stats.bySeverity.critical} Kritik`} 
                size="small" 
                sx={{ 
                  backgroundColor: getSeverityColor('critical'), 
                  color: 'white' 
                }}
              />
            )}
          </Box>
        </Box>

        {/* Notifications List */}
        {notifications.length === 0 ? (
          <Box sx={{ p: 3, textAlign: 'center' }}>
            <Typography color="text.secondary">
              Henüz bildirim yok
            </Typography>
          </Box>
        ) : (
          <List sx={{ p: 0, maxHeight: 400, overflow: 'auto' }}>
            {notifications.map((notification, index) => (
              <React.Fragment key={notification.id}>
                <ListItem
                  sx={{
                    backgroundColor: notification.read ? 'transparent' : 'rgba(25, 118, 210, 0.08)',
                    '&:hover': {
                      backgroundColor: 'rgba(255, 255, 255, 0.05)',
                    },
                    cursor: 'pointer',
                  }}
                  onClick={() => !notification.read && handleMarkAsRead(notification.id)}
                >
                  <ListItemIcon sx={{ minWidth: 40 }}>
                    {getNotificationIcon(notification.type)}
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <Typography 
                          variant="subtitle2" 
                          sx={{ 
                            fontWeight: notification.read ? 400 : 600,
                            fontSize: '0.9rem',
                            lineHeight: 1.3,
                            pr: 1
                          }}
                        >
                          {notification.title}
                        </Typography>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          {notification.severity && (
                            <Chip
                              label={notification.severity.toUpperCase()}
                              size="small"
                              sx={{
                                backgroundColor: getSeverityColor(notification.severity),
                                color: 'white',
                                fontSize: '0.7rem',
                                height: '20px',
                                minWidth: '50px',
                              }}
                            />
                          )}
                          <Tooltip title="Sil">
                            <IconButton 
                              size="small" 
                              onClick={(e) => {
                                e.stopPropagation();
                                handleDelete(notification.id);
                              }}
                            >
                              <DeleteIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </Box>
                    }
                    secondary={
                      <Box>
                        <Typography 
                          variant="body2" 
                          color="text.secondary" 
                          sx={{ 
                            fontSize: '0.8rem',
                            lineHeight: 1.4,
                            mb: 0.5
                          }}
                        >
                          {notification.message}
                        </Typography>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <Typography 
                            variant="caption" 
                            color="text.secondary"
                            sx={{ fontSize: '0.7rem' }}
                          >
                            {formatTimestamp(notification.timestamp || new Date())}
                          </Typography>
                          {notification.source && (
                            <Chip
                              label={notification.source}
                              size="small"
                              variant="outlined"
                              sx={{ fontSize: '0.7rem', height: '18px' }}
                            />
                          )}
                        </Box>
                      </Box>
                    }
                  />
                </ListItem>
                {index < notifications.length - 1 && (
                  <Divider sx={{ borderColor: '#333' }} />
                )}
              </React.Fragment>
            ))}
          </List>
        )}

        {/* Footer */}
        {notifications.length > 0 && (
          <Box sx={{ p: 2, borderTop: '1px solid #333', textAlign: 'center' }}>
            <Button 
              size="small" 
              variant="outlined"
              onClick={handleClose}
              sx={{ minWidth: 120 }}
            >
              Kapat
            </Button>
          </Box>
        )}
      </Menu>
    </>
  );
};

export default NotificationDropdown;
