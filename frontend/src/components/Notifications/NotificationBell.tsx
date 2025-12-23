import React, { useState, useEffect } from 'react';
import {
  IconButton,
  Badge,
  Menu,
  Typography,
  Box,
  Divider,
  List,
  ListItem,
  ListItemButton,
  Button,
  Chip,
  CircularProgress
} from '@mui/material';
import {
  Notifications as NotificationsIcon,
  Circle as CircleIcon,
  Delete as DeleteIcon,
  DoneAll as DoneAllIcon
} from '@mui/icons-material';
import { notificationService, Notification } from '../../services/notificationService';
import { useNavigate } from 'react-router-dom';

export const NotificationBell: React.FC = () => {
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [loading, setLoading] = useState(false);

  const open = Boolean(anchorEl);

  const fetchNotifications = async () => {
    setLoading(true);
    try {
      const [notifs, count] = await Promise.all([
        notificationService.getNotifications(),
        notificationService.getUnreadCount()
      ]);
      setNotifications(notifs);
      setUnreadCount(count);
    } catch (error) {
      console.error('Error fetching notifications:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchNotifications();
    // Poll every 30 seconds
    const interval = setInterval(fetchNotifications, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
    if (!open) {
      fetchNotifications();
    }
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleNotificationClick = async (notification: Notification) => {
    if (!notification.isRead) {
      await notificationService.markAsRead(notification.id);
      setUnreadCount(prev => Math.max(0, prev - 1));
      setNotifications(prev =>
        prev.map(n => n.id === notification.id ? { ...n, isRead: true } : n)
      );
    }

    if (notification.link) {
      navigate(notification.link);
    } else if (notification.scanId) {
      navigate(`/scan-history?scanId=${notification.scanId}`);
    }

    handleClose();
  };

  const handleMarkAllRead = async () => {
    await notificationService.markAllAsRead();
    setUnreadCount(0);
    setNotifications(prev => prev.map(n => ({ ...n, isRead: true })));
  };

  const handleDelete = async (notificationId: string, event: React.MouseEvent) => {
    event.stopPropagation();
    await notificationService.deleteNotification(notificationId);
    setNotifications(prev => prev.filter(n => n.id !== notificationId));
    if (notifications.find(n => n.id === notificationId && !n.isRead)) {
      setUnreadCount(prev => Math.max(0, prev - 1));
    }
  };

  const getNotificationColor = (type: string) => {
    switch (type) {
      case 'SCAN_CREATED':
        return 'info';
      case 'SCAN_COMPLETED':
        return 'success';
      case 'SCAN_FAILED':
        return 'error';
      case 'VULNERABILITY_CRITICAL':
      case 'VULNERABILITY_HIGH':
        return 'error';
      case 'SYSTEM_ALERT':
        return 'warning';
      default:
        return 'default';
    }
  };

  const formatTimeAgo = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const seconds = Math.floor((now.getTime() - date.getTime()) / 1000);

    if (seconds < 60) return 'Az önce';
    if (seconds < 3600) return `${Math.floor(seconds / 60)} dakika önce`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} saat önce`;
    if (seconds < 604800) return `${Math.floor(seconds / 86400)} gün önce`;
    return date.toLocaleDateString('tr-TR');
  };

  return (
    <>
      <IconButton color="inherit" onClick={handleClick}>
        <Badge badgeContent={unreadCount} color="error">
          <NotificationsIcon />
        </Badge>
      </IconButton>

      <Menu
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
        PaperProps={{
          sx: {
            width: 400,
            maxHeight: 600,
            overflow: 'auto'
          }
        }}
        transformOrigin={{ horizontal: 'right', vertical: 'top' }}
        anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
      >
        <Box sx={{ p: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6">Bildirimler</Typography>
          {unreadCount > 0 && (
            <Button
              size="small"
              startIcon={<DoneAllIcon />}
              onClick={handleMarkAllRead}
            >
              Tümünü Okundu İşaretle
            </Button>
          )}
        </Box>

        <Divider />

        {loading && (
          <Box display="flex" justifyContent="center" p={3}>
            <CircularProgress size={30} />
          </Box>
        )}

        {!loading && notifications.length === 0 && (
          <Box p={3} textAlign="center">
            <Typography variant="body2" color="text.secondary">
              Bildirim bulunmuyor
            </Typography>
          </Box>
        )}

        {!loading && notifications.length > 0 && (
          <List sx={{ p: 0 }}>
            {notifications.map((notification) => (
              <React.Fragment key={notification.id}>
                <ListItem disablePadding>
                  <ListItemButton
                    onClick={() => handleNotificationClick(notification)}
                    sx={{
                      bgcolor: notification.isRead ? 'transparent' : 'action.hover',
                      '&:hover': {
                        bgcolor: 'action.selected'
                      }
                    }}
                  >
                    <Box sx={{ width: '100%' }}>
                      <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={0.5}>
                        <Box display="flex" alignItems="center" gap={1} flex={1}>
                          {!notification.isRead && (
                            <CircleIcon sx={{ fontSize: 8, color: 'primary.main' }} />
                          )}
                          <Typography variant="subtitle2" sx={{ fontWeight: notification.isRead ? 400 : 600 }}>
                            {notification.title}
                          </Typography>
                        </Box>
                        <IconButton
                          size="small"
                          onClick={(e) => handleDelete(notification.id, e)}
                          sx={{ ml: 1 }}
                        >
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Box>

                      <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                        {notification.message}
                      </Typography>

                      {notification.scan && (
                        <Chip
                          label={notification.scan.name}
                          size="small"
                          color={getNotificationColor(notification.type) as any}
                          sx={{ mr: 1, mb: 0.5 }}
                        />
                      )}

                      <Typography variant="caption" color="text.disabled">
                        {formatTimeAgo(notification.createdAt || '')}
                      </Typography>
                    </Box>
                  </ListItemButton>
                </ListItem>
                <Divider component="li" />
              </React.Fragment>
            ))}
          </List>
        )}
      </Menu>
    </>
  );
};
