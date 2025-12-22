import React, { useState } from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Box,
  IconButton,
  Tooltip,
  Divider,
  Avatar,
  Menu,
  MenuItem,
  Chip,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  Build as BuildIcon,
  History as HistoryIcon,
  Assessment as ReportsIcon,
  Settings as SettingsIcon,
  AccountCircle as AccountIcon,
  Logout as LogoutIcon,
  Email as EmailIcon,
  AdminPanelSettings as AdminIcon,
  PhoneAndroid as MobileIcon,
  Person,
  MenuBook as DocumentationIcon,
  Biotech as TechnologyIcon,
  Speed as SpeedIcon,
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import NotificationDropdown from './NotificationDropdown';
import { NotificationBell } from '../Notifications/NotificationBell';
import authService from '../../services/authService';
import ibbLogo from '../../assets/ibb-logo.jpg';
import { usePermissions } from '../../contexts/PermissionContext';

const drawerWidth = 280;

interface MainLayoutProps {
  children: React.ReactNode;
}

const MainLayout: React.FC<MainLayoutProps> = ({ children }) => {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [userMenuAnchor, setUserMenuAnchor] = useState<null | HTMLElement>(null);
  const navigate = useNavigate();
  const location = useLocation();
  const user = authService.getUser();
  const {
    canAccessWebScanning,
    canAccessMobileScanning,
    canAccessAdminPanel,
    hasPermission
  } = usePermissions();

  // Dinamik menü - İzinlere göre filtrele
  const allMenuItems = [
    {
      text: 'Ana Sayfa',
      icon: <DashboardIcon />,
      path: '/dashboard',
      requiredPermission: null // Herkes görebilir
    },
    {
      text: 'Admin Panel',
      icon: <AdminIcon />,
      path: '/admin',
      requiredPermission: 'admin' // Özel kontrol
    },
    {
      text: 'Otomatik Tarama',
      icon: <SecurityIcon />,
      path: '/automated-scan',
      requiredPermission: 'web' // Web tarama izni
    },
    {
      text: 'Manuel Tarama',
      icon: <BuildIcon />,
      path: '/manual-scan',
      requiredPermission: 'web' // Web tarama izni
    },
    {
      text: 'Mobil Tarama',
      icon: <MobileIcon />,
      path: '/mobile-scan',
      requiredPermission: 'mobile' // Mobil tarama izni
    },
    {
      text: 'Teknoloji Tarayıcısı',
      icon: <TechnologyIcon />,
      path: '/technology-scanner',
      requiredPermission: 'web' // Web tarama izni
    },
    {
      text: 'Lighthouse Tarayıcı',
      icon: <SpeedIcon />,
      path: '/lighthouse',
      requiredPermission: 'web' // Web tarama izni
    },
    {
      text: 'Trivy Tarayıcı',
      icon: <SecurityIcon />,
      path: '/trivy',
      requiredPermission: 'web' // Security scanning
    },
    {
      text: 'Tarama Geçmişi',
      icon: <HistoryIcon />,
      path: '/scan-history',
      requiredPermission: null // Herkes kendi geçmişini görebilir
    },
    {
      text: 'Raporlar',
      icon: <ReportsIcon />,
      path: '/reports',
      requiredPermission: null // Herkes kendi raporlarını görebilir
    },
    {
      text: 'Email Tercihleri',
      icon: <EmailIcon />,
      path: '/email-preferences',
      requiredPermission: null // Herkes kendi email tercihlerini yönetebilir
    },
    {
      text: 'Uygulama Kılavuzu',
      icon: <DocumentationIcon />,
      path: '/application-guide',
      requiredPermission: null // Herkes dokümantasyona erişebilir
    },
  ];

  // İzinlere göre menü öğelerini filtrele
  const menuItems = allMenuItems.filter(item => {
    if (item.requiredPermission === null) return true; // Genel erişim
    if (item.requiredPermission === 'admin') return canAccessAdminPanel();
    if (item.requiredPermission === 'web') return canAccessWebScanning();
    if (item.requiredPermission === 'mobile') return canAccessMobileScanning();
    return false;
  });
  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  const handleUserMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setUserMenuAnchor(event.currentTarget);
  };

  const handleUserMenuClose = () => {
    setUserMenuAnchor(null);
  };

  const handleLogout = async () => {
    try {
      await authService.logout();
      navigate('/login');
    } catch (error) {
      navigate('/login'); // Force navigation even if logout fails
    }
    handleUserMenuClose();
  };

  const handleProfile = () => {
    navigate('/profile');
    handleUserMenuClose();
  };

  const drawer = (
    <Box sx={{ height: '100%', backgroundColor: '#1e1e1e' }}>      <Toolbar sx={{ borderBottom: '1px solid #333' }}>
      <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
        <Box
          component="img"
          src={ibbLogo}
          alt="İBB Logo"
          sx={{
            height: 40,
            width: 'auto',
            mr: 2,
            borderRadius: 1,
          }}
        />
        <Typography variant="h6" noWrap component="div" color="primary" sx={{ fontWeight: 600 }}>
          İBB Güvenlik
        </Typography>
      </Box>
    </Toolbar>

      {/* Geçici olarak kapatıldı - Status göstergeleri */}
      {/*
<Box sx={{ p: 2 }}>
  <ZapStatusIndicator />
  <Box sx={{ mt: 2 }}>
    <MobSFStatusIndicator />
  </Box>
</Box>
*/}

      <Divider sx={{ borderColor: '#333' }} />
      <List sx={{ pt: 1 }}>
        {menuItems.map((item) => (
          <ListItem key={item.text} disablePadding>
            <ListItemButton
              onClick={() => navigate(item.path)}
              selected={location.pathname === item.path}
              sx={{
                mx: 1,
                mb: 0.5,
                borderRadius: 1,
                '&.Mui-selected': {
                  backgroundColor: 'rgba(25, 118, 210, 0.12)',
                  borderLeft: '3px solid #1976d2',
                  '&:hover': {
                    backgroundColor: 'rgba(25, 118, 210, 0.2)',
                  },
                },
                '&:hover': {
                  backgroundColor: 'rgba(255, 255, 255, 0.05)',
                },
              }}
            >
              <ListItemIcon sx={{ color: location.pathname === item.path ? '#1976d2' : 'inherit' }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.text}
                sx={{
                  '& .MuiListItemText-primary': {
                    fontSize: '0.9rem',
                    fontWeight: location.pathname === item.path ? 600 : 400,
                  }
                }}
              />
            </ListItemButton>
          </ListItem>
        ))}
      </List>
    </Box>
  );

  return (
    <Box sx={{ display: 'flex' }}>
      <AppBar
        position="fixed"
        sx={{
          width: { sm: `calc(100% - ${drawerWidth}px)` },
          ml: { sm: `${drawerWidth}px` },
          boxShadow: 'none',
          borderBottom: '1px solid #333',
        }}
      >        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{ mr: 2, display: { sm: 'none' } }}
          >
            <MenuIcon />
          </IconButton>

          <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1 }}>
            İBB Güvenlik Test Platformu
          </Typography>
          <NotificationBell />

          {/* User Info */}
          {user && (
            <Box sx={{ display: 'flex', alignItems: 'center', ml: 2 }}>
              <Box sx={{ mr: 2, display: { xs: 'none', sm: 'block' } }}>
                <Typography variant="body2" sx={{ lineHeight: 1.2 }}>
                  {user.firstName} {user.lastName}
                </Typography>
                <Chip
                  label={user.role === 'admin' ? 'Admin' : 'Developer'}
                  size="small"
                  color={user.role === 'admin' ? 'primary' : 'secondary'}
                  sx={{ height: 18, fontSize: '0.7rem' }}
                />
              </Box>

              <Tooltip title="Hesap">
                <IconButton
                  color="inherit"
                  onClick={handleUserMenuOpen}
                  sx={{ p: 0 }}
                >
                  <Avatar sx={{ bgcolor: user.role === 'admin' ? 'primary.main' : 'secondary.main' }}>
                    {user.firstName.charAt(0)}{user.lastName.charAt(0)}
                  </Avatar>
                </IconButton>
              </Tooltip>
            </Box>
          )}
        </Toolbar>
      </AppBar>

      <Box
        component="nav"
        sx={{ width: { sm: drawerWidth }, flexShrink: { sm: 0 } }}
      >
        <Drawer
          variant="temporary"
          open={mobileOpen}
          onClose={handleDrawerToggle}
          ModalProps={{
            keepMounted: true,
          }}
          sx={{
            display: { xs: 'block', sm: 'none' },
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: drawerWidth,
            },
          }}
        >
          {drawer}
        </Drawer>
        <Drawer
          variant="permanent"
          sx={{
            display: { xs: 'none', sm: 'block' },
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: drawerWidth,
            },
          }}
          open
        >
          {drawer}
        </Drawer>
      </Box>

      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          width: { sm: `calc(100% - ${drawerWidth}px)` },
          minHeight: '100vh',
          backgroundColor: '#121212',
        }}
      >        <Toolbar />
        {children}
      </Box>

      {/* User Menu */}
      <Menu
        anchorEl={userMenuAnchor}
        open={Boolean(userMenuAnchor)}
        onClose={handleUserMenuClose}
        onClick={handleUserMenuClose}
        PaperProps={{
          elevation: 0,
          sx: {
            overflow: 'visible',
            filter: 'drop-shadow(0px 2px 8px rgba(0,0,0,0.32))',
            mt: 1.5,
            '& .MuiAvatar-root': {
              width: 32,
              height: 32,
              ml: -0.5,
              mr: 1,
            },
            '&:before': {
              content: '""',
              display: 'block',
              position: 'absolute',
              top: 0,
              right: 14,
              width: 10,
              height: 10,
              bgcolor: 'background.paper',
              transform: 'translateY(-50%) rotate(45deg)',
              zIndex: 0,
            },
          },
        }}
        transformOrigin={{ horizontal: 'right', vertical: 'top' }}
        anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
      >
        {user && (
          <Box sx={{ px: 2, py: 1, borderBottom: '1px solid', borderColor: 'divider' }}>
            <Typography variant="subtitle2">
              {user.firstName} {user.lastName}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {user.email}
            </Typography>
          </Box>
        )}

        <MenuItem onClick={handleProfile}>
          <AccountIcon sx={{ mr: 2 }} />
          Profil
        </MenuItem>

        <MenuItem onClick={handleLogout}>
          <LogoutIcon sx={{ mr: 2 }} />
          Çıkış Yap
        </MenuItem>
      </Menu>
    </Box>
  );
};

export default MainLayout;
