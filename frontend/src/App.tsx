import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline } from '@mui/material';
import MainLayout from './components/Layout/MainLayout';
import Dashboard from './components/Dashboard/Dashboard';
import AutomatedScan from './components/Scan/AutomatedScan';
import ManualScan from './components/Scan/ManualScan';
import MobileScan from './components/Scan/MobileScan';
import TechnologyScanner from './components/Scan/TechnologyScanner';
import LighthouseScanner from './components/Scan/LighthouseScanner';
import TrivyScanner from './components/Scan/TrivyScanner';
import ScanHistory from './components/Scan/ScanHistory';
import Reports from './components/Reports/Reports';
import Settings from './components/Settings/Settings';
import EmailPreferences from './components/Settings/EmailPreferences';
import Login from './components/Auth/Login';
import AdminPanel from './components/Admin/AdminPanel';
import { UserProfile } from './components/Profile/UserProfile';
import ProtectedRoute from './components/Auth/ProtectedRoute';
import RoleBasedRedirect from './components/Auth/RoleBasedRedirect';
import { PermissionProvider } from './contexts/PermissionContext';
import { ProtectedRoute as NewProtectedRoute } from './components/ProtectedRoute';
import ApplicationGuide from './components/Documentation/ApplicationGuide';
import { NotificationProvider } from './contexts/NotificationContext';

// Dark theme similar to ZAP Proxy
const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#1976d2',
      light: '#42a5f5',
      dark: '#1565c0',
    },
    secondary: {
      main: '#ff9800',
      light: '#ffb74d',
      dark: '#f57c00',
    },
    background: {
      default: '#121212',
      paper: '#1e1e1e',
    },
    text: {
      primary: '#ffffff',
      secondary: '#b0b0b0',
    },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
    h4: {
      fontWeight: 600,
    },
    h6: {
      fontWeight: 500,
    },
  },
  components: {
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: '#1e1e1e',
          borderBottom: '1px solid #333',
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundColor: '#1e1e1e',
          borderRight: '1px solid #333',
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundColor: '#1e1e1e',
          border: '1px solid #333',
        },
      },
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <NotificationProvider>
        <PermissionProvider>
          <Router>
            <Routes>
              {/* Public routes */}
              <Route path="/login" element={<Login />} />

              {/* Root redirect with role-based navigation */}
              <Route path="/" element={<RoleBasedRedirect />} />

              {/* Protected routes */}
              <Route
                path="/dashboard"
                element={
                  <ProtectedRoute>
                    <MainLayout>
                      <Dashboard />
                    </MainLayout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/automated-scan"
                element={
                  <NewProtectedRoute requiredPermissions={['SCAN_WEB_CREATE', 'SCAN_WEB_VIEW']}>
                    <MainLayout>
                      <AutomatedScan />
                    </MainLayout>
                  </NewProtectedRoute>
                }
              />
              <Route
                path="/manual-scan"
                element={
                  <NewProtectedRoute requiredPermissions={['SCAN_WEB_CREATE', 'SCAN_WEB_VIEW']}>
                    <MainLayout>
                      <ManualScan />
                    </MainLayout>
                  </NewProtectedRoute>
                }
              />
              <Route
                path="/mobile-scan"
                element={
                  <NewProtectedRoute requiredPermissions={['SCAN_MOBILE_CREATE', 'SCAN_MOBILE_VIEW']}>
                    <MainLayout>
                      <MobileScan />
                    </MainLayout>
                  </NewProtectedRoute>
                }
              />
              <Route
                path="/technology-scanner"
                element={
                  <ProtectedRoute>
                    <MainLayout>
                      <TechnologyScanner />
                    </MainLayout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/lighthouse"
                element={
                  <ProtectedRoute>
                    <MainLayout>
                      <LighthouseScanner />
                    </MainLayout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/trivy"
                element={
                  <ProtectedRoute>
                    <MainLayout>
                      <TrivyScanner />
                    </MainLayout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/scan-history"
                element={
                  <ProtectedRoute>
                    <MainLayout>
                      <ScanHistory />
                    </MainLayout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/reports"
                element={
                  <ProtectedRoute>
                    <MainLayout>
                      <Reports />
                    </MainLayout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/settings"
                element={
                  <ProtectedRoute>
                    <MainLayout>
                      <Settings />
                    </MainLayout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/email-preferences"
                element={
                  <ProtectedRoute>
                    <MainLayout>
                      <EmailPreferences />
                    </MainLayout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/application-guide"
                element={
                  <ProtectedRoute>
                    <MainLayout>
                      <ApplicationGuide />
                    </MainLayout>
                  </ProtectedRoute>
                }
              />
              <Route
                path="/profile"
                element={
                  <ProtectedRoute>
                    <MainLayout>
                      <UserProfile />
                    </MainLayout>
                  </ProtectedRoute>
                }
              />

              {/* Admin routes */}
              <Route
                path="/admin"
                element={
                  <NewProtectedRoute requiredPermissions={['USER_READ', 'ROLE_READ', 'GROUP_READ', 'SYSTEM_SETTINGS_VIEW']}>
                    <MainLayout>
                      <AdminPanel />
                    </MainLayout>
                  </NewProtectedRoute>
                }
              />

              {/* Fallback */}
              <Route path="*" element={<RoleBasedRedirect />} />
            </Routes>
          </Router>
        </PermissionProvider>
      </NotificationProvider>
    </ThemeProvider>
  );
}

export default App;
