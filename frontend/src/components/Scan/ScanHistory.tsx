import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Card,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Tooltip,
  Button,
  CircularProgress,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import {
  Visibility as VisibilityIcon,
  Delete as DeleteIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  CheckCircle as CheckCircleIcon,
  Assessment as AssessmentIcon,
} from '@mui/icons-material';
import scanService, { ScanHistoryItem } from '../../services/scanService';
import socketService from '../../services/socketService';
import ScanProgressBar from './ScanProgressBar';

interface Vulnerability {
  id: string;
  name: string;
  description?: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'CRITICAL';
  confidence?: string;
  solution?: string;
  reference?: string;
  url?: string;
  param?: string;
  attack?: string;
  evidence?: string;
}

const ScanHistory: React.FC = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedScan, setSelectedScan] = useState<ScanHistoryItem | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [expandedProgressScans, setExpandedProgressScans] = useState<Set<string>>(new Set());
  const [autoRefresh] = useState(true); // Keep for useEffect dependency

  useEffect(() => {
    loadScans();
    
    // Listen for scan completion events
    const handleScanCompleted = () => {
      setTimeout(() => {
        loadScans(); // Refresh after a small delay to ensure database is updated
      }, 2000);
    };
    
    window.addEventListener('scanCompleted', handleScanCompleted);
    
    // Listen for socket events for real-time updates
    const handleWorkflowComplete = (data: any) => {
      setTimeout(() => {
        loadScans();
      }, 1000);
    };
    
    const handleScanUpdate = (data: any) => {
      const status = data.status?.toString().toLowerCase();
      if (status === 'completed' || status === 'failed' || status === 'stopped') {
        setTimeout(() => {
          loadScans();
        }, 1000);
      }
    };
    
    const handleWorkflowUpdate = (data: any) => {
      const status = data.status?.toString().toUpperCase();
      if (status === 'COMPLETED' || status === 'FAILED' || status === 'STOPPED') {
        setTimeout(() => {
          loadScans();
        }, 1500);
      }
    };
    
    const handleScanStatusChanged = (data: any) => {
      console.log(`   Scan ID: ${data.scanId}, New Status: ${data.status}`);
      // Immediately refresh to get updated status
      loadScans();
    };
    
    socketService.on('workflowComplete', handleWorkflowComplete);
    socketService.on('workflowUpdate', handleWorkflowUpdate);
    socketService.on('scanUpdate', handleScanUpdate);
    socketService.on('scanStatusChanged', handleScanStatusChanged);
    
    return () => {
      window.removeEventListener('scanCompleted', handleScanCompleted);
      socketService.off('workflowComplete', handleWorkflowComplete);
      socketService.off('workflowUpdate', handleWorkflowUpdate);
      socketService.off('scanUpdate', handleScanUpdate);
      socketService.off('scanStatusChanged', handleScanStatusChanged);
    };
  }, []);

  // Auto-refresh running scans every 5 seconds
  useEffect(() => {
    if (!autoRefresh) return;

    const hasRunningScans = scans.some(scan => scan.status === 'RUNNING');
    
    // Only set interval if there are running scans
    if (!hasRunningScans) {
      return; // Don't set interval if no running scans
    }

    console.log('🔄 Setting up auto-refresh (found running scans)');
    const interval = setInterval(() => {
      const stillHasRunningScans = scans.some(scan => scan.status === 'RUNNING');
      if (stillHasRunningScans) {
        loadScans();
      } else {
      }
    }, 5000); // 5 seconds

    return () => {
      clearInterval(interval);
    };
  }, [scans, autoRefresh]);

  const loadScans = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await scanService.getScans();
      setScans(data);
    } catch (err) {
      console.error('🔴 Error loading scans:', err);
      
      // Daha detaylı hata mesajı
      let errorMessage = 'Failed to load scans';
      
      if (err instanceof Error) {
        if (err.message.includes('Network Error') || err.message.includes('ERR_CONNECTION_REFUSED')) {
          errorMessage = 'Backend server is not running. Please start the backend service with Docker.';
        } else if (err.message.includes('timeout')) {
          errorMessage = 'Connection timeout. Backend server may be slow or not responding.';
        } else {
          errorMessage = err.message;
        }
      }
      
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };
  const handleDeleteScan = async (scanId: string) => {
    try {
      await scanService.deleteScan(scanId);
      setScans(scans.filter(scan => scan.id !== scanId));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete scan');
    }
  };

  const handleGenerateReport = async (scanId: string, format: 'html' | 'json' = 'html') => {
    try {
      const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';
      const response = await fetch(`${API_BASE_URL}/api/scans/${scanId}/report/download?format=${format}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (!response.ok) {
        throw new Error('Failed to generate report');
      }

      // Create download link
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      
      // Extract filename from Content-Disposition header or create default
      const contentDisposition = response.headers.get('Content-Disposition');
      let filename = `IBB_GuvenlikTaramasi_${new Date().toISOString().split('T')[0]}.${format}`;
      
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="(.+)"/);
        if (filenameMatch) {
          filename = filenameMatch[1];
        }
      }
      
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      
      // Cleanup
      window.URL.revokeObjectURL(url);
      document.body.removeChild(link);
      
    } catch (err) {
      console.error('❌ Generate report failed:', err);
      setError(err instanceof Error ? err.message : 'Failed to generate report');
    }
  };

  const handleUpdateScanStatus = async (scanId: string, newStatus: string) => {
    try {
      const response = await fetch(`/api/scans/${scanId}/status`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ status: newStatus })
      });
      
      if (response.ok) {
        // Refresh scan list
        loadScans();
      } else {
        throw new Error('Failed to update scan status');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update scan status');
    }
  };

  const handleViewDetails = (scan: ScanHistoryItem) => {
    setSelectedScan(scan);
    setDetailsOpen(true);
  };

  const toggleProgressView = (scanId: string) => {
    const newExpanded = new Set(expandedProgressScans);
    if (newExpanded.has(scanId)) {
      newExpanded.delete(scanId);
    } else {
      newExpanded.add(scanId);
    }
    setExpandedProgressScans(newExpanded);
  };

  const handleProgressComplete = (scanId: string) => {
    // Remove from expanded progress and refresh scans
    const newExpanded = new Set(expandedProgressScans);
    newExpanded.delete(scanId);
    setExpandedProgressScans(newExpanded);
    loadScans();
  };

  const handleProgressError = (error: string) => {
    setError(error);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'COMPLETED': return 'success';
      case 'RUNNING': return 'primary';
      case 'FAILED': return 'error';
      case 'CANCELLED': return 'default';
      case 'PAUSED': return 'warning';
      default: return 'default';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress size={48} />
        <Typography variant="h6" sx={{ ml: 2 }}>
          Loading Scan History...
        </Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h4" gutterBottom>
            Scan History
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            View and manage all your security scans
          </Typography>
        </Box>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={loadScans}
        >
          Refresh
        </Button>
      </Box>

      {error && (
        <Alert 
          severity="error" 
          sx={{ mb: 3 }}
          action={
            <Button 
              color="inherit" 
              size="small" 
              onClick={loadScans}
            >
              RETRY
            </Button>
          }
        >
          <Typography variant="subtitle2" sx={{ fontWeight: 'bold', mb: 1 }}>
            Network Error
          </Typography>
          <Typography variant="body2">
            {error}
          </Typography>
          {error.includes('Backend server is not running') && (
            <Box sx={{ mt: 2, p: 2, bgcolor: 'rgba(0,0,0,0.1)', borderRadius: 1 }}>
              <Typography variant="caption" sx={{ fontFamily: 'monospace', display: 'block' }}>
                💡 To start the backend server:
              </Typography>
              <Typography variant="caption" sx={{ fontFamily: 'monospace', display: 'block', mt: 1 }}>
                1. Open Docker Desktop
              </Typography>
              <Typography variant="caption" sx={{ fontFamily: 'monospace', display: 'block' }}>
                2. Run: <code style={{ background: '#000', padding: '2px 6px', borderRadius: '3px' }}>docker-compose up -d</code>
              </Typography>
              <Typography variant="caption" sx={{ fontFamily: 'monospace', display: 'block' }}>
                3. Wait 30 seconds for services to start
              </Typography>
              <Typography variant="caption" sx={{ fontFamily: 'monospace', display: 'block' }}>
                4. Click RETRY button above
              </Typography>
            </Box>
          )}
        </Alert>
      )}

      <Card>
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Name / Target</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Started</TableCell>
                <TableCell>Duration</TableCell>
                <TableCell>Vulnerabilities</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {scans.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    <Typography variant="body2" color="text.secondary" sx={{ py: 4 }}>
                      No scans found. Start your first scan!
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                scans.map((scan) => (
                  <React.Fragment key={scan.id}>
                    <TableRow hover>
                      <TableCell>
                        <Box>
                          <Typography variant="subtitle2">
                            {scan.name || 'Unnamed Scan'}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {scan.targetUrl}
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={scan.scanType} 
                          size="small" 
                          variant="outlined" 
                        />
                      </TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center" gap={1}>
                          <Chip 
                            label={scan.status} 
                            size="small" 
                            color={getStatusColor(scan.status) as any}
                          />
                          {scan.status === 'RUNNING' && (
                            <Button
                              size="small"
                              variant="outlined"
                              onClick={() => toggleProgressView(scan.id)}
                            >
                              {expandedProgressScans.has(scan.id) ? 'Hide' : 'Show'} Progress
                            </Button>
                          )}
                        </Box>
                      </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {new Date(scan.startedAt).toLocaleDateString()}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {new Date(scan.startedAt).toLocaleTimeString()}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      {scan.completedAt ? (
                        <Typography variant="body2">
                          {Math.round(
                            (new Date(scan.completedAt).getTime() - 
                             new Date(scan.startedAt).getTime()) / (1000 * 60)
                          )} min
                        </Typography>
                      ) : scan.status === 'RUNNING' ? (
                        <Typography variant="body2" color="primary">
                          Running...
                        </Typography>
                      ) : (
                        <Typography variant="body2" color="text.secondary">
                          -
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell>
                      <Box display="flex" gap={0.5} flexWrap="wrap">
                        {scan.vulnerabilities && scan.vulnerabilities.length > 0 ? (
                          (() => {
                            const counts = scan.vulnerabilities.reduce((acc: Record<string, number>, vuln: Vulnerability) => {
                              acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
                              return acc;
                            }, {} as Record<string, number>);
                            
                            return Object.entries(counts).map(([severity, count]) => (
                              <Chip
                                key={severity}
                                label={`${severity}: ${count}`}
                                size="small"
                                color={getSeverityColor(severity) as any}
                              />
                            ));
                          })()
                        ) : (
                          <Typography variant="caption" color="text.secondary">
                            No data
                          </Typography>
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Box display="flex">
                        <Tooltip title="View Details">
                          <IconButton 
                            size="small" 
                            onClick={() => handleViewDetails(scan)}
                          >
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                        
                        {scan.status === 'RUNNING' && (
                          <Tooltip title="Stop Scan">
                            <IconButton size="small">
                              <StopIcon />
                            </IconButton>
                          </Tooltip>
                        )}
                        
                        {scan.status === 'RUNNING' && (
                          <Tooltip title="Mark as Completed (Test)">
                            <IconButton 
                              size="small" 
                              color="warning"
                              onClick={() => handleUpdateScanStatus(scan.id, 'COMPLETED')}
                            >
                              <CheckCircleIcon />
                            </IconButton>
                          </Tooltip>
                        )}
                        
                        {scan.status === 'COMPLETED' && (
                          <>
                            <Button
                              variant="contained"
                              color="success"
                              size="small"
                              startIcon={<AssessmentIcon />}
                              onClick={() => navigate(`/reports?scanId=${scan.id}`)}
                              sx={{ 
                                mr: 1, 
                                fontSize: '0.7rem',
                                padding: '4px 8px',
                                minWidth: 'auto'
                              }}
                            >
                              VIEW REPORT
                            </Button>
                            <Button
                              variant="outlined"
                              color="primary"
                              size="small"
                              startIcon={<SecurityIcon />}
                              onClick={() => handleGenerateReport(scan.id, 'html')}
                              sx={{ 
                                mr: 1, 
                                fontSize: '0.7rem',
                                padding: '4px 8px',
                                minWidth: 'auto'
                              }}
                            >
                              DOWNLOAD
                            </Button>
                          </>
                        )}
                        
                        <Tooltip title="Delete Scan">
                          <IconButton 
                            size="small" 
                            color="error"
                            onClick={() => handleDeleteScan(scan.id)}
                          >
                            <DeleteIcon />
                          </IconButton>
                        </Tooltip>                      </Box>
                    </TableCell>
                  </TableRow>
                  
                  {/* Progress Row for Running Scans */}
                  {scan.status === 'RUNNING' && expandedProgressScans.has(scan.id) && (
                    <TableRow>
                      <TableCell colSpan={7} sx={{ py: 0, borderBottom: 'none' }}>
                        <Box sx={{ py: 2 }}>
                          <ScanProgressBar
                            scanId={scan.id}
                            onComplete={() => handleProgressComplete(scan.id)}
                            onError={handleProgressError}
                          />
                        </Box>
                      </TableCell>
                    </TableRow>
                  )}
                  </React.Fragment>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Card>

      {/* Scan Details Dialog */}
      <Dialog
        open={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Scan Details
        </DialogTitle>
        <DialogContent>
          {selectedScan && (
            <Box>
              <Typography variant="h6" gutterBottom>
                {selectedScan.name || 'Unnamed Scan'}
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Target: {selectedScan.targetUrl}
              </Typography>
              
              <Box display="flex" gap={1} mb={2}>
                <Chip label={selectedScan.scanType} variant="outlined" />
                <Chip 
                  label={selectedScan.status} 
                  color={getStatusColor(selectedScan.status) as any}
                />
              </Box>

              <Typography variant="subtitle2" gutterBottom>
                Timeline
              </Typography>
              <Typography variant="body2">
                Started: {new Date(selectedScan.startedAt).toLocaleString()}
              </Typography>
              {selectedScan.completedAt && (
                <Typography variant="body2">
                  Completed: {new Date(selectedScan.completedAt).toLocaleString()}
                </Typography>
              )}

              {selectedScan.vulnerabilities && selectedScan.vulnerabilities.length > 0 && (
                <Box mt={3}>
                  <Typography variant="subtitle2" gutterBottom>
                    Vulnerabilities Found
                  </Typography>
                  {selectedScan.vulnerabilities.slice(0, 5).map((vuln: Vulnerability, index: number) => (
                    <Box key={index} mb={1}>
                      <Box display="flex" alignItems="center" gap={1}>
                        <Chip 
                          label={vuln.severity} 
                          size="small"
                          color={getSeverityColor(vuln.severity) as any}
                        />
                        <Typography variant="body2">
                          {vuln.name}
                        </Typography>
                      </Box>
                      {vuln.url && (
                        <Typography variant="caption" color="text.secondary">
                          URL: {vuln.url}
                        </Typography>
                      )}
                    </Box>
                  ))}
                  {selectedScan.vulnerabilities.length > 5 && (
                    <Typography variant="caption" color="text.secondary">
                      ... and {selectedScan.vulnerabilities.length - 5} more
                    </Typography>
                  )}
                </Box>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailsOpen(false)}>
            Close
          </Button>
          {selectedScan?.status === 'COMPLETED' && (
            <Button 
              variant="contained" 
              startIcon={<SecurityIcon />}
              onClick={() => handleGenerateReport(selectedScan.id, 'html')}
            >
              GENERATE REPORT
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ScanHistory;
