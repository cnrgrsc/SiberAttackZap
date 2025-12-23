import React, { useState, useEffect, useMemo } from 'react';
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
  TextField,
  InputAdornment,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Collapse,
  Stack,
  Divider,
  Badge,
  alpha,
} from '@mui/material';
import {
  Visibility as VisibilityIcon,
  Delete as DeleteIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  CheckCircle as CheckCircleIcon,
  Assessment as AssessmentIcon,
  Search as SearchIcon,
  FilterList as FilterListIcon,
  Clear as ClearIcon,
  KeyboardArrowDown as KeyboardArrowDownIcon,
  KeyboardArrowUp as KeyboardArrowUpIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Schedule as ScheduleIcon,
  BugReport as BugReportIcon,
  Speed as SpeedIcon,
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

// Filter state interface
interface FilterState {
  searchQuery: string;
  scanType: string;
  status: string;
  dateFrom: string;
  dateTo: string;
  sortBy: string;
  sortOrder: 'asc' | 'desc';
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

  // Filter states
  const [showFilters, setShowFilters] = useState(true);
  const [filters, setFilters] = useState<FilterState>({
    searchQuery: '',
    scanType: 'ALL',
    status: 'ALL',
    dateFrom: '',
    dateTo: '',
    sortBy: 'startedAt',
    sortOrder: 'desc',
  });

  // Get unique scan types from data
  const scanTypes = useMemo(() => {
    const types = new Set(scans.map((scan) => scan.scanType));
    return ['ALL', ...Array.from(types)];
  }, [scans]);

  // Filter and sort scans
  const filteredScans = useMemo(() => {
    let result = [...scans];

    // Search filter
    if (filters.searchQuery) {
      const query = filters.searchQuery.toLowerCase();
      result = result.filter(
        (scan) =>
          scan.name?.toLowerCase().includes(query) ||
          scan.targetUrl?.toLowerCase().includes(query)
      );
    }

    // Type filter
    if (filters.scanType !== 'ALL') {
      result = result.filter((scan) => scan.scanType === filters.scanType);
    }

    // Status filter
    if (filters.status !== 'ALL') {
      result = result.filter((scan) => scan.status === filters.status);
    }

    // Date from filter
    if (filters.dateFrom) {
      const fromDate = new Date(filters.dateFrom);
      result = result.filter((scan) => new Date(scan.startedAt) >= fromDate);
    }

    // Date to filter
    if (filters.dateTo) {
      const toDate = new Date(filters.dateTo);
      toDate.setHours(23, 59, 59, 999);
      result = result.filter((scan) => new Date(scan.startedAt) <= toDate);
    }

    // Sort
    result.sort((a, b) => {
      let compareA: any, compareB: any;

      switch (filters.sortBy) {
        case 'startedAt':
          compareA = new Date(a.startedAt).getTime();
          compareB = new Date(b.startedAt).getTime();
          break;
        case 'name':
          compareA = a.name?.toLowerCase() || '';
          compareB = b.name?.toLowerCase() || '';
          break;
        case 'status':
          compareA = a.status;
          compareB = b.status;
          break;
        case 'vulnerabilities':
          compareA = a.vulnerabilities?.length || 0;
          compareB = b.vulnerabilities?.length || 0;
          break;
        default:
          compareA = new Date(a.startedAt).getTime();
          compareB = new Date(b.startedAt).getTime();
      }

      if (filters.sortOrder === 'asc') {
        return compareA > compareB ? 1 : -1;
      } else {
        return compareA < compareB ? 1 : -1;
      }
    });

    return result;
  }, [scans, filters]);

  // Count active filters
  const activeFiltersCount = useMemo(() => {
    let count = 0;
    if (filters.searchQuery) count++;
    if (filters.scanType !== 'ALL') count++;
    if (filters.status !== 'ALL') count++;
    if (filters.dateFrom) count++;
    if (filters.dateTo) count++;
    return count;
  }, [filters]);

  // Clear all filters
  const clearFilters = () => {
    setFilters({
      searchQuery: '',
      scanType: 'ALL',
      status: 'ALL',
      dateFrom: '',
      dateTo: '',
      sortBy: 'startedAt',
      sortOrder: 'desc',
    });
  };

  // Quick filter handlers
  const handleQuickFilter = (type: string) => {
    if (type === 'running') {
      setFilters((prev) => ({ ...prev, status: 'RUNNING' }));
    } else if (type === 'completed') {
      setFilters((prev) => ({ ...prev, status: 'COMPLETED' }));
    } else if (type === 'failed') {
      setFilters((prev) => ({ ...prev, status: 'FAILED' }));
    } else if (type === 'today') {
      const today = new Date().toISOString().split('T')[0];
      setFilters((prev) => ({ ...prev, dateFrom: today, dateTo: today }));
    } else if (type === 'week') {
      const today = new Date();
      const weekAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
      setFilters((prev) => ({
        ...prev,
        dateFrom: weekAgo.toISOString().split('T')[0],
        dateTo: today.toISOString().split('T')[0],
      }));
    }
  };

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
      {/* Header Section */}
      <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h4" gutterBottom sx={{
            fontWeight: 700,
            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
          }}>
            Scan History
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            View and manage all your security scans
          </Typography>
        </Box>
        <Stack direction="row" spacing={2}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={loadScans}
            sx={{
              borderRadius: 2,
              borderColor: 'rgba(102, 126, 234, 0.5)',
              '&:hover': {
                borderColor: '#667eea',
                background: 'rgba(102, 126, 234, 0.1)',
              },
            }}
          >
            Refresh
          </Button>
        </Stack>
      </Box>

      {error && (
        <Alert
          severity="error"
          sx={{ mb: 3, borderRadius: 2 }}
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
        </Alert>
      )}

      {/* Filter Panel */}
      <Card
        sx={{
          mb: 3,
          borderRadius: 3,
          background: (theme) =>
            theme.palette.mode === 'dark'
              ? 'linear-gradient(135deg, rgba(30, 35, 50, 0.9) 0%, rgba(20, 25, 35, 0.95) 100%)'
              : 'linear-gradient(135deg, rgba(255, 255, 255, 0.9) 0%, rgba(248, 249, 254, 0.95) 100%)',
          backdropFilter: 'blur(20px)',
          border: (theme) =>
            `1px solid ${alpha(theme.palette.primary.main, 0.15)}`,
          boxShadow: (theme) =>
            theme.palette.mode === 'dark'
              ? '0 8px 32px rgba(0, 0, 0, 0.3)'
              : '0 8px 32px rgba(102, 126, 234, 0.1)',
        }}
      >
        {/* Filter Header */}
        <Box
          sx={{
            p: 2,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            borderBottom: (theme) =>
              `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            cursor: 'pointer',
            transition: 'all 0.2s ease',
            '&:hover': {
              background: (theme) => alpha(theme.palette.primary.main, 0.05),
            },
          }}
          onClick={() => setShowFilters(!showFilters)}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Badge
              badgeContent={activeFiltersCount}
              color="primary"
              sx={{
                '& .MuiBadge-badge': {
                  background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                },
              }}
            >
              <FilterListIcon sx={{ color: 'primary.main' }} />
            </Badge>
            <Typography variant="subtitle1" fontWeight={600}>
              Filters & Search
            </Typography>
            {activeFiltersCount > 0 && (
              <Chip
                label={`${activeFiltersCount} active`}
                size="small"
                sx={{
                  background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                  color: 'white',
                  fontWeight: 500,
                }}
              />
            )}
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {activeFiltersCount > 0 && (
              <Button
                size="small"
                startIcon={<ClearIcon />}
                onClick={(e) => {
                  e.stopPropagation();
                  clearFilters();
                }}
                sx={{
                  color: 'text.secondary',
                  '&:hover': {
                    color: 'error.main',
                  },
                }}
              >
                Clear All
              </Button>
            )}
            <IconButton size="small">
              {showFilters ? <KeyboardArrowUpIcon /> : <KeyboardArrowDownIcon />}
            </IconButton>
          </Box>
        </Box>

        {/* Filter Content */}
        <Collapse in={showFilters}>
          <Box sx={{ p: 3 }}>
            {/* Search and Primary Filters */}
            <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ mb: 3 }}>
              {/* Search Input */}
              <TextField
                placeholder="Search by name or URL..."
                value={filters.searchQuery}
                onChange={(e) =>
                  setFilters((prev) => ({ ...prev, searchQuery: e.target.value }))
                }
                size="small"
                sx={{
                  flex: 2,
                  '& .MuiOutlinedInput-root': {
                    borderRadius: 2,
                    background: (theme) => alpha(theme.palette.background.paper, 0.8),
                    '&:hover': {
                      '& .MuiOutlinedInput-notchedOutline': {
                        borderColor: 'primary.main',
                      },
                    },
                  },
                }}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon sx={{ color: 'text.secondary' }} />
                    </InputAdornment>
                  ),
                  endAdornment: filters.searchQuery && (
                    <InputAdornment position="end">
                      <IconButton
                        size="small"
                        onClick={() =>
                          setFilters((prev) => ({ ...prev, searchQuery: '' }))
                        }
                      >
                        <ClearIcon fontSize="small" />
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
              />

              {/* Scan Type Filter */}
              <FormControl size="small" sx={{ minWidth: 150 }}>
                <InputLabel>Scan Type</InputLabel>
                <Select
                  value={filters.scanType}
                  label="Scan Type"
                  onChange={(e) =>
                    setFilters((prev) => ({ ...prev, scanType: e.target.value }))
                  }
                  sx={{
                    borderRadius: 2,
                    '& .MuiOutlinedInput-notchedOutline': {
                      borderColor: filters.scanType !== 'ALL' ? 'primary.main' : undefined,
                    },
                  }}
                >
                  {scanTypes.map((type) => (
                    <MenuItem key={type} value={type}>
                      {type === 'ALL' ? 'All Types' : type}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              {/* Status Filter */}
              <FormControl size="small" sx={{ minWidth: 150 }}>
                <InputLabel>Status</InputLabel>
                <Select
                  value={filters.status}
                  label="Status"
                  onChange={(e) =>
                    setFilters((prev) => ({ ...prev, status: e.target.value }))
                  }
                  sx={{
                    borderRadius: 2,
                    '& .MuiOutlinedInput-notchedOutline': {
                      borderColor: filters.status !== 'ALL' ? 'primary.main' : undefined,
                    },
                  }}
                >
                  <MenuItem value="ALL">All Statuses</MenuItem>
                  <MenuItem value="RUNNING">
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <CircularProgress size={14} />
                      Running
                    </Box>
                  </MenuItem>
                  <MenuItem value="COMPLETED">
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <CheckCircleIcon sx={{ color: 'success.main', fontSize: 18 }} />
                      Completed
                    </Box>
                  </MenuItem>
                  <MenuItem value="FAILED">
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <SecurityIcon sx={{ color: 'error.main', fontSize: 18 }} />
                      Failed
                    </Box>
                  </MenuItem>
                </Select>
              </FormControl>
            </Stack>

            <Divider sx={{ my: 2, opacity: 0.5 }} />

            {/* Date Range and Sort */}
            <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems="center">
              {/* Date From */}
              <TextField
                label="From Date"
                type="date"
                size="small"
                value={filters.dateFrom}
                onChange={(e) =>
                  setFilters((prev) => ({ ...prev, dateFrom: e.target.value }))
                }
                InputLabelProps={{ shrink: true }}
                sx={{
                  minWidth: 160,
                  '& .MuiOutlinedInput-root': {
                    borderRadius: 2,
                  },
                }}
              />

              {/* Date To */}
              <TextField
                label="To Date"
                type="date"
                size="small"
                value={filters.dateTo}
                onChange={(e) =>
                  setFilters((prev) => ({ ...prev, dateTo: e.target.value }))
                }
                InputLabelProps={{ shrink: true }}
                sx={{
                  minWidth: 160,
                  '& .MuiOutlinedInput-root': {
                    borderRadius: 2,
                  },
                }}
              />

              <Box sx={{ flex: 1 }} />

              {/* Sort By */}
              <FormControl size="small" sx={{ minWidth: 150 }}>
                <InputLabel>Sort By</InputLabel>
                <Select
                  value={filters.sortBy}
                  label="Sort By"
                  onChange={(e) =>
                    setFilters((prev) => ({ ...prev, sortBy: e.target.value }))
                  }
                  sx={{ borderRadius: 2 }}
                >
                  <MenuItem value="startedAt">
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <ScheduleIcon fontSize="small" />
                      Date
                    </Box>
                  </MenuItem>
                  <MenuItem value="name">
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <SearchIcon fontSize="small" />
                      Name
                    </Box>
                  </MenuItem>
                  <MenuItem value="status">Status</MenuItem>
                  <MenuItem value="vulnerabilities">
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <BugReportIcon fontSize="small" />
                      Vulnerabilities
                    </Box>
                  </MenuItem>
                </Select>
              </FormControl>

              {/* Sort Order Toggle */}
              <Tooltip title={filters.sortOrder === 'desc' ? 'Descending' : 'Ascending'}>
                <IconButton
                  onClick={() =>
                    setFilters((prev) => ({
                      ...prev,
                      sortOrder: prev.sortOrder === 'asc' ? 'desc' : 'asc',
                    }))
                  }
                  sx={{
                    border: (theme) => `1px solid ${alpha(theme.palette.primary.main, 0.3)}`,
                    borderRadius: 2,
                    '&:hover': {
                      background: (theme) => alpha(theme.palette.primary.main, 0.1),
                    },
                  }}
                >
                  {filters.sortOrder === 'desc' ? (
                    <TrendingDownIcon />
                  ) : (
                    <TrendingUpIcon />
                  )}
                </IconButton>
              </Tooltip>
            </Stack>

            <Divider sx={{ my: 2, opacity: 0.5 }} />

            {/* Quick Filter Chips */}
            <Box>
              <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: 'block' }}>
                Quick Filters
              </Typography>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                <Chip
                  icon={<ScheduleIcon />}
                  label="Today"
                  size="small"
                  variant={
                    filters.dateFrom === new Date().toISOString().split('T')[0] &&
                      filters.dateTo === new Date().toISOString().split('T')[0]
                      ? 'filled'
                      : 'outlined'
                  }
                  onClick={() => handleQuickFilter('today')}
                  sx={{
                    borderRadius: 2,
                    transition: 'all 0.2s ease',
                    '&:hover': {
                      transform: 'translateY(-2px)',
                      boxShadow: (theme) => `0 4px 12px ${alpha(theme.palette.primary.main, 0.3)}`,
                    },
                  }}
                />
                <Chip
                  icon={<SpeedIcon />}
                  label="Last 7 Days"
                  size="small"
                  variant="outlined"
                  onClick={() => handleQuickFilter('week')}
                  sx={{
                    borderRadius: 2,
                    transition: 'all 0.2s ease',
                    '&:hover': {
                      transform: 'translateY(-2px)',
                      boxShadow: (theme) => `0 4px 12px ${alpha(theme.palette.primary.main, 0.3)}`,
                    },
                  }}
                />
                <Chip
                  label="Running"
                  size="small"
                  color={filters.status === 'RUNNING' ? 'primary' : 'default'}
                  variant={filters.status === 'RUNNING' ? 'filled' : 'outlined'}
                  onClick={() => handleQuickFilter('running')}
                  sx={{
                    borderRadius: 2,
                    transition: 'all 0.2s ease',
                    '&:hover': {
                      transform: 'translateY(-2px)',
                    },
                  }}
                />
                <Chip
                  label="Completed"
                  size="small"
                  color={filters.status === 'COMPLETED' ? 'success' : 'default'}
                  variant={filters.status === 'COMPLETED' ? 'filled' : 'outlined'}
                  onClick={() => handleQuickFilter('completed')}
                  sx={{
                    borderRadius: 2,
                    transition: 'all 0.2s ease',
                    '&:hover': {
                      transform: 'translateY(-2px)',
                    },
                  }}
                />
                <Chip
                  label="Failed"
                  size="small"
                  color={filters.status === 'FAILED' ? 'error' : 'default'}
                  variant={filters.status === 'FAILED' ? 'filled' : 'outlined'}
                  onClick={() => handleQuickFilter('failed')}
                  sx={{
                    borderRadius: 2,
                    transition: 'all 0.2s ease',
                    '&:hover': {
                      transform: 'translateY(-2px)',
                    },
                  }}
                />
              </Stack>
            </Box>
          </Box>
        </Collapse>

        {/* Results Summary */}
        <Box
          sx={{
            px: 3,
            py: 1.5,
            background: (theme) =>
              theme.palette.mode === 'dark'
                ? 'rgba(0, 0, 0, 0.2)'
                : 'rgba(0, 0, 0, 0.02)',
            borderTop: (theme) => `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <Typography variant="body2" color="text.secondary">
            Showing <strong>{filteredScans.length}</strong> of <strong>{scans.length}</strong> scans
          </Typography>
          {activeFiltersCount > 0 && (
            <Typography variant="caption" color="primary">
              {activeFiltersCount} filter{activeFiltersCount > 1 ? 's' : ''} applied
            </Typography>
          )}
        </Box>
      </Card>

      {/* Scan Table */}
      <Card sx={{ borderRadius: 3, overflow: 'hidden' }}>
        <TableContainer component={Paper} sx={{
          background: 'transparent',
          boxShadow: 'none',
        }}>
          <Table>
            <TableHead sx={{
              background: (theme) =>
                theme.palette.mode === 'dark'
                  ? 'rgba(102, 126, 234, 0.1)'
                  : 'rgba(102, 126, 234, 0.05)',
            }}>
              <TableRow>
                <TableCell sx={{ fontWeight: 600 }}>Name / Target</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>Type</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>Status</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>Started</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>Duration</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>Vulnerabilities</TableCell>
                <TableCell sx={{ fontWeight: 600 }}>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredScans.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    <Box sx={{ py: 6, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                      <SecurityIcon sx={{ fontSize: 48, color: 'text.secondary', opacity: 0.5 }} />
                      <Typography variant="body1" color="text.secondary">
                        {activeFiltersCount > 0
                          ? 'No scans match your current filters'
                          : 'No scans found. Start your first scan!'}
                      </Typography>
                      {activeFiltersCount > 0 && (
                        <Button
                          variant="outlined"
                          size="small"
                          onClick={clearFilters}
                          startIcon={<ClearIcon />}
                        >
                          Clear Filters
                        </Button>
                      )}
                    </Box>
                  </TableCell>
                </TableRow>
              ) : (
                filteredScans.map((scan) => (
                  <React.Fragment key={scan.id}>
                    <TableRow
                      hover
                      sx={{
                        transition: 'all 0.2s ease',
                        '&:hover': {
                          background: (theme) => alpha(theme.palette.primary.main, 0.05),
                        },
                      }}
                    >
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
