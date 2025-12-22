import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Grid,
  LinearProgress,
  Alert,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Tooltip,
  Fab,
  Snackbar,
} from '@mui/material';
import {
  CloudUpload as UploadIcon,
  Android as AndroidIcon,
  Apple as AppleIcon,
  Security as SecurityIcon,
  GetApp as DownloadIcon,
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
  Add as AddIcon,
  Visibility as ViewIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
} from '@mui/icons-material';
import { mobsfService, MobileScanResult, MobileScanStatistics } from '../../services/mobsfService';

interface MobileScanPanelProps {}

const MobileScanPanel: React.FC<MobileScanPanelProps> = () => {
  const [loading, setLoading] = useState(false);
  const [statistics, setStatistics] = useState<MobileScanStatistics | null>(null);
  const [scans, setScans] = useState<MobileScanResult[]>([]);
  const [uploadDialogOpen, setUploadDialogOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [scanName, setScanName] = useState('');
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('');
  const [platformFilter, setPlatformFilter] = useState('');

  useEffect(() => {
    loadData();
  }, [page, statusFilter, platformFilter]);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);

      const [statsData, scansData] = await Promise.allSettled([
        mobsfService.getStatistics(),
        mobsfService.getMobileScans({
          page,
          limit: 10,
          status: statusFilter || undefined,
          platform: platformFilter || undefined,
        }),
      ]);

      if (statsData.status === 'fulfilled') {
        setStatistics(statsData.value);
      }

      if (scansData.status === 'fulfilled') {
        setScans(scansData.value.scans);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load mobile scan data');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const allowedTypes = ['.apk', '.aab', '.ipa', '.zip'];
      const fileExtension = '.' + file.name.split('.').pop()?.toLowerCase();
      
      if (allowedTypes.includes(fileExtension)) {
        setSelectedFile(file);
        setScanName(`Mobile Scan - ${file.name}`);
      } else {
        setError('Invalid file type. Only APK, AAB, IPA, and ZIP files are allowed.');
      }
    }
  };

  const handleUploadAndScan = async () => {
    if (!selectedFile) {
      setError('Please select a file to upload');
      return;
    }

    try {
      setUploading(true);
      setError(null);

      const result = await mobsfService.uploadAndScan(selectedFile, scanName);
      setSuccess(`Upload successful! Scan started: ${result.fileName}`);
      
      // Reset form
      setSelectedFile(null);
      setScanName('');
      setUploadDialogOpen(false);
      
      // Reload data
      loadData();
    } catch (err: any) {
      setError(err.message || 'Failed to upload and scan file');
    } finally {
      setUploading(false);
    }
  };

  const handleDeleteScan = async (scanId: string) => {
    if (!window.confirm('Are you sure you want to delete this scan?')) {
      return;
    }

    try {
      await mobsfService.deleteScan(scanId);
      setSuccess('Scan deleted successfully');
      loadData();
    } catch (err: any) {
      setError(err.message || 'Failed to delete scan');
    }
  };

  const handleDownloadReport = async (scanId: string) => {
    try {
      await mobsfService.downloadPDFReport(scanId);
      setSuccess('Report downloaded successfully');
    } catch (err: any) {
      setError(err.message || 'Failed to download report');
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f57c00';
      case 'medium': return '#fbc02d';
      case 'low': return '#388e3c';
      case 'info': return '#1976d2';
      default: return '#1976d2';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'COMPLETED': return 'success';
      case 'RUNNING': return 'warning';
      case 'FAILED': return 'error';
      case 'CANCELLED': return 'default';
      default: return 'default';
    }
  };

  const getPlatformIcon = (platform: string) => {
    return platform === 'ANDROID' ? <AndroidIcon /> : <AppleIcon />;
  };

  if (loading && !statistics) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <LinearProgress sx={{ width: '100%' }} />
        <Typography variant="h6" sx={{ ml: 2 }}>
          Loading Mobile Security Dashboard...
        </Typography>
      </Box>
    );
  }

  return (
    <Box>
      {/* Statistics Cards */}
      {statistics && (
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid size={{ xs: 12, md: 3 }}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Total Mobile Scans
                </Typography>
                <Typography variant="h4" component="div">
                  {statistics.totalScans}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {statistics.runningScans} currently running
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid size={{ xs: 12, md: 3 }}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Android Apps
                </Typography>
                <Typography variant="h4" component="div" sx={{ display: 'flex', alignItems: 'center' }}>
                  <AndroidIcon sx={{ mr: 1, color: '#a4c639' }} />
                  {statistics.platformStats.android}
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid size={{ xs: 12, md: 3 }}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  iOS Apps
                </Typography>
                <Typography variant="h4" component="div" sx={{ display: 'flex', alignItems: 'center' }}>
                  <AppleIcon sx={{ mr: 1, color: '#000' }} />
                  {statistics.platformStats.ios}
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid size={{ xs: 12, md: 3 }}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Critical Issues
                </Typography>
                <Typography variant="h4" component="div" sx={{ color: getSeverityColor('critical') }}>
                  {statistics.vulnerabilityStats.critical}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Controls */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5">Mobile Application Scans</Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="contained"
            startIcon={<UploadIcon />}
            onClick={() => setUploadDialogOpen(true)}
          >
            Upload App
          </Button>
          <IconButton onClick={loadData}>
            <RefreshIcon />
          </IconButton>
        </Box>
      </Box>

      {/* Filters */}
      <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel>Status</InputLabel>
          <Select
            value={statusFilter}
            label="Status"
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <MenuItem value="">All</MenuItem>
            <MenuItem value="RUNNING">Running</MenuItem>
            <MenuItem value="COMPLETED">Completed</MenuItem>
            <MenuItem value="FAILED">Failed</MenuItem>
          </Select>
        </FormControl>

        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel>Platform</InputLabel>
          <Select
            value={platformFilter}
            label="Platform"
            onChange={(e) => setPlatformFilter(e.target.value)}
          >
            <MenuItem value="">All</MenuItem>
            <MenuItem value="ANDROID">Android</MenuItem>
            <MenuItem value="IOS">iOS</MenuItem>
          </Select>
        </FormControl>
      </Box>

      {/* Scans Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>App Name</TableCell>
              <TableCell>Platform</TableCell>
              <TableCell>Version</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Security Score</TableCell>
              <TableCell>Vulnerabilities</TableCell>
              <TableCell>Date</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {scans.map((scan) => (
              <TableRow key={scan.id}>
                <TableCell>
                  <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    {scan.mobileAppScan && getPlatformIcon(scan.mobileAppScan.platform)}
                    <Box sx={{ ml: 1 }}>
                      <Typography variant="subtitle2">
                        {scan.mobileAppScan?.appName || scan.name}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {scan.mobileAppScan?.packageName}
                      </Typography>
                    </Box>
                  </Box>
                </TableCell>
                <TableCell>
                  <Chip
                    label={scan.mobileAppScan?.platform || 'Unknown'}
                    size="small"
                    variant="outlined"
                  />
                </TableCell>
                <TableCell>{scan.mobileAppScan?.version || '-'}</TableCell>
                <TableCell>
                  <Chip
                    label={scan.status}
                    size="small"
                    color={getStatusColor(scan.status) as any}
                  />
                </TableCell>
                <TableCell>
                  {scan.mobileAppScan?.securityScore ? (
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <Typography variant="body2" sx={{ mr: 1 }}>
                        {scan.mobileAppScan.securityScore}/100
                      </Typography>
                      <LinearProgress
                        variant="determinate"
                        value={scan.mobileAppScan.securityScore}
                        sx={{ width: 50, height: 4 }}
                      />
                    </Box>
                  ) : (
                    '-'
                  )}
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', gap: 0.5 }}>
                    {scan.vulnerabilityCounts.critical > 0 && (
                      <Chip
                        label={scan.vulnerabilityCounts.critical}
                        size="small"
                        sx={{ 
                          backgroundColor: getSeverityColor('critical'), 
                          color: 'white',
                          fontSize: '0.7rem',
                          height: 20,
                        }}
                      />
                    )}
                    {scan.vulnerabilityCounts.high > 0 && (
                      <Chip
                        label={scan.vulnerabilityCounts.high}
                        size="small"
                        sx={{ 
                          backgroundColor: getSeverityColor('high'), 
                          color: 'white',
                          fontSize: '0.7rem',
                          height: 20,
                        }}
                      />
                    )}
                    {scan.vulnerabilityCounts.medium > 0 && (
                      <Chip
                        label={scan.vulnerabilityCounts.medium}
                        size="small"
                        sx={{ 
                          backgroundColor: getSeverityColor('medium'), 
                          color: 'black',
                          fontSize: '0.7rem',
                          height: 20,
                        }}
                      />
                    )}
                  </Box>
                </TableCell>
                <TableCell>
                  <Typography variant="caption">
                    {new Date(scan.startedAt).toLocaleDateString()}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <Tooltip title="View Details">
                      <IconButton size="small">
                        <ViewIcon />
                      </IconButton>
                    </Tooltip>
                    {scan.status === 'COMPLETED' && (
                      <Tooltip title="Download Report">
                        <IconButton 
                          size="small"
                          onClick={() => handleDownloadReport(scan.id)}
                        >
                          <DownloadIcon />
                        </IconButton>
                      </Tooltip>
                    )}
                    <Tooltip title="Delete">
                      <IconButton 
                        size="small"
                        onClick={() => handleDeleteScan(scan.id)}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {scans.length === 0 && !loading && (
        <Box sx={{ textAlign: 'center', py: 4 }}>
          <SecurityIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
          <Typography variant="h6" color="text.secondary">
            No mobile scans found
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Upload your first mobile application to get started
          </Typography>
          <Button
            variant="contained"
            startIcon={<UploadIcon />}
            onClick={() => setUploadDialogOpen(true)}
          >
            Upload App
          </Button>
        </Box>
      )}

      {/* Upload Dialog */}
      <Dialog open={uploadDialogOpen} onClose={() => setUploadDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Upload Mobile Application</DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2 }}>
            <TextField
              label="Scan Name"
              value={scanName}
              onChange={(e) => setScanName(e.target.value)}
              fullWidth
              sx={{ mb: 3 }}
            />
            
            <input
              type="file"
              accept=".apk,.aab,.ipa,.zip"
              onChange={handleFileUpload}
              style={{ display: 'none' }}
              id="file-upload"
            />
            <label htmlFor="file-upload">
              <Button
                variant="outlined"
                component="span"
                startIcon={<UploadIcon />}
                fullWidth
                sx={{ mb: 2 }}
              >
                Select File (APK, AAB, IPA, ZIP)
              </Button>
            </label>
            
            {selectedFile && (
              <Alert severity="info" sx={{ mb: 2 }}>
                Selected: {selectedFile.name} ({(selectedFile.size / 1024 / 1024).toFixed(2)} MB)
              </Alert>
            )}
            
            <Alert severity="info">
              <Typography variant="body2">
                Supported formats:
                <br />• APK - Android Application Package
                <br />• AAB - Android App Bundle  
                <br />• IPA - iOS App Store Package
                <br />• ZIP - Compressed source code
              </Typography>
            </Alert>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setUploadDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={handleUploadAndScan}
            variant="contained"
            disabled={!selectedFile || uploading}
          >
            {uploading ? 'Uploading...' : 'Upload & Scan'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbars */}
      <Snackbar
        open={!!error}
        autoHideDuration={6000}
        onClose={() => setError(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity="error" onClose={() => setError(null)}>
          {error}
        </Alert>
      </Snackbar>

      <Snackbar
        open={!!success}
        autoHideDuration={4000}
        onClose={() => setSuccess(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity="success" onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default MobileScanPanel;
