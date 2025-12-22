import React, { useState } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Typography,
  Chip,
  IconButton,
  Tooltip,
  Alert,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Divider
} from '@mui/material';
import {
  Download as DownloadIcon,
  Preview as PreviewIcon,
  Assessment as ReportIcon,
  Security as SecurityIcon,
  BugReport as BugIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  OpenInNew as OpenIcon
} from '@mui/icons-material';
import scanService from '../../services/scanService';

interface ModernReportGeneratorProps {
  scanId: string;
  scanData?: any;
}

interface ReportStats {
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  scanDuration: number;
}

const ModernReportGenerator: React.FC<ModernReportGeneratorProps> = ({ scanId, scanData }) => {
  const [loading, setLoading] = useState(false);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<ReportStats | null>(null);

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return '#dc2626';
      case 'high': return '#ea580c';
      case 'medium': return '#d97706';
      case 'low': return '#65a30d';
      case 'info': return '#0369a1';
      default: return '#6b7280';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return <ErrorIcon sx={{ color: '#dc2626' }} />;
      case 'high': return <WarningIcon sx={{ color: '#ea580c' }} />;
      case 'medium': return <WarningIcon sx={{ color: '#d97706' }} />;
      case 'low': return <InfoIcon sx={{ color: '#65a30d' }} />;
      case 'info': return <InfoIcon sx={{ color: '#0369a1' }} />;
      default: return <BugIcon sx={{ color: '#6b7280' }} />;
    }
  };

  const fetchReportData = async () => {
    try {
      const data = await scanService.getReportData(scanId);
      setStats(data.statistics);
      return data;
    } catch (error) {
      console.error('Error fetching report data:', error);
      setError('Failed to fetch report data');
      throw error;
    }
  };

  const downloadModernReport = async () => {
    setLoading(true);
    setError(null);
    
    try {
      await scanService.downloadModernReport(scanId);
    } catch (error) {
      console.error('Error downloading modern report:', error);
      setError('Failed to download modern report');
    } finally {
      setLoading(false);
    }
  };

  const previewReport = async () => {
    setLoading(true);
    setError(null);
    
    try {
      // Open preview in new window
      const previewUrl = `/api/reports/preview/${scanId}`;
      const newWindow = window.open(previewUrl, '_blank', 'width=1200,height=800,scrollbars=yes,resizable=yes');
      
      if (!newWindow) {
        throw new Error('Popup blocked. Please allow popups for this site.');
      }
      
    } catch (error) {
      console.error('Error previewing report:', error);
      setError('Failed to preview report');
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(() => {
    if (scanId) {
      fetchReportData().catch(console.error);
    }
  }, [scanId]);

  const formatDuration = (milliseconds: number) => {
    if (!milliseconds) return 'N/A';
    
    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) {
      return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  };

  return (
    <Card sx={{ mt: 2 }}>
      <CardContent>
        <Box display="flex" alignItems="center" mb={2}>
          <ReportIcon sx={{ mr: 1, color: 'primary.main' }} />
          <Typography variant="h6" component="h3">
            Modern Security Report
          </Typography>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {stats && (
          <Box mb={3}>
            <Typography variant="subtitle2" color="text.secondary" gutterBottom>
              Report Overview
            </Typography>
            <Box display="flex" gap={2} flexWrap="wrap">
              <Box textAlign="center" p={1} bgcolor="background.paper" borderRadius={1} border={1} borderColor="divider" flex="1" minWidth="120px">
                <Typography variant="h5" color="error.main" fontWeight="bold">
                  {stats.totalVulnerabilities}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Total Issues
                </Typography>
              </Box>
              <Box textAlign="center" p={1} bgcolor="background.paper" borderRadius={1} border={1} borderColor="divider" flex="1" minWidth="120px">
                <Typography variant="h5" sx={{ color: getSeverityColor('critical') }} fontWeight="bold">
                  {stats.criticalCount}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Critical
                </Typography>
              </Box>
              <Box textAlign="center" p={1} bgcolor="background.paper" borderRadius={1} border={1} borderColor="divider" flex="1" minWidth="120px">
                <Typography variant="h5" sx={{ color: getSeverityColor('high') }} fontWeight="bold">
                  {stats.highCount}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  High
                </Typography>
              </Box>
              <Box textAlign="center" p={1} bgcolor="background.paper" borderRadius={1} border={1} borderColor="divider" flex="1" minWidth="120px">
                <Typography variant="h5" sx={{ color: getSeverityColor('medium') }} fontWeight="bold">
                  {stats.mediumCount}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Medium
                </Typography>
              </Box>
            </Box>

            <Box mt={2} display="flex" gap={1} flexWrap="wrap">
              <Chip
                icon={getSeverityIcon('critical')}
                label={`${stats.criticalCount} Critical`}
                size="small"
                sx={{ backgroundColor: alpha(getSeverityColor('critical'), 0.1) }}
              />
              <Chip
                icon={getSeverityIcon('high')}
                label={`${stats.highCount} High`}
                size="small"
                sx={{ backgroundColor: alpha(getSeverityColor('high'), 0.1) }}
              />
              <Chip
                icon={getSeverityIcon('medium')}
                label={`${stats.mediumCount} Medium`}
                size="small"
                sx={{ backgroundColor: alpha(getSeverityColor('medium'), 0.1) }}
              />
              <Chip
                icon={getSeverityIcon('low')}
                label={`${stats.lowCount} Low`}
                size="small"
                sx={{ backgroundColor: alpha(getSeverityColor('low'), 0.1) }}
              />
              <Chip
                icon={getSeverityIcon('info')}
                label={`${stats.infoCount} Info`}
                size="small"
                sx={{ backgroundColor: alpha(getSeverityColor('info'), 0.1) }}
              />
            </Box>

            {stats.scanDuration > 0 && (
              <Box mt={2}>
                <Typography variant="body2" color="text.secondary">
                  <strong>Scan Duration:</strong> {formatDuration(stats.scanDuration)}
                </Typography>
              </Box>
            )}
          </Box>
        )}

        <Divider sx={{ my: 2 }} />

        <Typography variant="body2" color="text.secondary" paragraph>
          Generate a comprehensive, modern HTML security report with detailed vulnerability analysis, 
          interactive features, and professional styling. Perfect for stakeholders and compliance requirements.
        </Typography>

        <Box display="flex" gap={1} flexWrap="wrap">
          <Button
            variant="contained"
            startIcon={loading ? <CircularProgress size={16} /> : <DownloadIcon />}
            onClick={downloadModernReport}
            disabled={loading}
            sx={{
              background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
              '&:hover': {
                background: 'linear-gradient(135deg, #5a6fd8 0%, #6a4190 100%)',
              }
            }}
          >
            {loading ? 'Generating...' : 'Download Modern Report'}
          </Button>

          <Button
            variant="outlined"
            startIcon={<PreviewIcon />}
            onClick={previewReport}
            disabled={loading}
          >
            Preview Report
          </Button>
        </Box>

        <Box mt={2}>
          <Typography variant="caption" color="text.secondary">
            📊 Features: Interactive vulnerability details • Modern design • Mobile responsive • 
            Severity-based color coding • Executive summary • Technical details
          </Typography>
        </Box>
      </CardContent>
    </Card>
  );
};

// Helper function for alpha colors
function alpha(color: string, value: number): string {
  return `${color}${Math.round(value * 255).toString(16).padStart(2, '0')}`;
}

export default ModernReportGenerator;
