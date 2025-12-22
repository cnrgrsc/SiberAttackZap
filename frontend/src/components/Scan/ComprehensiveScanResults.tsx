import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Button,
  IconButton,
  Alert,
  LinearProgress,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Timeline as TimelineIcon,
  Download as DownloadIcon,
  Visibility as VisibilityIcon,
  BugReport as BugReportIcon,
  Speed as SpeedIcon,
  Search as SearchIcon,
  Language as LanguageIcon,
  NetworkCheck as NetworkCheckIcon,
  OpenInNew as OpenInNewIcon,
} from '@mui/icons-material';

interface ScanPhase {
  name: string;
  status: 'completed' | 'running' | 'pending' | 'failed';
  progress: number;
  urlsFound: number;
  alertsFound: number;
  duration: number;
  startTime?: string;
  endTime?: string;
}

interface Alert {
  id: string;
  name: string;
  risk: 'High' | 'Medium' | 'Low' | 'Informational';
  confidence: 'High' | 'Medium' | 'Low';
  url: string;
  description: string;
  solution?: string;
  reference?: string;
  param?: string;
  attack?: string;
  evidence?: string;
  phase: string;
}

interface ComprehensiveScanResultsProps {
  scanId: string;
  onClose: () => void;
}

const ComprehensiveScanResults: React.FC<ComprehensiveScanResultsProps> = ({
  scanId,
  onClose,
}) => {
  const [phases, setPhases] = useState<ScanPhase[]>([
    {
      name: 'Passive Analysis',
      status: 'completed',
      progress: 100,
      urlsFound: 0,
      alertsFound: 3,
      duration: 15000,
      startTime: '2024-01-15T10:00:00Z',
      endTime: '2024-01-15T10:00:15Z',
    },
    {
      name: 'Spider Crawl',
      status: 'completed',
      progress: 100,
      urlsFound: 45,
      alertsFound: 2,
      duration: 120000,
      startTime: '2024-01-15T10:00:15Z',
      endTime: '2024-01-15T10:02:15Z',
    },
    {
      name: 'AJAX Spider',
      status: 'completed',
      progress: 100,
      urlsFound: 23,
      alertsFound: 1,
      duration: 90000,
      startTime: '2024-01-15T10:02:15Z',
      endTime: '2024-01-15T10:03:45Z',
    },
    {
      name: 'Forced Browse',
      status: 'completed',
      progress: 100,
      urlsFound: 12,
      alertsFound: 0,
      duration: 180000,
      startTime: '2024-01-15T10:03:45Z',
      endTime: '2024-01-15T10:06:45Z',
    },
    {
      name: 'Active Vulnerability Testing',
      status: 'completed',
      progress: 100,
      urlsFound: 0,
      alertsFound: 8,
      duration: 450000,
      startTime: '2024-01-15T10:06:45Z',
      endTime: '2024-01-15T10:14:15Z',
    },
  ]);

  const [alerts, setAlerts] = useState<Alert[]>([]);

  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [urlsDiscovered, setUrlsDiscovered] = useState<string[]>([]);

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'High': return 'error';
      case 'Medium': return 'warning';
      case 'Low': return 'info';
      case 'Informational': return 'default';
      default: return 'default';
    }
  };

  const getPhaseIcon = (phaseName: string) => {
    switch (phaseName) {
      case 'Passive Analysis': return <InfoIcon />;
      case 'Spider Crawl': return <SearchIcon />;
      case 'AJAX Spider': return <LanguageIcon />;
      case 'Forced Browse': return <NetworkCheckIcon />;
      case 'Active Vulnerability Testing': return <SecurityIcon />;
      default: return <SpeedIcon />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'success';
      case 'running': return 'primary';
      case 'failed': return 'error';
      case 'pending': return 'default';
      default: return 'default';
    }
  };

  const formatDuration = (ms: number): string => {
    const minutes = Math.floor(ms / 60000);
    const seconds = Math.floor((ms % 60000) / 1000);
    return `${minutes}m ${seconds}s`;
  };

  const totalStats = phases.reduce(
    (acc, phase) => ({
      urlsFound: acc.urlsFound + phase.urlsFound,
      alertsFound: acc.alertsFound + phase.alertsFound,
      duration: acc.duration + phase.duration,
    }),
    { urlsFound: 0, alertsFound: 0, duration: 0 }
  );

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">
          Comprehensive Scan Results
        </Typography>
        <Button variant="outlined" onClick={onClose}>
          Close
        </Button>
      </Box>      {/* Summary Cards */}
      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 3, mb: 4 }}>
        <Card>
          <CardContent sx={{ textAlign: 'center' }}>
            <Typography variant="h4" color="primary">
              {totalStats.urlsFound}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              URLs Discovered
            </Typography>
          </CardContent>
        </Card>
        <Card>
          <CardContent sx={{ textAlign: 'center' }}>
            <Typography variant="h4" color="error">
              {totalStats.alertsFound}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Vulnerabilities Found
            </Typography>
          </CardContent>
        </Card>
        <Card>
          <CardContent sx={{ textAlign: 'center' }}>
            <Typography variant="h4" color="success">
              {phases.filter(p => p.status === 'completed').length}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Phases Completed
            </Typography>
          </CardContent>
        </Card>
        <Card>
          <CardContent sx={{ textAlign: 'center' }}>
            <Typography variant="h4" color="info">
              {formatDuration(totalStats.duration)}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Total Duration
            </Typography>
          </CardContent>
        </Card>
      </Box>

      {/* Phase Timeline */}
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Scan Phase Timeline
          </Typography>
          <List>
            {phases.map((phase, index) => (
              <ListItem key={index} sx={{ border: 1, borderColor: 'divider', borderRadius: 1, mb: 1 }}>
                <ListItemIcon>
                  {getPhaseIcon(phase.name)}
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="subtitle1">{phase.name}</Typography>
                      <Chip 
                        label={phase.status} 
                        color={getStatusColor(phase.status) as any}
                        size="small"
                      />
                    </Box>
                  }
                  secondary={
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        URLs: {phase.urlsFound} | Alerts: {phase.alertsFound} | Duration: {formatDuration(phase.duration)}
                      </Typography>
                      <LinearProgress 
                        variant="determinate" 
                        value={phase.progress} 
                        sx={{ mt: 1, height: 6, borderRadius: 3 }}
                      />
                    </Box>
                  }
                />
              </ListItem>
            ))}
          </List>
        </CardContent>
      </Card>

      {/* Vulnerabilities Table */}
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">
              Vulnerabilities Found ({alerts.length})
            </Typography>
            <Button 
              variant="outlined" 
              startIcon={<DownloadIcon />}
              size="small"
            >
              Export Report
            </Button>
          </Box>
          
          <TableContainer component={Paper} variant="outlined">
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Vulnerability</TableCell>
                  <TableCell>Risk</TableCell>
                  <TableCell>Confidence</TableCell>
                  <TableCell>URL</TableCell>
                  <TableCell>Phase</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {alerts.map((alert) => (
                  <TableRow key={alert.id} hover>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <BugReportIcon color="error" fontSize="small" />
                        <Typography variant="body2">{alert.name}</Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={alert.risk} 
                        color={getRiskColor(alert.risk) as any}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={alert.confidence} 
                        variant="outlined"
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      <Tooltip title={alert.url}>
                        <Typography 
                          variant="body2" 
                          sx={{ 
                            maxWidth: 200, 
                            overflow: 'hidden', 
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap'
                          }}
                        >
                          {alert.url}
                        </Typography>
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {alert.phase}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <IconButton 
                        size="small" 
                        onClick={() => setSelectedAlert(alert)}
                        color="primary"
                      >
                        <VisibilityIcon />
                      </IconButton>
                      <IconButton 
                        size="small" 
                        onClick={() => window.open(alert.url, '_blank')}
                        color="default"
                      >
                        <OpenInNewIcon />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>

      {/* Vulnerability Details Dialog */}
      <Dialog 
        open={!!selectedAlert} 
        onClose={() => setSelectedAlert(null)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <SecurityIcon color="error" />
            <Typography variant="h6">{selectedAlert?.name}</Typography>
            <Chip 
              label={selectedAlert?.risk} 
              color={getRiskColor(selectedAlert?.risk || '') as any}
              size="small"
            />
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedAlert && (
            <Box>
              <Typography variant="body1" paragraph>
                <strong>Description:</strong> {selectedAlert.description}
              </Typography>
              
              <Typography variant="body1" paragraph>
                <strong>URL:</strong> <code>{selectedAlert.url}</code>
              </Typography>
              
              {selectedAlert.param && (
                <Typography variant="body1" paragraph>
                  <strong>Parameter:</strong> <code>{selectedAlert.param}</code>
                </Typography>
              )}
              
              {selectedAlert.attack && (
                <Typography variant="body1" paragraph>
                  <strong>Attack:</strong> <code>{selectedAlert.attack}</code>
                </Typography>
              )}
              
              {selectedAlert.evidence && (
                <Typography variant="body1" paragraph>
                  <strong>Evidence:</strong> <code>{selectedAlert.evidence}</code>
                </Typography>
              )}
              
              {selectedAlert.solution && (
                <Alert severity="info" sx={{ mt: 2 }}>
                  <Typography variant="body2">
                    <strong>Solution:</strong> {selectedAlert.solution}
                  </Typography>
                </Alert>
              )}
              
              <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                <strong>Detected in Phase:</strong> {selectedAlert.phase}<br/>
                <strong>Confidence:</strong> {selectedAlert.confidence}
              </Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSelectedAlert(null)}>Close</Button>
          <Button 
            variant="contained" 
            onClick={() => selectedAlert && window.open(selectedAlert.url, '_blank')}
          >
            Open URL
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ComprehensiveScanResults;
