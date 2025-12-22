import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel
} from '@mui/material';
import {
  Visibility as ViewIcon,
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
  BugReport as BugReportIcon,
  Link as LinkIcon,
  GetApp as DownloadIcon
} from '@mui/icons-material';
import ComprehensiveScanMonitor from './ComprehensiveScanMonitor';
import socketService from '../../services/socketService';

interface ScanRecord {
  id: string;
  name: string;
  targetUrl: string;
  scanType: string;
  status: string;
  startedAt: string;
  completedAt?: string;
  vulnerabilities?: any[];
  scanUrls?: any[];
  _count: {
    vulnerabilities: number;
    scanUrls: number;
  };
}

const ScanHistoryPanel: React.FC = () => {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState<ScanRecord | null>(null);
  const [showScanDetails, setShowScanDetails] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filter and search states
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('Tümü');
  const [sortOrder, setSortOrder] = useState('En Son Taramalar');

  // Load scan history
  const loadScanHistory = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/zap/scans');

      if (response.ok) {
        const result = await response.json();
        setScans(result.data || []);
      } else {
        setError('Failed to load scan history');
      }
    } catch (error) {
      console.error('Error loading scan history:', error);
      setError('Error connecting to server');
    } finally {
      setLoading(false);
    }
  };

  // Delete scan
  const deleteScan = async (scanId: string) => {
    try {
      const response = await fetch(`/api/zap/scans/${scanId}`, {
        method: 'DELETE'
      });

      if (response.ok) {
        setScans(prev => prev.filter(scan => scan.id !== scanId));
      } else {
        setError('Failed to delete scan');
      }
    } catch (error) {
      console.error('Error deleting scan:', error);
      setError('Error deleting scan');
    }
  };

  // View scan details
  const viewScanDetails = (scan: ScanRecord) => {
    setSelectedScan(scan);
    setShowScanDetails(true);
  };

  // Generate report for scan
  const generateReport = async (scan: ScanRecord) => {
    try {
      const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';
      const response = await fetch(`${API_BASE_URL}/api/reports/scan/${scan.id}/html`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;

        const contentDisposition = response.headers.get('Content-Disposition');
        let filename = `SiberZed-Security-Report-${scan.id}.html`;

        if (contentDisposition) {
          const filenameMatch = contentDisposition.match(/filename="(.+)"/);
          if (filenameMatch) {
            filename = filenameMatch[1];
          }
        }

        link.download = filename;
        document.body.appendChild(link);
        link.click();

        window.URL.revokeObjectURL(url);
        document.body.removeChild(link);
      } else {
        setError('Failed to generate report');
      }
    } catch (error) {
      console.error('Error generating report:', error);
      setError('Error generating report');
    }
  };

  // Format date
  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleString('tr-TR', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  // Calculate duration
  const calculateDuration = (startedAt: string, completedAt?: string) => {
    if (!completedAt) return '-';
    const start = new Date(startedAt).getTime();
    const end = new Date(completedAt).getTime();
    const diff = end - start;
    const minutes = Math.floor(diff / 60000);
    const seconds = Math.floor((diff % 60000) / 1000);

    if (minutes === 0) return `${seconds} sn`;
    return `${minutes} dk`;
  };

  // Get status color
  const getStatusColor = (status: string) => {
    switch (status.toUpperCase()) {
      case 'COMPLETED': return 'success';
      case 'RUNNING': return 'warning';
      case 'FAILED': return 'error';
      case 'PENDING': return 'info';
      default: return 'default';
    }
  };

  // Get status label
  const getStatusLabel = (status: string) => {
    switch (status.toUpperCase()) {
      case 'COMPLETED': return 'Tamamlandı';
      case 'RUNNING': return 'Devam Ediyor';
      case 'FAILED': return 'Başarısız';
      case 'PENDING': return 'Bekliyor';
      default: return status;
    }
  };

  // Get vulnerability count display
  const getVulnDisplay = (count: number) => {
    if (count === 0) return { text: 'No data', color: '#666' };
    return { text: count.toString(), color: count > 10 ? '#f44336' : '#ff9800' };
  };

  useEffect(() => {
    loadScanHistory();

    const socket = socketService.getSocket();

    if (socket) {
      const handleWorkflowComplete = (data: any) => {
        console.log('🎉 Workflow completed, refreshing scan history in 2 seconds:', data);
        setTimeout(() => {
          console.log('🔄 Refreshing scan history after workflow completion...');
          loadScanHistory();
        }, 2000);
      };

      const handleScanUpdate = (data: any) => {
        console.log('📊 Scan update received:', data);
        if (data.status === 'COMPLETED' || data.status === 'FAILED' || data.status?.toLowerCase() === 'completed' || data.status?.toLowerCase() === 'failed') {
          console.log(`✅ Scan ${data.scanId || 'unknown'} ${data.status}, refreshing in 2 seconds...`);
          setTimeout(() => {
            console.log('🔄 Refreshing scan history after scan completion...');
            loadScanHistory();
          }, 2000);
        }
      };

      socket.on('workflowComplete', handleWorkflowComplete);
      socket.on('scanUpdate', handleScanUpdate);

      console.log('✅ Socket.IO listeners registered for scan history updates');

      return () => {
        socket.off('workflowComplete', handleWorkflowComplete);
        socket.off('scanUpdate', handleScanUpdate);
      };
    }
  }, []);

  // Apply filters and sorting
  const getFilteredAndSortedScans = () => {
    let filteredScans = scans.filter(scan => {
      const matchesSearch = searchQuery === '' ||
        scan.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        scan.targetUrl.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesStatus = statusFilter === 'Tümü' || scan.status === statusFilter;
      return matchesSearch && matchesStatus;
    });

    if (sortOrder === 'En Son Taramalar') {
      filteredScans = filteredScans.sort((a, b) =>
        new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime()
      );
    } else if (sortOrder === 'En Eski Taramalar') {
      filteredScans = filteredScans.sort((a, b) =>
        new Date(a.startedAt).getTime() - new Date(b.startedAt).getTime()
      );
    } else if (sortOrder === 'En Çok Zafiyet') {
      filteredScans = filteredScans.sort((a, b) =>
        b._count.vulnerabilities - a._count.vulnerabilities
      );
    }

    return filteredScans;
  };

  const filteredScans = getFilteredAndSortedScans();

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
          <Typography variant="h4" sx={{ fontWeight: 600 }}>
            Tarama Geçmişi
          </Typography>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={loadScanHistory}
            disabled={loading}
            size="small"
          >
            YENİLE
          </Button>
        </Box>
        <Typography variant="body2" color="text.secondary">
          Tüm güvenlik taramalarınızı görüntüleyin ve yönetin
        </Typography>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Filters */}
      <Box sx={{ display: 'flex', gap: 2, mb: 3, alignItems: 'center', flexWrap: 'wrap' }}>
        <TextField
          size="small"
          placeholder="Ara (İsim veya URL)"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          sx={{ flex: '1 1 300px', minWidth: 200 }}
        />
        <FormControl size="small" sx={{ minWidth: 150 }}>
          <InputLabel>Durum</InputLabel>
          <Select
            value={statusFilter}
            label="Durum"
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <MenuItem value="Tümü">Tümü</MenuItem>
            <MenuItem value="COMPLETED">Tamamlandı</MenuItem>
            <MenuItem value="RUNNING">Devam Ediyor</MenuItem>
            <MenuItem value="FAILED">Başarısız</MenuItem>
            <MenuItem value="PENDING">Bekliyor</MenuItem>
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 180 }}>
          <InputLabel>Sıralama</InputLabel>
          <Select
            value={sortOrder}
            label="Sıralama"
            onChange={(e) => setSortOrder(e.target.value)}
          >
            <MenuItem value="En Son Taramalar">En Son Taramalar</MenuItem>
            <MenuItem value="En Eski Taramalar">En Eski Taramalar</MenuItem>
            <MenuItem value="En Çok Zafiyet">En Çok Zafiyet</MenuItem>
          </Select>
        </FormControl>
        <Typography variant="body2" color="text.secondary" sx={{ ml: 'auto' }}>
          Toplam: {filteredScans.length} tarama
        </Typography>
      </Box>

      {/* Table */}
      <TableContainer component={Paper} sx={{ boxShadow: 3 }}>
        <Table>
          <TableHead sx={{ bgcolor: 'background.default' }}>
            <TableRow>
              <TableCell sx={{ fontWeight: 600 }}>İsim / Hedef</TableCell>
              <TableCell sx={{ fontWeight: 600 }}>Durum</TableCell>
              <TableCell sx={{ fontWeight: 600 }}>Başlangıç</TableCell>
              <TableCell sx={{ fontWeight: 600 }}>Bitiş</TableCell>
              <TableCell sx={{ fontWeight: 600 }}>Zafiyetler</TableCell>
              <TableCell sx={{ fontWeight: 600 }}>URL'ler</TableCell>
              <TableCell sx={{ fontWeight: 600 }}>İşlemler</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={7} align="center" sx={{ py: 4 }}>
                  <Typography variant="body2" color="text.secondary">
                    Yükleniyor...
                  </Typography>
                </TableCell>
              </TableRow>
            ) : filteredScans.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} align="center" sx={{ py: 4 }}>
                  <Typography variant="body2" color="text.secondary">
                    {searchQuery || statusFilter !== 'Tümü'
                      ? 'Filtrelere uygun tarama bulunamadı'
                      : 'Henüz hiç tarama yapılmamış'}
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              filteredScans.map((scan) => {
                const vulnDisplay = getVulnDisplay(scan._count.vulnerabilities);
                return (
                  <TableRow
                    key={scan.id}
                    sx={{
                      '&:hover': { bgcolor: 'action.hover' },
                      transition: 'background-color 0.2s'
                    }}
                  >
                    <TableCell>
                      <Box>
                        <Typography variant="body2" sx={{ fontWeight: 500, mb: 0.5 }}>
                          {scan.name || scan.targetUrl}
                        </Typography>
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          sx={{
                            display: 'block',
                            maxWidth: 300,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap'
                          }}
                        >
                          {scan.targetUrl}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={getStatusLabel(scan.status)}
                        color={getStatusColor(scan.status) as any}
                        size="small"
                        sx={{ fontWeight: 500 }}
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {formatDate(scan.startedAt)}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Box>
                        {scan.completedAt ? (
                          <>
                            <Typography variant="body2">
                              {formatDate(scan.completedAt)}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {calculateDuration(scan.startedAt, scan.completedAt)}
                            </Typography>
                          </>
                        ) : (
                          <Typography variant="body2" color="text.secondary">
                            {scan.status === 'RUNNING' ? 'Devam ediyor...' : '-'}
                          </Typography>
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {scan._count.vulnerabilities > 0 ? (
                          <>
                            <BugReportIcon sx={{ fontSize: 18, color: vulnDisplay.color }} />
                            <Typography variant="body2" sx={{ color: vulnDisplay.color, fontWeight: 600 }}>
                              {vulnDisplay.text}
                            </Typography>
                          </>
                        ) : (
                          <Typography variant="body2" color="text.secondary">
                            No data
                          </Typography>
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <LinkIcon sx={{ fontSize: 18, color: 'action.active' }} />
                        <Typography variant="body2">
                          {scan._count.scanUrls}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 0.5 }}>
                        <IconButton
                          size="small"
                          onClick={() => viewScanDetails(scan)}
                          title="Detayları Görüntüle"
                          sx={{ color: 'primary.main' }}
                        >
                          <ViewIcon fontSize="small" />
                        </IconButton>
                        {scan._count.vulnerabilities > 0 && (
                          <IconButton
                            size="small"
                            onClick={() => generateReport(scan)}
                            title="Rapor İndir"
                            sx={{ color: 'info.main' }}
                          >
                            <DownloadIcon fontSize="small" />
                          </IconButton>
                        )}
                        <IconButton
                          size="small"
                          onClick={() => deleteScan(scan.id)}
                          title="Sil"
                          sx={{ color: 'error.main' }}
                        >
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Box>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Scan Details Dialog */}
      {selectedScan && (
        <Dialog
          open={showScanDetails}
          onClose={() => setShowScanDetails(false)}
          maxWidth="xl"
          fullWidth
        >
          <DialogTitle>
            Tarama Detayları: {selectedScan.targetUrl}
          </DialogTitle>
          <DialogContent>
            <ComprehensiveScanMonitor
              workflowId={selectedScan.id}
              scanId={selectedScan.id}
              onClose={() => setShowScanDetails(false)}
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setShowScanDetails(false)}>
              Kapat
            </Button>
          </DialogActions>
        </Dialog>
      )}
    </Box>
  );
};

export default ScanHistoryPanel;
