import React, { useState, useEffect } from 'react';
import {
    Box,
    Card,
    CardContent,
    Typography,
    TextField,
    Button,
    Alert,
    CircularProgress,
    LinearProgress,
    Chip,
    Tabs,
    Tab,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Paper,
    ToggleButton,
    ToggleButtonGroup,
    Snackbar,
    Accordion,
    AccordionSummary,
    AccordionDetails,
    Tooltip,
} from '@mui/material';
import {
    Security as SecurityIcon,
    PlayArrow as PlayArrowIcon,
    Download as DownloadIcon,
    Refresh as RefreshIcon,
    ExpandMore as ExpandMoreIcon,
    Error as ErrorIcon,
    Warning as WarningIcon,
    Info as InfoIcon,
    CheckCircle as CheckCircleIcon,
    BugReport as BugReportIcon,
    Storage as StorageIcon,
    Code as CodeIcon,
    VpnKey as SecretIcon,
    List as SbomIcon,
} from '@mui/icons-material';
import { zapService } from '../../services/zapService';
import SavedRepositories from './SavedRepositories';

// Interfaces
interface Vulnerability {
    VulnerabilityID: string;
    PkgName: string;
    InstalledVersion: string;
    FixedVersion?: string;
    Severity: string;
    Title?: string;
    Description?: string;
}

interface ScanResult {
    Target: string;
    Vulnerabilities?: Vulnerability[];
    Secrets?: any[];
    Licenses?: any[];
    Misconfigurations?: any[];
}

interface TrivyScanResponse {
    id?: string;
    scanType: string;
    target: string;
    scanTime: string;
    results: ScanResult[];
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        unknown: number;
        total: number;
    };
    secrets?: any[];
    licenses?: any[];
}

// Severity colors and icons
const getSeverityColor = (severity: string): string => {
    switch (severity?.toUpperCase()) {
        case 'CRITICAL': return '#ff0000';
        case 'HIGH': return '#ff6600';
        case 'MEDIUM': return '#ffaa00';
        case 'LOW': return '#00aa00';
        default: return '#888888';
    }
};

const getSeverityIcon = (severity: string) => {
    switch (severity?.toUpperCase()) {
        case 'CRITICAL': return <ErrorIcon sx={{ color: '#ff0000' }} />;
        case 'HIGH': return <WarningIcon sx={{ color: '#ff6600' }} />;
        case 'MEDIUM': return <InfoIcon sx={{ color: '#ffaa00' }} />;
        case 'LOW': return <CheckCircleIcon sx={{ color: '#00aa00' }} />;
        default: return <InfoIcon sx={{ color: '#888888' }} />;
    }
};

const TrivyScanner: React.FC = () => {
    // Scan mode
    const [scanType, setScanType] = useState<'image' | 'repository' | 'sbom'>('image');

    // Input states
    const [imageName, setImageName] = useState('');
    const [repoUrl, setRepoUrl] = useState('');
    const [sbomTarget, setSbomTarget] = useState('');
    const [sbomFormat, setSbomFormat] = useState<'cyclonedx' | 'spdx'>('cyclonedx');

    // Severity filter
    const [severities, setSeverities] = useState<string[]>(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);

    // States
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [result, setResult] = useState<TrivyScanResponse | null>(null);
    const [sbomData, setSbomData] = useState<any | null>(null);
    const [serverStatus, setServerStatus] = useState<'online' | 'offline' | 'checking'>('checking');
    const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
        open: false,
        message: '',
        severity: 'success',
    });

    // Check server health on mount
    useEffect(() => {
        checkServerHealth();
    }, []);

    const checkServerHealth = async () => {
        setServerStatus('checking');
        try {
            const response = await zapService.trivyHealthCheck();
            setServerStatus(response.data?.status === 'operational' ? 'online' : 'offline');
        } catch {
            setServerStatus('offline');
        }
    };

    const runScan = async () => {
        setLoading(true);
        setError(null);
        setResult(null);
        setSbomData(null);

        try {
            let response;

            switch (scanType) {
                case 'image':
                    if (!imageName.trim()) {
                        setError('Image adı gerekli');
                        setLoading(false);
                        return;
                    }
                    response = await zapService.scanTrivyImage(imageName, severities);
                    setResult(response.data);
                    break;

                case 'repository':
                    if (!repoUrl.trim()) {
                        setError('Repository URL gerekli');
                        setLoading(false);
                        return;
                    }
                    response = await zapService.scanTrivyRepository(repoUrl, severities);
                    setResult(response.data);
                    break;

                case 'sbom':
                    if (!sbomTarget.trim()) {
                        setError('Target gerekli');
                        setLoading(false);
                        return;
                    }
                    response = await zapService.generateTrivySBOM(sbomTarget, sbomFormat);
                    setSbomData(response.data);
                    break;
            }

            setSnackbar({ open: true, message: 'Tarama tamamlandı!', severity: 'success' });

        } catch (err: any) {
            console.error('Trivy scan failed:', err);
            setError(err.response?.data?.error?.message || err.message || 'Tarama başarısız');
        } finally {
            setLoading(false);
        }
    };

    const downloadReport = () => {
        if (result?.id) {
            zapService.downloadTrivyReport(result.id);
        }
    };

    // Flatten vulnerabilities from all results
    const allVulnerabilities = result?.results?.flatMap(r => r.Vulnerabilities || []) || [];
    const allMisconfigurations = result?.results?.flatMap(r => r.Misconfigurations || []) || [];

    return (
        <Box sx={{ p: 3 }}>
            {/* Header */}
            <Box sx={{ mb: 4 }}>
                <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <SecurityIcon color="primary" sx={{ fontSize: 36 }} />
                    Trivy Güvenlik Tarayıcı
                </Typography>
                <Typography variant="subtitle1" color="text.secondary">
                    Container Image, Repository ve SBOM güvenlik analizi
                </Typography>
                <Box sx={{ mt: 1, display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Chip
                        label={serverStatus === 'online' ? '🟢 Server Online' : serverStatus === 'offline' ? '🔴 Server Offline' : '⏳ Checking...'}
                        size="small"
                        color={serverStatus === 'online' ? 'success' : serverStatus === 'offline' ? 'error' : 'default'}
                        onClick={checkServerHealth}
                    />
                    <Typography variant="caption" color="text.secondary">Port 5004</Typography>
                </Box>
            </Box>

            {/* Scan Type & Input */}
            <Card sx={{ mb: 3 }}>
                <CardContent>
                    {/* Scan Type Tabs */}
                    <Tabs value={scanType} onChange={(_, v) => setScanType(v)} sx={{ mb: 2 }}>
                        <Tab value="image" label="🐳 Container Image" icon={<StorageIcon />} iconPosition="start" />
                        <Tab value="repository" label="📦 Repository" icon={<CodeIcon />} iconPosition="start" />
                        <Tab value="sbom" label="📋 SBOM" icon={<SbomIcon />} iconPosition="start" />
                    </Tabs>

                    <Box sx={{ display: 'flex', flexDirection: { xs: 'column', md: 'row' }, gap: 2, alignItems: { md: 'flex-start' } }}>
                        {/* Severity Filter */}
                        {scanType !== 'sbom' && (
                            <Box>
                                <Typography variant="caption" color="text.secondary" sx={{ mb: 0.5, display: 'block' }}>Severity</Typography>
                                <ToggleButtonGroup
                                    value={severities}
                                    onChange={(_, v) => v?.length && setSeverities(v)}
                                    size="small"
                                    disabled={loading}
                                >
                                    <ToggleButton value="CRITICAL" sx={{ color: '#ff0000' }}>C</ToggleButton>
                                    <ToggleButton value="HIGH" sx={{ color: '#ff6600' }}>H</ToggleButton>
                                    <ToggleButton value="MEDIUM" sx={{ color: '#ffaa00' }}>M</ToggleButton>
                                    <ToggleButton value="LOW" sx={{ color: '#00aa00' }}>L</ToggleButton>
                                </ToggleButtonGroup>
                            </Box>
                        )}

                        {/* Input Field */}
                        <Box sx={{ flex: 1 }}>
                            {scanType === 'image' && (
                                <TextField
                                    fullWidth
                                    label="Docker Image"
                                    placeholder="alpine:latest, nginx:1.21, python:3.9-slim"
                                    value={imageName}
                                    onChange={(e) => setImageName(e.target.value)}
                                    disabled={loading}
                                    size="small"
                                    helperText="Public veya registry image adı girin"
                                />
                            )}
                            {scanType === 'repository' && (
                                <Box>
                                    {/* Saved Repositories Component */}
                                    <SavedRepositories
                                        onScan={async (repoId) => {
                                            setLoading(true);
                                            setError(null);
                                            setResult(null);
                                            try {
                                                const response = await zapService.scanSavedRepository(repoId, severities);
                                                setResult(response.data);
                                                setSnackbar({ open: true, message: 'Tarama tamamlandı!', severity: 'success' });
                                            } catch (err: any) {
                                                setError(err.response?.data?.error?.message || 'Saved repository taraması başarısız');
                                            } finally {
                                                setLoading(false);
                                            }
                                        }}
                                    />

                                    {/* Or scan one-time with URL */}
                                    <Box sx={{ mt: 3, pt: 3, borderTop: '1px dashed #ccc' }}>
                                        <Typography variant="subtitle2" gutterBottom>
                                            Veya Tek Seferlik Tarama
                                        </Typography>
                                        <TextField
                                            fullWidth
                                            label="Git Repository URL (Public)"
                                            placeholder="https://github.com/user/repo"
                                            value={repoUrl}
                                            onChange={(e) => setRepoUrl(e.target.value)}
                                            disabled={loading}
                                            size="small"
                                            helperText="Public repository için URL girin"
                                            sx={{ mt: 1 }}
                                        />
                                    </Box>
                                </Box>
                            )}
                            {scanType === 'sbom' && (
                                <Box sx={{ display: 'flex', gap: 2 }}>
                                    <TextField
                                        sx={{ flex: 1 }}
                                        label="Target (Image)"
                                        placeholder="alpine:latest"
                                        value={sbomTarget}
                                        onChange={(e) => setSbomTarget(e.target.value)}
                                        disabled={loading}
                                        size="small"
                                    />
                                    <ToggleButtonGroup
                                        value={sbomFormat}
                                        exclusive
                                        onChange={(_, v) => v && setSbomFormat(v)}
                                        size="small"
                                    >
                                        <ToggleButton value="cyclonedx">CycloneDX</ToggleButton>
                                        <ToggleButton value="spdx">SPDX</ToggleButton>
                                    </ToggleButtonGroup>
                                </Box>
                            )}
                        </Box>

                        {/* Scan Button */}
                        <Button
                            variant="contained"
                            startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <PlayArrowIcon />}
                            onClick={runScan}
                            disabled={loading || serverStatus === 'offline'}
                            sx={{ height: 40, minWidth: 140, alignSelf: 'flex-end' }}
                        >
                            {loading ? 'Taranıyor...' : 'Taramayı Başlat'}
                        </Button>
                    </Box>

                    {error && (
                        <Alert severity="error" sx={{ mt: 2 }} onClose={() => setError(null)}>
                            {error}
                        </Alert>
                    )}
                </CardContent>
            </Card>

            {/* Loading */}
            {loading && (
                <Card sx={{ mb: 3 }}>
                    <CardContent sx={{ textAlign: 'center', py: 4 }}>
                        <CircularProgress size={60} sx={{ mb: 2 }} />
                        <Typography variant="h6">Trivy Taraması...</Typography>
                        <Typography variant="body2" color="text.secondary">
                            {scanType === 'image' ? 'Image indiriliyor ve taranıyor' :
                                scanType === 'repository' ? 'Repository klonlanıyor ve taranıyor' :
                                    'SBOM oluşturuluyor'}
                        </Typography>
                        <LinearProgress sx={{ mt: 2, maxWidth: 300, mx: 'auto' }} />
                    </CardContent>
                </Card>
            )}

            {/* Vulnerability Results */}
            {result && (
                <>
                    {/* Summary */}
                    <Card sx={{ mb: 3 }}>
                        <CardContent>
                            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap: 2 }}>
                                <Box>
                                    <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                        <CheckCircleIcon color="success" />
                                        Tarama Tamamlandı
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                        {result.target} • {new Date(result.scanTime).toLocaleString('tr-TR')}
                                    </Typography>
                                </Box>
                                <Box sx={{ display: 'flex', gap: 1 }}>
                                    <Button variant="outlined" startIcon={<RefreshIcon />} onClick={runScan} size="small">
                                        Tekrar Tara
                                    </Button>
                                    {result.id && (
                                        <Button variant="outlined" startIcon={<DownloadIcon />} onClick={downloadReport} size="small">
                                            Rapor İndir
                                        </Button>
                                    )}
                                </Box>
                            </Box>

                            {/* Severity Summary */}
                            <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
                                {[
                                    { label: 'CRITICAL', count: result.summary.critical, color: '#ff0000' },
                                    { label: 'HIGH', count: result.summary.high, color: '#ff6600' },
                                    { label: 'MEDIUM', count: result.summary.medium, color: '#ffaa00' },
                                    { label: 'LOW', count: result.summary.low, color: '#00aa00' },
                                ].map(item => (
                                    <Box
                                        key={item.label}
                                        sx={{
                                            textAlign: 'center',
                                            p: 2,
                                            borderRadius: 2,
                                            bgcolor: `${item.color}22`,
                                            border: `1px solid ${item.color}`,
                                            minWidth: 100
                                        }}
                                    >
                                        <Typography variant="h4" sx={{ color: item.color, fontWeight: 'bold' }}>
                                            {item.count}
                                        </Typography>
                                        <Typography variant="caption">{item.label}</Typography>
                                    </Box>
                                ))}
                            </Box>
                        </CardContent>
                    </Card>

                    {/* Vulnerabilities Table */}
                    {allVulnerabilities.length > 0 && (
                        <Card sx={{ mb: 3 }}>
                            <CardContent>
                                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                    <BugReportIcon color="error" />
                                    Güvenlik Açıkları ({allVulnerabilities.length})
                                </Typography>
                                <TableContainer component={Paper} sx={{ maxHeight: 500 }}>
                                    <Table stickyHeader size="small">
                                        <TableHead>
                                            <TableRow>
                                                <TableCell>Severity</TableCell>
                                                <TableCell>CVE ID</TableCell>
                                                <TableCell>Package</TableCell>
                                                <TableCell>Installed</TableCell>
                                                <TableCell>Fixed</TableCell>
                                                <TableCell>Title</TableCell>
                                            </TableRow>
                                        </TableHead>
                                        <TableBody>
                                            {allVulnerabilities.slice(0, 100).map((vuln, idx) => (
                                                <TableRow key={idx} hover>
                                                    <TableCell>
                                                        <Chip
                                                            label={vuln.Severity}
                                                            size="small"
                                                            sx={{
                                                                bgcolor: `${getSeverityColor(vuln.Severity)}22`,
                                                                color: getSeverityColor(vuln.Severity),
                                                                fontWeight: 'bold'
                                                            }}
                                                        />
                                                    </TableCell>
                                                    <TableCell>
                                                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                                                            {vuln.VulnerabilityID}
                                                        </Typography>
                                                    </TableCell>
                                                    <TableCell>{vuln.PkgName}</TableCell>
                                                    <TableCell>{vuln.InstalledVersion}</TableCell>
                                                    <TableCell sx={{ color: vuln.FixedVersion ? '#00aa00' : '#888' }}>
                                                        {vuln.FixedVersion || '-'}
                                                    </TableCell>
                                                    <TableCell sx={{ maxWidth: 300 }}>
                                                        <Tooltip title={vuln.Description || ''}>
                                                            <Typography variant="body2" noWrap>
                                                                {vuln.Title || '-'}
                                                            </Typography>
                                                        </Tooltip>
                                                    </TableCell>
                                                </TableRow>
                                            ))}
                                        </TableBody>
                                    </Table>
                                </TableContainer>
                                {allVulnerabilities.length > 100 && (
                                    <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                                        İlk 100 sonuç gösteriliyor. Tamamı için raporu indirin.
                                    </Typography>
                                )}
                            </CardContent>
                        </Card>
                    )}

                    {/* No vulnerabilities message */}
                    {allVulnerabilities.length === 0 && (result.secrets?.length || 0) === 0 && (allMisconfigurations.length === 0) && (
                        <Card sx={{ mb: 3 }}>
                            <CardContent sx={{ textAlign: 'center', py: 4 }}>
                                <CheckCircleIcon sx={{ fontSize: 60, color: '#00aa00', mb: 2 }} />
                                <Typography variant="h6" color="success.main">
                                    Güvenlik Açığı Bulunamadı! ✅
                                </Typography>
                                <Typography variant="body2" color="text.secondary">
                                    Seçilen severity seviyelerinde hiç zafiyet tespit edilmedi.
                                </Typography>
                            </CardContent>
                        </Card>
                    )}

                    {/* Secrets Table */}
                    {(result.secrets?.length || 0) > 0 && (
                        <Card sx={{ mb: 3 }}>
                            <CardContent>
                                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                    <SecretIcon color="warning" />
                                    Bulunan Gizli Bilgiler (Secrets) ({result.secrets?.length || 0})
                                </Typography>
                                <TableContainer component={Paper} sx={{ maxHeight: 400 }}>
                                    <Table stickyHeader size="small">
                                        <TableHead>
                                            <TableRow>
                                                <TableCell>Severity</TableCell>
                                                <TableCell>Rule ID</TableCell>
                                                <TableCell>Category</TableCell>
                                                <TableCell>Title</TableCell>
                                                <TableCell>File</TableCell>
                                                <TableCell>Line</TableCell>
                                            </TableRow>
                                        </TableHead>
                                        <TableBody>
                                            {result.secrets?.slice(0, 50).map((secret, idx) => (
                                                <TableRow key={idx} hover>
                                                    <TableCell>
                                                        <Chip
                                                            label={secret.Severity}
                                                            size="small"
                                                            sx={{
                                                                bgcolor: `${getSeverityColor(secret.Severity)}22`,
                                                                color: getSeverityColor(secret.Severity),
                                                                fontWeight: 'bold'
                                                            }}
                                                        />
                                                    </TableCell>
                                                    <TableCell sx={{ fontFamily: 'monospace' }}>{secret.RuleID}</TableCell>
                                                    <TableCell>{secret.Category}</TableCell>
                                                    <TableCell>{secret.Title}</TableCell>
                                                    <TableCell sx={{ maxWidth: 200 }}>
                                                        <Typography variant="body2" noWrap>{secret.Match || '-'}</Typography>
                                                    </TableCell>
                                                    <TableCell>{secret.StartLine}</TableCell>
                                                </TableRow>
                                            ))}
                                        </TableBody>
                                    </Table>
                                </TableContainer>
                            </CardContent>
                        </Card>
                    )}

                    {/* Misconfigurations Table */}
                    {allMisconfigurations.length > 0 && (
                        <Card sx={{ mb: 3 }}>
                            <CardContent>
                                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                    <WarningIcon color="warning" />
                                    Yapılandırma Hataları (Misconfigurations) ({allMisconfigurations.length})
                                </Typography>
                                <TableContainer component={Paper} sx={{ maxHeight: 400 }}>
                                    <Table stickyHeader size="small">
                                        <TableHead>
                                            <TableRow>
                                                <TableCell>Severity</TableCell>
                                                <TableCell>ID</TableCell>
                                                <TableCell>Title</TableCell>
                                                <TableCell>Type</TableCell>
                                                <TableCell>Message</TableCell>
                                            </TableRow>
                                        </TableHead>
                                        <TableBody>
                                            {allMisconfigurations.slice(0, 50).map((mc, idx) => (
                                                <TableRow key={idx} hover>
                                                    <TableCell>
                                                        <Chip
                                                            label={mc.Severity}
                                                            size="small"
                                                            sx={{
                                                                bgcolor: `${getSeverityColor(mc.Severity)}22`,
                                                                color: getSeverityColor(mc.Severity),
                                                                fontWeight: 'bold'
                                                            }}
                                                        />
                                                    </TableCell>
                                                    <TableCell sx={{ fontFamily: 'monospace' }}>{mc.ID || mc.AVDID}</TableCell>
                                                    <TableCell>{mc.Title}</TableCell>
                                                    <TableCell>{mc.Type}</TableCell>
                                                    <TableCell sx={{ maxWidth: 300 }}>
                                                        <Tooltip title={mc.Description || ''}>
                                                            <Typography variant="body2" noWrap>{mc.Message || '-'}</Typography>
                                                        </Tooltip>
                                                    </TableCell>
                                                </TableRow>
                                            ))}
                                        </TableBody>
                                    </Table>
                                </TableContainer>
                            </CardContent>
                        </Card>
                    )}
                </>
            )}

            {/* SBOM Results */}
            {sbomData && (
                <Card sx={{ mb: 3 }}>
                    <CardContent>
                        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <SbomIcon color="primary" />
                            Software Bill of Materials (SBOM)
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                            <Chip label={`Format: ${sbomData.format?.toUpperCase()}`} />
                            <Chip label={`Target: ${sbomData.target}`} />
                            <Chip label={`Generated: ${new Date(sbomData.generatedAt).toLocaleString('tr-TR')}`} />
                        </Box>
                        <Accordion>
                            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                <Typography>SBOM JSON (Click to expand)</Typography>
                            </AccordionSummary>
                            <AccordionDetails>
                                <Box
                                    component="pre"
                                    sx={{
                                        bgcolor: '#1a1a1a',
                                        color: '#0f0',
                                        p: 2,
                                        borderRadius: 1,
                                        overflow: 'auto',
                                        maxHeight: 400,
                                        fontSize: 12
                                    }}
                                >
                                    {JSON.stringify(sbomData.sbom, null, 2)}
                                </Box>
                            </AccordionDetails>
                        </Accordion>
                    </CardContent>
                </Card>
            )}

            {/* Snackbar */}
            <Snackbar
                open={snackbar.open}
                autoHideDuration={4000}
                onClose={() => setSnackbar({ ...snackbar, open: false })}
                anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
            >
                <Alert severity={snackbar.severity} onClose={() => setSnackbar({ ...snackbar, open: false })}>
                    {snackbar.message}
                </Alert>
            </Snackbar>
        </Box>
    );
};

export default TrivyScanner;
