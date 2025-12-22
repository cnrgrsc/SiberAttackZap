import React, { useState } from 'react';
import {
    Box,
    Card,
    CardContent,
    Typography,
    TextField,
    Button,
    Alert,
    CircularProgress,
    Grid,
    Chip,
    Paper,
    List,
    ListItem,
    ListItemIcon,
    ListItemText,
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
    Snackbar,
    LinearProgress,
    Accordion,
    AccordionSummary,
    AccordionDetails,
    ToggleButton,
    ToggleButtonGroup,
    Tabs,
    Tab,
    Collapse,
    Table,
    TableBody,
    TableCell,
    TableRow,
} from '@mui/material';
import {
    Speed as SpeedIcon,
    Accessibility as AccessibilityIcon,
    Security as SecurityIcon,
    Search as SeoIcon,
    PlayArrow as PlayArrowIcon,
    Email as EmailIcon,
    Info as InfoIcon,
    CheckCircle as CheckCircleIcon,
    Warning as WarningIcon,
    Error as ErrorIcon,
    ExpandMore as ExpandMoreIcon,
    Refresh as RefreshIcon,
    Timer as TimerIcon,
    Image as ImageIcon,
    Code as CodeIcon,
    Computer as DesktopIcon,
    PhoneAndroid as MobileIcon,
    Insights as InsightsIcon,
    BugReport as DiagnosticsIcon,
} from '@mui/icons-material';
import { zapService } from '../../services/zapService';

// Interfaces
interface FileItem {
    url: string;
    totalBytes?: number;
    wastedBytes?: number;
    wastedMs?: number;
    wastedPercent?: number;
    label?: string;
}

interface InsightItem {
    id: string;
    title: string;
    description: string;
    score: number | null;
    severity: 'error' | 'warning' | 'info';
    displayValue?: string;
    savings?: string;
    items?: FileItem[];
}

interface DiagnosticItem {
    title: string;
    description: string;
    savings?: string;
    savingsMs?: number;
    savingsBytes?: number;
    category: string;
    items?: FileItem[];
}

interface AuditResult {
    id: string;
    title: string;
    description: string;
    score: number | null;
    displayValue?: string;
    scoreDisplayMode: string;
    category: string;
    details?: any;
}

interface CategoryAudits {
    failed: AuditResult[];
    passed: AuditResult[];
    notApplicable: AuditResult[];
    manual: AuditResult[];
}

interface MetricValue {
    value: number;
    displayValue: string;
    score: number;
}

interface CategoryResult {
    score: number;
    title: string;
    description?: string;
}

interface LighthouseResult {
    url: string;
    fetchTime: string;
    device: 'mobile' | 'desktop';
    categories: {
        performance: CategoryResult;
        accessibility: CategoryResult;
        bestPractices: CategoryResult;
        seo: CategoryResult;
    };
    metrics: {
        firstContentfulPaint: MetricValue;
        largestContentfulPaint: MetricValue;
        totalBlockingTime: MetricValue;
        cumulativeLayoutShift: MetricValue;
        speedIndex: MetricValue;
        interactive?: MetricValue;
    };
    audits: AuditResult[];
    diagnostics: DiagnosticItem[];
    insights: InsightItem[];
    categoryAudits: {
        performance: CategoryAudits;
        accessibility: CategoryAudits;
        bestPractices: CategoryAudits;
        seo: CategoryAudits;
    };
    treemapData?: any;
    filmstrip?: any[];
    finalScreenshot?: string;
    runWarnings: string[];
}

const LighthouseScanner: React.FC = () => {
    // Scan mode: single or multi
    const [scanMode, setScanMode] = useState<'single' | 'multi'>('single');
    const [targetUrl, setTargetUrl] = useState('');
    const [multiUrls, setMultiUrls] = useState('');
    const [device, setDevice] = useState<'mobile' | 'desktop'>('desktop');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Single scan result
    const [result, setResult] = useState<LighthouseResult | null>(null);
    const [savedScanId, setSavedScanId] = useState<string | null>(null);

    // Multi scan results
    const [multiResults, setMultiResults] = useState<LighthouseResult[]>([]);
    const [currentScanIndex, setCurrentScanIndex] = useState(0);
    const [totalScans, setTotalScans] = useState(0);
    const [selectedResultIndex, setSelectedResultIndex] = useState<number | null>(null);

    const [emailDialogOpen, setEmailDialogOpen] = useState(false);
    const [emailAddress, setEmailAddress] = useState('');
    const [emailSending, setEmailSending] = useState(false);
    const [activeTab, setActiveTab] = useState(0);
    const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
        open: false,
        message: '',
        severity: 'success',
    });

    const isValidUrl = (url: string): boolean => {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    };

    const runScan = async () => {
        if (scanMode === 'multi') {
            return runMultiScan();
        }

        if (!targetUrl || !isValidUrl(targetUrl)) {
            setError('Lütfen geçerli bir URL girin');
            return;
        }

        setLoading(true);
        setError(null);
        setResult(null);
        setSavedScanId(null);
        setMultiResults([]);

        try {
            const response = await zapService.runLighthouseScan(targetUrl, undefined, device);

            if (response.success && response.data) {
                setResult(response.data);

                // Otomatik olarak kaydet
                try {
                    const saveResponse = await zapService.saveLighthouseScan(response.data);
                    if (saveResponse.success && saveResponse.data?.scanId) {
                        setSavedScanId(saveResponse.data.scanId);
                        setSnackbar({ open: true, message: 'Tarama kaydedildi!', severity: 'success' });
                    }
                } catch (saveErr) {
                    console.error('Kaydetme hatası:', saveErr);
                }
            } else {
                setError(response.error?.message || 'Tarama başarısız oldu');
            }
        } catch (err: any) {
            console.error('Lighthouse scan failed:', err);
            setError(err.message || 'Tarama sırasında hata oluştu');
        } finally {
            setLoading(false);
        }
    };

    const runMultiScan = async () => {
        // Parse URLs from textarea
        const urls = multiUrls
            .split('\n')
            .map(url => url.trim())
            .filter(url => url && isValidUrl(url));

        if (urls.length === 0) {
            setError('Lütfen en az bir geçerli URL girin');
            return;
        }

        setLoading(true);
        setError(null);
        setResult(null);
        setMultiResults([]);
        setTotalScans(urls.length);
        setCurrentScanIndex(0);
        setSelectedResultIndex(null);

        const results: LighthouseResult[] = [];

        for (let i = 0; i < urls.length; i++) {
            setCurrentScanIndex(i + 1);

            try {
                const response = await zapService.runLighthouseScan(urls[i], undefined, device);

                if (response.success && response.data) {
                    results.push(response.data);
                    setMultiResults([...results]);

                    // Her taramayı kaydet
                    try {
                        await zapService.saveLighthouseScan(response.data);
                    } catch (saveErr) {
                        console.error('Kaydetme hatası:', saveErr);
                    }
                }
            } catch (err: any) {
                console.error(`Scan failed for ${urls[i]}:`, err);
                // Continue with next URL
            }
        }

        setLoading(false);
        setSnackbar({
            open: true,
            message: `${results.length}/${urls.length} tarama tamamlandı!`,
            severity: 'success'
        });
    };

    const downloadReport = () => {
        if (savedScanId) {
            zapService.downloadLighthouseReport(savedScanId);
        } else if (result) {
            // Kayıtlı değilse direkt HTML oluştur
            const htmlContent = generateLocalReport(result);
            const blob = new Blob([htmlContent], { type: 'text/html' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `lighthouse-report-${Date.now()}.html`;
            a.click();
            URL.revokeObjectURL(url);
        }
    };

    const generateLocalReport = (r: LighthouseResult): string => {
        return `<!DOCTYPE html>
<html><head><title>Lighthouse Report - ${r.url}</title>
<style>body{font-family:Arial;padding:20px}h1{color:#333}.score{display:inline-block;padding:10px 20px;border-radius:50%;font-size:24px;font-weight:bold;margin:10px}.green{background:#0cce6b33;color:#0cce6b}.orange{background:#ffa40033;color:#ffa400}.red{background:#ff4e4233;color:#ff4e42}</style></head>
<body><h1>🚀 Lighthouse Report</h1>
<p><strong>URL:</strong> ${r.url}</p>
<p><strong>Device:</strong> ${r.device}</p>
<p><strong>Date:</strong> ${new Date(r.fetchTime).toLocaleString()}</p>
<h2>Scores</h2>
<span class="score ${r.categories.performance.score >= 90 ? 'green' : r.categories.performance.score >= 50 ? 'orange' : 'red'}">${r.categories.performance.score}</span> Performance
<span class="score ${r.categories.accessibility.score >= 90 ? 'green' : r.categories.accessibility.score >= 50 ? 'orange' : 'red'}">${r.categories.accessibility.score}</span> Accessibility
<span class="score ${r.categories.bestPractices.score >= 90 ? 'green' : r.categories.bestPractices.score >= 50 ? 'orange' : 'red'}">${r.categories.bestPractices.score}</span> Best Practices
<span class="score ${r.categories.seo.score >= 90 ? 'green' : r.categories.seo.score >= 50 ? 'orange' : 'red'}">${r.categories.seo.score}</span> SEO
</body></html>`;
    };

    const sendEmailReport = async () => {
        if (!emailAddress || !result) return;
        setEmailSending(true);
        try {
            const response = await zapService.sendLighthouseEmailReport(result, emailAddress);
            if (response.success) {
                setSnackbar({ open: true, message: 'Rapor başarıyla gönderildi!', severity: 'success' });
                setEmailDialogOpen(false);
                setEmailAddress('');
            } else {
                setSnackbar({ open: true, message: response.error?.message || 'Gönderim başarısız', severity: 'error' });
            }
        } catch (err: any) {
            setSnackbar({ open: true, message: 'Email gönderilemedi', severity: 'error' });
        } finally {
            setEmailSending(false);
        }
    };

    const getScoreColor = (score: number): string => {
        if (score >= 90) return '#0cce6b';
        if (score >= 50) return '#ffa400';
        return '#ff4e42';
    };

    const getScoreBgColor = (score: number): string => {
        if (score >= 90) return 'rgba(12, 206, 107, 0.1)';
        if (score >= 50) return 'rgba(255, 164, 0, 0.1)';
        return 'rgba(255, 78, 66, 0.1)';
    };

    const getSeverityIcon = (severity: 'error' | 'warning' | 'info') => {
        switch (severity) {
            case 'error': return <ErrorIcon sx={{ color: '#ff4e42' }} fontSize="small" />;
            case 'warning': return <WarningIcon sx={{ color: '#ffa400' }} fontSize="small" />;
            default: return <InfoIcon sx={{ color: '#888' }} fontSize="small" />;
        }
    };

    const formatBytes = (bytes?: number): string => {
        if (!bytes) return '';
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    };

    // Score Circle Component
    const ScoreCircle: React.FC<{ score: number; label: string; icon: React.ReactNode }> = ({ score, label, icon }) => (
        <Box sx={{ textAlign: 'center', p: 2 }}>
            <Box
                sx={{
                    width: 100,
                    height: 100,
                    borderRadius: '50%',
                    border: `6px solid ${getScoreColor(score)}`,
                    backgroundColor: getScoreBgColor(score),
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    mx: 'auto',
                    mb: 1,
                    transition: 'all 0.3s ease',
                    '&:hover': { transform: 'scale(1.05)' },
                }}
            >
                <Typography variant="h4" sx={{ fontWeight: 'bold', color: getScoreColor(score) }}>
                    {score}
                </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 0.5 }}>
                {icon}
                <Typography variant="body2" color="text.secondary">{label}</Typography>
            </Box>
        </Box>
    );

    // Metric Card Component
    const MetricCard: React.FC<{ label: string; metric: MetricValue; icon: React.ReactNode }> = ({ label, metric, icon }) => (
        <Paper sx={{ p: 2, bgcolor: getScoreBgColor(metric.score), border: `1px solid ${getScoreColor(metric.score)}30`, borderRadius: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                {icon}
                <Typography variant="body2" color="text.secondary">{label}</Typography>
            </Box>
            <Typography variant="h5" sx={{ fontWeight: 'bold', color: getScoreColor(metric.score) }}>
                {metric.displayValue}
            </Typography>
        </Paper>
    );

    // Insight Card Component
    const InsightCard: React.FC<{ insight: InsightItem }> = ({ insight }) => {
        const [expanded, setExpanded] = useState(false);

        return (
            <Accordion
                expanded={expanded}
                onChange={() => setExpanded(!expanded)}
                sx={{ bgcolor: 'background.paper', '&:before': { display: 'none' }, mb: 1 }}
            >
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                        {getSeverityIcon(insight.severity)}
                        <Typography sx={{ flex: 1, fontSize: '0.9rem' }}>{insight.title}</Typography>
                        {insight.savings && (
                            <Chip label={insight.savings} size="small" color="success" variant="outlined" sx={{ fontSize: '0.75rem' }} />
                        )}
                        {insight.displayValue && !insight.savings && (
                            <Typography variant="body2" color="text.secondary">{insight.displayValue}</Typography>
                        )}
                    </Box>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 0 }}>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        {insight.description?.replace(/<[^>]*>/g, ' ').substring(0, 300)}...
                    </Typography>
                    {insight.items && insight.items.length > 0 && (
                        <Box sx={{ maxHeight: 200, overflow: 'auto' }}>
                            <Table size="small">
                                <TableBody>
                                    {insight.items.slice(0, 10).map((item, idx) => (
                                        <TableRow key={idx}>
                                            <TableCell sx={{ py: 0.5, fontSize: '0.8rem', wordBreak: 'break-all', maxWidth: 400 }}>
                                                {item.url?.split('/').pop() || item.url?.substring(0, 50) || item.label || 'Unknown'}
                                            </TableCell>
                                            <TableCell align="right" sx={{ py: 0.5, fontSize: '0.8rem', whiteSpace: 'nowrap' }}>
                                                {item.wastedBytes && <span style={{ color: '#ff4e42' }}>{formatBytes(item.wastedBytes)}</span>}
                                                {item.totalBytes && !item.wastedBytes && formatBytes(item.totalBytes)}
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        </Box>
                    )}
                </AccordionDetails>
            </Accordion>
        );
    };

    // Category Audits Section
    const CategoryAuditsSection: React.FC<{ title: string; audits: CategoryAudits; icon: React.ReactNode }> = ({ title, audits, icon }) => {
        const [showPassed, setShowPassed] = useState(false);

        return (
            <Box>
                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    {icon} {title}
                </Typography>

                {/* Failed */}
                {audits.failed.length > 0 && (
                    <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" color="error" gutterBottom>
                            Başarısız ({audits.failed.length})
                        </Typography>
                        {audits.failed.map((audit, i) => (
                            <Accordion key={i} sx={{ bgcolor: 'rgba(255, 78, 66, 0.05)', '&:before': { display: 'none' }, mb: 0.5 }}>
                                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                                        <ErrorIcon sx={{ color: '#ff4e42' }} fontSize="small" />
                                        <Typography sx={{ flex: 1, fontSize: '0.9rem' }}>{audit.title}</Typography>
                                        {audit.displayValue && (
                                            <Typography variant="body2" color="text.secondary">{audit.displayValue}</Typography>
                                        )}
                                    </Box>
                                </AccordionSummary>
                                <AccordionDetails>
                                    <Typography variant="body2" color="text.secondary">
                                        {audit.description?.replace(/<[^>]*>/g, ' ').substring(0, 200)}...
                                    </Typography>
                                    {audit.details?.items && audit.details.items.length > 0 && (
                                        <List dense sx={{ mt: 1 }}>
                                            {audit.details.items.slice(0, 5).map((item: any, idx: number) => (
                                                <ListItem key={idx} sx={{ py: 0 }}>
                                                    <ListItemIcon sx={{ minWidth: 24 }}>
                                                        <CodeIcon fontSize="small" color="disabled" />
                                                    </ListItemIcon>
                                                    <ListItemText
                                                        primary={item.url?.split('/').pop() || item.label || 'Unknown'}
                                                        primaryTypographyProps={{ fontSize: '0.8rem' }}
                                                    />
                                                </ListItem>
                                            ))}
                                        </List>
                                    )}
                                </AccordionDetails>
                            </Accordion>
                        ))}
                    </Box>
                )}

                {/* Passed - Collapsible */}
                {audits.passed.length > 0 && (
                    <Box>
                        <Button
                            size="small"
                            onClick={() => setShowPassed(!showPassed)}
                            startIcon={<CheckCircleIcon sx={{ color: '#0cce6b' }} />}
                        >
                            Başarılı ({audits.passed.length}) {showPassed ? '▲' : '▼'}
                        </Button>
                        <Collapse in={showPassed}>
                            <List dense sx={{ bgcolor: 'rgba(12, 206, 107, 0.05)', borderRadius: 1, mt: 1 }}>
                                {audits.passed.map((audit, i) => (
                                    <ListItem key={i}>
                                        <ListItemIcon sx={{ minWidth: 32 }}>
                                            <CheckCircleIcon sx={{ color: '#0cce6b' }} fontSize="small" />
                                        </ListItemIcon>
                                        <ListItemText primary={audit.title} primaryTypographyProps={{ fontSize: '0.85rem' }} />
                                    </ListItem>
                                ))}
                            </List>
                        </Collapse>
                    </Box>
                )}
            </Box>
        );
    };

    return (
        <Box sx={{ p: 3 }}>
            {/* Header */}
            <Box sx={{ mb: 4 }}>
                <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <SpeedIcon color="primary" sx={{ fontSize: 36 }} />
                    Lighthouse Tarayıcı
                </Typography>
                <Typography variant="subtitle1" color="text.secondary">
                    Web sitenizin Performance, Accessibility, Best Practices ve SEO analizi
                </Typography>
            </Box>

            {/* URL Input + Settings */}
            <Card sx={{ mb: 3 }}>
                <CardContent>
                    {/* Top Row: Scan Mode + Device + URL + Button */}
                    <Box sx={{ display: 'flex', flexDirection: { xs: 'column', md: 'row' }, gap: 2, alignItems: { md: 'center' } }}>
                        {/* Scan Mode & Device Selection */}
                        <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                            <Box>
                                <Typography variant="caption" color="text.secondary" sx={{ mb: 0.5, display: 'block' }}>Mod</Typography>
                                <ToggleButtonGroup
                                    value={scanMode}
                                    exclusive
                                    onChange={(_, val) => val && setScanMode(val)}
                                    size="small"
                                    disabled={loading}
                                >
                                    <ToggleButton value="single">📄 Tek</ToggleButton>
                                    <ToggleButton value="multi">📑 Çoklu</ToggleButton>
                                </ToggleButtonGroup>
                            </Box>
                            <Box>
                                <Typography variant="caption" color="text.secondary" sx={{ mb: 0.5, display: 'block' }}>Cihaz</Typography>
                                <ToggleButtonGroup
                                    value={device}
                                    exclusive
                                    onChange={(_, val) => val && setDevice(val)}
                                    size="small"
                                    disabled={loading}
                                >
                                    <ToggleButton value="desktop"><DesktopIcon sx={{ mr: 0.5 }} fontSize="small" /> Desktop</ToggleButton>
                                    <ToggleButton value="mobile"><MobileIcon sx={{ mr: 0.5 }} fontSize="small" /> Mobile</ToggleButton>
                                </ToggleButtonGroup>
                            </Box>
                        </Box>

                        {/* URL Input */}
                        <Box sx={{ flex: 1 }}>
                            {scanMode === 'single' ? (
                                <TextField
                                    fullWidth
                                    label="Hedef URL"
                                    placeholder="https://example.com"
                                    value={targetUrl}
                                    onChange={(e) => setTargetUrl(e.target.value)}
                                    error={Boolean(targetUrl && !isValidUrl(targetUrl))}
                                    helperText={targetUrl && !isValidUrl(targetUrl) ? 'Geçerli URL girin' : ''}
                                    disabled={loading}
                                    size="small"
                                />
                            ) : (
                                <TextField
                                    fullWidth
                                    multiline
                                    rows={3}
                                    label="Hedef URL'ler (her satıra bir URL)"
                                    placeholder={`https://example.com\nhttps://example.com/about`}
                                    value={multiUrls}
                                    onChange={(e) => setMultiUrls(e.target.value)}
                                    disabled={loading}
                                    helperText={`${multiUrls.split('\n').filter(u => u.trim() && isValidUrl(u.trim())).length} geçerli URL`}
                                    size="small"
                                />
                            )}
                        </Box>

                        {/* Scan Button */}
                        <Button
                            variant="contained"
                            startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <PlayArrowIcon />}
                            onClick={runScan}
                            disabled={loading || (scanMode === 'single' ? (!targetUrl || !isValidUrl(targetUrl)) : !multiUrls.trim())}
                            sx={{ height: 40, minWidth: 150, alignSelf: { xs: 'stretch', md: 'center' } }}
                        >
                            {loading
                                ? (scanMode === 'multi' ? `${currentScanIndex}/${totalScans}` : 'Taranıyor...')
                                : (scanMode === 'multi' ? 'Toplu Tara' : 'Taramayı Başlat')
                            }
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
                        {scanMode === 'multi' ? (
                            <>
                                <Typography variant="h6">Çoklu Tarama ({currentScanIndex}/{totalScans})</Typography>
                                <Typography variant="body2" color="text.secondary">
                                    Taranıyor: {multiUrls.split('\n').filter(u => u.trim() && isValidUrl(u.trim()))[currentScanIndex - 1] || '...'}
                                </Typography>
                                <LinearProgress
                                    variant="determinate"
                                    value={(currentScanIndex / totalScans) * 100}
                                    sx={{ mt: 2, maxWidth: 400, mx: 'auto' }}
                                />
                                <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                                    {multiResults.length} tarama tamamlandı
                                </Typography>
                            </>
                        ) : (
                            <>
                                <Typography variant="h6">Lighthouse Taraması ({device})...</Typography>
                                <Typography variant="body2" color="text.secondary">30-60 saniye sürebilir</Typography>
                                <LinearProgress sx={{ mt: 2, maxWidth: 300, mx: 'auto' }} />
                            </>
                        )}
                    </CardContent>
                </Card>
            )}

            {/* Multi Results Summary */}
            {multiResults.length > 0 && !loading && (
                <Card sx={{ mb: 3 }}>
                    <CardContent>
                        <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                            <CheckCircleIcon color="success" />
                            Çoklu Tarama Sonuçları ({multiResults.length} sayfa)
                            <Chip label={device.toUpperCase()} size="small" variant="outlined" sx={{ ml: 1 }} />
                        </Typography>

                        <Box sx={{ overflowX: 'auto' }}>
                            <Box sx={{ display: 'table', width: '100%', borderCollapse: 'collapse' }}>
                                {/* Header */}
                                <Box sx={{ display: 'table-row', bgcolor: 'action.hover' }}>
                                    <Typography sx={{ display: 'table-cell', p: 1, fontWeight: 'bold', width: '50%' }}>URL</Typography>
                                    <Typography sx={{ display: 'table-cell', p: 1, fontWeight: 'bold', textAlign: 'center' }}>Perf</Typography>
                                    <Typography sx={{ display: 'table-cell', p: 1, fontWeight: 'bold', textAlign: 'center' }}>Access</Typography>
                                    <Typography sx={{ display: 'table-cell', p: 1, fontWeight: 'bold', textAlign: 'center' }}>BP</Typography>
                                    <Typography sx={{ display: 'table-cell', p: 1, fontWeight: 'bold', textAlign: 'center' }}>SEO</Typography>
                                </Box>

                                {/* Results */}
                                {multiResults.map((r, idx) => (
                                    <Box
                                        key={idx}
                                        sx={{
                                            display: 'table-row',
                                            cursor: 'pointer',
                                            '&:hover': { bgcolor: 'action.hover' },
                                            bgcolor: selectedResultIndex === idx ? 'primary.dark' : 'transparent'
                                        }}
                                        onClick={() => {
                                            setSelectedResultIndex(idx);
                                            setResult(r);
                                        }}
                                    >
                                        <Typography sx={{ display: 'table-cell', p: 1, borderBottom: 1, borderColor: 'divider' }}>
                                            {new URL(r.url).pathname || '/'}
                                        </Typography>
                                        <Typography sx={{
                                            display: 'table-cell', p: 1, textAlign: 'center',
                                            borderBottom: 1, borderColor: 'divider',
                                            color: r.categories.performance.score >= 90 ? '#0cce6b' : r.categories.performance.score >= 50 ? '#ffa400' : '#ff4e42'
                                        }}>
                                            {r.categories.performance.score}
                                        </Typography>
                                        <Typography sx={{
                                            display: 'table-cell', p: 1, textAlign: 'center',
                                            borderBottom: 1, borderColor: 'divider',
                                            color: r.categories.accessibility.score >= 90 ? '#0cce6b' : r.categories.accessibility.score >= 50 ? '#ffa400' : '#ff4e42'
                                        }}>
                                            {r.categories.accessibility.score}
                                        </Typography>
                                        <Typography sx={{
                                            display: 'table-cell', p: 1, textAlign: 'center',
                                            borderBottom: 1, borderColor: 'divider',
                                            color: r.categories.bestPractices.score >= 90 ? '#0cce6b' : r.categories.bestPractices.score >= 50 ? '#ffa400' : '#ff4e42'
                                        }}>
                                            {r.categories.bestPractices.score}
                                        </Typography>
                                        <Typography sx={{
                                            display: 'table-cell', p: 1, textAlign: 'center',
                                            borderBottom: 1, borderColor: 'divider',
                                            color: r.categories.seo.score >= 90 ? '#0cce6b' : r.categories.seo.score >= 50 ? '#ffa400' : '#ff4e42'
                                        }}>
                                            {r.categories.seo.score}
                                        </Typography>
                                    </Box>
                                ))}
                            </Box>
                        </Box>

                        <Typography variant="caption" color="text.secondary" sx={{ mt: 2, display: 'block' }}>
                            💡 Detayları görmek için satıra tıklayın
                        </Typography>
                    </CardContent>
                </Card>
            )}

            {/* Single Result */}
            {result && (
                <>
                    {/* Scores */}
                    <Card sx={{ mb: 3 }}>
                        <CardContent>
                            <Box sx={{ display: 'flex', flexDirection: { xs: 'column', md: 'row' }, justifyContent: 'space-between', alignItems: { md: 'center' }, mb: 2, gap: 2 }}>
                                <Box>
                                    <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                        <CheckCircleIcon color="success" /> Tarama Tamamlandı
                                        <Chip label={result.device.toUpperCase()} size="small" variant="outlined" sx={{ ml: 1 }} />
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                        {result.url} • {new Date(result.fetchTime).toLocaleString('tr-TR')}
                                    </Typography>
                                </Box>
                                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                                    <Button variant="outlined" startIcon={<RefreshIcon />} onClick={runScan} size="small">
                                        Tekrar Tara
                                    </Button>
                                    <Button variant="outlined" color="success" onClick={downloadReport} size="small">
                                        📥 Rapor İndir
                                    </Button>
                                    <Button variant="contained" startIcon={<EmailIcon />} onClick={() => setEmailDialogOpen(true)} size="small">
                                        Email Gönder
                                    </Button>
                                </Box>
                            </Box>

                            {result.runWarnings?.length > 0 && (
                                <Alert severity="warning" sx={{ mb: 2 }}>
                                    {result.runWarnings.map((w, i) => <div key={i}>{w}</div>)}
                                </Alert>
                            )}

                            <Box sx={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'center', gap: 2 }}>
                                <ScoreCircle score={result.categories.performance.score} label="Performance" icon={<SpeedIcon fontSize="small" />} />
                                <ScoreCircle score={result.categories.accessibility.score} label="Accessibility" icon={<AccessibilityIcon fontSize="small" />} />
                                <ScoreCircle score={result.categories.bestPractices.score} label="Best Practices" icon={<SecurityIcon fontSize="small" />} />
                                <ScoreCircle score={result.categories.seo.score} label="SEO" icon={<SeoIcon fontSize="small" />} />
                            </Box>
                        </CardContent>
                    </Card>

                    {/* Tabs for Details */}
                    <Card sx={{ mb: 3 }}>
                        <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)} variant="scrollable" scrollButtons="auto">
                            <Tab label="Metrikler" icon={<TimerIcon />} iconPosition="start" />
                            <Tab label={`Insights (${result.insights?.length || 0})`} icon={<InsightsIcon />} iconPosition="start" />
                            <Tab label={`Diagnostics (${result.diagnostics?.length || 0})`} icon={<DiagnosticsIcon />} iconPosition="start" />
                            <Tab label="Accessibility" icon={<AccessibilityIcon />} iconPosition="start" />
                            <Tab label="Best Practices" icon={<SecurityIcon />} iconPosition="start" />
                            <Tab label="SEO" icon={<SeoIcon />} iconPosition="start" />
                        </Tabs>

                        <CardContent>
                            {/* Tab 0: Metrics */}
                            {activeTab === 0 && (
                                <Grid container spacing={2}>
                                    <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                                        <MetricCard label="First Contentful Paint (FCP)" metric={result.metrics.firstContentfulPaint} icon={<ImageIcon fontSize="small" color="primary" />} />
                                    </Grid>
                                    <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                                        <MetricCard label="Largest Contentful Paint (LCP)" metric={result.metrics.largestContentfulPaint} icon={<ImageIcon fontSize="small" color="primary" />} />
                                    </Grid>
                                    <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                                        <MetricCard label="Total Blocking Time (TBT)" metric={result.metrics.totalBlockingTime} icon={<CodeIcon fontSize="small" color="primary" />} />
                                    </Grid>
                                    <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                                        <MetricCard label="Cumulative Layout Shift (CLS)" metric={result.metrics.cumulativeLayoutShift} icon={<SpeedIcon fontSize="small" color="primary" />} />
                                    </Grid>
                                    <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                                        <MetricCard label="Speed Index" metric={result.metrics.speedIndex} icon={<SpeedIcon fontSize="small" color="primary" />} />
                                    </Grid>
                                    {result.metrics.interactive && (
                                        <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                                            <MetricCard label="Time to Interactive" metric={result.metrics.interactive} icon={<TimerIcon fontSize="small" color="primary" />} />
                                        </Grid>
                                    )}
                                </Grid>
                            )}

                            {/* Tab 1: Insights */}
                            {activeTab === 1 && (
                                <Box>
                                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                                        Chrome DevTools Performance Panel'deki öneriler
                                    </Typography>
                                    {result.insights && result.insights.length > 0 ? (
                                        result.insights.map((insight, i) => <InsightCard key={i} insight={insight} />)
                                    ) : (
                                        <Typography color="text.secondary">Insight bulunamadı</Typography>
                                    )}
                                </Box>
                            )}

                            {/* Tab 2: Diagnostics */}
                            {activeTab === 2 && (
                                <Box>
                                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                                        Performansı etkileyen sorunlar ve tasarruf önerileri
                                    </Typography>
                                    {result.diagnostics && result.diagnostics.length > 0 ? (
                                        result.diagnostics.map((diag, i) => (
                                            <Accordion key={i} sx={{ '&:before': { display: 'none' }, mb: 1 }}>
                                                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                                                        <WarningIcon color="warning" fontSize="small" />
                                                        <Typography sx={{ flex: 1 }}>{diag.title}</Typography>
                                                        {diag.savings && <Chip label={diag.savings} size="small" color="success" variant="outlined" />}
                                                    </Box>
                                                </AccordionSummary>
                                                <AccordionDetails>
                                                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                                        {diag.description?.replace(/<[^>]*>/g, ' ').substring(0, 200)}
                                                    </Typography>
                                                    {diag.items && diag.items.length > 0 && (
                                                        <List dense>
                                                            {diag.items.slice(0, 8).map((item, idx) => (
                                                                <ListItem key={idx} sx={{ py: 0 }}>
                                                                    <ListItemIcon sx={{ minWidth: 24 }}>
                                                                        <CodeIcon fontSize="small" color="disabled" />
                                                                    </ListItemIcon>
                                                                    <ListItemText
                                                                        primary={item.url?.split('/').pop() || item.label || 'Unknown'}
                                                                        secondary={item.wastedBytes ? formatBytes(item.wastedBytes) : ''}
                                                                        primaryTypographyProps={{ fontSize: '0.85rem' }}
                                                                    />
                                                                </ListItem>
                                                            ))}
                                                        </List>
                                                    )}
                                                </AccordionDetails>
                                            </Accordion>
                                        ))
                                    ) : (
                                        <Typography color="text.secondary">Diagnostic bulunamadı</Typography>
                                    )}
                                </Box>
                            )}

                            {/* Tab 3: Accessibility */}
                            {activeTab === 3 && result.categoryAudits?.accessibility && (
                                <CategoryAuditsSection
                                    title="Accessibility Denetimleri"
                                    audits={result.categoryAudits.accessibility}
                                    icon={<AccessibilityIcon color="primary" />}
                                />
                            )}

                            {/* Tab 4: Best Practices */}
                            {activeTab === 4 && result.categoryAudits?.bestPractices && (
                                <CategoryAuditsSection
                                    title="Best Practices Denetimleri"
                                    audits={result.categoryAudits.bestPractices}
                                    icon={<SecurityIcon color="primary" />}
                                />
                            )}

                            {/* Tab 5: SEO */}
                            {activeTab === 5 && result.categoryAudits?.seo && (
                                <CategoryAuditsSection
                                    title="SEO Denetimleri"
                                    audits={result.categoryAudits.seo}
                                    icon={<SeoIcon color="primary" />}
                                />
                            )}
                        </CardContent>
                    </Card>

                    {/* Screenshot */}
                    {result.finalScreenshot && (
                        <Card sx={{ mb: 3 }}>
                            <CardContent>
                                <Typography variant="h6" gutterBottom>Sayfa Ekran Görüntüsü</Typography>
                                <Box
                                    component="img"
                                    src={result.finalScreenshot}
                                    alt="Final Screenshot"
                                    sx={{ maxWidth: '100%', maxHeight: 400, borderRadius: 2, border: '1px solid', borderColor: 'divider' }}
                                />
                            </CardContent>
                        </Card>
                    )}
                </>
            )}

            {/* Email Dialog */}
            <Dialog open={emailDialogOpen} onClose={() => setEmailDialogOpen(false)} maxWidth="sm" fullWidth>
                <DialogTitle>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <EmailIcon color="primary" /> Raporu Email Gönder
                    </Box>
                </DialogTitle>
                <DialogContent>
                    <TextField
                        fullWidth
                        label="Email Adresi"
                        type="email"
                        value={emailAddress}
                        onChange={(e) => setEmailAddress(e.target.value)}
                        placeholder="ornek@ibb.gov.tr"
                        disabled={emailSending}
                        sx={{ mt: 2 }}
                    />
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => setEmailDialogOpen(false)} disabled={emailSending}>İptal</Button>
                    <Button
                        variant="contained"
                        onClick={sendEmailReport}
                        disabled={!emailAddress || emailSending}
                        startIcon={emailSending ? <CircularProgress size={20} /> : <EmailIcon />}
                    >
                        {emailSending ? 'Gönderiliyor...' : 'Gönder'}
                    </Button>
                </DialogActions>
            </Dialog>

            {/* Snackbar */}
            <Snackbar open={snackbar.open} autoHideDuration={6000} onClose={() => setSnackbar({ ...snackbar, open: false })}>
                <Alert severity={snackbar.severity} onClose={() => setSnackbar({ ...snackbar, open: false })}>
                    {snackbar.message}
                </Alert>
            </Snackbar>
        </Box>
    );
};

export default LighthouseScanner;
