import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
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
  Divider,
  Paper,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  IconButton,
} from '@mui/material';
import {
  Computer as ComputerIcon,
  Storage as StorageIcon,
  Code as CodeIcon,
  Web as WebIcon,
  Language as LanguageIcon,
  Build as BuildIcon,
  Refresh as RefreshIcon,
  PlayArrow as PlayArrowIcon,
  Settings as SettingsIcon,
  CheckCircle as CheckCircleIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { zapService } from '../../services/zapService';

interface TechnologyResult {
  name: string;
  type: string;
  confidence: string;
}

const TechnologyScanner: React.FC = () => {
  const navigate = useNavigate();
  const [targetUrl, setTargetUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [detectedTechnologies, setDetectedTechnologies] = useState<TechnologyResult[]>([]);
  const [scanComplete, setScanComplete] = useState(false);

  const isValidUrl = (url: string): boolean => {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  };

  const detectTechnologies = async () => {
    if (!targetUrl || !isValidUrl(targetUrl)) {
      setError('Lütfen geçerli bir URL girin');
      return;
    }

    setLoading(true);
    setError(null);
    setDetectedTechnologies([]);
    setScanComplete(false);

    try {
      const result = await zapService.detectTechnologies(targetUrl);
      console.log('📊 Result.data:', result.data);
      console.log('📊 Result.data.technologies.length:', result.data?.technologies?.length);

      if (result.data?.technologies && result.data.technologies.length > 0) {
        setDetectedTechnologies(result.data.technologies);
        setScanComplete(true);
      } else {
        setDetectedTechnologies([]);
        setError('Hiçbir teknoloji tespit edilemedi. Hedef sitede teknoloji imzaları bulunamadı.');
      }
    } catch (error) {
      console.error('❌ Technology detection failed:', error);
      setError('Teknoloji tespiti başarısız oldu. Lütfen URL\'yi kontrol edip tekrar deneyin.');
      setDetectedTechnologies([]);
    } finally {
      setLoading(false);
    }
  };

  const getIcon = (type: string) => {
    switch (type?.toLowerCase()) {
      case 'web server': return <ComputerIcon />;
      case 'database': return <StorageIcon />;
      case 'programming language': return <CodeIcon />;
      case 'javascript framework': return <WebIcon />;
      case 'cms': return <LanguageIcon />;
      default: return <BuildIcon />;
    }
  };

  const getColor = (confidence: string) => {
    switch (confidence?.toLowerCase()) {
      case 'high': return 'success';
      case 'medium': return 'warning';
      case 'low': return 'info';
      default: return 'default';
    }
  };

  const getTechnologyRecommendations = (technologies: TechnologyResult[]) => {
    const recommendations = [];
    
    if (technologies.some(t => t.name?.toLowerCase().includes('javascript') || t.type?.toLowerCase().includes('javascript'))) {
      recommendations.push({
        icon: <WebIcon color="info" />,
        title: 'AJAX Spider Kullanımı Önerilir',
        description: 'JavaScript framework tespit edildi - Dinamik içerik taraması için AJAX Spider kullanın'
      });
    }
    
    if (technologies.some(t => t.type?.toLowerCase().includes('database'))) {
      recommendations.push({
        icon: <StorageIcon color="error" />,
        title: 'Veritabanı Zafiyeti Taraması',
        description: 'Database tespit edildi - SQL Injection ve database zafiyetleri için yoğun tarama yapın'
      });
    }
    
    if (technologies.some(t => t.type?.toLowerCase().includes('cms'))) {
      recommendations.push({
        icon: <LanguageIcon color="warning" />,
        title: 'CMS Güvenlik Taraması',
        description: 'Content Management System tespit edildi - CMS specific zafiyetler için özel araçlar kullanın'
      });
    }
    
    if (technologies.some(t => t.name?.toLowerCase().includes('php'))) {
      recommendations.push({
        icon: <CodeIcon color="secondary" />,
        title: 'PHP Zafiyeti Taraması',
        description: 'PHP tespit edildi - PHP specific zafiyetler ve file inclusion saldırıları test edin'
      });
    }

    return recommendations;
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <BuildIcon color="primary" />
          🔍 Teknoloji Tarayıcısı
        </Typography>
        <Typography variant="subtitle1" color="text.secondary">
          Web sitelerinde kullanılan teknolojileri tespit edin ve güvenlik tarama stratejinizi optimize edin
        </Typography>
      </Box>

      {/* URL Input Section */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Hedef URL
          </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            Teknolojilerini tespit etmek istediğiniz web sitesinin URL'sini girin
          </Typography>
          
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'start' }}>
            <TextField
              fullWidth
              label="Target URL"
              placeholder="https://example.com"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              error={Boolean(targetUrl && !isValidUrl(targetUrl))}
              helperText={
                targetUrl && !isValidUrl(targetUrl) 
                  ? 'Lütfen geçerli bir URL girin (https:// ile başlamalı)' 
                  : 'Analiz edilecek web sitesinin ana URL\'si'
              }
              sx={{ mb: 2 }}
            />
            <Button
              variant="contained"
              startIcon={loading ? <CircularProgress size={20} /> : <PlayArrowIcon />}
              onClick={detectTechnologies}
              disabled={loading || !targetUrl || !isValidUrl(targetUrl)}
              size="large"
              sx={{ minWidth: 140, height: 56 }}
            >
              {loading ? 'Taranıyor...' : 'Teknoloji Tara'}
            </Button>
          </Box>

          {error && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {error}
              <Button 
                size="small" 
                onClick={() => setError(null)}
                sx={{ ml: 2 }}
              >
                Tamam
              </Button>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Loading State */}
      {loading && (
        <Card sx={{ mb: 3 }}>
          <CardContent sx={{ textAlign: 'center', py: 4 }}>
            <CircularProgress size={60} sx={{ mb: 2 }} />
            <Typography variant="h6" gutterBottom>
              Teknolojiler Tespit Ediliyor...
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Bu işlem birkaç saniye sürebilir. Lütfen bekleyin.
            </Typography>
          </CardContent>
        </Card>
      )}

      {/* Results Section */}
      {scanComplete && detectedTechnologies.length > 0 && (
        <>
          {/* Technology Results */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Typography variant="h6" color="success.main">
                  ✅ Teknoloji Tespiti Tamamlandı
                </Typography>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <Chip 
                    label={`${detectedTechnologies.length} teknoloji tespit edildi`}
                    color="success"
                    size="small"
                  />
                  <IconButton 
                    size="small" 
                    onClick={detectTechnologies}
                    title="Tekrar tespit et"
                  >
                    <RefreshIcon />
                  </IconButton>
                </Box>
              </Box>

              <Typography variant="body2" color="text.secondary" paragraph>
                Tespit edilen teknolojiler aşağıda listelenmiştir. Bu bilgileri kullanarak hedefe yönelik güvenlik taraması yapabilirsiniz.
              </Typography>

              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 3 }}>
                {detectedTechnologies.map((tech, index) => (
                  <Chip
                    key={index}
                    icon={getIcon(tech.type)}
                    label={`${tech.name} - ${tech.confidence}`}
                    color={getColor(tech.confidence) as any}
                    variant="outlined"
                    size="medium"
                  />
                ))}
              </Box>

              {/* Grouped Technologies */}
              <Divider sx={{ my: 2 }} />
              <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 'bold' }}>
                📋 Detaylı Teknoloji Analizi
              </Typography>
              
              {['Web Server', 'Programming Language', 'Database', 'JavaScript Framework', 'CMS', 'Session Management'].map(type => {
                const techsOfType = detectedTechnologies.filter(tech => tech.type === type);
                if (techsOfType.length === 0) return null;
                
                return (
                  <Box key={type} sx={{ mb: 2 }}>
                    <Typography variant="body1" sx={{ fontWeight: 'bold', mb: 1 }}>
                      {type}:
                    </Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, ml: 2 }}>
                      {techsOfType.map((tech, index) => (
                        <Chip
                          key={index}
                          label={`${tech.name} (${tech.confidence})`}
                          size="small"
                          variant="filled"
                          color={tech.confidence === 'High' ? 'success' : tech.confidence === 'Medium' ? 'warning' : 'info'}
                        />
                      ))}
                    </Box>
                  </Box>
                );
              })}
            </CardContent>
          </Card>

          {/* Recommendations */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                💡 Tarama Önerileri
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Tespit edilen teknolojilere göre önerilen güvenlik tarama stratejileri:
              </Typography>

              <List>
                {getTechnologyRecommendations(detectedTechnologies).map((rec, index) => (
                  <ListItem key={index}>
                    <ListItemIcon>
                      {rec.icon}
                    </ListItemIcon>
                    <ListItemText
                      primary={rec.title}
                      secondary={rec.description}
                    />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>

          {/* Action Buttons */}
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, md: 6 }}>
              <Paper sx={{ p: 3, textAlign: 'center' }}>
                <PlayArrowIcon color="primary" sx={{ fontSize: 48, mb: 1 }} />
                <Typography variant="h6" gutterBottom>
                  Otomatik Tarama Başlat
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Tespit edilen teknolojilere göre optimize edilmiş otomatik güvenlik taraması
                </Typography>
                <Button
                  variant="contained"
                  fullWidth
                  onClick={() => navigate('/automated-scan', { 
                    state: { 
                      targetUrl: targetUrl,
                      detectedTechnologies: detectedTechnologies 
                    } 
                  })}
                  sx={{ mt: 2 }}
                >
                  Otomatik Tarama Sayfasına Git
                </Button>
              </Paper>
            </Grid>
            
            <Grid size={{ xs: 12, md: 6 }}>
              <Paper sx={{ p: 3, textAlign: 'center' }}>
                <SettingsIcon color="secondary" sx={{ fontSize: 48, mb: 1 }} />
                <Typography variant="h6" gutterBottom>
                  Manuel Tarama Başlat
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Teknolojiye özgü manuel araçlar ve teknikler ile detaylı analiz
                </Typography>
                <Button
                  variant="outlined"
                  fullWidth
                  onClick={() => navigate('/manual-scan', { 
                    state: { 
                      targetUrl: targetUrl,
                      detectedTechnologies: detectedTechnologies 
                    } 
                  })}
                  sx={{ mt: 2 }}
                >
                  Manuel Tarama Sayfasına Git
                </Button>
              </Paper>
            </Grid>
          </Grid>
        </>
      )}

      {/* Info Card */}
      <Card sx={{ mt: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
            <InfoIcon color="info" />
            <Typography variant="h6">
              Teknoloji Tespiti Hakkında
            </Typography>
          </Box>
          <Typography variant="body2" color="text.secondary">
            Bu araç, web sitelerinde kullanılan teknolojileri tespit etmek için ZAP Proxy'nin pasif analiz özelliklerini kullanır. 
            HTTP header'ları, HTML içeriği ve server yanıtları analiz edilerek kullanılan web server, programlama dili, 
            veritabanı, JavaScript framework'leri ve diğer teknolojiler tespit edilir. Bu bilgiler, hedefe yönelik 
            güvenlik taraması stratejinizi optimize etmenize yardımcı olur.
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
};

export default TechnologyScanner;
