import React from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Alert,
  Button,
  Grid,
} from '@mui/material';
import {
  Settings as SettingsIcon,
  Launch as LaunchIcon,
} from '@mui/icons-material';

const Settings: React.FC = () => {
  return (
    <Box>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom>
          Settings
        </Typography>
        <Typography variant="subtitle1" color="text.secondary">
          Güvenlik platform ayarlarını yapılandırın
        </Typography>
      </Box>

      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="body2">
          Ayarlar ve yapılandırma seçenekleri yakında gelecek. Bu bölüm platform davranışını özelleştirmenize olanak tanıyacak.
        </Typography>
      </Alert>      <Grid container spacing={3}>
        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardContent>
              <SettingsIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                Coming Soon
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Settings features are under development and will be available in the next release.
              </Typography>
              <Button variant="outlined" startIcon={<LaunchIcon />}>
                Learn More
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Settings;
