import React, { useState, useEffect } from 'react';
import {
    Box,
    Card,
    CardContent,
    Typography,
    TextField,
    Button,
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
    List,
    ListItem,
    ListItemText,
    ListItemSecondaryAction,
    IconButton,
    Chip,
    Alert,
    CircularProgress,
    FormControlLabel,
    Switch,
    Tooltip,
    Divider,
} from '@mui/material';
import {
    Add as AddIcon,
    Delete as DeleteIcon,
    Edit as EditIcon,
    PlayArrow as ScanIcon,
    Visibility as VisibilityIcon,
    VisibilityOff as VisibilityOffIcon,
    Folder as FolderIcon,
} from '@mui/icons-material';
import { zapService } from '../../services/zapService';

interface SavedRepository {
    id: string;
    name: string;
    repoUrl: string;
    username: string;
    maskedToken: string;
    branch: string;
    scanCount: number;
    lastUsed: string;
    createdAt: string;
}

interface SavedRepositoriesProps {
    onScan: (repoId: string) => void;
}

const SavedRepositories: React.FC<SavedRepositoriesProps> = ({ onScan }) => {
    const [repositories, setRepositories] = useState<SavedRepository[]>([]);
    const [loading, setLoading] = useState(false);
    const [dialogOpen, setDialogOpen] = useState(false);
    const [editingRepo, setEditingRepo] = useState<SavedRepository | null>(null);

    // Form states
    const [formData, setFormData] = useState({
        name: '',
        repoUrl: '',
        username: '',
        password: '',
        branch: 'main',
    });
    const [showPassword, setShowPassword] = useState(false);

    useEffect(() => {
        loadRepositories();
    }, []);

    const loadRepositories = async () => {
        setLoading(true);
        try {
            const response = await zapService.getUserRepositories();
            setRepositories(response.data || []);
        } catch (error) {
            console.error('Failed to load repositories:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleOpenDialog = (repo?: SavedRepository) => {
        if (repo) {
            setEditingRepo(repo);
            setFormData({
                name: repo.name,
                repoUrl: repo.repoUrl,
                username: repo.username,
                password: '', // Don't populate password for security
                branch: repo.branch,
            });
        } else {
            setEditingRepo(null);
            setFormData({
                name: '',
                repoUrl: '',
                username: '',
                password: '',
                branch: 'main',
            });
        }
        setDialogOpen(true);
    };

    const handleCloseDialog = () => {
        setDialogOpen(false);
        setEditingRepo(null);
        setFormData({
            name: '',
            repoUrl: '',
            username: '',
            password: '',
            branch: 'main',
        });
        setShowPassword(false);
    };

    const handleSave = async () => {
        try {
            if (editingRepo) {
                // Update existing repository
                await zapService.updateRepository(editingRepo.id, {
                    name: formData.name,
                    username: formData.username,
                    password: formData.password || undefined,
                    branch: formData.branch,
                });
            } else {
                // Create new repository
                await zapService.saveGitRepository(
                    formData.name,
                    formData.repoUrl,
                    formData.username,
                    formData.password,
                    formData.branch
                );
            }

            handleCloseDialog();
            loadRepositories();
        } catch (error: any) {
            console.error('Failed to save repository:', error);
            alert(error.response?.data?.error?.message || 'Failed to save repository');
        }
    };

    const handleDelete = async (repoId: string) => {
        if (!window.confirm('Bu repository\'yi silmek istediğinize emin misiniz?')) {
            return;
        }

        try {
            await zapService.deleteRepository(repoId);
            loadRepositories();
        } catch (error: any) {
            console.error('Failed to delete repository:', error);
            alert(error.response?.data?.error?.message || 'Failed to delete repository');
        }
    };

    const formatDate = (dateString: string) => {
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now.getTime() - date.getTime();
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);

        if (diffMins < 60) return `${diffMins} dakika önce`;
        if (diffHours < 24) return `${diffHours} saat önce`;
        if (diffDays < 7) return `${diffDays} gün önce`;
        return date.toLocaleDateString('tr-TR');
    };

    return (
        <Box>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                <Typography variant="h6">
                    <FolderIcon sx={{ verticalAlign: 'middle', mr: 1 }} />
                    Kayıtlı Repository'ler
                </Typography>
                <Button
                    variant="contained"
                    startIcon={<AddIcon />}
                    onClick={() => handleOpenDialog()}
                >
                    Yeni Ekle
                </Button>
            </Box>

            {loading ? (
                <Box display="flex" justifyContent="center" p={3}>
                    <CircularProgress />
                </Box>
            ) : repositories.length === 0 ? (
                <Alert severity="info">
                    Henüz kayıtlı repository yok. "Yeni Ekle" butonuna tıklayarak başlayın!
                </Alert>
            ) : (
                <List>
                    {repositories.map((repo) => (
                        <Card key={repo.id} sx={{ mb: 2 }}>
                            <CardContent>
                                <Box display="flex" justifyContent="space-between" alignItems="flex-start">
                                    <Box flex={1}>
                                        <Typography variant="h6" gutterBottom>
                                            {repo.name}
                                        </Typography>
                                        <Typography variant="body2" color="text.secondary" gutterBottom>
                                            {repo.repoUrl}
                                        </Typography>
                                        <Box mt={1}>
                                            <Chip
                                                label={`Branch: ${repo.branch}`}
                                                size="small"
                                                sx={{ mr: 1 }}
                                            />
                                            <Chip
                                                label={`${repo.scanCount} tarama`}
                                                size="small"
                                                color="primary"
                                                sx={{ mr: 1 }}
                                            />
                                            <Typography variant="caption" color="text.secondary">
                                                Son kullanım: {formatDate(repo.lastUsed)}
                                            </Typography>
                                        </Box>
                                    </Box>
                                    <Box>
                                        <Tooltip title="Hızlı Tarama">
                                            <IconButton
                                                color="success"
                                                onClick={() => onScan(repo.id)}
                                            >
                                                <ScanIcon />
                                            </IconButton>
                                        </Tooltip>
                                        <Tooltip title="Düzenle">
                                            <IconButton
                                                color="primary"
                                                onClick={() => handleOpenDialog(repo)}
                                            >
                                                <EditIcon />
                                            </IconButton>
                                        </Tooltip>
                                        <Tooltip title="Sil">
                                            <IconButton
                                                color="error"
                                                onClick={() => handleDelete(repo.id)}
                                            >
                                                <DeleteIcon />
                                            </IconButton>
                                        </Tooltip>
                                    </Box>
                                </Box>
                            </CardContent>
                        </Card>
                    ))}
                </List>
            )}

            {/* Add/Edit Dialog */}
            <Dialog open={dialogOpen} onClose={handleCloseDialog} maxWidth="sm" fullWidth>
                <DialogTitle>
                    {editingRepo ? 'Repository Düzenle' : 'Yeni Repository Ekle'}
                </DialogTitle>
                <DialogContent>
                    <Box sx={{ pt: 2 }}>
                        <TextField
                            fullWidth
                            label="Repository Adı"
                            value={formData.name}
                            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                            margin="normal"
                            required
                            helperText="Örn: My Private API"
                        />
                        <TextField
                            fullWidth
                            label="Git URL"
                            value={formData.repoUrl}
                            onChange={(e) => setFormData({ ...formData, repoUrl: e.target.value })}
                            margin="normal"
                            required
                            disabled={!!editingRepo}
                            helperText="Örn: https://gitlab.com/username/project.git"
                        />
                        <TextField
                            fullWidth
                            label="Kullanıcı Adı / Email"
                            value={formData.username}
                            onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                            margin="normal"
                            required
                        />
                        <TextField
                            fullWidth
                            label="Şifre / Personal Access Token"
                            type={showPassword ? 'text' : 'password'}
                            value={formData.password}
                            onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                            margin="normal"
                            required={!editingRepo}
                            helperText={editingRepo ? 'Boş bırakırsanız mevcut şifre korunur' : 'Personal Access Token önerilir'}
                            InputProps={{
                                endAdornment: (
                                    <IconButton
                                        onClick={() => setShowPassword(!showPassword)}
                                        edge="end"
                                    >
                                        {showPassword ? <VisibilityOffIcon /> : <VisibilityIcon />}
                                    </IconButton>
                                )
                            }}
                        />
                        <TextField
                            fullWidth
                            label="Branch"
                            value={formData.branch}
                            onChange={(e) => setFormData({ ...formData, branch: e.target.value })}
                            margin="normal"
                            helperText="Varsayılan: main"
                        />

                        <Alert severity="warning" sx={{ mt: 2 }}>
                            <strong>Güvenlik Notu:</strong> Şifreniz AES-256-GCM ile şifrelenerek saklanır.
                            Yine de Personal Access Token kullanmanız önerilir.
                        </Alert>
                    </Box>
                </DialogContent>
                <DialogActions>
                    <Button onClick={handleCloseDialog}>İptal</Button>
                    <Button
                        onClick={handleSave}
                        variant="contained"
                        disabled={!formData.name || !formData.repoUrl || !formData.username || (!formData.password && !editingRepo)}
                    >
                        {editingRepo ? 'Güncelle' : 'Kaydet'}
                    </Button>
                </DialogActions>
            </Dialog>
        </Box>
    );
};

export default SavedRepositories;
