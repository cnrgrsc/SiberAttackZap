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
  TextField,
  FormControlLabel,
  Switch,
  Alert,
  CircularProgress,
  Tooltip,
  Avatar,
  AvatarGroup,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Group as GroupIcon,
  Person as PersonIcon,
  Email as EmailIcon,
  People as PeopleIcon,
} from '@mui/icons-material';
import api from '../../services/api';

interface Group {
  id: string;
  name: string;
  displayName: string;
  description?: string;
  memberCount: number;
  roleCount: number;
  emailEnabled: boolean;
  emailOnScanComplete: boolean;
  emailOnVulnFound: boolean;
  emailOnVulnCritical: boolean;
  emailOnVulnHigh: boolean;
  createdAt: string;
}

const GroupManagement: React.FC = () => {
  const [groups, setGroups] = useState<Group[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Dialog states
  const [openDialog, setOpenDialog] = useState(false);
  const [editingGroup, setEditingGroup] = useState<Group | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    displayName: '',
    description: '',
    emailEnabled: true,
    emailOnScanComplete: true,
    emailOnVulnFound: false,
    emailOnVulnCritical: true,
    emailOnVulnHigh: true,
  });

  // User management states
  const [openUserDialog, setOpenUserDialog] = useState(false);
  const [selectedGroup, setSelectedGroup] = useState<Group | null>(null);
  const [allUsers, setAllUsers] = useState<any[]>([]);
  const [groupMembers, setGroupMembers] = useState<any[]>([]);

  useEffect(() => {
    fetchGroups();
  }, []);

  const fetchGroups = async () => {
    try {
      setLoading(true);
      const response = await api.get('/admin/groups');
      console.log('👥 Gruplar API response:', response.data);
      // Backend'den gelen format: {success: true, data: [...]}
      const groupsData = response.data.data || response.data;
      setGroups(Array.isArray(groupsData) ? groupsData : []);
    } catch (err: any) {
      console.error('❌ Gruplar yüklenirken hata:', err);
      setError(err.response?.data?.error || 'Gruplar yüklenirken hata oluştu');
    } finally {
      setLoading(false);
    }
  };

  const fetchAllUsers = async () => {
    try {
      const response = await api.get('/simple-auth/users');
      setAllUsers(response.data || []);
    } catch (err: any) {
      console.error('Kullanıcılar yüklenirken hata:', err);
    }
  };

  const fetchGroupMembers = async (groupId: string) => {
    try {
      const response = await api.get(`/admin/groups/${groupId}`);
      console.log('🔍 Group members response:', response.data);
      const groupData = response.data.data || response.data;
      const members = groupData?.members || [];
      console.log('👥 Members array:', members);
      // Backend'den members array'i direkt kullanıcı objesi olarak geliyor
      setGroupMembers(members);
    } catch (err: any) {
      console.error('Grup üyeleri yüklenirken hata:', err);
      setGroupMembers([]);
    }
  };

  const handleOpenUserDialog = async (group: Group) => {
    setSelectedGroup(group);
    await fetchAllUsers();
    await fetchGroupMembers(group.id);
    setOpenUserDialog(true);
  };

  const handleCloseUserDialog = () => {
    setOpenUserDialog(false);
    setSelectedGroup(null);
    setGroupMembers([]);
  };

  const handleAddUserToGroup = async (userId: string) => {
    if (!selectedGroup) return;
    
    try {
      await api.post(`/admin/groups/${selectedGroup.id}/members`, {
        userIds: [userId],
      });
      setSuccess('Kullanıcı gruba eklendi');
      await fetchGroupMembers(selectedGroup.id);
      await fetchGroups();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Kullanıcı ekleme hatası');
    }
  };

  const handleRemoveUserFromGroup = async (userId: string) => {
    if (!selectedGroup) return;
    
    try {
      await api.delete(`/admin/groups/${selectedGroup.id}/members/${userId}`);
      setSuccess('Kullanıcı gruptan çıkarıldı');
      await fetchGroupMembers(selectedGroup.id);
      await fetchGroups();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Kullanıcı çıkarma hatası');
    }
  };

  const handleOpenDialog = (group?: Group) => {
    if (group) {
      setEditingGroup(group);
      setFormData({
        name: group.name,
        displayName: group.displayName,
        description: group.description || '',
        emailEnabled: group.emailEnabled,
        emailOnScanComplete: group.emailOnScanComplete,
        emailOnVulnFound: group.emailOnVulnFound,
        emailOnVulnCritical: group.emailOnVulnCritical,
        emailOnVulnHigh: group.emailOnVulnHigh,
      });
    } else {
      setEditingGroup(null);
      setFormData({
        name: '',
        displayName: '',
        description: '',
        emailEnabled: true,
        emailOnScanComplete: true,
        emailOnVulnFound: false,
        emailOnVulnCritical: true,
        emailOnVulnHigh: true,
      });
    }
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setEditingGroup(null);
  };

  const handleSaveGroup = async () => {
    try {
      if (editingGroup) {
        await api.put(`/admin/groups/${editingGroup.id}`, formData);
        setSuccess('Grup başarıyla güncellendi');
      } else {
        await api.post('/admin/groups', formData);
        setSuccess('Grup başarıyla oluşturuldu');
      }
      handleCloseDialog();
      fetchGroups();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Grup kaydedilirken hata oluştu');
    }
  };

  const handleDeleteGroup = async (group: Group) => {
    if (!window.confirm(`"${group.displayName}" grubunu silmek istediğinize emin misiniz?`)) {
      return;
    }

    try {
      await api.delete(`/admin/groups/${group.id}`);
      setSuccess('Grup başarıyla silindi');
      fetchGroups();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Grup silinirken hata oluştu');
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Typography variant="h5" gutterBottom>
            👥 Grup Yönetimi
          </Typography>
          <Typography variant="body2" color="textSecondary">
            Kullanıcı gruplarını ve email bildirimlerini yönetin
          </Typography>
        </Box>
        <Button
          variant="contained"
          color="primary"
          startIcon={<AddIcon />}
          onClick={() => handleOpenDialog()}
        >
          Yeni Grup Ekle
        </Button>
      </Box>

      {/* Alerts */}
      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      {success && (
        <Alert severity="success" onClose={() => setSuccess(null)} sx={{ mb: 2 }}>
          {success}
        </Alert>
      )}

      {/* Groups Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell><strong>Grup Adı</strong></TableCell>
              <TableCell><strong>Açıklama</strong></TableCell>
              <TableCell align="center"><strong>Üye Sayısı</strong></TableCell>
              <TableCell align="center"><strong>Roller</strong></TableCell>
              <TableCell align="center"><strong>Email Bildirimi</strong></TableCell>
              <TableCell align="right"><strong>İşlemler</strong></TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {groups && groups.length > 0 ? (
              groups.map((group) => (
              <TableRow key={group.id}>
                <TableCell>
                  <Box display="flex" alignItems="center" gap={1}>
                    <GroupIcon fontSize="small" color="primary" />
                    <Box>
                      <Typography variant="body1" fontWeight="bold">
                        {group.displayName}
                      </Typography>
                      <Typography variant="caption" color="textSecondary">
                        {group.name}
                      </Typography>
                    </Box>
                  </Box>
                </TableCell>
                <TableCell>{group.description || '-'}</TableCell>
                <TableCell align="center">
                  <Chip
                    icon={<PersonIcon fontSize="small" />}
                    label={group.memberCount}
                    size="small"
                    color={group.memberCount > 0 ? 'primary' : 'default'}
                  />
                </TableCell>
                <TableCell align="center">
                  <Chip
                    label={group.roleCount}
                    size="small"
                    color="success"
                  />
                </TableCell>
                <TableCell align="center">
                  {group.emailEnabled ? (
                    <Tooltip title="Email bildirimleri aktif">
                      <Chip
                        icon={<EmailIcon fontSize="small" />}
                        label="Aktif"
                        size="small"
                        color="success"
                      />
                    </Tooltip>
                  ) : (
                    <Chip label="Pasif" size="small" color="default" />
                  )}
                </TableCell>
                <TableCell align="right">
                  <Tooltip title="Üyeleri Yönet">
                    <IconButton
                      size="small"
                      color="secondary"
                      onClick={() => handleOpenUserDialog(group)}
                    >
                      <PeopleIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Düzenle">
                    <IconButton
                      size="small"
                      color="primary"
                      onClick={() => handleOpenDialog(group)}
                    >
                      <EditIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Sil">
                    <IconButton
                      size="small"
                      color="error"
                      onClick={() => handleDeleteGroup(group)}
                    >
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  <Typography variant="body2" color="textSecondary" sx={{ py: 3 }}>
                    Henüz grup oluşturulmamış. "Yeni Grup Ekle" butonuna tıklayarak başlayın.
                  </Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Create/Edit Dialog */}
      <Dialog open={openDialog} onClose={handleCloseDialog} maxWidth="sm" fullWidth>
        <DialogTitle>
          {editingGroup ? 'Grubu Düzenle' : 'Yeni Grup Oluştur'}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Grup Adı (Kod)"
              fullWidth
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value.toLowerCase().replace(/\s/g, '_') })}
              disabled={!!editingGroup}
              required
              helperText="Örn: security_team"
            />
            <TextField
              label="Görünen Ad"
              fullWidth
              value={formData.displayName}
              onChange={(e) => setFormData({ ...formData, displayName: e.target.value })}
              required
              helperText="Örn: Güvenlik Ekibi"
            />
            <TextField
              label="Açıklama"
              fullWidth
              multiline
              rows={2}
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            />

            <Typography variant="h6" sx={{ mt: 2 }}>
              📧 Email Bildirimleri
            </Typography>

            <FormControlLabel
              control={
                <Switch
                  checked={formData.emailEnabled}
                  onChange={(e) => setFormData({ ...formData, emailEnabled: e.target.checked })}
                />
              }
              label="Email bildirimlerini etkinleştir"
            />

            {formData.emailEnabled && (
              <>
                <FormControlLabel
                  control={
                    <Switch
                      checked={formData.emailOnScanComplete}
                      onChange={(e) => setFormData({ ...formData, emailOnScanComplete: e.target.checked })}
                    />
                  }
                  label="Tarama tamamlandığında email gönder"
                />
                <FormControlLabel
                  control={
                    <Switch
                      checked={formData.emailOnVulnFound}
                      onChange={(e) => setFormData({ ...formData, emailOnVulnFound: e.target.checked })}
                    />
                  }
                  label="Zafiyet bulunduğunda email gönder"
                />
                <FormControlLabel
                  control={
                    <Switch
                      checked={formData.emailOnVulnCritical}
                      onChange={(e) => setFormData({ ...formData, emailOnVulnCritical: e.target.checked })}
                    />
                  }
                  label="Kritik zafiyet bulunduğunda email gönder"
                />
                <FormControlLabel
                  control={
                    <Switch
                      checked={formData.emailOnVulnHigh}
                      onChange={(e) => setFormData({ ...formData, emailOnVulnHigh: e.target.checked })}
                    />
                  }
                  label="Yüksek riskli zafiyet bulunduğunda email gönder"
                />
              </>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>İptal</Button>
          <Button
            variant="contained"
            onClick={handleSaveGroup}
            disabled={!formData.displayName || !formData.name}
          >
            {editingGroup ? 'Güncelle' : 'Oluştur'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* User Management Dialog */}
      <Dialog open={openUserDialog} onClose={handleCloseUserDialog} maxWidth="md" fullWidth>
        <DialogTitle>
          👥 Üye Yönetimi - {selectedGroup?.displayName}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 3 }}>
            {/* Current Members */}
            <Box>
              <Typography variant="h6" gutterBottom>
                Mevcut Üyeler ({groupMembers.length})
              </Typography>
              {groupMembers.length > 0 ? (
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                  {groupMembers.map((user) => (
                    <Box
                      key={user.id}
                      sx={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        p: 2,
                        border: '1px solid',
                        borderColor: 'divider',
                        borderRadius: 1,
                        backgroundColor: 'background.paper',
                        '&:hover': {
                          backgroundColor: 'action.hover',
                        },
                      }}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        <Avatar sx={{ bgcolor: 'primary.main' }}>
                          {user.firstName?.[0]}{user.lastName?.[0]}
                        </Avatar>
                        <Box>
                          <Typography variant="body1" fontWeight="bold">
                            {user.firstName} {user.lastName}
                          </Typography>
                          <Typography variant="body2" color="textSecondary">
                            {user.email}
                          </Typography>
                          {user.department && (
                            <Typography variant="caption" color="textSecondary">
                              📍 {user.department}
                            </Typography>
                          )}
                        </Box>
                      </Box>
                      <Button
                        size="small"
                        color="error"
                        variant="outlined"
                        onClick={() => handleRemoveUserFromGroup(user.id)}
                      >
                        Çıkar
                      </Button>
                    </Box>
                  ))}
                </Box>
              ) : (
                <Alert severity="info">
                  Bu grupta henüz üye yok
                </Alert>
              )}
            </Box>

            {/* Available Users */}
            <Box>
              <Typography variant="h6" gutterBottom>
                Üye Ekle
              </Typography>
              {allUsers.filter(u => !groupMembers.find(gm => gm.id === u.id)).length > 0 ? (
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                  {allUsers
                    .filter(u => !groupMembers.find(gm => gm.id === u.id))
                    .map((user) => (
                      <Box
                        key={user.id}
                        sx={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          p: 2,
                          border: '1px solid',
                          borderColor: 'divider',
                          borderRadius: 1,
                          backgroundColor: 'background.paper',
                          '&:hover': {
                            backgroundColor: 'action.hover',
                          },
                        }}
                      >
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                          <Avatar sx={{ bgcolor: 'secondary.main' }}>
                            {user.firstName?.[0]}{user.lastName?.[0]}
                          </Avatar>
                          <Box>
                            <Typography variant="body1" fontWeight="bold">
                              {user.firstName} {user.lastName}
                            </Typography>
                            <Typography variant="body2" color="textSecondary">
                              {user.email}
                            </Typography>
                            {user.department && (
                              <Typography variant="caption" color="textSecondary">
                                📍 {user.department}
                              </Typography>
                            )}
                          </Box>
                        </Box>
                        <Button
                          size="small"
                          color="primary"
                          variant="contained"
                          onClick={() => handleAddUserToGroup(user.id)}
                        >
                          Ekle
                        </Button>
                      </Box>
                    ))}
                </Box>
              ) : (
                <Alert severity="info">
                  Tüm kullanıcılar bu grupta
                </Alert>
              )}
            </Box>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseUserDialog}>Kapat</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default GroupManagement;
