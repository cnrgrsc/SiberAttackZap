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
  Checkbox,
  Alert,
  CircularProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Stack,
  Tooltip,
  Avatar,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  People as PeopleIcon,
  CheckCircle as CheckCircleIcon,
} from '@mui/icons-material';
import api from '../../services/api';

interface Permission {
  id: string;
  name: string;
  displayName: string;
  category: string;
  description?: string;
}

interface Role {
  id: string;
  name: string;
  displayName: string;
  description?: string;
  isSystem: boolean;
  userCount: number;
  permissionCount: number;
  permissions: Permission[];
  createdAt: string;
  updatedAt: string;
}

interface GroupedPermissions {
  [category: string]: Permission[];
}

const RoleManagement: React.FC = () => {
  const [roles, setRoles] = useState<Role[]>([]);
  const [allPermissions, setAllPermissions] = useState<GroupedPermissions>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Dialog states
  const [openDialog, setOpenDialog] = useState(false);
  const [editingRole, setEditingRole] = useState<Role | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    displayName: '',
    description: '',
    permissions: [] as string[],
  });

  // User assignment states
  const [openUserDialog, setOpenUserDialog] = useState(false);
  const [selectedRole, setSelectedRole] = useState<Role | null>(null);
  const [allUsers, setAllUsers] = useState<any[]>([]);
  const [roleUsers, setRoleUsers] = useState<any[]>([]);

  useEffect(() => {
    fetchRoles();
    fetchPermissions();
  }, []);

  const fetchRoles = async () => {
    try {
      setLoading(true);
      const response = await api.get('/admin/roles');
      console.log('📋 Roller API response:', response.data);
      // Backend'den gelen format: {success: true, data: [...]}
      const rolesData = response.data.data || response.data;
      setRoles(Array.isArray(rolesData) ? rolesData : []);
    } catch (err: any) {
      console.error('❌ Roller yüklenirken hata:', err);
      setError(err.response?.data?.error || 'Roller yüklenirken hata oluştu');
    } finally {
      setLoading(false);
    }
  };

  const fetchPermissions = async () => {
    try {
      const response = await api.get('/admin/permissions');
      const grouped = response.data.data?.grouped || {};
      setAllPermissions(grouped);
    } catch (err: any) {
      console.error('İzinler yüklenirken hata:', err);
      setError('İzinler yüklenirken hata oluştu');
      setAllPermissions({});
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

  const fetchRoleUsers = async (roleId: string) => {
    try {
      const response = await api.get(`/admin/roles/${roleId}`);
      console.log('🔍 Role users response:', response.data);
      const roleData = response.data.data || response.data;
      const users = roleData?.users || [];
      console.log('👥 Users array:', users);
      // Backend'den users array'i direkt kullanıcı objesi olarak geliyor
      setRoleUsers(users);
    } catch (err: any) {
      console.error('Rol kullanıcıları yüklenirken hata:', err);
      setRoleUsers([]);
    }
  };

  const handleOpenUserDialog = async (role: Role) => {
    setSelectedRole(role);
    await fetchAllUsers();
    await fetchRoleUsers(role.id);
    setOpenUserDialog(true);
  };

  const handleCloseUserDialog = () => {
    setOpenUserDialog(false);
    setSelectedRole(null);
    setRoleUsers([]);
  };

  const handleAssignUserToRole = async (userId: string) => {
    if (!selectedRole) return;
    
    try {
      await api.post(`/admin/users/${userId}/roles`, {
        roleId: selectedRole.id,
      });
      setSuccess('Kullanıcıya rol atandı');
      await fetchRoleUsers(selectedRole.id);
      await fetchRoles();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Rol atama hatası');
    }
  };

  const handleRemoveUserFromRole = async (userId: string) => {
    if (!selectedRole) return;
    
    try {
      await api.delete(`/admin/users/${userId}/roles/${selectedRole.id}`);
      setSuccess('Kullanıcıdan rol kaldırıldı');
      await fetchRoleUsers(selectedRole.id);
      await fetchRoles();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Rol kaldırma hatası');
    }
  };

  const handleOpenDialog = (role?: Role) => {
    if (role) {
      setEditingRole(role);
      setFormData({
        name: role.name,
        displayName: role.displayName,
        description: role.description || '',
        permissions: role.permissions.map(p => p.id),
      });
    } else {
      setEditingRole(null);
      setFormData({
        name: '',
        displayName: '',
        description: '',
        permissions: [],
      });
    }
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setEditingRole(null);
    setFormData({
      name: '',
      displayName: '',
      description: '',
      permissions: [],
    });
  };

  const handleSaveRole = async () => {
    try {
      if (editingRole) {
        // Güncelleme
        await api.put(`/admin/roles/${editingRole.id}`, {
          displayName: formData.displayName,
          description: formData.description,
        });

        // İzinleri güncelle
        await api.post(`/admin/roles/${editingRole.id}/permissions`, {
          permissionIds: formData.permissions,
        });
      } else {
        // Yeni rol
        await api.post('/admin/roles', formData);
      }

      setSuccess(editingRole ? 'Rol başarıyla güncellendi' : 'Rol başarıyla oluşturuldu');
      handleCloseDialog();
      fetchRoles();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Rol kaydedilirken hata oluştu');
    }
  };

  const handleDeleteRole = async (role: Role) => {
    if (!window.confirm(`"${role.displayName}" rolünü silmek istediğinize emin misiniz?`)) {
      return;
    }

    try {
      await api.delete(`/admin/roles/${role.id}`);
      setSuccess('Rol başarıyla silindi');
      fetchRoles();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Rol silinirken hata oluştu');
    }
  };

  const handlePermissionToggle = (permissionId: string) => {
    setFormData(prev => ({
      ...prev,
      permissions: prev.permissions.includes(permissionId)
        ? prev.permissions.filter(id => id !== permissionId)
        : [...prev.permissions, permissionId],
    }));
  };

  const getCategoryDisplayName = (category: string): string => {
    const categoryNames: { [key: string]: string } = {
      USER_MANAGEMENT: 'Kullanıcı Yönetimi',
      ROLE_MANAGEMENT: 'Rol Yönetimi',
      GROUP_MANAGEMENT: 'Grup Yönetimi',
      SCAN_MANAGEMENT: 'Tarama Yönetimi',
      REPORT_MANAGEMENT: 'Rapor Yönetimi',
      VULNERABILITY_MANAGEMENT: 'Zafiyet Yönetimi',
      EMAIL_MANAGEMENT: 'Email Yönetimi',
      SYSTEM_MANAGEMENT: 'Sistem Yönetimi',
      API_MANAGEMENT: 'API Yönetimi',
      DASHBOARD_MANAGEMENT: 'Dashboard Yönetimi',
    };
    return categoryNames[category] || category;
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
            🛡️ Rol Yönetimi
          </Typography>
          <Typography variant="body2" color="textSecondary">
            Sistem rollerini ve izinlerini yönetin
          </Typography>
        </Box>
        <Button
          variant="contained"
          color="primary"
          startIcon={<AddIcon />}
          onClick={() => handleOpenDialog()}
        >
          Yeni Rol Ekle
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

      {/* Roles Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell><strong>Rol Adı</strong></TableCell>
              <TableCell><strong>Açıklama</strong></TableCell>
              <TableCell align="center"><strong>Kullanıcı Sayısı</strong></TableCell>
              <TableCell align="center"><strong>İzin Sayısı</strong></TableCell>
              <TableCell align="center"><strong>Durum</strong></TableCell>
              <TableCell align="right"><strong>İşlemler</strong></TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {roles && roles.length > 0 ? (
              roles.map((role) => (
              <TableRow key={role.id}>
                <TableCell>
                  <Box display="flex" alignItems="center" gap={1}>
                    <SecurityIcon fontSize="small" color="primary" />
                    <Box>
                      <Typography variant="body1" fontWeight="bold">
                        {role.displayName}
                      </Typography>
                      <Typography variant="caption" color="textSecondary">
                        {role.name}
                      </Typography>
                    </Box>
                  </Box>
                </TableCell>
                <TableCell>{role.description || '-'}</TableCell>
                <TableCell align="center">
                  <Chip
                    icon={<PeopleIcon fontSize="small" />}
                    label={role.userCount}
                    size="small"
                    color={role.userCount > 0 ? 'primary' : 'default'}
                  />
                </TableCell>
                <TableCell align="center">
                  <Chip
                    icon={<CheckCircleIcon fontSize="small" />}
                    label={role.permissionCount}
                    size="small"
                    color="success"
                  />
                </TableCell>
                <TableCell align="center">
                  {role.isSystem ? (
                    <Chip label="Sistem Rolü" size="small" color="warning" />
                  ) : (
                    <Chip label="Özel Rol" size="small" color="info" />
                  )}
                </TableCell>
                <TableCell align="right">
                  <Tooltip title="Kullanıcıları Yönet">
                    <IconButton
                      size="small"
                      color="secondary"
                      onClick={() => handleOpenUserDialog(role)}
                    >
                      <PeopleIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Düzenle">
                    <IconButton
                      size="small"
                      color="primary"
                      onClick={() => handleOpenDialog(role)}
                    >
                      <EditIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                  {!role.isSystem && (
                    <Tooltip title="Sil">
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => handleDeleteRole(role)}
                        disabled={role.userCount > 0}
                      >
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  )}
                </TableCell>
              </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  <Typography variant="body2" color="textSecondary" sx={{ py: 3 }}>
                    Henüz rol oluşturulmamış. "Yeni Rol Ekle" butonuna tıklayarak başlayın.
                  </Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Create/Edit Dialog */}
      <Dialog open={openDialog} onClose={handleCloseDialog} maxWidth="md" fullWidth>
        <DialogTitle>
          {editingRole ? 'Rolü Düzenle' : 'Yeni Rol Oluştur'}
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 2 }}>
            <TextField
              label="Rol Adı (Kod)"
              fullWidth
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value.toUpperCase().replace(/\s/g, '_') })}
              disabled={!!editingRole} // Rol adı düzenlenemez
              required
              helperText="Örn: QA_ENGINEER"
            />
            
            <TextField
              label="Görünen Ad"
              fullWidth
              value={formData.displayName}
              onChange={(e) => setFormData({ ...formData, displayName: e.target.value })}
              required
              helperText="Örn: QA Mühendisi"
            />
            
            <TextField
              label="Açıklama"
              fullWidth
              multiline
              rows={2}
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            />

            {/* Permissions */}
            <Box>
              <Typography variant="h6" gutterBottom sx={{ mt: 2 }}>
                İzinler
              </Typography>
              {allPermissions && Object.keys(allPermissions).length > 0 ? (
                Object.entries(allPermissions).map(([category, permissions]) => (
                  <Accordion key={category}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography fontWeight="bold">
                        {getCategoryDisplayName(category)} ({permissions?.length || 0})
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                        {permissions?.map((permission) => (
                        <Box key={permission.id} sx={{ width: { xs: '100%', sm: 'calc(50% - 4px)' } }}>
                          <FormControlLabel
                            control={
                              <Checkbox
                                checked={formData.permissions.includes(permission.id)}
                                onChange={() => handlePermissionToggle(permission.id)}
                              />
                            }
                            label={
                              <Box>
                                <Typography variant="body2">{permission.displayName}</Typography>
                                {permission.description && (
                                  <Typography variant="caption" color="textSecondary">
                                    {permission.description}
                                  </Typography>
                                )}
                              </Box>
                            }
                          />
                        </Box>
                      )) || null}
                    </Box>
                  </AccordionDetails>
                </Accordion>
                ))
              ) : (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  İzinler yüklenemedi. Lütfen sayfayı yenileyin.
                </Alert>
              )}
            </Box>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>İptal</Button>
          <Button
            variant="contained"
            onClick={handleSaveRole}
            disabled={!formData.displayName || !formData.name}
          >
            {editingRole ? 'Güncelle' : 'Oluştur'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* User Assignment Dialog */}
      <Dialog open={openUserDialog} onClose={handleCloseUserDialog} maxWidth="md" fullWidth>
        <DialogTitle>
          👥 Kullanıcı Yönetimi - {selectedRole?.displayName}
        </DialogTitle>
        <DialogContent>
          <Stack spacing={3} sx={{ pt: 2 }}>
            {/* Current Users */}
            <Box>
              <Typography variant="h6" gutterBottom>
                Mevcut Kullanıcılar ({roleUsers.length})
              </Typography>
              {roleUsers.length > 0 ? (
                <Stack spacing={1}>
                  {roleUsers.map((user) => (
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
                        onClick={() => handleRemoveUserFromRole(user.id)}
                      >
                        Kaldır
                      </Button>
                    </Box>
                  ))}
                </Stack>
              ) : (
                <Alert severity="info">
                  Bu role henüz kullanıcı atanmamış
                </Alert>
              )}
            </Box>

            {/* Available Users */}
            <Box>
              <Typography variant="h6" gutterBottom>
                Kullanıcı Ekle
              </Typography>
              {allUsers.filter(u => !roleUsers.find(ru => ru.id === u.id)).length > 0 ? (
                <Stack spacing={1}>
                  {allUsers
                    .filter(u => !roleUsers.find(ru => ru.id === u.id))
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
                          onClick={() => handleAssignUserToRole(user.id)}
                        >
                          Ekle
                        </Button>
                      </Box>
                    ))}
                </Stack>
              ) : (
                <Alert severity="info">
                  Tüm kullanıcılar bu role atanmış
                </Alert>
              )}
            </Box>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseUserDialog}>Kapat</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default RoleManagement;
