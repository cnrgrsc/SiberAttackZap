import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Tabs,
  Tab,
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
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  FormControlLabel,
  Checkbox,
  InputLabel,
  Select,
  MenuItem,
  Alert,
  Avatar,  Tooltip,  LinearProgress,
} from '@mui/material';
import {
  AdminPanelSettings as AdminIcon,
  People as PeopleIcon,
  Security as SecurityIcon,
  Assignment as AssignmentIcon,
  Settings as SettingsIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Check as CheckIcon,
  Close as CloseIcon,
  Code as DeveloperIcon,
  Visibility as ViewIcon,
  Download as DownloadIcon,
  Refresh as RefreshIcon,
  History as HistoryIcon,
  Group as GroupIcon,
} from '@mui/icons-material';
import authService, { User } from '../../services/authService';
import api from '../../services/api';
import SystemSettings from './SystemSettings';
import RoleManagement from './RoleManagement';
import GroupManagement from './GroupManagement';

interface AccessRequest {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  department: string;
  reason: string;
  requestedRole: 'admin' | 'developer';
  status: 'pending' | 'approved' | 'rejected';
  requestDate: string;
  reviewedBy?: string;
  reviewDate?: string;
  reviewNotes?: string;
}

interface AuditLog {
  id: string;
  userId: string;
  action: string;
  details?: string;
  ipAddress?: string;
  userAgent?: string;
  createdAt: string;
  user: {
    username: string;
    firstName: string;
    lastName: string;
    role: string;
  };
}

interface SystemStats {
  totalUsers: number;
  activeUsers: number;
  pendingRequests: number;
  totalScans: number;
  activeScans: number;
  criticalVulnerabilities: number;
}

const AdminPanel = () => {
  const [currentTab, setCurrentTab] = useState(0);
  const [users, setUsers] = useState<User[]>([]);
  const [accessRequests, setAccessRequests] = useState<AccessRequest[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [systemStats, setSystemStats] = useState<SystemStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Dialog states
  const [showUserDialog, setShowUserDialog] = useState(false);
  const [showRequestDialog, setShowRequestDialog] = useState(false);
  const [selectedRequest, setSelectedRequest] = useState<AccessRequest | null>(null);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [dialogMode, setDialogMode] = useState<'create' | 'edit' | 'view'>('create');

  // Form states
  const [userForm, setUserForm] = useState({
    username: '',
    firstName: '',
    lastName: '',
    email: '',
    role: 'developer' as 'admin' | 'developer',
    department: '',
    password: '',
    isActive: true,
  });

  const [reviewNotes, setReviewNotes] = useState('');

  // Roles and Groups
  const [allRoles, setAllRoles] = useState<any[]>([]);
  const [allGroups, setAllGroups] = useState<any[]>([]);
  const [selectedRoleIds, setSelectedRoleIds] = useState<string[]>([]);
  const [selectedGroupIds, setSelectedGroupIds] = useState<string[]>([]);

  useEffect(() => {
    loadAdminData();
    fetchRolesAndGroups();
  }, [currentTab]); // Tab değiştiğinde de yeniden yükle

  const fetchRolesAndGroups = async () => {
    try {
      const [rolesRes, groupsRes] = await Promise.all([
        api.get('/admin/roles'),
        api.get('/admin/groups'),
      ]);
      console.log('🔐 Roles:', rolesRes.data);
      console.log('👥 Groups:', groupsRes.data);
      setAllRoles(rolesRes.data.data || rolesRes.data || []);
      setAllGroups(groupsRes.data.data || groupsRes.data || []);
    } catch (error) {
      console.error('Rol ve gruplar yüklenirken hata:', error);
    }
  };

  const loadAdminData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Kullanıcıları getir
      const userResult = await authService.getAllUsers();
      if (userResult.success && userResult.users) {
        setUsers(userResult.users);
      } else {
        console.error('❌ User fetch failed:', userResult.message);
        setError(userResult.message || 'Kullanıcılar yüklenemedi');
      }

      // Audit logları getir
      const auditResult = await authService.getAuditLogs({ limit: 100 });
      if (auditResult.success && auditResult.data) {
        // auditResult.data is already the array, not an object with logs property
        const logs = Array.isArray(auditResult.data) ? auditResult.data : [];
        setAuditLogs(logs);
      } else {
        setAuditLogs([]);
      }

      // Erişim taleplerini backend'den al
      let accessRequestsFetched: AccessRequest[] = [];
      try {
        const accessResult = await authService.getAccessRequests();
        if (accessResult.success && accessResult.data) {
          // Ensure it's an array
          accessRequestsFetched = Array.isArray(accessResult.data) ? accessResult.data : [];
        } else {
          accessRequestsFetched = [];
        }
      } catch (error) {
        console.error('❌ Error fetching access requests:', error);
        setError('Erişim talepleri yüklenirken hata oluştu');
        accessRequestsFetched = [];
      }

      // Stats hesapla
      const stats: SystemStats = {
        totalUsers: userResult.users?.length || 0,
        activeUsers: userResult.users?.filter(u => u.isActive).length || 0,
        pendingRequests: Array.isArray(accessRequestsFetched) ? accessRequestsFetched.filter(r => r.status === 'pending').length : 0,
        totalScans: 0,
        activeScans: 0,
        criticalVulnerabilities: 0,
      };
      
      setAccessRequests(accessRequestsFetched);
      setSystemStats(stats);
    } catch (error) {
      console.error('❌ LoadAdminData error:', error);
      setError('Admin panel verileri yüklenirken hata oluştu');
    } finally {
      setLoading(false);
    }
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setCurrentTab(newValue);
  };

  const handleCreateUser = () => {
    setDialogMode('create');
    setUserForm({
      username: '',
      firstName: '',
      lastName: '',
      email: '',
      role: 'developer',
      department: '',
      password: '',
      isActive: true,
    });
    setSelectedRoleIds([]);
    setSelectedGroupIds([]);
    setShowUserDialog(true);
  };

  const handleEditUser = async (user: User) => {
    setSelectedUser(user);
    setDialogMode('edit');
    setUserForm({
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      role: user.role,
      department: user.department || '',
      password: '',
      isActive: user.isActive,
    });

    // Kullanıcının mevcut rollerini ve gruplarını çek
    try {
      // Rolleri çek
      const rolesResponse = await api.get(`/admin/users/${user.id}/roles`);
      const userRoles = rolesResponse.data.data || rolesResponse.data || [];
      setSelectedRoleIds(userRoles.map((r: any) => r.roleId || r.id));

      // Grupları çek
      const groupsResponse = await api.get(`/admin/users/${user.id}/groups`);
      const userGroups = groupsResponse.data.data || groupsResponse.data || [];
      setSelectedGroupIds(userGroups.map((g: any) => g.groupId || g.id));
    } catch (error) {
      console.error('Kullanıcı rol/grup bilgileri yüklenirken hata:', error);
      setSelectedRoleIds([]);
      setSelectedGroupIds([]);
    }

    setShowUserDialog(true);
  };

  const handleCloseUserDialog = () => {
    setShowUserDialog(false);
    setSelectedUser(null);
    setDialogMode('create');
    setSelectedRoleIds([]);
    setSelectedGroupIds([]);
    setUserForm({
      username: '',
      firstName: '',
      lastName: '',
      email: '',
      role: 'admin',
      department: '',
      password: '',
      isActive: true,
    });
  };

  const handleViewRequest = (request: AccessRequest) => {
    setSelectedRequest(request);
    setReviewNotes('');
    setShowRequestDialog(true);
  };

  const handleApproveRequest = async (requestId: string) => {
    try {
      const result = await authService.approveAccessRequest(requestId);
      
      if (result.success) {
        // Reload admin data to reflect changes
        await loadAdminData();
        setShowRequestDialog(false);
        alert(`✅ ${result.message}`);
      } else {
        console.error('❌ Request approval failed:', result.message);
        setError(result.message);
      }
    } catch (error) {
      console.error('❌ Request approval error:', error);
      setError('Talep onaylanırken hata oluştu');
    }
  };

  const handleRejectRequest = async (requestId: string) => {
    try {
      const result = await authService.rejectAccessRequest(requestId, reviewNotes);
      
      if (result.success) {
        // Reload admin data to reflect changes
        await loadAdminData();
        setShowRequestDialog(false);
        alert(`ℹ️ ${result.message}`);
      } else {
        console.error('❌ Request rejection failed:', result.message);
        setError(result.message);
      }
    } catch (error) {
      console.error('❌ Request rejection error:', error);
      setError('Talep reddedilirken hata oluştu');
    }
  };

  const handleActivateUser = async (userId: string) => {
    try {
      const result = await authService.activateUser(userId);
      if (result.success) {
        setUsers(prev => 
          prev.map(user => 
            user.id === userId ? { ...user, isActive: true } : user
          )
        );
      } else {
        setError(result.message);
      }
    } catch (error) {
      setError('Kullanıcı aktif hale getirilemedi');
    }
  };

  const handleDeactivateUser = async (userId: string) => {
    try {
      const result = await authService.deactivateUser(userId);
      if (result.success) {
        setUsers(prev => 
          prev.map(user => 
            user.id === userId ? { ...user, isActive: false } : user
          )
        );
      } else {
        setError(result.message);
      }
    } catch (error) {
      setError('Kullanıcı pasif hale getirilemedi');
    }
  };

  const handleUpdateUserRole = async (userId: string, newRole: 'admin' | 'developer') => {
    try {
      const result = await authService.updateUserRole(userId, newRole);
      if (result.success) {
        setUsers(prev => 
          prev.map(user => 
            user.id === userId ? { ...user, role: newRole } : user
          )
        );
      } else {
        setError(result.message);
      }
    } catch (error) {
      setError('Kullanıcı rolü güncellenemedi');
    }
  };

  const handleSaveUser = async () => {
    try {
      if (dialogMode === 'create') {
        const result = await authService.createUser({
          username: userForm.username,
          firstName: userForm.firstName,
          lastName: userForm.lastName,
          email: userForm.email,
          role: userForm.role,
          department: userForm.department || undefined
        });

        if (result.success && result.user) {
          const userId = result.user.id;

          // Rolleri ata
          for (const roleId of selectedRoleIds) {
            try {
              await api.post(`/admin/users/${userId}/roles`, { roleId });
            } catch (err) {
              console.error('Rol atama hatası:', err);
            }
          }

          // Gruplara ekle
          for (const groupId of selectedGroupIds) {
            try {
              await api.post(`/admin/groups/${groupId}/members`, {
                userIds: [userId],
              });
            } catch (err) {
              console.error('Grup ekleme hatası:', err);
            }
          }

          setUsers(prev => [...prev, result.user!]);
          setShowUserDialog(false);
          
          setSystemStats(prev => prev ? {
            ...prev,
            totalUsers: prev.totalUsers + 1,
            activeUsers: result.user!.isActive ? prev.activeUsers + 1 : prev.activeUsers
          } : null);
          
          alert(`✅ ${result.message}`);
        } else {
          setError(result.message);
        }
      } else if (dialogMode === 'edit' && selectedUser) {
        // Kullanıcı düzenleme işlemi
        
        // Her değişikliği ayrı ayrı güncelle
        let hasChanges = false;
        let updatePromises = [];
        
        // Ad soyad değişikliği (şimdilik desteklenmiyor, sadece bilgi mesajı)
        if (userForm.firstName !== selectedUser.firstName || 
            userForm.lastName !== selectedUser.lastName || 
            userForm.email !== selectedUser.email ||
            userForm.department !== selectedUser.department) {
        }
        
        // Rol değişikliği
        if (userForm.role !== selectedUser.role) {
          updatePromises.push(
            authService.updateUserRole(selectedUser.id, userForm.role)
              .then(result => ({ type: 'role', result }))
          );
          hasChanges = true;
        }
        
        // Aktif/pasif durum değişikliği
        if (userForm.isActive !== selectedUser.isActive) {
          const statusPromise = userForm.isActive 
            ? authService.activateUser(selectedUser.id)
            : authService.deactivateUser(selectedUser.id);
          
          updatePromises.push(
            statusPromise.then(result => ({ type: 'status', result }))
          );
          hasChanges = true;
        }

        // RBAC Rol güncellemeleri
        try {
          // Mevcut rolleri çek
          const currentRolesRes = await api.get(`/admin/users/${selectedUser.id}/roles`);
          const currentRoles = (currentRolesRes.data.data || currentRolesRes.data || []).map((r: any) => r.roleId || r.id);
          
          // Eklenecek roller
          const rolesToAdd = selectedRoleIds.filter(id => !currentRoles.includes(id));
          for (const roleId of rolesToAdd) {
            await api.post(`/admin/users/${selectedUser.id}/roles`, { roleId });
          }

          // Kaldırılacak roller
          const rolesToRemove = currentRoles.filter((id: string) => !selectedRoleIds.includes(id));
          for (const roleId of rolesToRemove) {
            await api.delete(`/admin/users/${selectedUser.id}/roles/${roleId}`);
          }

          if (rolesToAdd.length > 0 || rolesToRemove.length > 0) {
            hasChanges = true;
          }
        } catch (err) {
          console.error('RBAC rol güncelleme hatası:', err);
        }

        // Grup güncellemeleri
        try {
          // Mevcut grupları çek
          const currentGroupsRes = await api.get(`/admin/users/${selectedUser.id}/groups`);
          const currentGroups = (currentGroupsRes.data.data || currentGroupsRes.data || []).map((g: any) => g.groupId || g.id);
          
          // Eklenecek gruplar
          const groupsToAdd = selectedGroupIds.filter(id => !currentGroups.includes(id));
          for (const groupId of groupsToAdd) {
            await api.post(`/admin/groups/${groupId}/members`, {
              userIds: [selectedUser.id],
            });
          }

          // Çıkarılacak gruplar
          const groupsToRemove = currentGroups.filter((id: string) => !selectedGroupIds.includes(id));
          for (const groupId of groupsToRemove) {
            await api.delete(`/admin/groups/${groupId}/members/${selectedUser.id}`);
          }

          if (groupsToAdd.length > 0 || groupsToRemove.length > 0) {
            hasChanges = true;
          }
        } catch (err) {
          console.error('Grup güncelleme hatası:', err);
        }
        
        if (hasChanges) {
          // Tüm güncellemeleri bekle
          const results = await Promise.all(updatePromises);
          
          // Sonuçları kontrol et
          const failedUpdates = results.filter(r => !r.result.success);
          
          if (failedUpdates.length === 0) {
            // Başarılı, kullanıcı listesini güncelle
            setUsers(prev => 
              prev.map(user => 
                user.id === selectedUser.id 
                  ? { 
                      ...user, 
                      role: userForm.role,
                      isActive: userForm.isActive
                    } 
                  : user
              )
            );
            
            setShowUserDialog(false);
            setSelectedUser(null);
            alert('✅ Kullanıcı başarıyla güncellendi');
            
            // Stats'ı güncelle
            setSystemStats(prev => prev ? {
              ...prev,
              activeUsers: users.filter(u => u.id === selectedUser.id ? userForm.isActive : u.isActive).length
            } : null);
          } else {
            // Bazı güncellemeler başarısız
            const errorMessages = failedUpdates.map(f => f.result.message).join(', ');
            setError(`Güncelleme hatası: ${errorMessages}`);
          }
        } else {
          setShowUserDialog(false);
          setSelectedUser(null);
          alert('ℹ️ Değişiklik yapılmadı');
        }
      }
    } catch (error) {
      console.error('❌ Save user error:', error);
      setError('Kullanıcı kaydedilirken hata oluştu');
    }
  };

  const getStatusChip = (status: string) => {
    const config = {
      pending: { label: 'Beklemede', color: 'warning' as const },
      approved: { label: 'Onaylandı', color: 'success' as const },
      rejected: { label: 'Reddedildi', color: 'error' as const },
      active: { label: 'Aktif', color: 'success' as const },
      inactive: { label: 'Pasif', color: 'default' as const },
    };
    
    const statusConfig = config[status as keyof typeof config] || { label: status, color: 'default' as const };
    return <Chip label={statusConfig.label} color={statusConfig.color} size="small" />;
  };

  const getRoleIcon = (role: string) => {
    return role === 'admin' ? <AdminIcon color="primary" /> : <DeveloperIcon color="secondary" />;
  };

  const getActionLabel = (action: string) => {
    const actions: { [key: string]: string } = {
      'LOGIN': 'Giriş',
      'LOGOUT': 'Çıkış',
      'USER_CREATED': 'Kullanıcı Oluşturdu',
      'USER_ACTIVATED': 'Kullanıcı Aktif Etti',
      'USER_DEACTIVATED': 'Kullanıcı Pasif Etti',
      'USER_ROLE_UPDATED': 'Kullanıcı Rolü Güncelledi',
    };
    return actions[action] || action;
  };

  if (loading) {
    return (
      <Box sx={{ width: '100%', mt: 2 }}>
        <LinearProgress />
        <Typography variant="h6" sx={{ textAlign: 'center', mt: 2 }}>
          Admin panel yükleniyor...
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom display="flex" alignItems="center">
          <AdminIcon sx={{ mr: 2, fontSize: 40 }} />
          Admin Panel
        </Typography>
        <Typography variant="subtitle1" color="text.secondary">
          Kullanıcı yönetimi ve sistem kontrolü
        </Typography>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}      {/* Statistics Cards */}      {systemStats && (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, mb: 4 }}>
          <Box sx={{ flex: '1 1 200px', minWidth: 200 }}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Typography color="text.secondary" variant="body2">
                    Toplam Kullanıcı
                  </Typography>
                  <PeopleIcon color="primary" />
                </Box>
                <Typography variant="h4">{systemStats.totalUsers}</Typography>                <Typography variant="body2" color="success.main">
                  {systemStats.activeUsers} aktif
                </Typography>
              </CardContent>
            </Card>
          </Box>

          <Box sx={{ flex: '1 1 200px', minWidth: 200 }}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Typography color="text.secondary" variant="body2">
                    Bekleyen Talepler
                  </Typography>
                  <AssignmentIcon color="warning" />
                </Box>
                <Typography variant="h4">{systemStats.pendingRequests}</Typography>
                <Typography variant="body2" color="text.secondary">
                  İnceleme bekliyor
                </Typography>              </CardContent>
            </Card>
          </Box>

          <Box sx={{ flex: '1 1 200px', minWidth: 200 }}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Typography color="text.secondary" variant="body2">
                    Toplam Tarama
                  </Typography>
                  <SecurityIcon color="info" />
                </Box>
                <Typography variant="h4">{systemStats.totalScans}</Typography>
                <Typography variant="body2" color="info.main">
                  {systemStats.activeScans} aktif
                </Typography>              </CardContent>
            </Card>
          </Box>

          <Box sx={{ flex: '1 1 200px', minWidth: 200 }}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Typography color="text.secondary" variant="body2">
                    Kritik Zafiyet
                  </Typography>
                  <SecurityIcon color="error" />
                </Box>
                <Typography variant="h4">{systemStats.criticalVulnerabilities}</Typography>
                <Typography variant="body2" color="error.main">
                  Acil müdahale
                </Typography>              </CardContent>
            </Card>
          </Box>

          <Box sx={{ flex: '1 1 300px', minWidth: 300 }}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                  <Typography variant="h6">Hızlı İşlemler</Typography>
                  <SettingsIcon color="primary" />
                </Box>
                <Box display="flex" gap={1}>
                  <Button
                    variant="outlined"
                    size="small"
                    startIcon={<RefreshIcon />}
                    onClick={loadAdminData}
                  >
                    Yenile
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    startIcon={<DownloadIcon />}
                  >
                    Rapor Al
                  </Button>
                </Box>              </CardContent>
            </Card>
          </Box>
        </Box>
      )}

      {/* Tabs */}
      <Card>
        <Tabs value={currentTab} onChange={handleTabChange}>
          <Tab label="Kullanıcı Yönetimi" icon={<PeopleIcon />} />
          <Tab label="Erişim Talepleri" icon={<AssignmentIcon />} />
          <Tab label="Rol Yönetimi" icon={<SecurityIcon />} />
          <Tab label="Grup Yönetimi" icon={<GroupIcon />} />
          <Tab label="Audit Logları" icon={<HistoryIcon />} />
          <Tab label="Sistem Ayarları" icon={<SettingsIcon />} />
        </Tabs>

        {/* Users Tab */}
        {currentTab === 0 && (
          <CardContent>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
              <Typography variant="h6">Kullanıcı Listesi</Typography>
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={handleCreateUser}
              >
                Yeni Kullanıcı
              </Button>
            </Box>

            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Kullanıcı</TableCell>
                    <TableCell>E-posta</TableCell>
                    <TableCell>Departman</TableCell>
                    <TableCell>Rol</TableCell>
                    <TableCell>Durum</TableCell>
                    <TableCell>Son Giriş</TableCell>
                    <TableCell>İşlemler</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {users.map((user) => (
                    <TableRow key={user.id}>
                      <TableCell>
                        <Box display="flex" alignItems="center">
                          <Avatar sx={{ mr: 2 }}>
                            {getRoleIcon(user.role)}
                          </Avatar>
                          <Box>
                            <Typography variant="subtitle2">
                              {user.firstName} {user.lastName}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              @{user.username}
                            </Typography>
                          </Box>
                        </Box>
                      </TableCell>
                      <TableCell>{user.email}</TableCell>
                      <TableCell>{user.department || 'Bilinmiyor'}</TableCell>
                      <TableCell>
                        <Chip
                          label={user.role === 'admin' ? 'Admin' : 'Developer'}
                          color={user.role === 'admin' ? 'primary' : 'secondary'}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        {getStatusChip(user.isActive ? 'active' : 'inactive')}
                      </TableCell>
                      <TableCell>
                        {user.lastLogin 
                          ? new Date(user.lastLogin).toLocaleDateString() 
                          : 'Hiç giriş yapmadı'
                        }
                      </TableCell>
                      <TableCell>
                        <Box display="flex" gap={1}>
                          <Tooltip title={user.role === 'admin' ? 'Developer Yap' : 'Admin Yap'}>
                            <IconButton
                              size="small"
                              onClick={() => handleUpdateUserRole(
                                user.id, 
                                user.role === 'admin' ? 'developer' : 'admin'
                              )}
                              color={user.role === 'admin' ? 'secondary' : 'primary'}
                            >
                              {user.role === 'admin' ? <DeveloperIcon /> : <AdminIcon />}
                            </IconButton>
                          </Tooltip>

                          <Tooltip title={user.isActive ? 'Pasif Yap' : 'Aktif Yap'}>
                            <IconButton
                              size="small"
                              onClick={() => user.isActive 
                                ? handleDeactivateUser(user.id) 
                                : handleActivateUser(user.id)
                              }
                              color={user.isActive ? 'error' : 'success'}
                            >
                              {user.isActive ? <CloseIcon /> : <CheckIcon />}
                            </IconButton>
                          </Tooltip>

                          <Tooltip title="Düzenle">
                            <IconButton
                              size="small"
                              onClick={() => handleEditUser(user)}
                            >
                              <EditIcon />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        )}

        {/* Access Requests Tab */}
        {currentTab === 1 && (
          <CardContent>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
              <Typography variant="h6">
                Erişim Talepleri
              </Typography>
              <Button
                variant="outlined"
                startIcon={<RefreshIcon />}
                onClick={loadAdminData}
                disabled={loading}
              >
                Yenile
              </Button>
            </Box>

            {accessRequests.length === 0 ? (
              <Box textAlign="center" py={4}>
                <Typography variant="body2" color="text.secondary">
                  Henüz erişim talebi bulunmuyor
                </Typography>
              </Box>
            ) : (
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Talep Eden</TableCell>
                      <TableCell>Departman</TableCell>
                      <TableCell>Talep Edilen Rol</TableCell>
                      <TableCell>Durum</TableCell>
                      <TableCell>Tarih</TableCell>
                      <TableCell>İşlemler</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {accessRequests.map((request) => (
                      <TableRow key={request.id}>
                        <TableCell>
                          <Box>
                            <Typography variant="subtitle2">
                              {request.firstName} {request.lastName}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {request.email}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>{request.department}</TableCell>
                        <TableCell>
                          <Chip
                            label={request.requestedRole === 'admin' ? 'Admin' : 'Developer'}
                            color={request.requestedRole === 'admin' ? 'primary' : 'secondary'}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>{getStatusChip(request.status)}</TableCell>
                        <TableCell>
                          {new Date(request.requestDate).toLocaleDateString()}
                        </TableCell>
                        <TableCell>
                          <Tooltip title="İncele">
                            <IconButton
                              size="small"
                              onClick={() => handleViewRequest(request)}
                            >
                              <ViewIcon />
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </CardContent>
        )}

        {/* Role Management Tab */}
        {currentTab === 2 && (
          <CardContent>
            <RoleManagement />
          </CardContent>
        )}

        {/* Group Management Tab */}
        {currentTab === 3 && (
          <CardContent>
            <GroupManagement />
          </CardContent>
        )}

        {/* Audit Logs Tab */}
        {currentTab === 4 && (
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Audit Logları
            </Typography>

            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Kullanıcı</TableCell>
                    <TableCell>İşlem</TableCell>
                    <TableCell>Detaylar</TableCell>
                    <TableCell>IP Adresi</TableCell>
                    <TableCell>Tarih</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {auditLogs.map((log) => (
                    <TableRow key={log.id}>
                      <TableCell>
                        <Box>
                          <Typography variant="subtitle2">
                            {log.user.firstName} {log.user.lastName}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            @{log.user.username} ({log.user.role})
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={getActionLabel(log.action)}
                          size="small"
                          color={log.action.includes('LOGIN') ? 'success' : 'default'}
                        />
                      </TableCell>
                      <TableCell>
                        {log.details ? (
                          <Tooltip title={log.details}>
                            <Typography variant="body2" sx={{ 
                              maxWidth: 200, 
                              overflow: 'hidden', 
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap'
                            }}>
                              {JSON.parse(log.details).success ? 'Başarılı' : 'Başarısız'}
                            </Typography>
                          </Tooltip>
                        ) : '-'}
                      </TableCell>
                      <TableCell>{log.ipAddress || '-'}</TableCell>
                      <TableCell>
                        {new Date(log.createdAt).toLocaleString()}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        )}

        {/* System Settings Tab */}
        {currentTab === 5 && (
          <CardContent>
            <SystemSettings />
          </CardContent>
        )}
      </Card>

      {/* Access Request Review Dialog */}
      <Dialog
        open={showRequestDialog}
        onClose={() => setShowRequestDialog(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Erişim Talebi İncelemesi</DialogTitle>
        <DialogContent>
          {selectedRequest && (
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Talep Eden: {selectedRequest.firstName} {selectedRequest.lastName}
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                E-posta: {selectedRequest.email}
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Departman: {selectedRequest.department}
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                Talep Edilen Rol: {selectedRequest.requestedRole === 'admin' ? 'Admin' : 'Developer'}
              </Typography>
              <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
                Gerekçe:
              </Typography>
              <Typography variant="body2" paragraph>
                {selectedRequest.reason}
              </Typography>
              
              <TextField
                fullWidth
                label="İnceleme Notu"
                multiline
                rows={3}
                value={reviewNotes}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setReviewNotes(e.target.value)}
                placeholder="Onay/ret gerekçenizi yazınız..."
                sx={{ mt: 2 }}
              />
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowRequestDialog(false)}>
            İptal
          </Button>
          <Button
            variant="outlined"
            color="error"
            startIcon={<CloseIcon />}
            onClick={() => selectedRequest && handleRejectRequest(selectedRequest.id)}
          >
            Reddet
          </Button>
          <Button
            variant="contained"
            color="success"
            startIcon={<CheckIcon />}
            onClick={() => selectedRequest && handleApproveRequest(selectedRequest.id)}
          >
            Onayla
          </Button>
        </DialogActions>
      </Dialog>

      {/* User Create/Edit Dialog */}
      <Dialog
        open={showUserDialog}
        onClose={handleCloseUserDialog}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          {dialogMode === 'create' ? 'Yeni Kullanıcı Oluştur' : 'Kullanıcı Düzenle'}
        </DialogTitle>        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
                <TextField
                  fullWidth
                  label="Kullanıcı Adı"
                  value={userForm.username}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUserForm(prev => ({ ...prev, username: e.target.value }))}
                  disabled={dialogMode === 'edit'}
                  required
                />
              <Box sx={{ display: 'flex', gap: 2 }}>
                <TextField
                  fullWidth
                  label="Ad"                  value={userForm.firstName}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUserForm(prev => ({ ...prev, firstName: e.target.value }))}
                  required
                />
                <TextField
                  fullWidth
                  label="Soyad"
                  value={userForm.lastName}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUserForm(prev => ({ ...prev, lastName: e.target.value }))}
                  required                />
              </Box>
              <TextField
                  fullWidth
                  label="E-posta"
                  type="email"
                  value={userForm.email}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUserForm(prev => ({ ...prev, email: e.target.value }))}
                  required                />
              <Box sx={{ display: 'flex', gap: 2 }}>
                <FormControl fullWidth required>
                  <InputLabel>Rol (Eski)</InputLabel>
                  <Select
                    value={userForm.role}
                    label="Rol (Eski)"
                    onChange={(e: any) => setUserForm(prev => ({ ...prev, role: e.target.value as 'admin' | 'developer' }))}
                  >
                    <MenuItem value="developer">Developer</MenuItem>
                    <MenuItem value="admin">Admin</MenuItem>
                  </Select>
                </FormControl>
                <TextField
                  fullWidth
                  label="Departman"
                  value={userForm.department}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUserForm(prev => ({ ...prev, department: e.target.value }))}
                />
              </Box>

              {/* RBAC Rolleri - Hem create hem edit için */}
              <FormControl fullWidth>
                <InputLabel>Roller (RBAC)</InputLabel>
                <Select
                  multiple
                  value={selectedRoleIds}
                  onChange={(e) => setSelectedRoleIds(e.target.value as string[])}
                  label="Roller (RBAC)"
                  renderValue={(selected) => (
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                      {selected.map((value) => {
                        const role = allRoles.find(r => r.id === value);
                        return <Chip key={value} label={role?.displayName || value} size="small" />;
                      })}
                    </Box>
                  )}
                >
                  {allRoles.map((role) => (
                    <MenuItem key={role.id} value={role.id}>
                      <Checkbox checked={selectedRoleIds.indexOf(role.id) > -1} />
                      {role.displayName} - {role.description}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              {/* Gruplar - Hem create hem edit için */}
              <FormControl fullWidth>
                <InputLabel>Gruplar</InputLabel>
                <Select
                  multiple
                  value={selectedGroupIds}
                  onChange={(e) => setSelectedGroupIds(e.target.value as string[])}
                  label="Gruplar"
                  renderValue={(selected) => (
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                      {selected.map((value) => {
                        const group = allGroups.find(g => g.id === value);
                        return <Chip key={value} label={group?.displayName || value} size="small" />;
                      })}
                    </Box>
                  )}
                >
                  {allGroups.map((group) => (
                    <MenuItem key={group.id} value={group.id}>
                      <Checkbox checked={selectedGroupIds.indexOf(group.id) > -1} />
                      {group.displayName} - {group.description}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              {dialogMode === 'create' && (
                <>
                  {/* Bu alan artık gereksiz, yukarıda zaten var */}
                </>
              )}
              {dialogMode === 'edit' && (
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <FormControlLabel
                    control={
                      <Checkbox
                        checked={userForm.isActive}
                        onChange={(e: React.ChangeEvent<HTMLInputElement>) => 
                          setUserForm(prev => ({ ...prev, isActive: e.target.checked }))}
                      />
                    }
                    label="Kullanıcı Aktif"
                  />
                </Box>
              )}
              {dialogMode === 'create' && (
                <Alert severity="info">
                    <Typography variant="body2">
                      <Box component="span" fontWeight="bold">Not:</Box> Kullanıcı LDAP sistemi üzerinden giriş yapacaktır. 
                      Burada sadece sisteme kayıt edilmekte ve yetkilendirilmektedir.
                    </Typography>                  </Alert>
              )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseUserDialog}>
            İptal
          </Button>
          <Button
            variant="contained"
            onClick={handleSaveUser}
            disabled={!userForm.username || !userForm.firstName || !userForm.lastName || !userForm.email}
          >
            {dialogMode === 'create' ? 'Oluştur' : 'Güncelle'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default AdminPanel;