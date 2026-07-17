import React, { useState, useEffect } from 'react';
import api from '../../api';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Badge } from '../ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';
import { Alert, AlertDescription } from '../ui/alert';
import { toast } from 'sonner';
import { Users, Trash2, Shield, Edit, Plus, AlertTriangle, Download, Mail, Send, History } from 'lucide-react';

const UserManagement = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showResetPasswordDialog, setShowResetPasswordDialog] = useState(false);
  const [showDeleteConfirmDialog, setShowDeleteConfirmDialog] = useState(false);
  const [deleteStep, setDeleteStep] = useState(1);
  const [selectedUser, setSelectedUser] = useState(null);
  const [tempPasswordData, setTempPasswordData] = useState(null);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');

  // Create user form state
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('user');
  const [newEmail, setNewEmail] = useState('');
  const [creating, setCreating] = useState(false);

  // Edit user form state
  const [editPassword, setEditPassword] = useState('');
  const [editPasswordConfirm, setEditPasswordConfirm] = useState('');
  const [editRole, setEditRole] = useState('user');
  const [editIsActive, setEditIsActive] = useState(true);
  const [editEmail, setEditEmail] = useState('');
  const [updating, setUpdating] = useState(false);

  // Manual system backup (export/import)
  const [exportingBackup, setExportingBackup] = useState(false);
  const [importingBackup, setImportingBackup] = useState(false);
  const [preRestoreBackups, setPreRestoreBackups] = useState([]);
  const [loadingPreRestoreBackups, setLoadingPreRestoreBackups] = useState(false);

  // Automatic backup e-mail schedule
  const [backupSchedule, setBackupSchedule] = useState({
    enabled: false,
    frequency: 'daily',
    recipient_email: '',
    last_run_at: null,
    last_status: null,
    last_error: null
  });
  const [loadingSchedule, setLoadingSchedule] = useState(true);
  const [savingSchedule, setSavingSchedule] = useState(false);
  const [sendingTestMail, setSendingTestMail] = useState(false);

  const handleCleanupOrphanedData = async () => {
    const confirmed = window.confirm(
      'WARNUNG: Verwaiste Daten löschen?\n\n' +
      'Dies löscht alle iPads, Schüler, Zuordnungen und Verträge,\n' +
      'die zu gelöschten Benutzern gehören.\n\n' +
      'Dies ist sicher und macht gelöschte ITNr wieder verfügbar.\n\n' +
      'Fortfahren?'
    );

    if (!confirmed) return;

    try {
      toast.info('Cleanup wird ausgeführt...');
      const response = await api.post('/admin/cleanup-orphaned-data');

      const { deleted_resources, details } = response.data;

      toast.success(
        `Cleanup abgeschlossen!\n` +
        `iPads: ${deleted_resources.ipads}\n` +
        `Schüler: ${deleted_resources.students}\n` +
        `Zuordnungen: ${deleted_resources.assignments}\n` +
        `Verträge: ${deleted_resources.contracts}`
      );

      if (details.total_orphaned_ipads > 0) {
        console.log('Gelöschte iPad ITNr:', details.orphaned_ipad_itnrs);
      }

    } catch (error) {
      console.error('Cleanup error:', error);
      toast.error(error.response?.data?.detail || 'Fehler beim Cleanup');
    }
  };

  const loadUsers = async () => {
    try {
      const response = await api.get('/admin/users');
      setUsers(response.data);
    } catch (error) {
      toast.error('Fehler beim Laden der Benutzer');
      console.error('Users loading error:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadBackupSchedule = async () => {
    setLoadingSchedule(true);
    try {
      const response = await api.get('/settings/backup-schedule');
      setBackupSchedule(response.data);
    } catch (error) {
      console.error('Failed to load backup schedule:', error);
    } finally {
      setLoadingSchedule(false);
    }
  };

  const loadPreRestoreBackups = async () => {
    setLoadingPreRestoreBackups(true);
    try {
      const response = await api.get('/backup/pre-restore-backups');
      setPreRestoreBackups(response.data);
    } catch (error) {
      console.error('Failed to load pre-restore backups:', error);
    } finally {
      setLoadingPreRestoreBackups(false);
    }
  };

  const prefillScheduleEmail = async () => {
    try {
      const response = await api.get('/auth/me');
      if (response.data.email) {
        setBackupSchedule((prev) => (prev.recipient_email ? prev : { ...prev, recipient_email: response.data.email }));
      }
    } catch (error) {
      // Ignore - prefill is a convenience, not required
    }
  };

  useEffect(() => {
    loadUsers();
    loadBackupSchedule();
    loadPreRestoreBackups();
    prefillScheduleEmail();
  }, []);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    setCreating(true);

    try {
      await api.post('/admin/users', {
        username: newUsername,
        password: newPassword,
        role: newRole,
        email: newEmail || undefined
      });
      toast.success(`Benutzer ${newUsername} erfolgreich erstellt!`);
      setShowCreateDialog(false);
      setNewUsername('');
      setNewPassword('');
      setNewRole('user');
      setNewEmail('');
      await loadUsers();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Erstellen des Benutzers');
      console.error('User creation error:', error);
    } finally {
      setCreating(false);
    }
  };

  const handleUpdateUser = async (e) => {
    e.preventDefault();
    if (!selectedUser) return;

    if (editPassword && editPassword !== editPasswordConfirm) {
      toast.error('Die Passwörter stimmen nicht überein');
      return;
    }

    if (editPassword && editPassword.length < 6) {
      toast.error('Das Passwort muss mindestens 6 Zeichen lang sein');
      return;
    }

    setUpdating(true);

    try {
      const updateData = {
        role: editRole,
        is_active: editIsActive,
        email: editEmail || undefined
      };

      if (editPassword) {
        updateData.password = editPassword;
      }

      await api.put(`/admin/users/${selectedUser.id}`, updateData);
      toast.success(`Benutzer ${selectedUser.username} erfolgreich aktualisiert!`);
      setShowEditDialog(false);
      setSelectedUser(null);
      setEditPassword('');
      setEditPasswordConfirm('');
      await loadUsers();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Aktualisieren des Benutzers');
      console.error('User update error:', error);
    } finally {
      setUpdating(false);
    }
  };

  const handleBackupExport = async () => {
    setExportingBackup(true);
    try {
      const response = await api.get('/backup/export', {
        responseType: 'blob'
      });

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;

      const contentDisposition = response.headers['content-disposition'];
      let filename = 'rbbk_ipad_verwaltung_backup.json';
      if (contentDisposition) {
        const matches = contentDisposition.match(/filename="(.+)"/);
        if (matches) {
          filename = matches[1];
        }
      }

      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(link);

      toast.success('Komplettes System-Backup erfolgreich exportiert');
    } catch (error) {
      console.error('Failed to export backup:', error);
      toast.error('Fehler beim Exportieren des Backups');
    } finally {
      setExportingBackup(false);
    }
  };

  const handleBackupImport = async (file) => {
    if (!file) return;

    // Safety check
    if (!window.confirm("ACHTUNG: Das Einspielen eines Backups überschreibt ALLE aktuellen Daten im System. Vor der Wiederherstellung wird automatisch ein Sicherheits-Backup der aktuellen Daten angelegt. Möchten Sie wirklich fortfahren?")) {
      return;
    }

    setImportingBackup(true);
    try {
      const formData = new FormData();
      formData.append('file', file);

      toast.info('System-Backup wird wiederhergestellt...');

      const response = await api.post('/backup/import', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });

      toast.success(response.data.message);
      await loadPreRestoreBackups();

    } catch (error) {
      console.error('Failed to import backup:', error);
      toast.error(error.response?.data?.detail || 'Fehler beim Wiederherstellen des Backups');
      await loadPreRestoreBackups();
    } finally {
      setImportingBackup(false);
    }
  };

  const handleDownloadPreRestoreBackup = async (filename) => {
    try {
      const response = await api.get(`/backup/pre-restore-backups/${filename}/download`, {
        responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(link);
    } catch (error) {
      toast.error('Fehler beim Herunterladen des Sicherheits-Backups');
    }
  };

  const handleSaveBackupSchedule = async () => {
    if (backupSchedule.enabled && !backupSchedule.recipient_email) {
      toast.error('Bitte eine Ziel-E-Mail-Adresse angeben');
      return;
    }

    setSavingSchedule(true);
    try {
      const response = await api.put('/settings/backup-schedule', {
        enabled: backupSchedule.enabled,
        frequency: backupSchedule.frequency,
        recipient_email: backupSchedule.recipient_email || undefined
      });
      toast.success(response.data.message);
      await loadBackupSchedule();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Speichern des Backup-Zeitplans');
    } finally {
      setSavingSchedule(false);
    }
  };

  const handleSendTestMail = async () => {
    if (!backupSchedule.recipient_email) {
      toast.error('Bitte eine Ziel-E-Mail-Adresse angeben');
      return;
    }

    setSendingTestMail(true);
    try {
      const response = await api.post('/backup/send-now', {
        recipient_email: backupSchedule.recipient_email
      });
      toast.success(response.data.message);
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Senden der Test-Mail');
    } finally {
      setSendingTestMail(false);
    }
  };

  const handleDeleteUser = async (user) => {
    if (window.confirm(`Möchten Sie den Benutzer "${user.username}" wirklich deaktivieren?`)) {
      try {
        const response = await api.delete(`/admin/users/${user.id}`);
        toast.success(response.data.message);
        await loadUsers();
      } catch (error) {
        toast.error(error.response?.data?.detail || 'Fehler beim Deaktivieren des Benutzers');
        console.error('User deletion error:', error);
      }
    }
  };

  const handleCompleteDeleteUser = (user) => {
    setSelectedUser(user);
    setDeleteStep(1);
    setDeleteConfirmText('');
    setShowDeleteConfirmDialog(true);
  };

  const handleDeleteStep1Confirm = async () => {
    try {
      const [ipadsRes, studentsRes, assignmentsRes] = await Promise.all([
        api.get('/ipads'),
        api.get('/students'),
        api.get('/assignments')
      ]);

      const userIpads = ipadsRes.data.filter(i => i.user_id === selectedUser.id);
      const userStudents = studentsRes.data.filter(s => s.user_id === selectedUser.id);
      const userAssignments = assignmentsRes.data.filter(a => a.user_id === selectedUser.id);

      selectedUser.resourceCounts = {
        ipads: userIpads.length,
        students: userStudents.length,
        assignments: userAssignments.length
      };

      setDeleteStep(2);
    } catch (error) {
      toast.error('Fehler beim Laden der Ressourcen-Anzahl');
    }
  };

  const handleDeleteStep2Confirm = async () => {
    if (deleteConfirmText !== selectedUser.username) {
      toast.error(`Bitte geben Sie "${selectedUser.username}" ein, um zu bestätigen`);
      return;
    }

    try {
      const response = await api.delete(`/admin/users/${selectedUser.id}/complete`);
      const resources = response.data.deleted_resources || {};
      let successMsg = response.data.message;
      if (resources.pool_ipads_orphaned > 0) {
        successMsg += `. Hinweis: ${resources.pool_ipads_orphaned} Pool-iPad(s) bleiben weiter im Pool verfügbar.`;
      }
      toast.success(successMsg);
      setShowDeleteConfirmDialog(false);
      setSelectedUser(null);
      setDeleteConfirmText('');
      await loadUsers();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Löschen des Benutzers');
      console.error('Complete user deletion error:', error);
    }
  };

  const handleResetPassword = async (user) => {
    if (window.confirm(`Möchten Sie das Passwort für Benutzer "${user.username}" wirklich zurücksetzen?\n\nEin temporäres 8-stelliges Passwort wird generiert.`)) {
      try {
        const response = await api.post(`/admin/users/${user.id}/reset-password`);

        setTempPasswordData({
          username: response.data.username,
          password: response.data.temporary_password
        });
        setShowResetPasswordDialog(true);
        toast.success('Passwort wurde zurückgesetzt');
        await loadUsers();
      } catch (error) {
        toast.error(error.response?.data?.detail || 'Fehler beim Zurücksetzen des Passworts');
        console.error('Password reset error:', error);
      }
    }
  };

  const openEditDialog = (user) => {
    setSelectedUser(user);
    setEditRole(user.role);
    setEditIsActive(user.is_active);
    setEditEmail(user.email || '');
    setEditPassword('');
    setEditPasswordConfirm('');
    setShowEditDialog(true);
  };

  return (
    <div className="space-y-6">
      <Card className="shadow-lg border-l-4 border-yellow-500">
        <CardHeader>
          <div className="flex justify-between items-center">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Users className="h-5 w-5 text-yellow-600" />
                Benutzerverwaltung
                <span className="ml-2 px-2 py-1 bg-gradient-to-r from-yellow-400 to-orange-500 text-white text-xs font-bold rounded-full">
                  ADMIN
                </span>
              </CardTitle>
              <CardDescription>
                Benutzerkonten erstellen, bearbeiten und verwalten
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <Button
                onClick={handleCleanupOrphanedData}
                variant="outline"
                className="border-orange-500 text-orange-600 hover:bg-orange-50"
                title="Verwaiste Daten löschen (iPads von gelöschten Usern)"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Cleanup verwaiste Daten
              </Button>
              <Button
                onClick={() => setShowCreateDialog(true)}
                className="bg-gradient-to-r from-ipad-teal to-ipad-blue hover:from-ipad-blue hover:to-ipad-dark-blue"
              >
                <Plus className="h-4 w-4 mr-2" />
                Neuer Benutzer
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-center py-8">Lade Benutzer...</div>
          ) : users.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              Keine Benutzer vorhanden.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Benutzername</TableHead>
                    <TableHead>E-Mail</TableHead>
                    <TableHead>Rolle</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Erstellt von</TableHead>
                    <TableHead>Erstellt am</TableHead>
                    <TableHead>Aktionen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users.map((user) => (
                    <TableRow key={user.id}>
                      <TableCell className="font-medium">{user.username}</TableCell>
                      <TableCell className="text-gray-600">{user.email || '—'}</TableCell>
                      <TableCell>
                        <Badge className={user.role === 'admin' ? 'bg-yellow-100 text-yellow-800' : 'bg-blue-100 text-blue-800'}>
                          {user.role === 'admin' ? 'Administrator' : 'Benutzer'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-col gap-1">
                          <Badge className={user.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}>
                            {user.is_active ? 'Aktiv' : 'Deaktiviert'}
                          </Badge>
                          {user.force_password_change && (
                            <Badge className="bg-yellow-100 text-yellow-800 text-xs">
                              PW ändern
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>{user.created_by ? 'Admin' : 'System'}</TableCell>
                      <TableCell>{new Date(user.created_at).toLocaleDateString('de-DE')}</TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => openEditDialog(user)}
                            title="Benutzer bearbeiten"
                            className="hover:bg-blue-50"
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleResetPassword(user)}
                            title="Passwort zurücksetzen"
                            className="hover:bg-yellow-50 hover:text-yellow-600"
                            disabled={!user.is_active}
                          >
                            <Shield className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleDeleteUser(user)}
                            title="Benutzer deaktivieren"
                            className="hover:bg-orange-50 hover:text-orange-600"
                            disabled={!user.is_active}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleCompleteDeleteUser(user)}
                            title="VOLLSTÄNDIG LÖSCHEN (inkl. aller Daten!)"
                            className="hover:bg-red-100 hover:text-red-700 border-red-200"
                            disabled={!user.is_active}
                          >
                            <Trash2 className="h-4 w-4 text-red-600" />
                            <span className="ml-1 text-xs font-bold">x</span>
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Manual System Backup */}
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" />
            Vollständiges System-Backup (JSON)
          </CardTitle>
          <CardDescription>
            Komplettes Backup der gesamten Datenbank inkl. Benutzer und Zuordnungen (nur für Administratoren)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="border-l-4 border-amber-400 bg-amber-50 p-4 rounded">
              <h4 className="font-medium text-amber-800 mb-2">System-Backup erstellen</h4>
              <p className="text-sm text-amber-700 mb-4">
                Exportiert alle Daten (Benutzer, Schüler, iPads, Verträge, Einstellungen) in eine JSON-Datei,
                die später zur vollständigen Wiederherstellung verwendet werden kann.
              </p>
              <Button
                onClick={handleBackupExport}
                disabled={exportingBackup}
                className="bg-amber-600 hover:bg-amber-700 text-white transition-all duration-200"
              >
                <Download className="h-4 w-4 mr-2" />
                {exportingBackup ? 'Erstellt Backup...' : 'Backup herunterladen (JSON)'}
              </Button>
            </div>

            <div className="border-l-4 border-red-400 bg-red-50 p-4 rounded mt-4">
              <h4 className="font-medium text-red-800 mb-2">System-Backup wiederherstellen</h4>
              <p className="text-sm text-red-700 mb-4">
                <strong>ACHTUNG:</strong> Das Einspielen eines Backups überschreibt <strong>ALLE</strong> aktuellen Daten im System.
                Laden Sie hier eine zuvor erstellte .json Backup-Datei hoch. Vor der Wiederherstellung wird
                automatisch ein Sicherheits-Backup der aktuellen Daten angelegt.
              </p>
              <div className="border-2 border-dashed border-red-300 rounded-lg p-4 text-center hover:border-red-500 transition-colors bg-white">
                <Input
                  type="file"
                  accept=".json"
                  onChange={(e) => {
                    if (e.target.files[0]) {
                      handleBackupImport(e.target.files[0]);
                      e.target.value = ''; // Reset input
                    }
                  }}
                  disabled={importingBackup}
                  className="mb-2"
                />
                {importingBackup && (
                  <div className="text-sm text-red-600 font-medium mt-2">
                    Backup wird wiederhergestellt, bitte warten...
                  </div>
                )}
              </div>
            </div>

            <div className="border-l-4 border-gray-400 bg-gray-50 p-4 rounded mt-4">
              <h4 className="font-medium text-gray-800 mb-2 flex items-center gap-2">
                <History className="h-4 w-4" />
                Automatische Sicherheits-Backups (vor Wiederherstellung)
              </h4>
              <p className="text-sm text-gray-600 mb-3">
                Vor jeder Wiederherstellung wird automatisch ein Backup der vorherigen Daten angelegt.
                Die letzten {preRestoreBackups.length > 0 ? Math.max(preRestoreBackups.length, 5) : 5} Sicherheits-Backups bleiben erhalten.
              </p>
              {loadingPreRestoreBackups ? (
                <div className="text-sm text-gray-500">Lade Sicherheits-Backups...</div>
              ) : preRestoreBackups.length === 0 ? (
                <div className="text-sm text-gray-500">Noch keine Sicherheits-Backups vorhanden.</div>
              ) : (
                <ul className="space-y-1">
                  {preRestoreBackups.map((backup) => (
                    <li key={backup.filename} className="flex items-center justify-between text-sm bg-white border rounded px-3 py-2">
                      <span className="text-gray-700">
                        {new Date(backup.created_at).toLocaleString('de-DE')}
                        <span className="text-gray-400 ml-2">({Math.round(backup.size_bytes / 1024)} KB)</span>
                      </span>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleDownloadPreRestoreBackup(backup.filename)}
                      >
                        <Download className="h-3 w-3 mr-1" />
                        Herunterladen
                      </Button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Automatic Backup E-Mail Schedule */}
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Mail className="h-5 w-5" />
            Automatisches Backup per E-Mail
          </CardTitle>
          <CardDescription>
            Verschickt regelmäßig ein vollständiges System-Backup an eine hinterlegte E-Mail-Adresse
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loadingSchedule ? (
            <div className="text-center py-4">Lade Zeitplan...</div>
          ) : (
            <div className="space-y-4 max-w-lg">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="schedule-enabled"
                  checked={backupSchedule.enabled}
                  onChange={(e) => setBackupSchedule({ ...backupSchedule, enabled: e.target.checked })}
                  className="w-4 h-4"
                />
                <Label htmlFor="schedule-enabled">Automatische Backup-Mails aktivieren</Label>
              </div>

              <div className="space-y-2">
                <Label htmlFor="schedule-frequency">Häufigkeit</Label>
                <select
                  id="schedule-frequency"
                  value={backupSchedule.frequency}
                  onChange={(e) => setBackupSchedule({ ...backupSchedule, frequency: e.target.value })}
                  className="w-full p-2 border rounded-md"
                >
                  <option value="daily">Täglich</option>
                  <option value="weekly">Wöchentlich</option>
                  <option value="monthly">Monatlich</option>
                </select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="schedule-email">Ziel-E-Mail-Adresse</Label>
                <Input
                  id="schedule-email"
                  type="email"
                  value={backupSchedule.recipient_email || ''}
                  onChange={(e) => setBackupSchedule({ ...backupSchedule, recipient_email: e.target.value })}
                  placeholder="z.B. Ihre eigene Benutzer-E-Mail"
                />
              </div>

              {backupSchedule.last_run_at && (
                <div className="text-sm text-gray-600 bg-gray-50 p-3 rounded">
                  Letztes automatisches Backup: {new Date(backupSchedule.last_run_at).toLocaleString('de-DE')}
                  {' — '}
                  {backupSchedule.last_status === 'success' ? (
                    <span className="text-green-700 font-medium">erfolgreich</span>
                  ) : (
                    <span className="text-red-700 font-medium">
                      fehlgeschlagen{backupSchedule.last_error ? `: ${backupSchedule.last_error}` : ''}
                    </span>
                  )}
                </div>
              )}

              <div className="flex gap-2">
                <Button
                  onClick={handleSaveBackupSchedule}
                  disabled={savingSchedule}
                  className="bg-gradient-to-r from-ipad-teal to-ipad-blue hover:from-ipad-blue hover:to-ipad-dark-blue"
                >
                  {savingSchedule ? 'Speichert...' : 'Zeitplan speichern'}
                </Button>
                <Button
                  onClick={handleSendTestMail}
                  disabled={sendingTestMail}
                  variant="outline"
                >
                  <Send className="h-4 w-4 mr-2" />
                  {sendingTestMail ? 'Sendet...' : 'Test-Mail jetzt senden'}
                </Button>
              </div>
              <p className="text-xs text-gray-500">
                Für den Versand muss der Server unter <code className="bg-gray-100 px-1 rounded">backend/.env</code> mit
                SMTP-Zugangsdaten (SMTP_HOST, SMTP_USER, SMTP_PASSWORD, ...) konfiguriert sein.
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create User Dialog */}
      {showCreateDialog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-md">
            <CardHeader>
              <CardTitle>Neuen Benutzer erstellen</CardTitle>
              <CardDescription>
                Erstellen Sie ein neues Benutzerkonto mit Benutzername, Passwort und Rolle
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleCreateUser} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="new-username">Benutzername</Label>
                  <Input
                    id="new-username"
                    value={newUsername}
                    onChange={(e) => setNewUsername(e.target.value)}
                    placeholder="mindestens 3 Zeichen"
                    required
                    minLength={3}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="new-password">Passwort</Label>
                  <Input
                    id="new-password"
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="mindestens 6 Zeichen"
                    required
                    minLength={6}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="new-role">Rolle</Label>
                  <select
                    id="new-role"
                    value={newRole}
                    onChange={(e) => setNewRole(e.target.value)}
                    className="w-full p-2 border rounded-md"
                  >
                    <option value="user">Benutzer</option>
                    <option value="admin">Administrator</option>
                  </select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="new-email">E-Mail-Adresse (optional)</Label>
                  <Input
                    id="new-email"
                    type="email"
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                    placeholder="z.B. für automatische Backup-Mails"
                  />
                </div>
                <div className="flex gap-2 justify-end">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => {
                      setShowCreateDialog(false);
                      setNewUsername('');
                      setNewPassword('');
                      setNewRole('user');
                      setNewEmail('');
                    }}
                  >
                    Abbrechen
                  </Button>
                  <Button
                    type="submit"
                    disabled={creating}
                    className="bg-gradient-to-r from-ipad-teal to-ipad-blue"
                  >
                    {creating ? 'Erstelle...' : 'Erstellen'}
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Edit User Dialog */}
      {showEditDialog && selectedUser && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-md">
            <CardHeader>
              <CardTitle>Benutzer bearbeiten: {selectedUser.username}</CardTitle>
              <CardDescription>
                Passwort, Rolle oder Status ändern
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleUpdateUser} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="edit-password">Neues Passwort (optional)</Label>
                  <Input
                    id="edit-password"
                    type="password"
                    value={editPassword}
                    onChange={(e) => setEditPassword(e.target.value)}
                    placeholder="Leer lassen, um nicht zu ändern"
                    minLength={6}
                  />
                </div>
                {editPassword && (
                  <div className="space-y-2">
                    <Label htmlFor="edit-password-confirm">Passwort bestätigen</Label>
                    <Input
                      id="edit-password-confirm"
                      type="password"
                      value={editPasswordConfirm}
                      onChange={(e) => setEditPasswordConfirm(e.target.value)}
                      placeholder="Passwort wiederholen"
                      minLength={6}
                      required={editPassword.length > 0}
                    />
                    {editPassword !== editPasswordConfirm && editPasswordConfirm && (
                      <p className="text-sm text-red-600">Passwörter stimmen nicht überein</p>
                    )}
                  </div>
                )}
                <div className="space-y-2">
                  <Label htmlFor="edit-role">Rolle</Label>
                  <select
                    id="edit-role"
                    value={editRole}
                    onChange={(e) => setEditRole(e.target.value)}
                    className="w-full p-2 border rounded-md"
                  >
                    <option value="user">Benutzer</option>
                    <option value="admin">Administrator</option>
                  </select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="edit-email">E-Mail-Adresse (optional)</Label>
                  <Input
                    id="edit-email"
                    type="email"
                    value={editEmail}
                    onChange={(e) => setEditEmail(e.target.value)}
                    placeholder="z.B. für automatische Backup-Mails"
                  />
                </div>
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="edit-active"
                    checked={editIsActive}
                    onChange={(e) => setEditIsActive(e.target.checked)}
                    className="w-4 h-4"
                  />
                  <Label htmlFor="edit-active">Konto aktiviert</Label>
                </div>
                <div className="flex gap-2 justify-end">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => {
                      setShowEditDialog(false);
                      setSelectedUser(null);
                      setEditPassword('');
                      setEditPasswordConfirm('');
                    }}
                  >
                    Abbrechen
                  </Button>
                  <Button
                    type="submit"
                    disabled={updating}
                    className="bg-gradient-to-r from-ipad-teal to-ipad-blue"
                  >
                    {updating ? 'Aktualisiere...' : 'Aktualisieren'}
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Reset Password Result Dialog */}
      {showResetPasswordDialog && tempPasswordData && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-md">
            <CardHeader>
              <CardTitle className="text-green-600">Passwort erfolgreich zurückgesetzt!</CardTitle>
              <CardDescription>
                Das temporäre Passwort wurde generiert
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Alert className="bg-yellow-50 border-yellow-200">
                <AlertTriangle className="h-4 w-4 text-yellow-600" />
                <AlertDescription className="text-yellow-800 font-medium">
                  WICHTIG: Dieser Code wird nur einmal angezeigt!
                  Der Benutzer muss das Passwort beim nächsten Login ändern.
                </AlertDescription>
              </Alert>

              <div className="space-y-2">
                <Label>Benutzername</Label>
                <div className="p-3 bg-gray-100 rounded-md font-mono">
                  {tempPasswordData.username}
                </div>
              </div>

              <div className="space-y-2">
                <Label>Temporäres Passwort (8-stellig)</Label>
                <div className="flex gap-2">
                  <Input
                    type="text"
                    value={tempPasswordData.password}
                    readOnly
                    className="font-mono text-lg font-bold"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => {
                      navigator.clipboard.writeText(tempPasswordData.password);
                      toast.success('Passwort in Zwischenablage kopiert!');
                    }}
                    title="In Zwischenablage kopieren"
                  >
                    Kopieren
                  </Button>
                </div>
              </div>

              <div className="flex gap-2 justify-end pt-4">
                <Button
                  onClick={() => {
                    setShowResetPasswordDialog(false);
                    setTempPasswordData(null);
                  }}
                  className="bg-gradient-to-r from-ipad-teal to-ipad-blue"
                >
                  Verstanden
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Complete Delete Confirmation Dialog */}
      {showDeleteConfirmDialog && selectedUser && (
        <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-lg border-4 border-red-500">
            <CardHeader className="bg-red-50">
              <CardTitle className="text-red-700 flex items-center gap-2">
                <AlertTriangle className="h-6 w-6" />
                {deleteStep === 1 ? 'WARNUNG: Benutzer vollständig löschen?' : 'LETZTE WARNUNG'}
              </CardTitle>
              <CardDescription className="text-red-600 font-medium">
                {deleteStep === 1
                  ? 'Diese Aktion ist UNWIDERRUFLICH und löscht ALLE Daten!'
                  : 'Sind Sie ABSOLUT SICHER? Es gibt KEIN Zurück!'}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 pt-6">

              {deleteStep === 1 ? (
                <>
                  <Alert className="bg-red-50 border-red-300">
                    <AlertTriangle className="h-5 w-5 text-red-600" />
                    <AlertDescription className="text-red-800">
                      <div className="font-bold text-lg mb-2">
                        Sie sind dabei, Benutzer "{selectedUser.username}" VOLLSTÄNDIG zu löschen!
                      </div>
                      <div className="space-y-1 text-sm">
                        <p>Der Benutzer wird PERMANENT gelöscht</p>
                        <p>ALLE iPads des Benutzers werden gelöscht</p>
                        <p>ALLE Schüler des Benutzers werden gelöscht</p>
                        <p>ALLE Zuordnungen werden gelöscht</p>
                        <p>ALLE Verträge werden gelöscht</p>
                      </div>
                    </AlertDescription>
                  </Alert>

                  <div className="bg-yellow-50 border border-yellow-300 rounded p-4">
                    <p className="text-sm text-yellow-800 font-medium mb-2">
                      Alternative: Benutzer nur deaktivieren
                    </p>
                    <p className="text-xs text-yellow-700">
                      Wenn Sie den Benutzer nur vorübergehend sperren möchten, verwenden Sie stattdessen
                      den "Deaktivieren"-Button. Dies bewahrt alle Daten.
                    </p>
                  </div>

                  <div className="flex gap-2 justify-end pt-4">
                    <Button
                      variant="outline"
                      onClick={() => {
                        setShowDeleteConfirmDialog(false);
                        setSelectedUser(null);
                        setDeleteStep(1);
                      }}
                    >
                      Abbrechen
                    </Button>
                    <Button
                      onClick={handleDeleteStep1Confirm}
                      className="bg-red-600 hover:bg-red-700 text-white"
                    >
                      Weiter zur Bestätigung
                    </Button>
                  </div>
                </>
              ) : (
                <>
                  <Alert className="bg-red-100 border-red-400">
                    <AlertTriangle className="h-5 w-5 text-red-700" />
                    <AlertDescription className="text-red-900">
                      <div className="font-bold text-lg mb-3">
                        LETZTE BESTÄTIGUNG ERFORDERLICH
                      </div>
                      {selectedUser.resourceCounts && (
                        <div className="bg-white rounded p-3 mb-3">
                          <p className="font-semibold mb-2">Folgende Daten werden PERMANENT gelöscht:</p>
                          <ul className="space-y-1 text-sm">
                            <li><strong>{selectedUser.resourceCounts.ipads}</strong> iPads</li>
                            <li><strong>{selectedUser.resourceCounts.students}</strong> Schüler</li>
                            <li><strong>{selectedUser.resourceCounts.assignments}</strong> Zuordnungen</li>
                            <li>Benutzer-Account: <strong>{selectedUser.username}</strong></li>
                          </ul>
                        </div>
                      )}
                      <p className="text-sm font-medium">
                        Geben Sie zur Bestätigung den Benutzernamen ein:
                      </p>
                      <p className="text-lg font-mono font-bold text-red-700 mt-1">
                        {selectedUser.username}
                      </p>
                    </AlertDescription>
                  </Alert>

                  <div className="space-y-2">
                    <Label htmlFor="delete-confirm" className="text-red-700 font-medium">
                      Benutzername zur Bestätigung eingeben:
                    </Label>
                    <Input
                      id="delete-confirm"
                      type="text"
                      value={deleteConfirmText}
                      onChange={(e) => setDeleteConfirmText(e.target.value)}
                      placeholder={`Geben Sie "${selectedUser.username}" ein`}
                      className="border-red-300 focus:ring-red-500"
                      autoFocus
                    />
                    {deleteConfirmText && deleteConfirmText !== selectedUser.username && (
                      <p className="text-sm text-red-600">
                        Benutzername stimmt nicht überein
                      </p>
                    )}
                  </div>

                  <div className="flex gap-2 justify-end pt-4">
                    <Button
                      variant="outline"
                      onClick={() => setDeleteStep(1)}
                    >
                      Zurück
                    </Button>
                    <Button
                      onClick={handleDeleteStep2Confirm}
                      disabled={deleteConfirmText !== selectedUser.username}
                      className="bg-red-700 hover:bg-red-800 text-white disabled:bg-gray-400"
                    >
                      ENDGÜLTIG LÖSCHEN
                    </Button>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
};

export default UserManagement;
