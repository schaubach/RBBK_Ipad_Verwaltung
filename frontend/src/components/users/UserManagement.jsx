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
import { Users, Trash2, Shield, Edit, Plus, AlertTriangle } from 'lucide-react';

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
  const [creating, setCreating] = useState(false);
  
  // Edit user form state
  const [editPassword, setEditPassword] = useState('');
  const [editPasswordConfirm, setEditPasswordConfirm] = useState('');
  const [editRole, setEditRole] = useState('user');
  const [editIsActive, setEditIsActive] = useState(true);
  const [updating, setUpdating] = useState(false);

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

  useEffect(() => {
    loadUsers();
  }, []);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    setCreating(true);
    
    try {
      await api.post('/admin/users', {
        username: newUsername,
        password: newPassword,
        role: newRole
      });
      toast.success(`Benutzer ${newUsername} erfolgreich erstellt!`);
      setShowCreateDialog(false);
      setNewUsername('');
      setNewPassword('');
      setNewRole('user');
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
        is_active: editIsActive
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
      toast.success(response.data.message);
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
                <div className="flex gap-2 justify-end">
                  <Button 
                    type="button" 
                    variant="outline" 
                    onClick={() => {
                      setShowCreateDialog(false);
                      setNewUsername('');
                      setNewPassword('');
                      setNewRole('user');
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
