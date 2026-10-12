import React, { useState, useEffect } from 'react';
import api from '../../api';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Input } from '../ui/input';
import { Textarea } from '../ui/textarea';
import { Label } from '../ui/label';
import { Badge } from '../ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';
import { Alert, AlertDescription } from '../ui/alert';
import { toast } from 'sonner';
import { Users, Building2, Trash2, Shield, Edit, Plus, AlertTriangle, Download, History, Lock, Unlock, Server, KeyRound, RefreshCw, Settings as SettingsIcon, UserPlus, UserMinus } from 'lucide-react';
import { UserPicker } from '../shared/UserPicker';

import { downloadBlob } from '../../utils/download';

// Zuständigkeiten tragen ISO-Zeitstempel; angezeigt wird nur das Datum.
const formatDatum = (wert) => (wert ? new Date(wert).toLocaleDateString('de-DE') : '—');

// Warum ein Abruf scheiterte, steht je nach Fall an anderer Stelle - ohne Antwort gibt es nur
// die Meldung von axios ("Network Error"), und genau die ist der Unterschied zwischen
// "nichts vorhanden" und "nicht gefragt".
const fehlerText = (error) =>
  error?.response?.data?.detail || error?.message || 'Unbekannter Fehler';

// Die Antwort der Wiederherstellung nennt Sammlungen bei ihrem Datenbanknamen; in einer
// Meldung an den Admin haben die nichts zu suchen.
const SAMMLUNG_NAMEN = {
  users: 'Benutzer',
  bildungsgaenge: 'Bildungsgänge',
  zustaendigkeiten: 'Zuständigkeiten',
  students: 'Schüler',
  ipads: 'Geräte',
  assignments: 'Zuordnungen',
  contracts: 'Verträge',
  global_settings: 'Einstellungen',
};
const sammlungName = (name) => SAMMLUNG_NAMEN[name] || name;

// „3 Schüler, 2 Geräte" - das Backend zählt je Sammlung, gelesen wird es am Stück.
const ohneBildungsgangText = (ohne) => {
  const eintraege = Object.entries(ohne || {});
  if (eintraege.length === 0) return 'keine';
  return eintraege.map(([name, anzahl]) => `${anzahl} ${sammlungName(name)}`).join(', ');
};

// itnr_index_ok kennt drei Antworten: steht, fehlt, ließ sich nicht feststellen (null).
const itnrIndexText = (ergebnis) => {
  if (ergebnis.itnr_index_ok) return 'steht';
  if (ergebnis.itnr_index_ok === false) {
    return ergebnis.itnr_duplikate
      ? `fehlt — ${ergebnis.itnr_duplikate} ITNr ${ergebnis.itnr_duplikate === 1 ? 'kommt' : 'kommen'} mehrfach vor`
      : 'fehlt';
  }
  return 'unbekannt';
};

const UserManagement = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showResetPasswordDialog, setShowResetPasswordDialog] = useState(false);
  const [showDeleteConfirmDialog, setShowDeleteConfirmDialog] = useState(false);
  const [deleteStep, setDeleteStep] = useState(1);
  const [deletingUser, setDeletingUser] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [tempPasswordData, setTempPasswordData] = useState(null);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');

  // Create user form state
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('user');
  const [newComment, setNewComment] = useState('');
  const [creating, setCreating] = useState(false);

  // Bildungsgänge (eigene Sammlung, vom Admin gepflegt)
  const [bildungsgaenge, setBildungsgaenge] = useState([]);
  const [loadingBildungsgaenge, setLoadingBildungsgaenge] = useState(true);
  const [newBildungsgangName, setNewBildungsgangName] = useState('');
  const [newBildungsgangDescription, setNewBildungsgangDescription] = useState('');
  const [savingBildungsgang, setSavingBildungsgang] = useState(false);
  const [editingBildungsgang, setEditingBildungsgang] = useState(null);

  // Zuständigkeiten: offener Benutzer-Picker (Bildungsgang-ID) und dessen Suchtext
  const [zustaendigFuer, setZustaendigFuer] = useState(null);
  const [zustaendigSuche, setZustaendigSuche] = useState('');
  const [savingZustaendigkeit, setSavingZustaendigkeit] = useState(false);

  // Edit user form state
  const [editComment, setEditComment] = useState('');
  const [editPassword, setEditPassword] = useState('');
  const [editPasswordConfirm, setEditPasswordConfirm] = useState('');
  const [editRole, setEditRole] = useState('user');
  const [editIsActive, setEditIsActive] = useState(true);
  const [updating, setUpdating] = useState(false);

  // Manual system backup (restore/import)
  const [importingBackup, setImportingBackup] = useState(false);
  const [preRestoreBackups, setPreRestoreBackups] = useState([]);
  const [loadingPreRestoreBackups, setLoadingPreRestoreBackups] = useState(false);
  // Was die letzte Wiederherstellung hinterlassen hat. Steht hier und nicht in einer
  // Toast-Meldung: eine Wiederherstellung ist der folgenreichste Vorgang der Anwendung, und
  // was sie an Warnungen meldet (herrenlose Datensätze, fehlende Sammlungen), ist nach drei
  // Sekunden nicht erledigt.
  const [importErgebnis, setImportErgebnis] = useState(null);

  // Central backup encryption password (any admin may set it). password_state kennt drei
  // Lagen ('fehlt' | 'unlesbar' | 'bereit'); password_configured allein verschweigt die
  // mittlere - siehe Backup-Sicherheit weiter unten.
  const [backupEncryption, setBackupEncryption] = useState({ password_configured: false, password_state: 'fehlt', message: '' });
  const [loadingBackupEncryption, setLoadingBackupEncryption] = useState(true);
  // Grund, falls der Abruf scheitert. Ohne ihn bliebe der Anfangszustand stehen und „kein
  // Passwort hinterlegt" sähe aus wie eine Auskunft, obwohl niemand gefragt hat.
  const [backupEncryptionFehler, setBackupEncryptionFehler] = useState(null);
  const [newBackupPassword, setNewBackupPassword] = useState('');
  const [newBackupPasswordConfirm, setNewBackupPasswordConfirm] = useState('');
  const [savingBackupPassword, setSavingBackupPassword] = useState(false);
  // Antwort des letzten Setzens. Steht hier und nicht nur in einer Toast-Meldung, weil sie
  // sagen kann, dass das vorhandene Archiv dauerhaft unlesbar geworden ist - eine Nachricht,
  // die nach drei Sekunden verschwindet, ist dafuer die falsche Stelle.
  const [backupPasswordErgebnis, setBackupPasswordErgebnis] = useState(null);

  // Server-side backups (MongoDB/GridFS, rolling retention - SERVER_BACKUP_RETENTION_DAYS)
  const [serverBackups, setServerBackups] = useState([]);
  const [serverBackupStatus, setServerBackupStatus] = useState(null);
  const [loadingServerBackups, setLoadingServerBackups] = useState(false);
  // Dasselbe für Liste und Zustand der Server-Backups: „Noch keine vorhanden" ist eine
  // Aussage über den Server, nicht über eine ausgebliebene Antwort.
  const [serverBackupsFehler, setServerBackupsFehler] = useState(null);
  const [runningServerBackupNow, setRunningServerBackupNow] = useState(false);

  // Global settings (iPad defaults)
  const [globalSettings, setGlobalSettings] = useState({ ipad_typ: 'Apple iPad', pencil: 'ohne Apple Pencil' });
  const [loadingGlobalSettings, setLoadingGlobalSettings] = useState(true);
  const [savingGlobalSettings, setSavingGlobalSettings] = useState(false);

  // Data protection cleanup
  const [cleaning, setCleaning] = useState(false);

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

  const loadBildungsgaenge = async () => {
    setLoadingBildungsgaenge(true);
    try {
      const response = await api.get('/bildungsgaenge');
      setBildungsgaenge(response.data);
    } catch (error) {
      console.error('Failed to load Bildungsgänge:', error);
    } finally {
      setLoadingBildungsgaenge(false);
    }
  };

  const handleSaveBildungsgang = async (e) => {
    e.preventDefault();
    if (!newBildungsgangName.trim()) {
      toast.error('Bitte einen Namen angeben');
      return;
    }
    setSavingBildungsgang(true);
    try {
      if (editingBildungsgang) {
        await api.put(`/bildungsgaenge/${editingBildungsgang.id}`, {
          name: newBildungsgangName,
          description: newBildungsgangDescription
        });
        toast.success('Bildungsgang gespeichert');
      } else {
        await api.post('/bildungsgaenge', {
          name: newBildungsgangName,
          description: newBildungsgangDescription
        });
        toast.success('Bildungsgang angelegt');
      }
      setNewBildungsgangName('');
      setNewBildungsgangDescription('');
      setEditingBildungsgang(null);
      await loadBildungsgaenge();
      // Die Benutzertabelle zeigt die Namen der Bildungsgänge, eine Umbenennung schlägt dort durch.
      await loadUsers();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Speichern des Bildungsgangs');
    } finally {
      setSavingBildungsgang(false);
    }
  };

  const handleDeleteBildungsgang = async (bildungsgang) => {
    if (!window.confirm(`Bildungsgang "${bildungsgang.name}" wirklich löschen?`)) return;
    try {
      const response = await api.delete(`/bildungsgaenge/${bildungsgang.id}`);
      toast.success(response.data.message);
      await loadBildungsgaenge();
      await loadUsers();
    } catch (error) {
      // Das Backend verweigert das Löschen, solange dem Bildungsgang noch Daten gehören,
      // und nennt sie im Detail - diese Meldung ist hilfreicher als ein generischer Text.
      toast.error(error.response?.data?.detail || 'Fehler beim Löschen des Bildungsgangs');
    }
  };

  const handleAddZustaendigkeit = async (bildungsgang, user) => {
    setSavingZustaendigkeit(true);
    try {
      await api.post(`/bildungsgaenge/${bildungsgang.id}/zustaendige`, { user_id: user.id });
      toast.success(`${user.username} ist jetzt für "${bildungsgang.name}" zuständig`);
      setZustaendigFuer(null);
      setZustaendigSuche('');
      await loadBildungsgaenge();
      await loadUsers();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Eintragen der Zuständigkeit');
    } finally {
      setSavingZustaendigkeit(false);
    }
  };

  const handleEndZustaendigkeit = async (bildungsgang, person) => {
    // Beenden, nicht löschen: der Zugriff endet sofort, der Eintrag bleibt als Historie stehen.
    const confirmed = window.confirm(
      `Zuständigkeit von "${person.username}" für "${bildungsgang.name}" beenden?\n\n` +
      'Der Zugriff endet sofort. Die Daten des Bildungsgangs bleiben erhalten, ' +
      'der bisherige Zeitraum bleibt als Historie sichtbar.'
    );
    if (!confirmed) return;

    setSavingZustaendigkeit(true);
    try {
      await api.delete(`/bildungsgaenge/${bildungsgang.id}/zustaendige/${person.user_id}`);
      toast.success(`Zuständigkeit von ${person.username} wurde beendet`);
      await loadBildungsgaenge();
      await loadUsers();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Beenden der Zuständigkeit');
    } finally {
      setSavingZustaendigkeit(false);
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

  const loadBackupEncryption = async () => {
    setLoadingBackupEncryption(true);
    try {
      const response = await api.get('/settings/backup-encryption');
      setBackupEncryption(response.data);
      setBackupEncryptionFehler(null);
    } catch (error) {
      console.error('Failed to load backup encryption status:', error);
      setBackupEncryptionFehler(fehlerText(error));
    } finally {
      setLoadingBackupEncryption(false);
    }
  };

  const loadServerBackups = async () => {
    setLoadingServerBackups(true);
    try {
      const [listResponse, statusResponse] = await Promise.all([
        api.get('/backup/server-backups'),
        api.get('/backup/server-backups/status')
      ]);
      setServerBackups(listResponse.data);
      setServerBackupStatus(statusResponse.data);
      setServerBackupsFehler(null);
    } catch (error) {
      console.error('Failed to load server backups:', error);
      setServerBackupsFehler(fehlerText(error));
    } finally {
      setLoadingServerBackups(false);
    }
  };

  const loadGlobalSettings = async () => {
    setLoadingGlobalSettings(true);
    try {
      const response = await api.get('/settings/global');
      setGlobalSettings(response.data);
    } catch (error) {
      console.error('Failed to load global settings:', error);
      toast.error('Fehler beim Laden der globalen Einstellungen');
    } finally {
      setLoadingGlobalSettings(false);
    }
  };

  useEffect(() => {
    loadUsers();
    loadBildungsgaenge();
    loadPreRestoreBackups();
    loadBackupEncryption();
    loadServerBackups();
    loadGlobalSettings();
  }, []);

  const handleSaveGlobalSettings = async () => {
    setSavingGlobalSettings(true);
    try {
      const response = await api.put('/settings/global', globalSettings);
      toast.success(response.data.message);
    } catch (error) {
      console.error('Failed to save global settings:', error);
      toast.error('Fehler beim Speichern der globalen Einstellungen');
    } finally {
      setSavingGlobalSettings(false);
    }
  };

  const handleDataProtectionCleanup = async () => {
    // Double-click protection
    const now = Date.now();
    if (!window._lastCleanupClick || (now - window._lastCleanupClick) > 3000) {
      window._lastCleanupClick = now;
      toast.info('Datenschutz-Bereinigung starten? WARNUNG: Alle Schüler- und Vertragsdaten älter als 5 Jahre werden gelöscht! Klicken Sie nochmal in 3 Sekunden um zu bestätigen.');
      return;
    }

    setCleaning(true);
    try {
      const response = await api.post('/data-protection/cleanup-old-data');
      toast.success(response.data.message);
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler bei der Datenschutz-Bereinigung');
    } finally {
      setCleaning(false);
    }
  };

  const handleSetBackupPassword = async () => {
    if (newBackupPassword.length < 8) {
      toast.error('Das Backup-Passwort muss mindestens 8 Zeichen lang sein');
      return;
    }
    if (newBackupPassword !== newBackupPasswordConfirm) {
      toast.error('Die Passwörter stimmen nicht überein');
      return;
    }
    setSavingBackupPassword(true);
    setBackupPasswordErgebnis(null);
    try {
      const response = await api.put('/settings/backup-encryption', { password: newBackupPassword });
      // Statt einer Toast-Meldung: die Antwort bleibt stehen, bis der Admin sie wegklickt.
      // Sie zaehlt, wie viele vorhandene Sicherungen sich mit dem neuen Passwort nicht mehr
      // oeffnen lassen - wer das uebersieht, wirft sein Archiv weg, ohne es zu merken.
      setBackupPasswordErgebnis(response.data);
      setNewBackupPassword('');
      setNewBackupPasswordConfirm('');
      await loadBackupEncryption();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Setzen des Backup-Passworts');
    } finally {
      setSavingBackupPassword(false);
    }
  };

  const handleRunServerBackupNow = async () => {
    setRunningServerBackupNow(true);
    try {
      const response = await api.post('/backup/server-backups/run-now');
      // Die Dateikopie ist der einzige Weg aus diesem Server heraus. Scheitert sie, gelingt
      // das Backup trotzdem (GridFS) - aber es liegt dann nur in derselben Datenbank, die es
      // sichern soll. Das ist keine Erfolgsmeldung.
      if (response.data.file_error) {
        toast.error(`Server-Backup erstellt, aber die Dateikopie ist fehlgeschlagen: ${response.data.file_error}`);
      } else {
        toast.success(response.data.message);
      }
      await loadServerBackups();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Erstellen des Server-Backups');
    } finally {
      setRunningServerBackupNow(false);
    }
  };

  const handleDownloadServerBackup = async (backup) => {
    try {
      const response = await api.get(`/backup/server-backups/${backup.id}/download`, {
        responseType: 'blob'
      });
      downloadBlob(new Blob([response.data]), backup.filename);
    } catch (error) {
      toast.error('Fehler beim Herunterladen des Server-Backups');
    }
  };

  const handleCreateUser = async (e) => {
    e.preventDefault();
    setCreating(true);

    try {
      await api.post('/admin/users', {
        username: newUsername,
        password: newPassword,
        role: newRole,
        comment: newComment
      });
      toast.success(`Benutzer ${newUsername} erfolgreich erstellt!`);
      setShowCreateDialog(false);
      setNewUsername('');
      setNewPassword('');
      setNewRole('user');
      setNewComment('');
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
        // Immer mitschicken: das Backend unterscheidet "nicht gesendet" von "ausdruecklich
        // leer", nur so laesst sich ein Kommentar wieder entfernen.
        comment: editComment
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

  const handleBackupImport = async (file) => {
    if (!file) return;

    // Safety check
    if (!window.confirm("ACHTUNG: Das Einspielen eines Backups überschreibt ALLE aktuellen Daten im System. Vor der Wiederherstellung wird automatisch ein Sicherheits-Backup der aktuellen Daten angelegt. Möchten Sie wirklich fortfahren?")) {
      return;
    }

    setImportingBackup(true);
    setImportErgebnis(null);
    try {
      const formData = new FormData();
      formData.append('file', file);

      toast.info('System-Backup wird wiederhergestellt...');

      const response = await api.post('/backup/import', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });

      // Die Bestandsaufnahme des Backends bleibt stehen, bis der Admin sie wegklickt. Der
      // Toast sagt nur noch, dass es etwas zu lesen gibt - die Meldung selbst kann zehn
      // Zeilen lang sein und nennt Dinge, die danach noch von Hand zu tun sind.
      setImportErgebnis({ ok: true, ...response.data });
      const warnungen = response.data.warnungen || [];
      if (warnungen.length > 0) {
        toast.warning('Wiederherstellung abgeschlossen — bitte die Hinweise unten lesen');
      } else {
        toast.success(response.data.message);
      }
      await loadPreRestoreBackups();

    } catch (error) {
      console.error('Failed to import backup:', error);
      // Auch das Scheitern bleibt stehen: die Meldung nennt den Namen des Sicherheitsnetzes,
      // das danach von Hand zurückzuspielen ist.
      const detail = error.response?.data?.detail || 'Fehler beim Wiederherstellen des Backups';
      setImportErgebnis({ ok: false, detail });
      toast.error(detail);
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
      downloadBlob(new Blob([response.data]), filename);
    } catch (error) {
      toast.error('Fehler beim Herunterladen des Sicherheits-Backups');
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

  // Kein Vorab-Zählen mehr: früher wurden hier Datensätze über user_id gezählt und als
  // "wird gelöscht" angekündigt. user_id heißt inzwischen nur noch "angelegt von", und
  // gelöscht wird davon ohnehin nichts - die Daten gehören dem Bildungsgang. Die
  // tatsächlichen Zahlen liefert das Backend in seiner Antwort.
  const handleDeleteStep1Confirm = () => setDeleteStep(2);

  const handleDeleteStep2Confirm = async () => {
    if (deleteConfirmText !== selectedUser.username) {
      toast.error(`Bitte geben Sie "${selectedUser.username}" ein, um zu bestätigen`);
      return;
    }

    setDeletingUser(true);
    try {
      const { data } = await api.delete(`/admin/users/${selectedUser.id}/complete`);
      const erhalten = data.daten_erhalten || {};
      const summe = Object.values(erhalten).reduce((a, b) => a + b, 0);
      let meldung = data.message;
      if (data.zustaendigkeiten_beendet) {
        meldung += ` ${data.zustaendigkeiten_beendet} Zuständigkeit(en) beendet.`;
      }
      if (summe > 0) {
        meldung += ` ${summe} von dieser Person angelegte Datensätze bleiben bei ihrem Bildungsgang.`;
      }
      toast.success(meldung);
      setShowDeleteConfirmDialog(false);
      setSelectedUser(null);
      setDeleteConfirmText('');
      await loadUsers();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Löschen des Benutzers');
      console.error('Complete user deletion error:', error);
    } finally {
      setDeletingUser(false);
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
    setEditComment(user.comment || '');
    setEditPassword('');
    setEditPasswordConfirm('');
    setShowEditDialog(true);
  };

  // Drei Lagen, drei Anzeigen. "Hinterlegt, aber nicht entpackbar" sah bisher wie "alles gut"
  // aus, weil allein das Vorhandensein zaehlte - waehrend der Tagesjob seit Tagen scheiterte.
  // Dieser Fall ist ein Alarm, kein gruener Kasten.

  // Vierte Lage, die nicht vom Server kommt: der Abruf ist gescheitert. Dann ist der Zustand
  // unbekannt - und keine der drei Aussagen darf gemacht werden.
  const passwortUnbekannt = Boolean(backupEncryptionFehler);
  const passwortZustand = passwortUnbekannt
    ? 'unbekannt'
    : backupEncryption.password_state || (backupEncryption.password_configured ? 'bereit' : 'fehlt');
  const passwortBereit = passwortZustand === 'bereit';
  const passwortUnlesbar = passwortZustand === 'unlesbar';

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
                    <TableHead>Bildungsgänge</TableHead>
                    <TableHead>Kommentar</TableHead>
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
                        {(user.bildungsgaenge || []).length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {user.bildungsgaenge.map((b) => (
                              <Badge key={b.id} className="bg-purple-100 text-purple-800">{b.name}</Badge>
                            ))}
                          </div>
                        ) : (
                          <span className="text-gray-400 text-sm">—</span>
                        )}
                      </TableCell>
                      <TableCell className="max-w-xs">
                        {user.comment
                          ? <span className="text-sm text-gray-700 whitespace-pre-wrap break-words">{user.comment}</span>
                          : <span className="text-gray-400 text-sm">—</span>}
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

      {/* Global Settings */}
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <SettingsIcon className="h-5 w-5" />
            Globale Einstellungen
          </CardTitle>
          <CardDescription>
            Standard-Werte für iPad-Felder
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loadingGlobalSettings ? (
            <div className="text-center py-4">Lade Einstellungen...</div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="ipad_typ">iPad-Typ (Standard)</Label>
                  <Input
                    id="ipad_typ"
                    value={globalSettings.ipad_typ}
                    onChange={(e) => setGlobalSettings({...globalSettings, ipad_typ: e.target.value})}
                    placeholder="z.B. Apple iPad"
                    className="transition-all duration-200 focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="pencil">Pencil-Ausstattung (Standard)</Label>
                  <Input
                    id="pencil"
                    value={globalSettings.pencil}
                    onChange={(e) => setGlobalSettings({...globalSettings, pencil: e.target.value})}
                    placeholder="z.B. ohne Apple Pencil"
                    className="transition-all duration-200 focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </div>

              <div className="pt-4 border-t">
                <Button
                  onClick={handleSaveGlobalSettings}
                  disabled={savingGlobalSettings}
                  className="bg-gradient-to-r from-ipad-teal to-ipad-blue hover:from-ipad-blue hover:to-ipad-dark-blue transition-all duration-200"
                >
                  <SettingsIcon className="h-4 w-4 mr-2" />
                  {savingGlobalSettings ? 'Speichert...' : 'Einstellungen speichern'}
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Bildungsgänge: eigene Sammlung, damit eine Umbenennung die Zuordnungen nicht verliert */}
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Building2 className="h-5 w-5" />
            Bildungsgänge
          </CardTitle>
          <CardDescription>
            Bildungsgänge anlegen, umbenennen und löschen. Hier wird auch festgelegt, wer für einen
            Bildungsgang zuständig ist — nicht im Benutzerformular.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <form onSubmit={handleSaveBildungsgang} className="grid grid-cols-1 md:grid-cols-[1fr_2fr_auto] gap-3 items-end">
            <div className="space-y-1">
              <Label htmlFor="bildungsgang-name">Name</Label>
              <Input
                id="bildungsgang-name"
                value={newBildungsgangName}
                onChange={(e) => setNewBildungsgangName(e.target.value)}
                placeholder="z.B. Höhere Handelsschule"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="bildungsgang-description">Beschreibung (optional)</Label>
              <Input
                id="bildungsgang-description"
                value={newBildungsgangDescription}
                onChange={(e) => setNewBildungsgangDescription(e.target.value)}
                placeholder="kurze Erläuterung"
              />
            </div>
            <div className="flex gap-2">
              <Button type="submit" disabled={savingBildungsgang} className="bg-gradient-to-r from-ipad-teal to-ipad-blue">
                {savingBildungsgang ? 'Speichert...' : editingBildungsgang ? 'Speichern' : 'Anlegen'}
              </Button>
              {editingBildungsgang && (
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setEditingBildungsgang(null);
                    setNewBildungsgangName('');
                    setNewBildungsgangDescription('');
                  }}
                >
                  Abbrechen
                </Button>
              )}
            </div>
          </form>

          {loadingBildungsgaenge ? (
            <div className="text-center py-4">Lade Bildungsgänge...</div>
          ) : bildungsgaenge.length === 0 ? (
            <div className="text-sm text-gray-500">Noch keine Bildungsgänge angelegt.</div>
          ) : (
            <ul className="space-y-2">
              {bildungsgaenge.map((b) => {
                // Wer zuständig IST, steht nirgends gespeichert: es sind die Einträge ohne Ende.
                const aktuelle = (b.zustaendige || []).filter((z) => !z.bis);
                const ehemalige = (b.zustaendige || []).filter((z) => z.bis);
                const waehlbar = users.filter(
                  (u) => u.is_active && !aktuelle.some((z) => z.user_id === u.id)
                );

                return (
                  <li key={b.id} className="bg-gray-50 border rounded px-3 py-2 space-y-2">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <span className="font-medium">{b.name}</span>
                        <span className="text-gray-400 text-sm ml-2">
                          {aktuelle.length === 1 ? '1 zuständige Person' : `${aktuelle.length} zuständige Personen`}
                        </span>
                        {b.description && (
                          <div className="text-sm text-gray-600 truncate">{b.description}</div>
                        )}
                      </div>
                      <div className="flex gap-2 flex-shrink-0">
                        <Button
                          variant="outline"
                          size="sm"
                          title="Bildungsgang bearbeiten"
                          onClick={() => {
                            setEditingBildungsgang(b);
                            setNewBildungsgangName(b.name);
                            setNewBildungsgangDescription(b.description || '');
                          }}
                        >
                          <Edit className="h-3 w-3" />
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          title="Bildungsgang löschen (nur möglich, solange ihm keine Daten gehören)"
                          className="hover:bg-red-50 hover:text-red-600"
                          onClick={() => handleDeleteBildungsgang(b)}
                        >
                          <Trash2 className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>

                    <div className="space-y-1">
                      {aktuelle.length === 0 ? (
                        <div className="text-sm text-gray-500">Derzeit ist niemand zuständig.</div>
                      ) : (
                        aktuelle.map((z) => (
                          <div
                            key={z.user_id}
                            className="flex items-center justify-between gap-2 bg-white border rounded px-2 py-1"
                          >
                            <span className="text-sm text-gray-700 min-w-0">
                              <span className="font-medium">{z.username}</span>
                              <span className="text-gray-400 ml-2">zuständig seit {formatDatum(z.von)}</span>
                            </span>
                            <Button
                              variant="outline"
                              size="sm"
                              disabled={savingZustaendigkeit}
                              title="Zuständigkeit beenden — der Eintrag bleibt als Historie erhalten"
                              className="flex-shrink-0 hover:bg-orange-50 hover:text-orange-600"
                              onClick={() => handleEndZustaendigkeit(b, z)}
                            >
                              <UserMinus className="h-3 w-3 mr-1" />
                              Beenden
                            </Button>
                          </div>
                        ))
                      )}

                      {zustaendigFuer === b.id ? (
                        <div className="bg-white border rounded p-2 space-y-2">
                          <UserPicker
                            users={waehlbar}
                            searchQuery={zustaendigSuche}
                            onSearchChange={setZustaendigSuche}
                            onSelectUser={(u) => handleAddZustaendigkeit(b, u)}
                            searchTestId={`zustaendig-search-${b.id}`}
                            rowTestIdPrefix={`zustaendig-user-${b.id}`}
                          />
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              setZustaendigFuer(null);
                              setZustaendigSuche('');
                            }}
                          >
                            Abbrechen
                          </Button>
                        </div>
                      ) : (
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          disabled={savingZustaendigkeit}
                          onClick={() => {
                            setZustaendigFuer(b.id);
                            setZustaendigSuche('');
                          }}
                        >
                          <UserPlus className="h-3 w-3 mr-1" />
                          Zuständige Person hinzufügen
                        </Button>
                      )}

                      {ehemalige.length > 0 && (
                        <div className="pt-1 text-xs text-gray-400 space-y-0.5">
                          <div className="uppercase tracking-wide">Frühere Zuständigkeiten</div>
                          {ehemalige.map((z) => (
                            <div key={`${z.user_id}-${z.von}`}>
                              {z.username} ({formatDatum(z.von)} – {formatDatum(z.bis)})
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </CardContent>
      </Card>

      {/* Backup Security: central encryption password, manageable by any admin */}
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            {passwortUnbekannt ? (
              <AlertTriangle className="h-5 w-5 text-yellow-600" />
            ) : passwortUnlesbar ? (
              <AlertTriangle className="h-5 w-5 text-red-600" />
            ) : passwortBereit ? (
              <Lock className="h-5 w-5 text-green-600" />
            ) : (
              <Unlock className="h-5 w-5 text-gray-400" />
            )}
            Backup-Sicherheit
          </CardTitle>
          <CardDescription>
            Zentrales Verschlüsselungs-Passwort für alle Backups (von jedem Admin verwaltbar)
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loadingBackupEncryption ? (
            <div className="text-center py-4">Lade Konfiguration...</div>
          ) : (
            <div className="space-y-6">
              {passwortUnbekannt ? (
                <div className="border-l-4 border-yellow-500 bg-yellow-50 p-3 rounded text-sm text-yellow-900 space-y-2">
                  <div className="font-semibold flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                    Der Zustand des Backup-Passworts ließ sich nicht abrufen.
                  </div>
                  {/* "Der Server meldet" waere gelogen: oft kommt gar keine Antwort, und dann
                      steht hier die Meldung des Browsers. */}
                  <p>Grund: {backupEncryptionFehler}</p>
                  <p>
                    Ob ein Backup-Passwort hinterlegt ist und ob überhaupt Backups entstehen, ist damit
                    offen — die Seite bitte neu laden, sobald der Server wieder antwortet. Ein Passwort
                    lässt sich unten trotzdem setzen.
                  </p>
                </div>
              ) : passwortUnlesbar ? (
                <div className="border-l-4 border-red-500 bg-red-50 p-3 rounded text-sm text-red-800 space-y-2">
                  <div className="font-semibold flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                    Backup-Passwort hinterlegt, aber nicht lesbar — es entstehen <strong>keine</strong> Backups.
                  </div>
                  {/* Der Begruendungstext kommt vom Server: nur er weiss, woran es liegt. */}
                  {backupEncryption.message && <p>{backupEncryption.message}</p>}
                  <p>
                    <strong>Zu tun:</strong> unten ein Backup-Passwort <strong>neu setzen</strong>. Mit dem bisherigen
                    Passwort bleiben die vorhandenen Sicherungen lesbar, mit einem anderen nicht.
                  </p>
                </div>
              ) : (
                <div className={`border-l-4 p-3 rounded text-sm ${passwortBereit ? 'border-green-400 bg-green-50 text-green-800' : 'border-gray-300 bg-gray-50 text-gray-600'}`}>
                  {passwortBereit ? (
                    <>🔒 Alle Backups (manuell, E-Mail, Server) werden aktuell verschlüsselt.</>
                  ) : (
                    <>🔓 Es ist <strong>kein</strong> Backup-Passwort hinterlegt, deshalb entstehen keine Backups. Backup-Passwort setzen, um das zu ändern.</>
                  )}
                </div>
              )}

              {/* Central backup password, settable by any admin */}
              <div className="space-y-2 max-w-lg border-l-4 border-blue-400 bg-blue-50 p-4 rounded">
                <h4 className="font-medium text-blue-800 flex items-center gap-2">
                  <KeyRound className="h-4 w-4" />
                  Backup-Passwort {passwortUnbekannt ? 'setzen oder ändern' : passwortUnlesbar ? 'neu setzen' : passwortBereit ? 'ändern' : 'setzen'}
                </h4>
                <p className="text-xs text-blue-700 mb-2">
                  Mindestens 8 Zeichen. Gilt zentral für alle automatischen und manuellen Backups und wird
                  server-seitig verschlüsselt gespeichert, damit auch geplante Backups ohne manuelles Zutun
                  verschlüsselt werden können. Jeder Admin kann es jederzeit ändern.
                </p>
                {/* Steht vor dem Klick, nicht erst danach: nachtraeglich umschluesseln kann die
                    vorhandenen Sicherungen niemand. */}
                <p className="text-xs text-blue-700 mb-2">
                  <strong>Achtung:</strong> Ein <em>anderes</em> Passwort als das bisherige macht alle vorhandenen
                  Sicherungen dauerhaft unlesbar — auch die Dateikopien außer Haus. Nach dem Speichern steht hier,
                  wie viele betroffen sind.
                </p>
                <Input
                  type="password"
                  value={newBackupPassword}
                  onChange={(e) => setNewBackupPassword(e.target.value)}
                  placeholder="Neues Backup-Passwort"
                  minLength={8}
                />
                <Input
                  type="password"
                  value={newBackupPasswordConfirm}
                  onChange={(e) => setNewBackupPasswordConfirm(e.target.value)}
                  placeholder="Backup-Passwort bestätigen"
                  minLength={8}
                />
                <Button
                  onClick={handleSetBackupPassword}
                  disabled={savingBackupPassword || !newBackupPassword}
                  className="bg-gradient-to-r from-ipad-teal to-ipad-blue"
                >
                  {savingBackupPassword ? 'Speichert...' : 'Backup-Passwort speichern'}
                </Button>
              </div>

              {/* Das Ergebnis des letzten Setzens. Es verschwindet erst auf Klick: sagt es, dass
                  Sicherungen unlesbar geworden sind, ist das die wichtigste Zeile der ganzen
                  Seite - und ob der Admin sie gelesen hat, weiss niemand ausser ihm. */}
              {backupPasswordErgebnis && (
                <div
                  className={`border-l-4 p-3 rounded text-sm space-y-2 ${
                    backupPasswordErgebnis.sicherungen_unlesbar
                      ? 'border-red-500 bg-red-50 text-red-800'
                      : backupPasswordErgebnis.sicherungen_unlesbar === null
                        ? 'border-yellow-500 bg-yellow-50 text-yellow-800'
                        : 'border-green-400 bg-green-50 text-green-800'
                  }`}
                >
                  {backupPasswordErgebnis.sicherungen_unlesbar > 0 && (
                    <div className="font-semibold flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                      Vorhandene Sicherungen sind jetzt nur noch mit dem vorherigen Passwort zu öffnen
                    </div>
                  )}
                  <p>{backupPasswordErgebnis.message}</p>
                  <Button variant="outline" size="sm" onClick={() => setBackupPasswordErgebnis(null)}>
                    Hinweis gelesen
                  </Button>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Server-side daily backups (MongoDB/GridFS, SERVER_BACKUP_RETENTION_DAYS retention) */}
      <Card className="shadow-lg">
        <CardHeader>
          <div className="flex justify-between items-center">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Server className="h-5 w-5" />
                Server-Backups (MongoDB)
              </CardTitle>
              <CardDescription>
                Läuft automatisch einmal täglich. Auf dem Server werden die letzten 20 Tage aufbewahrt;
                zusätzlich wird jedes Backup als Datei abgelegt und von dort außer Haus gesichert.
              </CardDescription>
            </div>
            <Button
              onClick={handleRunServerBackupNow}
              disabled={runningServerBackupNow || !passwortBereit}
              title={passwortUnbekannt
                ? 'Ob ein Backup-Passwort hinterlegt ist, ließ sich nicht abrufen (siehe Backup-Sicherheit)'
                : passwortUnlesbar
                  ? 'Das hinterlegte Backup-Passwort lässt sich nicht entpacken - bitte unter Backup-Sicherheit neu setzen'
                  : !passwortBereit
                    ? 'Bitte zuerst ein Backup-Passwort setzen (siehe Backup-Sicherheit)'
                    : undefined}
              variant="outline"
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              {runningServerBackupNow ? 'Erstellt...' : 'Jetzt erstellen'}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {passwortUnbekannt && (
            <div className="text-sm text-yellow-900 bg-yellow-50 border-l-4 border-yellow-400 p-3 rounded flex items-start gap-2 mb-4">
              <AlertTriangle className="h-4 w-4 mt-0.5 flex-shrink-0" />
              <span>
                Ob ein Backup-Passwort hinterlegt ist, ließ sich nicht abrufen — damit ist auch offen,
                ob die täglichen Server-Backups überhaupt entstehen. Siehe <strong>Backup-Sicherheit</strong> oben.
              </span>
            </div>
          )}
          {/* Der Abruf von Liste und Zustand hängt an einem Aufruf: scheitert er, ist beides
              unbekannt - und was darunter steht, ist der Anfangszustand, nicht der Server. */}
          {serverBackupsFehler && (
            <div className="text-sm text-yellow-900 bg-yellow-50 border-l-4 border-yellow-400 p-3 rounded flex items-start gap-2 mb-4">
              <AlertTriangle className="h-4 w-4 mt-0.5 flex-shrink-0" />
              <span>
                Die Server-Backups ließen sich nicht abrufen — weder die Liste noch das Ergebnis des
                letzten Laufs. Grund: {serverBackupsFehler}
              </span>
            </div>
          )}
          {!passwortUnbekannt && !passwortBereit && (
            <div className="text-sm text-red-800 bg-red-50 border-l-4 border-red-400 p-3 rounded flex items-start gap-2 mb-4">
              {passwortUnlesbar ? <AlertTriangle className="h-4 w-4 mt-0.5 flex-shrink-0" /> : <Unlock className="h-4 w-4 mt-0.5 flex-shrink-0" />}
              <span>
                {passwortUnlesbar ? (
                  <>
                    Das hinterlegte Backup-Passwort lässt sich nicht mehr entpacken, deshalb entstehen
                    <strong> keine</strong> täglichen Server-Backups. Unter <strong>Backup-Sicherheit</strong> ein
                    Backup-Passwort neu setzen, dann läuft es wieder.
                  </>
                ) : (
                  <>
                    Ohne Backup-Passwort werden <strong>keine</strong> täglichen Server-Backups erstellt (Schülerdaten
                    dürfen nicht unverschlüsselt gespeichert werden).
                  </>
                )}
              </span>
            </div>
          )}
          {/* Fehlt der eindeutige Index auf ipads.itnr, meldet der Server das im Klartext - sonst
              stuende es nur als Logzeile vom letzten Start im Container. */}
          {serverBackupStatus?.itnr_index_meldung && (
            <div className="text-sm text-yellow-800 bg-yellow-50 border-l-4 border-yellow-400 p-3 rounded flex items-start gap-2 mb-4">
              <AlertTriangle className="h-4 w-4 mt-0.5 flex-shrink-0" />
              <span>{serverBackupStatus.itnr_index_meldung}</span>
            </div>
          )}
          {serverBackupStatus && serverBackupStatus.last_status === 'error' && (
            <div className="text-sm text-red-800 bg-red-50 border-l-4 border-red-400 p-3 rounded mb-4">
              <strong>Letzter automatischer Backup-Versuch fehlgeschlagen</strong>
              {(serverBackupStatus.last_attempt_at || serverBackupStatus.last_run_at) && (
                <> ({new Date(serverBackupStatus.last_attempt_at || serverBackupStatus.last_run_at).toLocaleString('de-DE')})</>
              )}
              {serverBackupStatus.last_error ? `: ${serverBackupStatus.last_error}` : '.'}
            </div>
          )}
          {/* Das Backup selbst gelingt, die Dateikopie scheitert: dann liegt die Sicherung nur in
              derselben Datenbank, die sie sichern soll, und die Abholung außer Haus bekommt
              nichts. Der Lauf zählt als Erfolg - sichtbar gehört es trotzdem. */}
          {serverBackupStatus?.last_file_error && (
            <div className="text-sm text-red-800 bg-red-50 border-l-4 border-red-400 p-3 rounded flex items-start gap-2 mb-4">
              <AlertTriangle className="h-4 w-4 mt-0.5 flex-shrink-0" />
              <span>
                <strong>Die Dateikopie des letzten Backups ist fehlgeschlagen.</strong> Die Sicherung liegt
                in der Datenbank, aber nicht als Datei — damit holt der Sync nichts außer Haus, und es gibt
                keine Kopie außerhalb dieses Servers.
                <div className="mt-1">{serverBackupStatus.last_file_error}</div>
              </span>
            </div>
          )}
          {/* Der Tageslauf ueberspringt, wenn sich am Bestand nichts geaendert hat. Ohne diesen
              Zweig verschwaende die Statuszeile ab dem ersten uebersprungenen Lauf ganz - und
              wer nachsieht, ob die Sicherung laeuft, fande gar nichts mehr vor. */}
          {serverBackupStatus?.last_status === 'unveraendert' && serverBackupStatus.last_run_at && (
            <div className="text-sm text-gray-600 bg-gray-50 p-3 rounded mb-4">
              Letztes automatisches Server-Backup: {new Date(serverBackupStatus.last_run_at).toLocaleString('de-DE')}
              {' — '}<span className="text-green-700 font-medium">unverändert, keine neue Sicherung nötig</span>
              {serverBackupStatus.last_completed_at && (
                <div className="mt-1 text-gray-500">
                  zuletzt geprüft: {new Date(serverBackupStatus.last_completed_at).toLocaleString('de-DE')}
                </div>
              )}
            </div>
          )}
          {serverBackupStatus && serverBackupStatus.last_status === 'success' && serverBackupStatus.last_run_at && (
            <div className="text-sm text-gray-600 bg-gray-50 p-3 rounded mb-4">
              Letztes automatisches Server-Backup: {new Date(serverBackupStatus.last_run_at).toLocaleString('de-DE')}
              {serverBackupStatus.last_file_error ? (
                <>{' — '}<span className="text-red-700 font-medium">nur in der Datenbank, ohne Dateikopie</span></>
              ) : (
                <>{' — '}<span className="text-green-700 font-medium">erfolgreich</span></>
              )}
            </div>
          )}
          {loadingServerBackups ? (
            <div className="text-center py-4">Lade Server-Backups...</div>
          ) : serverBackupsFehler ? (
            <div className="text-sm text-gray-500">
              Die Liste ließ sich nicht abrufen — ob Server-Backups vorhanden sind, ist unbekannt.
            </div>
          ) : serverBackups.length === 0 ? (
            <div className="text-sm text-gray-500">Noch keine Server-Backups vorhanden.</div>
          ) : (
            <ul className="space-y-1">
              {serverBackups.map((backup) => (
                <li key={backup.id} className="flex items-center justify-between text-sm bg-gray-50 border rounded px-3 py-2">
                  <span className="text-gray-700 flex items-center gap-2">
                    {backup.encrypted ? <Lock className="h-3 w-3 text-green-600" /> : <Unlock className="h-3 w-3 text-gray-400" />}
                    {new Date(backup.created_at).toLocaleString('de-DE')}
                    <span className="text-gray-400">({Math.round(backup.size_bytes / 1024)} KB)</span>
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleDownloadServerBackup(backup)}
                  >
                    <Download className="h-3 w-3 mr-1" />
                    Herunterladen
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      {/* Backup Restore: kept as its own card at the bottom of the Backup-Karten, since it's
          the rarest and most dangerous action - a one-off backup can already be created via
          "Server-Backups (MongoDB)" above, so there's no separate "System-Backup erstellen" here. */}
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" />
            Backup wiederherstellen
          </CardTitle>
          <CardDescription>
            Ein zuvor erstelltes System-Backup einspielen (nur für Administratoren)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="border-l-4 border-red-400 bg-red-50 p-4 rounded">
              <h4 className="font-medium text-red-800 mb-2">System-Backup wiederherstellen</h4>
              <p className="text-sm text-red-700 mb-4">
                <strong>ACHTUNG:</strong> Das Einspielen eines Backups überschreibt <strong>ALLE</strong> aktuellen Daten im System.
                Laden Sie hier eine zuvor erstellte .json oder .json.enc Backup-Datei hoch (verschlüsselte Dateien werden
                automatisch mit dem aktuellen Backup-Passwort entschlüsselt). Vor der Wiederherstellung wird
                automatisch ein Sicherheits-Backup der aktuellen Daten angelegt.
              </p>
              <div className="border-2 border-dashed border-red-300 rounded-lg p-4 text-center hover:border-red-500 transition-colors bg-white">
                <Input
                  type="file"
                  accept=".json,.enc"
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

            {/* Das Ergebnis der letzten Wiederherstellung. Es verschwindet erst auf Klick: was hier
                steht, ist nach dem Einspielen von Hand zu erledigen (ITNr nachtragen, Bildungsgänge
                zuordnen, Wanderungsskript laufen lassen) - eine Meldung, die von allein geht, hätte
                das schon vergessen, bevor jemand sie abarbeiten konnte. */}
            {importErgebnis && (
              <div
                className={`border-l-4 p-4 rounded space-y-3 text-sm ${
                  !importErgebnis.ok
                    ? 'border-red-500 bg-red-50 text-red-800'
                    : importErgebnis.warnungen?.length
                      ? 'border-yellow-500 bg-yellow-50 text-yellow-900'
                      : 'border-green-400 bg-green-50 text-green-800'
                }`}
              >
                <div className="font-semibold flex items-center gap-2">
                  {(!importErgebnis.ok || importErgebnis.warnungen?.length > 0) && (
                    <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                  )}
                  {!importErgebnis.ok
                    ? 'Die Wiederherstellung ist fehlgeschlagen'
                    : importErgebnis.warnungen?.length
                      ? 'Wiederherstellung abgeschlossen — mit Warnungen'
                      : 'Wiederherstellung abgeschlossen'}
                </div>

                {!importErgebnis.ok ? (
                  <p>{importErgebnis.detail}</p>
                ) : (
                  <>
                    {(importErgebnis.warnungen || []).map((warnung, index) => (
                      <div
                        key={index}
                        className="flex items-start gap-2 bg-white border border-yellow-300 rounded p-2"
                      >
                        <AlertTriangle className="h-4 w-4 mt-0.5 flex-shrink-0 text-yellow-700" />
                        <span>{warnung}</span>
                      </div>
                    ))}
                    <div className="bg-white border rounded p-3 space-y-1 text-gray-800">
                      <div>
                        <span className="font-medium">Sicherheits-Backup vorher angelegt:</span>{' '}
                        {importErgebnis.pre_restore_backup || '—'}
                      </div>
                      <div>
                        <span className="font-medium">Fehlende Sammlungen:</span>{' '}
                        {importErgebnis.fehlende_sammlungen?.length
                          ? importErgebnis.fehlende_sammlungen.map(sammlungName).join(', ')
                          : 'keine'}
                      </div>
                      <div>
                        <span className="font-medium">Datensätze ohne Bildungsgang:</span>{' '}
                        {ohneBildungsgangText(importErgebnis.ohne_bildungsgang)}
                      </div>
                      <div>
                        <span className="font-medium">Geräte ohne ITNr:</span>{' '}
                        {importErgebnis.geraete_ohne_itnr || 0}
                      </div>
                      <div>
                        <span className="font-medium">Eindeutiger Index auf ITNr:</span>{' '}
                        {itnrIndexText(importErgebnis)}
                      </div>
                    </div>
                  </>
                )}

                <Button variant="outline" size="sm" onClick={() => setImportErgebnis(null)}>
                  Hinweis gelesen
                </Button>
              </div>
            )}

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

      {/* Data Protection Settings */}
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Datenschutz-Einstellungen
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="border-l-4 border-blue-400 bg-blue-50 p-4 rounded">
            <h4 className="font-medium text-blue-800 mb-2">Automatisches Daten-Cleanup</h4>
            <p className="text-sm text-blue-700 mb-4">
              Löscht automatisch alle Schüler- und Vertragsdaten, die älter als 5 Jahre sind,
              um DSGVO-Compliance sicherzustellen.
            </p>
            <Button
              onClick={handleDataProtectionCleanup}
              disabled={cleaning}
              className="bg-gradient-to-r from-red-500 to-pink-500 hover:from-red-600 hover:to-pink-600"
            >
              <Shield className="h-4 w-4 mr-2" />
              {cleaning ? 'Bereinigung läuft...' : 'Datenschutz-Bereinigung starten'}
            </Button>
          </div>
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
                {/* Kein Bildungsgang-Feld: Zuständigkeiten sind n:m und zeitlich begrenzt und
                    werden deshalb in der Karte „Bildungsgänge" gepflegt. */}
                <div className="space-y-2">
                  <Label htmlFor="new-comment">Kommentar (optional)</Label>
                  <Textarea
                    id="new-comment"
                    value={newComment}
                    onChange={(e) => setNewComment(e.target.value)}
                    placeholder="z.B. Zuständigkeit, Vertretung, Hinweise"
                    rows={3}
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
                      setNewComment('');
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
                {/* Zuständigkeiten werden in der Karte „Bildungsgänge" gepflegt, siehe Anlegen-Dialog. */}
                <div className="space-y-2">
                  <Label htmlFor="edit-comment">Kommentar</Label>
                  <Textarea
                    id="edit-comment"
                    value={editComment}
                    onChange={(e) => setEditComment(e.target.value)}
                    placeholder="Leer lassen, um den Kommentar zu entfernen"
                    rows={3}
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
                  ? 'Diese Aktion ist UNWIDERRUFLICH — sie entfernt das Konto, nicht die Daten.'
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
                        <p>Das Benutzerkonto wird PERMANENT gelöscht</p>
                        <p>Laufende Zuständigkeiten werden beendet — der Zugriff endet sofort</p>
                        <p className="text-green-800 font-medium pt-1">
                          iPads, Schüler, Zuordnungen und Verträge bleiben erhalten: sie gehören
                          dem Bildungsgang, nicht der Person.
                        </p>
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
                      <div className="bg-white rounded p-3 mb-3">
                        <p className="font-semibold mb-2">Gelöscht wird ausschließlich:</p>
                        <ul className="space-y-1 text-sm">
                          <li>Benutzerkonto: <strong>{selectedUser.username}</strong></li>
                        </ul>
                        {selectedUser.bildungsgaenge?.length > 0 && (
                          <p className="text-sm text-gray-600 mt-2">
                            Zuständig für {selectedUser.bildungsgaenge.map(b => b.name).join(', ')} —
                            diese Zuständigkeit endet, die Daten bleiben.
                          </p>
                        )}
                      </div>
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
                      disabled={deletingUser}
                    >
                      Zurück
                    </Button>
                    <Button
                      onClick={handleDeleteStep2Confirm}
                      disabled={deleteConfirmText !== selectedUser.username || deletingUser}
                      className="bg-red-700 hover:bg-red-800 text-white disabled:bg-gray-400"
                    >
                      {deletingUser ? 'Wird gelöscht...' : 'ENDGÜLTIG LÖSCHEN'}
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
