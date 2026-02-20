import React, { useState, useEffect } from 'react';
import api, { SESSION_TIMEOUT } from '../../api';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { toast } from 'sonner';
import { Upload, Download, Shield, Settings as SettingsIcon, User } from 'lucide-react';

const Settings = () => {
  const [cleaning, setCleaning] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [globalSettings, setGlobalSettings] = useState({
    ipad_typ: 'Apple iPad',
    pencil: 'ohne Apple Pencil'
  });
  const [loadingSettings, setLoadingSettings] = useState(true);
  const [savingSettings, setSavingSettings] = useState(false);
  
  // Account management states
  const [changingPassword, setChangingPassword] = useState(false);
  const [changingUsername, setChangingUsername] = useState(false);
  const [passwordForm, setPasswordForm] = useState({
    current_password: '',
    new_password: '',
    confirm_password: ''
  });
  const [usernameForm, setUsernameForm] = useState({
    current_password: '',
    new_username: ''
  });

  // Load global settings on component mount
  useEffect(() => {
    const loadGlobalSettings = async () => {
      try {
        const response = await api.get('/settings/global');
        setGlobalSettings(response.data);
      } catch (error) {
        console.error('Failed to load global settings:', error);
        toast.error('Fehler beim Laden der globalen Einstellungen');
      } finally {
        setLoadingSettings(false);
      }
    };

    loadGlobalSettings();
  }, []);

  const handleSaveGlobalSettings = async () => {
    setSavingSettings(true);
    try {
      const response = await api.put('/settings/global', globalSettings);
      toast.success(response.data.message);
    } catch (error) {
      console.error('Failed to save global settings:', error);
      toast.error('Fehler beim Speichern der globalen Einstellungen');
    } finally {
      setSavingSettings(false);
    }
  };

  const handleInventoryExport = async () => {
    setExporting(true);
    try {
      const response = await api.get('/exports/inventory', {
        responseType: 'blob'
      });
      
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      
      // Extract filename from response headers or create default
      const contentDisposition = response.headers['content-disposition'];
      let filename = 'bestandsliste_export.xlsx';
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
      
      toast.success('Datensicherung erfolgreich exportiert');
    } catch (error) {
      console.error('Failed to export inventory:', error);
      toast.error('Fehler beim Exportieren der Datensicherung');
    } finally {
      setExporting(false);
    }
  };

  const handleInventoryImport = async (file) => {
    if (!file) return;
    
    setImporting(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      toast.info('Importiere Datensicherung...');
      
      const response = await api.post('/imports/inventory', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      
      toast.success(response.data.message);
      
      // Show detailed results if available
      if (response.data.ipads_created > 0 || response.data.students_created > 0 || response.data.assignments_created > 0) {
        const details = [];
        if (response.data.ipads_created > 0) details.push(`${response.data.ipads_created} neue iPads`);
        if (response.data.students_created > 0) details.push(`${response.data.students_created} neue Schüler`);
        if (response.data.assignments_created > 0) details.push(`${response.data.assignments_created} neue Zuordnungen`);
        
        toast.info(`Erstellt: ${details.join(', ')}`);
      }
      
      // Show skipped items
      if (response.data.ipads_skipped > 0 || response.data.students_skipped > 0) {
        const skipped = [];
        if (response.data.ipads_skipped > 0) skipped.push(`${response.data.ipads_skipped} iPads übersprungen`);
        if (response.data.students_skipped > 0) skipped.push(`${response.data.students_skipped} Schüler übersprungen`);
        
        toast.info(`Übersprungen: ${skipped.join(', ')}`);
      }
      
      // Show errors if any
      if (response.data.errors && response.data.errors.length > 0) {
        response.data.errors.forEach(error => {
          toast.error(error);
        });
      }
      
    } catch (error) {
      console.error('Failed to import inventory:', error);
      toast.error(error.response?.data?.detail || 'Fehler beim Importieren der Datensicherung');
    } finally {
      setImporting(false);
    }
  };

  const handlePasswordChange = async () => {
    if (passwordForm.new_password !== passwordForm.confirm_password) {
      toast.error('Neue Passwörter stimmen nicht überein');
      return;
    }

    if (passwordForm.new_password.length < 6) {
      toast.error('Neues Passwort muss mindestens 6 Zeichen lang sein');
      return;
    }

    setChangingPassword(true);
    try {
      const response = await api.put('/auth/change-password', {
        current_password: passwordForm.current_password,
        new_password: passwordForm.new_password
      });
      
      toast.success(response.data.message);
      setPasswordForm({ current_password: '', new_password: '', confirm_password: '' });
      
    } catch (error) {
      console.error('Failed to change password:', error);
      toast.error(error.response?.data?.detail || 'Fehler beim Ändern des Passworts');
    } finally {
      setChangingPassword(false);
    }
  };

  const handleUsernameChange = async () => {
    if (usernameForm.new_username.length < 3) {
      toast.error('Neuer Benutzername muss mindestens 3 Zeichen lang sein');
      return;
    }

    setChangingUsername(true);
    try {
      const response = await api.put('/auth/change-username', {
        current_password: usernameForm.current_password,
        new_username: usernameForm.new_username
      });
      
      toast.success(response.data.message);
      toast.info('Bitte melden Sie sich mit dem neuen Benutzernamen an.');
      
      // Clear form and logout after username change
      setUsernameForm({ current_password: '', new_username: '' });
      
      // Logout after 3 seconds to allow user to see the message
      setTimeout(() => {
        localStorage.removeItem('token');
        window.location.reload();
      }, 3000);
      
    } catch (error) {
      console.error('Failed to change username:', error);
      toast.error(error.response?.data?.detail || 'Fehler beim Ändern des Benutzernamens');
    } finally {
      setChangingUsername(false);
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
      if (response.data.details) {
        response.data.details.forEach(detail => {
          toast.info(detail);
        });
      }
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler bei der Datenschutz-Bereinigung');
    } finally {
      setCleaning(false);
    }
  };

  return (
    <div className="space-y-6">
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
          {loadingSettings ? (
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
                  disabled={savingSettings}
                  className="bg-gradient-to-r from-ipad-teal to-ipad-blue hover:from-ipad-blue hover:to-ipad-dark-blue transition-all duration-200"
                >
                  <SettingsIcon className="h-4 w-4 mr-2" />
                  {savingSettings ? 'Speichert...' : 'Einstellungen speichern'}
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Data Backup */}
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" />
            Datensicherung
          </CardTitle>
          <CardDescription>
            Vollständige Datensicherung aller Schüler und iPads für Backup und Wiederherstellung
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {/* Export Section */}
            <div className="border-l-4 border-green-400 bg-green-50 p-4 rounded">
              <h4 className="font-medium text-green-800 mb-2">Datensicherung erstellen</h4>
              <p className="text-sm text-green-700 mb-4">
                Exportiert eine vollständige Excel-Datei mit allen Daten: Schüler (auch ohne iPad), 
                iPads (auch ohne Zuordnung) und alle aktiven Zuordnungen. Bei Schülern mit mehreren 
                iPads wird pro Zuordnung eine Zeile erstellt.
              </p>
              <Button 
                onClick={handleInventoryExport}
                disabled={exporting}
                className="bg-gradient-to-r from-ipad-teal to-ipad-blue hover:from-ipad-blue hover:to-ipad-dark-blue transition-all duration-200"
              >
                <Download className="h-4 w-4 mr-2" />
                {exporting ? 'Exportiert...' : 'Als Excel exportieren'}
              </Button>
            </div>

          </div>
        </CardContent>
      </Card>

      {/* Unified Data Import */}
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" />
            Daten-Import
          </CardTitle>
          <CardDescription>
            Schüler, iPads oder vollständige Datensicherungen importieren
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {/* Template Download */}
            <div className="border-l-4 border-purple-400 bg-purple-50 p-4 rounded">
              <h4 className="font-medium text-purple-800 mb-2">Import-Vorlage herunterladen</h4>
              <p className="text-sm text-purple-700 mb-3">
                Laden Sie eine Excel-Vorlage mit allen unterstützten Spalten und Beispieldaten herunter.
              </p>
              <Button 
                onClick={async () => {
                  try {
                    const response = await api.get('/imports/template', { responseType: 'blob' });
                    const url = window.URL.createObjectURL(new Blob([response.data]));
                    const link = document.createElement('a');
                    link.href = url;
                    link.setAttribute('download', 'import_vorlage.xlsx');
                    document.body.appendChild(link);
                    link.click();
                    window.URL.revokeObjectURL(url);
                    document.body.removeChild(link);
                    toast.success('Vorlage heruntergeladen');
                  } catch (error) {
                    toast.error('Fehler beim Herunterladen der Vorlage');
                  }
                }}
                variant="outline"
                className="border-purple-400 text-purple-700 hover:bg-purple-100"
              >
                <Download className="h-4 w-4 mr-2" />
                Vorlage herunterladen
              </Button>
            </div>

            <div className="border-l-4 border-blue-400 bg-blue-50 p-4 rounded">
              <h4 className="font-medium text-blue-800 mb-2">Excel-Datei importieren</h4>
              <p className="text-sm text-blue-700 mb-4">
                <strong>Flexibler Import:</strong> Sie können verschiedene Datentypen mit einer Datei importieren:
              </p>
              <ul className="text-sm text-blue-700 mb-4 list-disc list-inside space-y-1">
                <li><strong>Nur Schüler:</strong> Excel mit Schüler-Spalten (SuSVorn, SuSNachn, etc.)</li>
                <li><strong>Nur iPads:</strong> Excel mit iPad-Spalten (ITNr, SNr, Status, etc.)</li>
                <li><strong>Komplett:</strong> Schüler + iPads + Zuordnungen in einer Datei</li>
                <li><strong>1:n Zuordnung:</strong> Schüler mit 2 oder 3 iPads erscheinen mehrfach (eine Zeile pro iPad)</li>
              </ul>
              <p className="text-sm text-blue-600 mb-4">
                Bereits vorhandene Einträge werden automatisch übersprungen. 
                Status-Werte: <code className="bg-blue-100 px-1 rounded">ok</code>, <code className="bg-blue-100 px-1 rounded">defekt</code>, <code className="bg-blue-100 px-1 rounded">gestohlen</code> (Standard: ok)
              </p>
              <div className="border-2 border-dashed border-blue-300 rounded-lg p-4 text-center hover:border-blue-500 transition-colors bg-white">
                <Input
                  type="file"
                  accept=".xlsx,.xls"
                  onChange={(e) => e.target.files[0] && handleInventoryImport(e.target.files[0])}
                  disabled={importing}
                  className="mb-2"
                  data-testid="data-import-input"
                />
                {importing && (
                  <div className="text-sm text-blue-600">
                    Daten werden importiert...
                  </div>
                )}
              </div>
            </div>
            
            <div className="text-xs text-gray-500 bg-gray-50 p-3 rounded">
              <strong>Unterstützte Spalten:</strong> Sname, SuSNachn, SuSVorn, SuSKl, SuSStrHNr, SuSPLZ, SuSOrt, SuSGeb, 
              Erz1Nachn, Erz1Vorn, Erz1StrHNr, Erz1PLZ, Erz1Ort, Erz2Nachn, Erz2Vorn, Erz2StrHNr, Erz2PLZ, Erz2Ort, 
              ITNr, SNr, Typ, Pencil, <strong>Status</strong>, AnschJahr, AusleiheDatum
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Account Management */}
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <User className="h-5 w-5" />
            Konto-Verwaltung
          </CardTitle>
          <CardDescription>
            Passwort und Benutzername ändern
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Password Change */}
            <div className="space-y-4">
              <h4 className="font-medium text-gray-800 mb-4">Passwort ändern</h4>
              <div className="space-y-3">
                <div>
                  <Label htmlFor="current_password">Aktuelles Passwort</Label>
                  <Input
                    id="current_password"
                    type="password"
                    value={passwordForm.current_password}
                    onChange={(e) => setPasswordForm({...passwordForm, current_password: e.target.value})}
                    className="transition-all duration-200 focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <Label htmlFor="new_password">Neues Passwort</Label>
                  <Input
                    id="new_password"
                    type="password"
                    value={passwordForm.new_password}
                    onChange={(e) => setPasswordForm({...passwordForm, new_password: e.target.value})}
                    className="transition-all duration-200 focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <Label htmlFor="confirm_password">Neues Passwort bestätigen</Label>
                  <Input
                    id="confirm_password"
                    type="password"
                    value={passwordForm.confirm_password}
                    onChange={(e) => setPasswordForm({...passwordForm, confirm_password: e.target.value})}
                    className="transition-all duration-200 focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <Button 
                  onClick={handlePasswordChange}
                  disabled={changingPassword || !passwordForm.current_password || !passwordForm.new_password || !passwordForm.confirm_password}
                  className="w-full bg-gradient-to-r from-ipad-teal to-ipad-blue hover:from-ipad-blue hover:to-ipad-dark-blue"
                >
                  {changingPassword ? 'Ändert Passwort...' : 'Passwort ändern'}
                </Button>
              </div>
            </div>

            {/* Username Change */}
            <div className="space-y-4">
              <h4 className="font-medium text-gray-800 mb-4">Benutzername ändern</h4>
              <div className="space-y-3">
                <div>
                  <Label htmlFor="username_current_password">Aktuelles Passwort</Label>
                  <Input
                    id="username_current_password"
                    type="password"
                    value={usernameForm.current_password}
                    onChange={(e) => setUsernameForm({...usernameForm, current_password: e.target.value})}
                    className="transition-all duration-200 focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <Label htmlFor="new_username">Neuer Benutzername</Label>
                  <Input
                    id="new_username"
                    type="text"
                    value={usernameForm.new_username}
                    onChange={(e) => setUsernameForm({...usernameForm, new_username: e.target.value})}
                    className="transition-all duration-200 focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div className="bg-yellow-50 p-3 rounded-lg">
                  <p className="text-sm text-yellow-800">
                    <strong>Hinweis:</strong> Nach der Änderung des Benutzernamens werden Sie automatisch abgemeldet.
                  </p>
                </div>
                <Button 
                  onClick={handleUsernameChange}
                  disabled={changingUsername || !usernameForm.current_password || !usernameForm.new_username}
                  className="w-full bg-gradient-to-r from-ipad-blue to-ipad-beige hover:from-ipad-dark-blue hover:to-ipad-dark-gray"
                >
                  {changingUsername ? 'Ändert Benutzername...' : 'Benutzername ändern'}
                </Button>
              </div>
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
          <div className="space-y-4">
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
            
            <div className="border-l-4 border-gray-400 bg-gray-50 p-4 rounded">
              <h4 className="font-medium text-gray-800 mb-2">System-Information</h4>
              <div className="text-sm text-gray-700 space-y-1">
                <div>Version: 1.0.0</div>
                <div>Datenbank: iPadDatabase</div>
                <div>Session-Timeout: {Math.round(SESSION_TIMEOUT / 60000)} Minuten</div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Settings;
