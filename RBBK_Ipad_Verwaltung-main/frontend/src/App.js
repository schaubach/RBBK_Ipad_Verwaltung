import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import './App.css';

// Import UI components
import { Button } from './components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card';
import { Input } from './components/ui/input';
import { Label } from './components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import { Alert, AlertDescription } from './components/ui/alert';
import { Badge } from './components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './components/ui/table';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './components/ui/select';
import { toast } from 'sonner';
import { Toaster } from './components/ui/sonner';
import { Upload, Users, Tablet, FileText, Settings as SettingsIcon, LogOut, Eye, Download, Trash2, ExternalLink, Shield, AlertTriangle, X, User, Edit, Plus } from 'lucide-react';

const API_BASE_URL = process.env.REACT_APP_BACKEND_URL ? `${process.env.REACT_APP_BACKEND_URL}/api` : '/api';

// API configuration
const api = axios.create({
  baseURL: API_BASE_URL,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Login Component
const Login = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [showForcePasswordChange, setShowForcePasswordChange] = useState(false);
  const [tempToken, setTempToken] = useState(null);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const response = await api.post('/auth/login', { username, password });
      const { access_token, role, username: loggedInUsername, force_password_change } = response.data;
      
      if (force_password_change) {
        // User must change password before proceeding
        setTempToken(access_token);
        setShowForcePasswordChange(true);
        toast.info('Sie müssen Ihr Passwort ändern, bevor Sie fortfahren können');
        setLoading(false);
        return;
      }
      
      localStorage.setItem('token', access_token);
      localStorage.setItem('userRole', role);
      localStorage.setItem('username', loggedInUsername);
      onLogin(role, loggedInUsername);
      toast.success(`Erfolgreich angemeldet als ${role === 'admin' ? 'Administrator' : 'Benutzer'}!`);
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleForcePasswordChange = async (e) => {
    e.preventDefault();
    
    if (newPassword.length < 6) {
      toast.error('Das Passwort muss mindestens 6 Zeichen lang sein');
      return;
    }
    
    if (newPassword !== confirmPassword) {
      toast.error('Die Passwörter stimmen nicht überein');
      return;
    }
    
    setLoading(true);
    
    try {
      // Use temporary token for this request
      await axios.put(
        `${API_BASE_URL}/auth/change-password-forced`,
        { new_password: newPassword },
        { headers: { Authorization: `Bearer ${tempToken}` } }
      );
      
      toast.success('Passwort erfolgreich geändert! Bitte melden Sie sich mit Ihrem neuen Passwort an.');
      setShowForcePasswordChange(false);
      setTempToken(null);
      setNewPassword('');
      setConfirmPassword('');
      setPassword(''); // Clear old password field
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Ändern des Passworts');
    } finally {
      setLoading(false);
    }
  };

  const checkSetup = async () => {
    try {
      const response = await api.post('/auth/setup');
      if (response.data.message.includes('Admin user created')) {
        toast.success('Setup completed! Please login with admin/admin123');
      }
    } catch (error) {
      // Setup likely already done
    }
  };

  useEffect(() => {
    checkSetup();
  }, []);

  // Force Password Change Dialog
  if (showForcePasswordChange) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-ipad-beige via-gray-50 to-ipad-teal/20 flex items-center justify-center p-4">
        <Card className="w-full max-w-md shadow-2xl border-yellow-500/50">
          <CardHeader className="text-center">
            <div className="w-16 h-16 bg-yellow-500 rounded-full flex items-center justify-center mx-auto mb-4">
              <AlertTriangle className="h-8 w-8 text-white" />
            </div>
            <CardTitle className="text-2xl font-bold text-yellow-600">
              Passwort ändern erforderlich
            </CardTitle>
            <CardDescription className="text-ipad-dark-gray">
              Ihr Administrator hat Ihr Passwort zurückgesetzt. Bitte wählen Sie ein neues Passwort.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleForcePasswordChange} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="new-password">Neues Passwort</Label>
                <Input
                  id="new-password"
                  type="password"
                  placeholder="Neues Passwort eingeben (min. 6 Zeichen)"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                  className="transition-all duration-200 focus:ring-2 focus:ring-yellow-500"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="confirm-password">Passwort bestätigen</Label>
                <Input
                  id="confirm-password"
                  type="password"
                  placeholder="Passwort wiederholen"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                  className="transition-all duration-200 focus:ring-2 focus:ring-yellow-500"
                />
              </div>
              <Button 
                type="submit" 
                className="w-full bg-yellow-500 hover:bg-yellow-600 text-white transition-all duration-200"
                disabled={loading}
              >
                {loading ? 'Wird geändert...' : 'Passwort ändern'}
              </Button>
            </form>
            <div className="mt-4 text-xs text-gray-500 text-center">
              Nach der Passwortänderung müssen Sie sich erneut anmelden.
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-ipad-beige via-gray-50 to-ipad-teal/20 flex items-center justify-center p-4">
      <Card className="w-full max-w-md shadow-2xl border-ipad-beige/20">
        <CardHeader className="text-center">
          <div className="w-16 h-16 bg-gradient-to-br from-ipad-teal to-ipad-blue rounded-full flex items-center justify-center mx-auto mb-4">
            <Tablet className="h-8 w-8 text-white" />
          </div>
          <CardTitle className="text-2xl font-bold bg-gradient-to-r from-ipad-teal to-ipad-blue bg-clip-text text-transparent">
            iPad-Verwaltung
          </CardTitle>
          <CardDescription className="text-ipad-dark-gray">
            Melden Sie sich an, um fortzufahren
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleLogin} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username">Benutzername</Label>
              <Input
                id="username"
                type="text"
                placeholder="Benutzername eingeben"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="transition-all duration-200 focus:ring-2 focus:ring-purple-500"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Passwort</Label>
              <Input
                id="password"
                type="password"
                placeholder="Passwort eingeben"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="transition-all duration-200 focus:ring-2 focus:ring-purple-500"
              />
            </div>
            <Button 
              type="submit" 
              className="w-full bg-gradient-to-r from-ipad-teal to-ipad-dark-blue hover:from-ipad-blue hover:to-ipad-dark-gray transition-all duration-200"
              disabled={loading}
            >
              {loading ? 'Anmeldung läuft...' : 'Anmelden'}
            </Button>
          </form>
          <div className="mt-6 text-center">
            <div className="text-sm text-gray-500 bg-gray-50 p-3 rounded-lg">
              <div className="font-medium text-gray-700 mb-1">Standard-Anmeldedaten:</div>
              <div>Benutzername: <span className="font-mono bg-gray-200 px-1 rounded">admin</span></div>
              <div>Passwort: <span className="font-mono bg-gray-200 px-1 rounded">admin123</span></div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

// iPad Detail Viewer Component
const IPadDetailViewer = ({ ipadId, onClose }) => {
  const [ipadData, setIPadData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadIPadDetails = async () => {
      try {
        const response = await api.get(`/ipads/${ipadId}/history`);
        setIPadData(response.data);
      } catch (error) {
        toast.error('Fehler beim Laden der iPad-Details');
        console.error('iPad details error:', error);
      } finally {
        setLoading(false);
      }
    };

    if (ipadId) {
      loadIPadDetails();
    }
  }, [ipadId]);

  if (loading) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white p-6 rounded-lg">
          <div className="text-center">Lade iPad-Details...</div>
        </div>
      </div>
    );
  }

  if (!ipadData) {
    return null;
  }

  const { ipad, current_assignment, assignment_history, current_contract, contract_history } = ipadData;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-6">
          <div className="flex justify-between items-start mb-6">
            <h2 className="text-2xl font-bold text-gray-900">
              iPad Details: {ipad.itnr}
            </h2>
            <Button variant="outline" onClick={onClose}>
              <X className="h-4 w-4" />
            </Button>
          </div>

          {/* iPad Information */}
          <Card className="mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Tablet className="h-5 w-5" />
                iPad Information
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
                <div><strong>ITNr:</strong> {ipad.itnr}</div>
                <div><strong>SNr:</strong> {ipad.snr || 'N/A'}</div>
                <div><strong>Typ:</strong> {ipad.typ || 'N/A'}</div>
                <div><strong>Pencil:</strong> {ipad.pencil || 'N/A'}</div>
                <div><strong>Status:</strong> 
                  <Badge className={`ml-2 ${
                    ipad.status === 'verfügbar' ? 'bg-ipad-teal/20 text-ipad-teal' :
                    ipad.status === 'zugewiesen' ? 'bg-ipad-blue/20 text-ipad-blue' :
                    'bg-red-100 text-red-800'
                  }`}>
                    {ipad.status}
                  </Badge>
                </div>
                <div><strong>Erstellt am:</strong> {ipad.created_at ? new Date(ipad.created_at).toLocaleDateString('de-DE') : 'N/A'}</div>
              </div>
            </CardContent>
          </Card>

          {/* Current Assignment */}
          {current_assignment && (
            <Card className="mb-6">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <User className="h-5 w-5" />
                  Aktuelle Zuordnung
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="bg-blue-50 p-4 rounded-lg">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div><strong>Schüler:</strong> {current_assignment.student_name}</div>
                    <div><strong>Zugewiesen am:</strong> {new Date(current_assignment.assigned_at).toLocaleDateString('de-DE')}</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Current Contract */}
          {current_contract && (
            <Card className="mb-6">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileText className="h-5 w-5" />
                  Aktueller Vertrag
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="bg-green-50 p-4 rounded-lg">
                  <div className="flex justify-between items-center">
                    <div>
                      <div className="text-sm"><strong>Datei:</strong> {current_contract.filename}</div>
                      <div className="text-sm"><strong>Hochgeladen:</strong> {new Date(current_contract.uploaded_at).toLocaleDateString('de-DE')}</div>
                    </div>
                    <Button 
                      variant="outline" 
                      size="sm"
                      onClick={async () => {
                        try {
                          const response = await api.get(`/contracts/${current_contract.id}/download`, {
                            responseType: 'blob'
                          });
                          const url = window.URL.createObjectURL(new Blob([response.data]));
                          const link = document.createElement('a');
                          link.href = url;
                          link.setAttribute('download', current_contract.filename);
                          document.body.appendChild(link);
                          link.click();
                          window.URL.revokeObjectURL(url);
                          document.body.removeChild(link);
                        } catch (error) {
                          toast.error('Fehler beim Download');
                        }
                      }}
                    >
                      <Download className="h-4 w-4 mr-2" />
                      Download
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Assignment History */}
          {assignment_history && assignment_history.length > 0 && (
            <Card className="mb-6">
              <CardHeader>
                <CardTitle>Zuordnungshistorie ({assignment_history.length})</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-40 overflow-y-auto">
                  {assignment_history.map((assignment) => (
                    <div key={assignment.id} className={`p-3 rounded-lg text-sm ${assignment.is_active ? 'bg-blue-50 border-l-4 border-blue-400' : 'bg-gray-50 border-l-4 border-gray-400'}`}>
                      <div className="flex justify-between items-start">
                        <div>
                          <div><strong>Schüler:</strong> {assignment.student_name}</div>
                          <div><strong>Zugewiesen:</strong> {new Date(assignment.assigned_at).toLocaleDateString('de-DE')}</div>
                          {assignment.unassigned_at && (
                            <div><strong>Aufgelöst:</strong> {new Date(assignment.unassigned_at).toLocaleDateString('de-DE')}</div>
                          )}
                        </div>
                        <Badge className={assignment.is_active ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-800'}>
                          {assignment.is_active ? 'Aktiv' : 'Historisch'}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Contract History */}
          {contract_history && contract_history.length > 0 && (
            <Card className="mb-6">
              <CardHeader>
                <CardTitle>Vertragshistorie ({contract_history.length})</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-40 overflow-y-auto">
                  {contract_history.map((contract) => (
                    <div key={contract.id} className="p-3 rounded-lg text-sm bg-gray-50 border-l-4 border-gray-400">
                      <div className="flex justify-between items-start">
                        <div>
                          <div><strong>Datei:</strong> {contract.filename}</div>
                          <div><strong>Hochgeladen:</strong> {new Date(contract.uploaded_at).toLocaleDateString('de-DE')}</div>
                        </div>
                        <div className="flex gap-2">
                          <Badge className="bg-gray-100 text-gray-800">Historisch</Badge>
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={async () => {
                              try {
                                const response = await api.get(`/contracts/${contract.id}/download`, {
                                  responseType: 'blob'
                                });
                                const url = window.URL.createObjectURL(new Blob([response.data]));
                                const link = document.createElement('a');
                                link.href = url;
                                link.setAttribute('download', contract.filename);
                                document.body.appendChild(link);
                                link.click();
                                window.URL.revokeObjectURL(url);
                                document.body.removeChild(link);
                              } catch (error) {
                                toast.error('Fehler beim Download');
                              }
                            }}
                          >
                            <Download className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          <div className="flex justify-end">
            <Button onClick={onClose} className="flex-1 md:flex-none">
              Schließen
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};

// iPad Management Component
const IPadsManagement = () => {
  const [ipads, setIPads] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [selectedIPadId, setSelectedIPadId] = useState(null);
  const [availableStudents, setAvailableStudents] = useState([]);
  
  // Filter states
  const [itnrFilter, setItnrFilter] = useState('');
  const [snrFilter, setSnrFilter] = useState('');
  
  // Autocomplete states
  const [activeAutocomplete, setActiveAutocomplete] = useState(null);
  const [studentSearchQuery, setStudentSearchQuery] = useState('');
  
  // Filtered iPads
  const filteredIPads = ipads.filter(ipad => {
    const itnrMatch = !itnrFilter || ipad.itnr?.toLowerCase().includes(itnrFilter.toLowerCase());
    const snrMatch = !snrFilter || ipad.snr?.toLowerCase().includes(snrFilter.toLowerCase());
    return itnrMatch && snrMatch;
  });

  const loadIPads = async () => {
    setLoading(true);
    try {
      const response = await api.get('/ipads');
      console.log('iPads API response:', response.data);
      setIPads(response.data || []);
    } catch (error) {
      console.error('Failed to load iPads:', error);
      toast.error('Fehler beim Laden der iPads');
      setIPads([]);
    } finally {
      setLoading(false);
    }
  };
  
  const loadAvailableStudents = async () => {
    try {
      const response = await api.get('/students/available-for-assignment');
      setAvailableStudents(response.data || []);
    } catch (error) {
      console.error('Failed to load available students:', error);
    }
  };

  useEffect(() => {
    loadIPads();
    loadAvailableStudents();
  }, []);

  const handleUpload = async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    setUploading(true);

    try {
      const response = await api.post('/ipads/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      toast.success(response.data.message);
      response.data.details.forEach(detail => {
        toast.info(detail);
      });
      await loadIPads();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'iPad upload failed');
    } finally {
      setUploading(false);
    }
  };

  const handleStatusChange = async (ipadId, newStatus) => {
    try {
      const response = await api.put(`/ipads/${ipadId}/status?status=${newStatus}`);
      toast.success(response.data.message);
      await loadIPads();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Status update failed');
    }
  };
  
  const handleManualAssignment = async (ipadId, studentId) => {
    if (!studentId || studentId === 'none') return;
    
    try {
      const response = await api.post('/assignments/manual', {
        ipad_id: ipadId,
        student_id: studentId
      });
      toast.success(response.data.message);
      // Reload both lists to update availability
      await loadIPads();
      await loadAvailableStudents();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Zuordnung fehlgeschlagen');
    }
  };

  const handleDeleteIPad = async (ipad) => {
    // Double-click confirmation
    const confirmed = window.confirm(
      `⚠️ WARNUNG: iPad ${ipad.itnr} wirklich löschen?\n\n` +
      `Dies löscht:\n` +
      `- Das iPad permanent\n` +
      `- Alle Zuordnungs-Historie\n` +
      `- Alle zugehörigen Verträge\n\n` +
      `Dies kann NICHT rückgängig gemacht werden!`
    );
    
    if (!confirmed) return;
    
    try {
      const response = await api.delete(`/ipads/${ipad.id}`);
      
      if (response && response.data) {
        const msg = response.data.message || 'iPad gelöscht';
        toast.success(msg);
      } else {
        toast.success('iPad erfolgreich gelöscht');
      }
      
      await loadIPads();
      await loadAvailableStudents();
      
    } catch (error) {
      console.error('Delete iPad error:', error);
      toast.error(error.response?.data?.detail || 'Fehler beim Löschen des iPads');
    }
  };


  const getStatusColor = (status) => {
    switch (status) {
      case 'ok':
        return 'bg-green-100 text-green-800';
      case 'defekt':
        return 'bg-red-100 text-red-800';
      case 'gestohlen':
        return 'bg-purple-100 text-purple-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };
  
  const getRowClassName = (status) => {
    if (status === 'defekt' || status === 'gestohlen') {
      return 'bg-red-50 hover:bg-red-100';
    }
    return 'hover:bg-gray-50';
  };

  const statusCounts = ipads.reduce((acc, ipad) => {
    acc[ipad.status] = (acc[ipad.status] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="space-y-6">
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" />
            iPads hochladen
          </CardTitle>
          <CardDescription>
            Excel-Datei mit iPad-Daten hochladen (ipads.xlsx Format)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-blue-400 transition-colors">
            <Input
              type="file"
              accept=".xlsx"
              onChange={(e) => e.target.files[0] && handleUpload(e.target.files[0])}
              className="mb-4"
              disabled={uploading}
            />
            {uploading && (
              <div className="text-sm text-gray-600">
                iPads werden hochgeladen und verarbeitet...
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Tablet className="h-5 w-5" />
            iPad-Status Übersicht
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
            <div className="bg-green-50 p-3 rounded-lg">
              <div className="font-medium text-green-800">OK</div>
              <div className="text-2xl font-bold text-green-600">{statusCounts.ok || 0}</div>
            </div>
            <div className="bg-red-50 p-3 rounded-lg">
              <div className="font-medium text-red-800">Defekt</div>
              <div className="text-2xl font-bold text-red-600">{statusCounts.defekt || 0}</div>
            </div>
            <div className="bg-purple-50 p-3 rounded-lg">
              <div className="font-medium text-purple-800">Gestohlen</div>
              <div className="text-2xl font-bold text-purple-600">{statusCounts.gestohlen || 0}</div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Tablet className="h-5 w-5" />
            iPads verwalten ({ipads.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {/* Filter Section */}
          <div className="mb-4 p-4 bg-gray-50 rounded-lg space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label htmlFor="ipad-itnr-filter">ITNr filtern</Label>
                <Input
                  id="ipad-itnr-filter"
                  placeholder="z.B. IT-001"
                  value={itnrFilter}
                  onChange={(e) => setItnrFilter(e.target.value)}
                />
              </div>
              <div>
                <Label htmlFor="ipad-snr-filter">SNr filtern</Label>
                <Input
                  id="ipad-snr-filter"
                  placeholder="z.B. ABC123"
                  value={snrFilter}
                  onChange={(e) => setSnrFilter(e.target.value)}
                />
              </div>
            </div>
            
            {(itnrFilter || snrFilter) && (
              <Button 
                onClick={() => {
                  setItnrFilter('');
                  setSnrFilter('');
                }}
                variant="outline"
              >
                Filter zurücksetzen
              </Button>
            )}
          </div>
          
          {loading ? (
            <div className="text-center py-8">Lade iPads...</div>
          ) : ipads.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              Keine iPads vorhanden. Laden Sie zuerst eine Excel-Datei hoch.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>ITNr</TableHead>
                    <TableHead>SNr</TableHead>
                    <TableHead>Typ</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Zugewiesen</TableHead>
                    <TableHead>Aktionen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredIPads.map((ipad) => (
                    <TableRow key={ipad.id} className={getRowClassName(ipad.status)}>
                      <TableCell className="font-medium">{ipad.itnr}</TableCell>
                      <TableCell>{ipad.snr || 'N/A'}</TableCell>
                      <TableCell>{ipad.typ || 'N/A'}</TableCell>
                      <TableCell>
                        <Select
                          value={ipad.status}
                          onValueChange={(newStatus) => handleStatusChange(ipad.id, newStatus)}
                        >
                          <SelectTrigger className="w-28">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="ok">OK</SelectItem>
                            <SelectItem value="defekt">Defekt</SelectItem>
                            <SelectItem value="gestohlen">Gestohlen</SelectItem>
                          </SelectContent>
                        </Select>
                      </TableCell>
                      <TableCell>
                        {ipad.current_assignment_id ? (
                          <Badge className="bg-blue-100 text-blue-800">Ja</Badge>
                        ) : (
                          <Badge className="bg-gray-100 text-gray-800">Nein</Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={() => setSelectedIPadId(ipad.id)}
                            title="iPad Details anzeigen"
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                          {!ipad.current_assignment_id && (
                            <div className="relative">
                              <Input
                                type="text"
                                placeholder="Schüler suchen..."
                                className="w-48"
                                onFocus={() => setActiveAutocomplete(`ipad-${ipad.id}`)}
                                onBlur={() => setTimeout(() => setActiveAutocomplete(null), 200)}
                                onChange={(e) => setStudentSearchQuery(e.target.value)}
                              />
                              {activeAutocomplete === `ipad-${ipad.id}` && (
                                <div className="absolute z-50 w-full mt-1 bg-white border rounded-md shadow-lg max-h-60 overflow-auto">
                                  {availableStudents
                                    .filter(s => 
                                      !studentSearchQuery || 
                                      s.name.toLowerCase().includes(studentSearchQuery.toLowerCase()) ||
                                      s.klasse.toLowerCase().includes(studentSearchQuery.toLowerCase())
                                    )
                                    .map((student) => (
                                      <div
                                        key={student.id}
                                        className="px-3 py-2 cursor-pointer hover:bg-gray-100"
                                        onClick={() => {
                                          handleManualAssignment(ipad.id, student.id);
                                          setActiveAutocomplete(null);
                                          setStudentSearchQuery('');
                                        }}
                                      >
                                        {student.name} <span className="text-gray-500">({student.klasse})</span>
                                      </div>
                                    ))}
                                  {availableStudents.filter(s => 
                                    !studentSearchQuery || 
                                    s.name.toLowerCase().includes(studentSearchQuery.toLowerCase()) ||
                                    s.klasse.toLowerCase().includes(studentSearchQuery.toLowerCase())
                                  ).length === 0 && (
                                    <div className="px-3 py-2 text-gray-500 text-sm">
                                      Keine Schüler gefunden
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          )}
                          {!ipad.current_assignment_id && (
                            <Button 
                              variant="outline" 
                              size="sm"
                              onClick={() => handleDeleteIPad(ipad)}
                              title="iPad löschen"
                              className="hover:bg-red-50 hover:text-red-600"
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          )}
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

      {/* iPad Detail Viewer Modal */}
      {selectedIPadId && (
        <IPadDetailViewer 
          ipadId={selectedIPadId} 
          onClose={() => setSelectedIPadId(null)} 
        />
      )}
    </div>
  );
};

// Students Management Component
const StudentsManagement = () => {
  const [students, setStudents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [selectedStudentId, setSelectedStudentId] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const [availableIPads, setAvailableIPads] = useState([]);
  
  // Autocomplete states
  const [activeAutocomplete, setActiveAutocomplete] = useState(null);
  const [ipadSearchQuery, setIpadSearchQuery] = useState('');
  
  // Filter states
  const [studentVornameFilter, setStudentVornameFilter] = useState('');
  const [studentNachnameFilter, setStudentNachnameFilter] = useState('');
  const [studentKlasseFilter, setStudentKlasseFilter] = useState('');
  
  // Filtered students
  const filteredStudents = students.filter(student => {
    const vornMatch = !studentVornameFilter || 
      student.sus_vorn?.toLowerCase().includes(studentVornameFilter.toLowerCase());
    const nachMatch = !studentNachnameFilter || 
      student.sus_nachn?.toLowerCase().includes(studentNachnameFilter.toLowerCase());
    const klMatch = !studentKlasseFilter || 
      student.sus_kl?.toLowerCase().includes(studentKlasseFilter.toLowerCase());
    
    return vornMatch && nachMatch && klMatch;
  });

  const loadStudents = async () => {
    setLoading(true);
    try {
      const response = await api.get('/students');
      console.log('Students API response:', response.data);
      setStudents(response.data || []);
    } catch (error) {
      console.error('Failed to load students:', error);
      toast.error('Fehler beim Laden der Schüler');
      setStudents([]);
    } finally {
      setLoading(false);
    }
  };
  
  const loadAvailableIPads = async () => {
    try {
      const response = await api.get('/ipads/available-for-assignment');
      setAvailableIPads(response.data || []);
    } catch (error) {
      console.error('Failed to load available iPads:', error);
    }
  };

  useEffect(() => {
    loadStudents();
    loadAvailableIPads();
  }, []);

  const handleUpload = async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    setUploading(true);

    try {
      const response = await api.post('/students/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      toast.success(response.data.message);
      response.data.details.forEach(detail => {
        toast.info(detail);
      });
      await loadStudents();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Student upload failed');
    } finally {
      setUploading(false);
    }
  };

  const handleDeleteStudent = async (student) => {
    // Confirmation dialog
    const confirmed = window.confirm(
      `⚠️ WARNUNG: Schüler ${student.sus_vorn} ${student.sus_nachn} wirklich löschen?\n\n` +
      `Dies löscht:\n` +
      `- Den Schüler permanent\n` +
      `- Alle Zuordnungs-Historie\n` +
      `- Alle zugehörigen Verträge\n` +
      `- Gibt zugeordnetes iPad frei\n\n` +
      `Dies kann NICHT rückgängig gemacht werden!`
    );
    
    if (!confirmed) return;

    try {
      toast.info('Lösche Schüler und alle zugehörigen Daten...');
      
      const response = await api.delete(`/students/${student.id}`);
      
      if (response && response.data) {
        const msg = response.data.message || 'Schüler gelöscht';
        const assignments = response.data.deleted_assignments || 0;
        const contracts = response.data.deleted_contracts || 0;
        toast.success(`${msg}. Gelöscht: ${assignments} Zuordnungen, ${contracts} Verträge`);
      } else {
        toast.success('Schüler erfolgreich gelöscht');
      }
      
      // Reload students list AND available iPads (freigegebene iPads!)
      await loadStudents();
      await loadAvailableIPads();
      
    } catch (error) {
      console.error('Delete student error:', error);
      toast.error(error.response?.data?.detail || 'Fehler beim Löschen des Schülers');
    }
  };

  const handleBatchDeleteStudents = async (deleteAll = false) => {
    const count = deleteAll ? students.length : filteredStudents.length;
    const type = deleteAll ? "ALLE" : "gefilterte";
    
    // Build confirmation message
    const message = `⚠️ WARNUNG: Sie sind dabei ${count} ${type} Schüler zu löschen!\n\nFür jeden Schüler wird gelöscht:\n- Alle Zuordnungen\n- Alle Verträge\n- Komplette Historie\n- iPads werden freigegeben\n\nDies kann NICHT rückgängig gemacht werden!\n\nMöchten Sie fortfahren?`;
    
    if (!window.confirm(message)) {
      return;
    }
    
    // Second confirmation
    const secondConfirm = window.confirm(`🚨 LETZTE BESTÄTIGUNG\n\n${count} Schüler werden PERMANENT gelöscht!\n\nWirklich fortfahren?`);
    
    if (!secondConfirm) {
      return;
    }
    
    try {
      setDeleting(true);
      toast.info(`Lösche ${count} Schüler...`);
      
      // Build filter parameters
      const filterParams = {};
      
      if (deleteAll) {
        filterParams.all = true;
      } else {
        // Apply current filters
        if (studentVornameFilter) filterParams.sus_vorn = studentVornameFilter;
        if (studentNachnameFilter) filterParams.sus_nachn = studentNachnameFilter;
        if (studentKlasseFilter) filterParams.sus_kl = studentKlasseFilter;
      }
      
      // Call batch delete endpoint
      const response = await api.post('/students/batch-delete', filterParams);
      
      toast.success(`✅ ${response.data.deleted_count} Schüler gelöscht, ${response.data.freed_ipads} iPads freigegeben!`);
      
      // Reload data AND available iPads (freigegebene iPads!)
      await loadStudents();
      await loadAvailableIPads();
      
    } catch (error) {
      console.error('Batch delete students error:', error);
      toast.error(error.response?.data?.detail || 'Fehler beim Löschen der Schüler');
    } finally {
      setDeleting(false);
    }
  };

  const handleManualIPadAssignment = async (studentId, ipadId) => {
    if (!ipadId || ipadId === 'none') return;
    
    try {
      const response = await api.post('/assignments/manual', {
        student_id: studentId,
        ipad_id: ipadId
      });
      toast.success(response.data.message);
      // Reload both lists to update availability
      await loadStudents();
      await loadAvailableIPads();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Zuordnung fehlgeschlagen');
    }
  };


  return (

    <div className="space-y-6">
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" />
            Schüler hochladen
          </CardTitle>
          <CardDescription>
            Excel-Datei mit Schülerdaten hochladen (schildexport.xlsx Format)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-blue-400 transition-colors">
            <Input
              type="file"
              accept=".xlsx"
              onChange={(e) => e.target.files[0] && handleUpload(e.target.files[0])}
              className="mb-4"
              disabled={uploading}
            />
            {uploading && (
              <div className="text-sm text-gray-600">
                Schüler werden hochgeladen und verarbeitet...
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users className="h-5 w-5" />
            Schüler verwalten ({students.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {/* Filter Section */}
          <div className="mb-4 p-4 bg-gray-50 rounded-lg space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <Label htmlFor="student-vorname-filter">Vorname filtern</Label>
                <Input
                  id="student-vorname-filter"
                  placeholder="z.B. Max"
                  value={studentVornameFilter}
                  onChange={(e) => setStudentVornameFilter(e.target.value)}
                />
              </div>
              <div>
                <Label htmlFor="student-nachname-filter">Nachname filtern</Label>
                <Input
                  id="student-nachname-filter"
                  placeholder="z.B. Müller"
                  value={studentNachnameFilter}
                  onChange={(e) => setStudentNachnameFilter(e.target.value)}
                />
              </div>
              <div>
                <Label htmlFor="student-klasse-filter">Klasse filtern</Label>
                <Input
                  id="student-klasse-filter"
                  placeholder="z.B. 10a"
                  value={studentKlasseFilter}
                  onChange={(e) => setStudentKlasseFilter(e.target.value)}
                />
              </div>
            </div>
            
            {/* Action Buttons */}
            <div className="flex gap-2 flex-wrap">
              <Button 
                onClick={() => handleBatchDeleteStudents(true)}
                disabled={deleting || students.length === 0}
                className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                {deleting ? 'Lösche...' : `Alle Schüler löschen (${students.length})`}
              </Button>
              
              {(studentVornameFilter || studentNachnameFilter || studentKlasseFilter) && filteredStudents.length > 0 && (
                <Button 
                  onClick={() => handleBatchDeleteStudents(false)}
                  disabled={deleting}
                  className="bg-gradient-to-r from-orange-500 to-red-500 hover:from-orange-600 hover:to-red-600 text-white"
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  {deleting ? 'Lösche...' : `Gefilterte Schüler löschen (${filteredStudents.length})`}
                </Button>
              )}
              
              {(studentVornameFilter || studentNachnameFilter || studentKlasseFilter) && (
                <Button 
                  onClick={() => {
                    setStudentVornameFilter('');
                    setStudentNachnameFilter('');
                    setStudentKlasseFilter('');
                  }}
                  variant="outline"
                >
                  Filter zurücksetzen
                </Button>
              )}
            </div>
          </div>
          
          {loading ? (
            <div className="text-center py-8">Lade Schüler...</div>
          ) : students.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              Keine Schüler vorhanden. Laden Sie zuerst eine Excel-Datei hoch.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Klasse</TableHead>
                    <TableHead>iPad-Status</TableHead>
                    <TableHead>Erstellt am</TableHead>
                    <TableHead>Aktionen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredStudents.map((student) => (
                    <TableRow key={student.id} className="hover:bg-gray-50">
                      <TableCell className="font-medium">
                        {student.sus_vorn} {student.sus_nachn}
                      </TableCell>
                      <TableCell>{student.sus_kl || 'N/A'}</TableCell>
                      <TableCell>
                        <Badge className={student.current_assignment_id ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}>
                          {student.current_assignment_id ? 'Zugewiesen' : 'Ohne iPad'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {student.created_at ? new Date(student.created_at).toLocaleDateString('de-DE') : 'N/A'}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={() => setSelectedStudentId(student.id)}
                            title="Schülerdetails anzeigen"
                            className="hover:bg-blue-50"
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                          {!student.current_assignment_id && (
                            <div className="relative">
                              <Input
                                type="text"
                                placeholder="iPad suchen (ITNr)..."
                                className="w-48"
                                onFocus={() => setActiveAutocomplete(`student-${student.id}`)}
                                onBlur={() => setTimeout(() => setActiveAutocomplete(null), 200)}
                                onChange={(e) => setIpadSearchQuery(e.target.value)}
                              />
                              {activeAutocomplete === `student-${student.id}` && (
                                <div className="absolute z-50 w-full mt-1 bg-white border rounded-md shadow-lg max-h-60 overflow-auto">
                                  {availableIPads
                                    .filter(ipad => 
                                      !ipadSearchQuery || 
                                      ipad.itnr.toLowerCase().includes(ipadSearchQuery.toLowerCase())
                                    )
                                    .map((ipad) => (
                                      <div
                                        key={ipad.id}
                                        className="px-3 py-2 cursor-pointer hover:bg-gray-100"
                                        onClick={() => {
                                          handleManualIPadAssignment(student.id, ipad.id);
                                          setActiveAutocomplete(null);
                                          setIpadSearchQuery('');
                                        }}
                                      >
                                        {ipad.itnr} <span className="text-gray-500">({ipad.status})</span>
                                      </div>
                                    ))}
                                  {availableIPads.filter(ipad => 
                                    !ipadSearchQuery || 
                                    ipad.itnr.toLowerCase().includes(ipadSearchQuery.toLowerCase())
                                  ).length === 0 && (
                                    <div className="px-3 py-2 text-gray-500 text-sm">
                                      Keine iPads gefunden
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          )}
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={() => handleDeleteStudent(student)}
                            title="Schüler löschen (inkl. aller Daten, iPad wird freigegeben)"
                            className="hover:bg-red-50 hover:text-red-600"
                          >
                            <Trash2 className="h-4 w-4" />
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

      {/* Student Detail Viewer Modal */}
      {selectedStudentId && (
        <StudentDetailViewer 
          studentId={selectedStudentId} 
          onClose={() => setSelectedStudentId(null)} 
        />
      )}
    </div>
  );
};

// Contract View Component
const ContractViewer = ({ contractId, onClose }) => {
  const [loading, setLoading] = useState(true);
  const [pdfUrl, setPdfUrl] = useState(null);

  useEffect(() => {
    const loadContract = async () => {
      try {
        const response = await api.get(`/contracts/${contractId}`);
        const blob = new Blob([response.data], { type: 'application/pdf' });
        const url = URL.createObjectURL(blob);
        setPdfUrl(url);
      } catch (error) {
        toast.error('Fehler beim Laden des Vertrags');
        console.error('Contract loading error:', error);
      } finally {
        setLoading(false);
      }
    };

    if (contractId) {
      loadContract();
    }

    return () => {
      if (pdfUrl) {
        URL.revokeObjectURL(pdfUrl);
      }
    };
  }, [contractId, pdfUrl]);

  const handleDownload = async () => {
    try {
      const response = await api.get(`/contracts/${contractId}/download`, {
        responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `contract_${contractId}.pdf`);
      document.body.appendChild(link);
      link.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(link);
    } catch (error) {
      toast.error('Fehler beim Download');
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg w-full max-w-4xl h-full max-h-[90vh] flex flex-col">
        <div className="flex justify-between items-center p-4 border-b">
          <h2 className="text-xl font-bold">Vertrag anzeigen</h2>
          <div className="flex gap-2">
            <Button variant="outline" onClick={handleDownload}>
              <Download className="h-4 w-4 mr-2" />
              Download
            </Button>
            <Button variant="outline" onClick={onClose}>
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>
        <div className="flex-1 p-4">
          {loading ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900 mx-auto"></div>
                <p className="mt-4">Lade Vertrag...</p>
              </div>
            </div>
          ) : pdfUrl ? (
            <iframe
              src={pdfUrl}
              className="w-full h-full border-0 rounded"
              title="PDF Viewer"
            />
          ) : (
            <div className="flex items-center justify-center h-full">
              <p>Vertrag konnte nicht geladen werden.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Student Detail Viewer Component
const StudentDetailViewer = ({ studentId, onClose }) => {
  const [studentData, setStudentData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadStudentDetails = async () => {
      try {
        const response = await api.get(`/students/${studentId}`);
        setStudentData(response.data);
      } catch (error) {
        toast.error('Fehler beim Laden der Schülerdetails');
        console.error('Student details error:', error);
      } finally {
        setLoading(false);
      }
    };

    if (studentId) {
      loadStudentDetails();
    }
  }, [studentId]);

  if (loading) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white p-6 rounded-lg">
          <div className="text-center">Lade Schülerdetails...</div>
        </div>
      </div>
    );
  }

  if (!studentData) {
    return null;
  }

  const { student, current_assignment, assignment_history, contracts } = studentData;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-6">
          <div className="flex justify-between items-start mb-6">
            <h2 className="text-2xl font-bold text-gray-900">
              Schülerdetails: {student.sus_vorn} {student.sus_nachn}
            </h2>
            <Button variant="outline" onClick={onClose}>
              <X className="h-4 w-4" />
            </Button>
          </div>

          {/* Student Information */}
          <Card className="mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <User className="h-5 w-5" />
                Persönliche Daten
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
                <div><strong>Schulname:</strong> {student.sname || 'N/A'}</div>
                <div><strong>Klasse:</strong> {student.sus_kl || 'N/A'}</div>
                <div><strong>Adresse:</strong> {student.sus_str_hnr || 'N/A'}</div>
                <div><strong>PLZ:</strong> {student.sus_plz || 'N/A'}</div>
                <div><strong>Ort:</strong> {student.sus_ort || 'N/A'}</div>
                <div><strong>Geburtsdatum:</strong> {student.sus_geb || 'N/A'}</div>
                <div><strong>Erstellt am:</strong> {student.created_at ? new Date(student.created_at).toLocaleDateString('de-DE') : 'N/A'}</div>
              </div>
            </CardContent>
          </Card>

          {/* Erziehungsberechtigte */}
          <Card className="mb-6">
            <CardHeader>
              <CardTitle>Erziehungsberechtigte</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="border rounded-lg p-4">
                  <h4 className="font-medium mb-2">Erziehungsberechtigte/r 1</h4>
                  <div className="text-sm space-y-1">
                    <div><strong>Name:</strong> {student.erz1_vorn} {student.erz1_nachn}</div>
                    <div><strong>Adresse:</strong> {student.erz1_str_hnr}</div>
                    <div><strong>PLZ/Ort:</strong> {student.erz1_plz} {student.erz1_ort}</div>
                  </div>
                </div>
                <div className="border rounded-lg p-4">
                  <h4 className="font-medium mb-2">Erziehungsberechtigte/r 2</h4>
                  <div className="text-sm space-y-1">
                    <div><strong>Name:</strong> {student.erz2_vorn} {student.erz2_nachn}</div>
                    <div><strong>Adresse:</strong> {student.erz2_str_hnr}</div>
                    <div><strong>PLZ/Ort:</strong> {student.erz2_plz} {student.erz2_ort}</div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Current Assignment */}
          {current_assignment && (
            <Card className="mb-6">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Tablet className="h-5 w-5" />
                  Aktuelle iPad-Zuordnung
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="bg-green-50 p-4 rounded-lg">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div><strong>iPad ITNr:</strong> {current_assignment.itnr}</div>
                    <div><strong>Zugewiesen am:</strong> {new Date(current_assignment.assigned_at).toLocaleDateString('de-DE')}</div>
                    <div><strong>Vertrag:</strong> 
                      <Badge className={current_assignment.contract_id ? 'bg-green-100 text-green-800 ml-2' : 'bg-gray-100 text-gray-800 ml-2'}>
                        {current_assignment.contract_id ? 'Vorhanden' : 'Fehlend'}
                      </Badge>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Assignment History */}
          {assignment_history && assignment_history.length > 0 && (
            <Card className="mb-6">
              <CardHeader>
                <CardTitle>Zuordnungshistorie ({assignment_history.length})</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-40 overflow-y-auto">
                  {assignment_history.map((assignment) => (
                    <div key={assignment.id} className={`p-3 rounded-lg text-sm ${assignment.is_active ? 'bg-green-50 border-l-4 border-green-400' : 'bg-gray-50 border-l-4 border-gray-400'}`}>
                      <div className="flex justify-between items-start">
                        <div>
                          <div><strong>iPad:</strong> {assignment.itnr}</div>
                          <div><strong>Zugewiesen:</strong> {new Date(assignment.assigned_at).toLocaleDateString('de-DE')}</div>
                          {assignment.unassigned_at && (
                            <div><strong>Aufgelöst:</strong> {new Date(assignment.unassigned_at).toLocaleDateString('de-DE')}</div>
                          )}
                        </div>
                        <Badge className={assignment.is_active ? 'bg-ipad-teal/20 text-ipad-teal' : 'bg-ipad-beige/30 text-ipad-dark-gray'}>
                          {assignment.is_active ? 'Aktiv' : 'Historisch'}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Contracts */}
          {contracts.length > 0 && (
            <Card className="mb-6">
              <CardHeader>
                <CardTitle>Verträge ({contracts.length})</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-40 overflow-y-auto">
                  {contracts.map((contract) => (
                    <div key={contract.id} className={`p-3 rounded-lg text-sm ${contract.is_active ? 'bg-blue-50 border-l-4 border-blue-400' : 'bg-gray-50 border-l-4 border-gray-400'}`}>
                      <div className="flex justify-between items-start">
                        <div>
                          <div><strong>Datei:</strong> {contract.filename}</div>
                          <div><strong>iPad:</strong> {contract.itnr || 'Unzugewiesen'}</div>
                          <div><strong>Hochgeladen:</strong> {new Date(contract.uploaded_at).toLocaleDateString('de-DE')}</div>
                        </div>
                        <Badge className={contract.is_active ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-800'}>
                          {contract.is_active ? 'Aktiv' : 'Historisch'}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          <div className="flex justify-end">
            <Button onClick={onClose} className="flex-1 md:flex-none">
              Schließen
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Assignments Management Component
const AssignmentsManagement = () => {
  const [assignments, setAssignments] = useState([]);
  const [filteredAssignments, setFilteredAssignments] = useState([]);
  const [ipads, setIPads] = useState([]);
  const [students, setStudents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [assigning, setAssigning] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [dissolving, setDissolving] = useState(false);
  const [selectedContractId, setSelectedContractId] = useState(null);
  const [uploadingContractForAssignment, setUploadingContractForAssignment] = useState(null);
  const [importing, setImporting] = useState(false);
  
  // Filter states
  const [vornameFilter, setVornameFilter] = useState('');
  const [nachnameFilter, setNachnameFilter] = useState('');
  const [klasseFilter, setKlasseFilter] = useState('');
  const [itnrFilter, setItnrFilter] = useState('');

  const loadAllData = async () => {
    try {
      console.log('Loading all data...'); // Debug log
      const [assignmentsRes, ipadsRes, studentsRes] = await Promise.all([
        api.get('/assignments'),
        api.get('/ipads'),
        api.get('/students')
      ]);
      
      console.log('Assignments loaded:', assignmentsRes.data); // Debug log
      console.log('iPads loaded:', ipadsRes.data); // Debug log
      console.log('Students loaded:', studentsRes.data); // Debug log
      
      setAssignments(assignmentsRes.data);
      setFilteredAssignments(assignmentsRes.data);  
      setIPads(ipadsRes.data);
      setStudents(studentsRes.data);
    } catch (error) {
      toast.error('Fehler beim Laden der Daten');
      console.error('Data loading error:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAllData();
  }, []);

  // Apply filters
  useEffect(() => {
    applyFilters();
  }, [assignments, vornameFilter, nachnameFilter, klasseFilter, itnrFilter]);

  const applyFilters = async () => {
    console.log('=== APPLYING FILTERS ===');
    console.log('Vorname filter:', vornameFilter);
    console.log('Nachname filter:', nachnameFilter);
    console.log('Klasse filter:', klasseFilter);
    console.log('ITNr filter:', itnrFilter);
    
    if (!vornameFilter && !nachnameFilter && !klasseFilter && !itnrFilter) {
      console.log('No filters active, showing all assignments');
      setFilteredAssignments(assignments);
      return;
    }

    try {
      const params = new URLSearchParams();
      if (vornameFilter) {
        params.append('sus_vorn', vornameFilter);
        console.log('Added vorname filter:', vornameFilter);
      }
      if (nachnameFilter) {
        params.append('sus_nachn', nachnameFilter);
        console.log('Added nachname filter:', nachnameFilter);
      }
      if (klasseFilter) {
        params.append('sus_kl', klasseFilter);
        console.log('Added klasse filter:', klasseFilter);
      }
      if (itnrFilter) {
        params.append('itnr', itnrFilter);
        console.log('Added itnr filter:', itnrFilter);
      }

      const url = `/assignments/filtered?${params.toString()}`;
      console.log('Filter API URL:', url);
      console.log('Full URL:', `${API_BASE_URL}${url}`);

      const response = await api.get(url);
      console.log('Filter API response:', response.data);
      console.log('Number of filtered assignments:', response.data.length);
      
      setFilteredAssignments(response.data);
      
      console.log('Filtered assignments set successfully');
    } catch (error) {
      console.error('=== FILTER ERROR ===');
      console.error('Filter error:', error);
      console.error('Error response:', error.response?.data);
      console.error('Error status:', error.response?.status);
      toast.error('Fehler beim Filtern der Zuordnungen');
    }
    
    console.log('=== FILTER APPLICATION END ===');
  };

  const handleAutoAssign = async () => {
    setAssigning(true);
    try {
      const response = await api.post('/assignments/auto-assign');
      toast.success(response.data.message);
      await loadAllData();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Auto-Zuordnung fehlgeschlagen');
      console.error('Auto-assignment error:', error);
    } finally {
      setAssigning(false);
    }
  };

  const handleDissolveAssignment = async (assignment) => {
    console.log('🔥 DISSOLUTION FUNCTION CALLED!');
    
    // Simple, working confirmation with setTimeout
    toast.info(`Zuordnung ${assignment.student_name} auflösen? Klicken Sie nochmal in 2 Sekunden um zu bestätigen.`);
    
    // Add a flag to require double-click
    const now = Date.now();
    if (!assignment._lastClick || (now - assignment._lastClick) > 3000) {
      assignment._lastClick = now;
      return; // First click - just show warning
    }
    
    try {
      toast.info('Löse Zuordnung auf...');
      
      const response = await fetch(`${API_BASE_URL}/assignments/${assignment.id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        toast.success('Zuordnung erfolgreich aufgelöst!');
        await loadAllData();
      } else {
        toast.error(`API Fehler: ${response.status}`);
      }
      
    } catch (error) {
      console.error('❌ Exception:', error);
      toast.error(`Fehler: ${error.message}`);
    }
  };

  const handleBatchDissolve = async (dissolveAll = false) => {
    const count = dissolveAll ? assignments.length : filteredAssignments.length;
    const type = dissolveAll ? "ALLE" : "gefilterte";
    
    // Build confirmation message
    const message = `⚠️ WARNUNG: Sie sind dabei ${count} ${type} Zuordnung(en) aufzulösen!\n\nDies kann NICHT rückgängig gemacht werden.\n\nMöchten Sie fortfahren?`;
    
    if (!window.confirm(message)) {
      return;
    }
    
    // Second confirmation
    const secondConfirm = window.confirm(`🚨 LETZTE BESTÄTIGUNG\n\n${count} Zuordnung(en) werden aufgelöst:\n- iPads werden auf "verfügbar" gesetzt\n- Schüler werden freigegeben\n- Verträge werden inaktiv\n\nWirklich fortfahren?`);
    
    if (!secondConfirm) {
      return;
    }
    
    try {
      setDissolving(true);
      toast.info(`Löse ${count} Zuordnung(en) auf...`);
      
      // Build filter parameters
      const filterParams = {};
      
      if (dissolveAll) {
        filterParams.all = true;
      } else {
        // Apply current filters
        if (vornameFilter) filterParams.sus_vorn = vornameFilter;
        if (nachnameFilter) filterParams.sus_nachn = nachnameFilter;
        if (klasseFilter) filterParams.sus_kl = klasseFilter;
        if (itnrFilter) filterParams.itnr = itnrFilter;
      }
      
      // Call batch dissolve endpoint
      const response = await api.post('/assignments/batch-dissolve', filterParams);
      
      toast.success(`✅ ${response.data.dissolved_count} Zuordnung(en) erfolgreich aufgelöst!`);
      
      // Reload data
      await loadAllData();
      
    } catch (error) {
      console.error('Batch dissolve error:', error);
      toast.error(error.response?.data?.detail || 'Fehler beim Auflösen der Zuordnungen');
    } finally {
      setDissolving(false);
    }
  };

  const handleViewContract = (assignment) => {
    if (assignment.contract_id) {
      setSelectedContractId(assignment.contract_id);
    } else {
      toast.info(`Kein Vertrag für iPad ${assignment.itnr} vorhanden`);
    }
  };

  const handleDismissWarning = async (assignment) => {
    // Double-click protection for warning dismissal
    const now = Date.now();
    if (!assignment._lastWarningClick || (now - assignment._lastWarningClick) > 2000) {
      assignment._lastWarningClick = now;
      toast.info(`Vertragswarnung für ${assignment.student_name} entfernen? Klicken Sie nochmal in 2 Sekunden um zu bestätigen.`);
      return;
    }

    try {
      await api.post(`/assignments/${assignment.id}/dismiss-warning`);
      toast.success('Vertragswarnung entfernt');
      await loadAllData();
    } catch (error) {
      toast.error('Fehler beim Entfernen der Warnung');
      console.error('Warning dismissal error:', error);
    }
  };


  const handleInventoryImport = async (file) => {
    if (!file) return;
    
    setImporting(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      toast.info('Importiere Bestandsliste...');
      
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
      
      // Reload data
      await loadAllData();
      
    } catch (error) {
      console.error('Failed to import inventory:', error);
      toast.error(error.response?.data?.detail || 'Fehler beim Importieren der Bestandsliste');
    } finally {
      setImporting(false);
    }
  };

  const handleUploadContractForAssignment = async (assignment, file) => {
    if (!file) return;
    
    setUploadingContractForAssignment(assignment.id);
    
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      toast.info(`Lade neuen Vertrag für ${assignment.student_name} hoch...`);
      
      const response = await api.post(`/assignments/${assignment.id}/upload-contract`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      
      toast.success(response.data.message);
      
      // Reload assignments to show updated validation status
      await loadAllData();
      
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Upload des Vertrags');
      console.error('Contract upload error:', error);
    } finally {
      setUploadingContractForAssignment(null);
    }
  };

  const handleExport = async (filtered = false) => {
    setExporting(true);
    try {
      // Build query parameters for filtered export
      const params = new URLSearchParams();
      if (filtered) {
        if (vornameFilter) params.append('sus_vorn', vornameFilter);
        if (nachnameFilter) params.append('sus_nachn', nachnameFilter);
        if (klasseFilter) params.append('sus_kl', klasseFilter);
        if (itnrFilter) params.append('itnr', itnrFilter);
      }
      
      const queryString = params.toString();
      const url = queryString ? `/assignments/export?${queryString}` : '/assignments/export';
      
      const response = await api.get(url, {
        responseType: 'blob'
      });
      
      const blob = new Blob([response.data], {
        type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      });
      
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      
      // Different filename for filtered vs all exports
      const filename = filtered ? 'zuordnungen_gefiltert_export.xlsx' : 'zuordnungen_export.xlsx';
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      window.URL.revokeObjectURL(downloadUrl);
      document.body.removeChild(link);
      
      const message = filtered ? 'Gefilterte Zuordnungen erfolgreich exportiert' : 'Alle Zuordnungen erfolgreich exportiert';
      toast.success(message);
    } catch (error) {
      toast.error('Fehler beim Export');
      console.error('Export error:', error);
    } finally {
      setExporting(false);
    }
  };

  const clearFilters = () => {
    setVornameFilter('');
    setNachnameFilter('');
    setKlasseFilter('');
    setItnrFilter('');
  };

  const unassignedStudents = students.filter(student => !student.current_assignment_id);
  // Verfügbare iPads = nicht zugewiesen (unabhängig vom Status ok/defekt/gestohlen)
  const availableIPads = ipads.filter(ipad => !ipad.current_assignment_id);

  return (
    <div className="space-y-6">
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle>Automatische Zuordnung</CardTitle>
          <CardDescription>
            Weist verfügbare iPads automatisch Schülern ohne iPad zu
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col gap-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
              <div className="bg-blue-50 p-3 rounded-lg">
                <div className="font-medium text-blue-800">Verfügbare iPads</div>
                <div className="text-2xl font-bold text-blue-600">{availableIPads.length}</div>
              </div>
              <div className="bg-green-50 p-3 rounded-lg">
                <div className="font-medium text-green-800">Schüler ohne iPad</div>
                <div className="text-2xl font-bold text-green-600">{unassignedStudents.length}</div>
              </div>
              <div className="bg-purple-50 p-3 rounded-lg">
                <div className="font-medium text-purple-800">Aktuelle Zuordnungen</div>
                <div className="text-2xl font-bold text-purple-600">{assignments.length}</div>
              </div>
            </div>
            <Button 
              onClick={handleAutoAssign}
              disabled={assigning || availableIPads.length === 0 || unassignedStudents.length === 0}
              className="bg-gradient-to-r from-ipad-teal to-ipad-blue hover:from-ipad-blue hover:to-ipad-dark-blue disabled:opacity-50"
            >
              {assigning ? 'Zuordnung läuft...' : 'Automatische Zuordnung starten'}
            </Button>
            {(availableIPads.length === 0 || unassignedStudents.length === 0) && (
              <p className="text-sm text-gray-600">
                {availableIPads.length === 0 && 'Keine verfügbaren iPads vorhanden. '}
                {unassignedStudents.length === 0 && 'Alle Schüler haben bereits ein iPad. '}
              </p>
            )}
          </div>
        </CardContent>
      </Card>

      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Zuordnungen verwalten ({filteredAssignments.length} von {assignments.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {/* Import Section - analog zu Schüler/iPad-Ansichten */}
          <Card className="mb-6">
            <CardHeader>
              <CardTitle>Bestandsliste-Import</CardTitle>
              <CardDescription>
                Excel-Datei mit vollständigen Daten hochladen (Bestandsliste mit iPads, Schülern, Zuordnungen - .xlsx Format)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-blue-400 transition-colors">
                <Input
                  type="file"
                  accept=".xlsx,.xls"
                  onChange={(e) => e.target.files[0] && handleInventoryImport(e.target.files[0])}
                  disabled={importing}
                  className="mb-4"
                />
                {importing && (
                  <div className="text-sm text-gray-600">
                    Bestandsliste wird hochgeladen und verarbeitet...
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Filter Controls */}
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6 p-4 bg-gray-50 rounded-lg">
            <div>
              <Label htmlFor="vorname">Vorname filtern:</Label>
              <Input
                id="vorname"
                value={vornameFilter}
                onChange={(e) => setVornameFilter(e.target.value)}
                placeholder="z.B. Anna"
                className="mt-1"
              />
            </div>
            <div>
              <Label htmlFor="nachname">Nachname filtern:</Label>
              <Input
                id="nachname"
                value={nachnameFilter}
                onChange={(e) => setNachnameFilter(e.target.value)}
                placeholder="z.B. Müller"
                className="mt-1"
              />
            </div>
            <div>
              <Label htmlFor="klasse">Klasse filtern:</Label>
              <Input
                id="klasse"
                value={klasseFilter}
                onChange={(e) => setKlasseFilter(e.target.value)}
                placeholder="z.B. 5A"
                className="mt-1"
              />
            </div>
            <div>
              <Label htmlFor="itnr">IT-Nummer filtern:</Label>
              <Input
                id="itnr"
                value={itnrFilter}
                onChange={(e) => setItnrFilter(e.target.value)}
                placeholder="z.B. IPAD001"
                className="mt-1"
              />
            </div>
            <div className="flex flex-col justify-end">
              <Button variant="outline" onClick={clearFilters} className="mt-1">
                Filter zurücksetzen
              </Button>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-2 mb-4">
            <Button 
              onClick={() => handleExport(false)}
              disabled={exporting}
              className="bg-gradient-to-r from-ipad-teal to-ipad-blue hover:from-ipad-blue hover:to-ipad-dark-blue"
            >
              <Download className="h-4 w-4 mr-2" />
              {exporting ? 'Exportiere...' : 'Alle Zuordnungen exportieren'}
            </Button>
            
            <Button 
              onClick={() => handleBatchDissolve(true)}
              disabled={dissolving || assignments.length === 0}
              className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white"
            >
              <Trash2 className="h-4 w-4 mr-2" />
              {dissolving ? 'Löse auf...' : `Alle Zuordnungen lösen (${assignments.length})`}
            </Button>
            
            {(vornameFilter || nachnameFilter || klasseFilter || itnrFilter) && filteredAssignments.length > 0 && (
              <>
                <Button 
                  onClick={() => handleExport(true)}
                  disabled={exporting}
                  className="bg-gradient-to-r from-ipad-blue to-ipad-dark-blue hover:from-ipad-dark-blue hover:to-ipad-dark-gray"
                >
                  <Download className="h-4 w-4 mr-2" />
                  {exporting ? 'Exportiere...' : `Gefilterte Zuordnungen exportieren (${filteredAssignments.length})`}
                </Button>
                
                <Button 
                  onClick={() => handleBatchDissolve(false)}
                  disabled={dissolving}
                  className="bg-gradient-to-r from-orange-500 to-red-500 hover:from-orange-600 hover:to-red-600 text-white"
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  {dissolving ? 'Löse auf...' : `Gefilterte Zuordnungen lösen (${filteredAssignments.length})`}
                </Button>
              </>
            )}
          </div>

          {loading ? (
            <div className="text-center py-8">Lade Zuordnungen...</div>
          ) : filteredAssignments.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              {assignments.length === 0 
                ? 'Keine Zuordnungen vorhanden. Verwenden Sie die automatische Zuordnung oben.'
                : 'Keine Zuordnungen entsprechen den Filterkriterien.'
              }
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>iPad ITNr</TableHead>
                    <TableHead>Schüler (Klasse)</TableHead>
                    <TableHead>Zugewiesen am</TableHead>
                    <TableHead>Vertrag</TableHead>
                    <TableHead>Aktionen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredAssignments.map((assignment) => (
                    <TableRow 
                      key={assignment.id} 
                      className={`hover:bg-gray-50 ${assignment.contract_warning && !assignment.warning_dismissed ? 'bg-orange-50 border-l-4 border-orange-400' : ''}`}
                    >
                      <TableCell className="font-medium">
                        <div className="flex items-center gap-2">
                          {assignment.contract_warning && !assignment.warning_dismissed && (
                            <AlertTriangle 
                              className="h-4 w-4 text-orange-500 cursor-pointer hover:text-orange-700" 
                              title="Vertragsvalidierung fehlgeschlagen - Doppelklick zum Entfernen"
                              onClick={() => handleDismissWarning(assignment)}
                            />
                          )}
                          {assignment.itnr}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div>
                          <div className="font-medium">{assignment.student_name}</div>
                          <div className="text-sm text-gray-500">
                            {(() => {
                              const student = students.find(s => s.id === assignment.student_id);
                              return student?.sus_kl ? `Klasse: ${student.sus_kl}` : 'Klasse: N/A';
                            })()}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>{new Date(assignment.assigned_at).toLocaleDateString('de-DE')}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Badge className={assignment.contract_id ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}>
                            {assignment.contract_id ? 'Vorhanden' : 'Fehlend'}
                          </Badge>
                          {assignment.contract_warning && !assignment.warning_dismissed && (
                            <span className="text-xs text-orange-600" title="Validierungsfehler: Nutzung/Kenntnisnahme oder Ausgabe-Option nicht korrekt">
                              ⚠️ Validation
                            </span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={(e) => {
                              console.log('🔵 Eye button clicked for assignment:', assignment);
                              e.preventDefault();
                              e.stopPropagation();
                              handleViewContract(assignment);
                            }}
                            title={assignment.contract_id ? "Vertrag anzeigen" : "Kein Vertrag vorhanden"}
                            className={assignment.contract_id ? "hover:bg-blue-50" : "opacity-50"}
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                          
                          {/* Contract Upload Button - Only show for assignments with validation warnings */}
                          {assignment.contract_warning && !assignment.warning_dismissed && (
                            <div className="relative">
                              <input
                                type="file"
                                accept=".pdf"
                                onChange={(e) => {
                                  if (e.target.files[0]) {
                                    handleUploadContractForAssignment(assignment, e.target.files[0]);
                                    e.target.value = ''; // Reset input
                                  }
                                }}
                                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                                disabled={uploadingContractForAssignment === assignment.id}
                              />
                              <Button 
                                variant="outline" 
                                size="sm"
                                title="Neuen korrekten Vertrag hochladen"
                                className="hover:bg-yellow-50 hover:text-yellow-600"
                                disabled={uploadingContractForAssignment === assignment.id}
                              >
                                {uploadingContractForAssignment === assignment.id ? (
                                  <div className="h-4 w-4 animate-spin rounded-full border-2 border-yellow-600 border-t-transparent"></div>
                                ) : (
                                  <Upload className="h-4 w-4" />
                                )}
                              </Button>
                            </div>
                          )}
                          
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={() => {
                              console.log('🗑️ BUTTON CLICKED!', assignment);
                              handleDissolveAssignment(assignment);
                            }}
                            title="Zuordnung auflösen"
                            className="hover:bg-red-50 hover:text-red-600"
                          >
                            <Trash2 className="h-4 w-4" />
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
      
      {/* Contract Viewer Modal */}
      {selectedContractId && (
        <ContractViewer 
          contractId={selectedContractId} 
          onClose={() => setSelectedContractId(null)} 
        />
      )}
      
      {/* Confirmation dialog removed for testing */}
    </div>
  );
};

// Contracts Management Component
const ContractsManagement = () => {
  const [unassignedContracts, setUnassignedContracts] = useState([]);
  const [availableAssignments, setAvailableAssignments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const [contractsRes, assignmentsRes] = await Promise.all([
        api.get('/contracts/unassigned'),
        api.get('/assignments/available-for-contracts')
      ]);
      setUnassignedContracts(contractsRes.data);
      setAvailableAssignments(assignmentsRes.data);
    } catch (error) {
      toast.error('Fehler beim Laden der Vertragsdaten');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleMultipleUpload = async (files) => {
    if (files.length === 0) return;
    
    // Limit to 50 files as specified in requirements
    if (files.length > 50) {
      toast.error('Maximal 50 Dateien können gleichzeitig hochgeladen werden');
      return;
    }

    const formData = new FormData();
    for (let i = 0; i < files.length; i++) {
      formData.append('files', files[i]);
    }
    
    setUploading(true);
    try {
      const response = await api.post('/contracts/upload-multiple', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      
      toast.success(response.data.message);
      if (response.data.details && response.data.details.length > 0) {
        response.data.details.forEach(detail => {
          toast.info(detail);
        });
      }
      
      await loadData();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Upload der Verträge');
    } finally {
      setUploading(false);
    }
  };

  const handleAssignContract = async (contractId, assignmentId) => {
    try {
      await api.post(`/contracts/${contractId}/assign/${assignmentId}`);
      toast.success('Vertrag erfolgreich zugeordnet');
      await loadData();
    } catch (error) {
      toast.error('Fehler bei der Zuordnung');
    }
  };

  const handleDownloadContract = async (contract) => {
    try {
      const response = await api.get(`/contracts/${contract.id}/download`, {
        responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', contract.filename);
      document.body.appendChild(link);
      link.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(link);
    } catch (error) {
      toast.error('Fehler beim Download');
    }
  };

  const handleDeleteContract = async (contract) => {
    // Double-click protection
    const now = Date.now();
    if (!contract._lastDeleteClick || (now - contract._lastDeleteClick) > 3000) {
      contract._lastDeleteClick = now;
      toast.info(`Vertrag ${contract.filename} löschen? Klicken Sie nochmal in 3 Sekunden um zu bestätigen.`);
      return;
    }

    try {
      await api.delete(`/contracts/${contract.id}`);
      toast.success('Vertrag erfolgreich gelöscht');
      await loadData();
    } catch (error) {
      toast.error('Fehler beim Löschen des Vertrags');
    }
  };

  return (
    <div className="space-y-6">
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" />
            Verträge hochladen
          </CardTitle>
          <CardDescription>
            PDF-Verträge hochladen (bis zu 50 Dateien gleichzeitig)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-blue-400 transition-colors">
            <Input
              type="file"
              accept=".pdf"
              multiple
              onChange={(e) => handleMultipleUpload(Array.from(e.target.files))}
              className="mb-4"
              disabled={uploading}
            />
            {uploading && (
              <div className="text-sm text-gray-600">
                Verträge werden hochgeladen und verarbeitet...
              </div>
            )}
            
            {/* Upload Guidelines */}
            <div className="mt-4 p-4 bg-blue-50 rounded-lg text-left">
              <h4 className="font-medium text-blue-800 mb-2">Upload-Hinweise:</h4>
              <ul className="text-sm text-blue-700 space-y-1">
                <li>• PDF-Verträge mit Formularfeldern werden automatisch zugeordnet</li>
                <li>• Verträge ohne Felder werden als "unzugewiesen" markiert</li>
                <li>• Maximale Upload-Anzahl: 50 Dateien gleichzeitig</li>
                <li>• Erwartete Felder: ITNr, SuSVorn, SuSNachn</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Unzugewiesene Verträge ({unassignedContracts.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-center py-8">Lade Verträge...</div>
          ) : unassignedContracts.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              Keine unzugewiesenen Verträge vorhanden.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Dateiname</TableHead>
                    <TableHead>Hochgeladen am</TableHead>
                    <TableHead>Zuordnung</TableHead>
                    <TableHead>Aktionen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {unassignedContracts.map((contract) => (
                    <TableRow key={contract.id} className="hover:bg-gray-50">
                      <TableCell className="font-medium">{contract.filename}</TableCell>
                      <TableCell>
                        {new Date(contract.uploaded_at).toLocaleDateString('de-DE')}
                      </TableCell>
                      <TableCell>
                        <Select
                          onValueChange={(assignmentId) => handleAssignContract(contract.id, assignmentId)}
                        >
                          <SelectTrigger className="w-64">
                            <SelectValue placeholder="Zuordnung auswählen..." />
                          </SelectTrigger>
                          <SelectContent>
                            {availableAssignments.map((assignment) => (
                              <SelectItem key={assignment.id} value={assignment.id}>
                                {assignment.itnr} → {assignment.student_name}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={() => handleDownloadContract(contract)}
                            title="Vertrag herunterladen"
                            className="hover:bg-green-50"
                          >
                            <Download className="h-4 w-4" />
                          </Button>
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={() => handleDeleteContract(contract)}
                            title="Vertrag löschen"
                            className="hover:bg-red-50 hover:text-red-600"
                          >
                            <Trash2 className="h-4 w-4" />
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
    </div>
  );
};

// Settings Component
const Settings = () => {
  const [cleaning, setCleaning] = useState(false);
  const [exporting, setExporting] = useState(false);
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
      
      toast.success('Bestandsliste erfolgreich exportiert');
    } catch (error) {
      console.error('Failed to export inventory:', error);
      toast.error('Fehler beim Exportieren der Bestandsliste');
    } finally {
      setExporting(false);
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
            Standard-Werte für iPad-Typ und Pencil-Ausstattung
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

      {/* Inventory Export & Import */}
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" />
            Bestandsliste-Export & Import
          </CardTitle>
          <CardDescription>
            Bestandsliste exportieren oder importieren für Datenwiederherstellung
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {/* Export Section */}
            <div className="border-l-4 border-green-400 bg-green-50 p-4 rounded">
              <h4 className="font-medium text-green-800 mb-2">Bestandsliste-Export (Backup)</h4>
              <p className="text-sm text-green-700 mb-4">
                Exportiert eine vollständige Excel-Datei mit allen iPads und zugehörigen Schülerdaten. 
                Beinhaltet alle Spalten: Schülerdaten, iPad-Details, Zuordnungsinformationen.
              </p>
              <Button 
                onClick={handleInventoryExport}
                disabled={exporting}
                className="bg-gradient-to-r from-ipad-teal to-ipad-blue hover:from-ipad-blue hover:to-ipad-dark-blue transition-all duration-200"
              >
                <Download className="h-4 w-4 mr-2" />
                {exporting ? 'Exportiert...' : 'Bestandsliste exportieren'}
              </Button>
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
                <div>Umgebung: Produktion</div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

// Session Timer Component
const SessionTimer = ({ onLogout }) => {
  const [timeLeft, setTimeLeft] = useState(30 * 60); // 30 minutes in seconds
  const [lastActivity, setLastActivity] = useState(Date.now());

  useEffect(() => {
    const updateActivity = () => {
      setLastActivity(Date.now());
      setTimeLeft(30 * 60); // Reset timer on activity
    };

    // Activity events to monitor
    const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'];
    
    events.forEach(event => {
      document.addEventListener(event, updateActivity, true);
    });

    // Timer countdown
    const timer = setInterval(() => {
      setTimeLeft(prev => {
        if (prev <= 1) {
          // Auto logout
          toast.error('Session abgelaufen. Sie werden automatisch abgemeldet.');
          setTimeout(() => {
            onLogout();
          }, 3000);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    // Warning at 5 minutes left
    const warningTimer = setInterval(() => {
      const current = Date.now();
      const timeSinceActivity = (current - lastActivity) / 1000;
      
      if (timeSinceActivity >= 25 * 60 && timeSinceActivity < 25 * 60 + 5) { // 25 minutes
        toast.warning('Session läuft in 5 Minuten ab. Bewegen Sie die Maus, um die Session zu verlängern.');
      }
    }, 5000);

    return () => {
      events.forEach(event => {
        document.removeEventListener(event, updateActivity, true);
      });
      clearInterval(timer);
      clearInterval(warningTimer);
    };
  }, [lastActivity, onLogout]);

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <div className={`text-sm px-3 py-1 rounded ${timeLeft < 5 * 60 ? 'bg-red-100 text-red-800' : 'bg-gray-100 text-gray-600'}`}>
      Session: {formatTime(timeLeft)}
    </div>
  );
};


// User Management Component (Admin Only)
const UserManagement = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showResetPasswordDialog, setShowResetPasswordDialog] = useState(false);
  const [showDeleteConfirmDialog, setShowDeleteConfirmDialog] = useState(false);
  const [deleteStep, setDeleteStep] = useState(1); // 1 = first confirm, 2 = second confirm
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
      '⚠️ WARNUNG: Verwaiste Daten löschen?\n\n' +
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
        `✅ Cleanup abgeschlossen!\n` +
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
    
    // Passwort-Validierung wenn Passwort geändert wird
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
    // Open first confirmation dialog
    setSelectedUser(user);
    setDeleteStep(1);
    setDeleteConfirmText('');
    setShowDeleteConfirmDialog(true);
  };

  const handleDeleteStep1Confirm = async () => {
    // Count user's resources
    try {
      const [ipadsRes, studentsRes, assignmentsRes] = await Promise.all([
        api.get('/ipads'),
        api.get('/students'),
        api.get('/assignments')
      ]);
      
      // Filter by selected user
      const userIpads = ipadsRes.data.filter(i => i.user_id === selectedUser.id);
      const userStudents = studentsRes.data.filter(s => s.user_id === selectedUser.id);
      const userAssignments = assignmentsRes.data.filter(a => a.user_id === selectedUser.id);
      
      // Store counts for second confirmation
      selectedUser.resourceCounts = {
        ipads: userIpads.length,
        students: userStudents.length,
        assignments: userAssignments.length
      };
      
      // Move to step 2
      setDeleteStep(2);
    } catch (error) {
      toast.error('Fehler beim Laden der Ressourcen-Anzahl');
    }
  };

  const handleDeleteStep2Confirm = async () => {
    // Check if user typed the confirmation text correctly
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
        
        // Show temporary password in copyable dialog
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
                              ⚠️ PW ändern
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
                            title="⚠️ VOLLSTÄNDIG LÖSCHEN (inkl. aller Daten!)"
                            className="hover:bg-red-100 hover:text-red-700 border-red-200"
                            disabled={!user.is_active}
                          >
                            <Trash2 className="h-4 w-4 text-red-600" />
                            <span className="ml-1 text-xs font-bold">×</span>
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
                      <p className="text-sm text-red-600">⚠️ Passwörter stimmen nicht überein</p>
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
              <CardTitle className="text-green-600">✅ Passwort erfolgreich zurückgesetzt!</CardTitle>
              <CardDescription>
                Das temporäre Passwort wurde generiert
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Alert className="bg-yellow-50 border-yellow-200">
                <AlertTriangle className="h-4 w-4 text-yellow-600" />
                <AlertDescription className="text-yellow-800 font-medium">
                  ⚠️ WICHTIG: Dieser Code wird nur einmal angezeigt!<br/>
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
                    📋 Kopieren
                  </Button>
                </div>
                <p className="text-sm text-gray-500">
                  Sie können das Passwort markieren und kopieren (Strg+C)
                </p>
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

      {/* Complete Delete Confirmation Dialog - Two Steps */}
      {showDeleteConfirmDialog && selectedUser && (
        <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-lg border-4 border-red-500">
            <CardHeader className="bg-red-50">
              <CardTitle className="text-red-700 flex items-center gap-2">
                <AlertTriangle className="h-6 w-6" />
                {deleteStep === 1 ? '⚠️ WARNUNG: Benutzer vollständig löschen?' : '🚨 LETZTE WARNUNG'}
              </CardTitle>
              <CardDescription className="text-red-600 font-medium">
                {deleteStep === 1 
                  ? 'Diese Aktion ist UNWIDERRUFLICH und löscht ALLE Daten!'
                  : 'Sind Sie ABSOLUT SICHER? Es gibt KEIN Zurück!'}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 pt-6">
              
              {deleteStep === 1 ? (
                // STEP 1: First Warning
                <>
                  <Alert className="bg-red-50 border-red-300">
                    <AlertTriangle className="h-5 w-5 text-red-600" />
                    <AlertDescription className="text-red-800">
                      <div className="font-bold text-lg mb-2">
                        Sie sind dabei, Benutzer "{selectedUser.username}" VOLLSTÄNDIG zu löschen!
                      </div>
                      <div className="space-y-1 text-sm">
                        <p>• Der Benutzer wird PERMANENT gelöscht</p>
                        <p>• ALLE iPads des Benutzers werden gelöscht</p>
                        <p>• ALLE Schüler des Benutzers werden gelöscht</p>
                        <p>• ALLE Zuordnungen werden gelöscht</p>
                        <p>• ALLE Verträge werden gelöscht</p>
                      </div>
                    </AlertDescription>
                  </Alert>

                  <div className="bg-yellow-50 border border-yellow-300 rounded p-4">
                    <p className="text-sm text-yellow-800 font-medium mb-2">
                      💡 Alternative: Benutzer nur deaktivieren
                    </p>
                    <p className="text-xs text-yellow-700">
                      Wenn Sie den Benutzer nur vorübergehend sperren möchten, verwenden Sie stattdessen 
                      den "Deaktivieren"-Button (🗑️). Dies bewahrt alle Daten.
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
                      Weiter zur Bestätigung →
                    </Button>
                  </div>
                </>
              ) : (
                // STEP 2: Final Confirmation with username typing
                <>
                  <Alert className="bg-red-100 border-red-400">
                    <AlertTriangle className="h-5 w-5 text-red-700" />
                    <AlertDescription className="text-red-900">
                      <div className="font-bold text-lg mb-3">
                        🚨 LETZTE BESTÄTIGUNG ERFORDERLICH
                      </div>
                      {selectedUser.resourceCounts && (
                        <div className="bg-white rounded p-3 mb-3">
                          <p className="font-semibold mb-2">Folgende Daten werden PERMANENT gelöscht:</p>
                          <ul className="space-y-1 text-sm">
                            <li>• <strong>{selectedUser.resourceCounts.ipads}</strong> iPads</li>
                            <li>• <strong>{selectedUser.resourceCounts.students}</strong> Schüler</li>
                            <li>• <strong>{selectedUser.resourceCounts.assignments}</strong> Zuordnungen</li>
                            <li>• Benutzer-Account: <strong>{selectedUser.username}</strong></li>
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
                        ⚠️ Benutzername stimmt nicht überein
                      </p>
                    )}
                  </div>

                  <div className="flex gap-2 justify-end pt-4">
                    <Button 
                      variant="outline"
                      onClick={() => setDeleteStep(1)}
                    >
                      ← Zurück
                    </Button>
                    <Button 
                      onClick={handleDeleteStep2Confirm}
                      disabled={deleteConfirmText !== selectedUser.username}
                      className="bg-red-700 hover:bg-red-800 text-white disabled:bg-gray-400"
                    >
                      🗑️ ENDGÜLTIG LÖSCHEN
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

// Main Dashboard Component
const Dashboard = ({ onLogout, userRole, currentUsername }) => {
  const [activeTab, setActiveTab] = useState('students');
  const isAdmin = userRole === 'admin';

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-ipad-dark-gray shadow-sm border-b border-ipad-beige">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <div className="flex-shrink-0 flex items-center">
                <div className="w-8 h-8 bg-gradient-to-br from-ipad-teal to-ipad-blue rounded-lg flex items-center justify-center">
                  <Tablet className="h-5 w-5 text-white" />
                </div>
                <span className="ml-3 text-xl font-bold bg-gradient-to-r from-ipad-teal to-ipad-blue bg-clip-text text-transparent">
                  iPad-Verwaltung
                </span>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-white">
                <User className="h-4 w-4" />
                <span className="text-sm font-medium">{currentUsername}</span>
                {isAdmin && (
                  <span className="ml-2 px-2 py-1 bg-gradient-to-r from-yellow-400 to-orange-500 text-white text-xs font-bold rounded-full">
                    ADMIN
                  </span>
                )}
              </div>
              <SessionTimer onLogout={onLogout} />
              <Button variant="outline" onClick={onLogout} className="flex items-center gap-2">
                <LogOut className="h-4 w-4" />
                Abmelden
              </Button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className={`grid w-full ${isAdmin ? 'grid-cols-6' : 'grid-cols-5'} mb-8`}>
            <TabsTrigger value="students" className="flex items-center gap-2">
              <Users className="h-4 w-4" />
              Schüler
            </TabsTrigger>
            <TabsTrigger value="ipads" className="flex items-center gap-2">
              <Tablet className="h-4 w-4" />
              iPads
            </TabsTrigger>
            <TabsTrigger value="assignments" className="flex items-center gap-2">
              <FileText className="h-4 w-4" />
              Zuordnungen
            </TabsTrigger>
            <TabsTrigger value="contracts" className="flex items-center gap-2">
              <FileText className="h-4 w-4" />
              Verträge
            </TabsTrigger>
            <TabsTrigger value="settings" className="flex items-center gap-2">
              <SettingsIcon className="h-4 w-4" />
              Einstellungen
            </TabsTrigger>
            {isAdmin && (
              <TabsTrigger value="users" className="flex items-center gap-2 bg-gradient-to-r from-yellow-400/10 to-orange-500/10">
                <Users className="h-4 w-4" />
                Benutzer
              </TabsTrigger>
            )}
          </TabsList>

          <TabsContent value="students">
            <StudentsManagement />
          </TabsContent>

          <TabsContent value="ipads">
            <IPadsManagement />
          </TabsContent>

          <TabsContent value="assignments">
            <AssignmentsManagement />
          </TabsContent>

          <TabsContent value="contracts">
            <ContractsManagement />
          </TabsContent>

          <TabsContent value="settings">
            <Settings />
          </TabsContent>

          {isAdmin && (
            <TabsContent value="users">
              <UserManagement />
            </TabsContent>
          )}
        </Tabs>
      </div>
    </div>
  );
};

// Main App Component
function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userRole, setUserRole] = useState('user');
  const [currentUsername, setCurrentUsername] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const savedRole = localStorage.getItem('userRole');
    const savedUsername = localStorage.getItem('username');
    if (token) {
      setIsAuthenticated(true);
      setUserRole(savedRole || 'user');
      setCurrentUsername(savedUsername || '');
    }
    setLoading(false);
  }, []);

  const handleLogin = (role, username) => {
    setIsAuthenticated(true);
    setUserRole(role);
    setCurrentUsername(username);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('userRole');
    localStorage.removeItem('username');
    setIsAuthenticated(false);
    setUserRole('user');
    setCurrentUsername('');
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-ipad-beige via-gray-50 to-ipad-teal/10 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-ipad-teal mx-auto"></div>
          <p className="mt-4 text-ipad-dark-gray">Lade Anwendung...</p>
        </div>
      </div>
    );
  }

  return (
    <Router>
      <div className="App">
        <Toaster richColors position="bottom-right" />
        <Routes>
          <Route 
            path="/" 
            element={
              isAuthenticated ? (
                <Dashboard 
                  onLogout={handleLogout} 
                  userRole={userRole} 
                  currentUsername={currentUsername}
                />
              ) : (
                <Login onLogin={handleLogin} />
              )
            } 
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;