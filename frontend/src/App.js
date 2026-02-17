import React, { useState, useEffect, useCallback } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import './App.css';

// API Configuration (extracted)
import api, { API_BASE_URL, SESSION_TIMEOUT, SESSION_WARNING } from './api';

// Extracted Components
import Login from './components/auth/Login';
import IPadDetailViewer from './components/ipads/IPadDetailViewer';
import IPadsManagement from './components/ipads/IPadsManagement';
import StudentsManagement from './components/students/StudentsManagement';
import AssignmentsManagement from './components/assignments/AssignmentsManagement';
import ContractsManagement from './components/contracts/ContractsManagement';
import Settings from './components/settings/Settings';
import SessionTimer from './components/shared/SessionTimer';
import UserManagement from './components/users/UserManagement';

// Import UI components
import { Button } from './components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import { toast } from 'sonner';
import { Toaster } from './components/ui/sonner';
import { Users, Tablet, FileText, Settings as SettingsIcon, LogOut } from 'lucide-react';

// Main Dashboard Component
const Dashboard = ({ onLogout, userRole, currentUsername }) => {
  const [activeTab, setActiveTab] = useState('students');
  const isAdmin = userRole === 'admin';
  
  // Filter states
  const [itnrFilter, setItnrFilter] = useState('');
  const [snrFilter, setSnrFilter] = useState('');
  
  // Autocomplete states (now dialog-based)
  const [searchDialogOpen, setSearchDialogOpen] = useState(false);
  const [searchDialogIpadId, setSearchDialogIpadId] = useState(null);
  const [studentSearchQuery, setStudentSearchQuery] = useState('');
  
  // Sort states
  const [sortField, setSortField] = useState(null);
  const [sortDirection, setSortDirection] = useState('asc');
  
  // Batch delete states
  const [selectedIPads, setSelectedIPads] = useState([]);
  const [deleting, setDeleting] = useState(false);
  
  // Delete dialog states
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [ipadToDelete, setIPadToDelete] = useState(null);
  const [batchDeleteDialogOpen, setBatchDeleteDialogOpen] = useState(false);
  
  // Create dialog states
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [newIPadData, setNewIPadData] = useState({
    itnr: '',
    snr: '',
    typ: '',
    status: 'ok'
  });
  const [creating, setCreating] = useState(false);
  
  // Assignment info dialog (click on "Ja" badge to see assigned student)
  const [assignmentInfoDialogOpen, setAssignmentInfoDialogOpen] = useState(false);
  const [assignmentInfoIpad, setAssignmentInfoIpad] = useState(null);
  const [assignmentInfoStudent, setAssignmentInfoStudent] = useState(null);
  const [assignmentInfoLoading, setAssignmentInfoLoading] = useState(false);
  
  // Load assignment info for iPad
  const loadAssignmentInfo = async (ipad) => {
    setAssignmentInfoLoading(true);
    setAssignmentInfoIpad(ipad);
    setAssignmentInfoDialogOpen(true);
    try {
      const response = await api.get(`/ipads/${ipad.id}/history`);
      // Find the active assignment from the assignments array
      const activeAssignment = response.data.assignments?.find(a => a.is_active);
      if (activeAssignment) {
        // Get student details
        const studentResponse = await api.get('/students');
        const student = studentResponse.data.find(s => s.id === activeAssignment.student_id);
        setAssignmentInfoStudent({
          ...student,
          assignment: activeAssignment
        });
      } else {
        setAssignmentInfoStudent(null);
      }
    } catch (error) {
      toast.error('Fehler beim Laden der Zuordnungsinformationen');
    } finally {
      setAssignmentInfoLoading(false);
    }
  };
  
  // Dissolve assignment from iPad view
  const dissolveAssignmentFromIPad = async (assignmentId) => {
    try {
      await api.delete(`/assignments/${assignmentId}`);
      toast.success('Zuordnung erfolgreich aufgelöst');
      setAssignmentInfoDialogOpen(false);
      setAssignmentInfoStudent(null);
      loadIPads();
    } catch (error) {
      toast.error('Fehler beim Auflösen der Zuordnung');
    }
  };
  
  // Filtered and sorted iPads
  const filteredIPads = ipads.filter(ipad => {
    const itnrMatch = !itnrFilter || ipad.itnr?.toLowerCase().includes(itnrFilter.toLowerCase());
    const snrMatch = !snrFilter || ipad.snr?.toLowerCase().includes(snrFilter.toLowerCase());
    return itnrMatch && snrMatch;
  }).sort((a, b) => {
    if (!sortField) return 0;
    
    let aVal = a[sortField] || '';
    let bVal = b[sortField] || '';
    
    // Handle assigned status (boolean -> number for 1:n)
    if (sortField === 'assigned') {
      aVal = a.assignment_count || 0;
      bVal = b.assignment_count || 0;
    }
    
    // String comparison
    if (typeof aVal === 'string') {
      aVal = aVal.toLowerCase();
      bVal = bVal.toLowerCase();
    }
    
    if (sortDirection === 'asc') {
      return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
    } else {
      return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
    }
  });
  
  // Sort handler
  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };
  
  // Batch delete handlers
  const toggleIPadSelection = (ipadId) => {
    setSelectedIPads(prev =>
      prev.includes(ipadId)
        ? prev.filter(id => id !== ipadId)
        : [...prev, ipadId]
    );
  };
  
  const toggleAllIPads = () => {
    if (selectedIPads.length === filteredIPads.length) {
      setSelectedIPads([]);
    } else {
      setSelectedIPads(filteredIPads.map(ipad => ipad.id));
    }
  };
  
  const openBatchDeleteDialog = () => {
    if (selectedIPads.length === 0) return;
    setBatchDeleteDialogOpen(true);
  };
  
  const handleBatchDelete = async () => {
    setDeleting(true);
    let successCount = 0;
    let errorCount = 0;
    
    for (const ipadId of selectedIPads) {
      try {
        await api.delete(`/ipads/${ipadId}`);
        successCount++;
      } catch (error) {
        errorCount++;
        console.error(`Failed to delete iPad ${ipadId}:`, error);
      }
    }
    
    setDeleting(false);
    setSelectedIPads([]);
    
    if (successCount > 0) {
      toast.success(`${successCount} iPad(s) erfolgreich gelöscht`);
      loadIPads();
    }
    if (errorCount > 0) {
      toast.error(`${errorCount} iPad(s) konnten nicht gelöscht werden`);
    }
  };

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

  const handleDeleteIPad = (ipad) => {
    setIPadToDelete(ipad);
    setDeleteDialogOpen(true);
  };
  
  const confirmDeleteIPad = async () => {
    if (!ipadToDelete) return;
    
    try {
      const response = await api.delete(`/ipads/${ipadToDelete.id}`);
      
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
    } finally {
      setDeleteDialogOpen(false);
      setIPadToDelete(null);
    }
  };
  
  const confirmBatchDeleteIPads = async () => {
    setBatchDeleteDialogOpen(false);
    await handleBatchDelete();
  };
  
  const handleCreateIPad = async () => {
    if (!newIPadData.itnr || !newIPadData.snr) {
      toast.error('ITNr und SNr sind Pflichtfelder');
      return;
    }
    
    setCreating(true);
    try {
      const response = await api.post('/ipads', newIPadData);
      toast.success('iPad erfolgreich angelegt!');
      setCreateDialogOpen(false);
      setNewIPadData({ itnr: '', snr: '', typ: '', status: 'ok' });
      loadIPads();
    } catch (error) {
      console.error('Create iPad error:', error);
      toast.error(error.response?.data?.detail || 'Fehler beim Anlegen des iPads');
    } finally {
      setCreating(false);
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
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Tablet className="h-5 w-5" />
              iPads verwalten ({ipads.length})
            </CardTitle>
            <Button onClick={() => setCreateDialogOpen(true)} className="flex items-center gap-2">
              <Plus className="h-4 w-4" />
              Neues iPad anlegen
            </Button>
          </div>
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
          
          {/* Batch Delete Button */}
          {selectedIPads.length > 0 && (
            <div className="mb-4">
              <Button
                onClick={openBatchDeleteDialog}
                variant="destructive"
                disabled={deleting}
              >
                {deleting ? 'Lösche...' : `${selectedIPads.length} iPad(s) löschen`}
              </Button>
            </div>
          )}
          
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
                    <TableHead className="w-12">
                      <Checkbox
                        checked={selectedIPads.length === filteredIPads.length && filteredIPads.length > 0}
                        onCheckedChange={toggleAllIPads}
                      />
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-50"
                      onClick={() => handleSort('itnr')}
                    >
                      <div className="flex items-center gap-1">
                        ITNr
                        {sortField === 'itnr' && (
                          sortDirection === 'asc' ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />
                        )}
                      </div>
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-50"
                      onClick={() => handleSort('snr')}
                    >
                      <div className="flex items-center gap-1">
                        SNr
                        {sortField === 'snr' && (
                          sortDirection === 'asc' ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />
                        )}
                      </div>
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-50"
                      onClick={() => handleSort('typ')}
                    >
                      <div className="flex items-center gap-1">
                        Typ
                        {sortField === 'typ' && (
                          sortDirection === 'asc' ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />
                        )}
                      </div>
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-50"
                      onClick={() => handleSort('status')}
                    >
                      <div className="flex items-center gap-1">
                        Status
                        {sortField === 'status' && (
                          sortDirection === 'asc' ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />
                        )}
                      </div>
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-50"
                      onClick={() => handleSort('assigned')}
                    >
                      <div className="flex items-center gap-1">
                        Zugewiesen
                        {sortField === 'assigned' && (
                          sortDirection === 'asc' ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />
                        )}
                      </div>
                    </TableHead>
                    <TableHead>Aktionen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredIPads.map((ipad) => (
                    <TableRow key={ipad.id} className={getRowClassName(ipad.status)}>
                      <TableCell>
                        <Checkbox
                          checked={selectedIPads.includes(ipad.id)}
                          onCheckedChange={() => toggleIPadSelection(ipad.id)}
                          disabled={ipad.current_assignment_id}
                        />
                      </TableCell>
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
                          <Badge 
                            className="bg-blue-100 text-blue-800 cursor-pointer hover:bg-blue-200 transition-colors"
                            onClick={() => loadAssignmentInfo(ipad)}
                            title="Klicken um zugewiesenen Schüler anzuzeigen"
                          >
                            Ja
                          </Badge>
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
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => {
                                setSearchDialogIpadId(ipad.id);
                                setSearchDialogOpen(true);
                                setStudentSearchQuery('');
                              }}
                            >
                              Schüler zuordnen
                            </Button>
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

      {/* Create iPad Dialog */}
      <AlertDialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <AlertDialogContent className="max-w-2xl">
          <AlertDialogHeader>
            <AlertDialogTitle>Neues iPad anlegen</AlertDialogTitle>
            <AlertDialogDescription>
              Geben Sie die Daten für das neue iPad ein.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="itnr">ITNr *</Label>
              <Input
                id="itnr"
                placeholder="z.B. 12345"
                value={newIPadData.itnr}
                onChange={(e) => setNewIPadData({...newIPadData, itnr: e.target.value})}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="snr">SNr *</Label>
              <Input
                id="snr"
                placeholder="z.B. ABC123XYZ"
                value={newIPadData.snr}
                onChange={(e) => setNewIPadData({...newIPadData, snr: e.target.value})}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="typ">Typ (optional)</Label>
              <Input
                id="typ"
                placeholder="z.B. iPad Pro 11"
                value={newIPadData.typ}
                onChange={(e) => setNewIPadData({...newIPadData, typ: e.target.value})}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="status">Status</Label>
              <Select 
                value={newIPadData.status} 
                onValueChange={(value) => setNewIPadData({...newIPadData, status: value})}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ok">OK</SelectItem>
                  <SelectItem value="defekt">Defekt</SelectItem>
                  <SelectItem value="gestohlen">Gestohlen</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>Abbrechen</AlertDialogCancel>
            <AlertDialogAction 
              onClick={handleCreateIPad} 
              disabled={creating || !newIPadData.itnr || !newIPadData.snr}
            >
              {creating ? 'Erstelle...' : 'iPad anlegen'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      
      {/* Delete iPad Confirmation Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>iPad löschen?</AlertDialogTitle>
            <AlertDialogDescription>
              Möchten Sie wirklich das iPad <strong>{ipadToDelete?.itnr}</strong> löschen?
              <br /><br />
              <strong>Dies löscht:</strong>
              <ul className="list-disc list-inside mt-2">
                <li>Das iPad permanent</li>
                <li>Alle Zuordnungs-Historie</li>
                <li>Alle zugehörigen Verträge</li>
              </ul>
              <br />
              Diese Aktion kann nicht rückgängig gemacht werden.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Abbrechen</AlertDialogCancel>
            <AlertDialogAction onClick={confirmDeleteIPad} className="bg-red-600 hover:bg-red-700">
              iPad löschen
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      
      {/* Batch Delete iPads Confirmation Dialog */}
      <AlertDialog open={batchDeleteDialogOpen} onOpenChange={setBatchDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{selectedIPads.length} iPad(s) löschen?</AlertDialogTitle>
            <AlertDialogDescription>
              Möchten Sie wirklich <strong>{selectedIPads.length} iPad(s)</strong> löschen?
              <br /><br />
              <strong>Dies löscht:</strong>
              <ul className="list-disc list-inside mt-2">
                <li>Die iPads permanent</li>
                <li>Alle Zuordnungs-Historien</li>
                <li>Alle zugehörigen Verträge</li>
              </ul>
              <br />
              Diese Aktion kann nicht rückgängig gemacht werden.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Abbrechen</AlertDialogCancel>
            <AlertDialogAction onClick={confirmBatchDeleteIPads} className="bg-red-600 hover:bg-red-700">
              {selectedIPads.length} iPad(s) löschen
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      
      {/* Student Search Dialog */}
      <AlertDialog open={searchDialogOpen} onOpenChange={setSearchDialogOpen}>
        <AlertDialogContent className="max-w-2xl max-h-[80vh]">
          <AlertDialogHeader>
            <AlertDialogTitle>Schüler zuordnen</AlertDialogTitle>
            <AlertDialogDescription>
              Wählen Sie einen Schüler für die Zuordnung aus.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="py-4">
            <Input
              placeholder="Schüler suchen (Name oder Klasse)..."
              value={studentSearchQuery}
              onChange={(e) => setStudentSearchQuery(e.target.value)}
              className="mb-4"
              autoFocus
            />
            <div className="max-h-96 overflow-auto border rounded-md">
              {availableStudents
                .filter(s => 
                  !studentSearchQuery || 
                  s.name.toLowerCase().includes(studentSearchQuery.toLowerCase()) ||
                  s.klasse.toLowerCase().includes(studentSearchQuery.toLowerCase())
                )
                .map((student) => (
                  <div
                    key={student.id}
                    className="px-4 py-3 cursor-pointer hover:bg-gray-100 border-b last:border-b-0"
                    onClick={() => {
                      handleManualAssignment(searchDialogIpadId, student.id);
                      setSearchDialogOpen(false);
                      setStudentSearchQuery('');
                    }}
                  >
                    <div className="font-medium">{student.name}</div>
                    <div className="text-sm text-gray-500">Klasse: {student.klasse}</div>
                  </div>
                ))}
              {availableStudents.filter(s => 
                !studentSearchQuery || 
                s.name.toLowerCase().includes(studentSearchQuery.toLowerCase()) ||
                s.klasse.toLowerCase().includes(studentSearchQuery.toLowerCase())
              ).length === 0 && (
                <div className="px-4 py-8 text-center text-gray-500">
                  Keine Schüler gefunden
                </div>
              )}
            </div>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setStudentSearchQuery('')}>Abbrechen</AlertDialogCancel>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      
      {/* Assignment Info Dialog - Shows assigned student when clicking "Ja" badge */}
      <AlertDialog open={assignmentInfoDialogOpen} onOpenChange={setAssignmentInfoDialogOpen}>
        <AlertDialogContent className="max-w-md">
          <AlertDialogHeader>
            <AlertDialogTitle>
              Zuordnung für iPad {assignmentInfoIpad?.itnr}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {assignmentInfoLoading ? (
                <div className="py-4 text-center">Lade Informationen...</div>
              ) : assignmentInfoStudent ? (
                <div className="space-y-4 mt-4">
                  <div className="bg-gray-50 p-4 rounded-lg space-y-2">
                    <div className="flex justify-between">
                      <span className="text-gray-600">Schüler:</span>
                      <span className="font-medium">{assignmentInfoStudent.sus_vorn} {assignmentInfoStudent.sus_nachn}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Klasse:</span>
                      <span className="font-medium">{assignmentInfoStudent.sus_kl || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Zugewiesen am:</span>
                      <span className="font-medium">
                        {assignmentInfoStudent.assignment?.assigned_at 
                          ? new Date(assignmentInfoStudent.assignment.assigned_at).toLocaleDateString('de-DE')
                          : 'N/A'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">iPads des Schülers:</span>
                      <span className="font-medium">{assignmentInfoStudent.assignment_count || 1}</span>
                    </div>
                  </div>
                  <Button
                    variant="destructive"
                    className="w-full"
                    onClick={() => dissolveAssignmentFromIPad(assignmentInfoStudent.assignment.id)}
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    Zuordnung auflösen
                  </Button>
                </div>
              ) : (
                <div className="py-4 text-center text-gray-500">
                  Keine Zuordnung gefunden
                </div>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => {
              setAssignmentInfoDialogOpen(false);
              setAssignmentInfoStudent(null);
            }}>
              Schließen
            </AlertDialogCancel>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      
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
  const [selectedStudentId, setSelectedStudentId] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const [availableIPads, setAvailableIPads] = useState([]);
  
  // Autocomplete states (now dialog-based)
  const [searchDialogOpen, setSearchDialogOpen] = useState(false);
  const [searchDialogStudentId, setSearchDialogStudentId] = useState(null);
  const [ipadSearchQuery, setIpadSearchQuery] = useState('');
  
  // Filter states
  const [studentVornameFilter, setStudentVornameFilter] = useState('');
  const [studentNachnameFilter, setStudentNachnameFilter] = useState('');
  const [studentKlasseFilter, setStudentKlasseFilter] = useState('');
  
  // Sort states
  const [sortField, setSortField] = useState(null);
  const [sortDirection, setSortDirection] = useState('asc');
  
  // Batch delete states
  const [selectedStudents, setSelectedStudents] = useState([]);
  
  // Delete dialog states
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [studentToDelete, setStudentToDelete] = useState(null);
  const [batchDeleteDialogOpen, setBatchDeleteDialogOpen] = useState(false);
  
  // Create dialog states
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [newStudentData, setNewStudentData] = useState({
    sus_vorn: '',
    sus_nachn: '',
    sus_kl: '',
    sus_geb: '',
    sus_str: '',
    sus_ort: ''
  });
  const [creating, setCreating] = useState(false);
  
  // iPad list dialog (click on "X iPad(s)" badge to see assigned iPads)
  const [ipadListDialogOpen, setIpadListDialogOpen] = useState(false);
  const [ipadListStudent, setIpadListStudent] = useState(null);
  const [ipadListData, setIpadListData] = useState([]);
  const [ipadListLoading, setIpadListLoading] = useState(false);
  
  // Load iPads for a student
  const loadStudentIPads = async (student) => {
    setIpadListLoading(true);
    setIpadListStudent(student);
    setIpadListDialogOpen(true);
    try {
      // Get all assignments for this student
      const assignmentsRes = await api.get('/assignments');
      const studentAssignments = assignmentsRes.data.filter(
        a => a.student_id === student.id && a.is_active
      );
      
      // Get iPad details for each assignment
      const ipadsRes = await api.get('/ipads');
      const studentIPads = studentAssignments.map(assignment => {
        const ipad = ipadsRes.data.find(i => i.id === assignment.ipad_id);
        return {
          ...ipad,
          assignment_id: assignment.id,
          assigned_at: assignment.assigned_at
        };
      }).filter(Boolean);
      
      setIpadListData(studentIPads);
    } catch (error) {
      toast.error('Fehler beim Laden der iPad-Liste');
    } finally {
      setIpadListLoading(false);
    }
  };
  
  // Dissolve single assignment from student view
  const dissolveAssignmentFromStudent = async (assignmentId) => {
    try {
      await api.delete(`/assignments/${assignmentId}`);
      toast.success('Zuordnung erfolgreich aufgelöst');
      // Reload iPad list
      if (ipadListStudent) {
        loadStudentIPads(ipadListStudent);
      }
      loadStudents();
    } catch (error) {
      toast.error('Fehler beim Auflösen der Zuordnung');
    }
  };
  
  // Filtered and sorted students
  const filteredStudents = students.filter(student => {
    const vornMatch = !studentVornameFilter || 
      student.sus_vorn?.toLowerCase().includes(studentVornameFilter.toLowerCase());
    const nachMatch = !studentNachnameFilter || 
      student.sus_nachn?.toLowerCase().includes(studentNachnameFilter.toLowerCase());
    const klMatch = !studentKlasseFilter || 
      student.sus_kl?.toLowerCase().includes(studentKlasseFilter.toLowerCase());
    
    return vornMatch && nachMatch && klMatch;
  }).sort((a, b) => {
    if (!sortField) return 0;
    
    let aVal = a[sortField] || '';
    let bVal = b[sortField] || '';
    
    // Handle assigned status (boolean -> number for 1:n)
    if (sortField === 'assigned') {
      aVal = a.assignment_count || 0;
      bVal = b.assignment_count || 0;
    }
    
    // String comparison
    if (typeof aVal === 'string') {
      aVal = aVal.toLowerCase();
      bVal = bVal.toLowerCase();
    }
    
    if (sortDirection === 'asc') {
      return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
    } else {
      return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
    }
  });
  
  // Sort handler
  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };
  
  // Batch delete handlers
  const toggleStudentSelection = (studentId) => {
    setSelectedStudents(prev =>
      prev.includes(studentId)
        ? prev.filter(id => id !== studentId)
        : [...prev, studentId]
    );
  };
  
  const toggleAllStudents = () => {
    if (selectedStudents.length === filteredStudents.length) {
      setSelectedStudents([]);
    } else {
      setSelectedStudents(filteredStudents.map(student => student.id));
    }
  };
  
  const openBatchDeleteDialog = () => {
    if (selectedStudents.length === 0) return;
    setBatchDeleteDialogOpen(true);
  };
  
  const handleBatchDelete = async () => {
    setDeleting(true);
    let successCount = 0;
    let errorCount = 0;
    
    for (const studentId of selectedStudents) {
      try {
        await api.delete(`/students/${studentId}`);
        successCount++;
      } catch (error) {
        errorCount++;
        console.error(`Failed to delete student ${studentId}:`, error);
      }
    }
    
    setDeleting(false);
    setSelectedStudents([]);
    
    if (successCount > 0) {
      toast.success(`${successCount} Schüler erfolgreich gelöscht`);
      loadStudents();
    }
    if (errorCount > 0) {
      toast.error(`${errorCount} Schüler konnten nicht gelöscht werden`);
    }
  };
  
  const confirmBatchDeleteStudents = async () => {
    setBatchDeleteDialogOpen(false);
    await handleBatchDelete();
  };
  
  const handleCreateStudent = async () => {
    if (!newStudentData.sus_vorn || !newStudentData.sus_nachn) {
      toast.error('Vorname und Nachname sind Pflichtfelder');
      return;
    }
    
    setCreating(true);
    try {
      const response = await api.post('/students', newStudentData);
      toast.success('Schüler erfolgreich angelegt!');
      setCreateDialogOpen(false);
      setNewStudentData({
        sus_vorn: '', sus_nachn: '', sus_kl: '', 
        sus_geb: '', sus_str: '', sus_ort: ''
      });
      loadStudents();
    } catch (error) {
      console.error('Create student error:', error);
      toast.error(error.response?.data?.detail || 'Fehler beim Anlegen des Schülers');
    } finally {
      setCreating(false);
    }
  };

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

  const handleDeleteStudent = (student) => {
    setStudentToDelete(student);
    setDeleteDialogOpen(true);
  };
  
  const confirmDeleteStudent = async () => {
    if (!studentToDelete) return;

    try {
      toast.info('Lösche Schüler und alle zugehörigen Daten...');
      
      const response = await api.delete(`/students/${studentToDelete.id}`);
      
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
    } finally {
      setDeleteDialogOpen(false);
      setStudentToDelete(null);
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
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5" />
              Schüler verwalten ({students.length})
            </CardTitle>
            <Button onClick={() => setCreateDialogOpen(true)} className="flex items-center gap-2">
              <Plus className="h-4 w-4" />
              Neuen Schüler anlegen
            </Button>
          </div>
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
          
          {/* Batch Delete Button */}
          {selectedStudents.length > 0 && (
            <div className="mb-4">
              <Button
                onClick={openBatchDeleteDialog}
                variant="destructive"
                disabled={deleting}
              >
                {deleting ? 'Lösche...' : `${selectedStudents.length} Schüler löschen`}
              </Button>
            </div>
          )}
          
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
                    <TableHead className="w-12">
                      <Checkbox
                        checked={selectedStudents.length === filteredStudents.length && filteredStudents.length > 0}
                        onCheckedChange={toggleAllStudents}
                      />
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-50"
                      onClick={() => handleSort('sus_nachn')}
                    >
                      <div className="flex items-center gap-1">
                        Name
                        {sortField === 'sus_nachn' && (
                          sortDirection === 'asc' ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />
                        )}
                      </div>
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-50"
                      onClick={() => handleSort('sus_kl')}
                    >
                      <div className="flex items-center gap-1">
                        Klasse
                        {sortField === 'sus_kl' && (
                          sortDirection === 'asc' ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />
                        )}
                      </div>
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-50"
                      onClick={() => handleSort('assigned')}
                    >
                      <div className="flex items-center gap-1">
                        iPad-Status
                        {sortField === 'assigned' && (
                          sortDirection === 'asc' ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />
                        )}
                      </div>
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-50"
                      onClick={() => handleSort('created_at')}
                    >
                      <div className="flex items-center gap-1">
                        Erstellt am
                        {sortField === 'created_at' && (
                          sortDirection === 'asc' ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />
                        )}
                      </div>
                    </TableHead>
                    <TableHead>Aktionen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredStudents.map((student) => (
                    <TableRow key={student.id} className="hover:bg-gray-50">
                      <TableCell>
                        <Checkbox
                          checked={selectedStudents.includes(student.id)}
                          onCheckedChange={() => toggleStudentSelection(student.id)}
                        />
                      </TableCell>
                      <TableCell className="font-medium">
                        {student.sus_vorn} {student.sus_nachn}
                      </TableCell>
                      <TableCell>{student.sus_kl || 'N/A'}</TableCell>
                      <TableCell>
                        <Badge 
                          className={`${(student.assignment_count && student.assignment_count > 0) 
                            ? 'bg-green-100 text-green-800 cursor-pointer hover:bg-green-200' 
                            : 'bg-gray-100 text-gray-800'} transition-colors`}
                          onClick={() => student.assignment_count > 0 && loadStudentIPads(student)}
                          title={student.assignment_count > 0 ? 'Klicken um zugewiesene iPads anzuzeigen' : ''}
                        >
                          {student.assignment_count > 0 ? `${student.assignment_count} iPad(s)` : 'Ohne iPad'}
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
                          {/* Schüler kann bis zu 3 iPads haben */}
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              setSearchDialogStudentId(student.id);
                              setSearchDialogOpen(true);
                              setIpadSearchQuery('');
                            }}
                            disabled={student.assignment_count >= 3}
                            title={student.assignment_count >= 3 ? 'Maximum von 3 iPads erreicht' : 'Weiteres iPad zuordnen'}
                          >
                            {student.assignment_count >= 3 ? 'Limit erreicht' : 'iPad zuordnen'}
                          </Button>
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

      {/* Create Student Dialog */}
      <AlertDialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <AlertDialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <AlertDialogHeader>
            <AlertDialogTitle>Neuen Schüler anlegen</AlertDialogTitle>
            <AlertDialogDescription>
              Geben Sie die Daten für den neuen Schüler ein. Pflichtfelder sind markiert mit *.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="sus_vorn">Vorname *</Label>
                <Input
                  id="sus_vorn"
                  placeholder="Max"
                  value={newStudentData.sus_vorn}
                  onChange={(e) => setNewStudentData({...newStudentData, sus_vorn: e.target.value})}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="sus_nachn">Nachname *</Label>
                <Input
                  id="sus_nachn"
                  placeholder="Mustermann"
                  value={newStudentData.sus_nachn}
                  onChange={(e) => setNewStudentData({...newStudentData, sus_nachn: e.target.value})}
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="sus_kl">Klasse</Label>
                <Input
                  id="sus_kl"
                  placeholder="z.B. 10a"
                  value={newStudentData.sus_kl}
                  onChange={(e) => setNewStudentData({...newStudentData, sus_kl: e.target.value})}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="sus_geb">Geburtsdatum</Label>
                <Input
                  id="sus_geb"
                  placeholder="TT.MM.JJJJ"
                  value={newStudentData.sus_geb}
                  onChange={(e) => setNewStudentData({...newStudentData, sus_geb: e.target.value})}
                />
              </div>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="sus_str">Straße</Label>
              <Input
                id="sus_str"
                placeholder="Musterstraße 123"
                value={newStudentData.sus_str}
                onChange={(e) => setNewStudentData({...newStudentData, sus_str: e.target.value})}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="sus_ort">Ort</Label>
              <Input
                id="sus_ort"
                placeholder="12345 Musterstadt"
                value={newStudentData.sus_ort}
                onChange={(e) => setNewStudentData({...newStudentData, sus_ort: e.target.value})}
              />
            </div>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>Abbrechen</AlertDialogCancel>
            <AlertDialogAction 
              onClick={handleCreateStudent} 
              disabled={creating || !newStudentData.sus_vorn || !newStudentData.sus_nachn}
            >
              {creating ? 'Erstelle...' : 'Schüler anlegen'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      
      {/* Delete Student Confirmation Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Schüler löschen?</AlertDialogTitle>
            <AlertDialogDescription>
              Möchten Sie wirklich den Schüler <strong>{studentToDelete?.sus_vorn} {studentToDelete?.sus_nachn}</strong> löschen?
              <br /><br />
              <strong>Dies löscht:</strong>
              <ul className="list-disc list-inside mt-2">
                <li>Den Schüler permanent</li>
                <li>Alle Zuordnungs-Historie</li>
                <li>Alle zugehörigen Verträge</li>
                <li>Gibt zugeordnetes iPad frei</li>
              </ul>
              <br />
              Diese Aktion kann nicht rückgängig gemacht werden.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Abbrechen</AlertDialogCancel>
            <AlertDialogAction onClick={confirmDeleteStudent} className="bg-red-600 hover:bg-red-700">
              Schüler löschen
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      
      {/* Batch Delete Students Confirmation Dialog */}
      <AlertDialog open={batchDeleteDialogOpen} onOpenChange={setBatchDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{selectedStudents.length} Schüler löschen?</AlertDialogTitle>
            <AlertDialogDescription>
              Möchten Sie wirklich <strong>{selectedStudents.length} Schüler</strong> löschen?
              <br /><br />
              <strong>Für jeden Schüler wird gelöscht:</strong>
              <ul className="list-disc list-inside mt-2">
                <li>Alle Zuordnungen</li>
                <li>Alle Verträge</li>
                <li>Komplette Historie</li>
                <li>iPads werden freigegeben</li>
              </ul>
              <br />
              Diese Aktion kann nicht rückgängig gemacht werden.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Abbrechen</AlertDialogCancel>
            <AlertDialogAction onClick={confirmBatchDeleteStudents} className="bg-red-600 hover:bg-red-700">
              {selectedStudents.length} Schüler löschen
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      
      {/* iPad Search Dialog */}
      <AlertDialog open={searchDialogOpen} onOpenChange={setSearchDialogOpen}>
        <AlertDialogContent className="max-w-2xl max-h-[80vh]">
          <AlertDialogHeader>
            <AlertDialogTitle>iPad zuordnen</AlertDialogTitle>
            <AlertDialogDescription>
              Wählen Sie ein iPad für die Zuordnung aus.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="py-4">
            <Input
              placeholder="iPad suchen (ITNr)..."
              value={ipadSearchQuery}
              onChange={(e) => setIpadSearchQuery(e.target.value)}
              className="mb-4"
              autoFocus
            />
            <div className="max-h-96 overflow-auto border rounded-md">
              {availableIPads
                .filter(ipad => 
                  !ipadSearchQuery || 
                  ipad.itnr.toLowerCase().includes(ipadSearchQuery.toLowerCase())
                )
                .map((ipad) => (
                  <div
                    key={ipad.id}
                    className="px-4 py-3 cursor-pointer hover:bg-gray-100 border-b last:border-b-0"
                    onClick={() => {
                      handleManualIPadAssignment(searchDialogStudentId, ipad.id);
                      setSearchDialogOpen(false);
                      setIpadSearchQuery('');
                    }}
                  >
                    <div className="font-medium">{ipad.itnr}</div>
                    <div className="text-sm text-gray-500">Status: {ipad.status}</div>
                  </div>
                ))}
              {availableIPads.filter(ipad => 
                !ipadSearchQuery || 
                ipad.itnr.toLowerCase().includes(ipadSearchQuery.toLowerCase())
              ).length === 0 && (
                <div className="px-4 py-8 text-center text-gray-500">
                  Keine iPads gefunden
                </div>
              )}
            </div>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setIpadSearchQuery('')}>Abbrechen</AlertDialogCancel>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      
      {/* iPad List Dialog - Shows assigned iPads when clicking "X iPad(s)" badge */}
      <AlertDialog open={ipadListDialogOpen} onOpenChange={setIpadListDialogOpen}>
        <AlertDialogContent className="max-w-lg">
          <AlertDialogHeader>
            <AlertDialogTitle>
              iPads von {ipadListStudent?.sus_vorn} {ipadListStudent?.sus_nachn}
            </AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div>
                {ipadListLoading ? (
                  <div className="py-4 text-center">Lade iPad-Liste...</div>
                ) : ipadListData.length > 0 ? (
                  <div className="space-y-3 mt-4">
                    {ipadListData.map((ipad, index) => (
                      <div key={ipad.id} className="bg-gray-50 p-4 rounded-lg">
                        <div className="flex justify-between items-start">
                          <div className="space-y-1">
                            <div className="font-medium text-gray-900">
                              iPad {index + 1}: {ipad.itnr}
                            </div>
                            <div className="text-sm text-gray-600">
                              SNr: {ipad.snr}
                            </div>
                            <div className="text-sm text-gray-600">
                              Typ: {ipad.typ || 'N/A'}
                            </div>
                            <div className="text-sm text-gray-600">
                              Zugewiesen am: {ipad.assigned_at 
                                ? new Date(ipad.assigned_at).toLocaleDateString('de-DE')
                                : 'N/A'}
                            </div>
                          </div>
                          <Button
                            variant="outline"
                            size="sm"
                            className="hover:bg-red-50 hover:text-red-600 hover:border-red-300"
                            onClick={() => dissolveAssignmentFromStudent(ipad.assignment_id)}
                            title="Diese Zuordnung auflösen"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    ))}
                    <div className="text-xs text-gray-500 text-center mt-2">
                      {ipadListData.length} von max. 3 iPads zugewiesen
                    </div>
                  </div>
                ) : (
                  <div className="py-4 text-center text-gray-500">
                    Keine iPads zugewiesen
                  </div>
                )}
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => {
              setIpadListDialogOpen(false);
              setIpadListData([]);
              setIpadListStudent(null);
            }}>
              Schließen
            </AlertDialogCancel>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      
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
  const [generatingContracts, setGeneratingContracts] = useState(false);
  
  // Filter states
  const [vornameFilter, setVornameFilter] = useState('');
  const [nachnameFilter, setNachnameFilter] = useState('');
  const [klasseFilter, setKlasseFilter] = useState('');
  const [itnrFilter, setItnrFilter] = useState('');
  
  // Sort states
  const [sortField, setSortField] = useState(null);
  const [sortDirection, setSortDirection] = useState('asc');
  
  // Batch delete states
  const [selectedAssignments, setSelectedAssignments] = useState([]);
  
  // Delete dialog states
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [assignmentToDelete, setAssignmentToDelete] = useState(null);
  const [batchDeleteDialogOpen, setBatchDeleteDialogOpen] = useState(false);

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

  // Apply sorting when filters or sort changes
  useEffect(() => {
    applySorting();
  }, [filteredAssignments, sortField, sortDirection]);

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
  
  const applySorting = () => {
    if (!sortField) return;
    
    const sorted = [...filteredAssignments].sort((a, b) => {
      let aVal = a[sortField] || '';
      let bVal = b[sortField] || '';
      
      // String comparison
      if (typeof aVal === 'string') {
        aVal = aVal.toLowerCase();
        bVal = bVal.toLowerCase();
      }
      
      if (sortDirection === 'asc') {
        return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
      } else {
        return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
      }
    });
    
    setFilteredAssignments(sorted);
  };
  
  // Sort handler
  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };
  
  // Batch delete handlers
  const toggleAssignmentSelection = (assignmentId) => {
    setSelectedAssignments(prev =>
      prev.includes(assignmentId)
        ? prev.filter(id => id !== assignmentId)
        : [...prev, assignmentId]
    );
  };
  
  const toggleAllAssignments = () => {
    if (selectedAssignments.length === filteredAssignments.length) {
      setSelectedAssignments([]);
    } else {
      setSelectedAssignments(filteredAssignments.map(assignment => assignment.id));
    }
  };
  
  const openBatchDissolveDialog = () => {
    if (selectedAssignments.length === 0) return;
    setBatchDeleteDialogOpen(true);
  };
  
  const handleBatchDissolve = async () => {
    setDissolving(true);
    let successCount = 0;
    let errorCount = 0;
    
    for (const assignmentId of selectedAssignments) {
      try {
        await api.delete(`/assignments/${assignmentId}`);
        successCount++;
      } catch (error) {
        errorCount++;
        console.error(`Failed to dissolve assignment ${assignmentId}:`, error);
      }
    }
    
    setDissolving(false);
    setSelectedAssignments([]);
    
    if (successCount > 0) {
      toast.success(`${successCount} Zuordnung(en) erfolgreich aufgelöst`);
      loadAllData();
    }
    if (errorCount > 0) {
      toast.error(`${errorCount} Zuordnung(en) konnten nicht aufgelöst werden`);
    }
  };
  
  const confirmBatchDissolve = async () => {
    setBatchDeleteDialogOpen(false);
    await handleBatchDissolve();
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

  const handleDissolveAssignment = (assignment) => {
    setAssignmentToDelete(assignment);
    setDeleteDialogOpen(true);
  };
  
  const confirmDissolveAssignment = async () => {
    if (!assignmentToDelete) return;
    
    try {
      toast.info('Löse Zuordnung auf...');
      
      const response = await fetch(`${API_BASE_URL}/assignments/${assignmentToDelete.id}`, {
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
    } finally {
      setDeleteDialogOpen(false);
      setAssignmentToDelete(null);
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

  // Generate contracts for assignments
  const handleGenerateContracts = async (filtered = false) => {
    setGeneratingContracts(true);
    try {
      // Build query parameters for filtered generation
      const params = new URLSearchParams();
      if (filtered) {
        if (vornameFilter) params.append('sus_vorn', vornameFilter);
        if (nachnameFilter) params.append('sus_nachn', nachnameFilter);
        if (klasseFilter) params.append('sus_kl', klasseFilter);
        if (itnrFilter) params.append('itnr', itnrFilter);
      }
      
      const queryString = params.toString();
      const url = queryString ? `/assignments/generate-contracts?${queryString}` : '/assignments/generate-contracts';
      
      const response = await api.post(url, {}, {
        responseType: 'blob'
      });
      
      const blob = new Blob([response.data], {
        type: 'application/zip'
      });
      
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      
      // Get filename from header or use default
      const contentDisposition = response.headers['content-disposition'];
      let filename = 'Vertraege.zip';
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename=(.+)/);
        if (filenameMatch) {
          filename = filenameMatch[1];
        }
      }
      
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      window.URL.revokeObjectURL(downloadUrl);
      document.body.removeChild(link);
      
      const successCount = response.headers['x-success-count'] || '?';
      const message = filtered 
        ? `${successCount} Verträge für gefilterte Zuordnungen erstellt` 
        : `${successCount} Verträge erstellt`;
      toast.success(message);
    } catch (error) {
      if (error.response?.status === 404) {
        toast.error('Keine Zuordnungen für Vertragserstellung gefunden');
      } else if (error.response?.data) {
        // Try to read error message from blob
        const text = await error.response.data.text?.() || 'Unbekannter Fehler';
        try {
          const json = JSON.parse(text);
          toast.error(json.detail || 'Fehler bei der Vertragserstellung');
        } catch {
          toast.error('Fehler bei der Vertragserstellung');
        }
      } else {
        toast.error('Fehler bei der Vertragserstellung');
      }
      console.error('Contract generation error:', error);
    } finally {
      setGeneratingContracts(false);
    }
  };

  const clearFilters = () => {
    setVornameFilter('');
    setNachnameFilter('');
    setKlasseFilter('');
    setItnrFilter('');
  };

  // Only students without any iPads for auto-assignment (1:n relationship)
  const unassignedStudents = students.filter(student => 
    !student.assignment_count || student.assignment_count === 0
  );
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
          <div className="flex flex-wrap gap-2 mb-4">
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
            
            {/* Contract Generation Buttons */}
            <Button 
              onClick={() => handleGenerateContracts(false)}
              disabled={generatingContracts || assignments.length === 0}
              className="bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800"
            >
              <FileText className="h-4 w-4 mr-2" />
              {generatingContracts ? 'Erstelle Verträge...' : `Alle Verträge erstellen (${assignments.length})`}
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
                  onClick={() => handleGenerateContracts(true)}
                  disabled={generatingContracts}
                  className="bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800"
                >
                  <FileText className="h-4 w-4 mr-2" />
                  {generatingContracts ? 'Erstelle...' : `Gefilterte Verträge erstellen (${filteredAssignments.length})`}
                </Button>
              </>
            )}
          </div>
          
          {/* Batch Delete Button */}
          {selectedAssignments.length > 0 && (
            <div className="mb-4">
              <Button
                onClick={openBatchDissolveDialog}
                variant="destructive"
                disabled={dissolving}
              >
                {dissolving ? 'Löse auf...' : `${selectedAssignments.length} Zuordnung(en) auflösen`}
              </Button>
            </div>
          )}

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
                    <TableHead className="w-12">
                      <Checkbox
                        checked={selectedAssignments.length === filteredAssignments.length && filteredAssignments.length > 0}
                        onCheckedChange={toggleAllAssignments}
                      />
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-50"
                      onClick={() => handleSort('itnr')}
                    >
                      <div className="flex items-center gap-1">
                        iPad ITNr
                        {sortField === 'itnr' && (
                          sortDirection === 'asc' ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />
                        )}
                      </div>
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-50"
                      onClick={() => handleSort('student_name')}
                    >
                      <div className="flex items-center gap-1">
                        Schüler (Klasse)
                        {sortField === 'student_name' && (
                          sortDirection === 'asc' ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />
                        )}
                      </div>
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-50"
                      onClick={() => handleSort('assigned_at')}
                    >
                      <div className="flex items-center gap-1">
                        Zugewiesen am
                        {sortField === 'assigned_at' && (
                          sortDirection === 'asc' ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />
                        )}
                      </div>
                    </TableHead>
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
                      <TableCell>
                        <Checkbox
                          checked={selectedAssignments.includes(assignment.id)}
                          onCheckedChange={() => toggleAssignmentSelection(assignment.id)}
                        />
                      </TableCell>
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
      
      {/* Batch Dissolve Assignments Confirmation Dialog */}
      <AlertDialog open={batchDeleteDialogOpen} onOpenChange={setBatchDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{selectedAssignments.length} Zuordnung(en) auflösen?</AlertDialogTitle>
            <AlertDialogDescription>
              Möchten Sie wirklich <strong>{selectedAssignments.length} Zuordnung(en)</strong> auflösen?
              <br /><br />
              <strong>Dies führt dazu:</strong>
              <ul className="list-disc list-inside mt-2">
                <li>iPads werden auf "verfügbar" gesetzt</li>
                <li>Schüler werden freigegeben</li>
                <li>Verträge werden inaktiv</li>
              </ul>
              <br />
              Diese Aktion kann nicht rückgängig gemacht werden.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Abbrechen</AlertDialogCancel>
            <AlertDialogAction onClick={confirmBatchDissolve} className="bg-red-600 hover:bg-red-700">
              {selectedAssignments.length} Zuordnung(en) auflösen
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      
      {/* Delete Assignment Confirmation Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Zuordnung auflösen?</AlertDialogTitle>
            <AlertDialogDescription>
              Möchten Sie wirklich die Zuordnung von <strong>{assignmentToDelete?.student_name}</strong> zum iPad <strong>{assignmentToDelete?.itnr}</strong> auflösen?
              <br /><br />
              Diese Aktion kann nicht rückgängig gemacht werden.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Abbrechen</AlertDialogCancel>
            <AlertDialogAction onClick={confirmDissolveAssignment} className="bg-red-600 hover:bg-red-700">
              Zuordnung auflösen
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      
      {/* Contract Viewer Modal */}
      {selectedContractId && (
        <ContractViewer 
          contractId={selectedContractId} 
          onClose={() => setSelectedContractId(null)} 
        />
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
  const [sessionWarningShown, setSessionWarningShown] = useState(false);

  // Session timeout handler
  const checkSessionTimeout = useCallback(() => {
    const lastActivity = localStorage.getItem('lastActivity');
    if (!lastActivity) return;
    
    const timeSinceActivity = Date.now() - parseInt(lastActivity, 10);
    const timeUntilTimeout = SESSION_TIMEOUT - timeSinceActivity;
    
    // Show warning 5 minutes before timeout
    if (timeUntilTimeout <= SESSION_WARNING && timeUntilTimeout > 0 && !sessionWarningShown) {
      setSessionWarningShown(true);
      const minutesLeft = Math.ceil(timeUntilTimeout / 60000);
      toast.warning(`Ihre Session läuft in ${minutesLeft} Minute${minutesLeft > 1 ? 'n' : ''} ab. Bitte speichern Sie Ihre Arbeit.`, {
        duration: 10000,
      });
    }
    
    // Session expired
    if (timeUntilTimeout <= 0) {
      toast.error('Ihre Session ist abgelaufen. Sie werden zur Anmeldeseite weitergeleitet.');
      handleLogout();
    }
  }, [sessionWarningShown]);

  // Update last activity on user interaction
  const updateActivity = useCallback(() => {
    if (isAuthenticated) {
      localStorage.setItem('lastActivity', Date.now().toString());
      setSessionWarningShown(false);
    }
  }, [isAuthenticated]);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const savedRole = localStorage.getItem('userRole');
    const savedUsername = localStorage.getItem('username');
    if (token) {
      setIsAuthenticated(true);
      setUserRole(savedRole || 'user');
      setCurrentUsername(savedUsername || '');
      
      // Initialize last activity if not set
      if (!localStorage.getItem('lastActivity')) {
        localStorage.setItem('lastActivity', Date.now().toString());
      }
    }
    setLoading(false);
    
    // Listener für automatischen Logout bei Session-Ablauf
    const handleSessionExpired = () => {
      handleLogout();
    };
    
    window.addEventListener('session-expired', handleSessionExpired);
    
    return () => {
      window.removeEventListener('session-expired', handleSessionExpired);
    };
  }, []);

  // Session timeout checker interval
  useEffect(() => {
    if (!isAuthenticated) return;
    
    const interval = setInterval(checkSessionTimeout, 10000); // Check every 10 seconds
    return () => clearInterval(interval);
  }, [isAuthenticated, checkSessionTimeout]);

  // Activity tracker
  useEffect(() => {
    if (!isAuthenticated) return;
    
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart'];
    
    events.forEach(event => {
      window.addEventListener(event, updateActivity);
    });
    
    return () => {
      events.forEach(event => {
        window.removeEventListener(event, updateActivity);
      });
    };
  }, [isAuthenticated, updateActivity]);

  const handleLogin = (role, username) => {
    setIsAuthenticated(true);
    setUserRole(role);
    setCurrentUsername(username);
    localStorage.setItem('lastActivity', Date.now().toString());
    setSessionWarningShown(false);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('userRole');
    localStorage.removeItem('username');
    localStorage.removeItem('lastActivity');
    setIsAuthenticated(false);
    setUserRole('user');
    setCurrentUsername('');
    setSessionWarningShown(false);
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