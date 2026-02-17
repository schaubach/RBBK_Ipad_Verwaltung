import React, { useState, useEffect, useCallback } from 'react';
import api from '../../api';
import IPadDetailViewer from './IPadDetailViewer';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Badge } from '../ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { Checkbox } from '../ui/checkbox';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '../ui/alert-dialog';
import { toast } from 'sonner';
import { Tablet, Eye, Trash2, Plus, ArrowUpDown, ArrowUp, ArrowDown, X } from 'lucide-react';

const IPadsManagement = () => {
  const [ipads, setIPads] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedIPadId, setSelectedIPadId] = useState(null);
  const [availableStudents, setAvailableStudents] = useState([]);
  
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



export default IPadsManagement;
