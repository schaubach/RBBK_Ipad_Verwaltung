import React, { useState, useEffect, useCallback } from 'react';
import api from '../../api';
import StudentDetailViewer from './StudentDetailViewer';
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
import { Users, Eye, Trash2, Plus, ArrowUpDown, ArrowUp, ArrowDown, X, Edit } from 'lucide-react';

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
                        <button
                          onClick={() => setSelectedStudentId(student.id)}
                          className="text-blue-600 hover:text-blue-800 hover:underline text-left"
                        >
                          {student.sus_vorn} {student.sus_nachn}
                        </button>
                      </TableCell>
                      <TableCell>
                        <button
                          onClick={() => setSelectedStudentId(student.id)}
                          className="text-blue-600 hover:text-blue-800 hover:underline"
                        >
                          {student.sus_kl || 'N/A'}
                        </button>
                      </TableCell>
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



export default StudentsManagement;
