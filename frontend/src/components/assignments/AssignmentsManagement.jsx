import React, { useState, useEffect, useCallback } from 'react';
import api from '../../api';
import StudentDetailViewer from '../students/StudentDetailViewer';
import IPadDetailViewer from '../ipads/IPadDetailViewer';
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
import { FileText, Download, Trash2, Upload, ExternalLink, Eye, X, ArrowUpDown, ArrowUp, ArrowDown } from 'lucide-react';

const AssignmentsManagement = () => {
  const [assignments, setAssignments] = useState([]);
  const [filteredAssignments, setFilteredAssignments] = useState([]);
  const [ipads, setIPads] = useState([]);
  const [students, setStudents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedStudentId, setSelectedStudentId] = useState(null);
  const [selectedIPadId, setSelectedIPadId] = useState(null);
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
  
  const handleBatchDissolve = async (dissolveAll = false, useFiltered = false) => {
    setDissolving(true);
    let successCount = 0;
    let errorCount = 0;
    
    // Bestimme welche Zuordnungen aufgelöst werden sollen
    let assignmentsToDissolve;
    if (dissolveAll) {
      // Alle oder gefilterte Zuordnungen
      assignmentsToDissolve = useFiltered ? filteredAssignments : assignments;
    } else {
      // Nur ausgewählte Zuordnungen
      assignmentsToDissolve = assignments.filter(a => selectedAssignments.includes(a.id));
    }
    
    for (const assignment of assignmentsToDissolve) {
      try {
        await api.delete(`/assignments/${assignment.id}`);
        successCount++;
      } catch (error) {
        errorCount++;
        console.error(`Failed to dissolve assignment ${assignment.id}:`, error);
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
      
      await api.delete(`/assignments/${assignmentToDelete.id}`);
      
      toast.success('Zuordnung erfolgreich aufgelöst!');
      await loadAllData();
      
    } catch (error) {
      console.error('❌ Exception:', error);
      toast.error(`Fehler: ${error.response?.data?.detail || error.message}`);
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
  // Frei & OK = nicht zugewiesen UND Status = "ok" (defekte/gestohlene werden nicht automatisch zugeordnet)
  const freeAndOkIPads = ipads.filter(ipad => !ipad.current_assignment_id && ipad.status === 'ok');

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
                  onClick={() => handleBatchDissolve(true, true)}
                  disabled={dissolving}
                  className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white"
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  {dissolving ? 'Löse auf...' : `Gefilterte Zuordnungen lösen (${filteredAssignments.length})`}
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
                          <button
                            onClick={() => setSelectedIPadId(assignment.ipad_id)}
                            className="text-blue-600 hover:text-blue-800 hover:underline"
                          >
                            {assignment.itnr}
                          </button>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div>
                          <button
                            onClick={() => setSelectedStudentId(assignment.student_id)}
                            className="font-medium text-blue-600 hover:text-blue-800 hover:underline text-left"
                          >
                            {assignment.student_name}
                          </button>
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

      {/* Student Detail Viewer Modal */}
      {selectedStudentId && (
        <StudentDetailViewer 
          studentId={selectedStudentId} 
          onClose={() => setSelectedStudentId(null)} 
        />
      )}

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



export default AssignmentsManagement;
