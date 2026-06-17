import React, { useState, useEffect, useCallback, useMemo } from 'react';
import api from '../../api';
import StudentDetailViewer from '../students/StudentDetailViewer';
import IPadDetailViewer from '../ipads/IPadDetailViewer';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Badge } from '../ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '../ui/alert-dialog';
import { Checkbox } from '../ui/checkbox';
import { toast } from 'sonner';
import { Upload, FileText, Download, Trash2, Search, Link, ArrowUpDown, ArrowUp, ArrowDown, RefreshCw, AlertTriangle } from 'lucide-react';

const ContractsManagement = () => {
  const [contracts, setContracts] = useState([]);
  const [availableAssignments, setAvailableAssignments] = useState([]);
  const [allAssignments, setAllAssignments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  
  // Selection
  const [selectedContracts, setSelectedContracts] = useState([]);
  
  // Sorting
  const [sortField, setSortField] = useState('uploaded_at');
  const [sortDirection, setSortDirection] = useState('desc');
  
  // Filtering
  const [filenameFilter, setFilenameFilter] = useState('');
  const [studentFilter, setStudentFilter] = useState('');
  const [itnrFilter, setItnrFilter] = useState('');
  
  // Dialog für Vertragszuordnung
  const [assignDialogOpen, setAssignDialogOpen] = useState(false);
  const [selectedContract, setSelectedContract] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [assigning, setAssigning] = useState(false);
  const [isReassign, setIsReassign] = useState(false);
  
  // Detail viewers
  const [selectedStudentId, setSelectedStudentId] = useState(null);
  const [selectedIPadId, setSelectedIPadId] = useState(null);
  
  // Delete dialog
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [contractToDelete, setContractToDelete] = useState(null);
  const [batchDeleteDialogOpen, setBatchDeleteDialogOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);

  // Verträge erstellen - Filter
  const [createVornameFilter, setCreateVornameFilter] = useState('');
  const [createNachnameFilter, setCreateNachnameFilter] = useState('');
  const [createKlasseFilter, setCreateKlasseFilter] = useState('');
  const [createItnrFilter, setCreateItnrFilter] = useState('');
  const [generatingContracts, setGeneratingContracts] = useState(false);
  const [selectedForGeneration, setSelectedForGeneration] = useState([]);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [contractsRes, availableRes, allAssignmentsRes] = await Promise.all([
        api.get('/contracts'),
        api.get('/assignments/available-for-contracts'),
        api.get('/assignments')
      ]);
      setContracts(contractsRes.data);
      setAvailableAssignments(availableRes.data);
      setAllAssignments(allAssignmentsRes.data);
    } catch (error) {
      toast.error('Fehler beim Laden der Vertragsdaten');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleMultipleUpload = async (files) => {
    if (files.length === 0) return;
    
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
      
      const { processed_count, unassigned_count, results } = response.data;
      
      if (processed_count > 0) {
        toast.success(`${processed_count} Verträge automatisch zugeordnet`);
      }
      if (unassigned_count > 0) {
        toast.info(`${unassigned_count} Verträge zur manuellen Zuordnung bereit`);
      }
      
      results.forEach(result => {
        if (result.status === 'error') {
          toast.error(`${result.filename}: ${result.message}`);
        }
      });
      
      loadData();
    } catch (error) {
      toast.error('Fehler beim Hochladen der Verträge');
    } finally {
      setUploading(false);
    }
  };

  const openAssignDialog = (contract, reassign = false) => {
    setSelectedContract(contract);
    setSearchTerm('');
    setIsReassign(reassign);
    setAssignDialogOpen(true);
  };

  const handleAssignContract = async (assignmentId) => {
    if (!selectedContract) return;
    
    setAssigning(true);
    try {
      // If reassigning, first unassign from current assignment
      if (isReassign && selectedContract.assignment_id) {
        await api.post(`/contracts/${selectedContract.id}/unassign`);
      }
      
      await api.post(`/contracts/${selectedContract.id}/assign/${assignmentId}`);
      toast.success(isReassign ? 'Vertrag erfolgreich neu zugeordnet' : 'Vertrag erfolgreich zugeordnet');
      setAssignDialogOpen(false);
      setSelectedContract(null);
      setIsReassign(false);
      loadData();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler bei der Zuordnung');
    } finally {
      setAssigning(false);
    }
  };

  const handleDeleteContract = async () => {
    if (!contractToDelete) return;
    setDeleting(true);
    try {
      await api.delete(`/contracts/${contractToDelete.id}`);
      toast.success('Vertrag gelöscht');
      setDeleteDialogOpen(false);
      setContractToDelete(null);
      loadData();
    } catch (error) {
      toast.error('Fehler beim Löschen des Vertrags');
    } finally {
      setDeleting(false);
    }
  };

  const handleBatchDelete = async () => {
    setDeleting(true);
    try {
      const response = await api.post('/contracts/batch-delete', {
        contract_ids: selectedContracts
      });
      
      const { deleted_count, errors } = response.data;
      
      if (deleted_count > 0) {
        toast.success(`${deleted_count} Vertrag/Verträge gelöscht`);
      }
      if (errors && errors.length > 0) {
        toast.error(`${errors.length} Vertrag/Verträge konnten nicht gelöscht werden`);
      }
    } catch (error) {
      toast.error('Fehler beim Löschen der Verträge');
    } finally {
      setDeleting(false);
      setBatchDeleteDialogOpen(false);
      setSelectedContracts([]);
      loadData();
    }
  };

  const handleDownloadContract = async (contractId, filename) => {
    try {
      const response = await api.get(`/contracts/${contractId}/download`, {
        responseType: 'blob'
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      toast.error('Fehler beim Herunterladen des Vertrags');
    }
  };

  // Verträge erstellen
  const [warnDialogOpen, setWarnDialogOpen] = useState(false);
  const [pendingGenerateMode, setPendingGenerateMode] = useState(null); // 'all' | 'filtered'

  // Count assignments with missing fields among selected/all
  const getIncompleteCount = (mode) => {
    if (mode === 'filtered') {
      return filteredAvailableAssignments
        .filter(a => selectedForGeneration.includes(a.assignment_id))
        .filter(a => (a.missing_fields?.length || 0) > 0)
        .length;
    }
    return availableAssignments.filter(a => (a.missing_fields?.length || 0) > 0).length;
  };

  const requestGenerateContracts = (filtered = false) => {
    const mode = filtered ? 'filtered' : 'all';
    if (mode === 'filtered' && selectedForGeneration.length === 0) {
      toast.error('Keine Zuordnungen ausgewählt');
      return;
    }
    const incomplete = getIncompleteCount(mode);
    if (incomplete > 0) {
      setPendingGenerateMode(mode);
      setWarnDialogOpen(true);
      return;
    }
    handleGenerateContracts(filtered);
  };

  const confirmGenerateWithWarnings = () => {
    setWarnDialogOpen(false);
    if (pendingGenerateMode) {
      handleGenerateContracts(pendingGenerateMode === 'filtered');
      setPendingGenerateMode(null);
    }
  };

  const handleGenerateContracts = async (filtered = false) => {
    setGeneratingContracts(true);
    try {
      let url = '/assignments/generate-contracts';
      let body = {};
      
      if (filtered) {
        // Use selected assignment IDs from the filtered table
        if (selectedForGeneration.length === 0) {
          toast.error('Keine Zuordnungen ausgewählt');
          setGeneratingContracts(false);
          return;
        }
        body = { assignment_ids: selectedForGeneration };
      }
      
      const response = await api.post(url, body, {
        responseType: 'blob'
      });
      
      const blob = new Blob([response.data], { type: 'application/zip' });
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      
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
      
      const successCount = response.headers['x-success-count'];
      toast.success(`${successCount || 'Verträge'} erfolgreich erstellt`);
    } catch (error) {
      if (error.response?.status === 404) {
        toast.error('Keine Zuordnungen für Vertragserstellung gefunden');
      } else {
        toast.error('Fehler bei der Vertragserstellung');
      }
      console.error('Contract generation error:', error);
    } finally {
      setGeneratingContracts(false);
    }
  };

  const hasCreateFilters = createVornameFilter || createNachnameFilter || createKlasseFilter || createItnrFilter;

  // Filter available assignments client-side based on create filters
  const filteredAvailableAssignments = useMemo(() => {
    if (!hasCreateFilters) return [];
    return availableAssignments.filter(a => {
      if (createVornameFilter && !(a.sus_vorn || '').toLowerCase().includes(createVornameFilter.toLowerCase())) return false;
      if (createNachnameFilter && !(a.sus_nachn || '').toLowerCase().includes(createNachnameFilter.toLowerCase())) return false;
      if (createKlasseFilter && !(a.sus_kl || '').toLowerCase().includes(createKlasseFilter.toLowerCase())) return false;
      if (createItnrFilter && !(a.itnr || '').toLowerCase().includes(createItnrFilter.toLowerCase())) return false;
      return true;
    });
  }, [availableAssignments, createVornameFilter, createNachnameFilter, createKlasseFilter, createItnrFilter, hasCreateFilters]);

  // Preselect all filtered assignments whenever filtered list changes
  useEffect(() => {
    setSelectedForGeneration(filteredAvailableAssignments.map(a => a.assignment_id));
  }, [filteredAvailableAssignments]);

  const toggleGenerationSelection = (assignmentId) => {
    setSelectedForGeneration(prev =>
      prev.includes(assignmentId)
        ? prev.filter(id => id !== assignmentId)
        : [...prev, assignmentId]
    );
  };

  const toggleAllGenerationSelection = () => {
    if (selectedForGeneration.length === filteredAvailableAssignments.length) {
      setSelectedForGeneration([]);
    } else {
      setSelectedForGeneration(filteredAvailableAssignments.map(a => a.assignment_id));
    }
  };

  // Sorting
  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const getSortIcon = (field) => {
    if (sortField !== field) return <ArrowUpDown className="h-4 w-4 ml-1" />;
    return sortDirection === 'asc' ? <ArrowUp className="h-4 w-4 ml-1" /> : <ArrowDown className="h-4 w-4 ml-1" />;
  };

  // Selection
  const toggleContractSelection = (contractId) => {
    setSelectedContracts(prev => 
      prev.includes(contractId) 
        ? prev.filter(id => id !== contractId)
        : [...prev, contractId]
    );
  };

  const toggleAllSelection = () => {
    if (selectedContracts.length === filteredContracts.length) {
      setSelectedContracts([]);
    } else {
      setSelectedContracts(filteredContracts.map(c => c.id));
    }
  };

  // Filtering and Sorting
  const filteredContracts = contracts
    .filter(contract => {
      const matchesFilename = !filenameFilter || contract.filename?.toLowerCase().includes(filenameFilter.toLowerCase());
      const matchesStudent = !studentFilter || contract.student_name?.toLowerCase().includes(studentFilter.toLowerCase());
      const matchesItnr = !itnrFilter || contract.itnr?.toLowerCase().includes(itnrFilter.toLowerCase());
      return matchesFilename && matchesStudent && matchesItnr;
    })
    .sort((a, b) => {
      let aVal, bVal;
      
      if (sortField === 'assigned') {
        aVal = a.assignment_id ? 1 : 0;
        bVal = b.assignment_id ? 1 : 0;
      } else if (sortField === 'uploaded_at') {
        aVal = new Date(a[sortField]).getTime();
        bVal = new Date(b[sortField]).getTime();
      } else {
        aVal = (a[sortField] || '').toString().toLowerCase();
        bVal = (b[sortField] || '').toString().toLowerCase();
      }
      
      if (sortDirection === 'asc') {
        return aVal > bVal ? 1 : -1;
      } else {
        return aVal < bVal ? 1 : -1;
      }
    });

  // Für Reassign: Alle Zuordnungen ohne Vertrag + die aktuelle Zuordnung des Vertrags
  const getAssignmentsForDialog = () => {
    if (isReassign && selectedContract?.assignment_id) {
      // Include the current assignment (for comparison) plus all available
      const currentAssignment = allAssignments.find(a => a.id === selectedContract.assignment_id);
      const available = availableAssignments.filter(a => a.assignment_id !== selectedContract.assignment_id);
      return currentAssignment 
        ? [...available, { 
            assignment_id: currentAssignment.id, 
            itnr: currentAssignment.itnr, 
            student_name: currentAssignment.student_name,
            contracts_count: 0,
            max_contracts: 3,
            isCurrent: true 
          }]
        : available;
    }
    return availableAssignments;
  };

  // Gefilterte Zuordnungen für Dialog
  const filteredAssignments = getAssignmentsForDialog().filter(a => {
    const term = searchTerm.toLowerCase();
    return (
      a.itnr?.toLowerCase().includes(term) ||
      a.student_name?.toLowerCase().includes(term)
    );
  });

  // Stats
  const assignedCount = contracts.filter(c => c.assignment_id).length;
  const unassignedCount = contracts.filter(c => !c.assignment_id).length;

  return (
    <div className="space-y-6">
      {/* Stats */}
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Verträge Übersicht
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
            <div className="bg-slate-100 p-3 rounded-lg">
              <div className="font-medium text-slate-800">Gesamt</div>
              <div className="text-2xl font-bold text-slate-600">{contracts.length}</div>
            </div>
            <div className="bg-green-50 p-3 rounded-lg">
              <div className="font-medium text-green-800">Zugeordnet</div>
              <div className="text-2xl font-bold text-green-600">{assignedCount}</div>
            </div>
            <div className="bg-orange-50 p-3 rounded-lg">
              <div className="font-medium text-orange-800">Unzugeordnet</div>
              <div className="text-2xl font-bold text-orange-600">{unassignedCount}</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Upload */}
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" />
            Verträge hochladen
          </CardTitle>
          <CardDescription>
            PDF oder Bilder hochladen (bis zu 50 Dateien)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="border-2 border-dashed border-gray-300 rounded-lg p-4 text-center hover:border-blue-400 transition-colors">
            <Input
              type="file"
              accept=".pdf,.png,.jpg,.jpeg,.gif,.bmp,.webp"
              multiple
              onChange={(e) => handleMultipleUpload(Array.from(e.target.files))}
              disabled={uploading}
            />
            {uploading && <div className="mt-2 text-sm text-gray-600">Hochladen...</div>}
          </div>
        </CardContent>
      </Card>

      {/* Verträge erstellen */}
      <Card className="shadow-lg border-l-4 border-l-green-500">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5 text-green-600" />
            Verträge erstellen
          </CardTitle>
          <CardDescription>
            PDF-Verträge für Zuordnungen generieren (verschlüsselt als ZIP)
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Filter */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div>
              <Label htmlFor="create-vorname" className="text-xs">Vorname</Label>
              <Input
                id="create-vorname"
                placeholder="z.B. Max"
                value={createVornameFilter}
                onChange={(e) => setCreateVornameFilter(e.target.value)}
                className="h-9"
              />
            </div>
            <div>
              <Label htmlFor="create-nachname" className="text-xs">Nachname</Label>
              <Input
                id="create-nachname"
                placeholder="z.B. Müller"
                value={createNachnameFilter}
                onChange={(e) => setCreateNachnameFilter(e.target.value)}
                className="h-9"
              />
            </div>
            <div>
              <Label htmlFor="create-klasse" className="text-xs">Klasse</Label>
              <Input
                id="create-klasse"
                placeholder="z.B. 10A"
                value={createKlasseFilter}
                onChange={(e) => setCreateKlasseFilter(e.target.value)}
                className="h-9"
              />
            </div>
            <div>
              <Label htmlFor="create-itnr" className="text-xs">ITNr</Label>
              <Input
                id="create-itnr"
                placeholder="z.B. IT-001"
                value={createItnrFilter}
                onChange={(e) => setCreateItnrFilter(e.target.value)}
                className="h-9"
              />
            </div>
          </div>
          
          {/* Buttons */}
          <div className="flex flex-wrap gap-2">
            <Button 
              onClick={() => requestGenerateContracts(false)}
              disabled={generatingContracts}
              className="bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800"
              data-testid="generate-all-contracts-btn"
            >
              <FileText className="h-4 w-4 mr-2" />
              {generatingContracts ? 'Erstelle...' : `Alle Verträge erstellen (${availableAssignments.length})`}
            </Button>
            
            {hasCreateFilters && (
              <Button 
                onClick={() => requestGenerateContracts(true)}
                disabled={generatingContracts || selectedForGeneration.length === 0}
                className="bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800"
                data-testid="generate-filtered-contracts-btn"
              >
                <Search className="h-4 w-4 mr-2" />
                {generatingContracts ? 'Erstelle...' : `Verträge erstellen (${selectedForGeneration.length} von ${filteredAvailableAssignments.length})`}
              </Button>
            )}
            
            {hasCreateFilters && (
              <Button 
                variant="outline"
                onClick={() => {
                  setCreateVornameFilter('');
                  setCreateNachnameFilter('');
                  setCreateKlasseFilter('');
                  setCreateItnrFilter('');
                }}
              >
                Filter zurücksetzen
              </Button>
            )}
          </div>

          {/* Gefilterte Zuordnungen Tabelle mit Auswahl-Checkboxen */}
          {hasCreateFilters && (
            <div className="mt-4 border rounded-lg overflow-hidden" data-testid="generation-selection-table">
              {filteredAvailableAssignments.length === 0 ? (
                <div className="p-6 text-center text-sm text-gray-500">
                  Keine passenden Zuordnungen ohne Vertrag gefunden.
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-12">
                        <Checkbox
                          checked={
                            selectedForGeneration.length === filteredAvailableAssignments.length &&
                            filteredAvailableAssignments.length > 0
                          }
                          onCheckedChange={toggleAllGenerationSelection}
                          data-testid="generation-select-all-checkbox"
                        />
                      </TableHead>
                      <TableHead>ITNr</TableHead>
                      <TableHead>Schüler</TableHead>
                      <TableHead>Klasse</TableHead>
                      <TableHead>Verträge</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredAvailableAssignments.map(a => (
                      <TableRow key={a.assignment_id} className={a.missing_fields?.length > 0 ? 'bg-amber-50' : ''}>
                        <TableCell>
                          <Checkbox
                            checked={selectedForGeneration.includes(a.assignment_id)}
                            onCheckedChange={() => toggleGenerationSelection(a.assignment_id)}
                            data-testid={`generation-checkbox-${a.assignment_id}`}
                          />
                        </TableCell>
                        <TableCell className="font-medium">
                          <div className="flex items-center gap-2">
                            {a.itnr}
                            {a.missing_fields?.length > 0 && (
                              <span
                                title={`Fehlende Pflichtfelder: ${a.missing_fields.join(', ')}. Vertrag wird unvollständig generiert.`}
                                data-testid={`generation-warning-${a.assignment_id}`}
                              >
                                <AlertTriangle className="h-4 w-4 text-amber-600" />
                              </span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>{a.sus_vorn} {a.sus_nachn}</TableCell>
                        <TableCell>{a.sus_kl || '-'}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{a.contracts_count} / {a.max_contracts}</Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </div>
          )}
          
          <p className="text-xs text-gray-500">
            Hinweis: ZIP-Dateien sind mit dem Geburtsdatum des Schülers verschlüsselt (Format: TT.MM.JJJJ).
          </p>
        </CardContent>
      </Card>

      {/* Contracts Table */}
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span className="flex items-center gap-2">
              <FileText className="h-5 w-5" />
              Verträge verwalten ({contracts.length})
            </span>
            {selectedContracts.length > 0 && (
              <Button 
                variant="destructive" 
                size="sm"
                onClick={() => setBatchDeleteDialogOpen(true)}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                {selectedContracts.length} löschen
              </Button>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {/* Filters */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <Label>Dateiname</Label>
              <Input
                placeholder="Dateiname filtern..."
                value={filenameFilter}
                onChange={(e) => setFilenameFilter(e.target.value)}
              />
            </div>
            <div>
              <Label>Schüler</Label>
              <Input
                placeholder="Schüler filtern..."
                value={studentFilter}
                onChange={(e) => setStudentFilter(e.target.value)}
              />
            </div>
            <div>
              <Label>ITNr</Label>
              <Input
                placeholder="ITNr filtern..."
                value={itnrFilter}
                onChange={(e) => setItnrFilter(e.target.value)}
              />
            </div>
          </div>

          {loading ? (
            <div className="text-center py-8">Lade Verträge...</div>
          ) : filteredContracts.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              Keine Verträge gefunden.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-12">
                      <Checkbox
                        checked={selectedContracts.length === filteredContracts.length && filteredContracts.length > 0}
                        onCheckedChange={toggleAllSelection}
                      />
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-100"
                      onClick={() => handleSort('filename')}
                    >
                      <div className="flex items-center">
                        Dateiname {getSortIcon('filename')}
                      </div>
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-100"
                      onClick={() => handleSort('student_name')}
                    >
                      <div className="flex items-center">
                        Schüler {getSortIcon('student_name')}
                      </div>
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-100"
                      onClick={() => handleSort('itnr')}
                    >
                      <div className="flex items-center">
                        ITNr {getSortIcon('itnr')}
                      </div>
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-100"
                      onClick={() => handleSort('assigned')}
                    >
                      <div className="flex items-center">
                        Zuordnung {getSortIcon('assigned')}
                      </div>
                    </TableHead>
                    <TableHead 
                      className="cursor-pointer hover:bg-gray-100"
                      onClick={() => handleSort('uploaded_at')}
                    >
                      <div className="flex items-center">
                        Hochgeladen {getSortIcon('uploaded_at')}
                      </div>
                    </TableHead>
                    <TableHead>Aktionen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredContracts.map((contract) => (
                    <TableRow key={contract.id} className="hover:bg-gray-50">
                      <TableCell>
                        <Checkbox
                          checked={selectedContracts.includes(contract.id)}
                          onCheckedChange={() => toggleContractSelection(contract.id)}
                        />
                      </TableCell>
                      <TableCell className="font-medium max-w-xs truncate">
                        {contract.filename}
                      </TableCell>
                      <TableCell>
                        {contract.student_name ? (
                          <button
                            onClick={() => setSelectedStudentId(contract.student_id)}
                            className="text-blue-600 hover:text-blue-800 hover:underline"
                            disabled={!contract.student_id}
                          >
                            {contract.student_name}
                          </button>
                        ) : (
                          <span className="text-gray-400">-</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {contract.itnr ? (
                          <button
                            onClick={() => setSelectedIPadId(contract.ipad_id)}
                            className="text-blue-600 hover:text-blue-800 hover:underline"
                            disabled={!contract.ipad_id}
                          >
                            {contract.itnr}
                          </button>
                        ) : (
                          <span className="text-gray-400">-</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {contract.assignment_id ? (
                          <Badge 
                            className="bg-green-100 text-green-800 cursor-pointer hover:bg-green-200"
                            title="Klicken für Details"
                            onClick={() => {
                              if (contract.student_id) setSelectedStudentId(contract.student_id);
                              else if (contract.ipad_id) setSelectedIPadId(contract.ipad_id);
                            }}
                          >
                            Zugeordnet
                          </Badge>
                        ) : (
                          <Badge 
                            className="bg-orange-100 text-orange-800 cursor-pointer hover:bg-orange-200"
                            onClick={() => openAssignDialog(contract)}
                          >
                            Nicht zugeordnet
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        {new Date(contract.uploaded_at).toLocaleDateString('de-DE', {
                          day: '2-digit', month: '2-digit', year: 'numeric'
                        })}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleDownloadContract(contract.id, contract.filename)}
                            title="Herunterladen"
                          >
                            <Download className="h-4 w-4" />
                          </Button>
                          {contract.assignment_id ? (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => openAssignDialog(contract, true)}
                              title="Zuordnung ändern"
                            >
                              <RefreshCw className="h-4 w-4" />
                            </Button>
                          ) : (
                            <Button
                              size="sm"
                              onClick={() => openAssignDialog(contract)}
                              className="bg-blue-600 hover:bg-blue-700"
                              title="Zuordnen"
                            >
                              <Link className="h-4 w-4" />
                            </Button>
                          )}
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => {
                              setContractToDelete(contract);
                              setDeleteDialogOpen(true);
                            }}
                            title="Löschen"
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

      {/* Dialog für Vertragszuordnung */}
      <AlertDialog open={assignDialogOpen} onOpenChange={setAssignDialogOpen}>
        <AlertDialogContent className="max-w-2xl max-h-[80vh] flex flex-col">
          <AlertDialogHeader>
            <AlertDialogTitle>{isReassign ? 'Zuordnung ändern' : 'Vertrag zuordnen'}</AlertDialogTitle>
            <AlertDialogDescription>
              {selectedContract && (
                <span>
                  Vertrag <strong>{selectedContract.filename}</strong> 
                  {isReassign ? ' einer neuen Zuordnung zuweisen.' : ' einer Zuordnung zuweisen.'}
                </span>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          
          <div className="py-4 flex-1 overflow-hidden flex flex-col">
            <div className="mb-4">
              <Label htmlFor="search">Suche (ITNr oder Schülername)</Label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  id="search"
                  placeholder="z.B. IT12345 oder Max Mustermann..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            
            <div className="flex-1 overflow-y-auto border rounded-lg">
              {filteredAssignments.length === 0 ? (
                <div className="p-4 text-center text-gray-500">
                  {searchTerm ? 'Keine passenden Zuordnungen gefunden' : 'Keine verfügbaren Zuordnungen'}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>ITNr</TableHead>
                      <TableHead>Schüler</TableHead>
                      <TableHead>Verträge</TableHead>
                      <TableHead>Aktion</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredAssignments.map((assignment) => (
                      <TableRow 
                        key={assignment.assignment_id} 
                        className={`hover:bg-gray-50 ${assignment.isCurrent ? 'bg-blue-50' : ''}`}
                      >
                        <TableCell className="font-medium">{assignment.itnr}</TableCell>
                        <TableCell>{assignment.student_name}</TableCell>
                        <TableCell>
                          <span className="text-sm text-gray-500">
                            {assignment.contracts_count}/{assignment.max_contracts}
                          </span>
                        </TableCell>
                        <TableCell>
                          {assignment.isCurrent ? (
                            <Badge className="bg-blue-100 text-blue-800">Aktuell</Badge>
                          ) : (
                            <Button
                              size="sm"
                              onClick={() => handleAssignContract(assignment.assignment_id)}
                              disabled={assigning}
                              className="bg-green-600 hover:bg-green-700"
                            >
                              {assigning ? 'Zuordnen...' : 'Zuordnen'}
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </div>
          </div>
          
          <AlertDialogFooter className="mt-4">
            <AlertDialogCancel onClick={() => setIsReassign(false)}>Abbrechen</AlertDialogCancel>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Incomplete Contracts Warning Dialog */}
      <AlertDialog open={warnDialogOpen} onOpenChange={setWarnDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-600" />
              Unvollständige Verträge erkannt
            </AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div>
                <p>
                  <strong>{pendingGenerateMode ? getIncompleteCount(pendingGenerateMode) : 0}</strong> der ausgewählten Zuordnungen haben fehlende Pflichtfelder (Typ, SNr oder Geburtsdatum).
                </p>
                <p className="mt-2">
                  Diese Verträge werden unvollständig generiert und das ZIP-Archiv kann ohne Geburtsdatum nicht korrekt verschlüsselt werden.
                </p>
                <p className="mt-2 font-medium">Trotzdem fortfahren?</p>
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setPendingGenerateMode(null)}>Abbrechen</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmGenerateWithWarnings}
              className="bg-amber-600 hover:bg-amber-700"
              data-testid="confirm-generate-warnings-btn"
            >
              Trotzdem erstellen
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Vertrag löschen?</AlertDialogTitle>
            <AlertDialogDescription>
              Möchten Sie den Vertrag <strong>{contractToDelete?.filename}</strong> wirklich löschen?
              {contractToDelete?.assignment_id && (
                <span className="block mt-2 text-orange-600">
                  Hinweis: Der Vertrag ist einer Zuordnung zugewiesen. Diese Zuordnung verliert den Verweis auf den Vertrag.
                </span>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Abbrechen</AlertDialogCancel>
            <AlertDialogAction 
              onClick={handleDeleteContract} 
              className="bg-red-600 hover:bg-red-700"
              disabled={deleting}
            >
              {deleting ? 'Lösche...' : 'Löschen'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Batch Delete Confirmation Dialog */}
      <AlertDialog open={batchDeleteDialogOpen} onOpenChange={setBatchDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{selectedContracts.length} Verträge löschen?</AlertDialogTitle>
            <AlertDialogDescription>
              Möchten Sie wirklich <strong>{selectedContracts.length} Verträge</strong> löschen?
              <br /><br />
              <span className="text-red-600 font-bold">Diese Aktion kann nicht rückgängig gemacht werden!</span>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Abbrechen</AlertDialogCancel>
            <AlertDialogAction 
              onClick={handleBatchDelete} 
              className="bg-red-600 hover:bg-red-700"
              disabled={deleting}
            >
              {deleting ? 'Lösche...' : `${selectedContracts.length} Verträge löschen`}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Student Detail Viewer */}
      {selectedStudentId && (
        <StudentDetailViewer 
          studentId={selectedStudentId} 
          onClose={() => setSelectedStudentId(null)}
          onUpdate={loadData}
        />
      )}

      {/* iPad Detail Viewer */}
      {selectedIPadId && (
        <IPadDetailViewer 
          ipadId={selectedIPadId} 
          onClose={() => setSelectedIPadId(null)}
          onUpdate={loadData}
        />
      )}
    </div>
  );
};

export default ContractsManagement;
