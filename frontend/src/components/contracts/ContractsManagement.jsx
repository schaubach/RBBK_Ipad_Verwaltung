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
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '../ui/alert-dialog';
import { Checkbox } from '../ui/checkbox';
import { toast } from 'sonner';
import { Upload, FileText, Download, Trash2, Search, Link, ArrowUpDown, ArrowUp, ArrowDown, Eye } from 'lucide-react';

const ContractsManagement = () => {
  const [contracts, setContracts] = useState([]);
  const [availableAssignments, setAvailableAssignments] = useState([]);
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
  
  // Detail viewers
  const [selectedStudentId, setSelectedStudentId] = useState(null);
  const [selectedIPadId, setSelectedIPadId] = useState(null);
  
  // Delete dialog
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [contractToDelete, setContractToDelete] = useState(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [contractsRes, assignmentsRes] = await Promise.all([
        api.get('/contracts'),
        api.get('/assignments/available-for-contracts')
      ]);
      setContracts(contractsRes.data);
      setAvailableAssignments(assignmentsRes.data);
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

  const openAssignDialog = (contract) => {
    setSelectedContract(contract);
    setSearchTerm('');
    setAssignDialogOpen(true);
  };

  const handleAssignContract = async (assignmentId) => {
    if (!selectedContract) return;
    
    setAssigning(true);
    try {
      await api.post(`/contracts/${selectedContract.id}/assign/${assignmentId}`);
      toast.success('Vertrag erfolgreich zugeordnet');
      setAssignDialogOpen(false);
      setSelectedContract(null);
      loadData();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler bei der Zuordnung');
    } finally {
      setAssigning(false);
    }
  };

  const handleDeleteContract = async () => {
    if (!contractToDelete) return;
    try {
      await api.delete(`/contracts/${contractToDelete.id}`);
      toast.success('Vertrag gelöscht');
      setDeleteDialogOpen(false);
      setContractToDelete(null);
      loadData();
    } catch (error) {
      toast.error('Fehler beim Löschen des Vertrags');
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
      let aVal = a[sortField] || '';
      let bVal = b[sortField] || '';
      
      if (sortField === 'uploaded_at') {
        aVal = new Date(aVal).getTime();
        bVal = new Date(bVal).getTime();
      } else if (typeof aVal === 'string') {
        aVal = aVal.toLowerCase();
        bVal = bVal.toLowerCase();
      }
      
      if (sortDirection === 'asc') {
        return aVal > bVal ? 1 : -1;
      } else {
        return aVal < bVal ? 1 : -1;
      }
    });

  // Gefilterte Zuordnungen für Dialog
  const filteredAssignments = availableAssignments.filter(a => {
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

      {/* Contracts Table */}
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Verträge verwalten ({contracts.length})
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
                    <TableHead>Zuordnung</TableHead>
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
                            title="Klicken um Details anzuzeigen"
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
                          {!contract.assignment_id && (
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
            <AlertDialogTitle>Vertrag zuordnen</AlertDialogTitle>
            <AlertDialogDescription>
              {selectedContract && (
                <span>Vertrag <strong>{selectedContract.filename}</strong> einer Zuordnung zuweisen.</span>
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
                      <TableRow key={assignment.assignment_id} className="hover:bg-gray-50">
                        <TableCell className="font-medium">{assignment.itnr}</TableCell>
                        <TableCell>{assignment.student_name}</TableCell>
                        <TableCell>
                          <span className="text-sm text-gray-500">
                            {assignment.contracts_count}/{assignment.max_contracts}
                          </span>
                        </TableCell>
                        <TableCell>
                          <Button
                            size="sm"
                            onClick={() => handleAssignContract(assignment.assignment_id)}
                            disabled={assigning}
                            className="bg-green-600 hover:bg-green-700"
                          >
                            {assigning ? 'Zuordnen...' : 'Zuordnen'}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </div>
          </div>
          
          <AlertDialogFooter className="mt-4">
            <AlertDialogCancel>Abbrechen</AlertDialogCancel>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Vertrag löschen?</AlertDialogTitle>
            <AlertDialogDescription>
              Möchten Sie den Vertrag <strong>{contractToDelete?.filename}</strong> wirklich löschen?
              Diese Aktion kann nicht rückgängig gemacht werden.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Abbrechen</AlertDialogCancel>
            <AlertDialogAction onClick={handleDeleteContract} className="bg-red-600 hover:bg-red-700">
              Löschen
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Student Detail Viewer */}
      {selectedStudentId && (
        <StudentDetailViewer 
          studentId={selectedStudentId} 
          onClose={() => setSelectedStudentId(null)} 
        />
      )}

      {/* iPad Detail Viewer */}
      {selectedIPadId && (
        <IPadDetailViewer 
          ipadId={selectedIPadId} 
          onClose={() => setSelectedIPadId(null)} 
        />
      )}
    </div>
  );
};

export default ContractsManagement;
