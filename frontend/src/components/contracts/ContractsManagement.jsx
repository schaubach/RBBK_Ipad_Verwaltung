import React, { useState, useEffect } from 'react';
import api from '../../api';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '../ui/alert-dialog';
import { toast } from 'sonner';
import { Upload, FileText, Download, Trash2, Search, Link } from 'lucide-react';

const ContractsManagement = () => {
  const [unassignedContracts, setUnassignedContracts] = useState([]);
  const [availableAssignments, setAvailableAssignments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  
  // Dialog für Vertragszuordnung
  const [assignDialogOpen, setAssignDialogOpen] = useState(false);
  const [selectedContract, setSelectedContract] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [assigning, setAssigning] = useState(false);

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

  const handleDeleteContract = async (contractId) => {
    try {
      await api.delete(`/contracts/${contractId}`);
      toast.success('Vertrag gelöscht');
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

  // Gefilterte Zuordnungen basierend auf Suchbegriff
  const filteredAssignments = availableAssignments.filter(a => {
    const term = searchTerm.toLowerCase();
    return (
      a.itnr?.toLowerCase().includes(term) ||
      a.student_name?.toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-6">
      <Card className="shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" />
            Verträge hochladen
          </CardTitle>
          <CardDescription>
            Verträge hochladen - PDF oder Bilder (bis zu 50 Dateien gleichzeitig)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-blue-400 transition-colors">
            <Input
              type="file"
              accept=".pdf,.png,.jpg,.jpeg,.gif,.bmp,.webp"
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
            
            <div className="mt-4 p-4 bg-blue-50 rounded-lg text-left">
              <h4 className="font-medium text-blue-800 mb-2">Upload-Hinweise:</h4>
              <ul className="text-sm text-blue-700 space-y-1">
                <li>• <strong>PDF-Verträge</strong> mit Formularfeldern (ITNr, SuSVorn, SuSNachn) werden automatisch zugeordnet</li>
                <li>• <strong>Bilder</strong> (PNG, JPG, etc.) müssen manuell zugeordnet werden</li>
                <li>• Pro Zuordnung kann nur 1 Vertrag zugewiesen werden</li>
                <li>• Pro Schüler sind max. 3 Verträge erlaubt</li>
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
                        <div className="flex gap-2">
                          <Button
                            size="sm"
                            onClick={() => openAssignDialog(contract)}
                            className="bg-blue-600 hover:bg-blue-700"
                          >
                            <Link className="h-4 w-4 mr-1" />
                            Zuordnen
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleDownloadContract(contract.id, contract.filename)}
                          >
                            <Download className="h-4 w-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => handleDeleteContract(contract.id)}
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
    </div>
  );
};

export default ContractsManagement;
