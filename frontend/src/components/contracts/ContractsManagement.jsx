import React, { useState, useEffect } from 'react';
import api from '../../api';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Input } from '../ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/table';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { toast } from 'sonner';
import { Upload, FileText, Download, Trash2 } from 'lucide-react';

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

export default ContractsManagement;
