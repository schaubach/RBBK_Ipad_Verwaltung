import React, { useState, useEffect } from 'react';
import api from '../../api';
import { Button } from '../ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { toast } from 'sonner';
import { Tablet, FileText, Download, X, User } from 'lucide-react';

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

  const handleDownload = async (contractId, filename) => {
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
      window.URL.revokeObjectURL(url);
      document.body.removeChild(link);
    } catch (error) {
      toast.error('Fehler beim Download');
    }
  };

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
                      onClick={() => handleDownload(current_contract.id, current_contract.filename)}
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
                            onClick={() => handleDownload(contract.id, contract.filename)}
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

export default IPadDetailViewer;
