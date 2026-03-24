import React, { useState, useEffect } from 'react';
import api from '../../api';
import { Button } from '../ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { toast } from 'sonner';
import { User, FileText, Download, X, Tablet, Pencil, Save, XCircle } from 'lucide-react';

const StudentDetailViewer = ({ studentId, onClose, onUpdate }) => {
  const [studentData, setStudentData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [editMode, setEditMode] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editedStudent, setEditedStudent] = useState({});

  useEffect(() => {
    const loadStudentDetails = async () => {
      try {
        const response = await api.get(`/students/${studentId}`);
        setStudentData(response.data);
        setEditedStudent(response.data.student);
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

  const handleInputChange = (field, value) => {
    setEditedStudent(prev => ({ ...prev, [field]: value }));
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const response = await api.put(`/students/${studentId}`, editedStudent);
      toast.success('Schüler erfolgreich aktualisiert');
      setStudentData(prev => ({ ...prev, student: response.data.student }));
      setEditMode(false);
      if (onUpdate) onUpdate();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Speichern');
    } finally {
      setSaving(false);
    }
  };

  const handleCancel = () => {
    setEditedStudent(studentData.student);
    setEditMode(false);
  };

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
            <div className="flex gap-2">
              {!editMode ? (
                <Button variant="outline" onClick={() => setEditMode(true)} data-testid="edit-student-btn">
                  <Pencil className="h-4 w-4 mr-2" />
                  Bearbeiten
                </Button>
              ) : (
                <>
                  <Button variant="outline" onClick={handleCancel} disabled={saving}>
                    <XCircle className="h-4 w-4 mr-2" />
                    Abbrechen
                  </Button>
                  <Button onClick={handleSave} disabled={saving} className="bg-green-600 hover:bg-green-700">
                    <Save className="h-4 w-4 mr-2" />
                    {saving ? 'Speichere...' : 'Speichern'}
                  </Button>
                </>
              )}
              <Button variant="outline" onClick={onClose}>
                <X className="h-4 w-4" />
              </Button>
            </div>
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
              {editMode ? (
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  <div>
                    <Label htmlFor="sus_vorn">Vorname</Label>
                    <Input
                      id="sus_vorn"
                      value={editedStudent.sus_vorn || ''}
                      onChange={(e) => handleInputChange('sus_vorn', e.target.value)}
                      data-testid="student-vorname-input"
                    />
                  </div>
                  <div>
                    <Label htmlFor="sus_nachn">Nachname</Label>
                    <Input
                      id="sus_nachn"
                      value={editedStudent.sus_nachn || ''}
                      onChange={(e) => handleInputChange('sus_nachn', e.target.value)}
                      data-testid="student-nachname-input"
                    />
                  </div>
                  <div>
                    <Label htmlFor="sname">Schulname</Label>
                    <Input
                      id="sname"
                      value={editedStudent.sname || ''}
                      onChange={(e) => handleInputChange('sname', e.target.value)}
                      data-testid="student-sname-input"
                    />
                  </div>
                  <div>
                    <Label htmlFor="sus_kl">Klasse</Label>
                    <Input
                      id="sus_kl"
                      value={editedStudent.sus_kl || ''}
                      onChange={(e) => handleInputChange('sus_kl', e.target.value)}
                      data-testid="student-klasse-input"
                    />
                  </div>
                  <div>
                    <Label htmlFor="sus_geb">Geburtsdatum</Label>
                    <Input
                      id="sus_geb"
                      type="date"
                      value={editedStudent.sus_geb || ''}
                      onChange={(e) => handleInputChange('sus_geb', e.target.value)}
                      data-testid="student-geb-input"
                    />
                  </div>
                  <div>
                    <Label htmlFor="sus_str_hnr">Adresse</Label>
                    <Input
                      id="sus_str_hnr"
                      value={editedStudent.sus_str_hnr || ''}
                      onChange={(e) => handleInputChange('sus_str_hnr', e.target.value)}
                      data-testid="student-adresse-input"
                    />
                  </div>
                  <div>
                    <Label htmlFor="sus_plz">PLZ</Label>
                    <Input
                      id="sus_plz"
                      value={editedStudent.sus_plz || ''}
                      onChange={(e) => handleInputChange('sus_plz', e.target.value)}
                      data-testid="student-plz-input"
                    />
                  </div>
                  <div>
                    <Label htmlFor="sus_ort">Ort</Label>
                    <Input
                      id="sus_ort"
                      value={editedStudent.sus_ort || ''}
                      onChange={(e) => handleInputChange('sus_ort', e.target.value)}
                      data-testid="student-ort-input"
                    />
                  </div>
                </div>
              ) : (
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
                  <div><strong>Vorname:</strong> {student.sus_vorn || 'N/A'}</div>
                  <div><strong>Nachname:</strong> {student.sus_nachn || 'N/A'}</div>
                  <div><strong>Schulname:</strong> {student.sname || 'N/A'}</div>
                  <div><strong>Klasse:</strong> {student.sus_kl || 'N/A'}</div>
                  <div><strong>Geburtsdatum:</strong> {student.sus_geb ? new Date(student.sus_geb).toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' }) : 'N/A'}</div>
                  <div><strong>Adresse:</strong> {student.sus_str_hnr || 'N/A'}</div>
                  <div><strong>PLZ:</strong> {student.sus_plz || 'N/A'}</div>
                  <div><strong>Ort:</strong> {student.sus_ort || 'N/A'}</div>
                  <div><strong>Erstellt am:</strong> {student.created_at ? new Date(student.created_at).toLocaleDateString('de-DE') : 'N/A'}</div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Erziehungsberechtigte */}
          <Card className="mb-6">
            <CardHeader>
              <CardTitle>Erziehungsberechtigte</CardTitle>
            </CardHeader>
            <CardContent>
              {editMode ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="border rounded-lg p-4">
                    <h4 className="font-medium mb-3">Erziehungsberechtigte/r 1</h4>
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <Label htmlFor="erz1_vorn">Vorname</Label>
                          <Input
                            id="erz1_vorn"
                            value={editedStudent.erz1_vorn || ''}
                            onChange={(e) => handleInputChange('erz1_vorn', e.target.value)}
                          />
                        </div>
                        <div>
                          <Label htmlFor="erz1_nachn">Nachname</Label>
                          <Input
                            id="erz1_nachn"
                            value={editedStudent.erz1_nachn || ''}
                            onChange={(e) => handleInputChange('erz1_nachn', e.target.value)}
                          />
                        </div>
                      </div>
                      <div>
                        <Label htmlFor="erz1_str_hnr">Adresse</Label>
                        <Input
                          id="erz1_str_hnr"
                          value={editedStudent.erz1_str_hnr || ''}
                          onChange={(e) => handleInputChange('erz1_str_hnr', e.target.value)}
                        />
                      </div>
                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <Label htmlFor="erz1_plz">PLZ</Label>
                          <Input
                            id="erz1_plz"
                            value={editedStudent.erz1_plz || ''}
                            onChange={(e) => handleInputChange('erz1_plz', e.target.value)}
                          />
                        </div>
                        <div>
                          <Label htmlFor="erz1_ort">Ort</Label>
                          <Input
                            id="erz1_ort"
                            value={editedStudent.erz1_ort || ''}
                            onChange={(e) => handleInputChange('erz1_ort', e.target.value)}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="border rounded-lg p-4">
                    <h4 className="font-medium mb-3">Erziehungsberechtigte/r 2</h4>
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <Label htmlFor="erz2_vorn">Vorname</Label>
                          <Input
                            id="erz2_vorn"
                            value={editedStudent.erz2_vorn || ''}
                            onChange={(e) => handleInputChange('erz2_vorn', e.target.value)}
                          />
                        </div>
                        <div>
                          <Label htmlFor="erz2_nachn">Nachname</Label>
                          <Input
                            id="erz2_nachn"
                            value={editedStudent.erz2_nachn || ''}
                            onChange={(e) => handleInputChange('erz2_nachn', e.target.value)}
                          />
                        </div>
                      </div>
                      <div>
                        <Label htmlFor="erz2_str_hnr">Adresse</Label>
                        <Input
                          id="erz2_str_hnr"
                          value={editedStudent.erz2_str_hnr || ''}
                          onChange={(e) => handleInputChange('erz2_str_hnr', e.target.value)}
                        />
                      </div>
                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <Label htmlFor="erz2_plz">PLZ</Label>
                          <Input
                            id="erz2_plz"
                            value={editedStudent.erz2_plz || ''}
                            onChange={(e) => handleInputChange('erz2_plz', e.target.value)}
                          />
                        </div>
                        <div>
                          <Label htmlFor="erz2_ort">Ort</Label>
                          <Input
                            id="erz2_ort"
                            value={editedStudent.erz2_ort || ''}
                            onChange={(e) => handleInputChange('erz2_ort', e.target.value)}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
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
              )}
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
                        <Badge className={assignment.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}>
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
          {contracts && contracts.length > 0 && (
            <Card className="mb-6">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileText className="h-5 w-5" />
                  Verträge ({contracts.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-60 overflow-y-auto">
                  {contracts.map((contract) => (
                    <div key={contract.id} className={`p-3 rounded-lg text-sm ${contract.is_active ? 'bg-blue-50 border-l-4 border-blue-400' : 'bg-gray-50 border-l-4 border-gray-400'}`}>
                      <div className="flex justify-between items-center">
                        <div className="flex-1">
                          <div><strong>Datei:</strong> {contract.filename}</div>
                          <div><strong>iPad:</strong> {contract.itnr || 'Unzugewiesen'}</div>
                          <div><strong>Hochgeladen:</strong> {new Date(contract.uploaded_at).toLocaleDateString('de-DE')}</div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge className={contract.is_active ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-800'}>
                            {contract.is_active ? 'Aktiv' : 'Historisch'}
                          </Badge>
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={async () => {
                              try {
                                const response = await api.get(`/contracts/${contract.id}/download`, { responseType: 'blob' });
                                const url = window.URL.createObjectURL(new Blob([response.data]));
                                const link = document.createElement('a');
                                link.href = url;
                                link.setAttribute('download', contract.filename);
                                document.body.appendChild(link);
                                link.click();
                                link.remove();
                              } catch (error) {
                                toast.error('Fehler beim Herunterladen');
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

export default StudentDetailViewer;
