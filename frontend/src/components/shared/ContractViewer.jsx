import React, { useState, useEffect } from 'react';
import api from '../../api';
import { Button } from '../ui/button';
import { X } from 'lucide-react';

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



export default ContractViewer;
