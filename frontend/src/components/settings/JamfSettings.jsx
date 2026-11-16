import React, { useEffect, useState } from 'react';
import api from '../../api';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { toast } from 'sonner';
import { Link2 } from 'lucide-react';

// Jamf-Anbindung: Admins stellen die Adresse ein, jede Person hinterlegt ihren eigenen
// Jamf-Login. Das Passwort geht nur an das Backend, das es bei Jamf prüft und verschlüsselt
// ablegt - zurück kommt es nie.
const JamfSettings = ({ isAdmin = false }) => {
  const [zugang, setZugang] = useState(null);
  const [url, setUrl] = useState('');
  const [form, setForm] = useState({ benutzername: '', passwort: '' });
  const [busy, setBusy] = useState(false);

  const laden = async () => {
    try {
      const res = await api.get('/jamf/zugang');
      setZugang(res.data);
      if (res.data.benutzername) setForm((f) => ({ ...f, benutzername: res.data.benutzername }));
    } catch {
      setZugang(null);
    }
    if (isAdmin) {
      try {
        const res = await api.get('/jamf/einstellungen');
        setUrl(res.data.url || '');
      } catch {
        // Anzeige bleibt leer
      }
    }
  };

  useEffect(() => {
    laden();
  }, [isAdmin]);

  const urlSpeichern = async () => {
    setBusy(true);
    try {
      const res = await api.put('/jamf/einstellungen', { url });
      setUrl(res.data.url);
      toast.success(res.data.url ? 'Jamf-Adresse gespeichert' : 'Jamf-Anbindung abgeschaltet');
      await laden();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Speichern der Jamf-Adresse');
    } finally {
      setBusy(false);
    }
  };

  const verbinden = async () => {
    setBusy(true);
    try {
      const res = await api.put('/jamf/zugang', form);
      setZugang(res.data);
      setForm((f) => ({ ...f, passwort: '' }));
      toast.success('Jamf-Login geprüft und hinterlegt');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Jamf-Login konnte nicht geprüft werden');
    } finally {
      setBusy(false);
    }
  };

  const trennen = async () => {
    setBusy(true);
    try {
      await api.delete('/jamf/zugang');
      setForm({ benutzername: '', passwort: '' });
      toast.success('Jamf-Login entfernt');
      await laden();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Entfernen');
    } finally {
      setBusy(false);
    }
  };

  if (!zugang) return null;
  // Ohne eingerichtete Adresse gibt es für Nicht-Admins nichts zu tun.
  if (!zugang.eingerichtet && !isAdmin) return null;

  return (
    <Card className="shadow-lg" data-testid="jamf-settings">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Link2 className="h-5 w-5" />
          Jamf Pro
        </CardTitle>
        <CardDescription>
          Mit Ihrem Jamf-Login können Sie iPads direkt aus der Detailansicht sperren, in den
          Verloren-Modus versetzen und mehr.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="max-w-md space-y-6">
          {isAdmin && (
            <div className="space-y-2 border-l-4 border-gray-300 bg-gray-50 p-4 rounded">
              <Label htmlFor="jamf-url">Jamf-Adresse (nur Admins)</Label>
              <Input
                id="jamf-url"
                placeholder="https://schule.jamfcloud.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
              <p className="text-xs text-gray-500">Leer lassen schaltet die Anbindung für alle ab.</p>
              <Button variant="outline" onClick={urlSpeichern} disabled={busy}>
                Adresse speichern
              </Button>
            </div>
          )}

          {zugang.eingerichtet && (
            <div className="space-y-3">
              {zugang.verknuepft && !zugang.gesperrt && (
                <div className="text-sm text-green-800 bg-green-50 border border-green-200 rounded p-3">
                  Verbunden als <strong>{zugang.benutzername}</strong>.{' '}
                  {zugang.befehle.length > 0
                    ? `Erlaubt: ${zugang.befehle.map((b) => b.titel).join(', ')}.`
                    : 'Ihr Jamf-Konto darf keinen der angebotenen Befehle senden.'}
                </div>
              )}
              {zugang.verknuepft && !zugang.gesperrt && zugang.fehlende_rechte?.length > 0 && (
                <div className="text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded p-3">
                  Einige Befehle nimmt Jamf über die Schnittstelle erst an, wenn Ihr Jamf-Konto zusätzlich
                  diese Rechte hat:
                  <ul className="list-disc ml-5 my-1">
                    {zugang.fehlende_rechte.map((r) => <li key={r}><strong>{r}</strong></li>)}
                  </ul>
                  Das vergibt die Jamf-Verwaltung (Systemhaus). Danach hier „Login aktualisieren“.
                </div>
              )}
              {zugang.gesperrt && (
                <div className="text-sm text-red-800 bg-red-50 border border-red-200 rounded p-3">
                  Jamf hat den hinterlegten Login abgelehnt (Passwort geändert?). Bitte neu eintragen.
                </div>
              )}
              <div>
                <Label htmlFor="jamf-benutzer">Jamf-Benutzername</Label>
                <Input
                  id="jamf-benutzer"
                  autoComplete="off"
                  value={form.benutzername}
                  onChange={(e) => setForm({ ...form, benutzername: e.target.value })}
                />
              </div>
              <div>
                <Label htmlFor="jamf-passwort">Jamf-Passwort</Label>
                <Input
                  id="jamf-passwort"
                  type="password"
                  autoComplete="new-password"
                  value={form.passwort}
                  onChange={(e) => setForm({ ...form, passwort: e.target.value })}
                />
              </div>
              <p className="text-xs text-gray-500">
                Das Passwort wird bei Jamf geprüft und verschlüsselt auf dem Server gespeichert.
                Melden Sie sich bei Jamf per Microsoft-Konto (SSO) an, funktioniert das nicht.
              </p>
              <div className="flex gap-2">
                <Button
                  onClick={verbinden}
                  disabled={busy || !form.benutzername || !form.passwort}
                  className="bg-gradient-to-r from-ipad-teal to-ipad-blue hover:from-ipad-blue hover:to-ipad-dark-blue"
                >
                  {busy ? 'Prüft...' : zugang.verknuepft ? 'Login aktualisieren' : 'Verbinden'}
                </Button>
                {zugang.verknuepft && (
                  <Button variant="outline" onClick={trennen} disabled={busy}>
                    Login entfernen
                  </Button>
                )}
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

export default JamfSettings;
