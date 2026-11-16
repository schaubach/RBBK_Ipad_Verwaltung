import React, { useEffect, useState } from 'react';
import api from '../../api';
import { Button } from '../ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '../ui/alert-dialog';
import { toast } from 'sonner';
import { ExternalLink, RefreshCw, Smartphone } from 'lucide-react';

// Was vor dem Senden abgefragt wird. Befehle ohne Eintrag gehen ohne Rückfrage raus -
// das sind die harmlosen (Inventar).
const RUECKFRAGE = {
  sperren: { text: 'Das iPad wird sofort gesperrt. Die Nachricht erscheint auf dem Sperrbildschirm.', felder: ['nachricht', 'telefon'] },
  verloren_an: {
    text: 'Das iPad wird gesperrt und zeigt die Nachricht, bis der Verloren-Modus wieder ausgeschaltet wird. Nachricht oder Telefonnummer ist Pflicht.',
    felder: ['nachricht', 'telefon'],
  },
  verloren_aus: { text: 'Der Verloren-Modus wird beendet, das iPad ist wieder normal nutzbar.' },
  verloren_ton: { text: 'Das iPad spielt einen Ton ab (nur im Verloren-Modus möglich).' },
  code_entfernen: { text: 'Der Code des iPads wird entfernt. Danach ist es ohne Code entsperrbar.' },
  neustart: { text: 'Das iPad wird neu gestartet. Ungesicherte Eingaben darauf gehen verloren.' },
};

const janein = (wert) => (wert === true ? 'ja' : wert === false ? 'nein' : '–');

const datum = (wert) =>
  wert ? new Date(wert).toLocaleString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '–';

// Zeigt sich nur, wenn die Person einen Jamf-Login hinterlegt hat.
const JamfPanel = ({ ipadId }) => {
  const [zugang, setZugang] = useState(null);
  const [daten, setDaten] = useState(null);
  const [fehler, setFehler] = useState(null);
  const [laedt, setLaedt] = useState(false);
  const [offen, setOffen] = useState(null);
  const [eingabe, setEingabe] = useState({ nachricht: '', telefon: '' });
  const [sendet, setSendet] = useState(false);

  const statusLaden = async () => {
    setLaedt(true);
    setFehler(null);
    try {
      const res = await api.get(`/ipads/${ipadId}/jamf`);
      setDaten(res.data);
    } catch (error) {
      setFehler(error.response?.data?.detail || 'Jamf-Status konnte nicht geladen werden');
    } finally {
      setLaedt(false);
    }
  };

  useEffect(() => {
    let abgebrochen = false;
    api.get('/jamf/zugang')
      .then((res) => {
        if (abgebrochen) return;
        setZugang(res.data);
        if (res.data.eingerichtet && res.data.verknuepft) statusLaden();
      })
      .catch(() => {});
    return () => { abgebrochen = true; };
  }, [ipadId]);

  if (!zugang || !zugang.eingerichtet || !zugang.verknuepft) return null;

  const senden = async (befehl) => {
    setSendet(true);
    try {
      const res = await api.post(`/ipads/${ipadId}/jamf/befehl`, { befehl, ...eingabe });
      toast.success(res.data.message);
      setDaten((d) => ({ ...(d || {}), protokoll: res.data.protokoll }));
      setOffen(null);
      setEingabe({ nachricht: '', telefon: '' });
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Befehl konnte nicht gesendet werden');
    } finally {
      setSendet(false);
    }
  };

  const klick = (befehl) => {
    if (RUECKFRAGE[befehl]) setOffen(befehl);
    else senden(befehl);
  };

  const geraet = daten?.geraet;
  const befehle = zugang.befehle || [];
  const titel = (name) => befehle.find((b) => b.name === name)?.titel || name;
  const rueckfrage = offen ? RUECKFRAGE[offen] : null;

  return (
    <Card className="mb-6 border-sky-200" data-testid="jamf-panel">
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-2 flex-wrap">
          <span className="flex items-center gap-2">
            <Smartphone className="h-5 w-5" />
            Jamf Pro
          </span>
          <span className="flex gap-2">
            <Button variant="outline" size="sm" onClick={statusLaden} disabled={laedt}>
              <RefreshCw className={`h-4 w-4 ${laedt ? 'animate-spin' : ''}`} />
            </Button>
            {geraet?.jamf_link && (
              <Button variant="outline" size="sm" asChild>
                <a href={geraet.jamf_link} target="_blank" rel="noopener noreferrer">
                  <ExternalLink className="h-4 w-4 mr-2" />
                  In Jamf öffnen
                </a>
              </Button>
            )}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {zugang.gesperrt && (
          <div className="text-sm text-red-800 bg-red-50 border border-red-200 rounded p-3">
            Jamf hat Ihren hinterlegten Login abgelehnt. Bitte unter Einstellungen neu eintragen.
          </div>
        )}
        {fehler && !zugang.gesperrt && <div className="text-sm text-red-700">{fehler}</div>}
        {laedt && !daten && <div className="text-sm text-gray-500">Lade Status aus Jamf...</div>}
        {daten && !geraet && (
          <div className="text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded p-3">
            Jamf kennt kein Gerät mit dieser Seriennummer.
          </div>
        )}

        {geraet && (
          <>
            <div className="flex gap-2 flex-wrap">
              {geraet.verloren_modus && <Badge className="bg-red-100 text-red-800">Verloren-Modus aktiv</Badge>}
              {geraet.aktivierungssperre && <Badge className="bg-amber-100 text-amber-800">Aktivierungssperre an</Badge>}
              {geraet.verwaltet === false && <Badge className="bg-gray-100 text-gray-800">Nicht verwaltet</Badge>}
            </div>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
              <div><strong>Name:</strong> {geraet.name || '–'}</div>
              <div><strong>iOS:</strong> {geraet.os_version || '–'}</div>
              <div><strong>Akku:</strong> {geraet.akku != null ? `${geraet.akku} %` : '–'}</div>
              <div>
                <strong>Speicher frei:</strong>{' '}
                {geraet.frei_mb != null ? `${(geraet.frei_mb / 1024).toFixed(1)} GB` : '–'}
                {geraet.kapazitaet_mb ? ` von ${(geraet.kapazitaet_mb / 1024).toFixed(0)} GB` : ''}
              </div>
              <div><strong>Letzte Inventur:</strong> {datum(geraet.letzte_inventur)}</div>
              <div><strong>Betreut:</strong> {janein(geraet.betreut)}</div>
              <div><strong>Code gesetzt:</strong> {janein(geraet.code_gesetzt)}</div>
              <div><strong>Aktivierungssperre:</strong> {janein(geraet.aktivierungssperre)}</div>
              {geraet.standort && (
                <div className="col-span-2 md:col-span-3">
                  <strong>Letzter Standort:</strong>{' '}
                  <a
                    className="text-blue-700 underline"
                    href={`https://www.openstreetmap.org/?mlat=${geraet.standort.breite}&mlon=${geraet.standort.laenge}#map=17/${geraet.standort.breite}/${geraet.standort.laenge}`}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Auf Karte zeigen
                  </a>{' '}
                  ({datum(geraet.standort.stand)})
                </div>
              )}
            </div>
            {geraet.aktivierungssperre && (
              <p className="text-xs text-gray-500">
                Den Code zum Aufheben der Aktivierungssperre gibt Jamf nur in der eigenen Oberfläche heraus:
                „In Jamf öffnen“ → Verwaltung.
              </p>
            )}

            {zugang.fehlende_rechte?.length > 0 && (
              <p className="text-xs text-gray-500">
                Einige Befehle fehlen, weil Ihrem Jamf-Konto Rechte fehlen (Details unter Einstellungen).
                Bis dahin: „In Jamf öffnen“.
              </p>
            )}
            {befehle.length > 0 && (
              <div className="flex gap-2 flex-wrap pt-2 border-t">
                {befehle
                  .filter((b) => (geraet.verloren_modus ? b.name !== 'verloren_an' : !['verloren_aus', 'verloren_ton'].includes(b.name)))
                  .map((b) => (
                    <Button
                      key={b.name}
                      variant="outline"
                      size="sm"
                      disabled={sendet}
                      onClick={() => klick(b.name)}
                      data-testid={`jamf-befehl-${b.name}`}
                      className={['sperren', 'verloren_an', 'code_entfernen'].includes(b.name) ? 'border-red-300 text-red-700 hover:bg-red-50' : ''}
                    >
                      {b.titel}
                    </Button>
                  ))}
              </div>
            )}
          </>
        )}

        {daten?.protokoll?.length > 0 && (
          <div className="pt-2 border-t">
            <div className="text-sm font-medium mb-2">Zuletzt gesendet</div>
            <div className="space-y-1 max-h-32 overflow-y-auto text-xs">
              {daten.protokoll.map((e, i) => (
                <div key={i} className={e.erfolg ? 'text-gray-700' : 'text-red-700'}>
                  {datum(e.at)} · {e.titel} · {e.username}
                  {e.erfolg ? '' : ` · abgelehnt: ${e.fehler}`}
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>

      <AlertDialog open={!!offen} onOpenChange={(o) => !o && !sendet && setOffen(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{offen ? titel(offen) : ''}?</AlertDialogTitle>
            <AlertDialogDescription>{rueckfrage?.text}</AlertDialogDescription>
          </AlertDialogHeader>
          {rueckfrage?.felder && (
            <div className="space-y-3">
              <div>
                <Label htmlFor="jamf-nachricht">Nachricht auf dem Bildschirm</Label>
                <Input
                  id="jamf-nachricht"
                  maxLength={500}
                  placeholder="z. B. Bitte im Sekretariat abgeben"
                  value={eingabe.nachricht}
                  onChange={(e) => setEingabe({ ...eingabe, nachricht: e.target.value })}
                />
              </div>
              <div>
                <Label htmlFor="jamf-telefon">Telefonnummer (optional)</Label>
                <Input
                  id="jamf-telefon"
                  maxLength={50}
                  value={eingabe.telefon}
                  onChange={(e) => setEingabe({ ...eingabe, telefon: e.target.value })}
                />
              </div>
            </div>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={sendet}>Abbrechen</AlertDialogCancel>
            <AlertDialogAction
              disabled={sendet || (offen === 'verloren_an' && !eingabe.nachricht.trim() && !eingabe.telefon.trim())}
              onClick={(e) => {
                e.preventDefault();
                senden(offen);
              }}
              className="bg-red-600 hover:bg-red-700"
            >
              {sendet ? 'Sendet...' : 'Senden'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
};

export default JamfPanel;
