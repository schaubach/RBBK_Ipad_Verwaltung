import React from 'react';
import { Layers } from 'lucide-react';
import { useBildungsgangAnsicht } from '../../hooks/BildungsgangAnsicht';

/**
 * Umschalter der Arbeitsansicht - gehört in die Kopfzeile, nicht in die einzelnen Listen:
 * Schüler, Geräte und Verträge eines Bildungsgangs sind Sichten auf dieselbe Einheit.
 *
 * Globale Einstellungen werden vergessen. Deshalb steht er neben dem Kontonamen und wird
 * hervorgehoben, sobald die Ansicht eingeengt ist - damit niemand rätselt, wo der halbe
 * Bestand geblieben ist.
 *
 * Zeigt sich nur, wenn es etwas umzuschalten gibt. Wer genau einen Bildungsgang betreut,
 * sieht ohnehin nur diesen.
 */
export function BildungsgangUmschalter() {
  const { ansichtBildungsgang, setAnsichtBildungsgang, auswaehlbar, laedt, isAdmin } =
    useBildungsgangAnsicht();

  if (laedt || auswaehlbar.length < 2) return null;

  const eingeengt = Boolean(ansichtBildungsgang);

  return (
    <div className="flex items-center gap-2 text-white">
      <Layers className="h-4 w-4" aria-hidden="true" />
      <label htmlFor="bildungsgang-umschalter" className="text-sm whitespace-nowrap">
        Ansicht
      </label>
      <select
        id="bildungsgang-umschalter"
        data-testid="bildungsgang-umschalter"
        value={ansichtBildungsgang}
        onChange={(e) => setAnsichtBildungsgang(e.target.value)}
        className={`rounded-md border bg-white px-2 py-1 text-sm text-ipad-dark-gray ${
          eingeengt ? 'border-amber-400 ring-2 ring-amber-400 font-semibold' : 'border-white/30'
        }`}
      >
        {/* Für eine Lehrkraft heißt "alles" ausdrücklich: alles, wofür SIE zuständig ist.
            Ein schlichtes "Alle Bildungsgänge" würde mehr versprechen, als die Rechte
            hergeben - die Liste bliebe dieselbe, nur die Beschriftung wäre falsch. */}
        <option value="">
          {isAdmin
            ? 'Alle Bildungsgänge'
            : `Meine Bildungsgänge (${auswaehlbar.map((b) => b.name).join(', ')})`}
        </option>
        {auswaehlbar.map((b) => (
          <option key={b.id} value={b.id}>
            {b.name}
          </option>
        ))}
      </select>
    </div>
  );
}
