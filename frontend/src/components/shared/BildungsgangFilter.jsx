import React from 'react';
import { Label } from '../ui/label';
import { useBildungsgaenge } from '../../hooks/useBildungsgaenge';

/**
 * Umschalter für die Ansicht: alles oder ein einzelner Bildungsgang.
 *
 * Reine Ansichtssache — die Rechte liegen im Backend und bleiben unberührt. Wer einen
 * Bildungsgang nicht sehen darf, bekommt auch über diesen Umschalter nichts zu sehen.
 * Deshalb steht hier auch die volle Liste: ein Admin darf alles, eine Lehrkraft bekommt
 * für fremde Einträge schlicht ein leeres Ergebnis.
 *
 * Zeigt sich nur, wenn es etwas umzuschalten gibt. Wer genau einen Bildungsgang betreut,
 * sieht ohnehin nur diesen; ein Umschalter wäre dort nur ein Feld, das nichts tut.
 */
export function BildungsgangFilter({ value, onChange, username, isAdmin = false, id = 'bildungsgang-filter' }) {
  const { alle, meine, laedt } = useBildungsgaenge(username);

  const auswaehlbar = isAdmin ? alle : meine;
  if (laedt || auswaehlbar.length < 2) return null;

  return (
    <div className="flex items-center gap-2">
      <Label htmlFor={id} className="whitespace-nowrap text-sm">
        Ansicht
      </Label>
      <select
        id={id}
        value={value || ''}
        onChange={(e) => onChange(e.target.value)}
        className="p-2 border rounded-md text-sm"
        data-testid="bildungsgang-filter"
      >
        <option value="">Alle{isAdmin && meine.length === 0 ? '' : ' Bildungsgänge'}</option>
        {auswaehlbar.map((b) => (
          <option key={b.id} value={b.id}>
            {b.name}
          </option>
        ))}
      </select>
    </div>
  );
}
