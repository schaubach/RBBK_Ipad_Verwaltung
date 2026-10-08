import React from 'react';
import { Label } from '../ui/label';
import { useBildungsgaenge } from '../../hooks/useBildungsgaenge';

/**
 * Auswahlfeld für den Bildungsgang eines neuen Datensatzes.
 *
 * Zeigt sich nur, wenn eine Wahl wirklich nötig ist: Wer für genau einen Bildungsgang
 * zuständig ist, bekommt kein zusätzliches Feld - das Backend ergänzt den Wert. Für alle
 * anderen ist die Angabe Pflicht, und zwar bewusst ohne Vorbelegung: eine geratene
 * Voreinstellung landet unbemerkt im falschen Bestand.
 *
 * Admins dürfen in jeden Bildungsgang schreiben und sehen deshalb die vollständige Liste.
 */
export function BildungsgangSelect({ value, onChange, username, isAdmin = false, label = 'Bildungsgang', id = 'bildungsgang' }) {
  const { alle, meine, laedt, auswahlNoetig } = useBildungsgaenge(username);

  if (laedt || !auswahlNoetig) return null;

  const optionen = isAdmin ? alle : meine;

  if (optionen.length === 0) {
    return (
      <p className="text-sm text-red-700 bg-red-50 border-l-4 border-red-400 p-3 rounded">
        Sie sind derzeit für keinen Bildungsgang zuständig und können deshalb nichts anlegen.
        Bitte an die Administration wenden.
      </p>
    );
  }

  return (
    <div className="space-y-2">
      <Label htmlFor={id}>
        {label} <span className="text-red-600">*</span>
      </Label>
      <select
        id={id}
        value={value || ''}
        onChange={(e) => onChange(e.target.value)}
        className="w-full p-2 border rounded-md"
      >
        <option value="">— bitte wählen —</option>
        {optionen.map((b) => (
          <option key={b.id} value={b.id}>
            {b.name}
          </option>
        ))}
      </select>
      {isAdmin && meine.length === 0 && (
        <p className="text-xs text-gray-500">
          Dieses Konto betreut selbst keinen Bildungsgang — bitte bewusst wählen.
        </p>
      )}
    </div>
  );
}
