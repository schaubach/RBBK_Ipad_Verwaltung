import React from 'react';
import { Input } from '../ui/input';

/**
 * Suche + anklickbare Liste von Bildungsgängen, genutzt von den Admin-Dialogen
 * "Pool-iPads zuweisen" und "Batch-Zuordnung per Datei".
 *
 * Das Gegenstück zum früheren UserPicker an diesen Stellen: Geräte gehören dem
 * Bildungsgang, nicht der Person. Wer ihn betreut, steht als Zusatz darunter — das ist
 * die Information, nach der man im Alltag sucht, aber sie ist nur Anzeige.
 */
export const BildungsgangPicker = ({
  bildungsgaenge,
  searchQuery,
  onSearchChange,
  onSelect,
  selectedId = null,
  searchTestId,
  rowTestIdPrefix,
}) => {
  const gefiltert = bildungsgaenge.filter(
    (b) => !searchQuery || b.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-2">
      <Input
        placeholder="Bildungsgang suchen..."
        value={searchQuery}
        onChange={(e) => onSearchChange(e.target.value)}
        data-testid={searchTestId}
      />
      <div className="max-h-64 overflow-y-auto border rounded-lg">
        {gefiltert.map((b) => {
          const aktuell = (b.zustaendige || []).filter((z) => !z.bis).map((z) => z.username);
          return (
            <button
              key={b.id}
              onClick={() => onSelect(b)}
              className={`w-full text-left p-3 hover:bg-gray-100 border-b last:border-b-0 ${
                selectedId === b.id ? 'bg-blue-50' : ''
              }`}
              data-testid={`${rowTestIdPrefix}-${b.id}`}
            >
              <div className="font-medium">{b.name}</div>
              <div className="text-xs text-gray-500">
                {aktuell.length > 0 ? `zuständig: ${aktuell.join(', ')}` : 'derzeit niemand zuständig'}
              </div>
            </button>
          );
        })}
        {gefiltert.length === 0 && (
          <div className="p-4 text-center text-sm text-gray-500">Kein Bildungsgang gefunden</div>
        )}
      </div>
    </div>
  );
};
