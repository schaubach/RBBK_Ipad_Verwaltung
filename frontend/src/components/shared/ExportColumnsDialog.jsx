import React, { useEffect, useMemo, useState } from 'react';
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
import { Checkbox } from '../ui/checkbox';
import { Button } from '../ui/button';
import { Label } from '../ui/label';
import api from '../../api';

const STORAGE_KEY = 'exportColumnsPreferences';

const GROUP_LABELS = {
  student: 'Schüler & Erziehungsberechtigte',
  ipad: 'iPad',
  contract: 'Vertrag',
};

/**
 * Reusable column-picker dialog that loads the canonical column list from
 * /exports/columns, remembers the user's last selection in localStorage and
 * invokes the parent's onConfirm(selectedColumns) when the user clicks
 * "Exportieren".  Pass `open` + `onOpenChange` from the parent.
 */
export const ExportColumnsDialog = ({ open, onOpenChange, onConfirm, title = 'Spalten für Export wählen', description }) => {
  const [groups, setGroups] = useState({});
  const [allColumns, setAllColumns] = useState([]);
  const [selected, setSelected] = useState(new Set());
  const [loading, setLoading] = useState(false);

  // Load column spec from backend on first open
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      try {
        const res = await api.get('/exports/columns');
        if (cancelled) return;
        setGroups(res.data.groups || {});
        setAllColumns(res.data.columns || []);
        // Restore from localStorage or default = all selected
        let initial;
        try {
          const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
          if (Array.isArray(stored) && stored.length > 0) {
            initial = new Set(stored.filter(c => res.data.columns.includes(c)));
          }
        } catch (e) {
          initial = undefined;
        }
        if (!initial || initial.size === 0) {
          initial = new Set(res.data.columns);
        }
        setSelected(initial);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [open]);

  const toggleColumn = (col) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(col)) next.delete(col); else next.add(col);
      return next;
    });
  };

  const toggleGroup = (groupKey, groupCols) => {
    setSelected(prev => {
      const next = new Set(prev);
      const allInGroup = groupCols.every(c => next.has(c));
      if (allInGroup) {
        groupCols.forEach(c => next.delete(c));
      } else {
        groupCols.forEach(c => next.add(c));
      }
      return next;
    });
  };

  const selectAll = () => setSelected(new Set(allColumns));
  const selectNone = () => setSelected(new Set());

  const handleConfirm = () => {
    const orderedSelection = allColumns.filter(c => selected.has(c));
    if (orderedSelection.length === 0) {
      return; // disable via button state below
    }
    // Persist selection
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(orderedSelection));
    } catch (e) {
      /* ignore quota errors */
    }
    onConfirm(orderedSelection);
  };

  const totalSelected = selected.size;
  const groupKeys = useMemo(() => Object.keys(groups), [groups]);

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent className="max-w-2xl" data-testid="export-columns-dialog">
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>
            {description || 'Wähle die Spalten, die im Excel-Export enthalten sein sollen. Deine Auswahl wird für das nächste Mal gespeichert.'}
          </AlertDialogDescription>
        </AlertDialogHeader>

        {loading ? (
          <div className="py-8 text-center text-sm text-gray-500">Lade Spaltenliste…</div>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center justify-between gap-2">
              <div className="text-sm text-gray-600" data-testid="export-columns-count">
                {totalSelected} von {allColumns.length} Spalten ausgewählt
              </div>
              <div className="flex gap-2">
                <Button type="button" variant="outline" size="sm" onClick={selectAll} data-testid="export-columns-select-all">
                  Alle
                </Button>
                <Button type="button" variant="outline" size="sm" onClick={selectNone} data-testid="export-columns-select-none">
                  Keine
                </Button>
              </div>
            </div>

            <div className="max-h-[55vh] overflow-y-auto pr-2 space-y-4">
              {groupKeys.map(gk => {
                const cols = groups[gk] || [];
                const allInGroup = cols.length > 0 && cols.every(c => selected.has(c));
                const someInGroup = cols.some(c => selected.has(c));
                const handleHeaderActivate = () => toggleGroup(gk, cols);
                return (
                  <div key={gk} className="border rounded-lg overflow-hidden">
                    <div
                      role="button"
                      tabIndex={0}
                      onClick={handleHeaderActivate}
                      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleHeaderActivate(); } }}
                      className="w-full flex items-center justify-between gap-3 px-3 py-2 bg-gray-50 hover:bg-gray-100 border-b cursor-pointer select-none"
                      data-testid={`export-columns-group-${gk}`}
                    >
                      <div className="flex items-center gap-2">
                        <Checkbox
                          checked={allInGroup}
                          data-state={allInGroup ? 'checked' : (someInGroup ? 'indeterminate' : 'unchecked')}
                          onCheckedChange={handleHeaderActivate}
                          onClick={(e) => e.stopPropagation()}
                        />
                        <span className="font-medium">{GROUP_LABELS[gk] || gk}</span>
                      </div>
                      <span className="text-xs text-gray-500">{cols.filter(c => selected.has(c)).length} / {cols.length}</span>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 p-3">
                      {cols.map(col => (
                        <Label
                          key={col}
                          className="flex items-center gap-2 cursor-pointer p-1 rounded hover:bg-gray-50 text-sm font-normal"
                          data-testid={`export-column-label-${col}`}
                        >
                          <Checkbox
                            checked={selected.has(col)}
                            onCheckedChange={() => toggleColumn(col)}
                            data-testid={`export-column-checkbox-${col}`}
                          />
                          <span>{col}</span>
                        </Label>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        <AlertDialogFooter>
          <AlertDialogCancel data-testid="export-columns-cancel-btn">Abbrechen</AlertDialogCancel>
          <AlertDialogAction
            onClick={handleConfirm}
            disabled={loading || totalSelected === 0}
            data-testid="export-columns-confirm-btn"
          >
            Exportieren ({totalSelected})
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
};

export default ExportColumnsDialog;
