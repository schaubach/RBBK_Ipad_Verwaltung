import { useEffect, useState } from 'react';
import api from '../api';

/**
 * Lädt die Bildungsgänge und sagt, ob die angemeldete Person überhaupt wählen muss.
 *
 * Die Regel spiegelt resolve_bildungsgang im Backend: Wer für genau einen Bildungsgang
 * zuständig ist, soll kein Auswahlfeld sehen - das Backend ergänzt den Wert von selbst.
 * Erst ab zwei (oder bei einem Admin ohne eigene Zuständigkeit) ist eine Wahl nötig.
 *
 * `meine` enthält die Bildungsgänge, für die man selbst zuständig ist; `alle` zusätzlich
 * die übrigen, die ein Admin ebenfalls ansprechen darf.
 */
export function useBildungsgaenge(username) {
  const [alle, setAlle] = useState([]);
  const [meine, setMeine] = useState([]);
  const [laedt, setLaedt] = useState(true);

  useEffect(() => {
    let abgebrochen = false;
    (async () => {
      try {
        const { data } = await api.get('/bildungsgaenge');
        if (abgebrochen) return;
        setAlle(data);
        setMeine(
          username
            ? data.filter((b) => (b.zustaendige || []).some((z) => z.username === username && !z.bis))
            : []
        );
      } catch (error) {
        console.error('Failed to load Bildungsgänge:', error);
      } finally {
        if (!abgebrochen) setLaedt(false);
      }
    })();
    return () => {
      abgebrochen = true;
    };
  }, [username]);

  // Genau eine eigene Zuständigkeit: das Backend ergänzt sie, die Oberfläche fragt nicht.
  const auswahlNoetig = !laedt && meine.length !== 1;
  const vorauswahl = meine.length === 1 ? meine[0].id : '';

  return { alle, meine, laedt, auswahlNoetig, vorauswahl };
}
