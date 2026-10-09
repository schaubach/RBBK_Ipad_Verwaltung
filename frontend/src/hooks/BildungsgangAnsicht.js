import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { useBildungsgaenge } from './useBildungsgaenge';

/**
 * Die gewählte Ansicht gilt für die ganze Anwendung: Schüler, iPads und Verträge
 * desselben Bildungsgangs gehören zusammen, drei getrennte Umschalter könnten
 * widersprüchliche Zustände erzeugen ("MEDA-Schüler, aber alle Geräte").
 *
 * Reine Ansichtssache - die Rechte liegen im Backend und bleiben unberührt. Ein leerer
 * Wert heißt "alles, was ich sehen darf".
 */
const SPEICHER_SCHLUESSEL = 'ansichtBildungsgang';

const AnsichtContext = createContext({
  ansichtBildungsgang: '',
  setAnsichtBildungsgang: () => {},
  auswaehlbar: [],
  laedt: true,
  isAdmin: false,
});

export function BildungsgangAnsichtProvider({ username, isAdmin = false, children }) {
  const { alle, meine, laedt } = useBildungsgaenge(username);

  // Übersteht ein Neuladen der Seite, nicht aber eine neue Anmeldung: handleLogout
  // räumt den Schlüssel weg. Wer sich anmeldet, sieht damit immer zuerst alles -
  // der Zustand, in dem nichts fehlen kann.
  const [ansichtBildungsgang, setAnsichtBildungsgang] = useState(() => {
    try {
      return localStorage.getItem(SPEICHER_SCHLUESSEL) || '';
    } catch {
      return '';
    }
  });

  // Ein Admin darf jeden Bildungsgang ansehen, eine Lehrkraft nur die eigenen. Für
  // fremde käme ohnehin nichts zurück - sie stünden nur als leere Auswahl im Weg.
  const auswaehlbar = useMemo(() => (isAdmin ? alle : meine), [isAdmin, alle, meine]);

  useEffect(() => {
    try {
      if (ansichtBildungsgang) localStorage.setItem(SPEICHER_SCHLUESSEL, ansichtBildungsgang);
      else localStorage.removeItem(SPEICHER_SCHLUESSEL);
    } catch {
      // Privater Modus o.ä.: die Ansicht gilt dann nur bis zum Neuladen.
    }
  }, [ansichtBildungsgang]);

  // Eine Zuständigkeit kann enden, während die alte Auswahl noch gespeichert ist. Ohne
  // diesen Rückfall bliebe alles leer, ohne dass jemand den Grund sähe.
  useEffect(() => {
    if (laedt || !ansichtBildungsgang) return;
    if (!auswaehlbar.some((b) => b.id === ansichtBildungsgang)) setAnsichtBildungsgang('');
  }, [laedt, auswaehlbar, ansichtBildungsgang]);

  const wert = useMemo(
    () => ({ ansichtBildungsgang, setAnsichtBildungsgang, auswaehlbar, laedt, isAdmin }),
    [ansichtBildungsgang, auswaehlbar, laedt, isAdmin]
  );

  return <AnsichtContext.Provider value={wert}>{children}</AnsichtContext.Provider>;
}

export function useBildungsgangAnsicht() {
  return useContext(AnsichtContext);
}

export { SPEICHER_SCHLUESSEL as ANSICHT_SPEICHER_SCHLUESSEL };
