// Anzahl für Listenüberschriften: ungefiltert "340", gefiltert "12 von 340".
export function anzahl(sichtbar, gesamt) {
  return sichtbar === gesamt ? `${gesamt}` : `${sichtbar} von ${gesamt}`;
}
