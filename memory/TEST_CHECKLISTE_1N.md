# Test-Checkliste: 1:n iPad-Schüler Beziehung

## Login & Grundlagen
- [ ] Login mit `admin` / `admin123` funktioniert
- [ ] Session-Timer wird angezeigt (oben rechts)
- [ ] Automatischer Logout nach Session-Ablauf

---

## 1. EXCEL IMPORT (Bestandsliste)

### 1.1 Standard-Import (1:1 Format - Abwärtskompatibilität)
- [ ] Import einer Excel-Datei mit je einem Schüler pro Zeile
- [ ] Neue Schüler werden korrekt angelegt
- [ ] Neue iPads werden korrekt angelegt
- [ ] Zuordnungen werden korrekt erstellt
- [ ] Import-Zusammenfassung zeigt korrekte Zahlen

### 1.2 Import mit 1:n Format (Schüler auf mehreren Zeilen)
- [ ] Schüler der auf 2 Zeilen erscheint (mit 2 verschiedenen iPads) → erhält beide iPads
- [ ] Schüler der auf 3 Zeilen erscheint → erhält alle 3 iPads
- [ ] Schüler wird nur einmal in der Datenbank angelegt (nicht dupliziert)
- [ ] Schülerdaten (Klasse, Adresse, etc.) werden von der ersten Zeile übernommen

### 1.3 Limit-Durchsetzung beim Import
- [ ] Schüler der auf 4+ Zeilen erscheint → nur 3 iPads werden zugewiesen
- [ ] Fehlermeldung erscheint für übersprungene Zuordnungen
- [ ] Das 4. iPad wird trotzdem erstellt (aber nicht zugewiesen)
- [ ] Bestehender Schüler mit 2 iPads + Import mit 2 weiteren → nur 1 wird zugewiesen

### 1.4 Edge Cases beim Import
- [ ] Leere Schülerfelder → iPad wird ohne Zuordnung importiert
- [ ] Bereits existierendes iPad → wird übersprungen (nicht dupliziert)
- [ ] Bereits existierender Schüler → wird wiederverwendet
- [ ] iPad bereits zugewiesen an anderen Schüler → wird übersprungen
- [ ] Zeile ohne ITNr → wird komplett übersprungen
- [ ] NaN/leere Werte in optionalen Feldern → keine Fehler

### 1.5 Fehlerbehandlung Import
- [ ] Ungültiges Dateiformat (.csv, .pdf) → Fehlermeldung
- [ ] Fehlende Pflichtspalte (ITNr) → Fehlermeldung
- [ ] Beschädigte Excel-Datei → Fehlermeldung
- [ ] Leere Excel-Datei → Import ohne Fehler (0 verarbeitet)

---

## 2. EXCEL EXPORT (Bestandsliste)

### 2.1 Export-Format
- [ ] Export erstellt gültige .xlsx Datei
- [ ] Jede Zuordnung ist eine separate Zeile
- [ ] Schüler mit 2 iPads → erscheint auf 2 Zeilen
- [ ] Schüler mit 3 iPads → erscheint auf 3 Zeilen
- [ ] Schülerdaten sind identisch auf allen Zeilen des gleichen Schülers

### 2.2 Export-Inhalt
- [ ] Alle Spalten vorhanden (SuSVorn, SuSNachn, SuSKl, ITNr, SNr, etc.)
- [ ] iPads ohne Zuordnung → erscheinen mit leeren Schülerfeldern
- [ ] Datumsformate korrekt (TT.MM.JJJJ)
- [ ] Keine MongoDB-IDs oder technische Felder im Export

### 2.3 Re-Import von Export
- [ ] Exportierte Datei kann ohne Fehler reimportiert werden
- [ ] Bestehende Daten werden nicht dupliziert
- [ ] Zuordnungen bleiben erhalten

---

## 3. MANUELLE ZUORDNUNG (UI)

### 3.1 Zuordnung erstellen
- [ ] "iPad zuordnen" Button bei Schüler mit <3 iPads sichtbar
- [ ] Klick öffnet Auswahl-Dialog für verfügbare iPads
- [ ] Nur nicht-zugewiesene iPads werden angezeigt
- [ ] Zuordnung wird sofort in der Liste angezeigt
- [ ] iPad-Zähler beim Schüler wird aktualisiert

### 3.2 Limit-Anzeige in UI
- [ ] Schüler mit 3 iPads zeigt "Limit erreicht" statt "iPad zuordnen"
- [ ] "Limit erreicht" Button ist deaktiviert/ausgegraut
- [ ] Badge zeigt "3 iPad(s)" an
- [ ] Tooltip erklärt das Limit (falls vorhanden)

### 3.3 Zuordnung auflösen
- [ ] Zuordnung kann einzeln gelöscht werden
- [ ] Bestätigungsdialog erscheint vor dem Löschen
- [ ] iPad wird wieder als "verfügbar" angezeigt
- [ ] Schüler iPad-Zähler wird reduziert
- [ ] "iPad zuordnen" Button erscheint wieder (wenn unter Limit)

---

## 4. SCHÜLER-VERWALTUNG

### 4.1 Schüler-Anzeige
- [ ] Tabelle zeigt alle Schüler
- [ ] "iPad-Status" Spalte zeigt Anzahl der iPads
- [ ] Sortierung nach Name funktioniert
- [ ] Sortierung nach Klasse funktioniert
- [ ] Sortierung nach iPad-Anzahl funktioniert (falls implementiert)
- [ ] Filter nach Vorname funktioniert
- [ ] Filter nach Nachname funktioniert
- [ ] Filter nach Klasse funktioniert

### 4.2 Schüler erstellen
- [ ] "Neuen Schüler anlegen" Button funktioniert
- [ ] Pflichtfelder werden validiert (Vorname, Nachname)
- [ ] Duplikat-Prüfung (gleicher Name) → Fehlermeldung
- [ ] Neuer Schüler erscheint sofort in der Liste
- [ ] Neuer Schüler hat 0 iPads

### 4.3 Schüler löschen
- [ ] Einzelner Schüler kann gelöscht werden
- [ ] Bestätigungsdialog erscheint
- [ ] Alle Zuordnungen werden aufgelöst
- [ ] Zugehörige iPads werden freigegeben
- [ ] Batch-Löschung funktioniert (mehrere auswählen)

### 4.4 Schüler-Details
- [ ] Klick auf Auge-Icon zeigt Details
- [ ] Liste der zugewiesenen iPads sichtbar
- [ ] Zuordnungshistorie sichtbar (falls implementiert)

---

## 5. iPAD-VERWALTUNG

### 5.1 iPad-Anzeige
- [ ] Tabelle zeigt alle iPads
- [ ] Status-Spalte zeigt "verfügbar" oder "zugewiesen"
- [ ] Zugewiesener Schüler wird angezeigt
- [ ] Sortierung nach ITNr funktioniert
- [ ] Sortierung nach Status funktioniert

### 5.2 iPad erstellen
- [ ] "Neues iPad anlegen" Button funktioniert
- [ ] Pflichtfelder werden validiert (ITNr, SNr)
- [ ] Duplikat-Prüfung (gleiche ITNr) → Fehlermeldung
- [ ] Neues iPad erscheint sofort in der Liste
- [ ] Neues iPad hat Status "verfügbar"

### 5.3 iPad löschen
- [ ] Nicht-zugewiesenes iPad kann gelöscht werden
- [ ] Zugewiesenes iPad kann NICHT gelöscht werden → Fehlermeldung
- [ ] Bestätigungsdialog erscheint

---

## 6. ZUORDNUNGEN-TAB

### 6.1 Zuordnungen-Anzeige
- [ ] Alle aktiven Zuordnungen werden angezeigt
- [ ] Schülername, Klasse, iPad-ITNr sichtbar
- [ ] Zuordnungsdatum wird angezeigt
- [ ] Ein Schüler mit 3 iPads → 3 Zeilen in der Tabelle

### 6.2 Bestandsliste-Import (im Zuordnungen-Tab)
- [ ] Import-Bereich ist sichtbar
- [ ] Datei-Upload funktioniert
- [ ] Fortschrittsanzeige während Import
- [ ] Erfolgs-/Fehlermeldung nach Import

### 6.3 Export
- [ ] "Alle Zuordnungen exportieren" Button funktioniert
- [ ] Gefilterte Zuordnungen können exportiert werden
- [ ] Datei wird heruntergeladen

---

## 7. EINSTELLUNGEN

### 7.1 Globale Einstellungen
- [ ] iPad-Typ (Standard) kann geändert werden
- [ ] Pencil-Ausstattung (Standard) kann geändert werden
- [ ] Änderungen werden gespeichert

### 7.2 Bestandsliste Export
- [ ] "Bestandsliste exportieren" Button funktioniert
- [ ] Vollständige Datei wird heruntergeladen

---

## 8. SPEZIELLE TEST-SZENARIEN

### 8.1 Datenmigration (Export alt → Import neu)
- [ ] System ohne Daten starten
- [ ] Alte Bestandsliste (1:1 Format) importieren
- [ ] Alle Daten korrekt angelegt
- [ ] Exportieren
- [ ] Daten löschen
- [ ] Re-Import → identischer Zustand

### 8.2 Grenzwerte
- [ ] Import mit 100+ Zeilen → funktioniert performant
- [ ] Import mit 1000+ Zeilen → funktioniert (evtl. langsamer)
- [ ] Schüler mit exakt 3 iPads → Limit erreicht
- [ ] Versuch, 4. iPad zuzuweisen → wird korrekt abgelehnt

### 8.3 Parallele Aktionen
- [ ] Zwei Browser-Tabs gleichzeitig offen
- [ ] Import in Tab 1, Refresh in Tab 2 → Daten sichtbar
- [ ] Manuelle Zuordnung während Import läuft

### 8.4 Fehlerzustände
- [ ] Backend nicht erreichbar → Fehlermeldung in UI
- [ ] Token abgelaufen während Aktion → Automatischer Logout
- [ ] Netzwerk-Timeout → Sinnvolle Fehlermeldung

---

## 9. TEST-DATEN REFERENZ

### Aktuelle Test-Schüler im System:
| Name | Klasse | iPads | Status |
|------|--------|-------|--------|
| Max Mustermann | 10a | 2 | Unter Limit |
| Anna Schmidt | 10b | 1 | Unter Limit |
| Peter Müller | 11a | 3 | **Limit erreicht** |
| Lisa Weber | 12a | 1 | Unter Limit |

### Test-Excel für 1:n Import:
```
SuSVorn,SuSNachn,SuSKl,ITNr,SNr
Max,Mustermann,10a,IT-001,SN-001
Max,Mustermann,10a,IT-002,SN-002  ← gleicher Schüler, 2. iPad
Anna,Schmidt,10b,IT-003,SN-003
```

---

## Notizen
- MAX_IPADS_PER_STUDENT = 3 (konfiguriert in backend/.env)
- Preview URL: https://student-ipad-mgmt.preview.emergentagent.com
- Bei libmagic Fehler: `sudo apt-get install -y libmagic1`
