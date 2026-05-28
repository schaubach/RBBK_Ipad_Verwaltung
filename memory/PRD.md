# iPad-Verwaltung - Product Requirements Document

## Original Problem Statement
iPad-Verwaltungs-Tool für RBBK (Schule). Verwaltung von iPads, Schülern, Zuordnungen (1:n Beziehung - ein Schüler kann mehrere iPads haben), Verträge und Benutzer.

## Core Features (Implemented)
1. **iPad-Management**: Anlegen, Bearbeiten, Löschen, Status-Verwaltung (OK, Defekt, Gestohlen)
2. **Schüler-Management**: Anlegen, Bearbeiten, Löschen mit vollständigen Kontaktdaten
3. **Zuordnungen (1:n)**: Ein Schüler kann bis zu 3 iPads zugeordnet bekommen
4. **Verträge**: Vertragsgenerierung als PDF/ZIP-Archiv, Batch-Upload, Batch-Delete, Zuordnung ändern
5. **Datensicherung**: Export aller Daten inkl. Status-Spalte
6. **Daten-Import**: Unified Import mit Status-Unterstützung + Excel-Template Download
7. **Benutzer-Verwaltung**: Admin kann Benutzer anlegen/verwalten
8. **Session-Timeout**: 30 Minuten automatischer Logout
9. **HTTPS/SSL**: Nginx Reverse Proxy mit selbstsignierten Zertifikaten
10. **Docker-Deployment**: Sichere docker-compose.yml (keine Ports nach außen exponiert)

## Security Features (NEW - Session 9)
1. **Rate Limiting**: 
   - Login: 5/Minute (Brute-Force-Schutz)
   - API: 60/Minute (Mass Exfiltration Schutz)
   - Exports: 10/Minute (Stricter für Daten-Export)
   - Nginx: 30r/s mit Burst
2. **HttpOnly Cookies**: JWT Token wird als HttpOnly Cookie gesetzt (JavaScript kann nicht zugreifen)
3. **RBAC (Role-Based Access Control)**: Admin-Only Endpoints geschützt
4. **CSP Hardening**: 'unsafe-eval' entfernt aus Content-Security-Policy

## Tech Stack
- **Frontend**: React, TailwindCSS, ShadCN/UI
- **Backend**: FastAPI, Python, Slowapi (Rate Limiting)
- **Database**: MongoDB
- **Auth**: JWT mit HttpOnly Cookie + Bearer Token (fallback), 30-min Session Timeout
- **Deployment**: Docker, docker-compose, Nginx (Reverse Proxy mit SSL + Rate Limiting)

## What's Been Implemented

### Session 9 - Mai 2025: Sicherheitsverbesserungen
- **Rate Limiting (Backend)**: Slowapi-basiertes Rate Limiting für alle kritischen Endpoints
- **Rate Limiting (Nginx)**: Zusätzliche Nginx-basierte Rate Limiting Zones
- **HttpOnly Cookies**: Login setzt Token als HttpOnly, Secure, SameSite=Strict Cookie
- **RBAC Audit**: Admin-Only Endpoints mit `require_admin()` geschützt
- **CSP Verbesserung**: 'unsafe-eval' aus CSP entfernt
- **Neue Endpoints**: `/api/auth/logout` (Cookie löschen), `/api/auth/me` (Auth-Status prüfen)
- **Zuordnungen-Tab**: Vertrag-Spalte sortierbar, gefilterte Buttons unter ungefilterten
- **Upload-Button**: Auch bei Zuordnungen ohne Vertrag sichtbar

### Session 8 - März 2025: Bearbeitungsfunktion in Detailansichten
- **iPad-Bearbeitung**: Alle Felder (ITNr, SNr, Typ, Pencil, Karton, Status, Anschaffungsjahr, Ausleihdatum) in Detailansicht editierbar
- **Schüler-Bearbeitung**: Alle Felder inkl. Erziehungsberechtigte 1 & 2 in Detailansicht editierbar
- **Bearbeitungsmodus**: "Bearbeiten"-Button öffnet editierbare Felder, "Speichern"/"Abbrechen" Buttons
- **Daten-Propagation**: Bei Namensänderung werden auch student_name in Assignments/Contracts aktualisiert
- **Neuer Endpoint**: `PUT /api/ipads/{ipad_id}` für vollständige iPad-Bearbeitung
- **Neuer Endpoint**: `PUT /api/students/{student_id}` für vollständige Schüler-Bearbeitung

### Session 7 - März 2025: Verträge-Tab Verbesserungen
- **Sortierung "Zuordnung"-Spalte**: Die Zuordnung-Spalte in der Verträge-Tabelle ist jetzt sortierbar
- **Zuordnung ändern Feature**: Bereits zugewiesene Verträge können einer neuen Zuordnung zugewiesen werden
- **Batch-Delete mit Checkboxen**: Mehrfachauswahl von Verträgen mit Batch-Löschung über neuen API-Endpoint
- **Bug-Fix: Veraltete Vertragsstatus**: Beim Löschen eines Vertrags wird jetzt `contract_id` im Assignment auf `null` gesetzt
- **Neuer Endpoint**: `POST /api/contracts/batch-delete` für effiziente Batch-Löschung
- **Neuer Endpoint**: `POST /api/contracts/{id}/unassign` für Vertrag von Zuordnung trennen

### Session 6 - Dezember 2025: Dokumentation & Cleanup
- **Dokumentation konsolidiert**: Alle Anleitungen in `ENTWICKLERDOKUMENTATION.md` zusammengeführt
- **Skript-Referenz**: Nutzung von `install.sh`, `uninstall.sh`, `deploy-smart.sh` dokumentiert
- **SSL/HTTPS-Anleitung**: Self-Signed und Let's Encrypt Setup dokumentiert
- **DEPLOYMENT.md entfernt**: Alle Inhalte in Entwicklerdokumentation übernommen
- **Docker-Compose bereinigt**: Nur noch gehärtete Version in `config/docker-compose.yml`
- **Ungehärtete Version gelöscht**: `/app/docker-compose.yml` entfernt
- **.env-Struktur angepasst**: `config/.env` für JWT_SECRET

### Session 5 - Sicherheit & Refactoring
- **Docker-Sicherheit**: docker-compose.yml ohne exponierte Ports (nur Nginx 80/443)
- MongoDB und Backend nur intern erreichbar via `expose` statt `ports`
- **Automatische Zuordnung (1:n Fix)**: Nur Schüler OHNE jegliches iPad bekommen eins
- **Import/Export**: Status-Spalte hinzugefügt, Excel-Template Download
- **Frontend-Refactoring**: App.js von 5174 auf 276 Zeilen reduziert (-95%)

## Projektstruktur

```
/app/frontend/src/
├── App.js                 (276 Zeilen)
├── api/index.js           (73 Zeilen)
├── components/
│   ├── auth/Login.jsx
│   ├── ipads/IPadDetailViewer.jsx, IPadsManagement.jsx
│   ├── students/StudentDetailViewer.jsx, StudentsManagement.jsx
│   ├── assignments/AssignmentsManagement.jsx
│   ├── contracts/ContractsManagement.jsx
│   ├── settings/Settings.jsx
│   ├── shared/ContractViewer.jsx, SessionTimer.jsx
│   └── users/UserManagement.jsx
```

## API Endpoints
- `GET /api/imports/template` - Excel-Vorlage herunterladen
- `POST /api/imports/inventory` - Unified data import (mit Status)
- `GET /api/exports/inventory` - Data backup export (mit Status)
- `POST /api/assignments/auto-assign` - Nur Schüler ohne iPad
- `POST /api/contracts/batch-delete` - Batch-Löschung von Verträgen (body: {contract_ids: []})
- `POST /api/contracts/{id}/unassign` - Vertrag von Zuordnung trennen
- `DELETE /api/contracts/{id}` - Einzelner Vertrag löschen (setzt Assignment.contract_id auf null)
- `PUT /api/ipads/{ipad_id}` - iPad vollständig bearbeiten (alle Felder)
- `PUT /api/students/{student_id}` - Schüler vollständig bearbeiten (alle Felder inkl. Erziehungsberechtigte)

## Credentials
- Admin: `admin` / `admin123`

## Known Issues
- `libmagic` muss im Pod installiert sein (`sudo apt-get install -y libmagic1`)

## Session 10 (Feb 2026) - Checkbox-UI Fix
- Doppelten "X Zuordnung(en) auflösen"-Button aus AssignmentsManagement.jsx entfernt
- Bug behoben: `setDissolveSelectedDialogOpen` (nicht existent) durch `setBatchDeleteDialogOpen` ersetzt
- "Ausgewählte exportieren" + "Ausgewählte lösen"-Buttons erscheinen jetzt korrekt bei Checkbox-Auswahl
- Verifiziert via Screenshot

## Session 11 (Feb 2026) - UX-Verbesserungen Verträge
- "Alle Zuordnungen exportieren" zeigt jetzt Anzahl: "Alle Zuordnungen exportieren (10)"
- Vertragserstellung mit Filter zeigt nun eine Vorschau-Tabelle mit Checkboxen
- Standardmäßig sind alle gefilterten Einträge vorausgewählt → User kann einzelne abwählen
- Button-Text: "Verträge erstellen (X von Y)"
- Backend `/assignments/available-for-contracts` liefert nun zusätzlich `sus_vorn`, `sus_nachn`, `sus_kl` für Client-side Filterung
- ⚠️ Warn-Icon in Vorschau-Tabelle bei fehlenden Pflichtfeldern (Modell/SNr/Geburtsdatum) mit Tooltip + amber Zeilen-Highlight
- Bestätigungs-Dialog beim Erstellen: wenn ausgewählte Verträge unvollständig sind, wird Anzahl der Problem-Verträge angezeigt + Bestätigung "Trotzdem erstellen" notwendig

## Session 12 (Feb 2026) - Live-Bug-Fixes
- **Bug 1 (White Screen):** Browser cached alte `index.html`. Fix: Nginx-Config in `default.conf` ergänzt — `index.html` und `config.js` haben jetzt `Cache-Control: no-store`, statische JS/CSS-Hashes bleiben 1 Jahr gecached
- **Bug 2 (500 bei Vertragserstellung):** pyzipper 0.3.6 unterstützt kein ZipCrypto-Schreiben. Migration auf **pyminizip** (echtes Windows-kompatibles ZipCrypto). Verifiziert: ZIP wird verschlüsselt, falsches Passwort wird abgelehnt, korrektes Passwort entpackt PDF
- requirements.txt: `pyminizip==0.2.6` hinzugefügt
- Hinweis für Live-Deployment: Backend-Container muss neugebaut werden (deploy-smart.sh Option 4 mit `--no-cache backend`)
