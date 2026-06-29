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

## Session 13 (Feb 2026) - RBAC Anpassung
**Admin → User (jetzt für alle Benutzer):**
- `DELETE /assignments/{id}` — einzelne Zuordnung auflösen
- `POST /assignments/auto-assign` — automatische Zuordnung
- `DELETE /students/{id}` — einzelnen Schüler löschen
- `POST /students/batch-delete` — Schüler-Batch-Löschen
- `DELETE /ipads/{id}` — iPad löschen

**User → Admin (jetzt nur noch Admin):**
- `PUT /settings/global` — globale Einstellungen ändern

## Session 16 (Feb 2026) - Regression Test + 3 Minor-Fixes
**Test-Bericht `/app/test_reports/iteration_4.json`**: 25 von 26 Tests bestanden, 0 kritische Bugs

**Behoben aus Testergebnissen:**
1. `HTTPBearer()` → `HTTPBearer(auto_error=False)`: Cookie-Auth funktioniert jetzt auch ohne Bearer-Header (z.B. für `/auth/me`)
2. PUT `/ipads/{id}` response inkludiert jetzt `modell` Feld
3. `available-for-contracts` Label: `Modell` → `Typ` (passt zum tatsächlich geprüften Feld `ipad.typ`)
4. Frontend-Warning-Dialog-Text entsprechend angepasst

**Verifizierte Bereiche (per Testing-Agent):**
- ✅ Auth (Admin/User Login, Logout, Cookies)
- ✅ RBAC: Settings nur Admin, alle anderen User-OK
- ✅ Pool-Feature (alle 12 Sub-Features)
- ✅ Modell-Feld (Create/Update/Import/Export)
- ✅ Stat-Cards
- ✅ Vertragserstellung mit ZipCrypto + Passwort
- ✅ One-Step Claim+Assign
- ✅ Race-Condition-Schutz (409 bei parallel claims)
- ✅ Excel-Import mit Pool-Flag + Modell-Spalte
- ✅ User-Delete behält orphaned Pool-iPads

## Session 15 (Feb 2026) - iPad-Modell Feld
- Neues Optional-Feld `modell: Optional[str] = None` im iPad-Modell
- Bestehende iPads zeigen automatisch `null` (keine DB-Migration nötig)
- Backend: POST/PUT `/ipads`, Import (`Modell`-Spalte in Excel), Export (`Modell`-Spalte) berücksichtigt das Feld
- Frontend: Eingabefeld im Create-Dialog (optional), Anzeige + Bearbeiten im Detail-Viewer ("z.B. iPad 9. Gen")
- Empty-String wird automatisch zu `null` konvertiert

## Session 14 (Feb 2026) - iPad-Pool Feature

**Konzept:** Gemeinsamer Geräte-Pool über User-Grenzen hinweg. iPads können im Pool importiert werden und sind dann für alle Nutzer sichtbar/übernehmbar.

**Datenmodell:**
- iPad: neue Felder `is_in_pool: bool` (default false), `pool_history: list` (Audit-Trail), `user_id: Optional[str]` (None = orphan)

**Neue Backend-Endpoints:**
- `POST /ipads/{id}/claim` — Pool-iPad atomar in eigenen Bestand übernehmen
- `POST /ipads/bulk-claim` — mehrere Pool-iPads auf einmal
- `POST /ipads/{id}/release-to-pool` — eigenes iPad freigeben (auto-dissolves assignments)

**Modifizierte Endpoints:**
- `GET /ipads` — liefert eigene + Pool-iPads
- `GET /ipads/available-for-assignment` — eigene + Pool-iPads
- `POST /ipads` — neuer Parameter `is_in_pool`
- `POST /imports/inventory` — neuer Form-Parameter `import_to_pool=true`
- `POST /assignments/manual` — Auto-Claim für Pool-iPads (one-step: claim + assign)
- `DELETE /ipads/{id}` — Admin kann beliebige Pool-iPads löschen
- `DELETE /admin/users/{id}/complete` — Pool-iPads bleiben mit `user_id=null` erhalten

**Frontend:**
- `IPadsManagement.jsx`: Filter "Alle/Meine/Pool", Pool-Badge + violetter Hintergrund, "📥 Übernehmen"/"📤 In Pool"-Buttons, Bulk-Claim, Stat-Card "🌐 Pool verfügbar", Create-Dialog mit Pool-Checkbox
- `Settings.jsx`: Import-Checkbox "🌐 In Pool importieren"
- `UserManagement.jsx`: Toast informiert über orphaned Pool-iPads
- `AssignmentsManagement.jsx`: Pool-Stat-Card hinzugefügt, "Frei & OK" zeigt nur eigene (nicht Pool)
- `IPadDetailViewer.jsx`: Pool-Badge im Header + Übernehmen/Freigeben-Buttons + **"Verwaltet von"-Feld** (zeigt Owner-Username, bei Pool-iPads "(Importeur)"-Hinweis) + **🌐 Pool-Historie Card** (chronologische Aktionsliste mit Username + Datum/Uhrzeit)
- One-step Claim+Assign mit Erfolgs-Toast: "iPad X aus Pool übernommen und Schüler Y zugewiesen"

**Backend ergänzt:** `GET /ipads/{id}/history` liefert nun `owner_username` Feld

**E2E-Tests bestanden (alle Pool-Funktionen):**
- ✅ Excel-Pool-Import (3 iPads, inkl. defekte)
- ✅ Single-Claim + Bulk-Claim
- ✅ Release-to-Pool (mit + ohne aktiver Zuordnung)
- ✅ Auto-Claim+Assign in einem Schritt
- ✅ "Verwaltet von" zeigt korrekten Owner nach jedem Vorgang
- ✅ User-Delete: Pool-iPads bleiben orphaned (counter `pool_ipads_orphaned`)

**Sicherheit:**
- Atomare Claim-Operationen (MongoDB `find_one_and_update` verhindert Race Conditions)
- Globale ITNr-Eindeutigkeitsprüfung beim Pool-Import
- Verträge bleiben beim ursprünglichen User wenn iPad zum Pool zurückgegeben wird

**Hinweis:** iPad-Batch-Löschen läuft im Frontend über mehrere einzelne `DELETE /ipads/{id}`-Calls → durch User-Berechtigung auf einzelnem Endpoint bereits abgedeckt.

Getestet via curl mit echtem User-Token: alle RBAC-Checks bestanden ✅


---

## Session 17 (29.06.2026) — server.py Refactoring ✅ ABGESCHLOSSEN + verifiziert

**Refactor:**
- Monolithisches `server.py` (4331 Zeilen) → schlanker Entry-Point (68 Zeilen, nur App-Setup + `app.include_router`)
- Neue Struktur passend zu Frontend:
  - `core/` (7 Module): `config.py`, `router.py`, `security.py`, `validators.py`, `mongo.py`, `middleware.py`, `__init__.py`
  - `models/` (5 Module): `user.py`, `ipad.py`, `student.py`, `assignment.py`, `contract.py`
  - `routes/` (10 Module): `auth.py`, `admin_users.py`, `ipads.py`, `students.py`, `assignments.py`, `contracts.py`, `settings.py`, `imports_exports.py`, `data_protection.py`, `contract_generation.py`
- Alle 59 API-Endpoints unverändert in der gleichen URL-Struktur
- Single `api_router = APIRouter(prefix="/api")` in `core/router.py`, von allen Route-Modulen geteilt → kein Decorator-Rewriting nötig

**Verifiziert (Testing-Agent + curl):**
- ✅ Testing-Agent: 24/25 PASS (alle Endpoints reagieren, Pool-Lifecycle, Rate-Limit, Vertrag-Export-Spalten, RBAC)
- ✅ AST-Parse + Import: alle 25 Module fehlerfrei
- ✅ Smoke-Test: 12 GET-Endpoints liefern HTTP 200

**Security-Fix (vorher schon offen, jetzt geschlossen):**
- `POST /api/data-protection/cleanup-old-data` war auf "authenticated"-Level statt "admin"
- Fix: `require_admin(current_user)` ergänzt
- Verifiziert: Standard-User → 403, Admin → 200

**Pre-Existing Issues (NICHT durch Refactor, nicht in Scope):**
- `PUT /api/ipads/{id}/status` nutzt Query-Parameter statt JSON-Body (Inkonsistenz, aber Frontend funktioniert)
- Mehrere Lint-Warnings (bare `except`, unused vars) — bestanden bereits in der Monolith-Version


**Feature:** Admin kann ein oder mehrere Pool-iPads explizit einem bestimmten Standard-User zuweisen.

**Backend:**
- `POST /api/admin/ipads/assign-to-user` (Admin-only): nimmt `ipad_ids[]` und `target_user_id`, holt Pool-iPads atomar (`find_one_and_update`) aus dem Pool, setzt `user_id=target_user_id`, ergänzt Pool-Historie-Eintrag (`action="admin_assigned"`, `from_pool=true`, `assigned_by=admin`, `assigned_to=target_username`). Liefert `success_count`, `failed_count`, `target_username`.

**Frontend (`IPadsManagement.jsx`):**
- Single-Row Button "👤 An User" (data-testid `assign-to-user-btn-{id}`) auf jeder Pool-iPad-Zeile (nur Admin sichtbar).
- Bulk-Bar Button "👤 N Pool-iPad(s) an User zuweisen" (data-testid `bulk-assign-to-user-btn`) wenn mehrere Pool-iPads selektiert.
- Dialog mit Live-Search (`user-search-input`), zeigt alle Nicht-Admin User mit Rolle, Klick weist sofort zu, Toast-Bestätigung mit Username.

**Verifiziert (25.06.2026):**
- ✅ Backend curl-Test (bereits Session 10)
- ✅ Frontend Screenshot-Verifikation (Pool-Filter aktiv → 20 Pool-iPads → Single-Dialog & Bulk-Dialog öffnen sich korrekt mit User-Liste)
- ✅ Race-Condition-sicher durch atomares `find_one_and_update`
- ✅ Non-Admin-Zugriff geblockt (HTTP 403)
