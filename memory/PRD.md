# iPad-Verwaltung - Product Requirements Document

## Original Problem Statement
iPad-Verwaltungs-Tool für RBBK (Schule). Verwaltung von iPads, Schülern, Zuordnungen (1:n Beziehung - ein Schüler kann mehrere iPads haben), Verträge und Benutzer.

## Core Features (Implemented)
1. **iPad-Management**: Anlegen, Bearbeiten, Löschen, Status-Verwaltung (OK, Defekt, Gestohlen)
2. **Schüler-Management**: Anlegen, Bearbeiten, Löschen mit vollständigen Kontaktdaten
3. **Zuordnungen (1:n)**: Ein Schüler kann bis zu 3 iPads zugeordnet bekommen
4. **Verträge**: Vertragsgenerierung als PDF/ZIP-Archiv
5. **Datensicherung**: Export aller Daten inkl. Status-Spalte
6. **Daten-Import**: Unified Import mit Status-Unterstützung + Excel-Template Download
7. **Benutzer-Verwaltung**: Admin kann Benutzer anlegen/verwalten
8. **Session-Timeout**: 30 Minuten automatischer Logout
9. **HTTPS/SSL**: Nginx Reverse Proxy mit selbstsignierten Zertifikaten
10. **Docker-Deployment**: Sichere docker-compose.yml (keine Ports nach außen exponiert)

## Tech Stack
- **Frontend**: React, TailwindCSS, ShadCN/UI
- **Backend**: FastAPI, Python
- **Database**: MongoDB
- **Auth**: JWT mit 30-min Session Timeout
- **Deployment**: Docker, docker-compose, Nginx (Reverse Proxy mit SSL)

## What's Been Implemented (Session 5 - Feb 17-18, 2026)

### Sicherheit & Docker
- **Docker-Sicherheit**: docker-compose.yml ohne exponierte Ports (nur Nginx 80/443)
- MongoDB und Backend nur intern erreichbar via `expose` statt `ports`

### Automatische Zuordnung (1:n Fix)
- **Korrigiert**: Nur Schüler OHNE jegliches iPad bekommen automatisch eins
- Schüler mit 1, 2 oder 3 iPads werden NICHT berücksichtigt
- Nur iPads mit Status "ok" werden automatisch zugewiesen

### Import/Export Verbesserungen
- **Status-Spalte**: Im Export und Import hinzugefügt (ok, defekt, gestohlen)
- **Excel-Template**: Download-Endpoint `/api/imports/template` mit Beispieldaten
- **1:n Hinweis**: Schüler mit mehreren iPads erscheinen mehrfach (eine Zeile pro iPad)

### Defekte/Gestohlene iPads
- **Bleiben zugeordnet**: Status-Änderung löst Zuordnung NICHT auf
- **Werden nicht automatisch zugewiesen**: Nur Status "ok" bei auto-assign

### Frontend-Refactoring
- App.js von 5174 auf 276 Zeilen reduziert (-95%)
- 13 modulare Komponenten-Dateien erstellt

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

## Credentials
- Admin: `admin` / `admin123`

## Known Issues
- `libmagic` muss im Pod installiert sein (`sudo apt-get install -y libmagic1`)
