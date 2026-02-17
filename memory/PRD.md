# iPad-Verwaltung - Product Requirements Document

## Original Problem Statement
iPad-Verwaltungs-Tool für RBBK (Schule). Verwaltung von iPads, Schülern, Zuordnungen (1:n Beziehung - ein Schüler kann mehrere iPads haben), Verträge und Benutzer.

## Core Features (Implemented)
1. **iPad-Management**: Anlegen, Bearbeiten, Löschen, Status-Verwaltung (OK, Defekt, Gestohlen)
2. **Schüler-Management**: Anlegen, Bearbeiten, Löschen mit vollständigen Kontaktdaten
3. **Zuordnungen (1:n)**: Ein Schüler kann bis zu 3 iPads zugeordnet bekommen
4. **Verträge**: Vertragsgenerierung als PDF/ZIP-Archiv
5. **Datensicherung**: Export aller Daten (Schüler, iPads, Zuordnungen) als Excel
6. **Daten-Import**: Unified Import für Schüler, iPads oder beides (im Einstellungen-Tab)
7. **Benutzer-Verwaltung**: Admin kann Benutzer anlegen/verwalten
8. **Session-Timeout**: 30 Minuten automatischer Logout
9. **HTTPS/SSL**: Nginx Reverse Proxy mit selbstsignierten Zertifikaten
10. **Docker-Deployment**: docker-compose.yml für Produktion

## Tech Stack
- **Frontend**: React, TailwindCSS, ShadCN/UI
- **Backend**: FastAPI, Python
- **Database**: MongoDB
- **Auth**: JWT mit 30-min Session Timeout
- **Deployment**: Docker, docker-compose, Nginx (Reverse Proxy mit SSL)

## What's Been Implemented (Latest: Feb 2026)

### Session 1-4 (Previous)
- Complete CRUD for iPads, Students, Assignments
- 1:n relationship (student can have multiple iPads)
- Contract generation
- Data backup/restore
- Security hardening (HTTPS, CSP, session timeout)
- Docker Compose setup

### Session 5 (Current - Feb 17, 2026)
- **Import-Konsolidierung**: 3 redundante Import-Funktionen zu einer zusammengeführt
  - Entfernt: "Schüler importieren" aus Schüler-Tab
  - Entfernt: "iPads importieren" aus iPad-Tab
  - Neu: "Daten-Import" im Einstellungen-Tab (kann Schüler, iPads oder beides importieren)
- Ungenutzte States und Handler entfernt (uploading, handleUpload)

## Prioritized Backlog

### P2 - Nice to Have
- **App.js Refactoring**: Die Datei ist über 3800 Zeilen und sollte in kleinere Komponenten aufgeteilt werden
  - IPadsManagement.jsx
  - StudentsManagement.jsx
  - AssignmentsManagement.jsx
  - Settings.jsx
  - ContractsManagement.jsx

## API Endpoints
- `POST /api/imports/inventory` - Unified data import
- `GET /api/exports/inventory` - Data backup export
- `GET/POST/PUT/DELETE /api/students` - Student CRUD
- `GET/POST/PUT/DELETE /api/ipads` - iPad CRUD
- `GET/POST/DELETE /api/assignments` - Assignment management
- `POST /api/auth/login` - Authentication

## DB Schema
- **students**: {_id, sus_vorn, sus_nachn, sus_kl, assigned_ipad_ids: List[str], ...}
- **ipads**: {_id, itnr, snr, status, current_assignment_id, ...}
- **assignments**: {_id, student_id, ipad_id, is_active, ...}
- **users**: {_id, username, password_hash, role, ...}

## Credentials
- Admin: `admin` / `admin123`

## Known Issues
- None currently

## Files of Reference
- `/app/frontend/src/App.js` - Main frontend (monolithic, needs refactoring)
- `/app/backend/server.py` - FastAPI backend
- `/app/docker-compose.yml` - Production deployment
- `/app/nginx/` - Nginx configuration with SSL
