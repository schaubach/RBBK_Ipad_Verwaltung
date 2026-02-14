# iPad-Verwaltungssystem - Product Requirements Document

## Original Problem Statement
Setup und Weiterentwicklung eines iPad-Verwaltungssystems für Schulen. Das System ermöglicht die Verwaltung von iPads, Schülern und deren Zuordnungen mit Excel Import/Export Funktionalität.

## User Credentials
- **Admin Login**: username: `admin`, password: `admin123`

## Core Requirements

### 1. iPad Management
- ✅ Import/Export von iPad-Listen via Excel
- ✅ Manuelle Erstellung von iPads
- ✅ Status-Tracking (verfügbar, zugewiesen, defekt, gestohlen)

### 2. Student Management
- ✅ Import/Export von Schülerlisten via Excel
- ✅ Manuelle Erstellung von Schülern
- ✅ Sortierbare Tabellen

### 3. Assignments (1:n Relationship)
- ✅ Ein Schüler kann bis zu 3 iPads haben (MAX_IPADS_PER_STUDENT konfigurierbar)
- ✅ Ein iPad kann nur einem Schüler zugewiesen sein
- ✅ Excel Import: Schüler die auf mehreren Zeilen erscheinen werden zusammengeführt
- ✅ Excel Export: Pro Zuordnung eine Zeile (Schülerdaten dupliziert)
- ✅ UI zeigt iPad-Anzahl pro Schüler und "Limit erreicht" wenn Maximum erreicht

### 4. Session Management
- ✅ JWT-basierte Authentifizierung
- ✅ Automatischer Logout bei Session-Ablauf (401)
- ✅ Rate Limiting (5 Login-Versuche/Minute)

### 5. Admin Features
- ✅ Benutzerverwaltung (erstellen, deaktivieren, Passwort zurücksetzen)
- ✅ Globale Einstellungen (Standard iPad-Typ, Pencil-Ausstattung)
- ✅ Datenschutz-Cleanup (alte Daten löschen)

## Technical Architecture

### Backend (FastAPI)
- `/app/backend/server.py` - Hauptanwendung mit allen Endpoints
- MongoDB für Datenspeicherung
- Key Endpoints:
  - `POST /api/imports/inventory` - Excel Import mit 1:n Unterstützung
  - `GET /api/exports/inventory` - Excel Export
  - `GET /api/students` - Schülerliste mit assignment_count
  - `POST /api/assignments` - Manuelle Zuordnung

### Frontend (React)
- `/app/frontend/src/App.js` - Monolithische Single-File Anwendung
- ShadCN/UI Komponenten
- Tabs: Schüler, iPads, Zuordnungen, Verträge, Einstellungen, Benutzer

## What's Been Implemented

### 2025-02-14: 1:n Relationship Feature (COMPLETED)
- ✅ Backend: `import_inventory()` updated to merge students appearing on multiple rows
- ✅ Backend: iPad limit enforcement (MAX_IPADS_PER_STUDENT=3)
- ✅ Backend: Export correctly outputs one row per assignment
- ✅ Frontend: UI shows iPad count per student
- ✅ Frontend: "Limit erreicht" button displayed when student at maximum
- ✅ Testing: 100% pass rate (backend and frontend)

### Previous Session (COMPLETED)
- ✅ All initial bugs fixed (dropdowns, sorting, delete dialogs, batch deletion)
- ✅ Manual creation of students/iPads
- ✅ Automatic session logout on expiry
- ✅ Code cleanup (32 unused UI components removed)
- ✅ Path aliases replaced with relative imports

## Configuration

### Environment Variables
- `MAX_IPADS_PER_STUDENT` - Maximum iPads per student (default: 3)
- `ACCESS_TOKEN_EXPIRE_MINUTES` - Session timeout (default: 30)
- `MONGO_URL` - MongoDB connection string
- `SECRET_KEY` - JWT secret (auto-generated if not provided)

## Known Issues
- `libmagic` Python dependency may need reinstallation after environment restarts
  - Fix: `sudo apt-get install -y libmagic1`

## Future Considerations (Backlog)
- Refactor `App.js` into smaller components (currently 4000+ lines)
- Add contract management features
- Implement reporting/analytics dashboard
