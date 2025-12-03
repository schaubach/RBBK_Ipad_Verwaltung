# 📚 Entwicklerdokumentation - iPad Management System

> **Umfassende Dokumentation für Entwickler, Administratoren und neue Teammitglieder**

---

## 📋 Inhaltsverzeichnis

1. [Einstiegspunkt und Überblick](#1-einstiegspunkt-und-überblick)
2. [Installations- und Entwicklungsumgebung](#2-installations--und-entwicklungsumgebung)
3. [Projektarchitektur und Struktur](#3-projektarchitektur-und-struktur)
4. [Code-Basis und APIs](#4-code-basis-und-apis)
5. [Deployment](#5-deployment)
6. [Troubleshooting](#6-troubleshooting)
7. [Best Practices](#7-best-practices)

---

# 1. Einstiegspunkt und Überblick

## 🎯 Zusammenfassung des Projekts

### Projektziel
Das **iPad Management System** ist eine webbasierte Anwendung zur Verwaltung von iPads, Schülern und deren Zuordnungen in Bildungseinrichtungen. Die Software löst folgende Probleme:

- **Inventarverwaltung:** Zentrale Verwaltung aller iPads mit Status-Tracking
- **Schülerverwaltung:** Verwaltung von Schülerdaten und deren iPad-Zuordnungen  
- **Zuordnungsmanagement:** Manuelle und automatische iPad-Zuordnungen
- **Vertragsverwaltung:** PDF-Generierung und Upload von Nutzungsverträgen
- **Datenimport/-export:** Excel-basierter Datenimport und -export
- **Benutzerverwaltung:** Rollenbasierte Zugriffskontrolle (Admin/User)

### Technologie-Stack

#### Frontend
- **React** 18.2.0 - Benutzeroberfläche
- **Shadcn/ui** - UI-Komponentenbibliothek
- **Tailwind CSS** - Styling
- **Axios** - HTTP-Client

#### Backend  
- **FastAPI** - Python Web Framework
- **Pydantic** - Datenvalidierung
- **Motor** - Async MongoDB Driver
- **Python-Magic** - Dateityp-Erkennung
- **Passlib** - Passwort-Hashing

#### Datenbank
- **MongoDB** - NoSQL-Datenbank für alle Daten

#### Infrastructure
- **Docker** & **Docker Compose** - Containerisierung
- **Nginx** - Reverse Proxy und Static File Serving
- **Supervisor** - Prozessmanagement (Entwicklung)

### Mindestanforderungen

#### Hardware
- **RAM:** 4GB minimum, 8GB empfohlen
- **Speicher:** 10GB verfügbar
- **CPU:** 2 Kerne minimum

#### Software
- **Docker** 20.0+ und **Docker Compose** 2.0+
- **Git** für Versionskontrolle
- **Modern Browser** (Chrome, Firefox, Safari, Edge)

---

# 2. Installations- und Entwicklungsumgebung

## 🚀 Detaillierte Installationsanleitung

### Schritt 1: Repository klonen
```bash
git clone <repository-url>
cd ipad-management-system
```

### Schritt 2: Environment-Dateien einrichten

#### Frontend (.env)
```bash
# /app/frontend/.env
REACT_APP_BACKEND_URL=http://localhost:8001
```

#### Backend (.env)
```bash
# /app/backend/.env  
MONGO_URL=mongodb://mongodb:27017/ipad_management
JWT_SECRET=your-secret-key-here
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
```

### Schritt 3: Docker Container starten

#### Produktionsumgebung
```bash
cd config
docker-compose up -d
```

#### Entwicklungsumgebung (mit Hot Reload)
```bash
# Backend
cd backend
pip install -r requirements.txt
python server.py

# Frontend  
cd frontend
yarn install
yarn start
```

## 🔧 Entwicklertools und Container-Kommunikation

### Docker-Container-Architektur

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Nginx         │    │   Frontend      │    │   Backend       │
│   Port: 80      │◄───│   Port: 3000    │◄───│   Port: 8001    │
│   Reverse Proxy │    │   React Dev     │    │   FastAPI       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                               │
                                               ▼
                                       ┌─────────────────┐
                                       │   MongoDB       │
                                       │   Port: 27017   │
                                       │   Database      │
                                       └─────────────────┘
```

### Container-Kommunikation

#### Nginx → Frontend
- **Entwicklung:** Proxy zu Port 3000 (Hot Reload)
- **Produktion:** Statische Dateien aus Volume

#### Frontend → Backend  
- **URL:** `REACT_APP_BACKEND_URL`
- **Pfad:** Alle API-Calls mit `/api` Prefix

#### Backend → MongoDB
- **URL:** `MONGO_URL` aus Environment
- **Auth:** Keine (interne Container-Kommunikation)

### Development vs. Production

| Aspekt | Development | Production |
|--------|------------|------------|
| **Frontend** | Hot Reload (Port 3000) | Statische Dateien in Volume |
| **Backend** | Supervisor + Hot Reload | Docker Container |
| **MongoDB** | Docker Container | Docker Container |
| **Nginx** | Proxy zu Dev-Servern | Statische Files + API Proxy |

---

# 3. Projektarchitektur und Struktur

## 🏗️ Architektur-Übersicht

### Microservices-Architektur
```
Frontend (React SPA)
    ↓ HTTP/REST
Backend (FastAPI)  
    ↓ Motor (Async)
MongoDB (NoSQL)
```

### Rollenbasierte Zugriffskontrolle (RBAC)
- **Admin:** Vollzugriff + Benutzerverwaltung
- **User:** Nur eigene Daten (iPads, Schüler, Zuordnungen)

## 📁 Projektstruktur

```
/app/
├── backend/                     # FastAPI Backend
│   ├── .env                    # Backend Environment
│   ├── server.py               # Hauptanwendung (~2800 Zeilen)
│   ├── requirements.txt        # Python Dependencies  
│   └── Dockerfile             # Backend Container
├── frontend/                   # React Frontend
│   ├── .env                   # Frontend Environment
│   ├── src/
│   │   └── App.js            # Monolithische App (~3800 Zeilen)
│   ├── public/               # Statische Assets
│   ├── package.json          # NPM Dependencies
│   └── Dockerfile           # Frontend Container  
├── config/                   # Docker Orchestrierung
│   └── docker-compose.yml   # Service-Definition
├── docs/                     # Dokumentation
│   ├── DEPLOYMENT_*.md       # Deployment-Guides
│   ├── CLEANUP_*.md         # Maintenance-Guides
│   └── *.md                 # Verschiedene Guides
├── nginx/                    # Reverse Proxy Config
└── deploy-smart.sh          # Intelligentes Deployment-Script
```

### Datenbankschema (MongoDB)

#### Collections
```javascript
// users - Benutzer
{
  id: "uuid",
  username: "string",
  email: "string", 
  hashed_password: "string",
  role: "admin|user",
  is_active: boolean,
  created_by: "uuid",
  force_password_change: boolean
}

// ipads - iPad-Inventar
{
  id: "uuid",
  user_id: "uuid",           // Besitzer
  itnr: "string",            // IT-Nummer (unique)
  snr: "string",             // Seriennummer  
  typ: "string",             // iPad-Modell
  status: "ok|defekt|gestohlen",
  current_assignment_id: "uuid|null",
  created_at: "datetime",
  updated_at: "datetime"
}

// students - Schülerdaten
{
  id: "uuid",
  user_id: "uuid",           // Besitzer
  sus_vorn: "string",        // Vorname
  sus_nachn: "string",       // Nachname  
  sus_kl: "string",          // Klasse
  sus_geb: "date",           // Geburtsdatum
  current_assignment_id: "uuid|null",
  // ... weitere Schülerdaten
}

// assignments - Zuordnungen  
{
  id: "uuid",
  user_id: "uuid",           // Ersteller
  student_id: "uuid",        // Schüler
  ipad_id: "uuid",           // iPad
  contract_id: "uuid|null",  // Vertrag (optional)
  is_active: boolean,
  created_at: "datetime",
  unassigned_at: "datetime|null"
}

// contracts - Verträge
{
  id: "uuid", 
  user_id: "uuid",           // Ersteller
  assignment_id: "uuid",     // Zuordnung
  pdf_content: "base64",     // PDF-Daten
  is_active: boolean,
  created_at: "datetime"
}
```

---

# 4. Code-Basis und APIs

## 🧩 Modul- und Komponentenbeschreibung

### Backend (server.py)

#### Hauptkomponenten
```python
# Authentifizierung & Autorisierung
- JWT-Token-Generierung und -Validierung
- Passwort-Hashing mit Passlib
- RBAC-Middleware für Admin/User-Rollen

# CRUD-Endpoints für alle Entities
- Users: /api/users/*, /api/admin/users/*
- iPads: /api/ipads/*
- Students: /api/students/*  
- Assignments: /api/assignments/*
- Contracts: /api/contracts/*

# Import/Export-Funktionen
- Excel-Upload für iPads/Schüler
- PDF-Vertragsmanagement  
- Datenexport als Excel

# Spezielle Features
- Batch-Operationen (Delete, Dissolve)
- Manuelle Zuordnungen
- Cleanup verwaister Daten
```

#### Wichtige Funktionen
```python
# Datenvalidierung
get_user_filter()           # RBAC-Filter für Queries
require_admin()             # Admin-Berechtigung prüfen
prepare_for_mongo()         # Pydantic → MongoDB

# Business Logic  
auto_assign_ipads()         # Automatische Zuordnung
manual_assign()             # Manuelle Zuordnung
batch_delete_students()     # Batch-Löschung
cleanup_orphaned_data()     # Verwaiste Daten löschen
```

### Frontend (App.js)

#### Hauptkomponenten
```javascript
// Authentifizierung
- LoginForm: Login-Formular mit JWT
- AuthContext: Globaler Auth-State

// Management-Komponenten
- IPadsManagement: iPad-CRUD + Upload
- StudentsManagement: Schüler-CRUD + Upload  
- AssignmentsManagement: Zuordnungs-Management + Import
- UserManagement: Admin-Benutzerverwaltung
- Settings: Einstellungen + Passwort-Änderung

// UI-Komponenten (Shadcn/ui)
- Tables: Daten-Darstellung mit Filtering
- Dialogs: Bestätigungen und Formulare
- Toast: Benachrichtigungen
- Autocomplete: Suchfelder für Zuordnungen
```

## 🔌 API-Dokumentation

### Authentifizierung
```http
POST /api/auth/login
Content-Type: application/json
{
  "username": "string",
  "password": "string" 
}
→ {"access_token": "jwt_token", "user": {...}}
```

### iPad-Management
```http
# CRUD-Operationen
GET    /api/ipads                     # Liste aller iPads
POST   /api/ipads/upload              # Excel-Upload
PUT    /api/ipads/{id}/status         # Status ändern
DELETE /api/ipads/{id}                # iPad löschen

# Zuordnungen
GET    /api/ipads/available-for-assignment  # Verfügbare iPads
POST   /api/assignments/manual              # Manuelle Zuordnung
```

### Schüler-Management  
```http
# CRUD-Operationen
GET    /api/students                  # Liste aller Schüler
POST   /api/students/upload           # Excel-Upload  
DELETE /api/students/{id}             # Schüler löschen
POST   /api/students/batch-delete     # Batch-Löschung

# Zuordnungen
GET    /api/students/available-for-assignment  # Verfügbare Schüler
```

### Admin-Funktionen
```http
# Benutzerverwaltung
GET    /api/admin/users               # Alle Benutzer
POST   /api/admin/users               # Benutzer erstellen
DELETE /api/admin/users/{id}/complete # Komplette Löschung

# Maintenance  
POST   /api/admin/cleanup-orphaned-data    # Verwaiste Daten löschen
```

### Import/Export
```http
POST   /api/imports/inventory         # Vollständiger Datenimport
GET    /api/exports/assignments       # Zuordnungen als Excel
GET    /api/exports/inventory         # Komplettes Inventar
```

---

# 5. Deployment

## 🚀 Smart Deployment System

Das Projekt verwendet ein intelligentes Deployment-System mit mehreren Optionen:

### Smart Deployment Script
```bash
# Hauptscript: Automatische Erkennung
sudo bash deploy-smart.sh

# Optionen:
1) Nur Frontend (App.js, CSS, etc.)       → 2-3 Min
2) Nur Backend (server.py, etc.)          → 1-2 Min  
3) Beides (Frontend + Backend)            → 3-4 Min
4) Full Build (package.json/requirements) → 5-7 Min
```

### Einzelne Deployment-Scripts

#### Frontend-Deployment
```bash
# Standard (mit Cache)
sudo bash frontend/deploy-production.sh      # 2-3 Min

# Vollständig (ohne Cache)  
sudo bash frontend/deploy-production-full.sh # 3-5 Min
```

#### Ein-Zeilen-Deployment
```bash
cd /home/RBBK_Ipad_Verwaltung-main/config && \
docker-compose down && \
docker rm -f ipad_frontend_build && \
docker volume rm config_frontend_build && \
docker-compose build frontend && \
docker-compose up -d
```

### Deployment-Workflow

#### Entwicklung → Produktion
```bash
1. Code-Änderungen auf Entwicklungs-System
2. Dateien auf Produktions-Server kopieren:
   - frontend/src/App.js
   - backend/server.py  
   - frontend/Dockerfile (bei Optimierungen)
3. Smart Deployment ausführen
4. Browser-Cache leeren (Strg+Shift+Entf)
```

#### Kritische Dateien
```bash
# MÜSSEN kopiert werden bei Änderungen:
/app/frontend/src/App.js              # Frontend-Logic
/app/backend/server.py                # Backend-Logic  
/app/frontend/Dockerfile              # Build-Optimierungen
/app/deploy-smart.sh                  # Deployment-Logic
```

### Docker Layer Caching
Das System nutzt intelligentes Caching:
- **Frontend:** `yarn install` wird gecacht wenn `package.json` unverändert
- **Backend:** `pip install` wird gecacht wenn `requirements.txt` unverändert
- **Rebuild:** Nur bei Abhängigkeits-Änderungen nötig

---

# 6. Troubleshooting

## 🔧 Häufige Probleme und Lösungen

### Backend-Probleme

#### libmagic-Fehler
```bash
# Symptom: ImportError: failed to find libmagic
# Lösung:
sudo apt-get install -y libmagic1
sudo supervisorctl restart backend
```

#### MongoDB-Verbindung
```bash
# Symptom: Connection refused
# Lösung: Container-Status prüfen
docker ps | grep mongodb
docker logs ipad_mongodb
```

### Frontend-Probleme

#### Änderungen nicht sichtbar
```bash
# Ursachen & Lösungen:
1. Browser-Cache: Strg+Shift+Entf → Cache leeren
2. Docker Volume: docker volume rm config_frontend_build  
3. Hard Reload: Strg+F5
4. Frontend neu bauen: docker-compose build frontend
```

#### Build-Fehler
```bash
# Container-Konflikte
docker rm -f ipad_frontend_build
docker volume rm config_frontend_build

# Abhängigkeits-Probleme  
docker-compose build --no-cache frontend
```

### Performance-Probleme

#### RAM-Probleme
```bash
# Docker RAM erhöhen (Docker Desktop)
Settings → Resources → Memory → 8GB

# Container-Status überwachen
docker stats
```

#### Lange Build-Zeiten
```bash
# Docker BuildKit aktivieren
export DOCKER_BUILDKIT=1
docker-compose build frontend
```

### Deployment-Probleme

#### Deploy-Script-Fehler
```bash
# Berechtigungen
chmod +x deploy-smart.sh

# Docker-Compose-Pfad
cd /pfad/zur/config && sudo bash ../deploy-smart.sh
```

## 🔍 Debug-Techniken

### Logs prüfen
```bash
# Backend-Logs  
docker logs ipad_backend
# oder bei Supervisor:
tail -f /var/log/supervisor/backend.*.log

# Frontend-Build-Logs
docker logs ipad_frontend_build

# Nginx-Logs
docker logs ipad_nginx
```

### Direkter Container-Zugriff
```bash
# Backend-Container
docker exec -it ipad_backend /bin/bash

# Datenbank-Zugriff
docker exec -it ipad_mongodb mongo ipad_management
```

---

# 7. Best Practices

## 💡 Entwicklungs-Best-Practices

### Code-Organisation
- **Backend:** Funktionen nach Entities gruppieren (iPad, Student, Assignment)
- **Frontend:** Komponenten nach Features gruppieren
- **Gemeinsam:** Konsistente Namenskonventionen

### Datenbank-Best-Practices
```javascript
// IMMER "_id" ausschließen bei MongoDB-Queries
await db.ipads.find({}, {"_id": 0}).to_list(length=None)

// UUIDs für alle IDs verwenden
import { v4 as uuid4 } from 'uuid';
const id = uuid4();

// Datetime mit Timezone
datetime.now(timezone.utc).isoformat()
```

### Sicherheits-Best-Practices
- **RBAC:** Jede API-Route mit Benutzer-Filter
- **Input-Validation:** Pydantic für Backend, PropTypes für Frontend  
- **File-Upload:** Typ- und Größen-Validierung
- **Passwörter:** Nie im Klartext speichern/loggen

### Performance-Best-Practices
- **Frontend:** Lazy Loading für große Datasets
- **Backend:** Async/Await für DB-Operationen
- **Caching:** Docker Layer Caching nutzen
- **Pagination:** Bei >100 Datensätzen implementieren

## 🔄 Maintenance-Richtlinien

### Regelmäßige Tasks
```bash
# Verwaiste Daten löschen (nach User-Löschungen)
POST /api/admin/cleanup-orphaned-data

# Docker-Images aufräumen (monatlich)
docker system prune -a

# Logs rotieren (wöchentlich)  
docker-compose logs --no-color | head -1000 > logs_backup.txt
```

### Backup-Strategie
```bash
# MongoDB-Backup
docker exec ipad_mongodb mongodump --db ipad_management --out /backup

# Code-Backup
git push origin main
git tag -a v1.0 -m "Production release"
```

### Monitoring
- **Container-Status:** `docker ps` täglich prüfen
- **Resource-Usage:** `docker stats` bei Performance-Problemen
- **Log-Levels:** ERROR/WARNING-Logs täglich prüfen
- **Disk-Space:** Bei großen Excel-Imports überwachen

---

## 📞 Support und Hilfe

### Dokumentation
- **Deployment:** `/docs/SMART_DEPLOYMENT.md`
- **Cleanup:** `/docs/CLEANUP_ANLEITUNG.md` 
- **Troubleshooting:** `/docs/FRONTEND_REBUILD.md`

### Debugging-Tools
- **Backend:** FastAPI Auto-Docs unter `/docs`
- **Frontend:** React DevTools Browser-Extension
- **Database:** MongoDB Compass für GUI-Zugriff

### Community
- **Issues:** GitHub Issues für Bug-Reports
- **Diskussionen:** GitHub Discussions für Features
- **Updates:** Release-Notes für Änderungen verfolgen

---

**📚 Diese Dokumentation ist ein lebendiges Dokument und sollte bei Änderungen am System aktualisiert werden.**

*Version: 1.0 | Letzte Aktualisierung: Dezember 2024*