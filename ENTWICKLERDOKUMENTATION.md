# iPad-Verwaltungssystem - Entwicklerdokumentation

> **Umfassende Dokumentation für Installation, Deployment, Entwicklung und Wartung**
> 
> Version: 2.0 | Stand: Dezember 2025

---

## Inhaltsverzeichnis

1. [Projektübersicht](#1-projektübersicht)
2. [Schnellstart](#2-schnellstart)
3. [Lokale Entwicklung](#3-lokale-entwicklung)
4. [Produktion (Docker)](#4-produktion-docker)
5. [SSL/HTTPS Konfiguration](#5-sslhttps-konfiguration)
6. [Skript-Referenz](#6-skript-referenz)
7. [Architektur](#7-architektur)
8. [API-Dokumentation](#8-api-dokumentation)
9. [Troubleshooting](#9-troubleshooting)
10. [Best Practices](#10-best-practices)

---

## 1. Projektübersicht

### Was ist das iPad-Verwaltungssystem?

Eine webbasierte Anwendung zur Verwaltung von iPads, Schülern und deren Zuordnungen in Bildungseinrichtungen.

**Kernfunktionen:**
- Inventarverwaltung für iPads (IT-Nummer, Seriennummer, Status)
- Schülerverwaltung mit Klassenzuordnung
- Manuelle und automatische iPad-Zuordnungen (1:n möglich)
- PDF-Vertragsgenerierung und -verwaltung
- Excel-basierter Datenimport/-export
- Rollenbasierte Zugriffskontrolle (Admin/User)

### Technologie-Stack

| Komponente | Technologie | Version |
|------------|-------------|---------|
| Frontend | React (Komponenten-Architektur) | 18.2.0 |
| UI-Bibliothek | Shadcn/ui + Tailwind CSS | - |
| Backend | FastAPI (Python) | 0.100+ |
| Datenbank | MongoDB | 6.0 |
| Reverse Proxy | Nginx | Alpine |
| Container | Docker + Docker Compose | 20.0+ |

### Systemanforderungen

**Hardware (Minimum):**
- RAM: 4 GB (8 GB empfohlen)
- Speicher: 10 GB verfügbar
- CPU: 2 Kerne

**Software:**
- Docker 20.0+ mit Docker Compose 2.0+
- Git (für Versionskontrolle)
- Moderner Browser (Chrome, Firefox, Safari, Edge)

---

## 2. Schnellstart

### Option A: Automatische Installation (empfohlen)

```bash
# 1. Repository klonen
git clone <repository-url>
cd ipad-verwaltungssystem

# 2. Installation starten
bash install.sh
```

Das Installationsskript führt automatisch durch:
- Prüfung der Voraussetzungen (Docker, Docker Compose)
- Erstellung der Environment-Dateien
- Build der Docker-Container
- Start aller Services
- Initialisierung der Datenbank mit Admin-User

### Option B: Manuelle Installation

```bash
# 1. Repository klonen
git clone <repository-url>
cd ipad-verwaltungssystem

# 2. Environment-Dateien erstellen
cp .env.example .env
# JWT_SECRET eintragen (siehe Abschnitt 4.2)

# 3. Docker starten
docker-compose up -d
```

### Standard-Login

Nach der Installation:
- **URL:** https://localhost (oder Server-IP)
- **Benutzername:** `admin`
- **Passwort:** `admin123`

> **Wichtig:** Ändern Sie das Admin-Passwort nach dem ersten Login!

---

## 3. Lokale Entwicklung

### 3.1 Entwicklungsumgebung einrichten

#### Backend

```bash
cd backend

# Virtual Environment erstellen (empfohlen)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# oder: venv\Scripts\activate  # Windows

# Dependencies installieren
pip install -r requirements.txt

# Backend starten (Hot Reload aktiv)
uvicorn server:app --reload --host 0.0.0.0 --port 8001
```

**Backend Environment (`backend/.env`):**
```bash
MONGO_URL=mongodb://localhost:27017/iPadDatabase
DB_NAME=iPadDatabase
JWT_SECRET=entwicklung-geheimer-schluessel
```

#### Frontend

```bash
cd frontend

# Dependencies installieren
yarn install

# Entwicklungsserver starten (Hot Reload aktiv)
yarn start
```

**Frontend Environment (`frontend/.env`):**
```bash
REACT_APP_BACKEND_URL=http://localhost:8001
```

#### MongoDB (lokal via Docker)

```bash
# Standalone MongoDB starten
docker run -d --name mongodb-dev \
  -p 27017:27017 \
  -v mongodb_dev_data:/data/db \
  mongo:6
```

### 3.2 Entwicklungs-Workflow

```
┌─────────────────────────────────────────────────────────────┐
│  Entwicklung (lokale Maschine)                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ Frontend    │  │ Backend     │  │ MongoDB     │         │
│  │ Port 3000   │──│ Port 8001   │──│ Port 27017  │         │
│  │ yarn start  │  │ uvicorn     │  │ Docker      │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 Code-Änderungen testen

```bash
# Backend-Tests
cd backend
pytest tests/

# Frontend Lint
cd frontend
yarn lint
```

---

## 4. Produktion (Docker)

### 4.1 Architektur-Übersicht

```
Internet
    │
    ▼
┌────────────────┐
│  Nginx         │ ← Einziger öffentlicher Eintrittspunkt
│  Port 80/443   │
└───────┬────────┘
        │ (internes Docker-Netzwerk)
        ├──────────────────┐
        ▼                  ▼
┌──────────────┐    ┌──────────────┐
│ Backend      │    │ MongoDB      │
│ Port 8001    │────│ Port 27017   │
│ (nur intern) │    │ (nur intern) │
└──────────────┘    └──────────────┘
```

**Sicherheitskonzept:**
- Nginx ist der **einzige** Service, der von außen erreichbar ist
- Backend und MongoDB sind **nur im Docker-Netzwerk** erreichbar
- JWT sichert alle API-Zugriffe
- HTTPS mit SSL/TLS verschlüsselt die Verbindung

### 4.2 Konfiguration (.env)

Vor dem Start muss eine `.env`-Datei im `config/`-Verzeichnis erstellt werden:

```bash
cd config

# Beispieldatei kopieren
cp .env.example .env

# Sicheres JWT-Secret generieren
openssl rand -hex 32

# In .env eintragen
nano .env
```

**Inhalt der `config/.env`-Datei:**
```bash
# Mindestens 32 Zeichen, zufällig generiert
JWT_SECRET=ihr_generiertes_secret_hier_eintragen
```

> **Wichtig:** Das JWT_SECRET muss **sicher** und **geheim** sein! Verwenden Sie `openssl rand -hex 32` zur Generierung.

### 4.3 Docker Compose starten

```bash
# Container bauen und starten
docker-compose up -d

# Status prüfen
docker-compose ps

# Logs anzeigen (alle Services)
docker-compose logs -f

# Nur bestimmter Service
docker-compose logs -f backend
docker-compose logs -f nginx
docker-compose logs -f mongodb

# Services stoppen
docker-compose down

# Services stoppen UND Volumes löschen (VORSICHT: Datenverlust!)
docker-compose down -v
```

### 4.4 Ports und Zugriff

| Port | Service | Von außen erreichbar | Beschreibung |
|------|---------|---------------------|--------------|
| 80 | Nginx | Ja | HTTP → Redirect auf HTTPS |
| 443 | Nginx | Ja | HTTPS (Haupteingang) |
| 8001 | Backend | **Nein** | Nur intern via Nginx |
| 27017 | MongoDB | **Nein** | Nur intern im Docker-Netzwerk |

**Zugriff auf die Anwendung:**
- HTTPS: `https://<SERVER-IP>`
- HTTP wird automatisch auf HTTPS umgeleitet

---

## 5. SSL/HTTPS Konfiguration

### 5.1 Self-Signed Zertifikat erstellen

Für interne Netzwerke oder Testumgebungen:

```bash
# SSL-Verzeichnis erstellen
mkdir -p nginx/ssl

# Zertifikat generieren (gültig für 365 Tage)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/server.key \
  -out nginx/ssl/server.crt \
  -subj "/C=DE/ST=NRW/L=Dortmund/O=RBBK/CN=iPad-Verwaltung"
```

**Erklärung der Parameter:**
- `-x509`: Self-Signed Zertifikat
- `-nodes`: Kein Passwort für den Private Key
- `-days 365`: Gültigkeit (1 Jahr)
- `-newkey rsa:2048`: 2048-bit RSA Key
- `/C=DE`: Land (Deutschland)
- `/ST=NRW`: Bundesland
- `/L=Dortmund`: Stadt
- `/O=RBBK`: Organisation
- `/CN=iPad-Verwaltung`: Common Name

### 5.2 Let's Encrypt (Produktion)

Für öffentlich erreichbare Server empfohlen:

```bash
# Certbot installieren
sudo apt install certbot python3-certbot-nginx

# Zertifikat anfordern
sudo certbot --nginx -d ihre-domain.de

# Automatische Erneuerung testen
sudo certbot renew --dry-run
```

**Nginx-Konfiguration anpassen (`nginx/default.conf`):**
```nginx
ssl_certificate /etc/letsencrypt/live/ihre-domain.de/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/ihre-domain.de/privkey.pem;
```

### 5.3 SSL-Sicherheitseinstellungen

Die aktuelle Nginx-Konfiguration enthält bereits:

```nginx
# TLS 1.2+ (TLS 1.0/1.1 deaktiviert)
ssl_protocols TLSv1.2 TLSv1.3;

# Sichere Cipher-Suites
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...;

# HSTS (1 Jahr)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

# Content-Security-Policy
add_header Content-Security-Policy "default-src 'self'; ...";
```

---

## 6. Skript-Referenz

### 6.1 install.sh - Erstinstallation

**Zweck:** Vollständige Erstinstallation des Systems

**Ausführung:**
```bash
bash install.sh
# oder
sudo bash install.sh  # falls Docker sudo benötigt
```

**Was macht das Skript?**
1. Prüft Docker und Docker Compose Installation
2. Prüft Projektstruktur auf Vollständigkeit
3. Erstellt `backend/.env` und `frontend/.env` (falls nicht vorhanden)
4. Baut alle Docker-Container
5. Startet alle Services
6. Wartet auf Service-Verfügbarkeit
7. Erstellt Admin-User in der Datenbank

**Voraussetzungen:**
- Docker und Docker Compose installiert
- `config/docker-compose.yml` vorhanden
- `backend/server.py` vorhanden
- `frontend/package.json` vorhanden

### 6.2 uninstall.sh - Deinstallation

**Zweck:** Vollständige Entfernung aller Docker-Ressourcen

**Ausführung:**
```bash
bash uninstall.sh
```

**Was macht das Skript?**
1. Zeigt Warnung über Datenverlust
2. Fragt Bestätigung ab (`ja` eingeben)
3. Stoppt alle Container (ipad_*)
4. Löscht alle Container
5. Löscht alle Volumes (config_*)
6. Optional: Löscht Docker Images
7. Optional: Löscht .env-Dateien
8. Optional: Docker System Cleanup

**Interaktive Abfragen:**
- Bestätigung vor Deinstallation
- Docker-Images löschen? (j/n)
- .env-Dateien löschen? (j/n)
- Docker-System-Bereinigung? (j/n)

### 6.3 deploy-smart.sh - Smart Deployment

**Zweck:** Intelligentes Deployment nach Code-Änderungen

**Ausführung:**
```bash
sudo bash deploy-smart.sh
```

**Deployment-Optionen:**
```
1) Nur Frontend (App.js, CSS, etc.)       → 2-3 Min
2) Nur Backend (server.py, etc.)          → 1-2 Min
3) Beides (Frontend + Backend)            → 3-4 Min
4) Full Build (package.json/requirements) → 5-7 Min
```

**Wann welche Option?**
- **Option 1:** React-Komponenten, CSS, UI-Änderungen
- **Option 2:** Python-Code, API-Endpoints
- **Option 3:** Änderungen in beiden Bereichen
- **Option 4:** Neue npm-Pakete oder pip-Dependencies

**Nach dem Deployment:**
```
Browser-Cache leeren:
1. Strg + Shift + Entf
2. "Cache/Zwischengespeicherte Dateien" wählen
3. "Daten löschen" klicken
4. Strg + F5 (Hard Reload)
```

### 6.4 check-system.sh - Systemprüfung

**Zweck:** Prüft ob Docker-Ressourcen existieren

**Ausführung:**
```bash
bash check-system.sh
```

**Prüft:**
- Container mit "ipad" im Namen
- Volumes mit "config_" im Namen
- Docker Images mit "config-" im Namen
- Vorhandensein der .env-Dateien

---

## 7. Architektur

### 7.1 Projektstruktur

```
/projekt-root/
├── docker-compose.yml          # Gehärtete Produktion (ohne Auth, isoliert)
├── .env.example                # Vorlage für Umgebungsvariablen
├── .env                        # JWT_SECRET (nicht in Git!)
├── install.sh                  # Erstinstallation
├── uninstall.sh                # Deinstallation
├── deploy-smart.sh             # Smart Deployment
├── check-system.sh             # Systemprüfung
│
├── backend/
│   ├── .env                    # Backend-Konfiguration
│   ├── server.py               # FastAPI Hauptanwendung
│   ├── contract_generator.py   # PDF-Vertragsgenerierung
│   ├── requirements.txt        # Python Dependencies
│   ├── Dockerfile              # Backend Container
│   ├── templates/              # Vertragsvorlagen
│   └── tests/                  # Backend-Tests
│
├── frontend/
│   ├── .env                    # Frontend-Konfiguration
│   ├── package.json            # NPM Dependencies
│   ├── Dockerfile              # Frontend Container
│   ├── src/
│   │   ├── App.js              # Haupt-App (Routing, Layout)
│   │   ├── api/
│   │   │   └── index.js        # Zentralisierte Axios-Konfiguration
│   │   └── components/         # React-Komponenten
│   │       ├── auth/           # Authentifizierung
│   │       ├── ipads/          # iPad-Verwaltung
│   │       ├── students/       # Schüler-Verwaltung
│   │       ├── assignments/    # Zuordnungen
│   │       ├── contracts/      # Verträge
│   │       ├── settings/       # Einstellungen
│   │       ├── users/          # Benutzerverwaltung (Admin)
│   │       └── shared/         # Gemeinsame Komponenten
│   └── public/                 # Statische Assets
│
├── nginx/
│   ├── nginx.conf              # Nginx Hauptkonfiguration
│   ├── default.conf            # Server-Block Konfiguration
│   └── ssl/                    # SSL-Zertifikate
│       ├── server.crt
│       └── server.key
│
└── config/
    └── docker-compose.yml      # Alternative (mit MongoDB Auth)
```

### 7.2 Frontend-Komponenten-Architektur

Das Frontend wurde von einer monolithischen `App.js` in eine modulare Komponenten-Architektur refaktoriert:

```
frontend/src/
├── App.js                      # ~280 Zeilen (Routing, Layout, Auth-State)
├── api/
│   └── index.js                # Axios-Instanz mit Interceptors
└── components/
    ├── auth/
    │   └── LoginForm.jsx       # Login-Formular
    ├── ipads/
    │   └── IPadsManagement.jsx # iPad-CRUD, Status-Änderungen
    ├── students/
    │   └── StudentsManagement.jsx
    ├── assignments/
    │   └── AssignmentsManagement.jsx
    ├── contracts/
    │   └── ContractsManagement.jsx
    ├── settings/
    │   └── Settings.jsx        # Daten-Import/Export, Excel-Template
    ├── users/
    │   └── UserManagement.jsx  # Admin-Benutzerverwaltung
    └── shared/
        └── ...                 # Gemeinsame UI-Komponenten
```

### 7.3 Datenbank-Schema

**Collection: users**
```javascript
{
  id: "uuid",
  username: "string",
  email: "string",
  hashed_password: "string",
  role: "admin" | "user",
  is_active: true,
  created_by: "uuid",
  force_password_change: false
}
```

**Collection: ipads**
```javascript
{
  id: "uuid",
  user_id: "uuid",              // Besitzer
  itnr: "string",               // IT-Nummer (unique)
  snr: "string",                // Seriennummer
  typ: "string",                // iPad-Modell
  status: "ok" | "defekt" | "gestohlen",
  current_assignment_id: "uuid" | null,
  created_at: "datetime",
  updated_at: "datetime"
}
```

**Collection: students**
```javascript
{
  id: "uuid",
  user_id: "uuid",              // Besitzer
  sus_vorn: "string",           // Vorname
  sus_nachn: "string",          // Nachname
  sus_kl: "string",             // Klasse
  sus_geb: "date",              // Geburtsdatum
  current_assignment_id: "uuid" | null
}
```

**Collection: assignments**
```javascript
{
  id: "uuid",
  user_id: "uuid",              // Ersteller
  student_id: "uuid",
  ipad_id: "uuid",
  contract_id: "uuid" | null,
  is_active: true,
  created_at: "datetime",
  unassigned_at: "datetime" | null
}
```

**Collection: contracts**
```javascript
{
  id: "uuid",
  user_id: "uuid",
  assignment_id: "uuid",
  pdf_content: "base64",
  is_active: true,
  created_at: "datetime"
}
```

---

## 8. API-Dokumentation

### 8.1 Authentifizierung

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "string",
  "password": "string"
}

→ 200: {"access_token": "jwt_token", "user": {...}}
→ 401: {"detail": "Invalid credentials"}
```

### 8.2 iPad-Endpoints

```http
# Liste aller iPads
GET /api/ipads

# iPad erstellen
POST /api/ipads
{
  "itnr": "IT-001",
  "snr": "ABC123",
  "typ": "iPad Pro 12.9",
  "status": "ok"
}

# iPad-Status ändern
PUT /api/ipads/{id}/status
{"status": "defekt"}

# iPad löschen
DELETE /api/ipads/{id}

# Verfügbare iPads für Zuordnung
GET /api/ipads/available-for-assignment
```

### 8.3 Schüler-Endpoints

```http
# Liste aller Schüler
GET /api/students

# Schüler erstellen
POST /api/students
{
  "sus_vorn": "Max",
  "sus_nachn": "Mustermann",
  "sus_kl": "10a"
}

# Schüler löschen
DELETE /api/students/{id}

# Batch-Löschung
POST /api/students/batch-delete
{"ids": ["uuid1", "uuid2"]}

# Verfügbare Schüler für Zuordnung
GET /api/students/available-for-assignment
```

### 8.4 Zuordnungs-Endpoints

```http
# Alle Zuordnungen
GET /api/assignments

# Manuelle Zuordnung
POST /api/assignments/manual
{
  "student_id": "uuid",
  "ipad_id": "uuid"
}

# Auto-Zuordnung (alle Schüler ohne iPad)
POST /api/auto-assign-all

# Zuordnung auflösen
POST /api/assignments/{id}/dissolve
```

### 8.5 Import/Export-Endpoints

```http
# Vollständiger Datenimport (Excel)
POST /api/imports/inventory
Content-Type: multipart/form-data
file: <excel-datei>

# Datenexport (Excel)
GET /api/exports/inventory

# Excel-Template herunterladen
GET /api/exports/template
```

### 8.6 Admin-Endpoints

```http
# Alle Benutzer (nur Admin)
GET /api/admin/users

# Benutzer erstellen
POST /api/admin/users
{
  "username": "neuer_user",
  "email": "user@example.com",
  "password": "sicheres_passwort",
  "role": "user"
}

# Benutzer komplett löschen (inkl. Daten)
DELETE /api/admin/users/{id}/complete

# Verwaiste Daten bereinigen
POST /api/admin/cleanup-orphaned-data
```

---

## 9. Troubleshooting

### 9.1 Backend startet nicht

**Symptom:** `ImportError: failed to find libmagic`

**Lösung:**
```bash
# In der Entwicklungsumgebung:
sudo apt-get install -y libmagic1
sudo supervisorctl restart backend

# Im Docker-Container:
docker exec -it ipad-backend apt-get install -y libmagic1
docker-compose restart backend
```

### 9.2 MongoDB-Verbindungsfehler

**Symptom:** `Connection refused to MongoDB`

**Diagnose:**
```bash
# Container-Status prüfen
docker ps | grep mongodb

# MongoDB-Logs anzeigen
docker logs ipad-mongodb

# Verbindung testen
docker exec -it ipad-mongodb mongosh --eval "db.adminCommand('ping')"
```

### 9.3 Frontend-Änderungen nicht sichtbar

**Ursachen und Lösungen:**

1. **Browser-Cache:** `Strg + Shift + Entf` → Cache leeren
2. **Docker-Volume:** `docker volume rm config_frontend_build`
3. **Hard Reload:** `Strg + F5`
4. **Container neu bauen:** `docker-compose build --no-cache frontend`

### 9.4 SSL-Zertifikat-Fehler

**Symptom:** Browser zeigt "Nicht sicher" oder blockiert

**Für Self-Signed Zertifikate:**
- Chrome: "Erweitert" → "Weiter zu <IP> (unsicher)"
- Firefox: "Erweitert" → "Risiko akzeptieren und fortfahren"

**Zertifikat erneuern:**
```bash
# Neues Zertifikat generieren
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/server.key \
  -out nginx/ssl/server.crt \
  -subj "/C=DE/ST=NRW/L=Dortmund/O=RBBK/CN=iPad-Verwaltung"

# Nginx neu starten
docker-compose restart nginx
```

### 9.5 Container-Logs prüfen

```bash
# Alle Logs
docker-compose logs -f

# Bestimmter Service
docker-compose logs -f backend
docker-compose logs -f nginx
docker-compose logs -f mongodb

# Letzte 100 Zeilen
docker-compose logs --tail=100 backend
```

### 9.6 Direkter Container-Zugriff

```bash
# Backend-Container
docker exec -it ipad-backend /bin/bash

# MongoDB-Shell
docker exec -it ipad-mongodb mongosh iPadDatabase

# Nginx-Container
docker exec -it ipad-nginx /bin/sh
```

---

## 10. Best Practices

### 10.1 Sicherheit

**Passwörter:**
- Admin-Passwort nach Erstinstallation ändern
- Starke Passwörter verwenden (min. 12 Zeichen)
- JWT_SECRET niemals in Git commiten

**Updates:**
```bash
# Docker-Images aktualisieren
docker-compose pull
docker-compose up -d

# System-Updates (Produktionsserver)
sudo apt update && sudo apt upgrade
```

### 10.2 Backup-Strategie

**MongoDB-Backup erstellen:**
```bash
# Backup
docker exec ipad-mongodb mongodump --db iPadDatabase --out /data/backup

# Backup auf Host kopieren
docker cp ipad-mongodb:/data/backup ./backup_$(date +%Y%m%d)
```

**MongoDB-Backup wiederherstellen:**
```bash
# Backup in Container kopieren
docker cp ./backup ipad-mongodb:/data/backup

# Wiederherstellen
docker exec ipad-mongodb mongorestore /data/backup
```

### 10.3 Monitoring

**Container-Ressourcen überwachen:**
```bash
# Live-Statistiken
docker stats

# Disk-Usage
docker system df
```

**Regelmäßige Wartung:**
```bash
# Ungenutzte Docker-Ressourcen bereinigen (monatlich)
docker system prune -a

# Logs rotieren
docker-compose logs --no-color backend > backend_logs_$(date +%Y%m%d).txt
```

### 10.4 Code-Konventionen

**MongoDB:**
```python
# IMMER "_id" ausschließen bei Queries
await db.ipads.find({}, {"_id": 0}).to_list(length=None)

# UUIDs für IDs verwenden
import uuid
new_id = str(uuid.uuid4())

# Datetime mit Timezone
from datetime import datetime, timezone
created_at = datetime.now(timezone.utc).isoformat()
```

**Frontend:**
```javascript
// API-Aufrufe über zentrale Axios-Instanz
import api from '../api';
const response = await api.get('/ipads');

// Komponenten-Struktur
// - Eine Komponente pro Datei
// - Named exports für Komponenten
// - Default exports für Seiten
```

---

## Support und Hilfe

**API-Dokumentation (Swagger):**
- Entwicklung: `http://localhost:8001/docs`
- Produktion: `https://<SERVER>/api/docs` (falls aktiviert)

**Debugging-Tools:**
- Backend: FastAPI Auto-Docs
- Frontend: React DevTools (Browser-Extension)
- Database: MongoDB Compass (GUI)

---

*Diese Dokumentation wird bei Änderungen am System aktualisiert.*

**Version 2.0** | Dezember 2025
