# iPad-Verwaltungssystem - Projekt-Informationen

## 📋 Projekt-Übersicht

**Name:** iPad-Verwaltungssystem für Schulen
**Zweck:** Web-basierte Verwaltung von iPads, Schülern und Zuweisungen
**Status:** Produktionsreif, läuft stabil

## 🏗️ Technologie-Stack

- **Frontend:** React 18 mit Shadcn UI
- **Backend:** FastAPI (Python)
- **Datenbank:** MongoDB 4.4
- **Reverse Proxy:** Nginx
- **Container:** Docker + Docker Compose

## 🎯 Haupt-Features

1. **Multi-User-System** mit RBAC (Admin/Benutzer-Rollen)
2. **iPad-Verwaltung** (CRUD, Status-Tracking: ok/defekt/gestohlen)
3. **Schüler-Verwaltung** (CRUD, vollständige Daten)
4. **Zuweisungen** (iPad ↔ Schüler mit Vertragsinfo)
5. **Excel-Import/Export** für alle Datentypen
6. **Batch-Operationen** (Massenbearbeitung)
7. **Daten-Isolation** (User sehen nur ihre Daten, Admins alles)

## 🔑 Standard-Login

- **Benutzername:** admin
- **Passwort:** admin123
- **Rolle:** Administrator

⚠️ **Nach erstem Login ändern!**

## 📁 Projekt-Struktur

```
/app/
├── backend/
│   ├── server.py           # Haupt-Backend (FastAPI)
│   ├── requirements.txt    # Python-Dependencies
│   ├── Dockerfile
│   └── .env               # Backend-Konfiguration
├── frontend/
│   ├── src/
│   │   └── App.js         # React Haupt-App (Monolith, 3500+ Zeilen!)
│   ├── package.json       # Node-Dependencies
│   ├── Dockerfile
│   └── .env              # Frontend-Konfiguration
├── config/
│   └── docker-compose.yml # Docker-Orchestrierung
├── nginx/
│   ├── nginx.conf
│   └── default.conf      # Reverse Proxy Config
├── mongo-init/
│   └── init.js           # DB-Initialisierung
├── install.sh            # Installation
├── uninstall.sh          # Deinstallation
├── deploy-smart.sh       # Smart Deployment
├── check-system.sh       # System-Status
├── debug-frontend.sh     # Frontend-Debugging
├── troubleshoot-access.sh # Zugriffs-Probleme
├── ENTWICKLERDOKUMENTATION.md
└── README.md
```

## 🚀 Netzwerk-Architektur

**Reverse Proxy Setup (Nginx):**
```
Client
  ↓
Nginx (Port 80/443)
  ├─→ Frontend (statische Dateien)
  └─→ Backend (http://backend:8001/api/)
```

**Exponierte Ports:**
- `80` - Nginx HTTP (Hauptzugriff)
- `443` - Nginx HTTPS
- `8001` - Backend API (direkter Zugriff)
- `27017` - MongoDB (optional)

**Zugriff:**
- Frontend: `http://localhost` oder `http://localhost:80`
- Backend API: `http://localhost/api/` oder `http://localhost:8001`
- API Docs: `http://localhost:8001/docs`

## 🗄️ Datenbank-Schema

**Kollektionen:**

1. **users**
   ```javascript
   {
     id: string,
     username: string,
     email: string,
     hashed_password: string,
     role: 'admin' | 'user',
     is_active: boolean,
     created_at: Date
   }
   ```

2. **ipads**
   ```javascript
   {
     id: string,
     user_id: string,  // Owner
     itnr: string,     // Unique IT-Nummer
     snr: string,      // Seriennummer (Pflicht)
     status: 'ok' | 'defekt' | 'gestohlen',
     current_assignment_id: string | null,
     created_at: Date
   }
   ```

3. **students**
   ```javascript
   {
     id: string,
     user_id: string,
     sus_vorn: string,  // Vorname
     sus_nachn: string, // Nachname
     current_assignment_id: string | null,
     created_at: Date
   }
   ```

4. **assignments**
   ```javascript
   {
     id: string,
     user_id: string,
     student_id: string,
     ipad_id: string,
     contract_id: string,
     is_active: boolean,
     created_at: Date,
     ended_at: Date | null
   }
   ```

## ⚙️ Umgebungsvariablen

**Backend (.env):**
```bash
MONGO_URL=mongodb://admin:password@mongodb:27017/iPadDatabase?authSource=admin
SECRET_KEY=your-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
IPAD_DB_NAME=iPadDatabase
```

**Frontend (.env):**
```bash
REACT_APP_BACKEND_URL=http://localhost:8001
```

## 🔧 Wichtige Hinweise

### ⚠️ Bekannte Einschränkungen

1. **App.js ist ein Monolith**
   - 3500+ Zeilen Code
   - Sollte refactored werden in kleinere Komponenten
   - Vorsicht bei Änderungen!

2. **Keine automatischen Tests**
   - Manuelles Testing notwendig
   - Test-Dateien wurden entfernt (System nicht live)

3. **Container-Namen verwenden Unterstriche**
   - `ipad_mongodb` (NICHT `ipad-mongodb`)
   - `ipad_backend`
   - `ipad_frontend_build`
   - `ipad_nginx`

### ✅ Best Practices

1. **Immer `bash` verwenden** (NICHT `sh`)
2. **Docker Compose**: Alte Version = `docker-compose`, neue = `docker compose`
3. **Vor größeren Änderungen**: `bash check-system.sh`
4. **Nach Änderungen**: `bash troubleshoot-access.sh`

## 📦 Docker Volumes

- `config_mongodb_data` - Datenbank-Daten (persistent)
- `config_backend_uploads` - Hochgeladene Dateien
- `config_frontend_build` - React Build-Artefakte

## 🔒 Sicherheit

- JWT-basierte Authentifizierung
- Passwort-Hashing mit bcrypt
- RBAC für Datenzugriff
- Nginx Security Headers aktiviert
- CORS korrekt konfiguriert

## 📊 Performance

- Frontend: Statisch gebaut und über Nginx serviert
- Backend: Async FastAPI mit Motor (async MongoDB)
- Datenbank: MongoDB mit Indizes auf user_id

## 🌐 Sprache

- **UI:** Deutsch
- **Code:** Englisch
- **Dokumentation:** Deutsch
- **Datenbank-Felder:** Teilweise Deutsch (sus_vorn, sus_nachn)
