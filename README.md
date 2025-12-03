# iPad-Verwaltungssystem

Ein webbasiertes System zur Verwaltung von iPads, Schülern und Zuweisungen mit Rollen-basierter Zugriffskontrolle (RBAC).

## 🚀 Schnellstart

### Installation

```bash
./install.sh
```

Das System wird automatisch installiert und gestartet:
- Frontend: http://localhost:3000
- Backend: http://localhost:8001
- API Docs: http://localhost:8001/docs

**Standard-Login:**
- Benutzername: `admin`
- Passwort: `admin123`

⚠️ **Wichtig:** Ändern Sie das Admin-Passwort nach dem ersten Login!

### Deployment auf Produktions-Server

```bash
./deploy-smart.sh
```

Das Script erkennt automatisch geänderte Dateien und baut nur die benötigten Services neu.

### Deinstallation

```bash
./uninstall.sh
```

Entfernt alle Docker-Container, Volumes und optional die Konfigurationsdateien.

## 📋 Voraussetzungen

- Docker (Version 20.x oder höher)
- Docker Compose (Version 2.x oder höher)
- Bash (für Scripts)

## 🏗️ Architektur

- **Frontend:** React mit Shadcn UI
- **Backend:** FastAPI (Python)
- **Datenbank:** MongoDB
- **Reverse Proxy:** Nginx

## 📚 Dokumentation

Die vollständige Dokumentation finden Sie in:
- **[ENTWICKLERDOKUMENTATION.md](ENTWICKLERDOKUMENTATION.md)** - Komplette technische Dokumentation

## 🔧 Nützliche Befehle

```bash
# Services verwalten
cd config
docker compose ps              # Status anzeigen
docker compose logs -f         # Logs anzeigen
docker compose restart         # Services neu starten
docker compose down            # Services stoppen

# Spezifische Logs
docker compose logs -f backend   # Nur Backend-Logs
docker compose logs -f frontend  # Nur Frontend-Logs
```

## ✨ Features

- **Multi-User-System** mit Admin- und Benutzer-Rollen
- **iPad-Verwaltung** mit Status-Tracking (ok, defekt, gestohlen)
- **Schüler-Verwaltung** mit vollständigen Daten
- **Zuweisungen** zwischen iPads und Schülern
- **Daten-Import** via Excel (iPads, Schüler, Zuweisungen)
- **RBAC:** Benutzer sehen nur ihre eigenen Daten, Admins sehen alles

## 📞 Support

Bei Problemen konsultieren Sie die `ENTWICKLERDOKUMENTATION.md`.

## 📄 Lizenz

Dieses Projekt ist für den internen Schulgebrauch bestimmt.
