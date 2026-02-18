# iPad-Verwaltung - Deployment Anleitung

## Voraussetzungen
- Docker & Docker Compose installiert
- Node.js (für Frontend-Build)

## Deployment-Schritte

### 1. Umgebungsvariablen konfigurieren (WICHTIG!)
```bash
# Beispiel-Datei kopieren
cp .env.example .env

# Datei bearbeiten und sichere Werte setzen
nano .env
```

**Inhalt der .env Datei:**
```
# MongoDB Zugangsdaten
MONGO_USER=ipad_admin
MONGO_PASSWORD=IhrSicheresPasswort123!
MONGO_DB=iPadDatabase

# JWT Secret (mindestens 32 Zeichen)
# Generieren mit: openssl rand -hex 32
JWT_SECRET=ihr_sehr_langes_zufaelliges_secret_hier
```

### 2. Frontend bauen
```bash
cd frontend
npm install
npm run build
cd ..
```

### 3. SSL-Zertifikat erstellen (falls nicht vorhanden)
```bash
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/server.key \
  -out nginx/ssl/server.crt \
  -subj "/C=DE/ST=NRW/L=Dortmund/O=RBBK/CN=iPad-Verwaltung"
```

### 4. Docker starten
```bash
# Erstmaliger Start (erstellt MongoDB mit Auth)
docker-compose up -d

# Logs anzeigen
docker-compose logs -f

# Stoppen
docker-compose down
```

### 5. Zugriff
- HTTPS: https://<IP-ADRESSE>
- HTTP wird automatisch auf HTTPS umgeleitet
- Standard-Login: admin / admin123

## Sicherheitshinweise

### Exponierte Ports
| Port | Service | Von außen erreichbar |
|------|---------|---------------------|
| 80   | Nginx   | Ja (Redirect)       |
| 443  | Nginx   | Ja (HTTPS)          |
| 8001 | Backend | Nein (nur intern)   |
| 27017| MongoDB | Nein (nur intern)   |

### MongoDB-Authentifizierung
- MongoDB startet mit Authentifizierung (`--auth`)
- Benutzername/Passwort aus `.env` Datei
- **WICHTIG:** Bei erstmaliger Installation wird der Admin-User erstellt
- Bei bestehenden Daten: Volume löschen oder User manuell anlegen

## Datenbank-Backup

```bash
# Backup erstellen (mit Auth)
docker exec ipad-mongodb mongodump \
  -u $MONGO_USER -p $MONGO_PASSWORD \
  --authenticationDatabase admin \
  --out /data/backup

# Backup auf Host kopieren
docker cp ipad-mongodb:/data/backup ./backup

# Backup wiederherstellen
docker exec ipad-mongodb mongorestore \
  -u $MONGO_USER -p $MONGO_PASSWORD \
  --authenticationDatabase admin \
  /data/backup
```

## Troubleshooting

### MongoDB-Auth funktioniert nicht bei bestehenden Daten
Wenn bereits Daten ohne Auth existieren:
```bash
# Option 1: Neu starten (DATENVERLUST!)
docker-compose down -v
docker-compose up -d

# Option 2: User manuell anlegen
docker exec -it ipad-mongodb mongosh
> use admin
> db.createUser({user: "ipad_admin", pwd: "IhrPasswort", roles: ["root"]})
```

### Container-Logs prüfen
```bash
docker-compose logs backend
docker-compose logs mongodb
docker-compose logs nginx
```
