# iPad-Verwaltung - Deployment Anleitung

## Voraussetzungen
- Docker & Docker Compose installiert
- Node.js (für Frontend-Build)

## Deployment-Schritte

### 1. Frontend bauen
```bash
cd frontend
npm install
npm run build
cd ..
```

### 2. SSL-Zertifikat (optional - bereits vorhanden)
Falls Sie ein neues Zertifikat benötigen:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/server.key \
  -out nginx/ssl/server.crt \
  -subj "/C=DE/ST=NRW/L=Dortmund/O=RBBK/CN=iPad-Verwaltung"
```

### 3. Docker starten
```bash
# Starten
docker-compose up -d

# Logs anzeigen
docker-compose logs -f

# Stoppen
docker-compose down
```

### 4. Zugriff
- HTTPS: https://<IP-ADRESSE>
- HTTP wird automatisch auf HTTPS umgeleitet

## Umgebungsvariablen
In `.env` Datei (optional):
```
JWT_SECRET=ihr-geheimer-schluessel
```

## Ports
- 80: HTTP (Redirect zu HTTPS)
- 443: HTTPS (Nginx)
- 8001: Backend (nur intern)
- 27017: MongoDB (nur intern)

## Datenbank-Backup
```bash
# Backup erstellen
docker exec ipad-mongodb mongodump --out /data/backup

# Backup kopieren
docker cp ipad-mongodb:/data/backup ./backup
```
