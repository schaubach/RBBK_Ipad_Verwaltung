# iPad-Verwaltung - Deployment Anleitung

## Voraussetzungen
- Docker & Docker Compose installiert
- Node.js (für Frontend-Build)

## Deployment-Schritte

### 1. JWT Secret konfigurieren
```bash
# Beispiel-Datei kopieren
cp .env.example .env

# Sicheres Secret generieren und eintragen
openssl rand -hex 32
nano .env
```

**Inhalt der .env Datei:**
```
JWT_SECRET=ihr_generiertes_secret_hier_eintragen
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
# Starten
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

## Sicherheitsarchitektur

```
Internet → [Nginx :80/:443] → [Backend :8001] → [MongoDB :27017]
              ↑                      ↑                 ↑
         öffentlich             nur intern        nur intern
```

| Port | Service | Von außen erreichbar |
|------|---------|---------------------|
| 80   | Nginx   | Ja (→ Redirect 443) |
| 443  | Nginx   | Ja (HTTPS)          |
| 8001 | Backend | Nein                |
| 27017| MongoDB | Nein                |

**Warum keine MongoDB-Authentifizierung?**
- MongoDB ist nur im Docker-Netzwerk erreichbar
- Kein Port nach außen exponiert
- Nginx ist der einzige Eintrittspunkt
- JWT sichert die API-Zugriffe

## Datenbank-Backup

```bash
# Backup erstellen
docker exec ipad-mongodb mongodump --out /data/backup

# Backup auf Host kopieren
docker cp ipad-mongodb:/data/backup ./backup

# Backup wiederherstellen
docker exec ipad-mongodb mongorestore /data/backup
```

## Troubleshooting

### Container-Logs prüfen
```bash
docker-compose logs backend
docker-compose logs mongodb
docker-compose logs nginx
```

### Neustart bei Problemen
```bash
docker-compose down
docker-compose up -d
```

### Daten komplett zurücksetzen (VORSICHT!)
```bash
docker-compose down -v  # Löscht auch das Datenbank-Volume!
docker-compose up -d
```
