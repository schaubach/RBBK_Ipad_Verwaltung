#!/bin/bash

###############################################################################
# Frontend Debug Script - Findet heraus warum Frontend nicht erreichbar ist
###############################################################################

# Prüfe ob das Script mit Bash ausgeführt wird
if [ -z "$BASH_VERSION" ]; then
    echo "FEHLER: Dieses Script benötigt Bash!"
    echo "Bitte verwende: bash $0"
    exit 1
fi

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "════════════════════════════════════════════════════════"
echo "  🔍 Frontend Debug - Systematische Fehlersuche"
echo "════════════════════════════════════════════════════════"
echo ""

# 1. Container Status
printf "${BLUE}[1/7] Container Status${NC}\n"
echo "─────────────────────────────────────────────────────────"
docker ps --filter "name=ipad" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo ""

# 2. Frontend Build Container genauer prüfen
printf "${BLUE}[2/7] Frontend Build Container Details${NC}\n"
echo "─────────────────────────────────────────────────────────"
FRONTEND_STATUS=$(docker inspect ipad_frontend_build --format='{{.State.Status}}' 2>/dev/null)
if [ -z "$FRONTEND_STATUS" ]; then
    printf "${RED}✗ Frontend Container existiert nicht!${NC}\n"
elif [ "$FRONTEND_STATUS" = "running" ]; then
    printf "${GREEN}✓ Container läuft${NC}\n"
    
    # Prüfe ob Port 3000 im Container läuft
    docker exec ipad_frontend_build netstat -tlnp 2>/dev/null | grep :3000 || echo "⚠️  Port 3000 nicht gebunden"
else
    printf "${RED}✗ Container Status: $FRONTEND_STATUS${NC}\n"
fi
echo ""

# 3. Frontend Logs (letzte 30 Zeilen)
printf "${BLUE}[3/7] Frontend Build Logs (letzte 30 Zeilen)${NC}\n"
echo "─────────────────────────────────────────────────────────"
docker logs ipad_frontend_build --tail 30 2>&1
echo ""

# 4. Nginx Status
printf "${BLUE}[4/7] Nginx Container${NC}\n"
echo "─────────────────────────────────────────────────────────"
NGINX_STATUS=$(docker inspect ipad_nginx --format='{{.State.Status}}' 2>/dev/null)
if [ "$NGINX_STATUS" = "running" ]; then
    printf "${GREEN}✓ Nginx läuft${NC}\n"
    
    # Prüfe Health Status
    NGINX_HEALTH=$(docker inspect ipad_nginx --format='{{.State.Health.Status}}' 2>/dev/null)
    if [ "$NGINX_HEALTH" = "healthy" ]; then
        printf "${GREEN}✓ Nginx ist healthy${NC}\n"
    else
        printf "${YELLOW}⚠️  Nginx Health: $NGINX_HEALTH${NC}\n"
    fi
else
    printf "${RED}✗ Nginx Status: $NGINX_STATUS${NC}\n"
fi
echo ""

# 5. Nginx Logs
printf "${BLUE}[5/7] Nginx Error Logs (letzte 20 Zeilen)${NC}\n"
echo "─────────────────────────────────────────────────────────"
docker logs ipad_nginx --tail 20 2>&1 | grep -i error || echo "Keine Error-Logs gefunden"
echo ""

# 6. Port-Bindings prüfen
printf "${BLUE}[6/7] Port-Bindings${NC}\n"
echo "─────────────────────────────────────────────────────────"
echo "Erwartete Ports:"
echo "  - 3000: Frontend"
echo "  - 8001: Backend"
echo "  - 80: Nginx (optional)"
echo ""
echo "Aktuelle Port-Bindings:"
docker ps --filter "name=ipad" --format "{{.Names}}: {{.Ports}}"
echo ""

# 7. Verbindungstest
printf "${BLUE}[7/7] Verbindungstests${NC}\n"
echo "─────────────────────────────────────────────────────────"

# Test Frontend direkt
printf "Frontend (Port 3000): "
if curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 | grep -q "200\|301\|302"; then
    printf "${GREEN}✓ Erreichbar${NC}\n"
else
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000)
    printf "${RED}✗ Nicht erreichbar (HTTP $HTTP_CODE)${NC}\n"
fi

# Test Backend
printf "Backend (Port 8001): "
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8001/health | grep -q "200"; then
    printf "${GREEN}✓ Erreichbar${NC}\n"
else
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8001/health)
    printf "${RED}✗ Nicht erreichbar (HTTP $HTTP_CODE)${NC}\n"
fi

# Test Nginx
printf "Nginx (Port 80):     "
if curl -s -o /dev/null -w "%{http_code}" http://localhost:80 2>/dev/null | grep -q "200\|301\|302"; then
    printf "${GREEN}✓ Erreichbar${NC}\n"
else
    printf "${YELLOW}⚠️  Nicht konfiguriert oder nicht erreichbar${NC}\n"
fi

echo ""
echo "════════════════════════════════════════════════════════"
printf "${YELLOW}📋 DIAGNOSE & LÖSUNGEN${NC}\n"
echo "════════════════════════════════════════════════════════"
echo ""

# Automatische Diagnose
FRONTEND_RUNNING=$(docker ps --filter "name=ipad_frontend_build" --filter "status=running" -q)
FRONTEND_LOGS=$(docker logs ipad_frontend_build 2>&1 | tail -10)

if [ -z "$FRONTEND_RUNNING" ]; then
    echo "❌ PROBLEM: Frontend Container läuft nicht"
    echo ""
    echo "LÖSUNG:"
    echo "  cd config && docker-compose restart frontend"
    echo ""
elif echo "$FRONTEND_LOGS" | grep -qi "error\|failed\|cannot"; then
    echo "⚠️  PROBLEM: Frontend Build hat Fehler"
    echo ""
    echo "Mögliche Ursachen:"
    echo "  - Node Module fehlen"
    echo "  - Build-Fehler in React"
    echo ""
    echo "LÖSUNG 1 - Rebuild ohne Cache:"
    echo "  cd config"
    echo "  docker-compose stop frontend"
    echo "  docker-compose build --no-cache frontend"
    echo "  docker-compose up -d frontend"
    echo ""
    echo "LÖSUNG 2 - In Container debuggen:"
    echo "  docker exec -it ipad_frontend_build sh"
    echo "  cd /app && yarn start"
    echo ""
elif ! curl -s http://localhost:3000 &> /dev/null; then
    echo "⚠️  PROBLEM: Frontend läuft, aber Port 3000 nicht erreichbar"
    echo ""
    echo "Mögliche Ursachen:"
    echo "  - Port-Binding fehlt in docker-compose.yml"
    echo "  - Firewall blockiert Port 3000"
    echo "  - React Dev Server läuft nicht"
    echo ""
    echo "LÖSUNG 1 - Prüfe Port-Binding:"
    echo "  cat config/docker-compose.yml | grep -A 5 frontend"
    echo ""
    echo "LÖSUNG 2 - Prüfe ob React läuft:"
    echo "  docker exec ipad_frontend_build ps aux | grep node"
    echo ""
    echo "LÖSUNG 3 - Manuell starten:"
    echo "  docker exec -it ipad_frontend_build sh"
    echo "  cd /app && yarn start"
    echo ""
else
    echo "✅ Frontend scheint zu laufen!"
    echo ""
    echo "Wenn du es trotzdem nicht erreichen kannst:"
    echo "  - Prüfe Browser-Cache (Strg+Shift+R)"
    echo "  - Prüfe Firewall-Einstellungen"
    echo "  - Versuche: http://127.0.0.1:3000"
    echo ""
fi

echo "════════════════════════════════════════════════════════"
echo ""
