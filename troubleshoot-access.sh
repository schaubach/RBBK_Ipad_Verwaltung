#!/bin/bash

###############################################################################
# Troubleshoot Access - Prüft alle Zugriffsmöglichkeiten
###############################################################################

if [ -z "$BASH_VERSION" ]; then
    echo "FEHLER: Dieses Script benötigt Bash!"
    echo "Bitte verwende: bash $0"
    exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "════════════════════════════════════════════════════════"
echo "  🔍 Zugriffs-Troubleshooting"
echo "════════════════════════════════════════════════════════"
echo ""

# Prüfe welche Ports offen sind
printf "${BLUE}Exponierte Ports:${NC}\n"
echo "─────────────────────────────────────────────────────────"
docker ps --filter "name=ipad" --format "{{.Names}}: {{.Ports}}"
echo ""

# Test alle möglichen Zugriffspunkte
printf "${BLUE}Zugriffstests:${NC}\n"
echo "─────────────────────────────────────────────────────────"

# Test 1: Nginx Port 80
printf "1. Nginx (Port 80):           "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:80 2>/dev/null)
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "304" ]; then
    printf "${GREEN}✓ Erreichbar (HTTP $HTTP_CODE)${NC}\n"
    echo "   → Öffne: http://localhost"
elif [ "$HTTP_CODE" = "000" ]; then
    printf "${RED}✗ Keine Verbindung möglich${NC}\n"
    echo "   → Port 80 ist nicht erreichbar"
else
    printf "${YELLOW}⚠ HTTP $HTTP_CODE${NC}\n"
fi

# Test 2: Backend Port 8001
printf "2. Backend (Port 8001):       "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8001/docs 2>/dev/null)
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "307" ]; then
    printf "${GREEN}✓ Erreichbar (HTTP $HTTP_CODE)${NC}\n"
    echo "   → Öffne: http://localhost:8001/docs"
elif [ "$HTTP_CODE" = "000" ]; then
    printf "${RED}✗ Keine Verbindung möglich${NC}\n"
    echo "   → Port 8001 ist nicht exponiert oder blockiert"
else
    printf "${YELLOW}⚠ HTTP $HTTP_CODE${NC}\n"
fi

# Test 3: Frontend Port 3000 (falls exponiert)
printf "3. Frontend (Port 3000):      "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 2>/dev/null)
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "304" ]; then
    printf "${GREEN}✓ Erreichbar (HTTP $HTTP_CODE)${NC}\n"
    echo "   → Öffne: http://localhost:3000"
elif [ "$HTTP_CODE" = "000" ]; then
    printf "${YELLOW}⚠ Nicht exponiert${NC}\n"
    echo "   → Frontend läuft nur über Nginx (Port 80)"
else
    printf "${YELLOW}⚠ HTTP $HTTP_CODE${NC}\n"
fi

# Test 4: MongoDB Port 27017
printf "4. MongoDB (Port 27017):      "
if nc -z localhost 27017 2>/dev/null; then
    printf "${GREEN}✓ Erreichbar${NC}\n"
    echo "   → Für DB-Tools: mongodb://localhost:27017"
else
    printf "${YELLOW}⚠ Nicht exponiert (normal für Produktion)${NC}\n"
fi

echo ""
echo "════════════════════════════════════════════════════════"
printf "${YELLOW}📋 EMPFOHLENE ZUGRIFFSMETHODE${NC}\n"
echo "════════════════════════════════════════════════════════"
echo ""

# Finde die beste Zugriffsmethode
NGINX_WORKS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:80 2>/dev/null)
BACKEND_WORKS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8001 2>/dev/null)

if [ "$NGINX_WORKS" = "200" ] || [ "$NGINX_WORKS" = "304" ]; then
    printf "${GREEN}✅ Verwende Nginx (empfohlen):${NC}\n"
    echo ""
    echo "   Frontend: http://localhost"
    echo "   Backend:  http://localhost/api/"
    echo ""
    echo "   Dies ist die Produktions-Architektur."
    echo ""
elif [ "$BACKEND_WORKS" = "200" ]; then
    printf "${YELLOW}⚠️  Nginx nicht erreichbar, aber Backend läuft:${NC}\n"
    echo ""
    echo "   Backend API Docs: http://localhost:8001/docs"
    echo ""
    echo "   Problem: Port 80 ist blockiert oder belegt"
    echo ""
    echo "   LÖSUNGEN:"
    echo "   1. Prüfe ob anderer Webserver läuft:"
    echo "      sudo netstat -tlnp | grep :80"
    echo ""
    echo "   2. Verwende alternativen Port (z.B. 8080):"
    echo "      Bearbeite config/docker-compose.yml:"
    echo "      nginx ports: - \"8080:80\""
    echo "      Dann: http://localhost:8080"
    echo ""
else
    printf "${RED}❌ Weder Nginx noch Backend erreichbar!${NC}\n"
    echo ""
    echo "   PROBLEM: Container laufen nicht oder Ports sind blockiert"
    echo ""
    echo "   LÖSUNGEN:"
    echo "   1. Prüfe Container Status:"
    echo "      docker ps --filter 'name=ipad'"
    echo ""
    echo "   2. Prüfe Container Logs:"
    echo "      docker logs ipad_nginx"
    echo "      docker logs ipad_backend"
    echo ""
    echo "   3. Starte Container neu:"
    echo "      cd config && docker-compose restart"
    echo ""
fi

echo "════════════════════════════════════════════════════════"
echo ""

# Zusätzliche Checks
printf "${BLUE}Zusätzliche Diagnose:${NC}\n"
echo "─────────────────────────────────────────────────────────"

# Prüfe ob Port 80 belegt ist
PORT_80_USED=$(sudo netstat -tlnp 2>/dev/null | grep ":80 " | grep -v "ipad_nginx" || true)
if [ -n "$PORT_80_USED" ]; then
    printf "${YELLOW}⚠️  Port 80 wird von anderem Prozess verwendet:${NC}\n"
    echo "$PORT_80_USED"
    echo ""
    echo "Lösung: Stoppe den anderen Service oder verwende anderen Port"
    echo ""
fi

# Prüfe Firewall (nur Linux)
if command -v ufw &> /dev/null; then
    UFW_STATUS=$(sudo ufw status 2>/dev/null | grep "80/tcp")
    if [ -n "$UFW_STATUS" ]; then
        echo "Firewall-Regel für Port 80:"
        echo "$UFW_STATUS"
    fi
fi

echo "════════════════════════════════════════════════════════"
echo ""
