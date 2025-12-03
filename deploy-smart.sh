#!/bin/bash

# SMART DEPLOYMENT für Frontend + Backend
# Erkennt automatisch, was geändert wurde und baut nur das Nötige
# Verwendung: sudo bash deploy-smart.sh

echo "════════════════════════════════════════════════════════"
echo "  🚀 Smart Deployment - Frontend + Backend"
echo "════════════════════════════════════════════════════════"
echo ""

# Docker Compose Befehl ermitteln
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker-compose"
    echo "ℹ️  Verwende: docker-compose (alte Version)"
elif docker compose version &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker compose"
    echo "ℹ️  Verwende: docker compose (neue Version)"
else
    echo "❌ Fehler: Docker Compose ist nicht installiert!"
    exit 1
fi
echo ""

# Finde das richtige Verzeichnis
# Prüfe zuerst, ob wir im Hauptverzeichnis sind (wo config/ als Unterverzeichnis liegt)
if [ -d "./config" ]; then
    CONFIG_DIR="./config"
    echo "📍 Erkannt: Hauptverzeichnis (./config gefunden)"
# Oder ob wir bereits im config-Verzeichnis sind
elif [ -f "./docker-compose.yml" ]; then
    CONFIG_DIR="."
    echo "📍 Erkannt: Bereits im config-Verzeichnis"
# Oder absolute Pfade
elif [ -d "/home/RBBK_Ipad_Verwaltung-main/config" ]; then
    CONFIG_DIR="/home/RBBK_Ipad_Verwaltung-main/config"
    echo "📍 Erkannt: Absoluter Pfad (Produktions-Server)"
elif [ -d "/app/config" ]; then
    CONFIG_DIR="/app/config"
    echo "📍 Erkannt: Absoluter Pfad (Entwicklungs-System)"
else
    echo "❌ Fehler: config-Verzeichnis nicht gefunden!"
    echo ""
    echo "   Aktuelles Verzeichnis: $(pwd)"
    echo "   Inhalt: $(ls -la | head -5)"
    echo ""
    echo "   Bitte führe das Script aus:"
    echo "   cd /home/RBBK_Ipad_Verwaltung-main && sudo bash deploy-smart.sh"
    echo ""
    echo "   ODER"
    echo ""
    echo "   cd /home/RBBK_Ipad_Verwaltung-main/config && sudo bash ../deploy-smart.sh"
    exit 1
fi

cd "$CONFIG_DIR" || {
    echo "❌ Fehler: Konnte nicht in $CONFIG_DIR wechseln!"
    exit 1
}
echo "📍 Arbeitsverzeichnis: $(pwd)"
echo ""

# Frage den Nutzer, was geändert wurde
echo "═══════════════════════════════════════════════════════"
echo "  Was wurde geändert?"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "  1) Nur Frontend (App.js, CSS, etc.)"
echo "  2) Nur Backend (server.py, etc.)"
echo "  3) Beides (Frontend + Backend)"
echo "  4) package.json oder requirements.txt geändert (FULL BUILD)"
echo ""
read -p "Deine Auswahl [1-4]: " CHOICE
echo ""

BUILD_FRONTEND=false
BUILD_BACKEND=false
NO_CACHE=false

case $CHOICE in
    1)
        echo "✅ Auswahl: Nur Frontend"
        BUILD_FRONTEND=true
        ;;
    2)
        echo "✅ Auswahl: Nur Backend"
        BUILD_BACKEND=true
        ;;
    3)
        echo "✅ Auswahl: Frontend + Backend"
        BUILD_FRONTEND=true
        BUILD_BACKEND=true
        ;;
    4)
        echo "✅ Auswahl: Full Build (Frontend + Backend ohne Cache)"
        BUILD_FRONTEND=true
        BUILD_BACKEND=true
        NO_CACHE=true
        ;;
    *)
        echo "❌ Ungültige Auswahl!"
        exit 1
        ;;
esac

echo ""
echo "════════════════════════════════════════════════════════"
echo "  🚀 Starte Deployment..."
echo "════════════════════════════════════════════════════════"
echo ""

# Schritt 1: Container stoppen
echo "🛑 [1/5] Stoppe alle Container..."
$DOCKER_COMPOSE_CMD down
echo "✅ Container gestoppt"
echo ""

# Schritt 2: Cleanup
echo "🗑️  [2/5] Cleanup..."
if [ "$BUILD_FRONTEND" = true ]; then
    docker rm -f ipad_frontend_build 2>/dev/null && echo "   ✅ Frontend-Container gelöscht" || echo "   ⚠️  Frontend-Container existierte nicht"
    docker volume rm config_frontend_build 2>/dev/null && echo "   ✅ Frontend-Volume gelöscht" || echo "   ⚠️  Frontend-Volume existierte nicht"
fi
if [ "$BUILD_BACKEND" = true ]; then
    docker rm -f ipad_backend 2>/dev/null && echo "   ✅ Backend-Container gelöscht" || echo "   ⚠️  Backend-Container existierte nicht"
fi
echo ""

# Schritt 3: Build
echo "🔨 [3/5] Baue Container..."

if [ "$BUILD_BACKEND" = true ]; then
    echo "   📦 Baue Backend..."
    if [ "$NO_CACHE" = true ]; then
        echo "      (ohne Cache - pip install läuft neu)"
        $DOCKER_COMPOSE_CMD build --no-cache backend
    else
        echo "      (mit Cache)"
        $DOCKER_COMPOSE_CMD build backend
    fi
    
    if [ $? -ne 0 ]; then
        echo "❌ Backend-Build fehlgeschlagen!"
        exit 1
    fi
    echo "   ✅ Backend erfolgreich gebaut"
fi

if [ "$BUILD_FRONTEND" = true ]; then
    echo "   📦 Baue Frontend..."
    if [ "$NO_CACHE" = true ]; then
        echo "      (ohne Cache - yarn install läuft neu)"
        docker-compose build --no-cache frontend
    else
        echo "      (mit Cache - yarn install wird gecached)"
        docker-compose build frontend
    fi
    
    if [ $? -ne 0 ]; then
        echo "❌ Frontend-Build fehlgeschlagen!"
        exit 1
    fi
    echo "   ✅ Frontend erfolgreich gebaut"
fi

echo "✅ Build abgeschlossen"
echo ""

# Schritt 4: Container starten
echo "🚀 [4/5] Starte alle Container..."
docker-compose up -d
echo "✅ Container gestartet"
echo ""

# Schritt 5: Status prüfen
echo "⏳ [5/5] Warte 10 Sekunden auf Container-Start..."
sleep 10
echo ""

echo "📋 Container-Status:"
docker ps --filter "name=ipad" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo ""

# Prüfe ob alle Container laufen
RUNNING=$(docker ps --filter "name=ipad" --filter "status=running" | wc -l)
EXPECTED=4  # frontend_build, backend, nginx, mongodb

if [ "$RUNNING" -lt 3 ]; then
    echo "⚠️  Warnung: Nicht alle Container laufen!"
    echo ""
    echo "🔍 Logs prüfen:"
    echo "   docker logs ipad_backend"
    echo "   docker logs ipad_frontend_build"
    echo "   docker logs ipad_nginx"
else
    echo "✅ Alle Container laufen!"
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "✅ DEPLOYMENT ABGESCHLOSSEN!"
echo "════════════════════════════════════════════════════════"
echo ""

# Zeige was gebaut wurde
if [ "$BUILD_FRONTEND" = true ] && [ "$BUILD_BACKEND" = true ]; then
    echo "📦 Gebaut: Frontend + Backend"
    if [ "$NO_CACHE" = true ]; then
        echo "⏱️  Dauer: ~5-7 Minuten (Full Build)"
    else
        echo "⏱️  Dauer: ~3-4 Minuten"
    fi
elif [ "$BUILD_FRONTEND" = true ]; then
    echo "📦 Gebaut: Nur Frontend"
    echo "⏱️  Dauer: ~2-3 Minuten"
elif [ "$BUILD_BACKEND" = true ]; then
    echo "📦 Gebaut: Nur Backend"
    echo "⏱️  Dauer: ~1-2 Minuten"
fi

echo ""
echo "🌐 WICHTIG - Jetzt im Browser:"
echo "   1. Drücke: Strg + Shift + Entf"
echo "   2. Wähle: Cache/Zwischengespeicherte Dateien"
echo "   3. Klicke: Daten löschen"
echo "   4. Drücke: Strg + F5 (Hard Reload)"
echo ""
echo "🔍 Bei Problemen Logs prüfen:"
echo "   docker logs ipad_backend"
echo "   docker logs ipad_nginx"
echo "   docker logs ipad_frontend_build"
echo ""
echo "════════════════════════════════════════════════════════"
