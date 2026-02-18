#!/bin/bash

###############################################################################
# System-Check: Prüft ob das iPad-System vollständig deinstalliert wurde
###############################################################################

# Prüfe ob das Script mit Bash ausgeführt wird
if [ -z "$BASH_VERSION" ]; then
    echo "FEHLER: Dieses Script benötigt Bash!"
    echo "Bitte verwende: bash $0"
    exit 1
fi

echo "════════════════════════════════════════════════════════"
echo "  🔍 System-Check: iPad-Verwaltungssystem"
echo "════════════════════════════════════════════════════════"
echo ""

# Prüfe Container
echo "📦 Container mit 'ipad' im Namen:"
CONTAINERS=$(docker ps -a --filter "name=ipad" --format "{{.Names}}\t{{.Status}}" 2>/dev/null)
if [ -z "$CONTAINERS" ]; then
    echo "   ✅ Keine Container gefunden"
else
    echo "$CONTAINERS"
fi
echo ""

# Prüfe Volumes
echo "💾 Volumes mit 'config_' im Namen:"
VOLUMES=$(docker volume ls --filter "name=config_" --format "{{.Name}}" 2>/dev/null)
if [ -z "$VOLUMES" ]; then
    echo "   ✅ Keine Volumes gefunden"
else
    echo "$VOLUMES"
fi
echo ""

# Prüfe Images
echo "🖼️  Images mit 'config-' im Namen:"
IMAGES=$(docker images --filter "reference=config-*" --format "{{.Repository}}:{{.Tag}}" 2>/dev/null)
if [ -z "$IMAGES" ]; then
    echo "   ✅ Keine Images gefunden"
else
    echo "$IMAGES"
fi
echo ""

# Prüfe .env Dateien
echo "⚙️  Konfigurationsdateien:"
if [ -f "config/.env" ]; then
    echo "   📄 config/.env existiert (JWT_SECRET)"
else
    echo "   ❌ config/.env nicht vorhanden"
fi

if [ -f "backend/.env" ]; then
    echo "   📄 backend/.env existiert"
else
    echo "   ❌ backend/.env nicht vorhanden"
fi

if [ -f "frontend/.env" ]; then
    echo "   📄 frontend/.env existiert"
else
    echo "   ❌ frontend/.env nicht vorhanden"
fi
echo ""

# Fazit
echo "════════════════════════════════════════════════════════"
if [ -z "$CONTAINERS" ] && [ -z "$VOLUMES" ]; then
    echo "✅ System ist sauber - bereit für Neuinstallation!"
    echo ""
    echo "Führe aus: ./install.sh"
else
    echo "⚠️  Es existieren noch Docker-Ressourcen"
    echo ""
    echo "Manuell aufräumen:"
    echo "  docker rm -f \$(docker ps -aq --filter 'name=ipad')"
    echo "  docker volume rm \$(docker volume ls -q --filter 'name=config_')"
fi
echo "════════════════════════════════════════════════════════"
echo ""
