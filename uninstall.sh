#!/bin/bash

###############################################################################
# iPad-Verwaltungssystem - Deinstallations-Script
# Entfernt alle Docker-Container, Volumes und optional Daten
###############################################################################

# Farben für Ausgabe
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Stelle sicher, dass wir im Skript-Verzeichnis sind
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

print_header() {
    echo -e "${RED}═══════════════════════════════════════════════════════${NC}"
    echo -e "${RED}    iPad-Verwaltungssystem - DEINSTALLATION${NC}"
    echo -e "${RED}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_step() {
    echo -e "${GREEN}➜${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Docker Compose Befehl ermitteln (ältere Version zuerst prüfen)
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker-compose"
    echo "Verwende: docker-compose (alte Version)"
elif docker compose version &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker compose"
    echo "Verwende: docker compose (neue Version)"
else
    echo -e "${RED}✗${NC} Docker Compose ist nicht installiert!"
    exit 1
fi

print_header

echo -e "${RED}ACHTUNG: Diese Aktion wird folgendes löschen:${NC}"
echo ""
echo "  1. Alle Docker-Container (frontend, backend, mongodb, nginx)"
echo "  2. Alle Docker-Volumes (MongoDB-Daten)"
echo "  3. Optional: .env-Dateien"
echo ""
echo -e "${YELLOW}Alle Daten (iPads, Schüler, Zuweisungen, Benutzer) gehen verloren!${NC}"
echo ""

# Sicherheitsabfrage
read -p "Möchten Sie fortfahren? (ja/nein): " confirm

if [ "$confirm" != "ja" ]; then
    echo ""
    print_warning "Deinstallation abgebrochen"
    exit 0
fi

echo ""
print_step "Starte Deinstallation..."
echo ""

# Stoppe alle Container
print_step "Stoppe alle Container..."
cd config
$DOCKER_COMPOSE_CMD down
cd ..
print_success "Container gestoppt"

# Lösche Container und Volumes
print_step "Lösche Container und Volumes..."
cd config
$DOCKER_COMPOSE_CMD down -v
cd ..
print_success "Container und Volumes gelöscht"

# Lösche spezifische Container falls sie noch existieren
print_step "Prüfe auf verbleibende Container..."
CONTAINERS=$(docker ps -a --filter "name=ipad-" --format "{{.Names}}")
if [ -n "$CONTAINERS" ]; then
    echo "Lösche verbleibende Container: $CONTAINERS"
    docker rm -f $CONTAINERS 2>/dev/null || true
    print_success "Verbleibende Container gelöscht"
else
    print_success "Keine verbleibenden Container gefunden"
fi

# Lösche spezifische Volumes
print_step "Prüfe auf verbleibende Volumes..."
VOLUMES=$(docker volume ls --filter "name=config_" --format "{{.Name}}")
if [ -n "$VOLUMES" ]; then
    echo "Lösche Volumes: $VOLUMES"
    docker volume rm $VOLUMES 2>/dev/null || true
    print_success "Volumes gelöscht"
else
    print_success "Keine Volumes gefunden"
fi

# Frage ob Images auch gelöscht werden sollen
echo ""
read -p "Möchten Sie auch die Docker-Images löschen? (j/n): " delete_images

if [ "$delete_images" = "j" ] || [ "$delete_images" = "J" ]; then
    print_step "Lösche Docker-Images..."
    docker images --filter "reference=config-*" --format "{{.Repository}}:{{.Tag}}" | xargs -r docker rmi -f 2>/dev/null || true
    print_success "Images gelöscht"
fi

# Frage ob .env Dateien gelöscht werden sollen
echo ""
read -p "Möchten Sie auch die .env-Dateien löschen? (j/n): " delete_env

if [ "$delete_env" = "j" ] || [ "$delete_env" = "J" ]; then
    print_step "Lösche .env-Dateien..."
    rm -f backend/.env
    rm -f frontend/.env
    print_success ".env-Dateien gelöscht"
else
    print_warning ".env-Dateien wurden behalten"
fi

# Optionales Aufräumen von Docker System
echo ""
read -p "Möchten Sie eine vollständige Docker-System-Bereinigung durchführen? (j/n): " cleanup_docker

if [ "$cleanup_docker" = "j" ] || [ "$cleanup_docker" = "J" ]; then
    print_step "Führe Docker System Cleanup durch..."
    docker system prune -f
    print_success "Docker System bereinigt"
fi

# Finale Zusammenfassung
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}    ✓ Deinstallation erfolgreich abgeschlossen!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}Das System wurde vollständig entfernt.${NC}"
echo ""
echo -e "${BLUE}Für eine Neuinstallation:${NC}"
echo -e "  ${YELLOW}./install.sh${NC}"
echo ""
echo -e "${BLUE}Projektdateien:${NC}"
echo -e "  Die Anwendungsdateien (Code) wurden ${GREEN}NICHT${NC} gelöscht."
echo -e "  Nur die Docker-Container und Daten wurden entfernt."
echo ""
