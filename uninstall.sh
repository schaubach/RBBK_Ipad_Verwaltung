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
    printf "${RED}═══════════════════════════════════════════════════════${NC}\n"
    printf "${RED}    iPad-Verwaltungssystem - DEINSTALLATION${NC}\n"
    printf "${RED}═══════════════════════════════════════════════════════${NC}\n"
    echo ""
}

print_warning() {
    printf "${YELLOW}⚠${NC} $1\n"
}

print_step() {
    printf "${GREEN}➜${NC} $1\n"
}

print_success() {
    printf "${GREEN}✓${NC} $1\n"
}

print_error() {
    printf "${RED}✗${NC} $1\n"
}

print_header

printf "${RED}ACHTUNG: Diese Aktion wird folgendes löschen:${NC}\n"
echo ""
echo "  1. Alle Docker-Container (frontend, backend, mongodb, nginx)"
echo "  2. Alle Docker-Volumes (MongoDB-Daten)"
echo "  3. Alle Docker-Images vom Projekt"
echo "  4. Optional: .env-Dateien"
echo ""
printf "${YELLOW}Alle Daten (iPads, Schüler, Zuweisungen, Benutzer) gehen verloren!${NC}\n"
echo ""

# Sicherheitsabfrage
read -p "Möchten Sie fortfahren? (ja/nein): " confirm

if [ "$confirm" != "ja" ]; then
    echo ""
    print_warning "Deinstallation abgebrochen"
    exit 0
fi

echo ""
print_step "Starte vollständige Deinstallation..."
echo ""

# Zeige was gefunden wurde
print_step "Suche nach iPad-System Ressourcen..."
CONTAINERS=$(docker ps -a --filter "name=ipad" --format "{{.Names}}" 2>/dev/null | tr '\n' ' ')
VOLUMES=$(docker volume ls --filter "name=config_" --format "{{.Name}}" 2>/dev/null | tr '\n' ' ')
IMAGES=$(docker images --filter "reference=config-*" --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | tr '\n' ' ')

if [ -n "$CONTAINERS" ]; then
    echo "   Gefundene Container: $CONTAINERS"
else
    echo "   Keine Container gefunden"
fi

if [ -n "$VOLUMES" ]; then
    echo "   Gefundene Volumes: $VOLUMES"
else
    echo "   Keine Volumes gefunden"
fi

if [ -n "$IMAGES" ]; then
    echo "   Gefundene Images: $IMAGES"
else
    echo "   Keine Images gefunden"
fi
echo ""

# Stoppe alle Container
print_step "Stoppe alle laufenden Container..."
RUNNING_CONTAINERS=$(docker ps --filter "name=ipad" --format "{{.Names}}" 2>/dev/null)
if [ -n "$RUNNING_CONTAINERS" ]; then
    echo "$RUNNING_CONTAINERS" | xargs docker stop 2>/dev/null || true
    print_success "Container gestoppt"
else
    print_success "Keine laufenden Container gefunden"
fi

# Lösche alle Container
print_step "Lösche alle Container..."
ALL_CONTAINERS=$(docker ps -a --filter "name=ipad" --format "{{.Names}}" 2>/dev/null)
if [ -n "$ALL_CONTAINERS" ]; then
    echo "$ALL_CONTAINERS" | xargs docker rm -f 2>/dev/null || true
    print_success "Container gelöscht: $ALL_CONTAINERS"
else
    print_success "Keine Container zu löschen"
fi

# Lösche alle Volumes
print_step "Lösche alle Volumes..."
ALL_VOLUMES=$(docker volume ls --filter "name=config_" --format "{{.Name}}" 2>/dev/null)
if [ -n "$ALL_VOLUMES" ]; then
    echo "$ALL_VOLUMES" | xargs docker volume rm -f 2>/dev/null || true
    print_success "Volumes gelöscht: $ALL_VOLUMES"
else
    print_success "Keine Volumes zu löschen"
fi

# Frage ob Images auch gelöscht werden sollen
echo ""
read -p "Möchten Sie auch die Docker-Images löschen? (j/n): " delete_images

if [ "$delete_images" = "j" ] || [ "$delete_images" = "J" ]; then
    print_step "Lösche Docker-Images..."
    ALL_IMAGES=$(docker images --filter "reference=config-*" --format "{{.Repository}}:{{.Tag}}" 2>/dev/null)
    if [ -n "$ALL_IMAGES" ]; then
        echo "$ALL_IMAGES" | xargs docker rmi -f 2>/dev/null || true
        print_success "Images gelöscht"
    else
        print_success "Keine Images zu löschen"
    fi
fi

# Frage ob .env Dateien gelöscht werden sollen
echo ""
read -p "Möchten Sie auch die .env-Dateien löschen? (j/n): " delete_env

if [ "$delete_env" = "j" ] || [ "$delete_env" = "J" ]; then
    print_step "Lösche .env-Dateien..."
    rm -f backend/.env 2>/dev/null || true
    rm -f frontend/.env 2>/dev/null || true
    print_success ".env-Dateien gelöscht"
else
    print_warning ".env-Dateien wurden behalten"
fi

# Optionales Aufräumen von Docker System
echo ""
read -p "Möchten Sie eine vollständige Docker-System-Bereinigung durchführen? (j/n): " cleanup_docker

if [ "$cleanup_docker" = "j" ] || [ "$cleanup_docker" = "J" ]; then
    print_step "Führe Docker System Cleanup durch..."
    docker system prune -f 2>/dev/null || true
    print_success "Docker System bereinigt"
fi

# Führe finalen Check durch
echo ""
print_step "Führe finalen Check durch..."
REMAINING_CONTAINERS=$(docker ps -a --filter "name=ipad" --format "{{.Names}}" 2>/dev/null)
REMAINING_VOLUMES=$(docker volume ls --filter "name=config_" --format "{{.Name}}" 2>/dev/null)

if [ -z "$REMAINING_CONTAINERS" ] && [ -z "$REMAINING_VOLUMES" ]; then
    print_success "Alle Ressourcen erfolgreich entfernt!"
else
    if [ -n "$REMAINING_CONTAINERS" ]; then
        print_warning "Noch vorhandene Container: $REMAINING_CONTAINERS"
    fi
    if [ -n "$REMAINING_VOLUMES" ]; then
        print_warning "Noch vorhandene Volumes: $REMAINING_VOLUMES"
    fi
fi

# Finale Zusammenfassung
echo ""
printf "${GREEN}═══════════════════════════════════════════════════════${NC}\n"
printf "${GREEN}    ✓ Deinstallation abgeschlossen!${NC}\n"
printf "${GREEN}═══════════════════════════════════════════════════════${NC}\n"
echo ""
printf "${BLUE}Das System wurde entfernt.${NC}\n"
echo ""
printf "${BLUE}Für eine Neuinstallation:${NC}\n"
printf "  ${YELLOW}./install.sh${NC}\n"
echo ""
printf "${BLUE}Status prüfen:${NC}\n"
printf "  ${YELLOW}./check-system.sh${NC}\n"
echo ""
printf "${BLUE}Projektdateien:${NC}\n"
printf "  Die Anwendungsdateien (Code) wurden ${GREEN}NICHT${NC} gelöscht.\n"
printf "  Nur die Docker-Container und Daten wurden entfernt.\n"
echo ""
