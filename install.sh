#!/bin/bash

###############################################################################
# iPad-Verwaltungssystem - Installations-Script
# Version: 3.0 - Vereinfacht und optimiert
###############################################################################

# Prüfe ob das Script mit Bash ausgeführt wird
if [ -z "$BASH_VERSION" ]; then
    echo "FEHLER: Dieses Script benötigt Bash!"
    echo "Bitte verwende: bash $0"
    echo "Oder: sudo bash $0"
    exit 1
fi

set -e  # Bei Fehler abbrechen

# Stelle sicher, dass wir im Skript-Verzeichnis sind
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Farben für Ausgabe
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funktionen
print_header() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}    iPad-Verwaltungssystem - Installation${NC}"
    echo -e "${BLUE}    Version 3.0 mit RBAC${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

print_step() {
    echo -e "${GREEN}➜${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

# Prüfe System-Voraussetzungen
check_dependencies() {
    print_step "Überprüfe System-Voraussetzungen..."

    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker ist nicht installiert!"
        echo "Bitte installieren Sie Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi
    print_success "Docker gefunden: $(docker --version)"

    # Check Docker Compose (ältere Version zuerst prüfen)
    if command -v docker-compose &> /dev/null; then
        DOCKER_COMPOSE_CMD="docker-compose"
        print_success "Docker Compose gefunden (docker-compose)"
    elif docker compose version &> /dev/null; then
        DOCKER_COMPOSE_CMD="docker compose"
        print_success "Docker Compose gefunden (docker compose)"
    else
        print_error "Docker Compose ist nicht installiert!"
        echo "Bitte installieren Sie Docker Compose"
        exit 1
    fi

    echo ""
}

# Prüfe Projektstruktur
check_project_structure() {
    print_step "Überprüfe Projektstruktur..."

    local missing_dirs=()

    [ ! -d "frontend" ] && missing_dirs+=("frontend")
    [ ! -d "backend" ] && missing_dirs+=("backend")
    [ ! -d "config" ] && missing_dirs+=("config")

    if [ ${#missing_dirs[@]} -gt 0 ]; then
        print_error "Fehlende Verzeichnisse: ${missing_dirs[*]}"
        exit 1
    fi

    [ ! -f "backend/main.py" ] && print_error "backend/main.py fehlt!" && exit 1
    [ ! -f "frontend/package.json" ] && print_error "frontend/package.json fehlt!" && exit 1
    [ ! -f "config/docker-compose.yml" ] && print_error "config/docker-compose.yml fehlt!" && exit 1

    print_success "Projektstruktur ist vollständig"
    echo ""
}

# Setup Umgebungsvariablen
setup_environment() {
    print_step "Setup Umgebungsvariablen..."

    # Haupt-.env für Docker Compose (JWT_SECRET)
    if [ ! -f "config/.env" ]; then
        print_warning "config/.env fehlt - wird erstellt..."
        JWT_SECRET=$(openssl rand -hex 32)
        cat > config/.env << EOF
JWT_SECRET=$JWT_SECRET
EOF
        print_success "config/.env erstellt (JWT_SECRET generiert)"
    else
        print_success "config/.env bereits vorhanden"
    fi

    # Backend .env (für lokale Entwicklung)
    if [ ! -f "backend/.env" ]; then
        print_warning "backend/.env fehlt - wird erstellt..."
        cat > backend/.env << EOF
MONGO_URL=mongodb://localhost:27017/iPadDatabase
DB_NAME=iPadDatabase

EOF
        print_success "backend/.env erstellt"
    else
        print_success "backend/.env bereits vorhanden"
    fi

    # Frontend .env (für lokale Entwicklung)
    if [ ! -f "frontend/.env" ]; then
        print_warning "frontend/.env fehlt - wird erstellt..."
        cat > frontend/.env << EOF
REACT_APP_BACKEND_URL=http://localhost:8001
EOF
        print_success "frontend/.env erstellt"
    else
        print_success "frontend/.env bereits vorhanden"
    fi

    echo ""
}

# Baue Docker Container
build_containers() {
    print_step "Baue Docker Container..."
    echo "Das kann einige Minuten dauern..."
    echo ""

    cd config

    if $DOCKER_COMPOSE_CMD -f docker-compose.yml -f docker-compose.dev.yml build; then
        print_success "Container erfolgreich gebaut"
    else
        print_error "Fehler beim Bauen der Container"
        exit 1
    fi

    cd ..
    echo ""
}

# Starte Services
start_services() {
    print_step "Starte Services..."

    cd config

    if $DOCKER_COMPOSE_CMD -f docker-compose.yml -f docker-compose.dev.yml up -d; then
        print_success "Services gestartet"
    else
        print_error "Fehler beim Starten der Services"
        exit 1
    fi

    cd ..
    echo ""
}

# Warte auf Services
wait_for_services() {
    print_step "Warte auf Services..."

    echo -n "Warte auf MongoDB"
    for i in {1..30}; do
        if docker exec ipad_mongodb mongosh --eval "db.adminCommand('ping')" &> /dev/null; then
            echo ""
            print_success "MongoDB ist bereit"
            break
        fi
        echo -n "."
        sleep 2
    done

    echo -n "Warte auf Backend"
    for i in {1..30}; do
        if curl -sf http://localhost:8001/docs &> /dev/null; then
            echo ""
            print_success "Backend ist bereit"
            break
        fi
        echo -n "."
        sleep 2
    done

    echo -n "Warte auf Frontend"
    for i in {1..30}; do
        if curl -s http://localhost:3000 &> /dev/null; then
            echo ""
            print_success "Frontend ist bereit"
            break
        fi
        echo -n "."
        sleep 2
    done

    echo ""
}

# Zustand des Admin-Kontos nach init_database: vorhanden | angelegt | fehlt. Vorbelegt mit dem
# ungünstigsten Fall, damit der Abschlussbericht niemals Zugangsdaten nennt, die es nicht gibt.
ADMIN_ZUSTAND="fehlt"

# Initialisiere Datenbank mit Admin-User
init_database() {
    print_step "Initialisiere Datenbank..."

    # Prüfe ob Admin-User bereits existiert (korrekte Datenbank: iPadDatabase)
    ADMIN_EXISTS=$(docker exec ipad_mongodb mongosh iPadDatabase --quiet --eval "db.users.countDocuments({role: 'admin'})")

    if [ "$ADMIN_EXISTS" -gt 0 ]; then
        ADMIN_ZUSTAND="vorhanden"
        print_success "Admin-User bereits vorhanden"
    else
        print_warning "Erstelle Admin-User..."

        # Der Setup-Endpunkt legt nur noch an, wenn die Benutzerliste völlig leer ist. In jedem
        # anderen Fall antwortet er mit ein und derselben knappen Meldung - absichtlich, damit ein
        # unangemeldeter Aufrufer nicht erfährt, in welchem Zustand die Anlage ist. Für uns heißt
        # das: Nur der Anlege-Text zählt als Erfolg; eine Antwort mit irgendeinem "message"-Feld
        # bedeutet gar nichts. Genau darauf hat diese Prüfung früher hereingefallen.
        RESPONSE=$(curl -s -X POST http://localhost:8001/api/auth/setup)

        if echo "$RESPONSE" | grep -q "Admin user created successfully"; then
            ADMIN_ZUSTAND="angelegt"
            print_success "Admin-User angelegt (Login mit admin/admin123 möglich)"
        else
            print_error "Es wurde KEIN Admin-User angelegt - Antwort des Servers: $RESPONSE"

            # Warum nichts angelegt wurde, verrät der Endpunkt bewusst nicht. Hier läuft das
            # Skript aber auf dem Server selbst - also fragen wir die Datenbank direkt, um dem
            # Betreiber sagen zu können, was er nun tun muss. Ein Fehlschlag dieser Abfrage darf
            # die Installation nicht abbrechen: Sie dient allein dem Hinweis.
            BENUTZER_GESAMT=$(docker exec ipad_mongodb mongosh iPadDatabase --quiet --eval "db.users.countDocuments({})" 2>/dev/null || true)

            if [ "${BENUTZER_GESAMT:-x}" -gt 0 ] 2>/dev/null; then
                print_warning "Die Datenbank enthält $BENUTZER_GESAMT Benutzer, aber keinen Administrator."
                print_warning "Der Setup-Endpunkt legt aus Sicherheitsgründen nur in eine völlig leere"
                print_warning "Benutzerliste an - sonst stünde die Verwaltung jedem offen, der das"
                print_warning "Standardpasswort kennt. Die Login-Seite wiederholt den Aufruf deshalb"
                print_warning "auch NICHT. Ein Admin muss von Hand nachgetragen werden, zum Beispiel:"
                echo ""
                echo -e "  ${YELLOW}docker exec ipad_mongodb mongosh iPadDatabase --eval 'db.users.updateOne({username: \"IHR_BENUTZER\"}, {\$set: {role: \"admin\", is_active: true}})'${NC}"
            elif [ "$BENUTZER_GESAMT" = "0" ]; then
                print_warning "Die Benutzerliste ist leer - der Aufruf kam also gar nicht durch"
                print_warning "(Backend noch nicht bereit oder nicht erreichbar)."
                print_warning "Beim ersten Öffnen der Login-Seite wird der Setup-Aufruf wiederholt."
            else
                print_warning "Die Benutzerliste ließ sich nicht abfragen (Antwort: ${BENUTZER_GESAMT:-leer})."
                print_warning "Bitte von Hand prüfen, ob ein Administrator-Konto existiert."
            fi
        fi
    fi

    echo ""
}

# Zeige finale Informationen
print_final_info() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}    ✓ Installation erfolgreich abgeschlossen!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BLUE}Zugriff auf die Anwendung:${NC}"
    echo -e "  Frontend: ${GREEN}http://localhost:3000${NC}"
    echo -e "  Backend:  ${GREEN}http://localhost:8001${NC}"
    echo -e "  API Docs: ${GREEN}http://localhost:8001/docs${NC}"
    echo ""
    # Die Standard-Zugangsdaten nur nennen, wenn dieser Lauf das Konto auch wirklich angelegt
    # hat. Sonst versprechen sie einen Login, den es nicht gibt - und im Fall "fehlt" wiegten
    # sie den Betreiber in Sicherheit, obwohl er von Hand eingreifen muss.
    case "$ADMIN_ZUSTAND" in
        angelegt)
            echo -e "${BLUE}Standard-Login:${NC}"
            echo -e "  Benutzername: ${YELLOW}admin${NC}"
            echo -e "  Passwort:     ${YELLOW}admin123${NC}"
            echo -e "  Rolle:        ${YELLOW}Administrator${NC}"
            echo ""
            echo -e "${RED}⚠  WICHTIG: Ändern Sie das Admin-Passwort nach dem ersten Login!${NC}"
            ;;
        vorhanden)
            echo -e "${BLUE}Login:${NC}"
            echo -e "  Mit dem vorhandenen Administrator-Konto anmelden."
            ;;
        *)
            echo -e "${RED}⚠  Es existiert KEIN Administrator-Konto!${NC}"
            echo -e "${RED}   Die Anwendung läuft, aber niemand kann sie verwalten.${NC}"
            echo -e "${RED}   Siehe die Hinweise oben unter \"Initialisiere Datenbank\".${NC}"
            ;;
    esac
    echo ""
    echo -e "${BLUE}Nützliche Befehle:${NC}"
    echo -e "  In config-Verzeichnis:   ${YELLOW}cd config${NC}"
    echo -e "  Status anzeigen:         ${YELLOW}$DOCKER_COMPOSE_CMD ps${NC}"
    echo -e "  Logs anzeigen:           ${YELLOW}$DOCKER_COMPOSE_CMD logs -f${NC}"
    echo -e "  Backend-Logs:            ${YELLOW}$DOCKER_COMPOSE_CMD logs -f backend${NC}"
    echo -e "  Frontend-Logs:           ${YELLOW}$DOCKER_COMPOSE_CMD logs -f frontend${NC}"
    echo -e "  Services stoppen:        ${YELLOW}$DOCKER_COMPOSE_CMD down${NC}"
    echo -e "  Services neu starten:    ${YELLOW}$DOCKER_COMPOSE_CMD restart${NC}"
    echo ""
    echo -e "${BLUE}Deployment auf Produktions-Server:${NC}"
    echo -e "  Script verwenden:        ${YELLOW}./deploy-smart.sh${NC}"
    echo ""
    echo -e "${BLUE}RBAC-Funktionen:${NC}"
    echo -e "  • Multi-User-Unterstützung mit Rollenzuweisung"
    echo -e "  • Admins können Benutzer verwalten (Tab: Benutzer)"
    echo -e "  • Benutzer sehen nur ihre eigenen Daten"
    echo -e "  • Admins sehen alle Systemdaten"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

# Hauptprogramm
main() {
    print_header

    # Prüfungen
    check_dependencies
    check_project_structure

    # Setup
    setup_environment

    # Docker
    build_containers
    start_services

    # Warte auf Services
    wait_for_services

    # Datenbank
    init_database

    # Abschluss
    print_final_info
}

# Script ausführen
main
