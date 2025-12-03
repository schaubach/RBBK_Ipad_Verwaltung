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
    
    [ ! -f "backend/server.py" ] && print_error "backend/server.py fehlt!" && exit 1
    [ ! -f "frontend/package.json" ] && print_error "frontend/package.json fehlt!" && exit 1
    [ ! -f "config/docker-compose.yml" ] && print_error "config/docker-compose.yml fehlt!" && exit 1
    
    print_success "Projektstruktur ist vollständig"
    echo ""
}

# Setup Umgebungsvariablen
setup_environment() {
    print_step "Setup Umgebungsvariablen..."
    
    # Backend .env
    if [ ! -f "backend/.env" ]; then
        print_warning "backend/.env fehlt - wird erstellt..."
        cat > backend/.env << EOF
MONGO_URL=mongodb://mongodb:27017/ipad_management
SECRET_KEY=$(openssl rand -hex 32)
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
EOF
        print_success "backend/.env erstellt"
    else
        print_success "backend/.env bereits vorhanden"
    fi
    
    # Frontend .env
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
    
    if $DOCKER_COMPOSE_CMD build; then
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
    
    if $DOCKER_COMPOSE_CMD up -d; then
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
        if curl -s http://localhost:8001/health &> /dev/null; then
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

# Initialisiere Datenbank mit Admin-User
init_database() {
    print_step "Initialisiere Datenbank..."
    
    # Prüfe ob Admin-User bereits existiert
    ADMIN_EXISTS=$(docker exec ipad_mongodb mongosh ipad_management --quiet --eval "db.users.countDocuments({username: 'admin'})")
    
    if [ "$ADMIN_EXISTS" -gt 0 ]; then
        print_success "Admin-User bereits vorhanden"
    else
        print_warning "Erstelle Admin-User..."
        
        # Erstelle Admin-User über Backend-API
        RESPONSE=$(curl -s -X POST http://localhost:8001/api/auth/register \
            -H "Content-Type: application/json" \
            -d '{
                "username": "admin",
                "email": "admin@ipad-system.local",
                "password": "admin123",
                "role": "admin"
            }')
        
        if echo "$RESPONSE" | grep -q "id"; then
            print_success "Admin-User erstellt"
        else
            print_warning "Admin-User konnte nicht über API erstellt werden"
            print_warning "Erstelle direkt in Datenbank..."
            
            # Fallback: Direkt in Datenbank erstellen
            docker exec ipad-mongodb mongosh ipad_management --eval "
                db.users.insertOne({
                    id: 'admin-$(date +%s)',
                    username: 'admin',
                    email: 'admin@ipad-system.local',
                    hashed_password: '\$2b\$12\$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5aCPnZPxfNPxe',
                    role: 'admin',
                    is_active: true,
                    created_at: new Date()
                })
            " &> /dev/null
            
            print_success "Admin-User direkt in Datenbank erstellt"
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
    echo -e "${BLUE}Standard-Login:${NC}"
    echo -e "  Benutzername: ${YELLOW}admin${NC}"
    echo -e "  Passwort:     ${YELLOW}admin123${NC}"
    echo -e "  Rolle:        ${YELLOW}Administrator${NC}"
    echo ""
    echo -e "${RED}⚠  WICHTIG: Ändern Sie das Admin-Passwort nach dem ersten Login!${NC}"
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
    echo -e "${BLUE}Dokumentation:${NC}"
    echo -e "  Vollständige Doku:       ${GREEN}ENTWICKLERDOKUMENTATION.md${NC}"
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
