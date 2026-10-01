#!/bin/bash
# Erzeugt ein selbstsigniertes TLS-Zertifikat fuer nginx.
#
# Der private Schluessel darf NICHT in die Versionsverwaltung - er wird deshalb
# auf dem jeweiligen Server erzeugt und von .gitignore ausgeschlossen. Ein frisch
# geklontes Repo hat also kein Zertifikat; deploy-smart.sh ruft dieses Skript auf,
# bevor die Container starten.
#
# Verwendung:
#   bash nginx/generate-ssl-cert.sh              # nur erzeugen, wenn noch keines da ist
#   bash nginx/generate-ssl-cert.sh --force      # vorhandenes ersetzen (Schluesseltausch)
#   bash nginx/generate-ssl-cert.sh --force 10.97.6.249 ipad.rbbk-do.de

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSL_DIR="$SCRIPT_DIR/ssl"   # nginx mountet ../nginx/ssl nach /etc/nginx/ssl
CRT="$SSL_DIR/server.crt"
KEY="$SSL_DIR/server.key"
DAYS=825

mkdir -p "$SSL_DIR"

FORCE=false
HOSTS=()
for arg in "$@"; do
    if [ "$arg" = "--force" ]; then FORCE=true; else HOSTS+=("$arg"); fi
done

if [ -f "$CRT" ] && [ -f "$KEY" ] && [ "$FORCE" = false ]; then
    echo "✅ Zertifikat vorhanden: $CRT"
    openssl x509 -in "$CRT" -noout -subject -dates 2>/dev/null || true
    echo "   (Neuerzeugung mit: bash nginx/generate-ssl-cert.sh --force)"
    exit 0
fi

# Ohne Angabe: alle IPv4-Adressen des Hosts als SAN aufnehmen, damit der Zugriff
# ueber die Server-IP keine zusaetzliche Zertifikatswarnung ausloest.
if [ ${#HOSTS[@]} -eq 0 ]; then
    if command -v hostname >/dev/null && hostname -I >/dev/null 2>&1; then
        read -r -a HOSTS <<< "$(hostname -I)"
    fi
    HOSTS+=("$(hostname -f 2>/dev/null || hostname)")
fi

SAN="DNS:localhost,IP:127.0.0.1"
for h in "${HOSTS[@]}"; do
    [ -z "$h" ] && continue
    if [[ "$h" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        SAN="$SAN,IP:$h"
    else
        SAN="$SAN,DNS:$h"
    fi
done

echo "🔐 Erzeuge neues Zertifikat (gueltig $DAYS Tage)"
echo "   SAN: $SAN"

CONF="$(mktemp)"
trap 'rm -f "$CONF"' EXIT
cat > "$CONF" <<CONFEOF
[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
C = DE
ST = Nordrhein-Westfalen
L = Dortmund
O = Robert-Bosch-Berufskolleg
OU = IT
CN = iPad-Verwaltung
[v3]
subjectAltName = $SAN
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
CONFEOF

openssl req -x509 -newkey rsa:4096 -nodes -days "$DAYS" \
    -keyout "$KEY" -out "$CRT" -config "$CONF" >/dev/null 2>&1

chmod 600 "$KEY"
chmod 644 "$CRT"

echo "✅ Fertig:"
openssl x509 -in "$CRT" -noout -subject -dates
echo ""
echo "⚠️  Der private Schluessel bleibt auf diesem Server und gehoert nicht ins Repo."
