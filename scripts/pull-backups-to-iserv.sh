#!/bin/bash
# Holt die Backups vom Server auf diesen Mac und legt sie in einen IServ-Ordner.
#
# Warum dieser Weg: so liegt KEIN IServ-Zugang auf dem Server. Das IServ-Passwort bleibt
# im Schluesselbund dieses Macs, wo es hingehoert. Der Server kennt nur den oeffentlichen
# SSH-Schluessel dieses Rechners - und der laesst sich jederzeit zurueckziehen.
#
# Voraussetzung: IServ ist im Finder als WebDAV eingebunden (Finder > Gehe zu > Mit Server
# verbinden), und der Zielordner liegt unterhalb von /Volumes/.
#
# Einrichtung und automatischer Lauf: siehe scripts/BACKUP-OFFSITE.md

set -euo pipefail

CONF="${BACKUP_PULL_CONF:-$HOME/.config/ipad-verwaltung/backup-pull.conf}"
if [ ! -r "$CONF" ]; then
    echo "FEHLER: Konfiguration $CONF nicht lesbar." >&2
    echo "        Vorlage anlegen: siehe scripts/BACKUP-OFFSITE.md" >&2
    exit 1
fi
# shellcheck source=/dev/null
. "$CONF"

: "${SERVER:?SERVER ist in $CONF nicht gesetzt (z.B. schaubach@10.97.6.249)}"
: "${ISERV_DIR:?ISERV_DIR ist in $CONF nicht gesetzt (z.B. /Volumes/Files/Backups/iPad-Verwaltung)}"
REMOTE_DIR="${REMOTE_DIR:-/var/backups/ipad-verwaltung}"
LOCAL_CACHE="${LOCAL_CACHE:-$HOME/Library/Application Support/ipad-verwaltung-backups}"
KEEP_DAYS="${KEEP_DAYS:-30}"
MAX_AGE_HOURS="${MAX_AGE_HOURS:-36}"
PATTERN="rbbk_ipad_verwaltung_backup_*"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S')  $*"; }

# IServ muss eingebunden sein. Ohne diese Pruefung wuerde rsync munter in einen leeren
# lokalen Ordner schreiben, der nur so aussieht wie das Netzlaufwerk.
if [ ! -d "$ISERV_DIR" ]; then
    echo "FEHLER: $ISERV_DIR ist nicht erreichbar - IServ im Finder eingebunden?" >&2
    exit 1
fi

mkdir -p "$LOCAL_CACHE"

log "Hole Backups von $SERVER:$REMOTE_DIR"
rsync -az --timeout=120 \
    --include="$PATTERN" --exclude='*' \
    "$SERVER:$REMOTE_DIR/" "$LOCAL_CACHE/"

# Nach dem Zeitstempel IM DATEINAMEN sortieren, nicht nach der Aenderungszeit: beim
# Kopieren liegen die Zeiten dicht beieinander, der Name ist eindeutig und sortierbar.
NEWEST="$(ls -1 "$LOCAL_CACHE"/$PATTERN 2>/dev/null | sort | tail -1 || true)"
if [ -z "$NEWEST" ]; then
    echo "FEHLER: kein Backup geholt - erzeugt der Server noch welche?" >&2
    exit 1
fi

AGE_HOURS=$(( ( $(date +%s) - $(stat -f %m "$NEWEST") ) / 3600 ))
if [ "$AGE_HOURS" -gt "$MAX_AGE_HOURS" ]; then
    echo "FEHLER: neuestes Backup ist ${AGE_HOURS}h alt (Grenze: ${MAX_AGE_HOURS}h)." >&2
    echo "        $(basename "$NEWEST")" >&2
    exit 1
fi
log "Neuestes Backup: $(basename "$NEWEST") (${AGE_HOURS}h alt)"

log "Kopiere nach $ISERV_DIR"
rsync -a --include="$PATTERN" --exclude='*' "$LOCAL_CACHE/" "$ISERV_DIR/"

# Nachweisen statt vertrauen: rsync meldet auch dann Erfolg, wenn es nichts zu tun gab.
if [ ! -f "$ISERV_DIR/$(basename "$NEWEST")" ]; then
    echo "FEHLER: $(basename "$NEWEST") liegt nicht in $ISERV_DIR." >&2
    exit 1
fi
log "Bestaetigt: $(basename "$NEWEST") liegt bei IServ."

# Aufbewahrung getrennt von der des Servers (dort 7 Tage)
find "$LOCAL_CACHE" -maxdepth 1 -name "$PATTERN" -mtime "+$KEEP_DAYS" -delete 2>/dev/null || true
find "$ISERV_DIR"   -maxdepth 1 -name "$PATTERN" -mtime "+$KEEP_DAYS" -delete 2>/dev/null || true

COUNT="$(find "$ISERV_DIR" -maxdepth 1 -name "$PATTERN" | wc -l | tr -d ' ')"
log "Fertig. Backups bei IServ: $COUNT (Aufbewahrung ${KEEP_DAYS} Tage)"
