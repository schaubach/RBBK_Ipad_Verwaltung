#!/bin/bash
# Holt die Backups vom Server auf diesen Mac und laedt sie zu IServ hoch.
#
# Warum dieser Weg: so liegt KEIN IServ-Zugang auf dem Server. Das IServ-Passwort steht im
# Schluesselbund dieses Macs, nicht in einer Datei. Der Server kennt nur den oeffentlichen
# SSH-Schluessel dieses Rechners - und der laesst sich jederzeit zurueckziehen.
#
# Hochgeladen wird direkt per WebDAV, nicht ueber ein im Finder eingebundenes Laufwerk.
# Zwei Gruende: ein solcher Mount ueberlebt keinen Neustart, und macOS verweigert
# Hintergrundprozessen den Zugriff auf Netzlaufwerke - der naechtliche Job wuerde daran
# scheitern, waehrend derselbe Aufruf im Terminal funktioniert.
#
# Einrichtung: siehe scripts/BACKUP-OFFSITE.md

set -euo pipefail

CONF="${BACKUP_PULL_CONF:-$HOME/.config/ipad-verwaltung/backup-pull.conf}"
if [ ! -r "$CONF" ]; then
    echo "FEHLER: Konfiguration $CONF nicht lesbar." >&2
    exit 1
fi
# shellcheck source=/dev/null
. "$CONF"

: "${SERVER:?SERVER ist in $CONF nicht gesetzt (z.B. schaubach@10.97.6.249)}"
: "${WEBDAV_URL:?WEBDAV_URL ist in $CONF nicht gesetzt}"
: "${WEBDAV_USER:?WEBDAV_USER ist in $CONF nicht gesetzt}"
REMOTE_DIR="${REMOTE_DIR:-/var/backups/ipad-verwaltung}"
LOCAL_CACHE="${LOCAL_CACHE:-$HOME/Library/Application Support/ipad-verwaltung-backups}"
KEYCHAIN_SERVICE="${KEYCHAIN_SERVICE:-iserv-webdav}"
KEEP_DAYS="${KEEP_DAYS:-20}"
MAX_AGE_HOURS="${MAX_AGE_HOURS:-36}"
PATTERN="rbbk_ipad_verwaltung_backup_*"
WEBDAV_URL="${WEBDAV_URL%/}"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S')  $*"; }

# Auch in die Fehlerausgabe eine datierte Startzeile schreiben. launchd haengt an seine
# Protokolldateien an und leert sie nie - ohne Marke sieht eine Fehlermeldung von vor Tagen
# aus wie das Ergebnis des letzten Laufs.
echo "$(date '+%Y-%m-%d %H:%M:%S')  --- Lauf gestartet ---" >&2

# --- Passwort aus dem Schluesselbund, niemals aus einer Datei ---------------
if ! PASS="$(security find-generic-password -s "$KEYCHAIN_SERVICE" -a "$WEBDAV_USER" -w 2>/dev/null)"; then
    echo "FEHLER: Kein Passwort im Schluesselbund fuer Dienst '$KEYCHAIN_SERVICE', Konto '$WEBDAV_USER'." >&2
    echo "        Einmalig hinterlegen mit:" >&2
    echo "        security add-generic-password -s '$KEYCHAIN_SERVICE' -a '$WEBDAV_USER' -w" >&2
    exit 1
fi

# curl-Zugangsdaten ueber eine Konfigurationsdatei statt ueber -u: Argumente sind in der
# Prozessliste fuer jeden Benutzer sichtbar, diese Datei ist es nicht.
CURLRC="$(mktemp)"
chmod 600 "$CURLRC"
trap 'rm -f "$CURLRC"' EXIT
printf 'user = "%s:%s"\n' "$WEBDAV_USER" "$PASS" > "$CURLRC"
unset PASS
CURL=(curl -sS -K "$CURLRC" --fail-with-body --connect-timeout 20 --max-time 1800)

webdav_list() {
    "${CURL[@]}" -X PROPFIND -H "Depth: 1" "$WEBDAV_URL/" 2>/dev/null \
        | tr '<>' '\n\n' | grep -o "rbbk_ipad_verwaltung_backup_[^\"<]*\.enc" | sort -u
}

# Groesse der Datei am Ziel, oder leer wenn sie fehlt. Der Dateiname allein genuegt als
# Nachweis NICHT: eine abgebrochene Uebertragung hinterlaesst denselben Namen mit
# unvollstaendigem Inhalt, und ein Namensvergleich haelt das faelschlich fuer erledigt.
webdav_size() {
    "${CURL[@]}" -I "$WEBDAV_URL/$1" 2>/dev/null \
        | tr -d '\r' | awk 'tolower($1) == "content-length:" { print $2 }' | tail -1
}

# Zugang vorab pruefen. Sonst scheitert erst der Upload, nach der Uebertragung vom Server,
# mit einer rohen curl-Meldung wie "error: 401".
if ! "${CURL[@]}" -X PROPFIND -H "Depth: 0" "$WEBDAV_URL/" -o /dev/null 2>/dev/null; then
    echo "FEHLER: Zugriff auf $WEBDAV_URL nicht moeglich." >&2
    echo "        Passwort im Schluesselbund pruefen (Dienst '$KEYCHAIN_SERVICE', Konto '$WEBDAV_USER')," >&2
    echo "        oder die Adresse in $CONF. Ersetzen mit:" >&2
    echo "        security add-generic-password -U -s '$KEYCHAIN_SERVICE' -a '$WEBDAV_USER' -w" >&2
    exit 1
fi

# --- Server erreichbar? ----------------------------------------------------
if ! ssh -o BatchMode=yes -o ConnectTimeout=15 "$SERVER" true 2>/dev/null; then
    echo "FEHLER: $SERVER ist nicht erreichbar." >&2
    echo "        Haeufigste Ursache: dieser Rechner ist nicht im Schulnetz." >&2
    exit 1
fi

mkdir -p "$LOCAL_CACHE"

log "Hole Backups von $SERVER:$REMOTE_DIR"
rsync -az --timeout=120 --include="$PATTERN" --exclude='*' "$SERVER:$REMOTE_DIR/" "$LOCAL_CACHE/"

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

# --- Hochladen, was dort noch fehlt ---------------------------------------
UPLOADED=0
for f in "$LOCAL_CACHE"/$PATTERN; do
    name="$(basename "$f")"
    lokal="$(stat -f %z "$f")"
    dort="$(webdav_size "$name")"
    if [ "$dort" = "$lokal" ]; then
        continue
    fi
    [ -n "$dort" ] && log "Unvollstaendig am Ziel ($dort statt $lokal Bytes) - lade neu: $name"
    log "Lade hoch: $name ($(( lokal / 1024 / 1024 )) MB)"
    "${CURL[@]}" -T "$f" "$WEBDAV_URL/$name" > /dev/null
    UPLOADED=$((UPLOADED + 1))
done
[ "$UPLOADED" -eq 0 ] && log "Nichts hochzuladen - alles schon vollstaendig bei IServ."

# --- Nachweisen statt vertrauen: Groesse vergleichen, nicht nur den Namen --
neu_name="$(basename "$NEWEST")"
neu_lokal="$(stat -f %z "$NEWEST")"
neu_dort="$(webdav_size "$neu_name")"
if [ -z "$neu_dort" ]; then
    echo "FEHLER: $neu_name ist bei IServ nicht auffindbar." >&2
    exit 1
fi
if [ "$neu_dort" != "$neu_lokal" ]; then
    echo "FEHLER: $neu_name ist bei IServ unvollstaendig ($neu_dort statt $neu_lokal Bytes)." >&2
    exit 1
fi
log "Bestaetigt: $neu_name liegt vollstaendig bei IServ ($neu_lokal Bytes)."

REMOTE_FILES="$(webdav_list || true)"

# --- Aufraeumen, anhand des Datums IM DATEINAMEN --------------------------
CUTOFF="$(date -v-"${KEEP_DAYS}"d +%Y-%m-%d)"
while read -r name; do
    [ -z "$name" ] && continue
    datum="${name#rbbk_ipad_verwaltung_backup_}"
    datum="${datum:0:10}"
    if [[ "$datum" < "$CUTOFF" ]]; then
        log "Entferne bei IServ: $name"
        "${CURL[@]}" -X DELETE "$WEBDAV_URL/$name" > /dev/null || true
    fi
done <<< "$REMOTE_FILES"

find "$LOCAL_CACHE" -maxdepth 1 -name "$PATTERN" -mtime "+$KEEP_DAYS" -delete 2>/dev/null || true

COUNT="$(webdav_list | wc -l | tr -d ' ')"
log "Fertig. Backups bei IServ: $COUNT (Aufbewahrung ${KEEP_DAYS} Tage)"
