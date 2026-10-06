#!/bin/bash
# Schiebt die Tagesbackups ausser Haus (z.B. IServ Files per WebDAV).
#
# Bewusst ausserhalb der Anwendung: der Transport muss auch dann funktionieren, wenn die
# Anwendung selbst defekt ist, und die Zugangsdaten bleiben im Betriebssystem statt in der
# Datenbank. Aufruf ueber den systemd-Timer in scripts/systemd/.
#
# Konfiguration: /etc/ipad-verwaltung-backup.conf (nicht im Repo, enthaelt keine Passwoerter -
# die liegen in der rclone-Konfiguration). Einrichtung: siehe scripts/BACKUP-OFFSITE.md
#
# Exit-Code != 0 bedeutet: der Lauf hat sein Ziel nicht erreicht. systemd markiert die Unit
# dann als failed, was ueber 'systemctl status' bzw. OnFailure sichtbar wird.

set -euo pipefail

CONF="${BACKUP_SYNC_CONF:-/etc/ipad-verwaltung-backup.conf}"
if [ ! -r "$CONF" ]; then
    echo "FEHLER: Konfiguration $CONF nicht lesbar." >&2
    exit 1
fi
# shellcheck source=/dev/null
. "$CONF"

BACKUP_DIR="${BACKUP_DIR:-/var/backups/ipad-verwaltung}"
REMOTE_RETENTION_DAYS="${REMOTE_RETENTION_DAYS:-30}"
MAX_AGE_HOURS="${MAX_AGE_HOURS:-36}"
RCLONE="${RCLONE_BIN:-rclone}"
PATTERN="rbbk_ipad_verwaltung_backup_*"

if [ -z "${RCLONE_REMOTE:-}" ]; then
    echo "FEHLER: RCLONE_REMOTE ist in $CONF nicht gesetzt." >&2
    exit 1
fi

command -v "$RCLONE" >/dev/null || { echo "FEHLER: $RCLONE nicht gefunden." >&2; exit 1; }
[ -d "$BACKUP_DIR" ] || { echo "FEHLER: $BACKUP_DIR existiert nicht." >&2; exit 1; }

# Neuestes lokales Backup ermitteln. Fehlt eines, laeuft die Backup-Erzeugung in der
# Anwendung nicht - das ist ein Alarm, kein stilles Ueberspringen.
NEWEST="$(find "$BACKUP_DIR" -maxdepth 1 -type f -name "$PATTERN" 2>/dev/null | sort | tail -1 || true)"
if [ -z "$NEWEST" ]; then
    echo "FEHLER: kein Backup in $BACKUP_DIR gefunden - erzeugt die Anwendung noch welche?" >&2
    exit 1
fi

AGE_HOURS=$(( ( $(date +%s) - $(stat -c %Y "$NEWEST") ) / 3600 ))
if [ "$AGE_HOURS" -gt "$MAX_AGE_HOURS" ]; then
    echo "FEHLER: neuestes Backup ist $AGE_HOURS Stunden alt (Grenze: $MAX_AGE_HOURS)." >&2
    echo "        $NEWEST" >&2
    exit 1
fi

echo "Neuestes Backup: $(basename "$NEWEST") (${AGE_HOURS}h alt)"
echo "Ziel: $RCLONE_REMOTE"

# copy statt sync: das lokale Aufraeumen nach 7 Tagen soll die Kopien ausser Haus nicht
# mitloeschen. Deren Aufbewahrung wird unten getrennt geregelt.
"$RCLONE" copy "$BACKUP_DIR" "$RCLONE_REMOTE" \
    --include "$PATTERN" --no-traverse --stats-one-line ${RCLONE_EXTRA_ARGS:-}

# Nachweisen, dass die neueste Datei wirklich angekommen ist - 'copy' allein meldet auch
# dann Erfolg, wenn es nichts zu tun gab.
if ! "$RCLONE" lsf "$RCLONE_REMOTE" --include "$PATTERN" | grep -Fxq "$(basename "$NEWEST")"; then
    echo "FEHLER: $(basename "$NEWEST") ist am Ziel nicht auffindbar." >&2
    exit 1
fi
echo "Bestaetigt: $(basename "$NEWEST") liegt am Ziel."

"$RCLONE" delete "$RCLONE_REMOTE" --include "$PATTERN" \
    --min-age "${REMOTE_RETENTION_DAYS}d" --rmdirs 2>/dev/null || true

REMOTE_COUNT="$("$RCLONE" lsf "$RCLONE_REMOTE" --include "$PATTERN" | wc -l | tr -d ' ')"
echo "Fertig. Backups am Ziel: $REMOTE_COUNT (Aufbewahrung ${REMOTE_RETENTION_DAYS} Tage)"
