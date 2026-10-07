# Backups außer Haus sichern

Die Anwendung erzeugt einmal täglich ein verschlüsseltes Backup und legt es zweifach ab:
in MongoDB (GridFS, 7 Tage) und als Datei unter `/var/backups/ipad-verwaltung` auf dem Server.
Von dort wird es außer Haus gesichert.

**E-Mail-Versand gibt es nicht mehr.** Die Vertrags-PDFs liegen als Binärdaten in den
MongoDB-Dokumenten, das Backup wächst mit jedem Vertrag und hat die üblichen ~25 MB für
Anhänge längst überschritten. Komprimieren hilft nicht: die base64-Kodierung einer E-Mail
bläht das Ergebnis exakt wieder auf den Ausgangswert auf.

Es gibt zwei Wege. **Weg A** braucht keinen Zugang auf dem Server und ist der empfohlene,
solange Sie keinen IServ-Funktionsaccount haben.

---

## Weg A: Der Mac holt die Backups ab (empfohlen)

Ihr Rechner holt die Backups per SSH vom Server und legt sie in einen IServ-Ordner, den Sie
im Finder eingebunden haben.

Der Vorteil: **auf dem Server liegt kein IServ-Zugang.** Das IServ-Passwort bleibt im
Schlüsselbund Ihres Macs. Der Server kennt nur Ihren öffentlichen SSH-Schlüssel, und der
lässt sich jederzeit zurückziehen.

Der Preis: es läuft nur, wenn Ihr Rechner an und angemeldet ist. In den Ferien entsteht eine
Lücke — die Server-Backups laufen in dieser Zeit weiter, nur die Kopie außer Haus pausiert.

### Einrichtung

> **Wo wird was ausgeführt?** Alle Befehle dieses Abschnitts laufen **auf Ihrem Mac** — auch
> die, die per `ssh` etwas auf dem Server erledigen. Nur so landet der private Schlüssel dort,
> wo er hingehört: auf Ihrem Rechner, nicht auf dem Server.
>
> Befehle mit `sudo` auf der Gegenseite brauchen `ssh -t`. Ohne das gibt es kein Terminal, in
> dem `sudo` nach dem Passwort fragen könnte, und der Befehl scheitert mit
> *„a terminal is required to read the password"*.

**1. SSH-Schlüssel erzeugen und auf den Server bringen** — ⚠️ **auf dem Mac**, nicht auf dem
Server. Ein auf dem Server erzeugter Schlüssel nützt nichts: dann könnte sich der Server nur
bei sich selbst anmelden.

```bash
ssh-keygen -t ed25519 -C "backup-abholung-mac"   # nur wenn Sie noch keinen haben
ssh-copy-id schaubach@10.97.6.249
```

Prüfen, dass die Anmeldung ohne Passwort klappt:

```bash
ssh schaubach@10.97.6.249 'echo Anmeldung ok'
```

**2. Prüfen, dass `rsync` auf dem Server vorhanden ist** (vom Mac aus):

```bash
ssh -t schaubach@10.97.6.249 'rsync --version | head -1 || sudo apt-get install -y rsync'
```

**3. Lesezugriff auf das Backup-Verzeichnis.** Die Anwendung schreibt als root; abgeholt wird
unter Ihrem Konto. Das Verzeichnis bekommt deshalb Ihre Gruppe **und das setgid-Bit**:

```bash
ssh -t schaubach@10.97.6.249 'sudo chgrp -R $USER /var/backups/ipad-verwaltung && sudo chmod 2750 /var/backups/ipad-verwaltung && sudo chmod -R g+rX /var/backups/ipad-verwaltung'
```

Das setgid-Bit (die `2` in `2750`) ist der entscheidende Teil, und zwar für die **Zukunft**:
nur dadurch erbt jede neu geschriebene Datei die Gruppe des Verzeichnisses. Ohne setgid
korrigiert `chgrp -R` zwar die vorhandenen Dateien, aber jedes neue Backup wäre wieder
`root:root` und für die Abholung unlesbar — ohne dass etwas Sichtbares passiert, bis Sie
irgendwann merken, dass seit Tagen nichts mehr bei IServ ankommt.

Prüfen, dass es wirkt (die Zeile muss `drwxr-s---` zeigen, das `s` ist das setgid-Bit):

```bash
ssh schaubach@10.97.6.249 'ls -ld /var/backups/ipad-verwaltung'
```

**4. IServ im Finder einbinden:** *Gehe zu → Mit Server verbinden*, die WebDAV-Adresse Ihrer
IServ-Instanz. Notieren Sie den Pfad unterhalb von `/Volumes/`.

**5. Konfiguration anlegen:**

```bash
mkdir -p ~/.config/ipad-verwaltung
cat > ~/.config/ipad-verwaltung/backup-pull.conf <<'CONF'
SERVER=schaubach@10.97.6.249
REMOTE_DIR=/var/backups/ipad-verwaltung
ISERV_DIR=/Volumes/Files/Backups/iPad-Verwaltung
KEEP_DAYS=30
MAX_AGE_HOURS=36
CONF
```

`ISERV_DIR` an Ihren tatsächlichen Mountpfad anpassen. `MAX_AGE_HOURS` ist die Alarmschwelle:
ist das neueste Backup älter, bricht der Lauf mit Fehler ab, statt stillschweigend eine alte
Datei nochmal zu kopieren.

**6. Einmal von Hand testen:**

```bash
bash scripts/pull-backups-to-iserv.sh
```

**7. Täglich automatisch:**

```bash
cp scripts/de.rbbk.ipad-backup-pull.plist ~/Library/LaunchAgents/
# Pfad in der Datei auf Ihr Benutzerverzeichnis anpassen!
launchctl load ~/Library/LaunchAgents/de.rbbk.ipad-backup-pull.plist
```

Kontrolle: `cat /tmp/ipad-backup-pull.log` und `/tmp/ipad-backup-pull.err`.

---

## Weg B: Der Server schiebt selbst zu IServ

Braucht einen **IServ-Funktionsaccount** mit WebDAV-Zugriff, von der IServ-Administration
einzurichten. Nicht Ihren persönlichen Account: dessen Passwort läge dann auf dem Server, und
wer den Server übernimmt, hätte Ihren gesamten IServ-Zugang.

> Beachten Sie: `rclone obscure` ist **keine** Verschlüsselung. `rclone reveal` holt das
> Passwort in einem Befehl wieder heraus. `chmod 600` schützt gegen andere Benutzer auf dem
> Server, nicht gegen root und nicht gegen einen Einbruch.

### Einrichtung

```bash
sudo apt-get update && sudo apt-get install -y rclone
sudo rclone config        # n → Name "iserv" → webdav → URL von der IServ-Administration
                          # Vendor: other, Benutzer/Passwort des Funktionsaccounts
sudo rclone lsd iserv:    # Zugang prüfen
```

```bash
sudo tee /etc/ipad-verwaltung-backup.conf > /dev/null <<'CONF'
BACKUP_DIR=/var/backups/ipad-verwaltung
RCLONE_REMOTE=iserv:
REMOTE_RETENTION_DAYS=30
MAX_AGE_HOURS=36
CONF
sudo chmod 600 /etc/ipad-verwaltung-backup.conf

sudo /home/schaubach/RBBK_Ipad_Verwaltung/scripts/sync-backups.sh     # einmal von Hand

sudo cp /home/schaubach/RBBK_Ipad_Verwaltung/scripts/systemd/ipad-backup-sync.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ipad-backup-sync.timer
```

Kontrolle:

```bash
systemctl list-timers ipad-backup-sync.timer
systemctl status ipad-backup-sync.service
journalctl -u ipad-backup-sync.service --since -7d
```

---

## Reste des E-Mail-Versands entfernen

In der Datenbank liegen noch die alten Einstellungen (SMTP-Zugangsdaten und Zeitplan). Sie
richten keinen Schaden an, die Anwendung liest sie nicht mehr — aber in `smtp_config` steckt
ein verschlüsseltes Passwort, das dort nichts mehr zu suchen hat:

```bash
docker exec ipad_mongodb mongosh iPadDatabase --quiet --eval 'printjson(db.global_settings.deleteMany({type:{$in:["smtp_config","backup_schedule"]}}))'
```

## Wiederherstellung

Backups sind mit dem **Backup-Passwort** aus dem Admin-Tab verschlüsselt. Ohne dieses
Passwort ist eine Datei wertlos — bewahren Sie es getrennt vom Server auf, etwa in einem
Passwortmanager.

Einspielen über **Admin → Backup wiederherstellen**.

> Ein Backup, das nie zurückgespielt wurde, ist kein Backup, sondern eine Vermutung.
> Probieren Sie die Wiederherstellung einmal auf einer Testinstanz aus, bevor Sie sie im
> Ernstfall zum ersten Mal brauchen.

## Was noch aussteht

Übertragen wird jede Nacht das **vollständige** Backup, einschließlich aller Vertrags-PDFs —
auch der unveränderten. Das trägt bis in den Bereich einiger hundert MB. Wenn die Übertragung
spürbar länger dauert oder der Platz knapp wird, ist der nächste Schritt, die Vertragsdateien
aus den MongoDB-Dokumenten herauszulösen; dann überträgt die Nacht nur noch das Hinzugekommene.
