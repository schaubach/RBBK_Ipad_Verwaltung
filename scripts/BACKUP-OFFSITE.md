# Backups außer Haus sichern (IServ Files per WebDAV)

Die Anwendung erzeugt einmal täglich ein verschlüsseltes Backup und legt es zweifach ab:
in MongoDB (GridFS, 7 Tage) und als Datei unter `/var/backups/ipad-verwaltung` auf dem Host.
Ein systemd-Timer schiebt diese Dateien anschließend nach IServ.

Der Transport liegt bewusst **außerhalb** der Anwendung. Zwei Gründe: er funktioniert auch
dann noch, wenn die Anwendung selbst defekt ist — also genau im Ernstfall —, und die
Zugangsdaten liegen im Betriebssystem statt in der Datenbank.

E-Mail-Versand ist für diesen Zweck ungeeignet: die Vertrags-PDFs liegen als Binärdaten in
der Datenbank, das Backup wächst mit jedem Vertrag, und Anhänge sind bei etwa 25 MB am Ende.

## Voraussetzungen

Ein **Funktionsaccount in IServ** mit WebDAV-Zugang, von der IServ-Administration
einzurichten. Nicht Ihren persönlichen Account verwenden: das Passwort liegt auf dem Server,
und der Zugriff soll auf den Backup-Ordner beschränkt bleiben.

Erfragen Sie dort die **WebDAV-URL** Ihrer Instanz — der Pfad unterscheidet sich je nach
IServ-Version, und die Anwendung kann ihn nicht erraten.

## Einrichtung

### 1. rclone installieren

```bash
sudo apt-get update && sudo apt-get install -y rclone
```

### 2. Zugang einrichten

```bash
sudo rclone config
```

* `n` für einen neuen Remote, Name: **iserv**
* Typ: **webdav**
* URL: die von der IServ-Administration genannte Adresse, inklusive Zielordner
* Vendor: **other**
* Benutzer und Passwort des Funktionsaccounts

Prüfen, dass der Zugang trägt:

```bash
sudo rclone lsd iserv:
```

### 3. Konfiguration anlegen

```bash
sudo tee /etc/ipad-verwaltung-backup.conf > /dev/null <<'CONF'
BACKUP_DIR=/var/backups/ipad-verwaltung
RCLONE_REMOTE=iserv:
REMOTE_RETENTION_DAYS=30
MAX_AGE_HOURS=36
CONF
sudo chmod 600 /etc/ipad-verwaltung-backup.conf
```

`REMOTE_RETENTION_DAYS` ist unabhängig von der lokalen Aufbewahrung: auf dem Server bleiben
7 Tage, bei IServ 30. `MAX_AGE_HOURS` ist die Alarmschwelle — ist das neuste Backup älter,
bricht der Lauf mit Fehler ab, statt stillschweigend nichts zu tun.

### 4. Einmal von Hand testen

```bash
sudo /home/RBBK_Ipad_Verwaltung/scripts/sync-backups.sh
```

Erwartete Ausgabe: das neuste Backup, die Bestätigung, dass es am Ziel liegt, und die Anzahl
der dortigen Backups.

### 5. Timer aktivieren

```bash
sudo cp /home/RBBK_Ipad_Verwaltung/scripts/systemd/ipad-backup-sync.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ipad-backup-sync.timer
```

## Kontrolle

```bash
systemctl list-timers ipad-backup-sync.timer     # wann lief er, wann läuft er wieder
systemctl status ipad-backup-sync.service        # Ergebnis des letzten Laufs
journalctl -u ipad-backup-sync.service --since -7d
```

Ein fehlgeschlagener Lauf hinterlässt die Unit im Zustand `failed`. Wer das aktiv gemeldet
bekommen möchte, hinterlegt in der Service-Unit ein `OnFailure=`.

## Wiederherstellung

Backups sind mit dem **Backup-Passwort** aus dem Admin-Tab verschlüsselt. Ohne dieses
Passwort ist eine heruntergeladene Datei wertlos — bewahren Sie es getrennt vom Server auf,
etwa in einem Passwortmanager.

Einspielen über **Admin → Backup wiederherstellen**.

> Ein Backup, das nie zurückgespielt wurde, ist kein Backup, sondern eine Vermutung.
> Probieren Sie die Wiederherstellung einmal auf einer Testinstanz aus, bevor Sie sie
> im Ernstfall zum ersten Mal brauchen.

## Was noch aussteht

Jede Nacht wird das **vollständige** Backup übertragen, einschließlich aller Vertrags-PDFs —
auch der unveränderten. Das trägt bis in den Bereich einiger hundert MB. Wenn die Übertragung
spürbar länger dauert oder der IServ-Platz knapp wird, ist der nächste Schritt, die
Vertragsdateien aus den MongoDB-Dokumenten herauszulösen; dann überträgt die Nacht nur noch
das Hinzugekommene.
