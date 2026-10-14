// Backup (Admin-Bereich): Passwort setzen, Server-Backup erstellen und herunterladen, und
// genau dieses Backup wieder einspielen.
//
// Gefahrlos nur im Wegwerf-Stack: Die Wiederherstellung überschreibt die ganze Datenbank.
// Eingespielt wird das Backup, das der Test Sekunden vorher selbst erstellt hat - danach ist
// der Stand derselbe, und die übrigen Tests merken nichts davon. Die Dateikopie der
// Server-Backups landet im Container (SERVER_BACKUP_DIR in docker-compose.yml), nicht auf dem Host.
//
// NICHT angefasst: "Datenschutz-Bereinigung starten" - sie löscht Daten nach Alter.
const fs = require('fs');
const { test, expect } = require('@playwright/test');
const {
  start,
  oeffneTab,
  toast,
  sammleSeitenfehler,
  bestaetigeNaechstenDialog,
  neuerSchueler,
  neuesIPad,
  herunterladen,
  adminToken,
  api,
} = require('./helpers');

// Immer dasselbe: Ein NEUES Passwort machte vorhandene Sicherungen unlesbar, und ein zweiter
// Lauf gegen denselben Stack bekäme dann Warnungen statt einer schlichten Bestätigung.
const BACKUP_PASSWORT = 'E2E-Backup-Passwort';

let fehler;
test.beforeEach(async ({ page }) => {
  fehler = sammleSeitenfehler(page);
  await start(page);
  await oeffneTab(page, 'Admin');
});
test.afterEach(() => expect(fehler, 'Fehler in der Browser-Konsole').toEqual([]));

function karte(page, titel) {
  return page.locator('div.rounded-xl').filter({ has: page.getByText(titel, { exact: true }) }).last();
}

test.describe.serial('Backup', () => {
  let backupDatei;

  test('Backup-Passwort setzen', async ({ page }) => {
    const k = karte(page, 'Backup-Sicherheit');
    await k.getByPlaceholder('Neues Backup-Passwort').fill(BACKUP_PASSWORT);
    await k.getByPlaceholder('Backup-Passwort bestätigen').fill(BACKUP_PASSWORT);
    await k.getByRole('button', { name: 'Backup-Passwort speichern' }).click();

    await expect(k.getByText('Backup-Passwort erfolgreich gesetzt.')).toBeVisible();
    await k.getByRole('button', { name: 'Hinweis gelesen' }).click();
    await expect(k).toContainText('werden aktuell verschlüsselt');
  });

  test('Server-Backup erstellen und herunterladen', async ({ page, request }) => {
    const k = karte(page, 'Server-Backups (MongoDB)');
    await k.getByRole('button', { name: 'Jetzt erstellen' }).click();
    await expect(toast(page, 'Server-Backup erfolgreich erstellt.')).toBeVisible();

    const datei = await herunterladen(page, () =>
      k.getByRole('button', { name: 'Herunterladen' }).first().click()
    );
    expect(datei.name).toMatch(/^rbbk_ipad_verwaltung_backup_.*\.json\.enc$/);
    // Ganz oben steht das neueste - also das eben erstellte.
    const liste = await api(request).get('/backup/server-backups');
    const neuestes = [...liste].sort((a, b) => b.created_at.localeCompare(a.created_at))[0];
    expect(datei.name).toBe(neuestes.filename);
    expect(fs.statSync(datei.pfad).size).toBeGreaterThan(100);
    backupDatei = { name: datei.name, buffer: fs.readFileSync(datei.pfad) };
  });

  test('Backup wieder einspielen', async ({ page, request }) => {
    test.skip(!backupDatei, 'braucht das Backup aus dem vorigen Test');
    // Ein Schüler, der NACH dem Backup entsteht, ist nach dem Einspielen wieder weg - daran
    // sieht man, dass wirklich der Stand aus der Datei zurückkam.
    const spaeter = await neuerSchueler(request);

    const k = karte(page, 'Backup wiederherstellen');
    bestaetigeNaechstenDialog(page);
    await k.locator('input[type=file]').setInputFiles({
      name: backupDatei.name,
      mimeType: 'application/octet-stream',
      buffer: backupDatei.buffer,
    });

    await expect(toast(page, 'System-Backup erfolgreich wiederhergestellt.')).toBeVisible({ timeout: 30_000 });
    await expect(k.getByText('Wiederherstellung abgeschlossen', { exact: true })).toBeVisible();
    await expect(k).toContainText('Sicherheits-Backup vorher angelegt');

    const schueler = await api(request).get('/students');
    expect(schueler.find((s) => s.id === spaeter.id), 'Lernende nach dem Backup sind weg').toBeUndefined();
  });

  test('Pool-iPads lösen beim Einspielen keine Warnung aus', async ({ page, request }) => {
    // Pool-iPads haben absichtlich keinen Bildungsgang; früher warnte das Einspielen trotzdem
    // "Ohne Bildungsgang kommen an" (routes/backup.py, pruefe_backup_inhalt).
    const a = api(request);
    const ipad = await neuesIPad(request);
    await a.post(`/ipads/${ipad.id}/release-to-pool`, {});
    await a.post('/backup/server-backups/run-now', {});
    const liste = await a.get('/backup/server-backups');
    const neuestes = [...liste].sort((x, y) => y.created_at.localeCompare(x.created_at))[0];
    const antwort = await request.get(`/api/backup/server-backups/${neuestes.id}/download`, {
      headers: { Authorization: `Bearer ${adminToken()}` },
    });
    expect(antwort.ok()).toBeTruthy();

    const k = karte(page, 'Backup wiederherstellen');
    bestaetigeNaechstenDialog(page);
    await k.locator('input[type=file]').setInputFiles({
      name: neuestes.filename,
      mimeType: 'application/octet-stream',
      buffer: await antwort.body(),
    });
    await expect(k.getByText(/^Wiederherstellung abgeschlossen/)).toBeVisible({ timeout: 30_000 });
    await expect(k).not.toContainText('Ohne Bildungsgang kommen an', { timeout: 2_000 });
  });
});
