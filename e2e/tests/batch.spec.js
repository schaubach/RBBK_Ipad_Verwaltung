// Batch-Zuordnung per Datei: Geräte (per ITNr) einem Bildungsgang zuordnen und die Übergabe
// an eine Person festhalten. Neue Geräte werden angelegt, Pool-Geräte übernommen, Geräte im
// Ziel-Bildungsgang quittiert.
const fs = require('fs');
const { test, expect } = require('@playwright/test');
const {
  ADMIN,
  BILDUNGSGANG,
  start,
  oeffneTab,
  toast,
  sammleSeitenfehler,
  neuesIPad,
  excelDatei,
  leseExcel,
  herunterladen,
  bildungsgangNamens,
  eindeutig,
  api,
} = require('./helpers');

const KOPF = ['ITNr', 'SNr', 'Karton', 'Pencil', 'Typ', 'AnschJahr', 'Status'];

let fehler;
test.beforeEach(async ({ page }) => {
  fehler = sammleSeitenfehler(page);
  await start(page);
  await oeffneTab(page, 'iPads');
});
test.afterEach(() => expect(fehler, 'Fehler in der Browser-Konsole').toEqual([]));

async function oeffneDialog(page, request) {
  const bg = await bildungsgangNamens(request, BILDUNGSGANG);
  const ich = await api(request).get('/auth/me');
  await page.getByTestId('open-batch-import-btn').click();
  const dialog = page.getByTestId('batch-import-dialog');
  await expect(dialog).toBeVisible();
  return { dialog, bg, ich };
}

test('Vorlage für die Batch-Zuordnung herunterladen', async ({ page, request }) => {
  const { dialog } = await oeffneDialog(page, request);
  const datei = await herunterladen(page, () => dialog.getByTestId('batch-import-template-btn').click());
  expect(datei.name).toBe('batch_zuordnung_vorlage.xlsx');
  const { kopf } = await leseExcel(datei.pfad);
  expect(kopf).toEqual(KOPF);
});

test('Batch-Zuordnung: neu, aus dem Pool, quittiert, ungültig', async ({ page, request }) => {
  const neu = eindeutig('BATCH-');
  const ausPool = await neuesIPad(request);
  await api(request).post(`/ipads/${ausPool.id}/release-to-pool`, {});
  const vorhanden = await neuesIPad(request);
  await page.reload();
  await oeffneTab(page, 'iPads');

  const { dialog, bg, ich } = await oeffneDialog(page, request);

  // Schritt 1 und 2 - danach klappen beide zu und zeigen ihre Wahl.
  await dialog.getByTestId(`batch-import-bildungsgang-row-${bg.id}`).click();
  await dialog.getByTestId('batch-import-empfaenger-search-input').fill(ADMIN.username);
  await dialog.getByTestId(`batch-import-empfaenger-row-${ich.id}`).click();
  await expect(dialog.getByTestId('batch-import-schritt-bildungsgang-summary')).toContainText(BILDUNGSGANG);
  await expect(dialog.getByTestId('batch-import-schritt-empfaenger-summary')).toContainText(ADMIN.username);

  // Schritt 3: die Datei. Erst danach lässt sich starten.
  await expect(dialog.getByTestId('batch-import-submit-btn')).toBeDisabled();
  await dialog.getByTestId('batch-import-file-input').setInputFiles(
    await excelDatei('batch.xlsx', 'Geräte-Zuordnung', KOPF, [
      { ITNr: neu, SNr: eindeutig('SN'), Typ: 'Apple iPad', Status: 'ok' },
      { ITNr: ausPool.itnr },
      { ITNr: vorhanden.itnr },
      { SNr: 'ohne-ITNr' },
    ])
  );
  await dialog.getByTestId('batch-import-submit-btn').click();

  const ergebnis = page.getByTestId('batch-import-result-dialog');
  await expect(ergebnis).toBeVisible();
  await expect(toast(page, `Übergabe von 3 Gerät(en) an ${ADMIN.username} festgehalten`)).toBeVisible();
  for (const [itnr, text] of [
    [neu, 'Neu erstellt & zugeordnet'],
    [ausPool.itnr, 'Aus Pool zugeordnet'],
    [vorhanden.itnr, 'Im Bildungsgang (Übergabe quittiert)'],
  ]) {
    await expect(ergebnis.getByRole('row').filter({ hasText: itnr })).toContainText(text);
  }
  await expect(ergebnis.getByText('Ungültige Zeile (ITNr fehlt)')).toBeVisible();

  // Das Protokoll als CSV.
  const log = await herunterladen(page, () => ergebnis.getByTestId('batch-import-csv-download-btn').click());
  expect(log.name).toMatch(/^batch_zuordnung_log_.*\.csv$/);
  const csv = fs.readFileSync(log.pfad, 'utf8');
  for (const itnr of [neu, ausPool.itnr, vorhanden.itnr]) expect(csv).toContain(itnr);
  await ergebnis.getByRole('button', { name: 'Schließen' }).click();

  // Und in der Datenbank: alle drei im Bildungsgang, keins mehr im Pool.
  const ipads = await api(request).get('/ipads');
  for (const itnr of [neu, ausPool.itnr, vorhanden.itnr]) {
    expect(ipads.find((i) => i.itnr === itnr)?.bildungsgang_id, itnr).toBe(bg.id);
  }
});
