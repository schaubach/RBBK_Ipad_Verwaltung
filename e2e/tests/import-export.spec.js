// Excel: Import-Vorlage, Import, Datensicherung als Excel und die Exporte mit Spaltenauswahl.
const { test, expect } = require('@playwright/test');
const {
  start,
  oeffneTab,
  toast,
  sammleSeitenfehler,
  neuerSchueler,
  neuesIPad,
  zuordnen,
  excelDatei,
  leseExcel,
  herunterladen,
  eindeutig,
  api,
} = require('./helpers');

let fehler;
test.beforeEach(async ({ page }) => {
  fehler = sammleSeitenfehler(page);
  await start(page);
});
test.afterEach(() => expect(fehler, 'Fehler in der Browser-Konsole').toEqual([]));

// Spalten der Import-Vorlage (routes/imports_exports.py) - die Datei unten nutzt dieselben.
const IMPORT_KOPF = [
  'Sname', 'SuSNachn', 'SuSVorn', 'SuSKl', 'SuSStrHNr', 'SuSPLZ', 'SuSOrt', 'SuSGeb',
  'Erz1Nachn', 'Erz1Vorn', 'Erz1StrHNr', 'Erz1PLZ', 'Erz1Ort',
  'Erz2Nachn', 'Erz2Vorn', 'Erz2StrHNr', 'Erz2PLZ', 'Erz2Ort',
  'Pencil', 'ITNr', 'SNr', 'Typ', 'Karton', 'Status', 'AnschJahr', 'AusleiheDatum', 'Rückgabe',
];

test('Import-Vorlage herunterladen', async ({ page }) => {
  await oeffneTab(page, 'Einstellungen');
  const datei = await herunterladen(page, () =>
    page.getByRole('button', { name: 'Vorlage herunterladen' }).click()
  );
  expect(datei.name).toBe('import_vorlage.xlsx');
  await expect(toast(page, 'Vorlage heruntergeladen')).toBeVisible();

  const { blatt, kopf } = await leseExcel(datei.pfad);
  expect(blatt).toBe('Import-Vorlage');
  expect(kopf).toEqual(IMPORT_KOPF);
});

test('Excel-Import legt Lernende, iPads und Zuordnung an und hält die Übergabe fest', async ({ page, request }) => {
  const mitIPad = { SuSVorn: 'Ina', SuSNachn: eindeutig('Import'), SuSKl: 'E2E1', SuSGeb: '03.04.2008' };
  const ohneIPad = { SuSVorn: 'Ole', SuSNachn: eindeutig('Import'), SuSKl: 'E2E1' };
  const itnrZugeordnet = eindeutig('IMP-');
  const itnrFrei = eindeutig('IMP-');

  // Ein Gerät liegt schon im Pool - der Import holt es in den Bildungsgang.
  const ausPool = await neuesIPad(request);
  await api(request).post(`/ipads/${ausPool.id}/release-to-pool`, {});
  const datei = await excelDatei('import.xlsx', 'Import-Vorlage', IMPORT_KOPF, [
    { ...mitIPad, ITNr: itnrZugeordnet, SNr: eindeutig('SN'), Status: 'ok', AusleiheDatum: '15.09.2026' },
    ohneIPad,
    { ITNr: itnrFrei, SNr: eindeutig('SN'), Status: 'defekt' },
    { ITNr: ausPool.itnr },
  ]);
  const ich = await api(request).get('/auth/me');

  await oeffneTab(page, 'Einstellungen');
  // Ohne "Übergeben an" lässt sich keine Datei wählen.
  await expect(page.getByTestId('data-import-input')).toBeDisabled();
  await page.getByTestId('import-empfaenger-select').selectOption(ich.id);
  await page.getByTestId('data-import-input').setInputFiles(datei);
  await expect(toast(page, 'Import abgeschlossen')).toBeVisible();

  // Ergebnis in der Datenbank ...
  const schueler = await api(request).get('/students');
  const ina = schueler.find((s) => s.sus_nachn === mitIPad.SuSNachn);
  expect(ina, 'Lernende mit iPad angelegt').toBeTruthy();
  expect(schueler.find((s) => s.sus_nachn === ohneIPad.SuSNachn), 'Lernende ohne iPad angelegt').toBeTruthy();
  const ipads = await api(request).get('/ipads');
  expect(ipads.find((i) => i.itnr === itnrFrei)?.status).toBe('defekt');
  expect(ipads.find((i) => i.itnr === itnrZugeordnet)?.current_assignment_id).toBeTruthy();

  // Neu angelegt wie aus dem Pool geholt: Die Übergabe steht in der Gerätehistorie.
  const neu = ipads.find((i) => i.itnr === itnrFrei);
  for (const id of [neu.id, ausPool.id]) {
    const { ipad, pool_history } = await api(request).get(`/ipads/${id}/history`);
    expect(ipad.is_in_pool, ipad.itnr).toBe(false);
    expect(pool_history.at(-1).uebergeben_an, ipad.itnr).toBe(ich.username);
  }

  // ... und in der Oberfläche.
  await oeffneTab(page, 'Lernende');
  await page.locator('#student-nachname-filter').fill(mitIPad.SuSNachn);
  await expect(page.getByRole('row').filter({ hasText: mitIPad.SuSNachn }).getByText('1 iPad(s)')).toBeVisible();
});

test('Datensicherung als Excel exportieren', async ({ page, request }) => {
  const s = await neuerSchueler(request);
  await oeffneTab(page, 'Einstellungen');
  const datei = await herunterladen(page, () =>
    page.getByRole('button', { name: 'Als Excel exportieren' }).click()
  );
  await expect(toast(page, 'Datensicherung erfolgreich exportiert')).toBeVisible();
  // Der Name kommt vom Server, mit Zeitstempel (Content-Disposition ohne Anführungszeichen).
  expect(datei.name).toMatch(/^datensicherung_\d{8}_\d{6}\.xlsx$/);

  const { kopf, daten } = await leseExcel(datei.pfad);
  const spalte = kopf.indexOf('SuSNachn');
  expect(spalte).toBeGreaterThanOrEqual(0);
  expect(daten.map((z) => z[spalte])).toContain(s.sus_nachn);
});

test('Export der Lernenden mit allen Spalten', async ({ page, request }) => {
  const s = await neuerSchueler(request);
  const ipad = await neuesIPad(request);
  await zuordnen(request, s, ipad);
  await page.reload();
  await oeffneTab(page, 'Lernende');
  await page.locator('#student-nachname-filter').fill(s.sus_nachn);

  await page.getByRole('button', { name: 'Exportieren', exact: true }).click();
  const dialog = page.getByTestId('export-columns-dialog');
  // Voreingestellt: alle angebotenen Spalten. Die Zahl steht nicht fest im Test - kommt eine
  // Spalte hinzu, soll der Test sie mitprüfen, statt an der alten Zahl zu scheitern.
  const zaehler = dialog.getByTestId('export-columns-count');
  await expect(zaehler).toHaveText(/^(\d+) von \1 Spalten/);
  const spalten = Number((await zaehler.innerText()).split(' ')[0]);
  const datei = await herunterladen(page, () => dialog.getByTestId('export-columns-confirm-btn').click());
  expect(datei.name).toBe('schueler_export.xlsx');
  await expect(toast(page, 'Export erfolgreich')).toBeVisible();

  const { kopf, daten } = await leseExcel(datei.pfad);
  expect(kopf).toHaveLength(spalten);
  const zeile = daten.find((z) => z[kopf.indexOf('SuSNachn')] === s.sus_nachn);
  expect(zeile, 'gefilterte lernende Person im Export').toBeTruthy();
  expect(zeile[kopf.indexOf('ITNr')]).toBe(ipad.itnr);
});

test('iPad-Export nur mit ausgewählten Spalten', async ({ page, request }) => {
  const ipad = await neuesIPad(request);
  await page.reload();
  await oeffneTab(page, 'iPads');

  await page.getByRole('button', { name: 'Exportieren', exact: true }).click();
  const dialog = page.getByTestId('export-columns-dialog');
  await dialog.getByTestId('export-columns-select-none').click();
  await expect(dialog.getByTestId('export-columns-confirm-btn')).toBeDisabled();
  await dialog.getByTestId('export-column-checkbox-ITNr').click();
  await dialog.getByTestId('export-column-checkbox-Status').click();
  await expect(dialog.getByTestId('export-columns-confirm-btn')).toHaveText('Exportieren (2)');

  const datei = await herunterladen(page, () => dialog.getByTestId('export-columns-confirm-btn').click());
  expect(datei.name).toBe('ipads_export.xlsx');
  const { kopf, daten } = await leseExcel(datei.pfad);
  expect(kopf).toEqual(['ITNr', 'Status']);
  expect(daten.map((z) => z[0])).toContain(ipad.itnr);
});
