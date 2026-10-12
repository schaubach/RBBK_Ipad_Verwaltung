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

test('Excel-Import legt Schüler, iPads und Zuordnung an', async ({ page, request }) => {
  const mitIPad = { SuSVorn: 'Ina', SuSNachn: eindeutig('Import'), SuSKl: 'E2E1', SuSGeb: '03.04.2008' };
  const ohneIPad = { SuSVorn: 'Ole', SuSNachn: eindeutig('Import'), SuSKl: 'E2E1' };
  const itnrZugeordnet = eindeutig('IMP-');
  const itnrFrei = eindeutig('IMP-');
  const datei = await excelDatei('import.xlsx', 'Import-Vorlage', IMPORT_KOPF, [
    { ...mitIPad, ITNr: itnrZugeordnet, SNr: eindeutig('SN'), Status: 'ok', AusleiheDatum: '15.09.2026' },
    ohneIPad,
    { ITNr: itnrFrei, SNr: eindeutig('SN'), Status: 'defekt' },
  ]);

  await oeffneTab(page, 'Einstellungen');
  await page.getByTestId('data-import-input').setInputFiles(datei);
  await expect(toast(page, 'Import abgeschlossen')).toBeVisible();

  // Ergebnis in der Datenbank ...
  const schueler = await api(request).get('/students');
  const ina = schueler.find((s) => s.sus_nachn === mitIPad.SuSNachn);
  expect(ina, 'Schüler mit iPad angelegt').toBeTruthy();
  expect(schueler.find((s) => s.sus_nachn === ohneIPad.SuSNachn), 'Schüler ohne iPad angelegt').toBeTruthy();
  const ipads = await api(request).get('/ipads');
  expect(ipads.find((i) => i.itnr === itnrFrei)?.status).toBe('defekt');
  expect(ipads.find((i) => i.itnr === itnrZugeordnet)?.current_assignment_id).toBeTruthy();

  // ... und in der Oberfläche.
  await oeffneTab(page, 'Schüler');
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
  expect(datei.name).toMatch(/\.xlsx$/);

  const { kopf, daten } = await leseExcel(datei.pfad);
  const spalte = kopf.indexOf('SuSNachn');
  expect(spalte).toBeGreaterThanOrEqual(0);
  expect(daten.map((z) => z[spalte])).toContain(s.sus_nachn);
});

test('Schüler-Export mit allen Spalten', async ({ page, request }) => {
  const s = await neuerSchueler(request);
  const ipad = await neuesIPad(request);
  await zuordnen(request, s, ipad);
  await page.reload();
  await oeffneTab(page, 'Schüler');
  await page.locator('#student-nachname-filter').fill(s.sus_nachn);

  await page.getByRole('button', { name: 'Exportieren', exact: true }).click();
  const dialog = page.getByTestId('export-columns-dialog');
  await expect(dialog.getByTestId('export-columns-count')).toContainText('31 von 31');
  const datei = await herunterladen(page, () => dialog.getByTestId('export-columns-confirm-btn').click());
  expect(datei.name).toBe('schueler_export.xlsx');
  await expect(toast(page, 'Export erfolgreich')).toBeVisible();

  const { kopf, daten } = await leseExcel(datei.pfad);
  expect(kopf).toHaveLength(31);
  const zeile = daten.find((z) => z[kopf.indexOf('SuSNachn')] === s.sus_nachn);
  expect(zeile, 'gefilterter Schüler im Export').toBeTruthy();
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
