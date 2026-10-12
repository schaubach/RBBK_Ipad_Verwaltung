// Verträge: Hochladen (automatisch und von Hand zugeordnet), Herunterladen, Löschen,
// und die Warnung vor unvollständigen Verträgen beim Erstellen.
const fs = require('fs');
const { test, expect } = require('@playwright/test');
const {
  start,
  oeffneTab,
  toast,
  sammleSeitenfehler,
  neuerSchueler,
  neuesIPad,
  zuordnen,
  pdfDatei,
  herunterladen,
  eindeutig,
  api,
} = require('./helpers');

let fehler;
test.beforeEach(async ({ page }) => {
  fehler = sammleSeitenfehler(page);
  await start(page);
  await oeffneTab(page, 'Verträge');
});
test.afterEach(() => expect(fehler, 'Fehler in der Browser-Konsole').toEqual([]));

/** Schüler mit aktiver Zuordnung ohne Vertrag. */
async function zuordnungOhneVertrag(request, schuelerFelder = {}) {
  const s = await neuerSchueler(request, { sus_geb: '01.02.2008', ...schuelerFelder });
  const ipad = await neuesIPad(request, { typ: 'Apple iPad' });
  await zuordnen(request, s, ipad);
  return { s, ipad };
}

async function neuLaden(page) {
  await page.reload();
  await oeffneTab(page, 'Verträge');
}

function hochladen(page, ...dateien) {
  // Das einzige Datei-Feld auf dem Tab; der Upload startet beim Auswählen.
  return page.locator('input[type=file]').setInputFiles(dateien);
}

function vertragsZeile(page, dateiname) {
  return page.getByRole('row').filter({ hasText: dateiname });
}

async function vertragAusApi(request, dateiname) {
  const antwort = await api(request).get('/contracts');
  const liste = Array.isArray(antwort) ? antwort : antwort.contracts || antwort.items || [];
  return liste.find((c) => c.filename === dateiname);
}

test('PDF mit Vorname_Nachname.pdf wird automatisch zugeordnet', async ({ page, request }) => {
  const { s, ipad } = await zuordnungOhneVertrag(request);
  await neuLaden(page);
  const dateiname = `${s.sus_vorn}_${s.sus_nachn}.pdf`;

  await hochladen(page, pdfDatei(dateiname));
  await expect(toast(page, '1 Verträge automatisch zugeordnet')).toBeVisible();

  await page.getByPlaceholder('Dateiname filtern...').fill(dateiname);
  const zeile = vertragsZeile(page, dateiname);
  await expect(zeile).toContainText(ipad.itnr);
  await expect(zeile.getByText('Zugeordnet', { exact: true })).toBeVisible();
});

test('Nicht zuordenbarer Vertrag wird von Hand zugeordnet', async ({ page, request }) => {
  const { s, ipad } = await zuordnungOhneVertrag(request);
  await neuLaden(page);
  const dateiname = `${eindeutig('scan')}.pdf`;

  await hochladen(page, pdfDatei(dateiname));
  await expect(toast(page, '1 Verträge zur manuellen Zuordnung bereit')).toBeVisible();

  await page.getByPlaceholder('Dateiname filtern...').fill(dateiname);
  const zeile = vertragsZeile(page, dateiname);
  await zeile.getByTitle('Zuordnen', { exact: true }).click();

  const dialog = page.getByRole('alertdialog', { name: 'Vertrag zuordnen' });
  await dialog.locator('#search').fill(ipad.itnr);
  await dialog.getByRole('row').filter({ hasText: ipad.itnr }).getByRole('button', { name: 'Zuordnen' }).click();

  await expect(toast(page, 'Vertrag erfolgreich zugeordnet')).toBeVisible();
  await expect(zeile).toContainText(ipad.itnr);
  await expect(zeile).toContainText(s.sus_nachn);
});

test('Vertrag herunterladen', async ({ page, request }) => {
  const { s } = await zuordnungOhneVertrag(request);
  const dateiname = `${s.sus_vorn}_${s.sus_nachn}.pdf`;
  await hochladen(page, pdfDatei(dateiname));
  await expect(toast(page, '1 Verträge automatisch zugeordnet')).toBeVisible();

  await page.getByPlaceholder('Dateiname filtern...').fill(dateiname);
  const datei = await herunterladen(page, () =>
    vertragsZeile(page, dateiname).getByTitle('Herunterladen', { exact: true }).click()
  );
  expect(datei.name).toBe(dateiname);
  expect(fs.readFileSync(datei.pfad).subarray(0, 5).toString()).toBe('%PDF-');
});

test('Vertrag löschen', async ({ page, request }) => {
  const dateiname = `${eindeutig('weg')}.pdf`;
  await hochladen(page, pdfDatei(dateiname));
  await expect(toast(page, '1 Verträge zur manuellen Zuordnung bereit')).toBeVisible();

  await page.getByPlaceholder('Dateiname filtern...').fill(dateiname);
  await vertragsZeile(page, dateiname).getByTitle('Löschen', { exact: true }).click();
  const dialog = page.getByRole('alertdialog', { name: 'Vertrag löschen?' });
  await expect(dialog).toContainText(dateiname);
  await dialog.getByRole('button', { name: 'Löschen', exact: true }).click();

  await expect(toast(page, 'Vertrag gelöscht')).toBeVisible();
  await expect(vertragsZeile(page, dateiname)).toHaveCount(0);
  expect(await vertragAusApi(request, dateiname)).toBeUndefined();
});

test('Warnung vor unvollständigen Verträgen: Trotzdem erstellen', async ({ page, request }) => {
  // Ohne Geburtsdatum fehlt ein Pflichtfeld - die Oberfläche fragt vor dem Erstellen nach.
  const { ipad } = await zuordnungOhneVertrag(request, { sus_geb: '' });
  await neuLaden(page);

  await page.locator('#create-itnr').fill(ipad.itnr);
  await expect(page.getByTestId('generate-filtered-contracts-btn')).toHaveText(/\(1 von 1\)/);
  await page.getByTestId('generate-filtered-contracts-btn').click();

  const warnung = page.getByRole('alertdialog').filter({ hasText: 'Trotzdem fortfahren?' });
  await expect(warnung).toBeVisible();
  const datei = await herunterladen(page, () => warnung.getByTestId('confirm-generate-warnings-btn').click());
  expect(datei.name).toMatch(/\.zip$/);
  await expect(toast(page, 'erfolgreich erstellt')).toBeVisible();
});

test('Warnung vor unvollständigen Verträgen: Abbrechen', async ({ page, request }) => {
  // FEHLER in der App: Der Knopf "Abbrechen" im Warndialog ruft setPendingGenerateMode(null)
  // auf (ContractsManagement.jsx), und das gibt es nirgends - ein ReferenceError beim Klick.
  // Ist das behoben, schlägt dieser Test als "unexpectedly passed" fehl - dann gehört
  // test.fail() hier raus.
  test.fail();
  const { ipad } = await zuordnungOhneVertrag(request, { sus_geb: '' });
  await neuLaden(page);

  await page.locator('#create-itnr').fill(ipad.itnr);
  await expect(page.getByTestId('generate-filtered-contracts-btn')).toHaveText(/\(1 von 1\)/);
  await page.getByTestId('generate-filtered-contracts-btn').click();
  const warnung = page.getByRole('alertdialog').filter({ hasText: 'Trotzdem fortfahren?' });
  await warnung.getByRole('button', { name: 'Abbrechen' }).click();

  await expect(warnung).toHaveCount(0, { timeout: 2_000 });
  // Die Zuordnung ist weiter offen - es wurde nichts erstellt.
  await expect(page.getByTestId('generate-filtered-contracts-btn')).toHaveText(/\(1 von 1\)/);
  expect(fehler).toEqual([]);
});
