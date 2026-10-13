// Schüler: Detailansicht, Bearbeiten, Zuordnung lösen, Löschen.
const { test, expect } = require('@playwright/test');
const {
  start,
  oeffneTab,
  toast,
  sammleSeitenfehler,
  neuerSchueler,
  neuesIPad,
  zuordnen,
  api,
} = require('./helpers');

let fehler;
test.beforeEach(async ({ page }) => {
  fehler = sammleSeitenfehler(page);
  await start(page);
  await oeffneTab(page, 'Schüler');
});
test.afterEach(() => expect(fehler, 'Fehler in der Browser-Konsole').toEqual([]));

function zeile(page, schueler) {
  return page.getByRole('row').filter({ hasText: schueler.sus_nachn });
}

async function filtere(page, schueler) {
  await page.locator('#student-nachname-filter').fill(schueler.sus_nachn);
  await expect(zeile(page, schueler)).toHaveCount(1);
}

test('Detailansicht zeigt Daten, Zuordnung und Historie', async ({ page, request }) => {
  const s = await neuerSchueler(request, { sus_geb: '01.02.2008' });
  const ipad = await neuesIPad(request);
  await zuordnen(request, s, ipad);
  await page.reload();
  await oeffneTab(page, 'Schüler');
  await filtere(page, s);

  await zeile(page, s).getByRole('button', { name: `${s.sus_vorn} ${s.sus_nachn}` }).click();
  const ansicht = page.locator('div.fixed').filter({
    has: page.getByRole('heading', { name: `Schülerdetails: ${s.sus_vorn} ${s.sus_nachn}` }),
  });
  await expect(ansicht.getByText('Persönliche Daten')).toBeVisible();
  await expect(ansicht.getByText(`iPad ITNr: ${ipad.itnr}`)).toBeVisible();
  await expect(ansicht.getByText(/Zuordnungshistorie \(1\)/)).toBeVisible();
  await ansicht.getByRole('button', { name: 'Schließen', exact: true }).click();
  await expect(ansicht).toHaveCount(0);
});

test('Schüler bearbeiten', async ({ page, request }) => {
  const s = await neuerSchueler(request);
  await page.reload();
  await oeffneTab(page, 'Schüler');
  await filtere(page, s);

  await zeile(page, s).getByRole('button', { name: `${s.sus_vorn} ${s.sus_nachn}` }).click();
  await page.getByTestId('edit-student-btn').click();
  await page.getByTestId('student-klasse-input').fill('E2E2');
  await page.getByTestId('student-ort-input').fill('Dortmund');
  await page.getByRole('button', { name: 'Speichern', exact: true }).click();

  await expect(toast(page, 'Schüler erfolgreich aktualisiert')).toBeVisible();
  await page.getByRole('button', { name: 'Schließen', exact: true }).click();
  await expect(zeile(page, s)).toContainText('E2E2');

  const { student: gespeichert } = await api(request).get(`/students/${s.id}`);
  expect(gespeichert.sus_kl).toBe('E2E2');
  expect(gespeichert.sus_ort).toBe('Dortmund');
});

test('Detailansicht zeigt nach dem Speichern weiter das Anlagedatum', async ({ page, request }) => {
  const s = await neuerSchueler(request);
  await page.reload();
  await oeffneTab(page, 'Schüler');
  await filtere(page, s);

  await zeile(page, s).getByRole('button', { name: `${s.sus_vorn} ${s.sus_nachn}` }).click();
  const heute = new Date().toLocaleDateString('de-DE');
  // Vor dem Speichern stimmt es noch - sonst prüfte der Test etwas anderes.
  await expect(page.getByText(`Erstellt am: ${heute}`)).toBeVisible();
  await page.getByTestId('edit-student-btn').click();
  await page.getByTestId('student-klasse-input').fill('E2E3');
  await page.getByRole('button', { name: 'Speichern', exact: true }).click();
  await expect(toast(page, 'Schüler erfolgreich aktualisiert')).toBeVisible();
  await expect(page.getByText(`Erstellt am: ${heute}`)).toBeVisible({ timeout: 2_000 });
});

test('Zuordnung über die iPad-Liste des Schülers lösen', async ({ page, request }) => {
  const s = await neuerSchueler(request);
  const ipad = await neuesIPad(request);
  await zuordnen(request, s, ipad);
  await page.reload();
  await oeffneTab(page, 'Schüler');
  await filtere(page, s);

  await zeile(page, s).getByTitle('Klicken um zugewiesene iPads anzuzeigen').click();
  const dialog = page.getByRole('alertdialog', { name: `iPads von ${s.sus_vorn} ${s.sus_nachn}` });
  await expect(dialog.getByText(ipad.itnr)).toBeVisible();
  await dialog.getByTitle('Diese Zuordnung auflösen').click();

  await expect(toast(page, 'Zuordnung erfolgreich aufgelöst')).toBeVisible();
  await expect(dialog.getByText('Keine iPads zugewiesen')).toBeVisible();
  await dialog.getByRole('button', { name: 'Schließen' }).click();
  await expect(zeile(page, s).getByText('Ohne iPad')).toBeVisible();
});

test('Schüler löschen gibt das iPad frei', async ({ page, request }) => {
  const s = await neuerSchueler(request);
  const ipad = await neuesIPad(request);
  await zuordnen(request, s, ipad);
  await page.reload();
  await oeffneTab(page, 'Schüler');
  await filtere(page, s);

  await zeile(page, s).getByTitle(/^Schüler löschen/).click();
  const dialog = page.getByRole('alertdialog', { name: 'Schüler löschen?' });
  await expect(dialog).toContainText(`${s.sus_vorn} ${s.sus_nachn}`);
  await dialog.getByRole('button', { name: 'Schüler löschen' }).click();

  await expect(toast(page, `Schüler ${s.sus_vorn} ${s.sus_nachn} erfolgreich gelöscht`)).toBeVisible();
  await expect(zeile(page, s)).toHaveCount(0);

  // Das iPad ist wieder frei und lässt sich löschen.
  await oeffneTab(page, 'iPads');
  await page.locator('#ipad-itnr-filter').fill(ipad.itnr);
  const ipadZeile = page.getByRole('row').filter({ has: page.getByRole('button', { name: ipad.itnr, exact: true }) });
  await expect(ipadZeile.getByText('Nein', { exact: true })).toBeVisible();
  await expect(ipadZeile.getByTitle('iPad löschen')).toBeVisible();
});
