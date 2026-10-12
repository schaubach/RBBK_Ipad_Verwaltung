// iPads: Bearbeiten, Status, Zuordnung lösen, Löschen, Pool.
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
  await oeffneTab(page, 'iPads');
});
test.afterEach(() => expect(fehler, 'Fehler in der Browser-Konsole').toEqual([]));

function zeile(page, ipad) {
  return page.getByRole('row').filter({ has: page.getByRole('button', { name: ipad.itnr, exact: true }) });
}

async function filtere(page, ipad) {
  await page.locator('#ipad-itnr-filter').fill(ipad.itnr);
  await expect(zeile(page, ipad)).toHaveCount(1);
}

async function neuLaden(page) {
  await page.reload();
  await oeffneTab(page, 'iPads');
}

function detailansicht(page, ipad) {
  return page.locator('div.fixed').filter({
    has: page.getByRole('heading', { name: new RegExp(`^iPad Details: ${ipad.itnr}`) }),
  });
}

async function ipadAusApi(request, ipad) {
  return (await api(request).get('/ipads')).find((i) => i.id === ipad.id);
}

test('iPad bearbeiten', async ({ page, request }) => {
  const ipad = await neuesIPad(request);
  await neuLaden(page);
  await filtere(page, ipad);

  await zeile(page, ipad).getByRole('button', { name: ipad.itnr, exact: true }).click();
  const ansicht = detailansicht(page, ipad);
  await ansicht.getByTestId('edit-ipad-btn').click();
  await ansicht.getByTestId('ipad-karton-input').fill('K-42');
  await ansicht.getByTestId('ipad-ansch-jahr-input').fill('2026');
  await ansicht.getByRole('button', { name: 'Speichern', exact: true }).click();

  await expect(toast(page, 'iPad erfolgreich aktualisiert')).toBeVisible();
  const gespeichert = await ipadAusApi(request, ipad);
  expect(gespeichert.karton).toBe('K-42');
  expect(String(gespeichert.ansch_jahr)).toBe('2026');
});

test('Status in der Liste auf defekt setzen', async ({ page, request }) => {
  const ipad = await neuesIPad(request);
  await neuLaden(page);
  await filtere(page, ipad);

  await zeile(page, ipad).getByRole('combobox').click();
  await page.getByRole('option', { name: 'Defekt' }).click();

  await expect(toast(page, 'iPad status updated to defekt')).toBeVisible();
  await expect(zeile(page, ipad)).toHaveClass(/bg-red-50/);
  expect((await ipadAusApi(request, ipad)).status).toBe('defekt');
});

test('Zuordnung über die iPad-Liste lösen', async ({ page, request }) => {
  const s = await neuerSchueler(request);
  const ipad = await neuesIPad(request);
  await zuordnen(request, s, ipad);
  await neuLaden(page);
  await filtere(page, ipad);

  await zeile(page, ipad).getByTitle('Klicken um zugewiesenen Schüler anzuzeigen').click();
  const dialog = page.getByRole('alertdialog', { name: `Zuordnung für iPad ${ipad.itnr}` });
  await expect(dialog).toContainText(s.sus_nachn);
  await dialog.getByRole('button', { name: 'Zuordnung auflösen' }).click();

  await expect(toast(page, 'Zuordnung erfolgreich aufgelöst')).toBeVisible();
  await expect(zeile(page, ipad).getByText('Nein', { exact: true })).toBeVisible();
});

test('iPad löschen', async ({ page, request }) => {
  const ipad = await neuesIPad(request);
  await neuLaden(page);
  await filtere(page, ipad);

  await zeile(page, ipad).getByTitle('iPad löschen').click();
  const dialog = page.getByRole('alertdialog', { name: 'iPad löschen?' });
  await expect(dialog).toContainText(ipad.itnr);
  await dialog.getByRole('button', { name: 'iPad löschen' }).click();

  await expect(toast(page, `iPad ${ipad.itnr} erfolgreich gelöscht`)).toBeVisible();
  await expect(zeile(page, ipad)).toHaveCount(0);
  expect(await ipadAusApi(request, ipad)).toBeUndefined();
});

test('iPad in den Pool freigeben und wieder übernehmen', async ({ page, request }) => {
  const ipad = await neuesIPad(request);
  await neuLaden(page);
  await filtere(page, ipad);

  await page.getByTestId(`release-btn-${ipad.id}`).click();
  const dialog = page.getByRole('alertdialog', { name: 'iPad in den Pool freigeben?' });
  await dialog.getByTestId('confirm-release-btn').click();
  await expect(toast(page, `iPad ${ipad.itnr} in den Pool freigegeben`)).toBeVisible();
  await expect(zeile(page, ipad).getByTitle('Im gemeinsamen Pool')).toBeVisible();
  expect((await ipadAusApi(request, ipad)).bildungsgang_id ?? null).toBeNull();

  await page.getByTestId(`claim-btn-${ipad.id}`).click();
  await expect(toast(page, `iPad ${ipad.itnr} übernommen`)).toBeVisible();
  await expect(page.getByTestId(`release-btn-${ipad.id}`)).toBeVisible();
  expect((await ipadAusApi(request, ipad)).bildungsgang_id).toBeTruthy();
});

test('Detailansicht zeigt ein Pool-iPad nach dem Speichern weiter als Pool-iPad', async ({ page, request }) => {
  // FEHLER in der App: IPadDetailViewer.jsx ersetzt nach dem Speichern das angezeigte iPad
  // durch die Antwort des PUT, und der fehlt is_in_pool. Das Abzeichen "Im Pool" verschwindet,
  // statt "Übernehmen" wird "In Pool freigeben" angeboten. Ist das behoben, schlägt dieser Test
  // als "unexpectedly passed" fehl - dann gehört test.fail() hier raus.
  test.fail();
  const ipad = await neuesIPad(request);
  await api(request).post(`/ipads/${ipad.id}/release-to-pool`, {});
  await neuLaden(page);
  await filtere(page, ipad);

  await zeile(page, ipad).getByRole('button', { name: ipad.itnr, exact: true }).click();
  const ansicht = detailansicht(page, ipad);
  await expect(ansicht.getByTestId('detail-claim-btn')).toBeVisible();
  await ansicht.getByTestId('edit-ipad-btn').click();
  await ansicht.getByTestId('ipad-karton-input').fill('K-7');
  await ansicht.getByRole('button', { name: 'Speichern', exact: true }).click();
  await expect(toast(page, 'iPad erfolgreich aktualisiert')).toBeVisible();
  await expect(ansicht.getByTestId('detail-claim-btn')).toBeVisible({ timeout: 2_000 });
});
