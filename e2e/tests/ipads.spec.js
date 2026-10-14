// iPads: Bearbeiten, Status, Zuordnung lösen, Löschen, Pool.
const { test, expect } = require('@playwright/test');
const {
  BILDUNGSGANG,
  start,
  oeffneTab,
  toast,
  sammleSeitenfehler,
  neuerSchueler,
  neuesIPad,
  zuordnen,
  neuerBenutzer,
  bildungsgangNamens,
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

test('iPad in den Pool freigeben und per "BG zuordnen" wieder ausgeben', async ({ page, request }) => {
  const ipad = await neuesIPad(request);
  const bg = await bildungsgangNamens(request, BILDUNGSGANG);
  const ich = await api(request).get('/auth/me');
  const lehrkraft = await neuerBenutzer(request);
  const ausgeschieden = await neuerBenutzer(request);
  await api(request).put(`/admin/users/${ausgeschieden.id}`, { is_active: false });
  await neuLaden(page);
  await filtere(page, ipad);

  await page.getByTestId(`release-btn-${ipad.id}`).click();
  const dialog = page.getByRole('alertdialog', { name: 'iPad in den Pool freigeben?' });
  await dialog.getByTestId('confirm-release-btn').click();
  await expect(toast(page, `iPad ${ipad.itnr} in den Pool freigegeben`)).toBeVisible();
  await expect(zeile(page, ipad).getByTitle('Im gemeinsamen Pool')).toBeVisible();
  expect((await ipadAusApi(request, ipad)).bildungsgang_id ?? null).toBeNull();

  // Aus dem Pool geht es nur noch mit Bildungsgang UND Übergabe - weder "Übernehmen" noch
  // direkt "Schüler zuordnen"; das macht danach der Bildungsgang.
  await expect(zeile(page, ipad).getByRole('button', { name: /Übernehmen/ })).toHaveCount(0);
  await expect(zeile(page, ipad).getByRole('button', { name: 'Schüler zuordnen' })).toHaveCount(0);
  await zeile(page, ipad).getByRole('button', { name: 'BG zuordnen' }).click();
  const zuordnen = page.getByTestId('assign-to-user-dialog');
  await expect(zuordnen.getByTestId('zuweisung-geraete')).toContainText(ipad.itnr);
  await zuordnen.getByTestId(`assign-bildungsgang-row-${bg.id}`).click();
  // Wie bei der Batch-Zuordnung: der erledigte Schritt klappt zu und zeigt seine Wahl.
  await expect(zuordnen.getByTestId('zuweisung-schritt-bildungsgang-summary')).toContainText(BILDUNGSGANG);

  // Empfänger: aktive Konten, Admins eingeschlossen - ausgeschiedene nicht.
  await expect(zuordnen.getByTestId(`zuweisung-empfaenger-row-${ich.id}`)).toBeVisible();
  await expect(zuordnen.getByTestId(`zuweisung-empfaenger-row-${lehrkraft.id}`)).toBeVisible();
  await expect(zuordnen.getByTestId(`zuweisung-empfaenger-row-${ausgeschieden.id}`)).toHaveCount(0);
  await zuordnen.getByTestId(`zuweisung-empfaenger-row-${ich.id}`).click();
  await expect(zuordnen.getByTestId('zuweisung-schritt-empfaenger-summary')).toContainText(ich.username);
  await zuordnen.getByRole('button', { name: 'Zuweisen und Übergabe festhalten' }).click();

  await expect(toast(page, `1 iPad(s) an ${BILDUNGSGANG} zugewiesen, übergeben an ${ich.username}`)).toBeVisible();
  await expect(page.getByTestId(`release-btn-${ipad.id}`)).toBeVisible();
  await expect(zeile(page, ipad).getByRole('button', { name: 'Schüler zuordnen' })).toBeVisible();
  expect((await ipadAusApi(request, ipad)).bildungsgang_id).toBe(bg.id);
});

test('Detailansicht zeigt ein Pool-iPad nach dem Speichern weiter als Pool-iPad', async ({ page, request }) => {
  const ipad = await neuesIPad(request);
  await api(request).post(`/ipads/${ipad.id}/release-to-pool`, {});
  await neuLaden(page);
  await filtere(page, ipad);

  await zeile(page, ipad).getByRole('button', { name: ipad.itnr, exact: true }).click();
  const ansicht = detailansicht(page, ipad);
  await expect(ansicht.getByText('🌐 Im Pool')).toBeVisible();
  await expect(ansicht.getByTestId('detail-release-btn')).toHaveCount(0);
  await ansicht.getByTestId('edit-ipad-btn').click();
  await ansicht.getByTestId('ipad-karton-input').fill('K-7');
  await ansicht.getByRole('button', { name: 'Speichern', exact: true }).click();
  await expect(toast(page, 'iPad erfolgreich aktualisiert')).toBeVisible();
  await expect(ansicht.getByText('🌐 Im Pool')).toBeVisible();
  await expect(ansicht.getByTestId('detail-release-btn')).toHaveCount(0);
});
