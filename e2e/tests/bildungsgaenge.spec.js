// Bildungsgänge (Admin-Bereich): Anlegen, Umbenennen, Zuständigkeit vergeben und beenden,
// Löschen - und dass ein Bildungsgang mit Daten sich nicht löschen lässt.
//
// Zuständig gemacht wird hier immer eine Lehrkraft, nie der Admin: Er muss für genau EINEN
// Bildungsgang zuständig bleiben (siehe helpers.js, BILDUNGSGANG).
const { test, expect } = require('@playwright/test');
const {
  start,
  oeffneTab,
  toast,
  sammleSeitenfehler,
  erlaubeFehler,
  bestaetigeNaechstenDialog,
  neuerSchueler,
  neuerBenutzer,
  eindeutig,
  api,
} = require('./helpers');

let fehler;
test.beforeEach(async ({ page }) => {
  fehler = sammleSeitenfehler(page);
  await start(page);
  await oeffneTab(page, 'Admin');
});
test.afterEach(() => expect(fehler, 'Fehler in der Browser-Konsole').toEqual([]));

function eintrag(page, name) {
  return page.locator('li').filter({ has: page.getByText(name, { exact: true }) });
}

async function neuLaden(page) {
  await page.reload();
  await oeffneTab(page, 'Admin');
}

test('Bildungsgang anlegen und umbenennen', async ({ page }) => {
  const name = eindeutig('E2E BG ');
  await page.locator('#bildungsgang-name').fill(name);
  await page.locator('#bildungsgang-description').fill('aus dem E2E-Test');
  await page.getByRole('button', { name: 'Anlegen', exact: true }).click();
  await expect(toast(page, 'Bildungsgang angelegt')).toBeVisible();
  await expect(eintrag(page, name)).toContainText('Derzeit ist niemand zuständig.');

  const neuerName = `${name} (neu)`;
  await eintrag(page, name).getByTitle('Bildungsgang bearbeiten').click();
  await expect(page.locator('#bildungsgang-name')).toHaveValue(name);
  await page.locator('#bildungsgang-name').fill(neuerName);
  await page.getByRole('button', { name: 'Speichern', exact: true }).click();
  await expect(toast(page, 'Bildungsgang gespeichert')).toBeVisible();
  await expect(eintrag(page, neuerName)).toBeVisible();
  await expect(eintrag(page, name)).toHaveCount(0);
});

test('Zuständigkeit vergeben und beenden', async ({ page, request }) => {
  const u = await neuerBenutzer(request);
  const bg = await api(request).post('/bildungsgaenge', { name: eindeutig('E2E BG ') });
  await neuLaden(page);

  const e = eintrag(page, bg.name);
  await e.getByRole('button', { name: 'Zuständige Person hinzufügen' }).click();
  await e.getByTestId(`zustaendig-search-${bg.id}`).fill(u.username);
  await e.getByTestId(`zustaendig-user-${bg.id}-${u.id}`).click();
  await expect(toast(page, `${u.username} ist jetzt für "${bg.name}" zuständig`)).toBeVisible();
  await expect(e).toContainText('1 zuständige Person');

  bestaetigeNaechstenDialog(page);
  await e.getByRole('button', { name: 'Beenden' }).click();
  await expect(toast(page, `Zuständigkeit von ${u.username} wurde beendet`)).toBeVisible();
  await expect(e).toContainText('Derzeit ist niemand zuständig.');
  await expect(e).toContainText('Frühere Zuständigkeiten');
  await expect(e).toContainText(u.username);
});

test('Leeren Bildungsgang löschen', async ({ page, request }) => {
  const bg = await api(request).post('/bildungsgaenge', { name: eindeutig('E2E BG ') });
  await neuLaden(page);

  bestaetigeNaechstenDialog(page);
  await eintrag(page, bg.name).getByTitle(/^Bildungsgang löschen/).click();
  await expect(toast(page, `Bildungsgang "${bg.name}" wurde gelöscht.`)).toBeVisible();
  await expect(eintrag(page, bg.name)).toHaveCount(0);
});

test('Bildungsgang mit Schülern lässt sich nicht löschen', async ({ page, request }) => {
  const bg = await api(request).post('/bildungsgaenge', { name: eindeutig('E2E BG ') });
  await neuerSchueler(request, { bildungsgang_id: bg.id });
  await neuLaden(page);

  bestaetigeNaechstenDialog(page);
  await eintrag(page, bg.name).getByTitle(/^Bildungsgang löschen/).click();
  await expect(toast(page, `Bildungsgang "${bg.name}" besitzt noch`)).toBeVisible();
  await expect(eintrag(page, bg.name)).toBeVisible();
  erlaubeFehler(fehler, /status of 400/);
});

test('Globale Standardwerte gelten für neue iPads', async ({ page, request }) => {
  const typ = eindeutig('iPad Test ');
  const vorher = await api(request).get('/settings/global');
  try {
    await page.locator('#ipad_typ').fill(typ);
    await page.locator('#pencil').fill('mit Apple Pencil');
    await page.getByRole('button', { name: 'Einstellungen speichern' }).click();
    await expect(toast(page, 'Einstellungen erfolgreich aktualisiert')).toBeVisible();

    await oeffneTab(page, 'iPads');
    await page.getByRole('button', { name: 'Neues iPad anlegen' }).click();
    const dialog = page.getByRole('alertdialog', { name: 'Neues iPad anlegen' });
    await expect(dialog.locator('#typ')).toHaveValue(typ);
    await expect(dialog.locator('#pencil')).toHaveValue('mit Apple Pencil');
  } finally {
    await api(request).put('/settings/global', vorher);
  }
});
