// Benutzer: Anlegen, Bearbeiten, Deaktivieren, Passwort zurücksetzen (mit erzwungenem
// Wechsel bei der nächsten Anmeldung), vollständig Löschen - und was eine Lehrkraft sieht.
//
// Wer sich als jemand anderes anmeldet, tut das in einem EIGENEN Browser-Kontext: Die
// Sitzung des Admins (gespeicherter Zustand der übrigen Tests) bleibt davon unberührt.
const { test, expect } = require('@playwright/test');
const {
  BILDUNGSGANG,
  start,
  oeffneTab,
  toast,
  anmelden,
  sammleSeitenfehler,
  bestaetigeNaechstenDialog,
  neuerSchueler,
  neuerBenutzer,
  bildungsgangNamens,
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

function zeile(page, username) {
  return page.getByRole('row').filter({ has: page.getByRole('cell', { name: username, exact: true }) });
}

/** Neuer, leerer Kontext - ohne die gespeicherte Admin-Sitzung. */
async function fremderBrowser(browser) {
  const kontext = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  return { kontext, seite: await kontext.newPage() };
}

test('Benutzer anlegen und bearbeiten', async ({ page }) => {
  const name = eindeutig('lk');
  await page.getByRole('button', { name: 'Neuer Benutzer' }).click();
  await page.locator('#new-username').fill(name);
  await page.locator('#new-password').fill('Start-Passwort-1');
  await page.locator('#new-role').selectOption('user');
  await page.locator('#new-comment').fill('angelegt im E2E-Test');
  await page.getByRole('button', { name: 'Erstellen', exact: true }).click();

  await expect(toast(page, `Benutzer ${name} erfolgreich erstellt!`)).toBeVisible();
  await expect(zeile(page, name)).toContainText('Benutzer');
  await expect(zeile(page, name)).toContainText('angelegt im E2E-Test');

  await zeile(page, name).getByTitle('Benutzer bearbeiten').click();
  await page.locator('#edit-comment').fill('geändert im E2E-Test');
  await page.getByRole('button', { name: 'Aktualisieren', exact: true }).click();
  await expect(toast(page, `Benutzer ${name} erfolgreich aktualisiert!`)).toBeVisible();
  await expect(zeile(page, name)).toContainText('geändert im E2E-Test');
});

test('Deaktivierter Benutzer kann sich nicht mehr anmelden', async ({ page, request, browser }) => {
  const u = await neuerBenutzer(request);
  await page.reload();
  await oeffneTab(page, 'Admin');

  bestaetigeNaechstenDialog(page);
  await zeile(page, u.username).getByTitle('Benutzer deaktivieren').click();
  await expect(toast(page, `User ${u.username} has been deactivated`)).toBeVisible();
  await expect(zeile(page, u.username)).toContainText('Deaktiviert');

  const { kontext, seite } = await fremderBrowser(browser);
  await anmelden(seite, u.username, 'Start-Passwort-1');
  await expect(toast(seite, 'User account is deactivated')).toBeVisible();
  await expect(seite.getByRole('button', { name: 'Abmelden' })).toHaveCount(0);
  await kontext.close();
});

test('Passwort zurücksetzen erzwingt einen Wechsel bei der nächsten Anmeldung', async ({
  page,
  request,
  browser,
}) => {
  const u = await neuerBenutzer(request);
  await page.reload();
  await oeffneTab(page, 'Admin');

  bestaetigeNaechstenDialog(page);
  await zeile(page, u.username).getByTitle('Passwort zurücksetzen').click();
  await expect(toast(page, 'Passwort wurde zurückgesetzt')).toBeVisible();
  const ergebnis = page.locator('div.fixed').filter({ hasText: 'Passwort erfolgreich zurückgesetzt!' });
  const temporaer = await ergebnis.locator('input[readonly]').inputValue();
  expect(temporaer).toMatch(/^\d{8}$/);
  await ergebnis.getByRole('button', { name: 'Verstanden' }).click();
  await expect(zeile(page, u.username)).toContainText('PW ändern');

  // Die Lehrkraft meldet sich mit dem temporären Passwort an und muss es ändern.
  const { kontext, seite } = await fremderBrowser(browser);
  await anmelden(seite, u.username, temporaer);
  await expect(seite.getByText('Passwort ändern erforderlich')).toBeVisible();
  await seite.locator('#new-password').fill('Neues-Passwort-2');
  await seite.locator('#confirm-password').fill('Neues-Passwort-2');
  await seite.getByRole('button', { name: 'Passwort ändern' }).click();
  await expect(toast(seite, 'Passwort erfolgreich geändert!')).toBeVisible();

  // Danach gilt nur noch das neue.
  await seite.locator('#password').fill('Neues-Passwort-2');
  await seite.getByRole('button', { name: 'Anmelden' }).click();
  await expect(seite.getByRole('button', { name: 'Abmelden' })).toBeVisible();
  await kontext.close();
});

test('Benutzer vollständig löschen', async ({ page, request }) => {
  const u = await neuerBenutzer(request);
  await page.reload();
  await oeffneTab(page, 'Admin');

  await zeile(page, u.username).getByTitle('VOLLSTÄNDIG LÖSCHEN (inkl. aller Daten!)').click();
  await page.getByRole('button', { name: 'Weiter zur Bestätigung' }).click();
  const endgueltig = page.getByRole('button', { name: 'ENDGÜLTIG LÖSCHEN' });
  await expect(endgueltig).toBeDisabled();
  await page.locator('#delete-confirm').fill(u.username);
  await endgueltig.click();

  await expect(toast(page, `Benutzerkonto '${u.username}' wurde gelöscht.`)).toBeVisible();
  await expect(zeile(page, u.username)).toHaveCount(0);
});

test('Lehrkraft sieht nur ihren Bildungsgang und keinen Admin-Bereich', async ({ request, browser }) => {
  // Eine Lehrkraft, zuständig für einen eigenen Bildungsgang mit einem Schüler. Ein zweiter
  // Schüler gehört zum gemeinsamen Test-Bildungsgang - den darf sie nicht sehen.
  const a = api(request);
  const u = await neuerBenutzer(request);
  const eigenerBg = await a.post('/bildungsgaenge', { name: eindeutig('E2E LK ') });
  await a.post(`/bildungsgaenge/${eigenerBg.id}/zustaendige`, { user_id: u.id });
  const eigener = await neuerSchueler(request, { bildungsgang_id: eigenerBg.id });
  const fremder = await neuerSchueler(request, {
    bildungsgang_id: (await bildungsgangNamens(request, BILDUNGSGANG)).id,
  });

  const { kontext, seite } = await fremderBrowser(browser);
  const fehlerLk = sammleSeitenfehler(seite);
  await anmelden(seite, u.username, 'Start-Passwort-1');
  await expect(seite.getByRole('button', { name: 'Abmelden' })).toBeVisible();
  await expect(seite.getByText('ADMIN', { exact: true })).toHaveCount(0);

  // innerText: Jeder Reiter trägt Lang- und Kurznamen, sichtbar ist je nach Breite nur einer.
  await expect(seite.getByRole('tab')).toHaveText(['Lernende', 'iPads', 'Verträge', 'Einstellungen'], {
    useInnerText: true,
  });
  await expect(seite.getByRole('tab', { name: 'Admin' })).toHaveCount(0);

  await expect(seite.getByRole('row').filter({ hasText: eigener.sus_nachn })).toHaveCount(1);
  await expect(seite.getByRole('row').filter({ hasText: fremder.sus_nachn })).toHaveCount(0);

  // Kein Anlegen von iPads für Lehrkräfte.
  await oeffneTab(seite, 'iPads');
  await expect(seite.getByRole('button', { name: 'Neues iPad anlegen' })).toHaveCount(0);

  // Das eigene Passwort ändern.
  await oeffneTab(seite, 'Einstellungen');
  await seite.locator('#current_password').fill('Start-Passwort-1');
  await seite.locator('#new_password').fill('Eigenes-Passwort-3');
  await seite.locator('#confirm_password').fill('Eigenes-Passwort-3');
  await seite.getByRole('button', { name: 'Passwort ändern' }).click();
  await expect(toast(seite, 'Password changed successfully')).toBeVisible();

  expect(fehlerLk, 'Fehler in der Browser-Konsole der Lehrkraft').toEqual([]);
  await kontext.close();
});

test('Falsches Passwort meldet keinen Sitzungsablauf', async ({ browser }) => {
  const { kontext, seite } = await fremderBrowser(browser);
  await anmelden(seite, 'admin', 'falsches-passwort');
  await expect(toast(seite, 'Invalid credentials')).toBeVisible();
  await expect(seite.locator('[data-sonner-toast]').filter({ hasText: 'Session' })).toHaveCount(0, {
    timeout: 2_000,
  });
  await kontext.close();
});
