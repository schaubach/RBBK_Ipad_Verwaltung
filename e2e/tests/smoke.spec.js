// Smoke-Test: Kommt die Anwendung hoch, und lässt sich jeder Bereich öffnen, ohne dass im
// Browser etwas abstürzt? Schnell, ohne Daten anzulegen - der erste Blick nach einem Deploy.
const { test, expect } = require('@playwright/test');
const { sammleSeitenfehler, oeffneTab } = require('./helpers');

test.describe('Smoke @smoke', () => {
  test('Backend meldet sich gesund', async ({ request }) => {
    const antwort = await request.get('/api/health');
    expect(antwort.ok()).toBeTruthy();
  });

  test.describe('ohne Anmeldung', () => {
    test.use({ storageState: { cookies: [], origins: [] } });

    test('Login-Seite lädt', async ({ page }) => {
      const fehler = sammleSeitenfehler(page);
      await page.goto('/');
      await expect(page.locator('#username')).toBeVisible();
      await expect(page.locator('#password')).toBeVisible();
      await expect(page.getByRole('button', { name: 'Anmelden' })).toBeVisible();
      expect(fehler).toEqual([]);
    });

    test('unbekannte Adresse führt zurück zur Startseite', async ({ page }) => {
      await page.goto('/gibt/es/nicht');
      await expect(page).toHaveURL(/\/$/);
      await expect(page.getByRole('button', { name: 'Anmelden' })).toBeVisible();
    });
  });

  test('alle Bereiche öffnen sich ohne Fehler', async ({ page }) => {
    const fehler = sammleSeitenfehler(page);
    await page.goto('/');

    await oeffneTab(page, 'Lernende');
    await expect(page.getByRole('button', { name: 'Lernende anlegen' })).toBeVisible();

    await oeffneTab(page, 'iPads');
    await expect(page.getByRole('button', { name: 'Neues iPad anlegen' })).toBeVisible();

    await oeffneTab(page, 'Verträge');
    await expect(page.getByText('Verträge erstellen').first()).toBeVisible();

    await oeffneTab(page, 'Einstellungen');
    await expect(page.getByText('Daten-Import').first()).toBeVisible();

    await oeffneTab(page, 'Admin');
    await expect(page.locator('#bildungsgang-name')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Neuer Benutzer' })).toBeVisible();

    expect(fehler).toEqual([]);
  });

  test('Abmelden führt zur Login-Seite', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: 'Abmelden' }).click();
    await expect(page.getByRole('button', { name: 'Anmelden' })).toBeVisible();
    // Abmelden räumt nur den localStorage DIESES Testkontexts ab; die gespeicherte
    // Sitzung der übrigen Tests bleibt gültig.
  });
});
