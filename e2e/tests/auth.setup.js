// Ersteinrichtung und Anmeldung - einmal für die ganze Suite (siehe playwright.config.js).
//
// Auf einer leeren Datenbank legt die Login-Seite beim Laden selbst das Konto admin/admin123
// an (GET /auth/setup-status, dann POST /auth/setup). Das ist hier zugleich der Test dafür,
// dass eine frische Installation überhaupt betretbar ist. Läuft der Stack schon länger,
// existiert das Konto bereits und der Hinweis bleibt aus - beides ist in Ordnung.
const { test: setup, expect } = require('@playwright/test');
const { ADMIN } = require('./helpers');

setup('Ersteinrichtung und Anmeldung als admin', async ({ page }) => {
  const setupStatus = page.waitForResponse((r) => r.url().endsWith('/api/auth/setup-status'));
  await page.goto('/');
  const antwort = await setupStatus;
  expect(antwort.ok()).toBeTruthy();

  if ((await antwort.json()).setup_required) {
    await expect(page.getByText('Ersteinrichtung abgeschlossen')).toBeVisible();
  }

  await page.locator('#username').fill(ADMIN.username);
  await page.locator('#password').fill(ADMIN.password);
  await page.getByRole('button', { name: 'Anmelden' }).click();

  await expect(page.getByRole('button', { name: 'Abmelden' })).toBeVisible();
  await expect(page.getByText('ADMIN', { exact: true })).toBeVisible();

  await page.context().storageState({ path: '.auth/admin.json' });
});
