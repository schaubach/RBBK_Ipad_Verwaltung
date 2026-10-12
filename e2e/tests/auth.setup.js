// Ersteinrichtung und Anmeldung - einmal für die ganze Suite (siehe playwright.config.js).
//
// Auf einer leeren Datenbank legt die Login-Seite beim Laden selbst das Konto admin/admin123
// an (GET /auth/setup-status, dann POST /auth/setup). Das ist hier zugleich der Test dafür,
// dass eine frische Installation überhaupt betretbar ist. Läuft der Stack schon länger,
// existiert das Konto bereits und der Hinweis bleibt aus - beides ist in Ordnung.
//
// Danach die gemeinsame Ausgangslage aller Tests: der Bildungsgang BILDUNGSGANG mit dem
// Admin als einzigem Zuständigen. Über die API, denn das Anlegen über die Oberfläche hat
// eigene Tests (bildungsgaenge.spec.js, ablauf.spec.js).
const { test: setup, expect } = require('@playwright/test');
const { ADMIN, BILDUNGSGANG, AUTH_DATEI, api } = require('./helpers');

setup('Ersteinrichtung und Anmeldung als admin', async ({ page, request }) => {
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

  await page.context().storageState({ path: AUTH_DATEI });

  // Gemeinsame Ausgangslage.
  const a = api(request);
  const ich = await a.get('/auth/me');
  let bg = (await a.get('/bildungsgaenge')).find((b) => b.name === BILDUNGSGANG);
  if (!bg) bg = await a.post('/bildungsgaenge', { name: BILDUNGSGANG, description: 'Playwright' });
  const zustaendig = bg.zustaendige.some((z) => z.user_id === ich.id && !z.bis);
  if (!zustaendig) await a.post(`/bildungsgaenge/${bg.id}/zustaendige`, { user_id: ich.id });

  const meine = (await a.get('/bildungsgaenge')).filter((b) =>
    b.zustaendige.some((z) => z.user_id === ich.id && !z.bis)
  );
  expect(meine.map((b) => b.name), 'Admin muss für GENAU einen Bildungsgang zuständig sein').toEqual([
    BILDUNGSGANG,
  ]);
});
