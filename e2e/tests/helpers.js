const { expect } = require('@playwright/test');

// Das Konto, das /api/auth/setup in einer leeren Datenbank anlegt (routes/auth.py).
// Gilt nur im Wegwerf-Stack aus docker-compose.yml.
const ADMIN = { username: 'admin', password: 'admin123' };

// Ein Bildungsgang für alle Abläufe. Der Admin ist für genau diesen einen zuständig - dann
// setzt das Backend ihn beim Anlegen von selbst ein (core/security.py, resolve_bildungsgang),
// und das Schülerformular, das gar keine Auswahl hat, funktioniert.
const BILDUNGSGANG = 'E2E Bildungsgang';

/**
 * Sammelt Fehler aus der Browser-Konsole und nicht abgefangene Ausnahmen der Seite.
 * Aufrufen, BEVOR die Seite geladen wird.
 */
function sammleSeitenfehler(page) {
  const fehler = [];
  page.on('pageerror', (e) => fehler.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') fehler.push(`console: ${m.text()}`);
  });
  return fehler;
}

async function oeffneTab(page, name) {
  await page.getByRole('tab', { name }).click();
  await expect(page.getByRole('tab', { name })).toHaveAttribute('aria-selected', 'true');
}

/** Toast von sonner (unten rechts). */
function toast(page, text) {
  return page.locator('[data-sonner-toast]').filter({ hasText: text });
}

module.exports = { ADMIN, BILDUNGSGANG, sammleSeitenfehler, oeffneTab, toast };
