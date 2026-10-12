// Playwright gegen den Wegwerf-Stack aus docker-compose.yml (Frontend :3000, Backend :8001).
//
// Die Anmeldung läuft genau EINMAL, im Projekt "setup", und alle anderen Tests übernehmen
// deren Sitzung: /api/auth/login lässt nur fünf Versuche pro Minute zu, und mit einer
// Anmeldung je Test wäre die Suite ab dem sechsten Test rot - aus einem Grund, der mit dem
// Geprüften nichts zu tun hat.
const { defineConfig, devices } = require('@playwright/test');

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:3000';

module.exports = defineConfig({
  testDir: './tests',
  // Die Abläufe bauen in einer gemeinsamen Datenbank aufeinander auf.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : [['list']],
  use: {
    baseURL: BASE_URL,
    locale: 'de-DE',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'setup', testMatch: /auth\.setup\.js/ },
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], storageState: '.auth/admin.json' },
      dependencies: ['setup'],
    },
  ],
});
