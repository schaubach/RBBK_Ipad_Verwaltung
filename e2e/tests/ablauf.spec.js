// E2E: der Kernablauf der Verwaltung, so wie ein Mensch ihn durch die Oberfläche klickt.
//
//   Bildungsgang anlegen und sich zuständig machen
//   -> Schüler anlegen -> iPad anlegen -> iPad dem Schüler zuordnen -> Vertrag erstellen
//
// Die Schritte bauen aufeinander auf (test.describe.serial): scheitert einer, werden die
// übrigen übersprungen statt mit Folgefehlern rot zu werden.
//
// Schüler und iPad tragen eine Kennung je Lauf, damit ein zweiter Lauf gegen denselben
// Stack nicht an der schulweit eindeutigen ITNr scheitert. Der Bildungsgang dagegen bleibt
// derselbe: Mit einer zweiten Zuständigkeit müsste der Admin beim Anlegen wählen, und das
// Schülerformular hat dafür kein Feld.
const { test, expect } = require('@playwright/test');
const { ADMIN, BILDUNGSGANG, sammleSeitenfehler, oeffneTab, toast } = require('./helpers');

const lauf = Date.now().toString(36).toUpperCase();
const SCHUELER = { vorname: 'Erika', nachname: `Probe${lauf}`, klasse: 'E2E1' };
const ITNR = `E2E-${lauf}`;

test.describe.serial('Kernablauf', () => {
  let fehler;

  test.beforeEach(async ({ page }) => {
    fehler = sammleSeitenfehler(page);
    await page.goto('/');
    await expect(page.getByRole('button', { name: 'Abmelden' })).toBeVisible();
  });

  test.afterEach(() => {
    expect(fehler, 'Fehler in der Browser-Konsole').toEqual([]);
  });

  test('Bildungsgang anlegen und Admin zuständig machen', async ({ page }) => {
    await oeffneTab(page, 'Admin');
    const eintrag = page.locator('li').filter({ hasText: BILDUNGSGANG });

    // Die Liste kommt asynchron; erst danach ist "fehlt" eine verlässliche Aussage.
    await expect(page.locator('#bildungsgang-name')).toBeVisible();
    await page.waitForLoadState('networkidle');

    if ((await eintrag.count()) === 0) {
      await page.locator('#bildungsgang-name').fill(BILDUNGSGANG);
      await page.locator('#bildungsgang-description').fill('angelegt von den Playwright-Tests');
      await page.getByRole('button', { name: 'Anlegen', exact: true }).click();
      await expect(toast(page, 'Bildungsgang angelegt')).toBeVisible();
    }
    await expect(eintrag).toBeVisible();

    if (await eintrag.getByText('Derzeit ist niemand zuständig.').isVisible()) {
      await eintrag.getByRole('button', { name: 'Zuständige Person hinzufügen' }).click();
      await eintrag.locator('[data-testid^="zustaendig-user-"]').filter({ hasText: ADMIN.username }).click();
      await expect(toast(page, `${ADMIN.username} ist jetzt für "${BILDUNGSGANG}" zuständig`)).toBeVisible();
    }
    await expect(eintrag.getByText('1 zuständige Person')).toBeVisible();
  });

  test('Lernende anlegen', async ({ page }) => {
    await oeffneTab(page, 'Lernende');
    await page.getByRole('button', { name: 'Lernende anlegen' }).click();

    const dialog = page.getByRole('alertdialog', { name: 'Lernende anlegen' });
    await dialog.locator('#sus_vorn').fill(SCHUELER.vorname);
    await dialog.locator('#sus_nachn').fill(SCHUELER.nachname);
    await dialog.locator('#sus_kl').fill(SCHUELER.klasse);
    await dialog.locator('#sus_geb').fill('01.02.2008');
    await dialog.locator('#sus_str').fill('Teststraße 1');
    await dialog.locator('#sus_ort').fill('44135 Dortmund');
    await dialog.getByRole('button', { name: 'Anlegen', exact: true }).click();

    await expect(toast(page, 'Lernende erfolgreich angelegt!')).toBeVisible();
    await page.locator('#student-nachname-filter').fill(SCHUELER.nachname);
    const zeile = page.getByRole('row').filter({ hasText: SCHUELER.nachname });
    await expect(zeile).toBeVisible();
    await expect(zeile.getByText('Ohne iPad')).toBeVisible();
  });

  test('iPad anlegen', async ({ page }) => {
    await oeffneTab(page, 'iPads');
    await page.getByRole('button', { name: 'Neues iPad anlegen' }).click();

    const dialog = page.getByRole('alertdialog', { name: 'Neues iPad anlegen' });
    await dialog.locator('#itnr').fill(ITNR);
    await dialog.locator('#snr').fill(`SN${lauf}`);
    // Genau eine Zuständigkeit: keine Bildungsgang-Auswahl, das Backend setzt ihn selbst.
    await expect(dialog.locator('#create-bildungsgang')).toHaveCount(0);
    await dialog.getByRole('button', { name: 'iPad anlegen' }).click();

    await expect(toast(page, 'iPad erfolgreich angelegt!')).toBeVisible();
    await expect(page.getByRole('row').filter({ hasText: ITNR })).toBeVisible();
  });

  test('iPad einer lernenden Person zuordnen', async ({ page }) => {
    await oeffneTab(page, 'Lernende');
    await page.locator('#student-nachname-filter').fill(SCHUELER.nachname);
    const zeile = page.getByRole('row').filter({ hasText: SCHUELER.nachname });
    await zeile.getByRole('button', { name: 'iPad zuordnen' }).click();

    const dialog = page.getByRole('alertdialog', { name: 'iPad zuordnen' });
    await dialog.getByPlaceholder('iPad suchen (ITNr)...').fill(ITNR);
    await dialog.getByText(ITNR, { exact: true }).click();

    await expect(
      toast(page, `iPad ${ITNR} erfolgreich ${SCHUELER.vorname} ${SCHUELER.nachname} zugewiesen`)
    ).toBeVisible();
    await expect(zeile.getByText('1 iPad(s)')).toBeVisible();
  });

  test('Vertrag für die Zuordnung erstellen', async ({ page }) => {
    await oeffneTab(page, 'Verträge');
    await page.locator('#create-itnr').fill(ITNR);

    const tabelle = page.getByTestId('generation-selection-table');
    await expect(tabelle.getByRole('row').filter({ hasText: ITNR })).toBeVisible();

    const alle = page.getByTestId('generation-select-all-checkbox');
    if ((await alle.getAttribute('data-state')) !== 'checked') await alle.click();
    const erstellen = page.getByTestId('generate-filtered-contracts-btn');
    await expect(erstellen).toHaveText(/\(1 von 1\)/);

    const download = page.waitForEvent('download');
    await erstellen.click();
    // Fehlende Angaben (z. B. Erziehungsberechtigte) fragt die Oberfläche vorher ab.
    const warnung = page.getByTestId('confirm-generate-warnings-btn');
    if (await warnung.isVisible({ timeout: 2_000 }).catch(() => false)) await warnung.click();

    expect((await download).suggestedFilename()).toMatch(/\.zip$/);
    await expect(toast(page, 'erfolgreich erstellt')).toBeVisible();
  });
});
