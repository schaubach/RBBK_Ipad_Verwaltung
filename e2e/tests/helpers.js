const fs = require('fs');
const path = require('path');
const ExcelJS = require('exceljs');
const { expect } = require('@playwright/test');

// Das Konto, das /api/auth/setup in einer leeren Datenbank anlegt (routes/auth.py).
// Gilt nur im Wegwerf-Stack aus docker-compose.yml.
const ADMIN = { username: 'admin', password: 'admin123' };

// Ein Bildungsgang für alle Abläufe. Der Admin ist für genau diesen einen zuständig - dann
// setzt das Backend ihn beim Anlegen von selbst ein (core/security.py, resolve_bildungsgang),
// und das Schülerformular, das gar keine Auswahl hat, funktioniert. Kein Test darf den Admin
// für einen ZWEITEN Bildungsgang zuständig machen.
const BILDUNGSGANG = 'E2E Bildungsgang';

const AUTH_DATEI = path.join(__dirname, '..', '.auth', 'admin.json');

// --- Eindeutige Namen ------------------------------------------------------------------
// Je Lauf und Aufruf verschieden, damit Wiederholungen gegen denselben Stack nicht an
// schulweit eindeutigen Werten (ITNr, Benutzername) scheitern.
const LAUF = Date.now().toString(36).toUpperCase();
let zaehler = 0;
function eindeutig(praefix) {
  zaehler += 1;
  return `${praefix}${LAUF}${zaehler}`;
}

// --- Browser ----------------------------------------------------------------------------

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
  return page.locator('[data-sonner-toast]').filter({ hasText: text }).first();
}

/** Das nächste window.confirm bestätigen. */
function bestaetigeNaechstenDialog(page) {
  page.once('dialog', (d) => d.accept());
}

/** Startseite laden und warten, bis die Sitzung steht. */
async function start(page) {
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Abmelden' })).toBeVisible();
}

/** Anmeldung über die Maske, in einem frischen Kontext ohne gespeicherte Sitzung. */
async function anmelden(page, username, password) {
  await page.goto('/');
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);
  await page.getByRole('button', { name: 'Anmelden' }).click();
}

// --- API: Ausgangsdaten schnell anlegen --------------------------------------------------
// Die Tests prüfen einen Bedienweg im Browser. Was dafür nur VORAUSSETZUNG ist (ein Schüler,
// ein iPad, eine Zuordnung), entsteht über die API - schneller, und ein Fehler im Anlegen-
// Dialog lässt dann nicht jeden anderen Test mit rot werden. Das Anlegen über die Oberfläche
// hat seinen eigenen Test in ablauf.spec.js.

function adminToken() {
  const stand = JSON.parse(fs.readFileSync(AUTH_DATEI, 'utf8'));
  for (const o of stand.origins) {
    const eintrag = o.localStorage.find((e) => e.name === 'token');
    if (eintrag) return eintrag.value;
  }
  throw new Error(`Kein Token in ${AUTH_DATEI} - lief das Setup-Projekt?`);
}

function api(request, token = adminToken()) {
  const headers = { Authorization: `Bearer ${token}` };
  const pruefe = async (antwort, was) => {
    if (!antwort.ok()) {
      throw new Error(`${was}: HTTP ${antwort.status()} ${await antwort.text()}`);
    }
    const text = await antwort.text();
    return text ? JSON.parse(text) : null;
  };
  return {
    get: async (url) => pruefe(await request.get(`/api${url}`, { headers }), `GET ${url}`),
    post: async (url, data) => pruefe(await request.post(`/api${url}`, { headers, data }), `POST ${url}`),
    put: async (url, data) => pruefe(await request.put(`/api${url}`, { headers, data }), `PUT ${url}`),
  };
}

async function neuerSchueler(request, felder = {}) {
  return api(request).post('/students', {
    sus_vorn: 'Erika',
    sus_nachn: eindeutig('Probe'),
    sus_kl: 'E2E1',
    ...felder,
  });
}

async function neuesIPad(request, felder = {}) {
  return api(request).post('/ipads', { itnr: eindeutig('E2E-'), snr: eindeutig('SN'), ...felder });
}

async function zuordnen(request, schueler, ipad) {
  return api(request).post('/assignments/manual', { student_id: schueler.id, ipad_id: ipad.id });
}

async function neuerBenutzer(request, felder = {}) {
  return api(request).post('/admin/users', {
    username: eindeutig('lk'),
    password: 'Start-Passwort-1',
    role: 'user',
    ...felder,
  });
}

async function bildungsgangNamens(request, name) {
  const alle = await api(request).get('/bildungsgaenge');
  return alle.find((b) => b.name === name);
}

// --- Dateien -----------------------------------------------------------------------------

/** Excel-Datei im Speicher, für setInputFiles. Alle Werte als Text, wie in einer echten Liste. */
async function excelDatei(name, blatt, kopf, zeilen) {
  const mappe = new ExcelJS.Workbook();
  const ws = mappe.addWorksheet(blatt);
  ws.addRow(kopf);
  for (const z of zeilen) ws.addRow(kopf.map((k) => (z[k] === undefined ? null : String(z[k]))));
  const buffer = Buffer.from(await mappe.xlsx.writeBuffer());
  return {
    name,
    mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    buffer,
  };
}

/** Erste Zeile und Datenzeilen einer heruntergeladenen Excel-Datei. */
async function leseExcel(datei) {
  const mappe = new ExcelJS.Workbook();
  await mappe.xlsx.readFile(datei);
  const ws = mappe.worksheets[0];
  const zeilen = [];
  ws.eachRow((row) => zeilen.push(row.values.slice(1).map((v) => (v == null ? '' : String(v)))));
  return { blatt: ws.name, kopf: zeilen[0] || [], daten: zeilen.slice(1) };
}

/** Kleinstes gültiges PDF mit einer Seite und korrekter Querverweistabelle. */
function pdfDatei(name, text = 'E2E Vertrag') {
  const objekte = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R ' +
      '/Resources << /Font << /F1 5 0 R >> >> >>',
    null, // Inhalt, unten mit Länge
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  const inhalt = `BT /F1 18 Tf 72 760 Td (${text}) Tj ET`;
  objekte[3] = `<< /Length ${inhalt.length} >>\nstream\n${inhalt}\nendstream`;

  let pdf = '%PDF-1.4\n';
  const versatz = [];
  objekte.forEach((o, i) => {
    versatz.push(pdf.length);
    pdf += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const xref = pdf.length;
  pdf += `xref\n0 ${objekte.length + 1}\n0000000000 65535 f \n`;
  for (const v of versatz) pdf += `${String(v).padStart(10, '0')} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objekte.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return { name, mimeType: 'application/pdf', buffer: Buffer.from(pdf, 'latin1') };
}

/** Herunterladen auslösen und auf die Datei warten. */
async function herunterladen(page, ausloeser) {
  const download = page.waitForEvent('download');
  await ausloeser();
  const d = await download;
  return { name: d.suggestedFilename(), pfad: await d.path() };
}

module.exports = {
  ADMIN,
  BILDUNGSGANG,
  AUTH_DATEI,
  eindeutig,
  sammleSeitenfehler,
  oeffneTab,
  toast,
  bestaetigeNaechstenDialog,
  start,
  anmelden,
  api,
  neuerSchueler,
  neuesIPad,
  zuordnen,
  neuerBenutzer,
  bildungsgangNamens,
  excelDatei,
  leseExcel,
  pdfDatei,
  herunterladen,
};
