# Prüfungen: lokal beim Commit, auf GitHub bei jedem Push

Zwei Stufen, damit das Committen schnell bleibt und trotzdem nichts ungeprüft auf `main` landet:

| Wann | Was | Dauer |
|---|---|---|
| **`git commit`** (lokal, pre-commit-Hook) | Ruff (Lint + Format) für `backend/`, YAML-Syntax | Sekunden |
| **`git push`** (GitHub Actions, `.github/workflows/ci.yml`) | `lint`: dieselben Hooks noch einmal · `backend`: pytest gegen MongoDB · `frontend`: Produktions-Build inkl. ESLint · `e2e`: Playwright im Browser - Smoke-Test und jede Funktion einmal auf dem Normalweg (siehe unten) | einige Minuten |

Die langsamen Prüfungen (Backend-Suite ~6 min, E2E mit Docker-Build) laufen bewusst NICHT beim
Commit, sondern nur in der CI. Das Ergebnis steht auf GitHub unter **Actions** und als
Haken/Kreuz am Commit.

## Browser-Tests (e2e/)

Playwright gegen einen Wegwerf-Stack (`e2e/docker-compose.yml`: leere MongoDB, Backend-Image,
Produktions-Build des Frontends). Je Bereich eine Datei unter `e2e/tests/`:

| Datei | Was |
|---|---|
| `smoke.spec.js` | Backend gesund, Login-Seite, alle Bereiche öffnen ohne Konsolenfehler, Abmelden |
| `ablauf.spec.js` | Kernablauf über die Oberfläche: Schüler → iPad → Zuordnung → Vertrag |
| `schueler.spec.js` | Detailansicht, Bearbeiten, Zuordnung lösen, Löschen (iPad wird frei) |
| `ipads.spec.js` | Bearbeiten, Status „defekt“, Zuordnung lösen, Löschen, Pool hin und zurück |
| `vertraege.spec.js` | Hochladen (automatisch / von Hand zugeordnet), Herunterladen, Löschen, Warnung beim Erstellen |
| `import-export.spec.js` | Import-Vorlage, Excel-Import, Datensicherung, Schüler- und iPad-Export mit Spaltenwahl |
| `batch.spec.js` | Batch-Zuordnung per Datei: neu, aus dem Pool, quittiert, ungültige Zeile, CSV-Protokoll |
| `benutzer.spec.js` | Anlegen, Bearbeiten, Deaktivieren, Passwort zurücksetzen mit Zwangswechsel, Löschen, Sicht einer Lehrkraft |
| `bildungsgaenge.spec.js` | Anlegen, Umbenennen, Zuständigkeit, Löschen (leer / mit Daten), globale Standardwerte |
| `backup.spec.js` | Backup-Passwort, Server-Backup erstellen/herunterladen, wieder einspielen |

Regeln, die die Wiederholbarkeit sichern:
- Ausgangsdaten (ein Schüler, ein iPad, ...) entstehen über die API, geprüft wird der eine Bedienweg im Browser.
- Der Admin ist für **genau einen** Bildungsgang zuständig - kein Test darf das ändern.
- Ein Konsolenfehler im Browser lässt den Test scheitern.
- **Bekannte Fehler der App** stehen als `test.fail()` mit Begründung im Test (wie `xfail` im
  Backend). Ist ein Fehler behoben, wird der Test als „unexpectedly passed“ rot - dann gehört
  `test.fail()` heraus.
- Im Test-Stack ist die Mengenbegrenzung aus (`DISABLE_RATE_LIMIT=true`), weil alle Aufrufe
  über einen Proxy von derselben Adresse kommen. Die Bremse selbst prüft `backend/tests/test_ratelimit.py`.

Lokal ausführen:

```bash
cd e2e && npm ci && npm run stack:up
E2E_CHANNEL=chrome npx playwright test     # installiertes Chrome; ohne Variable: npx playwright install chromium
npm run stack:down
```

## Einrichtung (einmalig je Rechner)

```bash
brew install pre-commit      # oder: pip install pre-commit
pre-commit install           # im Repo-Wurzelverzeichnis
```

Ab jetzt läuft der Hook bei jedem `git commit`. Was Ruff selbst beheben kann (Import-Reihenfolge,
Formatierung), behebt er - der Commit bricht dann einmal ab, die Änderungen liegen im
Arbeitsverzeichnis: anschauen, `git add`, nochmal committen.

## Was wird geprüft?

| Hook | Wirkung |
|---|---|
| **ruff** (`--fix`) | Lintet Python-Code in `backend/`; behebt sichere Fälle selbst (unbenutzte Imports, Reihenfolge, ...); bricht ab bei echten Fehlern |
| **ruff-format** | Formatiert Python-Code einheitlich |
| **check-yaml** | Prüft alle YAML-Dateien auf Syntaxfehler (u. a. die CI-Definition und die Compose-Dateien) |

Ruff ist kein Test, sondern ein Linter: Er führt den Code nicht aus, sondern liest ihn und
erkennt typische Fehlermuster. Beispiel: `routes/data_protection.py` importierte einst
`require_admin`, rief es aber nie auf - die Rechteprüfung fehlte. Ruff meldet so etwas als
`F401: imported but unused` und hält den Commit an.

## Manuell auslösen

```bash
pre-commit run --all-files                       # alles
pre-commit run --files backend/routes/ipads.py   # eine Datei
pre-commit run ruff --all-files                  # ein Hook
```

## Konfiguration

- Hooks: `.pre-commit-config.yaml`
- Ruff-Regeln: `ruff.toml` (Regelgruppen E/W, F, B, I, UP, S; bewusste Ausnahmen mit Begründung dort)
- CI: `.github/workflows/ci.yml`

## Hook umgehen (nur Notfall)

```bash
git commit --no-verify -m "..."
```

Der `lint`-Job in der CI prüft trotzdem - ein übergangener Hook fällt spätestens dort auf.
