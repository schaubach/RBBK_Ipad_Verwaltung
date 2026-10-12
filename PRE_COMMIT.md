# Prüfungen: lokal beim Commit, auf GitHub bei jedem Push

Zwei Stufen, damit das Committen schnell bleibt und trotzdem nichts ungeprüft auf `main` landet:

| Wann | Was | Dauer |
|---|---|---|
| **`git commit`** (lokal, pre-commit-Hook) | Ruff (Lint + Format) für `backend/`, YAML-Syntax | Sekunden |
| **`git push`** (GitHub Actions, `.github/workflows/ci.yml`) | `lint`: dieselben Hooks noch einmal · `backend`: pytest gegen MongoDB · `frontend`: Produktions-Build inkl. ESLint · `e2e`: Playwright-Smoke-Test und Kernablauf im Browser | einige Minuten |

Die langsamen Prüfungen (Backend-Suite ~6 min, E2E mit Docker-Build) laufen bewusst NICHT beim
Commit, sondern nur in der CI. Das Ergebnis steht auf GitHub unter **Actions** und als
Haken/Kreuz am Commit.

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
