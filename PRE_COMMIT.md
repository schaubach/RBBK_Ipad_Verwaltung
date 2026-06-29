# Pre-Commit-Hook mit Ruff

Automatischer Code-Check bevor jeder `git commit` durchgeht. Verhindert,
dass typische Bugs (unbenutzte Imports, tote Variablen, kaputter Code) ins
Repository gelangen.

## Setup (einmalig)

```bash
pip install pre-commit
cd /app
pre-commit install
```

Das war's. Ab jetzt läuft der Hook **automatisch bei jedem `git commit`**.

## Was wird geprüft?

| Hook | Wirkung |
|---|---|
| **ruff** (`--fix`) | Lintet Python-Code im `backend/`-Ordner; behebt sichere Issues automatisch (unbenutzte Imports, Reihenfolge, etc.); bricht ab bei echten Bugs |
| **ruff-format** | Formatiert Python-Code (PEP8, Zeilenumbrüche, Quotes) |
| **check-yaml** | Prüft alle YAML-Dateien auf Syntax-Fehler |

## Manuell auslösen

```bash
# Alle Dateien prüfen (z.B. nach Refactor):
pre-commit run --all-files

# Nur bestimmte Datei:
pre-commit run --files backend/routes/ipads.py

# Einzelnen Hook erzwingen:
pre-commit run ruff --all-files
```

## Real-World-Beispiel (Bug der gefangen würde)

Der `require_admin`-Security-Bug aus Session 17 (data_protection.py) wäre nie
ins Repo gelangt: `routes/data_protection.py` importierte `require_admin`, rief
es aber nie auf. Ruff hätte `F401: 'require_admin' imported but unused`
gemeldet und den Commit blockiert.

## Konfiguration

- **Hook-Definition**: `/app/.pre-commit-config.yaml`
- **Ruff-Regeln**: `/app/ruff.toml`

Aktivierte Regel-Gruppen:
- `E`/`W` — pycodestyle Errors/Warnings
- `F` — pyflakes (unused imports, unused vars)
- `B` — bugbear (Mutable defaults, etc.)
- `I` — Import-Sortierung
- `UP` — Modernisierungs-Hinweise
- `S` — Security (Bandit-Regeln)

Bewusst ignoriert (mit Begründung in `ruff.toml`): E501, E722, B008, B904,
UP006/UP007/UP035, S101/S104/S105/S106/S110/S113/S311.

## Hook umgehen (nur Notfall)

```bash
git commit --no-verify -m "..."
```

Bitte nur in Ausnahmefällen — der Hook ist dein Sicherheitsnetz.
