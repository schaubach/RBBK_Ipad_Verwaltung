#!/usr/bin/env python3
"""Entfernt das "S", das der Scanner vor Seriennummern gesetzt hat.

Auf Apples Verpackungsetiketten steht vor dem Strichcode der Seriennummer das Kennzeichen
"(S)", und der Scanner liest es mit. Apple-Seriennummern haben 10 Zeichen (seit 2021) oder
12 Zeichen (ältere Geräte). Eine Nummer, die mit "S" beginnt und 11 oder 13 Zeichen lang
ist, trägt also das Kennzeichen - nur diese werden korrigiert. Alles andere bleibt, wie es
ist.

Übersprungen wird ein Gerät, wenn die korrigierte Nummer schon bei einem ANDEREN Gerät
steht: dann ist vermutlich dasselbe Gerät zweimal erfasst, und das muss jemand von Hand
entscheiden. Der Trockenlauf listet diese Fälle auf.

Bereits ausgestellte Leihverträge (PDF) enthalten die alte Nummer weiterhin - sie werden
nicht neu erzeugt.

Standardmäßig ein Trockenlauf. Erst `--apply` verändert Daten. Wiederholbar: ein zweiter
Lauf findet nichts mehr.

Aufruf im Backend-Container:
    docker exec -i ipad_backend python - < scripts/fix-snr-s-prefix.py             # Trockenlauf
    docker exec -i ipad_backend python - < scripts/fix-snr-s-prefix.py -- --apply  # echt

Mit Protokoll:
    docker exec -i ipad_backend python - < scripts/fix-snr-s-prefix.py -- --apply 2>&1 | tee ~/snr-korrektur.log
"""

import asyncio
import os
import sys
from datetime import UTC, datetime

sys.path.insert(0, "/app")
from motor.motor_asyncio import AsyncIOMotorClient  # noqa: E402

APPLY = "--apply" in sys.argv

# Länge MIT dem Kennzeichen: 10- bzw. 12-stellige Seriennummer plus "S".
LAENGEN_MIT_KENNZEICHEN = {11, 13}


def korrigiert(snr: str):
    """Die Nummer ohne Kennzeichen - oder None, wenn sie keins trägt."""
    if snr.startswith("S") and len(snr) in LAENGEN_MIT_KENNZEICHEN:
        return snr[1:]
    return None


async def main():
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client["iPadDatabase"]

    print("=" * 70)
    print("SNr-Korrektur -", "ECHTLAUF" if APPLY else "TROCKENLAUF (nichts wird geändert)")
    print("=" * 70)

    geraete = await db.ipads.find({}, {"id": 1, "itnr": 1, "snr": 1}).to_list(length=None)
    itnr_je_snr = {}
    for g in geraete:
        if g.get("snr"):
            itnr_je_snr.setdefault(g["snr"], []).append(g.get("itnr") or g["id"])

    korrigierbar, kollisionen = [], []
    for g in geraete:
        neu = korrigiert((g.get("snr") or "").strip())
        if not neu:
            continue
        if neu in itnr_je_snr:
            kollisionen.append((g, neu, itnr_je_snr[neu]))
        else:
            korrigierbar.append((g, neu))

    print(f"\nZu korrigieren: {len(korrigierbar)} von {len(geraete)} Geräten")
    for g, neu in sorted(korrigierbar, key=lambda x: x[0].get("itnr") or ""):
        print(f"  {g.get('itnr', '?'):<12} {g['snr']:<14} -> {neu}")

    if kollisionen:
        print(f"\nÜbersprungen, weil die Nummer ohne 'S' schon vergeben ist: {len(kollisionen)}")
        for g, neu, andere in kollisionen:
            print(f"  {g.get('itnr', '?'):<12} {g['snr']:<14} -> {neu} steht schon bei {', '.join(andere)}")

    if not APPLY:
        print("\nTrockenlauf - nichts geändert. Mit --apply ausführen, um zu korrigieren.")
        return

    jetzt = datetime.now(UTC).isoformat()
    geaendert = 0
    for g, neu in korrigierbar:
        # Nur schreiben, wenn die Nummer noch die gelesene ist - falls parallel jemand von Hand
        # korrigiert hat, gewinnt die Hand.
        ergebnis = await db.ipads.update_one(
            {"id": g["id"], "snr": g["snr"]},
            {"$set": {"snr": neu, "updated_at": jetzt}},
        )
        geaendert += ergebnis.modified_count
    print(f"\nKorrigiert: {geaendert} Geräte.")


asyncio.run(main())
