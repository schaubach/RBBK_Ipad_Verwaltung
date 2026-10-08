#!/usr/bin/env python3
"""Wandert die Zugehörigkeit von Benutzern auf Bildungsgänge.

Standardmäßig ein Trockenlauf: es wird nur berichtet, was geschähe. Erst `--apply`
verändert Daten. Vorher ein Backup ziehen - die Löschungen am Ende sind endgültig.

Aufruf im Backend-Container:
    docker exec -i ipad_backend python - < scripts/migrate-to-bildungsgang.py            # Trockenlauf
    docker exec -i ipad_backend python - < scripts/migrate-to-bildungsgang.py -- --apply # echt
"""

import asyncio
import os
import sys
import uuid
from datetime import UTC, datetime

sys.path.insert(0, "/app")
from motor.motor_asyncio import AsyncIOMotorClient  # noqa: E402

APPLY = "--apply" in sys.argv

# --- Zuordnung, wie mit der Schulleitung abgestimmt ---------------------------
# Wem die DATEN eines Kontos künftig gehören. Ein Konto -> genau ein Bildungsgang.
DATEN_NACH = {
    "admin": "Lehrkräfte",      # 105 Geräte + 122 Lehrkraft-Datensätze aus einem Massenimport
    "wieners": "Lehrkräfte",
    "bakenecker": "GYM",
    "schaubach": "MEDA",
    "kunze": "OP",
    "barvar": "FSMV",
    "keggenhoff": "ET",
    "malina": "HÖTE",
    "mehinagic": "BFS",
    "graaff": "MT",
    "papoulias": "ITA",
}

# Wer wofür ZUSTÄNDIG ist. Mehrfachnennung ausdrücklich erlaubt - das ist der Kern des Umbaus.
# Das Konto "admin" bekommt bewusst keine Zuständigkeit: es ist ein Verwaltungskonto, kein
# Bildungsgang. Seine Daten gehen an Lehrkräfte, betreut von wieners.
ZUSTAENDIG = {
    "wieners": ["Lehrkräfte"],
    "bakenecker": ["GYM"],
    "schaubach": ["MEDA", "IT"],
    "kunze": ["OP"],
    "barvar": ["FSMV"],
    "keggenhoff": ["ET"],
    "malina": ["HÖTE"],
    "mehinagic": ["BFS", "AVWH"],
    "graaff": ["MT"],
    "papoulias": ["ITA"],
    # timpte: Bildungsgang noch offen, hält keine Daten
}

ALLE_BILDUNGSGAENGE = sorted({b for v in ZUSTAENDIG.values() for b in v} | set(DATEN_NACH.values()))
NEU_ANZULEGENDE_KONTEN = ["papoulias"]
SAMMLUNGEN = ["ipads", "students", "assignments", "contracts"]

log = []


def sag(zeile=""):
    log.append(zeile)
    print(zeile)


async def main():
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client["iPadDatabase"]

    sag("=" * 70)
    sag("TROCKENLAUF - es wird nichts verändert" if not APPLY else "ECHTLAUF - Daten werden verändert")
    sag("=" * 70)
    if not APPLY:
        sag("")
        sag("Hinweis zum Lesen: spätere Schritte sehen die Wirkung früherer NICHT, weil nichts")
        sag("geschrieben wird. Im Trockenlauf erscheinen deshalb zwangsläufig:")
        sag("  - 'KONTO FEHLT' für Konten, die Schritt [2] erst anlegen würde")
        sag("  - 'wird angelegt' für Bildungsgänge, die Schritt [1] übernommen hätte")
        sag("  - in [6] noch die vollen Zahlen von barvar, obwohl [5] dort löschen würde")
        sag("  - in [7] alles 'ohne Bildungsgang', weil [6] nichts gesetzt hat")
        sag("Keiner dieser Punkte ist ein Fehler.")

    # --- 0. Ausgangslage festhalten -----------------------------------------
    vorher = {c: await db[c].count_documents({}) for c in SAMMLUNGEN}
    sag(f"\nAusgangslage: {vorher}")

    # --- 1. Alte departments-Sammlung übernehmen ----------------------------
    alt = await db.departments.count_documents({})
    if alt:
        sag(f"\n[1] {alt} vorhandene Einträge aus 'departments' übernehmen")
        for d in await db.departments.find({}).to_list(length=None):
            sag(f"      {d['name']}")
            if APPLY and not await db.bildungsgaenge.find_one({"name": d["name"]}):
                await db.bildungsgaenge.insert_one({k: v for k, v in d.items() if k != "_id"})
        if APPLY:
            await db.departments.drop()
    else:
        sag("\n[1] keine alte 'departments'-Sammlung vorhanden")

    # --- 2. Fehlende Konten anlegen -----------------------------------------
    sag("\n[2] Konten")
    for name in NEU_ANZULEGENDE_KONTEN:
        if await db.users.find_one({"username": name}):
            sag(f"      {name}: existiert bereits")
        else:
            sag(f"      {name}: wird angelegt (Passwort muss anschließend gesetzt werden)")
            if APPLY:
                from core.security import get_password_hash

                await db.users.insert_one(
                    {
                        "id": str(uuid.uuid4()),
                        "username": name,
                        "password_hash": get_password_hash(uuid.uuid4().hex),
                        "role": "user",
                        "is_active": True,
                        "force_password_change": True,
                        "created_at": datetime.now(UTC).isoformat(),
                        "updated_at": datetime.now(UTC).isoformat(),
                    }
                )

    # --- 3. Bildungsgänge anlegen -------------------------------------------
    sag("\n[3] Bildungsgänge")
    bg_ids = {}
    for name in ALLE_BILDUNGSGAENGE:
        vorhanden = await db.bildungsgaenge.find_one({"name": name})
        if vorhanden:
            bg_ids[name] = vorhanden["id"]
            sag(f"      {name}: vorhanden")
        else:
            neu_id = str(uuid.uuid4())
            bg_ids[name] = neu_id
            sag(f"      {name}: wird angelegt")
            if APPLY:
                await db.bildungsgaenge.insert_one(
                    {
                        "id": neu_id,
                        "name": name,
                        "description": None,
                        "created_at": datetime.now(UTC).isoformat(),
                        "updated_at": datetime.now(UTC).isoformat(),
                    }
                )

    # --- 4. Zuständigkeiten -------------------------------------------------
    sag("\n[4] Zuständigkeiten")
    for username, bgs in ZUSTAENDIG.items():
        user = await db.users.find_one({"username": username})
        if not user:
            sag(f"      {username}: KONTO FEHLT - übersprungen")
            continue
        sag(f"      {username}: {', '.join(bgs)}")
        for bg in bgs:
            if APPLY and not await db.zustaendigkeiten.find_one(
                {"bildungsgang_id": bg_ids[bg], "user_id": user["id"], "bis": None}
            ):
                await db.zustaendigkeiten.insert_one(
                    {
                        "id": str(uuid.uuid4()),
                        "bildungsgang_id": bg_ids[bg],
                        "user_id": user["id"],
                        "von": datetime.now(UTC).isoformat(),
                        "bis": None,
                        "created_by": None,
                        "created_at": datetime.now(UTC).isoformat(),
                    }
                )

    # --- 5. Sonderfälle VOR der Wanderung -----------------------------------
    # Barvars Dubletten: dieselben Schüler und dieselbe ITNr liegen bei bakenecker.
    # Erst die Zuordnungen auflösen, dann die Schüler, sonst bleiben Verweise ins Leere.
    sag("\n[5] Sonderfälle barvar (Dubletten von bakenecker)")
    barvar = await db.users.find_one({"username": "barvar"})
    bakenecker = await db.users.find_one({"username": "bakenecker"})
    if barvar and bakenecker:
        dubletten = []
        for s in await db.students.find({"user_id": barvar["id"]}).to_list(length=None):
            if await db.students.find_one(
                {"sus_vorn": s["sus_vorn"], "sus_nachn": s["sus_nachn"], "user_id": bakenecker["id"]}
            ):
                dubletten.append(s)
        s_ids = [s["id"] for s in dubletten]
        zuordnungen = await db.assignments.find({"student_id": {"$in": s_ids}}).to_list(length=None)
        z_ids = [z["id"] for z in zuordnungen]
        sag(f"      {len(dubletten)} Schüler löschen: " + ", ".join(f"{s['sus_vorn']} {s['sus_nachn']}" for s in dubletten))
        sag(f"      {len(zuordnungen)} Zuordnungen auflösen")
        if APPLY and s_ids:
            # Geräte freigeben, die auf diese Zuordnungen zeigen
            await db.ipads.update_many(
                {"current_assignment_id": {"$in": z_ids}},
                {"$set": {"current_assignment_id": None, "updated_at": datetime.now(UTC).isoformat()}},
            )
            await db.assignments.delete_many({"id": {"$in": z_ids}})
            await db.students.delete_many({"id": {"$in": s_ids}})

        # Doppelte ITNr: gehört zu bakenecker, barvars Kopie entfällt
        doppelt = []
        for i in await db.ipads.find({"user_id": barvar["id"]}).to_list(length=None):
            if await db.ipads.find_one({"itnr": i["itnr"], "user_id": {"$ne": barvar["id"]}}):
                doppelt.append(i)
        sag(f"      {len(doppelt)} iPads löschen (ITNr auch bei bakenecker): " + ", ".join(i["itnr"] for i in doppelt))
        if APPLY and doppelt:
            await db.ipads.delete_many({"id": {"$in": [i["id"] for i in doppelt]}})

    # --- 6. Die eigentliche Wanderung ---------------------------------------
    sag("\n[6] Zugehörigkeit setzen (user_id bleibt als 'angelegt von' erhalten)")
    for username, bg in DATEN_NACH.items():
        user = await db.users.find_one({"username": username})
        if not user:
            sag(f"      {username}: KONTO FEHLT - übersprungen")
            continue
        zeilen = []
        for coll in SAMMLUNGEN:
            query = {"user_id": user["id"]}
            if coll == "ipads":
                query["is_in_pool"] = {"$ne": True}  # Poolgeräte gehören keinem Bildungsgang
            n = await db[coll].count_documents(query)
            if n:
                zeilen.append(f"{n} {coll}")
                if APPLY:
                    await db[coll].update_many(query, {"$set": {"bildungsgang_id": bg_ids[bg]}})
        sag(f"      {username:12} -> {bg:12} {', '.join(zeilen) if zeilen else '(keine Daten)'}")

    # --- 7. Abgleich ---------------------------------------------------------
    sag("\n[7] Abgleich")
    nachher = {c: await db[c].count_documents({}) for c in SAMMLUNGEN}
    sag(f"      vorher:  {vorher}")
    sag(f"      nachher: {nachher}")
    ohne = {}
    for coll in SAMMLUNGEN:
        q = {"bildungsgang_id": None}
        if coll == "ipads":
            q["is_in_pool"] = {"$ne": True}
        n = await db[coll].count_documents(q)
        if n:
            ohne[coll] = n
    sag(f"      ohne Bildungsgang (ohne Pool): {ohne if ohne else 'keine'}")
    if ohne and APPLY:
        sag("      ACHTUNG: diese Datensätze sieht künftig nur noch ein Admin.")

    if not APPLY:
        sag("\nTrockenlauf beendet. Mit  -- --apply  tatsächlich ausführen.")
    client.close()


asyncio.run(main())
