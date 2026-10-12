#!/usr/bin/env python3
"""Wandert die Zugehörigkeit von Benutzern auf Bildungsgänge.

Standardmäßig ein Trockenlauf: es wird nur berichtet, was geschähe. Erst `--apply`
verändert Daten. Vorher ein Backup ziehen - die Löschungen am Ende sind endgültig.

Jeder Lauf ist wiederholbar: er legt nichts doppelt an und überschreibt keine Zugehörigkeit,
die nach einem früheren Lauf von Hand korrigiert wurde. Bricht ein Lauf mittendrin ab, startet
man ihn einfach neu - genau dafür ist die Wiederholbarkeit da.

Das Skript selbst schreibt KEIN Protokoll. Es nennt Schülernamen, und die einzigen
Verzeichnisse im Container, die einen neuen Container überleben, sind die der Backups - dort
gehört eine unverschlüsselte Namensliste neben die verschlüsselten Archive gerade nicht. Das
Protokoll macht stattdessen der Aufrufer mit `tee`: es landet dort, wo der Lauf gestartet
wurde, und steht auch nach einem Abbruch vollständig bis zur Abbruchstelle in der Datei.

Aufruf im Backend-Container:
    docker exec -i ipad_backend python - < scripts/migrate-to-bildungsgang.py            # Trockenlauf
    docker exec -i ipad_backend python - < scripts/migrate-to-bildungsgang.py -- --apply # echt

Mit Protokoll - 2>&1, damit auch ein Abbruch mit Fehlermeldung in der Datei steht:
    docker exec -i ipad_backend python - < scripts/migrate-to-bildungsgang.py -- --apply 2>&1 | tee ~/wanderung.log

Diese Datei enthält Schülernamen: nicht im Backup-Verzeichnis ablegen (von dort geht der Sync
ausser Haus) und löschen, sobald der Lauf abgehakt ist.
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
    # papoulias: Konto wird von Hand angelegt, hält noch keine Daten
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
    # papoulias (ITA): Konto und Zuständigkeit werden von Hand in der Oberfläche angelegt
    # timpte: Bildungsgang noch offen, hält keine Daten
}

# Bildungsgänge, die es gibt, für die aber (noch) niemand hinterlegt ist. ITA gehört zur
# Schule unabhängig davon, wer sie betreut - angelegt wird sie, damit das Konto später
# nur noch zugeordnet werden muss.
OHNE_ZUSTAENDIGE = ["ITA"]

ALLE_BILDUNGSGAENGE = sorted(
    {b for v in ZUSTAENDIG.values() for b in v} | set(DATEN_NACH.values()) | set(OHNE_ZUSTAENDIGE)
)
# Konten legt dieses Skript nicht an - das geschieht in der Benutzerverwaltung, damit das
# Passwort gleich an die richtige Person geht.
NEU_ANZULEGENDE_KONTEN = []
SAMMLUNGEN = ["ipads", "students", "assignments", "contracts"]


def sag(zeile=""):
    """Jede Zeile sofort ausgeben.

    Ohne flush sammelt Python die Ausgabe hinter einer Pipe (`| tee`) in Blöcken. Bricht der
    Lauf ab, fehlt im Protokoll dann ausgerechnet der letzte Block - der, in dem steht, wie
    weit er gekommen ist.
    """
    print(zeile, flush=True)


def jetzt():
    """Zeitstempel als ISO-Text - so legt die Anwendung ihn überall ab, ein Datumsobjekt fiele aus der Reihe."""
    return datetime.now(UTC).isoformat()


def widerspricht(a, b, feld):
    """Leere Angaben widersprechen nicht - gefüllte müssen übereinstimmen."""
    x = (a.get(feld) or "").strip().lower()
    y = (b.get(feld) or "").strip().lower()
    return bool(x) and bool(y) and x != y


def dieselbe_person(a, b):
    """Gleicher Name allein genügt nicht - Klasse und Geburtsdatum dürfen nicht widersprechen."""
    return not widerspricht(a, b, "sus_geb") and not widerspricht(a, b, "sus_kl")


def aufzaehlung(namen):
    """Hängt eine Aufzählung an eine Meldung - und bei nichts zu zählen eben nichts."""
    return ": " + ", ".join(namen) if namen else ""


async def vertraege_auf(db, feld, wert, zuordnungen):
    """Verträge, die auf diesen Schüler bzw. dieses Gerät zeigen - direkt oder über eine Zuordnung."""
    return await db.contracts.count_documents(
        {
            "$or": [
                {feld: wert},
                {"assignment_id": {"$in": [z["id"] for z in zuordnungen]}},
                {"id": {"$in": [z["contract_id"] for z in zuordnungen if z.get("contract_id")]}},
            ]
        }
    )


async def main():
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client["iPadDatabase"]

    sag("=" * 70)
    sag("TROCKENLAUF - es wird nichts verändert" if not APPLY else "ECHTLAUF - Daten werden verändert")
    sag("=" * 70)
    sag("Diese Ausgabe ist das einzige Protokoll - das Skript schreibt keine Datei. Läuft der")
    sag("Aufruf ohne  2>&1 | tee …  , jetzt mit Strg-C abbrechen: der Lauf ist wiederholbar.")
    if not APPLY:
        sag("")
        sag("Hinweis zum Lesen: spätere Schritte sehen die Wirkung früherer NICHT, weil nichts")
        sag("geschrieben wird. Im Trockenlauf erscheinen deshalb zwangsläufig, ohne dass etwas")
        sag("fehlt:")
        sag("  - 'wird angelegt' für Bildungsgänge, die Schritt [1] übernommen hätte")
        sag("  - in [6] noch die vollen Zahlen von barvar, obwohl [5] dort löschen würde")
        sag("  - in [7] alles 'ohne Bildungsgang', weil [6] nichts gesetzt hat")
        sag("ECHT ist dagegen 'KONTO FEHLT': Schritt [2] legt keine Konten mehr an, der Echtlauf")
        sag("fände das Konto genauso wenig. Erst in der Benutzerverwaltung anlegen - sonst bleiben")
        sag("seine Daten ohne Bildungsgang liegen und seine Zuständigkeit ungesetzt.")

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
    if not NEU_ANZULEGENDE_KONTEN:
        sag("      keine - Konten werden von Hand in der Benutzerverwaltung angelegt")
    for name in NEU_ANZULEGENDE_KONTEN:
        if await db.users.find_one({"username": name}):
            sag(f"      {name}: existiert bereits")
        else:
            sag(f"      {name}: wird angelegt (Passwort muss anschließend gesetzt werden)")
            if APPLY:
                # Import bewusst erst hier: NEU_ANZULEGENDE_KONTEN ist heute leer, der Zweig
                # läuft also nie. Oben im Kopf würde er bei jedem Trockenlauf die halbe
                # Anwendung samt Passwort-Bibliothek nachziehen, nur um sie nicht zu benutzen.
                from core.security import get_password_hash

                await db.users.insert_one(
                    {
                        "id": str(uuid.uuid4()),
                        "username": name,
                        "password_hash": get_password_hash(uuid.uuid4().hex),
                        "role": "user",
                        "is_active": True,
                        "force_password_change": True,
                        "created_at": jetzt(),
                        "updated_at": jetzt(),
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
                        "created_at": jetzt(),
                        "updated_at": jetzt(),
                    }
                )

    # --- 4. Zuständigkeiten -------------------------------------------------
    sag("\n[4] Zuständigkeiten")
    for username, bgs in ZUSTAENDIG.items():
        user = await db.users.find_one({"username": username})
        if not user:
            sag(f"      {username}: KONTO FEHLT - übersprungen")
            continue
        for bg in bgs:
            # Auch eine BEENDETE Zuständigkeit zählt als vorhanden. Wer nach einem Lauf die
            # Betreuung wechselt, setzt "bis" und legt die neue Person an - ein zweiter Lauf
            # dieses Skripts darf den alten Stand dann nicht wieder einsetzen.
            vorhanden = await db.zustaendigkeiten.find_one(
                {"bildungsgang_id": bg_ids[bg], "user_id": user["id"]}
            )
            if vorhanden:
                stand = "läuft" if vorhanden.get("bis") is None else f"beendet am {vorhanden['bis']}"
                sag(f"      {username:12} -> {bg:12} vorhanden ({stand})")
                continue
            sag(f"      {username:12} -> {bg:12} wird angelegt")
            if APPLY:
                await db.zustaendigkeiten.insert_one(
                    {
                        "id": str(uuid.uuid4()),
                        "bildungsgang_id": bg_ids[bg],
                        "user_id": user["id"],
                        "von": jetzt(),
                        "bis": None,
                        "created_by": None,
                        "created_at": jetzt(),
                    }
                )

    # --- 5. Sonderfälle VOR der Wanderung -----------------------------------
    # Barvars Dubletten: dieselben Schüler und dieselbe ITNr liegen bei bakenecker. Zugesagt ist
    # ausdrücklich, bei barvar nur anzufassen, was auch bei BAKENECKER auftaucht - nicht, was
    # irgendwo sonst in der Schule auftaucht.
    sag("\n[5] Sonderfälle barvar (Dubletten von bakenecker)")
    barvar = await db.users.find_one({"username": "barvar"})
    bakenecker = await db.users.find_one({"username": "bakenecker"})
    if not (barvar and bakenecker):
        # Ein Lauf, der genau einmal stattfindet, darf nichts stillschweigend auslassen: sonst
        # merkt niemand, dass die Dubletten noch liegen.
        fehlt = [name for name, konto in (("barvar", barvar), ("bakenecker", bakenecker)) if not konto]
        sag(f"      ÜBERSPRUNGEN - Konto fehlt: {', '.join(fehlt)}")
        sag("      Ohne beide Konten ist keine Dublette bestimmbar. Bitte von Hand nachsehen.")
    else:
        # Der gleiche Name allein entscheidet nicht über eine Löschung - zwei Menschen können so
        # heißen. Klasse und Geburtsdatum müssen dazu passen; leer heißt "sagt nichts",
        # widersprüchlich heißt "andere Person". In der laufenden Instanz kommt schulweit kein
        # Vor- und Nachname doppelt vor, die schärfere Bedingung kostet dort also keinen Treffer.
        dubletten, namensgleich = [], []
        for s in await db.students.find({"user_id": barvar["id"]}).to_list(length=None):
            treffer = await db.students.find(
                {"sus_vorn": s["sus_vorn"], "sus_nachn": s["sus_nachn"], "user_id": bakenecker["id"]}
            ).to_list(length=None)
            if not treffer:
                continue
            (dubletten if any(dieselbe_person(s, t) for t in treffer) else namensgleich).append(s)

        # Ein unterschriebener Vertrag ist das einzige Stück, das es nur einmal gibt. Hängt einer
        # am Schüler oder am Gerät, wird hier nichts gelöscht, sondern gemeldet - nach dem
        # einmaligen Lauf könnte das niemand mehr zurückholen.
        schueler, geraete, zuordnungen, mit_vertrag = [], [], [], []
        for s in dubletten:
            zu_s = await db.assignments.find({"student_id": s["id"]}).to_list(length=None)
            if await vertraege_auf(db, "student_id", s["id"], zu_s):
                mit_vertrag.append(f"Schüler {s['sus_vorn']} {s['sus_nachn']}")
            else:
                schueler.append(s)
                zuordnungen += zu_s

        # Doppelte ITNr: das Gerät gehört zu bakenecker, barvars Zweitschrift entfällt.
        geraete_zuordnungen = []  # (Zuordnung, ITNr) - nur über diesen Weg verliert ein Fremder etwas
        for i in await db.ipads.find({"user_id": barvar["id"]}).to_list(length=None):
            if not await db.ipads.find_one({"itnr": i["itnr"], "user_id": bakenecker["id"]}):
                continue
            zu_i = await db.assignments.find({"ipad_id": i["id"]}).to_list(length=None)
            if await vertraege_auf(db, "ipad_id", i["id"], zu_i):
                mit_vertrag.append(f"iPad {i['itnr']}")
            else:
                geraete.append(i)
                zuordnungen += zu_i
                geraete_zuordnungen += [(z, i["itnr"]) for z in zu_i]

        s_ids = [s["id"] for s in schueler]
        i_ids = [i["id"] for i in geraete]
        z_ids = sorted({z["id"] for z in zuordnungen})

        # Die Löschbedingung für die GERÄTE hält die Zusage wörtlich ein - angefasst wird nur,
        # was auch bei bakenecker liegt. Über die Zuordnungen greift sie aber weiter: wessen
        # Gerät als ITNr-Dublette verschwindet, verliert seine Zuordnung, auch wenn er selbst
        # keine Dublette ist. Anders geht es nicht, eine Zuordnung ohne Gerät ist ein Verweis
        # ins Leere - aber dann muss hier stehen, WER danach ohne Gerät dasteht. Diese Schüler
        # findet sonst niemand wieder.
        verlieren = []
        for z, itnr in geraete_zuordnungen:
            if z.get("student_id") in s_ids:
                continue  # dieser Schüler wird selbst gelöscht, seine Zuordnung geht mit ihm
            s = await db.students.find_one({"id": z.get("student_id")}) if z.get("student_id") else None
            name = f"{s['sus_vorn']} {s['sus_nachn']}" if s else f"unbekannter Schüler ({z.get('student_id')})"
            verlieren.append(f"{name} - iPad {itnr}")

        sag(
            f"      {len(schueler)} Schüler löschen"
            + aufzaehlung([f"{s['sus_vorn']} {s['sus_nachn']}" for s in schueler])
        )
        sag(
            f"      {len(geraete)} iPads löschen (ITNr auch bei bakenecker)"
            + aufzaehlung([i["itnr"] for i in geraete])
        )
        sag(f"      {len(z_ids)} Zuordnungen auf diese Schüler und Geräte löschen")
        if verlieren:
            sag(f"      ACHTUNG: {len(verlieren)} dieser Zuordnungen gehören Schülern, die KEINE Dublette")
            sag("      sind und bleiben. Ihr Gerät ist eine ITNr-Dublette und verschwindet, die")
            sag("      Zuordnung kann es deshalb nicht - sie stehen danach ohne Gerät da und müssen")
            sag("      in der Oberfläche neu zugeordnet werden:")
            for eintrag in sorted(verlieren):
                sag(f"        {eintrag}")
        if namensgleich:
            # "NICHT angefasst" wäre zu viel versprochen: der Datensatz bleibt zwar stehen, die
            # Zuordnung kann über ein gelöschtes Dubletten-Gerät aber trotzdem entfallen.
            dazu = " (Zuordnung kann entfallen, siehe oben)" if verlieren else ""
            sag(
                "      Nicht gelöscht - gleicher Name, aber Klasse oder Geburtsdatum widersprechen"
                + dazu
                + aufzaehlung([f"{s['sus_vorn']} {s['sus_nachn']}" for s in namensgleich])
            )
        if mit_vertrag:
            sag("      Nicht gelöscht - daran hängt ein Vertrag" + aufzaehlung(mit_vertrag))

        if APPLY and (s_ids or i_ids):
            # Hier wird hart gelöscht, nicht nur beendet (is_active=False, unassigned_at). Die
            # Anwendung beendet eine Zuordnung, wenn ein Gerät wirklich zurückkommt - die Übergabe
            # hat stattgefunden und gehört in die Historie. Diese Übergabe hat es nie gegeben: der
            # Datensatz ist eine Zweitschrift, die bei bakenecker vollständig weiterlebt. Eine
            # beendete Zuordnung auf einen gelöschten Schüler wäre genau der Verweis ins Leere, den
            # dieser Schritt beseitigen soll. Der Löschweg der Anwendung räumt die Historie eines
            # gelöschten Schülers aus demselben Grund mit delete_many weg (routes/students.py).
            # Reihenfolge: erst die Verweise lösen, dann die Datensätze.
            if z_ids:
                await db.ipads.update_many(
                    {"current_assignment_id": {"$in": z_ids}},
                    {"$set": {"current_assignment_id": None, "updated_at": jetzt()}},
                )
                await db.assignments.delete_many({"id": {"$in": z_ids}})
            if s_ids:
                await db.students.delete_many({"id": {"$in": s_ids}})
            if i_ids:
                await db.ipads.delete_many({"id": {"$in": i_ids}})

    # --- 6. Die eigentliche Wanderung ---------------------------------------
    sag("\n[6] Zugehörigkeit setzen (user_id bleibt als 'angelegt von' erhalten)")
    # Welche Bildungsgänge es wirklich gibt. Zeigt ein Datensatz auf einen anderen, ist er
    # herrenlos - und das ist etwas anderes als "liegt bei einem anderen Bildungsgang".
    # bg_ids kommt dazu, weil Schritt [3] im Trockenlauf noch nichts geschrieben hat.
    bekannte_bg = {b["id"] for b in await db.bildungsgaenge.find({}, {"id": 1}).to_list(length=None)}
    bekannte_bg |= set(bg_ids.values())
    for username, bg in DATEN_NACH.items():
        user = await db.users.find_one({"username": username})
        if not user:
            sag(f"      {username}: KONTO FEHLT - übersprungen")
            continue
        zeilen, woanders, herrenlos = [], [], []
        tote_ids = set()
        for coll in SAMMLUNGEN:
            query = {"user_id": user["id"]}
            if coll == "ipads":
                query["is_in_pool"] = {"$ne": True}  # Poolgeräte gehören keinem Bildungsgang
            # Nur Datensätze ohne Zugehörigkeit. Ein zweiter Lauf überschreibt damit nichts, was
            # nach dem ersten von Hand auf einen anderen Bildungsgang gesetzt wurde.
            offen = dict(query, bildungsgang_id=None)
            n = await db[coll].count_documents(offen)
            if n:
                zeilen.append(f"{n} {coll}")
                if APPLY:
                    await db[coll].update_many(offen, {"$set": {"bildungsgang_id": bg_ids[bg]}})
            anderswo = dict(query, bildungsgang_id={"$nin": [None, bg_ids[bg]]})
            fremd = await db[coll].count_documents(anderswo)
            if fremd:
                tot = [i for i in await db[coll].distinct("bildungsgang_id", anderswo) if i not in bekannte_bg]
                n_tot = await db[coll].count_documents(dict(query, bildungsgang_id={"$in": tot})) if tot else 0
                if fremd - n_tot:
                    woanders.append(f"{fremd - n_tot} {coll}")
                if n_tot:
                    herrenlos.append(f"{n_tot} {coll}")
                    tote_ids.update(tot)
        sag(f"      {username:12} -> {bg:12} {', '.join(zeilen) if zeilen else '(nichts offen)'}")
        if woanders:
            sag(f"      {'':12}    liegt schon bei einem anderen Bildungsgang, bleibt dort: {', '.join(woanders)}")
        if herrenlos:
            # Nicht beruhigend melden: dieser Bildungsgang existiert nicht mehr, also ist niemand
            # für ihn zuständig. Die Datensätze bleiben liegen, wo sie keiner sieht.
            sag(f"      {'':12}    ACHTUNG herrenlos: {', '.join(herrenlos)} zeigen auf einen Bildungsgang,")
            sag(f"      {'':12}    den es nicht (mehr) gibt. Dafür ist niemand zuständig - nur noch ein Admin")
            sag(f"      {'':12}    sieht sie. Bitte von Hand einem bestehenden Bildungsgang zuordnen.")
            sag(f"      {'':12}    bildungsgang_id ohne Bildungsgang: {', '.join(sorted(tote_ids))}")

    # --- 6b. Poolgeräte vom alten Bildungsgang lösen -------------------------
    # release_ipad_to_pool leert den Bildungsgang erst seit dem Umbau. Geräte, die vorher
    # freigegeben wurden, tragen ihren alten noch - für einen Admin erscheinen sie damit
    # weiterhin im Bestand eines Bildungsgangs, dem sie nicht mehr gehören.
    alt_im_pool = await db.ipads.count_documents({"is_in_pool": True, "bildungsgang_id": {"$ne": None}})
    sag(f"\n[6b] Poolgeräte mit altem Bildungsgang: {alt_im_pool}")
    if alt_im_pool and APPLY:
        await db.ipads.update_many(
            {"is_in_pool": True, "bildungsgang_id": {"$ne": None}},
            {"$set": {"bildungsgang_id": None, "updated_at": jetzt()}},
        )
        sag("      gelöst - sie gehören jetzt wie alle Poolgeräte niemandem")

    # --- 7. Abgleich ---------------------------------------------------------
    sag("\n[7] Abgleich")
    nachher = {c: await db[c].count_documents({}) for c in SAMMLUNGEN}
    sag(f"      vorher:  {vorher}")
    sag(f"      nachher: {nachher}")
    # Nach Konto aufgeschlüsselt: eine blanke Zahl je Sammlung zwingt dazu, die liegen
    # gebliebenen Datensätze hinterher von Hand zu suchen. Mit dem Konto daneben weiß man sofort,
    # wen man fragen muss, wohin die Daten gehören.
    namen = {u["id"]: u["username"] for u in await db.users.find({}, {"id": 1, "username": 1}).to_list(length=None)}
    ohne_gesamt = 0
    for coll in SAMMLUNGEN:
        q = {"bildungsgang_id": None}
        if coll == "ipads":
            q["is_in_pool"] = {"$ne": True}
        je_konto = {}
        for d in await db[coll].find(q, {"user_id": 1}).to_list(length=None):
            konto = namen.get(d.get("user_id"), f"unbekanntes Konto {d.get('user_id')}")
            je_konto[konto] = je_konto.get(konto, 0) + 1
        ohne_gesamt += sum(je_konto.values())
        if je_konto:
            aufstellung = ", ".join(f"{k}: {v}" for k, v in sorted(je_konto.items(), key=lambda p: (-p[1], p[0])))
            sag(f"      ohne Bildungsgang - {coll}: {aufstellung}")

    # Ein Verweis auf einen Bildungsgang, den es nicht gibt, wirkt genauso wie gar keiner - er
    # fällt oben nur nicht auf, weil dort auf None geprüft wird. Schritt [6] sieht ihn ausserdem
    # nur bei den Konten aus DATEN_NACH; hier fällt auch auf, was unter einem anderen liegt.
    herrenlos_gesamt = []
    for coll in SAMMLUNGEN:
        tot = [i for i in await db[coll].distinct("bildungsgang_id") if i and i not in bekannte_bg]
        if tot:
            herrenlos_gesamt.append(f"{await db[coll].count_documents({'bildungsgang_id': {'$in': tot}})} {coll}")
    if herrenlos_gesamt:
        sag(f"      herrenlos (Bildungsgang gibt es nicht): {', '.join(herrenlos_gesamt)}")

    if not ohne_gesamt and not herrenlos_gesamt:
        sag("      ohne Bildungsgang (ohne Pool): keine")
    elif APPLY:
        sag("      ACHTUNG: diese Datensätze sieht künftig nur noch ein Admin.")

    # Doppelte ITNr müssen vor dem nächsten Start weg: main.py legt den eindeutigen Index
    # "itnr_eindeutig" an und lässt die Anwendung bei Dubletten trotzdem weiterlaufen - der
    # Batch-Upload verliert dann still seinen Schutz gegen zwei gleichzeitige Läufe.
    doppelte = await db.ipads.aggregate(
        [
            {"$group": {"_id": "$itnr", "anzahl": {"$sum": 1}, "konten": {"$addToSet": "$user_id"}}},
            {"$match": {"anzahl": {"$gt": 1}}},
            {"$sort": {"_id": 1}},
        ]
    ).to_list(length=None)
    if doppelte:
        sag(f"      ACHTUNG: {len(doppelte)} ITNr kommen mehrfach vor:")
        for d in doppelte:
            konten = ", ".join(sorted(namen.get(k, "unbekannt") for k in d["konten"]))
            sag(f"        {d['_id']}: {d['anzahl']}x bei {konten}")
        sag("      Folge: der eindeutige Index itnr_eindeutig lässt sich nicht anlegen (main.py beim")
        sag("      Start). Ohne ihn fangen zwei gleichzeitige Batch-Uploads dieselbe neue ITNr nicht")
        sag("      mehr ab und legen das Gerät zweimal an.")
        sag("      Nächster Schritt: die Nummern oben in der Oberfläche bereinigen - je ITNr bleibt")
        sag("      ein Gerät - und danach das Backend neu starten; beim Start entsteht der Index.")
    else:
        sag("      doppelte ITNr: keine")

    if not APPLY:
        sag("\nTrockenlauf beendet. Mit  -- --apply  tatsächlich ausführen.")
    else:
        # Der Echtlauf findet genau einmal statt. Wer ohne tee gestartet hat, hat die Ausgabe nur
        # noch im Fenster - das ist der letzte Moment, in dem sie zu retten ist.
        sag("\nEchtlauf beendet. Diese Ausgabe ist das Protokoll: ohne  | tee  jetzt sichern,")
        sag("bevor das Fenster zugeht. Sie enthält Schülernamen - nicht ins Backup-Verzeichnis.")
    client.close()


asyncio.run(main())
