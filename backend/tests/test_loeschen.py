"""Löschen: was dabei mitgeht - und was stehen bleiben muss.

Jede Löschung räumt hinter sich auf: ein gelöschtes Gerät lässt keine Zuordnung zurück, ein
gelöschter Schüler keinen Vertrag, der auf ihn zeigt. Das Aufräumen ist aber genau die Stelle,
an der eine Trennung verlorengeht, die überall sonst sorgfältig gezogen wird - es läuft über
die ganze Datenbank, während die Rechteprüfung nur den einen Datensatz betrachtet hat, den
jemand löschen wollte.

Zwei der Tests hier halten denselben Fehler fest, einmal für Geräte und einmal für Schüler:
Das Löschen entfernte "verwaiste Verträge" ohne jede Einschränkung. Wer in MEDA ein Gerät
löschte, löschte damit die herrenlosen Verträge des GYM gleich mit - unwiederbringlich, denn
im Vertrag steckt das unterschriebene PDF.
"""

from tests.conftest import anmelden


async def schueler(db, sid, bildungsgang_id, vorn="Max", nachn="Mustermann"):
    await db.students.insert_one(
        {
            "id": sid,
            "user_id": "u_admin",
            "bildungsgang_id": bildungsgang_id,
            "sus_vorn": vorn,
            "sus_nachn": nachn,
            "sus_kl": "M1",
            "sus_geb": "01.01.2008",
        }
    )


async def geraet(db, gid, bildungsgang_id, itnr, current_assignment_id=None):
    await db.ipads.insert_one(
        {
            "id": gid,
            "user_id": "u_admin",
            "bildungsgang_id": bildungsgang_id,
            "itnr": itnr,
            "snr": f"SN-{gid}",
            "typ": "iPad 9",
            "status": "ok",
            "is_in_pool": False,
            "current_assignment_id": current_assignment_id,
        }
    )


async def zuordnung(db, aid, bildungsgang_id, student_id, ipad_id, itnr, user_id="u_admin"):
    await db.assignments.insert_one(
        {
            "id": aid,
            "user_id": user_id,
            "bildungsgang_id": bildungsgang_id,
            "student_id": student_id,
            "ipad_id": ipad_id,
            "itnr": itnr,
            "student_name": "Max Mustermann",
            "is_active": True,
            "assigned_at": "2026-02-01T00:00:00+00:00",
            "contract_id": None,
        }
    )


async def vertrag(db, cid, bildungsgang_id, **abweichend):
    """Ein Vertrag ohne Schüler, ohne Gerät und ohne Zuordnung ist "verwaist" - genau das,
    was die Aufräumschritte beim Löschen entfernen sollen."""
    daten = {
        "id": cid,
        "user_id": "u_admin",
        "bildungsgang_id": bildungsgang_id,
        "assignment_id": None,
        "ipad_id": None,
        "student_id": None,
        "itnr": None,
        "student_name": None,
        "filename": f"{cid}.pdf",
        "file_data": b"%PDF-1.4 unterschrieben",
        "form_fields": {},
        "uploaded_at": "2026-02-01T00:00:00+00:00",
        "is_active": True,
    }
    daten.update(abweichend)
    await db.contracts.insert_one(daten)


# --------------------------------------------------------------------------------------
# Aufräumen endet am eigenen Bildungsgang
# --------------------------------------------------------------------------------------


async def test_geraeteloeschung_laesst_fremden_verwaisten_vertrag_stehen(welt, client):
    """Der wichtigste Test dieser Reihe.

    schaubach löscht sein MEDA-Gerät. Im GYM liegt ein Vertrag, der schon vorher niemandem
    mehr zugeordnet war. Er geht schaubach nichts an und darf diese Löschung nicht spüren -
    das PDF darin ist eine Unterschrift, die es kein zweites Mal gibt.
    """
    await vertrag(welt, "c_gym", "bg_gym")
    await geraet(welt, "g_meda", "bg_meda", "IT-100")
    await vertrag(welt, "c_meda", "bg_meda", ipad_id="g_meda")

    kopf = await anmelden(client, "schaubach")
    antwort = await client.delete("/api/ipads/g_meda", headers=kopf)

    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["deleted_contracts"] == 1, "Nur der eigene Vertrag war zu löschen"
    assert (
        await welt.contracts.find_one({"id": "c_meda"}) is None
    ), "Der Vertrag, den diese Löschung verwaist hat, gehört weg"
    assert (
        await welt.contracts.find_one({"id": "c_gym"}) is not None
    ), "Ein verwaister Vertrag des GYM geht eine MEDA-Löschung nichts an"


async def test_admin_loeschung_laesst_fremde_verwaiste_vertraege_stehen(welt, client):
    """Auch der Admin darf nicht nebenbei aufräumen.

    Er sieht alle Bildungsgänge, löscht aber genau ein Gerät. Verwaiste Verträge sind
    Altlasten, die jemand sichten muss - keine Nebenwirkung einer fremden Löschung.
    """
    await vertrag(welt, "c_gym", "bg_gym")
    await vertrag(welt, "c_it", "bg_it")
    await geraet(welt, "g_meda", "bg_meda", "IT-100")

    kopf = await anmelden(client, "admin")
    antwort = await client.delete("/api/ipads/g_meda", headers=kopf)

    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["deleted_contracts"] == 0
    assert await welt.contracts.count_documents({}) == 2


async def test_schuelerloeschung_laesst_fremden_verwaisten_vertrag_stehen(welt, client):
    """Dasselbe für den Schüler: sein eigener Vertrag wird verwaist und geht mit, der
    herrenlose Vertrag des GYM bleibt liegen."""
    await vertrag(welt, "c_gym", "bg_gym")
    await schueler(welt, "s_meda", "bg_meda")
    await vertrag(welt, "c_meda", "bg_meda", student_id="s_meda")

    kopf = await anmelden(client, "schaubach")
    antwort = await client.delete("/api/students/s_meda", headers=kopf)

    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["deleted_contracts"] == 1, "Nur der eigene Vertrag war zu löschen"
    assert await welt.contracts.find_one({"id": "c_meda"}) is None
    assert (
        await welt.contracts.find_one({"id": "c_gym"}) is not None
    ), "Ein verwaister Vertrag des GYM geht eine MEDA-Löschung nichts an"


async def test_schuelerloeschung_loescht_auch_den_vertrag_am_geraet(welt, client):
    """Der Löschdialog verspricht "Alle zugehörigen Verträge".

    Früher blieb ein Vertrag stehen, solange er noch an einem Gerät hing - also fast immer.
    Der Schüler war gelöscht, sein unterschriebener Vertrag über das Gerät weiter abrufbar.
    """
    await schueler(welt, "s_meda", "bg_meda")
    await geraet(welt, "g_meda", "bg_meda", "IT-100", current_assignment_id="a_meda")
    await zuordnung(welt, "a_meda", "bg_meda", "s_meda", "g_meda", "IT-100")
    await welt.assignments.update_one({"id": "a_meda"}, {"$set": {"contract_id": "c_meda"}})
    await vertrag(welt, "c_meda", "bg_meda", student_id="s_meda", ipad_id="g_meda", assignment_id="a_meda")

    kopf = await anmelden(client, "schaubach")
    antwort = await client.delete("/api/students/s_meda", headers=kopf)

    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["deleted_contracts"] == 1
    assert await welt.contracts.find_one({"id": "c_meda"}) is None
    assert (await welt.ipads.find_one({"id": "g_meda"}))["current_assignment_id"] is None


async def test_schuelerloeschung_findet_alten_vertrag_ueber_die_zuordnung(welt, client):
    """Altbestand: der Vertrag trägt keine student_id, nur die Zuordnung - auch er geht mit."""
    await schueler(welt, "s_meda", "bg_meda")
    await geraet(welt, "g_meda", "bg_meda", "IT-100", current_assignment_id="a_meda")
    await zuordnung(welt, "a_meda", "bg_meda", "s_meda", "g_meda", "IT-100")
    await vertrag(welt, "c_alt", "bg_meda", ipad_id="g_meda", assignment_id="a_meda")

    kopf = await anmelden(client, "schaubach")
    antwort = await client.delete("/api/students/s_meda", headers=kopf)

    assert antwort.status_code == 200, antwort.text
    assert await welt.contracts.find_one({"id": "c_alt"}) is None


# --------------------------------------------------------------------------------------
# Stapellöschung: zuständig sein genügt
# --------------------------------------------------------------------------------------


async def test_stapelloeschung_loest_auch_die_zuordnung_einer_kollegin(welt, client):
    """Seit dem Umbau sagt user_id nur noch, WER etwas angelegt hat.

    Die Zuordnung hat bakenecker eingetragen, zuständig für MEDA ist aber schaubach. Filterte
    die Stapellöschung nach Urheberschaft, bliebe die Zuordnung stehen: der Schüler wäre weg,
    das Gerät aber weiterhin als vergeben geführt - und niemand käme je wieder daran.
    """
    await schueler(welt, "s_meda", "bg_meda")
    await geraet(welt, "g_meda", "bg_meda", "IT-100", current_assignment_id="a_meda")
    await zuordnung(welt, "a_meda", "bg_meda", "s_meda", "g_meda", "IT-100", user_id="u_bakenecker")

    kopf = await anmelden(client, "schaubach")
    antwort = await client.post("/api/students/batch-delete", json={"all": True}, headers=kopf)

    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["freed_ipads"] == 1, "Das Gerät muss als freigeworden gezählt werden"
    assert (await welt.ipads.find_one({"id": "g_meda"}))[
        "current_assignment_id"
    ] is None, "Ein Gerät ohne Schüler darf nicht als vergeben stehenbleiben"
    assert await welt.students.count_documents({"id": "s_meda"}) == 0
    assert await welt.assignments.count_documents({"id": "a_meda"}) == 0


async def test_stapelloeschung_ruehrt_den_fremden_bildungsgang_nicht_an(welt, client):
    """Zuständigkeit erweitert den Zugriff auf fremde Urheber, sie öffnet ihn nicht für
    fremde Bildungsgänge. "all" heißt alle EIGENEN."""
    await schueler(welt, "s_gym", "bg_gym", nachn="Fremdling")
    await geraet(welt, "g_gym", "bg_gym", "IT-200", current_assignment_id="a_gym")
    await zuordnung(welt, "a_gym", "bg_gym", "s_gym", "g_gym", "IT-200")

    kopf = await anmelden(client, "schaubach")
    antwort = await client.post("/api/students/batch-delete", json={"all": True}, headers=kopf)

    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["deleted_count"] == 0
    assert await welt.students.count_documents({"id": "s_gym"}) == 1
    assert (await welt.ipads.find_one({"id": "g_gym"}))["current_assignment_id"] == "a_gym"
