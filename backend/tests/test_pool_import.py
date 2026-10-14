"""Pool-Import: Geräte, die es schon gibt, bleiben, wo sie sind - und man erfährt, warum.

Der Pool-Import holt nichts aus einem Bildungsgang zurück. Früher verschwand ein solches Gerät
aber wortlos in "X iPads übersprungen", ununterscheidbar von denen, die ohnehin schon im Pool
lagen. Jetzt nennt eine Meldung je Zeile, wem das Gerät gehört.
"""

import io

import pandas as pd

from tests.conftest import anmelden


def excel(zeilen):
    puffer = io.BytesIO()
    pd.DataFrame(zeilen).to_excel(puffer, index=False)
    return {
        "file": ("pool.xlsx", puffer.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    }


async def geraet(db, gid, itnr, bildungsgang_id=None, is_in_pool=False, current_assignment_id=None):
    await db.ipads.insert_one(
        {
            "id": gid,
            "user_id": "u_admin",
            "bildungsgang_id": bildungsgang_id,
            "itnr": itnr,
            "snr": f"SN-{gid}",
            "typ": "iPad 9",
            "status": "ok",
            "is_in_pool": is_in_pool,
            "current_assignment_id": current_assignment_id,
        }
    )


async def pool_import(client, zeilen):
    kopf = await anmelden(client, "admin")
    return await client.post(
        "/api/imports/inventory", files=excel(zeilen), data={"import_to_pool": "true"}, headers=kopf
    )


async def test_geraet_eines_bildungsgangs_wird_gemeldet_und_bleibt(welt, client):
    await geraet(welt, "g_meda", "IT-100", bildungsgang_id="bg_meda", current_assignment_id="a_meda")

    antwort = await pool_import(client, [{"ITNr": "IT-100", "SNr": "SN-NEU"}])

    assert antwort.status_code == 200, antwort.text
    daten = antwort.json()
    assert daten["ipads_skipped"] == 1
    assert daten["errors"] == ["Zeile 2: ITNr IT-100 gehört bereits zu MEDA - nicht in den Pool übernommen"]
    unveraendert = await welt.ipads.find_one({"id": "g_meda"})
    assert unveraendert["bildungsgang_id"] == "bg_meda"
    assert unveraendert["is_in_pool"] is False
    assert unveraendert["current_assignment_id"] == "a_meda", "Die Zuordnung darf der Import nicht anfassen"
    assert unveraendert["snr"] == "SN-g_meda"


async def test_geraet_schon_im_pool_wird_still_uebersprungen(welt, client):
    await geraet(welt, "g_pool", "IT-200", is_in_pool=True)

    antwort = await pool_import(client, [{"ITNr": "IT-200"}])

    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["ipads_skipped"] == 1
    assert antwort.json()["errors"] == [], "Ein Gerät, das schon im Pool liegt, ist kein Konflikt"


async def test_neues_geraet_kommt_ohne_meldung_in_den_pool(welt, client):
    antwort = await pool_import(client, [{"ITNr": "IT-300"}])

    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["ipads_created"] == 1
    assert antwort.json()["errors"] == []
    neu = await welt.ipads.find_one({"itnr": "IT-300"})
    assert neu["is_in_pool"] is True


async def test_schueler_ohne_ipad_werden_als_solche_gezaehlt(welt, client):
    """students_only_created zählte nie: Die Abfrage sah erst nach, nachdem der Schüler schon im
    Cache stand. Jetzt zählt jeder neu angelegte Schüler ohne Gerät - ein wiederverwendeter nicht."""
    kopf = await anmelden(client, "admin")
    zeilen = [
        {"SuSVorn": "Ohne", "SuSNachn": "Gerät", "ITNr": None},
        {"SuSVorn": "Mit", "SuSNachn": "Gerät", "ITNr": "IT-ZAEHL", "SNr": "SN-ZAEHL"},
        {"SuSVorn": "Ohne", "SuSNachn": "Gerät", "ITNr": None},
    ]
    antwort = await client.post(
        "/api/imports/inventory",
        files=excel(zeilen),
        data={"import_to_pool": "false", "bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        headers=kopf,
    )

    assert antwort.status_code == 200, antwort.text
    daten = antwort.json()
    assert daten["students_created"] == 2
    assert daten["students_only_created"] == 1


# --- Bestandsimport mit Geräten: wer hat sie bekommen? ------------------------------------


async def bestand_import(client, zeilen, **felder):
    kopf = await anmelden(client, "admin")
    return await client.post(
        "/api/imports/inventory",
        files=excel(zeilen),
        data={"import_to_pool": "false", "bildungsgang_id": "bg_meda", **felder},
        headers=kopf,
    )


async def test_geraeteimport_ohne_empfaenger_schreibt_nichts(welt, client):
    """Ohne "Übergeben an" bricht der Import ab, BEVOR etwas geschrieben ist - ein halber
    Import ohne Quittung ließe sich nicht mehr nachtragen."""
    await geraet(welt, "g_pool", "IT-POOL", is_in_pool=True)

    antwort = await bestand_import(
        client,
        [
            {"SuSVorn": "Ina", "SuSNachn": "Neu", "ITNr": "IT-NEU", "SNr": "SN-NEU"},
            {"SuSVorn": "Ole", "SuSNachn": "Pool", "ITNr": "IT-POOL"},
        ],
    )

    assert antwort.status_code == 400
    assert "Übergeben an" in antwort.json()["detail"]
    assert await welt.ipads.count_documents({"itnr": "IT-NEU"}) == 0
    assert (await welt.ipads.find_one({"id": "g_pool"}))["is_in_pool"] is True
    assert await welt.students.count_documents({"sus_nachn": {"$in": ["Neu", "Pool"]}}) == 0


async def test_geraeteimport_haelt_die_uebergabe_fest(welt, client):
    """Neu angelegte und aus dem Pool geholte Geräte tragen beide die Quittung."""
    await geraet(welt, "g_pool", "IT-POOL", is_in_pool=True)

    antwort = await bestand_import(
        client,
        [
            {"SuSVorn": "Ina", "SuSNachn": "Neu", "ITNr": "IT-NEU", "SNr": "SN-NEU"},
            {"SuSVorn": "Ole", "SuSNachn": "Pool", "ITNr": "IT-POOL"},
        ],
        uebergeben_an_user_id="u_bakenecker",
    )
    assert antwort.status_code == 200, antwort.text

    neu = await welt.ipads.find_one({"itnr": "IT-NEU"})
    geholt = await welt.ipads.find_one({"id": "g_pool"})
    assert geholt["is_in_pool"] is False
    assert geholt["bildungsgang_id"] == "bg_meda"
    for geraet_ in (neu, geholt):
        eintrag = geraet_["pool_history"][-1]
        assert eintrag["uebergeben_an"] == {"user_id": "u_bakenecker", "username": "bakenecker"}, geraet_["itnr"]
        assert eintrag["bildungsgang_id"] == "bg_meda"
    assert neu["pool_history"][-1]["action"] == "created_by_import"
    assert geholt["pool_history"][-1]["action"] == "claimed_by_import"


async def test_reiner_schuelerimport_braucht_keinen_empfaenger(welt, client):
    """Keine Geräte, nichts zu übergeben - dann darf auch nichts verlangt werden."""
    antwort = await bestand_import(client, [{"SuSVorn": "Nur", "SuSNachn": "Schüler"}])
    assert antwort.status_code == 200, antwort.text
    assert await welt.students.count_documents({"sus_nachn": "Schüler"}) == 1


async def test_empfaenger_muss_existieren(welt, client):
    antwort = await bestand_import(client, [{"ITNr": "IT-X", "SNr": "SN-X"}], uebergeben_an_user_id="gibtsnicht")
    assert antwort.status_code == 404
    assert await welt.ipads.count_documents({"itnr": "IT-X"}) == 0
