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
    return {"file": ("pool.xlsx", puffer.getvalue(),
                     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}


async def geraet(db, gid, itnr, bildungsgang_id=None, is_in_pool=False, current_assignment_id=None):
    await db.ipads.insert_one({
        "id": gid, "user_id": "u_admin", "bildungsgang_id": bildungsgang_id,
        "itnr": itnr, "snr": f"SN-{gid}", "typ": "iPad 9", "status": "ok", "is_in_pool": is_in_pool,
        "current_assignment_id": current_assignment_id,
    })


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
