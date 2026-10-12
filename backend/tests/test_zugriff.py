"""Zugriffsrechte: wer sieht was.

Der wichtigste Testbereich der Anwendung. Ein Fehler hier bedeutet, dass jemand fremde
Schülerdaten sieht - oder die eigenen nicht mehr.
"""

from tests.conftest import anmelden


async def geraet(db, ipad_id, bildungsgang_id, pool=False):
    await db.ipads.insert_one(
        {
            "id": ipad_id,
            "bildungsgang_id": bildungsgang_id,
            "is_in_pool": pool,
            "itnr": f"IT{ipad_id}",
            "snr": f"SN{ipad_id}",
            "status": "ok",
            "user_id": "u_admin",
        }
    )


async def test_sieht_alle_eigenen_bildungsgaenge(welt, client):
    """Eine Person mit zwei Zuständigkeiten sieht beide - aus EINEM Konto.

    Das ist der Grund für den ganzen Umbau: vorher brauchte es zwei Anmeldungen.
    """
    await geraet(welt, "a", "bg_meda")
    await geraet(welt, "b", "bg_it")
    await geraet(welt, "c", "bg_gym")

    kopf = await anmelden(client, "schaubach")
    antwort = await client.get("/api/ipads", headers=kopf)
    assert antwort.status_code == 200
    assert sorted(i["id"] for i in antwort.json()) == ["a", "b"]


async def test_fremder_bildungsgang_bleibt_unsichtbar(welt, client):
    await geraet(welt, "c", "bg_gym")
    kopf = await anmelden(client, "schaubach")
    assert (await client.get("/api/ipads", headers=kopf)).json() == []


async def test_beendete_zustaendigkeit_entzieht_zugriff(welt, client):
    """Wer ausgeschieden ist, sieht nichts mehr - auch nicht, was er selbst angelegt hat."""
    await welt.ipads.insert_one(
        {
            "id": "x",
            "bildungsgang_id": "bg_gym",
            "is_in_pool": False,
            "itnr": "ITx",
            "snr": "SNx",
            "status": "ok",
            "user_id": "u_ausgeschieden",
        }
    )
    kopf = await anmelden(client, "ausgeschieden")
    assert (await client.get("/api/ipads", headers=kopf)).json() == []


async def test_admin_sieht_alles_inklusive_pool(welt, client):
    await geraet(welt, "a", "bg_meda")
    await geraet(welt, "p", None, pool=True)
    kopf = await anmelden(client, "admin")
    ids = sorted(i["id"] for i in (await client.get("/api/ipads", headers=kopf)).json())
    assert ids == ["a", "p"]


async def test_poolgeraet_bleibt_fuer_lehrkraft_unsichtbar(welt, client):
    """Ein Poolgerät gehört niemandem - es darf nicht im Bestand auftauchen."""
    await geraet(welt, "p", None, pool=True)
    kopf = await anmelden(client, "schaubach")
    assert (await client.get("/api/ipads", headers=kopf)).json() == []


async def test_ansichtsfilter_kann_nur_einengen(welt, client):
    """Der Ansichtsparameter darf die Rechte nicht aushebeln."""
    await geraet(welt, "a", "bg_meda")
    await geraet(welt, "c", "bg_gym")
    kopf = await anmelden(client, "schaubach")

    eigener = await client.get("/api/ipads?bildungsgang_id=bg_meda", headers=kopf)
    assert [i["id"] for i in eigener.json()] == ["a"]

    fremder = await client.get("/api/ipads?bildungsgang_id=bg_gym", headers=kopf)
    assert fremder.json() == [], "Ansichtsparameter darf keinen fremden Bildungsgang öffnen"


async def test_ohne_anmeldung_kein_zugriff(client):
    assert (await client.get("/api/ipads")).status_code == 401
