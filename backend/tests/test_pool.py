"""Pool und Übergabe: wie ein Gerät den Besitzer wechselt - und wer es in die Hand bekommt.

Zwei Dinge werden hier konsequent auseinandergehalten, weil sie im Alltag ständig
verwechselt werden:

- BESITZ ist der Bildungsgang. Er steht in `bildungsgang_id` und entscheidet, wer das
  Gerät sieht. Ein Poolgerät hat keinen - es gehört niemandem.
- ÜBERGABE ist eine Quittung: wer hat die Kiste körperlich bekommen, und wann. Sie steht
  in der `pool_history` und begründet keinerlei Zugriff.

`user_id` ist weder das eine noch das andere: es sagt nur, wer den Datensatz angelegt hat.
Keine Übergabe darf es überschreiben, sonst ist nicht mehr feststellbar, woher ein Gerät
im Bestand stammt.
"""

import asyncio
import io
from datetime import UTC, datetime

import pandas as pd
import pytest

from tests.conftest import anmelden

EXCEL_TYP = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


async def poolgeraet(db, ipad_id, itnr=None, angelegt_von="u_admin"):
    """Gerät im Pool: ohne Bildungsgang, also ohne Besitzer."""
    await db.ipads.insert_one({
        "id": ipad_id, "bildungsgang_id": None, "is_in_pool": True,
        "itnr": itnr or f"IT{ipad_id}", "snr": f"SN{ipad_id}", "status": "ok",
        "user_id": angelegt_von, "pool_history": [], "current_assignment_id": None,
    })


async def geraet(db, ipad_id, bildungsgang_id, itnr=None, angelegt_von="u_admin"):
    await db.ipads.insert_one({
        "id": ipad_id, "bildungsgang_id": bildungsgang_id, "is_in_pool": False,
        "itnr": itnr or f"IT{ipad_id}", "snr": f"SN{ipad_id}", "status": "ok",
        "user_id": angelegt_von, "pool_history": [], "current_assignment_id": None,
    })


def excel(zeilen):
    """Eine Importliste als echte .xlsx-Datei - die Route prüft den Dateiinhalt, nicht die Endung."""
    puffer = io.BytesIO()
    pd.DataFrame(zeilen, columns=["ITNr", "SNr"]).to_excel(puffer, index=False)
    return puffer.getvalue()


def anhang(inhalt, name="liste.xlsx", typ=EXCEL_TYP):
    return {"file": (name, inhalt, typ)}


def frisch(zeitpunkt: str) -> bool:
    """Der Zeitstempel muss gerade eben entstanden sein, nicht irgendwann."""
    return abs((datetime.now(UTC) - datetime.fromisoformat(zeitpunkt)).total_seconds()) < 300


# --- Ein Poolgerät gehört niemandem ---------------------------------------------------


async def test_poolanlage_ignoriert_den_angegebenen_bildungsgang(welt, client):
    """Wer ein Gerät in den Pool legt, kann es nicht gleichzeitig einem Bildungsgang geben.

    Der mitgeschickte Bildungsgang wird bewusst verworfen statt abgelehnt: der Pool ist der
    Ort für Geräte, die noch niemandem gehören.
    """
    kopf = await anmelden(client, "admin")
    antwort = await client.post(
        "/api/ipads",
        json={"itnr": "IT900", "snr": "SN900", "is_in_pool": True, "bildungsgang_id": "bg_meda"},
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["bildungsgang_id"] is None
    assert antwort.json()["is_in_pool"] is True


async def test_poolgeraet_taucht_in_keinem_bestand_auf(welt, client):
    """Niemandes Gerät: für die Lehrkraft unsichtbar, für die zentrale Verwaltung sichtbar."""
    admin = await anmelden(client, "admin")
    erzeugt = await client.post(
        "/api/ipads", json={"itnr": "IT901", "snr": "SN901", "is_in_pool": True}, headers=admin
    )
    assert erzeugt.status_code == 200, erzeugt.text

    lehrkraft = await anmelden(client, "schaubach")
    assert (await client.get("/api/ipads", headers=lehrkraft)).json() == []
    assert [i["itnr"] for i in (await client.get("/api/ipads", headers=admin)).json()] == ["IT901"]


# --- Claim: aus dem Pool in einen Bildungsgang ----------------------------------------


async def test_claim_holt_das_geraet_in_den_bildungsgang(welt, client):
    """Nach der Übernahme sieht die zuständige Lehrkraft das Gerät - vorher nicht."""
    await poolgeraet(welt, "g1")
    admin = await anmelden(client, "admin")
    lehrkraft = await anmelden(client, "schaubach")

    assert (await client.get("/api/ipads", headers=lehrkraft)).json() == []

    antwort = await client.post(
        "/api/ipads/g1/claim", json={"bildungsgang_id": "bg_meda"}, headers=admin
    )
    assert antwort.status_code == 200, antwort.text

    bestand = (await client.get("/api/ipads", headers=lehrkraft)).json()
    assert [i["id"] for i in bestand] == ["g1"]
    assert bestand[0]["is_in_pool"] is False
    assert bestand[0]["bildungsgang_id"] == "bg_meda"


async def test_claim_ohne_zustaendigkeit_verlangt_eine_auswahl(welt, client):
    """Das admin-Konto betreut selbst keinen Bildungsgang - es darf nichts geraten werden.

    Genau diese stille Vorauswahl hat in der Altanwendung den gesamten Bestand am
    admin-Konto angehäuft.
    """
    await poolgeraet(welt, "g1")
    kopf = await anmelden(client, "admin")

    antwort = await client.post("/api/ipads/g1/claim", json={}, headers=kopf)
    assert antwort.status_code == 400
    assert "auswählen" in antwort.json()["detail"].lower()
    assert (await welt.ipads.find_one({"id": "g1"}))["is_in_pool"] is True


async def test_claim_nutzt_die_einzige_zustaendigkeit_ohne_rueckfrage(welt, client):
    """Wer genau einen Bildungsgang betreut, muss ihn nicht jedes Mal angeben."""
    await poolgeraet(welt, "g1")
    kopf = await anmelden(client, "wieners")

    antwort = await client.post("/api/ipads/g1/claim", headers=kopf)
    assert antwort.status_code == 200, antwort.text
    assert (await welt.ipads.find_one({"id": "g1"}))["bildungsgang_id"] == "bg_lehrkräfte"


async def test_claim_in_unbekannten_bildungsgang_wird_abgelehnt(welt, client):
    await poolgeraet(welt, "g1")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/ipads/g1/claim", json={"bildungsgang_id": "bg_gibtsnicht"}, headers=kopf
    )
    assert antwort.status_code == 400
    assert (await welt.ipads.find_one({"id": "g1"}))["is_in_pool"] is True


async def test_claim_auf_bereits_uebernommenes_geraet_scheitert(welt, client):
    """Der zweite Zugriff darf den ersten nicht überschreiben, sonst wandert ein bereits
    ausgegebenes Gerät unbemerkt in einen anderen Bestand."""
    await poolgeraet(welt, "g1")
    admin = await anmelden(client, "admin")

    erster = await client.post("/api/ipads/g1/claim", json={"bildungsgang_id": "bg_meda"}, headers=admin)
    assert erster.status_code == 200, erster.text

    zweiter = await client.post("/api/ipads/g1/claim", json={"bildungsgang_id": "bg_gym"}, headers=admin)
    assert zweiter.status_code == 409
    assert (await welt.ipads.find_one({"id": "g1"}))["bildungsgang_id"] == "bg_meda"


async def test_zwei_gleichzeitige_claims_koennen_nicht_beide_gewinnen(welt, client):
    """Zwei Personen greifen im selben Moment nach demselben Gerät: genau eine bekommt es.

    Gingen beide durch, läge dasselbe Gerät in zwei Beständen und würde zweimal ausgegeben.
    """
    await poolgeraet(welt, "g1")
    einer = await anmelden(client, "admin")
    andere = await anmelden(client, "wieners")

    a, b = await asyncio.gather(
        client.post("/api/ipads/g1/claim", json={"bildungsgang_id": "bg_meda"}, headers=einer),
        client.post("/api/ipads/g1/claim", json={"bildungsgang_id": "bg_gym"}, headers=andere),
    )
    assert sorted([a.status_code, b.status_code]) == [200, 409]

    gewinner = "bg_meda" if a.status_code == 200 else "bg_gym"
    gespeichert = await welt.ipads.find_one({"id": "g1"})
    assert gespeichert["bildungsgang_id"] == gewinner
    assert gespeichert["is_in_pool"] is False


async def test_claim_auf_unbekanntes_geraet_meldet_404(welt, client):
    kopf = await anmelden(client, "admin")
    antwort = await client.post(
        "/api/ipads/gibtsnicht/claim", json={"bildungsgang_id": "bg_meda"}, headers=kopf
    )
    assert antwort.status_code == 404


async def test_lehrkraft_darf_nicht_aus_dem_pool_holen(welt, client):
    """Der Pool wird zentral verwaltet - sonst bedient sich jeder selbst."""
    await poolgeraet(welt, "g1")
    kopf = await anmelden(client, "schaubach")

    antwort = await client.post("/api/ipads/g1/claim", json={"bildungsgang_id": "bg_meda"}, headers=kopf)
    assert antwort.status_code == 403
    assert (await welt.ipads.find_one({"id": "g1"}))["is_in_pool"] is True


# --- Bulk-Claim -----------------------------------------------------------------------


async def test_bulk_claim_holt_nur_was_noch_im_pool_liegt(welt, client):
    """Ein fremdes Gerät in der Liste darf den Durchlauf nicht abbrechen und nicht wandern."""
    await poolgeraet(welt, "g1")
    await poolgeraet(welt, "g2")
    await geraet(welt, "fremd", "bg_gym")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/ipads/bulk-claim",
        json={"ipad_ids": ["g1", "g2", "fremd"], "bildungsgang_id": "bg_meda"},
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["success_count"] == 2
    assert antwort.json()["failed_count"] == 1
    assert (await welt.ipads.find_one({"id": "fremd"}))["bildungsgang_id"] == "bg_gym"


async def test_bulk_claim_ohne_auswahl_wird_abgelehnt(welt, client):
    kopf = await anmelden(client, "admin")
    antwort = await client.post(
        "/api/ipads/bulk-claim", json={"ipad_ids": [], "bildungsgang_id": "bg_meda"}, headers=kopf
    )
    assert antwort.status_code == 400


async def test_bulk_claim_ohne_zustaendigkeit_verlangt_eine_auswahl(welt, client):
    await poolgeraet(welt, "g1")
    kopf = await anmelden(client, "admin")

    antwort = await client.post("/api/ipads/bulk-claim", json={"ipad_ids": ["g1"]}, headers=kopf)
    assert antwort.status_code == 400
    assert (await welt.ipads.find_one({"id": "g1"}))["is_in_pool"] is True


# --- Freigabe in den Pool -------------------------------------------------------------


async def zuordnung_anlegen(welt, client, kopf, ipad_id="g1", bildungsgang_id="bg_meda"):
    """Ein ausgegebenes Gerät samt Schüler und aktiver Zuordnung - Ausgangslage für die Freigabe."""
    await welt.students.insert_one({
        "id": "s1", "bildungsgang_id": bildungsgang_id, "user_id": "u_admin",
        "sus_vorn": "Ada", "sus_nachn": "Lovelace",
    })
    await geraet(welt, ipad_id, bildungsgang_id)
    antwort = await client.post(
        "/api/assignments/manual", json={"student_id": "s1", "ipad_id": ipad_id}, headers=kopf
    )
    assert antwort.status_code == 200, antwort.text
    return antwort.json()["assignment_id"]


async def test_freigabe_loest_die_aktive_zuordnung_auf(welt, client):
    """Ein Gerät kann nicht gleichzeitig im Pool liegen und bei einem Schüler sein."""
    kopf = await anmelden(client, "admin")
    zuordnung_id = await zuordnung_anlegen(welt, client, kopf)

    antwort = await client.post("/api/ipads/g1/release-to-pool", headers=kopf)
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["dissolved_assignment"] is True

    aktive = await client.get("/api/assignments", headers=kopf)
    assert zuordnung_id not in [z["id"] for z in aktive.json()]

    gespeichert = await welt.ipads.find_one({"id": "g1"})
    assert gespeichert["is_in_pool"] is True
    assert gespeichert["current_assignment_id"] is None


async def test_freigabe_setzt_den_vertrag_inaktiv(welt, client):
    """Der Vertrag bleibt als Beleg erhalten, gilt aber nicht mehr - gelöscht wird nichts."""
    kopf = await anmelden(client, "admin")
    zuordnung_id = await zuordnung_anlegen(welt, client, kopf)
    await welt.contracts.insert_one({
        "id": "v1", "assignment_id": zuordnung_id, "ipad_id": "g1", "student_id": "s1",
        "bildungsgang_id": "bg_meda", "user_id": "u_admin", "itnr": "ITg1",
        "student_name": "Ada Lovelace", "filename": "v1.pdf", "is_active": True,
    })

    assert (await client.post("/api/ipads/g1/release-to-pool", headers=kopf)).status_code == 200

    verlauf = await client.get("/api/ipads/g1/history", headers=kopf)
    assert verlauf.status_code == 200, verlauf.text
    vertraege = {v["id"]: v for v in verlauf.json()["contracts"]}
    assert "v1" in vertraege, "Der Vertrag muss in der Historie erhalten bleiben"
    assert vertraege["v1"]["is_active"] is False


async def test_freigegebenes_geraet_verschwindet_aus_dem_bestand(welt, client):
    """Nach der Freigabe gehört das Gerät wieder niemandem: die Lehrkraft sieht es nicht mehr."""
    await geraet(welt, "g1", "bg_meda")
    admin = await anmelden(client, "admin")
    lehrkraft = await anmelden(client, "schaubach")

    assert [i["id"] for i in (await client.get("/api/ipads", headers=lehrkraft)).json()] == ["g1"]
    assert (await client.post("/api/ipads/g1/release-to-pool", headers=admin)).status_code == 200

    assert (await client.get("/api/ipads", headers=lehrkraft)).json() == []
    assert [i["id"] for i in (await client.get("/api/ipads", headers=admin)).json()] == ["g1"]


async def test_freigabe_eines_poolgeraets_wird_abgelehnt(welt, client):
    await poolgeraet(welt, "g1")
    kopf = await anmelden(client, "admin")

    antwort = await client.post("/api/ipads/g1/release-to-pool", headers=kopf)
    assert antwort.status_code == 400
    assert "bereits im Pool" in antwort.json()["detail"]


async def test_freigabe_eines_unbekannten_geraets_meldet_404(welt, client):
    kopf = await anmelden(client, "admin")
    assert (await client.post("/api/ipads/gibtsnicht/release-to-pool", headers=kopf)).status_code == 404


async def test_lehrkraft_darf_nicht_in_den_pool_freigeben(welt, client):
    await geraet(welt, "g1", "bg_meda")
    kopf = await anmelden(client, "schaubach")

    antwort = await client.post("/api/ipads/g1/release-to-pool", headers=kopf)
    assert antwort.status_code == 403
    assert (await welt.ipads.find_one({"id": "g1"}))["is_in_pool"] is False


@pytest.mark.xfail(
    reason="release_ipad_to_pool laesst bildungsgang_id stehen. Ein freigegebenes Geraet "
    "gehoert niemandem mehr, erscheint fuer den Admin aber weiterhin in der Ansicht seines "
    "frueheren Bildungsgangs - anders als ein von Anfang an im Pool angelegtes Geraet.",
    strict=True,
)
async def test_poolgeraet_erscheint_nicht_in_der_bildungsgang_ansicht(welt, client):
    """Beide Geräte liegen im Pool - also darf keines unter MEDA auftauchen."""
    admin = await anmelden(client, "admin")
    await poolgeraet(welt, "nie_vergeben")
    await geraet(welt, "freigegeben", "bg_meda")
    assert (await client.post("/api/ipads/freigegeben/release-to-pool", headers=admin)).status_code == 200

    ansicht = await client.get("/api/ipads?bildungsgang_id=bg_meda", headers=admin)
    assert [i["id"] for i in ansicht.json()] == []


# --- Zuweisung an einen Bildungsgang --------------------------------------------------


async def test_zuweisung_an_unbekannten_bildungsgang_wird_abgelehnt(welt, client):
    """Ein Tippfehler im Bildungsgang darf die Geräte nicht ins Nichts verschieben."""
    await poolgeraet(welt, "g1")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/assign-to-bildungsgang",
        json={"ipad_ids": ["g1"], "bildungsgang_id": "bg_gibtsnicht"},
        headers=kopf,
    )
    assert antwort.status_code == 404
    assert (await welt.ipads.find_one({"id": "g1"}))["is_in_pool"] is True


async def test_zuweisung_ohne_geraete_wird_abgelehnt(welt, client):
    kopf = await anmelden(client, "admin")
    antwort = await client.post(
        "/api/admin/ipads/assign-to-bildungsgang",
        json={"ipad_ids": [], "bildungsgang_id": "bg_meda"},
        headers=kopf,
    )
    assert antwort.status_code == 400


async def test_zuweisung_verschiebt_nur_poolgeraete(welt, client):
    """Ein bereits vergebenes Gerät wird nicht umgehängt, sondern als Fehlschlag gemeldet."""
    await poolgeraet(welt, "g1")
    await geraet(welt, "fremd", "bg_gym")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/assign-to-bildungsgang",
        json={"ipad_ids": ["g1", "fremd"], "bildungsgang_id": "bg_meda"},
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["success_count"] == 1
    assert antwort.json()["failed_count"] == 1
    assert antwort.json()["bildungsgang_name"] == "MEDA"
    assert (await welt.ipads.find_one({"id": "fremd"}))["bildungsgang_id"] == "bg_gym"
    assert (await welt.ipads.find_one({"id": "g1"}))["bildungsgang_id"] == "bg_meda"


async def test_zuweisung_laesst_angelegt_von_unberuehrt(welt, client):
    """`user_id` ist die Herkunft des Datensatzes, nicht der Besitz - sie darf nicht wandern."""
    await poolgeraet(welt, "g1", angelegt_von="u_bakenecker")
    kopf = await anmelden(client, "wieners")

    antwort = await client.post(
        "/api/admin/ipads/assign-to-bildungsgang",
        json={"ipad_ids": ["g1"], "bildungsgang_id": "bg_meda"},
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert (await welt.ipads.find_one({"id": "g1"}))["user_id"] == "u_bakenecker"


async def test_lehrkraft_darf_keinem_bildungsgang_zuweisen(welt, client):
    await poolgeraet(welt, "g1")
    kopf = await anmelden(client, "schaubach")

    antwort = await client.post(
        "/api/admin/ipads/assign-to-bildungsgang",
        json={"ipad_ids": ["g1"], "bildungsgang_id": "bg_meda"},
        headers=kopf,
    )
    assert antwort.status_code == 403


# --- Batch-Import: Besitz und Übergabe getrennt festhalten ----------------------------


async def test_batch_import_haelt_die_uebergabe_getrennt_vom_besitz_fest(welt, client):
    """Die Kernforderung: später nachvollziehen, WEM die Geräte konkret gegeben wurden.

    Besitz (Bildungsgang) und Quittung (Empfänger) stehen nebeneinander in derselben
    Zeile der Historie - die Person begründet dabei keinen Zugriff.
    """
    await poolgeraet(welt, "g1", itnr="IT100")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT100", "SN100")])),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["summary"]["from_pool_count"] == 1
    assert antwort.json()["uebergeben_an"] == "bakenecker"

    verlauf = await client.get("/api/ipads/g1/history", headers=kopf)
    assert verlauf.status_code == 200, verlauf.text
    eintrag = verlauf.json()["pool_history"][-1]
    assert eintrag["bildungsgang_name"] == "MEDA"
    assert eintrag["uebergeben_an"] == "bakenecker"
    assert eintrag["by_username"] == "admin"
    assert frisch(eintrag["at"])


async def test_uebergabe_gibt_dem_empfaenger_keinen_zugriff(welt, client):
    """Bakenecker hat die Kiste bekommen - sehen darf er die Geräte trotzdem nicht.

    Er betreut GYM, die Geräte gehören MEDA. Wäre die Quittung ein Zugriffsrecht, läge
    genau hier das Leck.
    """
    await poolgeraet(welt, "g1", itnr="IT100")
    admin = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT100", "SN100")])),
        headers=admin,
    )
    assert antwort.status_code == 200, antwort.text

    empfaenger = await anmelden(client, "bakenecker")
    assert (await client.get("/api/ipads", headers=empfaenger)).json() == []
    zustaendige = await anmelden(client, "schaubach")
    assert [i["id"] for i in (await client.get("/api/ipads", headers=zustaendige)).json()] == ["g1"]


async def test_uebergabe_aendert_nicht_wer_das_geraet_angelegt_hat(welt, client):
    """`user_id` bleibt "angelegt von". Überschriebe die Übergabe sie, wäre die Herkunft weg."""
    await poolgeraet(welt, "g1", itnr="IT100", angelegt_von="u_wieners")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT100", "SN100")])),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text

    assert (await welt.ipads.find_one({"id": "g1"}))["user_id"] == "u_wieners"
    verlauf = await client.get("/api/ipads/g1/history", headers=kopf)
    assert verlauf.json()["owner_username"] == "wieners"


async def test_batch_import_legt_unbekannte_geraete_an_und_quittiert_sie(welt, client):
    """Eine noch nie erfasste ITNr wird angelegt - samt Bildungsgang und Übergabe-Quittung."""
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT500", "SN500")])),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["summary"]["created_count"] == 1

    neu = await welt.ipads.find_one({"itnr": "IT500"})
    assert neu["bildungsgang_id"] == "bg_meda"
    assert neu["is_in_pool"] is False
    assert neu["user_id"] == "u_admin", "angelegt von dem, der importiert hat"

    verlauf = await client.get(f"/api/ipads/{neu['id']}/history", headers=kopf)
    eintrag = verlauf.json()["pool_history"][-1]
    assert eintrag["uebergeben_an"] == "bakenecker"
    assert eintrag["bildungsgang_name"] == "MEDA"
    assert frisch(eintrag["at"])


async def test_batch_import_ohne_empfaenger_bleibt_ohne_quittung(welt, client):
    """Ohne Empfänger wird der Besitz trotzdem festgehalten - die Quittung bleibt leer.

    Beweist, dass beides getrennt geführt wird und nicht eines das andere ersetzt.
    """
    await poolgeraet(welt, "g1", itnr="IT100")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda"},
        files=anhang(excel([("IT100", "SN100")])),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["uebergeben_an"] is None

    eintrag = (await client.get("/api/ipads/g1/history", headers=kopf)).json()["pool_history"][-1]
    assert eintrag["bildungsgang_name"] == "MEDA"
    assert eintrag["uebergeben_an"] is None


async def test_batch_import_laesst_fremde_geraete_unberuehrt(welt, client):
    """Ein Gerät, das schon einem anderen Bildungsgang gehört, wird gemeldet, nicht umgehängt."""
    await geraet(welt, "g1", "bg_gym", itnr="IT100")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT100", "SN100")])),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zeile = antwort.json()["rows"][0]
    assert zeile["outcome"] == "already_assigned"
    assert zeile["assigned_to"] == "GYM"
    assert (await welt.ipads.find_one({"id": "g1"}))["bildungsgang_id"] == "bg_gym"


async def test_batch_import_meldet_zeile_ohne_itnr(welt, client):
    """Eine kaputte Zeile darf den Rest der Liste nicht verhindern."""
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda"},
        files=anhang(excel([("IT500", "SN500"), ("", "SN501")])),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zusammenfassung = antwort.json()["summary"]
    assert zusammenfassung["created_count"] == 1
    assert zusammenfassung["invalid_rows"] == 1
    assert await welt.ipads.count_documents({}) == 1


async def test_batch_import_verlangt_einen_bekannten_bildungsgang(welt, client):
    await poolgeraet(welt, "g1", itnr="IT100")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_gibtsnicht"},
        files=anhang(excel([("IT100", "SN100")])),
        headers=kopf,
    )
    assert antwort.status_code == 404
    assert (await welt.ipads.find_one({"id": "g1"}))["is_in_pool"] is True


async def test_batch_import_verlangt_einen_bekannten_empfaenger(welt, client):
    """Ein unbekannter Empfänger bricht den Import ab - eine Quittung auf niemanden ist wertlos."""
    await poolgeraet(welt, "g1", itnr="IT100")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_gibtsnicht"},
        files=anhang(excel([("IT100", "SN100")])),
        headers=kopf,
    )
    assert antwort.status_code == 404
    assert (await welt.ipads.find_one({"id": "g1"}))["is_in_pool"] is True


async def test_batch_import_lehnt_fremde_dateiformate_ab(welt, client):
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda"},
        files=anhang(b"ITNr;SNr\nIT100;SN100\n", name="liste.csv", typ="text/csv"),
        headers=kopf,
    )
    assert antwort.status_code == 400
    assert await welt.ipads.count_documents({}) == 0


async def test_lehrkraft_darf_keinen_batch_import(welt, client):
    await poolgeraet(welt, "g1", itnr="IT100")
    kopf = await anmelden(client, "schaubach")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda"},
        files=anhang(excel([("IT100", "SN100")])),
        headers=kopf,
    )
    assert antwort.status_code == 403
    assert (await welt.ipads.find_one({"id": "g1"}))["is_in_pool"] is True


@pytest.mark.xfail(
    reason="batch_assign_import quittiert nur Geraete, die neu angelegt oder aus dem Pool "
    "geholt wurden. Liegt ein Geraet bereits im Ziel-Bildungsgang, bleibt die Uebergabe "
    "unvermerkt - bei einer Nachlieferung an denselben Bildungsgang ist hinterher nicht "
    "mehr feststellbar, wer die Geraete bekommen hat.",
    strict=True,
)
async def test_uebergabe_wird_auch_bei_bereits_zugeordnetem_geraet_quittiert(welt, client):
    """Das Gerät gehört MEDA schon - übergeben wird es trotzdem, also muss es in der Historie stehen."""
    await geraet(welt, "g1", "bg_meda", itnr="IT100")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT100", "SN100")])),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text

    verlauf = await client.get("/api/ipads/g1/history", headers=kopf)
    quittungen = [h for h in verlauf.json()["pool_history"] if h["uebergeben_an"] == "bakenecker"]
    assert quittungen, "Die körperliche Übergabe muss festgehalten werden"
