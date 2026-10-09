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


async def geraet_ohne_poolfeld(db, ipad_id, bildungsgang_id, itnr=None, angelegt_von="u_admin"):
    """Ein Bestandsgerät, dem `is_in_pool` ganz FEHLT - so liegt die Mehrheit des echten Bestands.

    Das Feld kam erst mit dem Pool hinzu; die davor zentral importierten Geräte tragen es bis
    heute nicht (349 von 430). `geraet` setzt es auf False und geht damit an genau der Lage
    vorbei, in der jede Abfrage auf {"is_in_pool": False} ins Leere läuft. Deshalb wird hier
    direkt in die Datenbank geschrieben: über die API entstünde das Feld unvermeidlich.
    """
    await db.ipads.insert_one({
        "id": ipad_id, "bildungsgang_id": bildungsgang_id,
        "itnr": itnr or f"IT{ipad_id}", "snr": f"SN{ipad_id}", "status": "ok",
        "user_id": angelegt_von, "pool_history": [], "current_assignment_id": None,
    })


async def einstellungen(db, ipad_typ, pencil):
    """Die Admin-Vorgaben, aus denen die Route leer gelassene Zellen füllt."""
    await db.global_settings.insert_one({"type": "app_settings", "ipad_typ": ipad_typ, "pencil": pencil})


# Die vollständige Lieferliste, in der Reihenfolge, in der die Spalten in der Datei stehen.
SPALTEN_VOLL = ("ITNr", "SNr", "Karton", "Pencil", "Typ", "AnschJahr", "Status")


def excel(zeilen, spalten=("ITNr", "SNr")):
    """Eine Importliste als echte .xlsx-Datei - die Route prüft den Dateiinhalt, nicht die Endung.

    `spalten` bleibt per Vorgabe bei ITNr/SNr: so sah die Liste vor dem Ausbau aus, und genau
    die muss weiterhin dasselbe Ergebnis liefern.
    """
    puffer = io.BytesIO()
    pd.DataFrame(zeilen, columns=list(spalten)).to_excel(puffer, index=False)
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
        json={"ipad_ids": ["g1", "g2", "fremd"], "bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["success_count"] == 2
    assert antwort.json()["failed_count"] == 1
    assert (await welt.ipads.find_one({"id": "fremd"}))["bildungsgang_id"] == "bg_gym"


async def test_bulk_claim_ohne_auswahl_wird_abgelehnt(welt, client):
    kopf = await anmelden(client, "admin")
    antwort = await client.post(
        "/api/ipads/bulk-claim", json={"ipad_ids": [], "bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"}, headers=kopf
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
        json={"ipad_ids": ["g1"], "bildungsgang_id": "bg_gibtsnicht", "uebergeben_an_user_id": "u_bakenecker"},
        headers=kopf,
    )
    assert antwort.status_code == 404
    assert (await welt.ipads.find_one({"id": "g1"}))["is_in_pool"] is True


async def test_zuweisung_ohne_geraete_wird_abgelehnt(welt, client):
    kopf = await anmelden(client, "admin")
    antwort = await client.post(
        "/api/admin/ipads/assign-to-bildungsgang",
        json={"ipad_ids": [], "bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
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
        json={"ipad_ids": ["g1", "fremd"], "bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
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
        json={"ipad_ids": ["g1"], "bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert (await welt.ipads.find_one({"id": "g1"}))["user_id"] == "u_bakenecker"


async def test_lehrkraft_darf_keinem_bildungsgang_zuweisen(welt, client):
    await poolgeraet(welt, "g1")
    kopf = await anmelden(client, "schaubach")

    antwort = await client.post(
        "/api/admin/ipads/assign-to-bildungsgang",
        json={"ipad_ids": ["g1"], "bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
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


async def test_batch_import_ohne_empfaenger_wird_abgelehnt(welt, client):
    """Auch der Dateiimport verlangt einen Empfänger.

    Besitz und Übergabe bleiben getrennte Angaben - aber beide sind verpflichtend. Ohne die
    zweite bliebe offen, bei wem die Geräte körperlich gelandet sind, und genau das ist die
    Frage, die im Schuljahr aufkommt.
    """
    await poolgeraet(welt, "g1", itnr="IT100")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda"},  # absichtlich OHNE Empfänger
        files=anhang(excel([("IT100", "SN100")])),
        headers=kopf,
    )
    assert antwort.status_code == 422, antwort.text
    assert (await welt.ipads.find_one({"id": "g1"}))["is_in_pool"] is True, "Gerät darf im Pool bleiben"


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
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
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
        data={"bildungsgang_id": "bg_gibtsnicht", "uebergeben_an_user_id": "u_bakenecker"},
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
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
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
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT100", "SN100")])),
        headers=kopf,
    )
    assert antwort.status_code == 403
    assert (await welt.ipads.find_one({"id": "g1"}))["is_in_pool"] is True


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


# --- Batch-Import: die Stammdaten aus der Lieferliste -------------------------------------
#
# Die Lieferliste des Schulträgers ist das erste Dokument, das Karton, Pencil, genauen Typ,
# Anschaffungsjahr und Status kennt. Sie ist zugleich das älteste: der Bestand wurde seit dem
# zentralen Import in der App gepflegt. Deshalb füllt sie nur Lücken und überschreibt nie.


async def test_lieferliste_legt_das_geraet_mit_allen_angaben_an(welt, client):
    """Eine noch nie erfasste ITNr bekommt alles mit, was in der Zeile steht."""
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel(
            [("IT500", "SN500", "K7", "mit Apple Pencil", "Apple iPad 9. Gen, 64 GB", "2024", "defekt")],
            spalten=SPALTEN_VOLL,
        )),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["summary"]["created_count"] == 1

    neu = await welt.ipads.find_one({"itnr": "IT500"})
    assert neu["karton"] == "K7"
    assert neu["pencil"] == "mit Apple Pencil"
    assert neu["typ"] == "Apple iPad 9. Gen, 64 GB"
    assert neu["ansch_jahr"] == "2024"
    assert neu["status"] == "defekt"


async def test_leere_zellen_fallen_auf_die_einstellungen_zurueck(welt, client):
    """Eine leere Zelle ist keine Angabe - und darf keinen Leerstring in den Bestand schreiben.

    Typ und Pencil holt sich die Route aus den Admin-Einstellungen, der Status ist "ok".
    Karton und Anschaffungsjahr haben keine Vorgabe: dort muss None stehen. Ein "" sähe im
    Bestand aus wie eine gemachte, aber leere Angabe - und wäre nicht mehr nachtragbar, weil
    die Lieferliste nur füllt, was leer ist.
    """
    await einstellungen(welt, ipad_typ="Apple iPad 10. Gen", pencil="mit Apple Pencil")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT500", "SN500", "", "", "", "", "")], spalten=SPALTEN_VOLL)),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text

    neu = await welt.ipads.find_one({"itnr": "IT500"})
    assert neu["typ"] == "Apple iPad 10. Gen"
    assert neu["pencil"] == "mit Apple Pencil"
    assert neu["status"] == "ok"
    assert neu["karton"] is None
    assert neu["ansch_jahr"] is None


async def test_lieferliste_ergaenzt_am_poolgeraet_nur_was_fehlt(welt, client):
    """Beim Griff in den Pool werden Lücken gefüllt - ein vorhandener Typ bleibt stehen.

    In der Liste steht die grobe Sammelbezeichnung, im Bestand die in der App nachgetragene
    genaue. Die gröbere darf die genauere nicht ersetzen.
    """
    await poolgeraet(welt, "g1", itnr="IT100")
    await welt.ipads.update_one({"id": "g1"}, {"$set": {"typ": "Apple iPad 9. Gen, 64 GB"}})
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel(
            [("IT100", "SNg1", "K7", "mit Apple Pencil", "Apple iPad", "2024", "ok")],
            spalten=SPALTEN_VOLL,
        )),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zeile = antwort.json()["rows"][0]
    assert zeile["outcome"] == "from_pool"
    assert "ergänzt" in zeile["note"]

    nachher = await welt.ipads.find_one({"id": "g1"})
    assert nachher["karton"] == "K7"
    assert nachher["pencil"] == "mit Apple Pencil"
    assert nachher["ansch_jahr"] == "2024"
    assert nachher["typ"] == "Apple iPad 9. Gen, 64 GB", "die genauere Angabe aus der App bleibt"
    assert nachher["bildungsgang_id"] == "bg_meda"


async def test_nachlieferung_ergaenzt_im_eigenen_bildungsgang_nur_was_fehlt(welt, client):
    """Das Gerät gehört MEDA schon - auch dann gilt: füllen, nicht überschreiben."""
    await geraet(welt, "g1", "bg_meda", itnr="IT100")
    await welt.ipads.update_one({"id": "g1"}, {"$set": {"karton": "K1"}})
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel(
            [("IT100", "SNg1", "K7", "mit Apple Pencil", "Apple iPad 9. Gen, 64 GB", "2024", "ok")],
            spalten=SPALTEN_VOLL,
        )),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["rows"][0]["outcome"] == "already_assigned"

    nachher = await welt.ipads.find_one({"id": "g1"})
    assert nachher["karton"] == "K1", "der in der App gepflegte Karton bleibt"
    assert nachher["pencil"] == "mit Apple Pencil"
    assert nachher["typ"] == "Apple iPad 9. Gen, 64 GB"
    assert nachher["ansch_jahr"] == "2024"


async def test_nachlieferung_erreicht_auch_geraete_ohne_poolfeld(welt, client):
    """Der Normalfall des echten Bestands: `is_in_pool` fehlt dem Gerät ganz.

    Das ist kein Randfall, sondern die Mehrheit - das Feld kam erst mit dem Pool hinzu. Eine
    Abfrage auf {"is_in_pool": False} findet ein fehlendes Feld nicht: die Nachlieferung lief
    für diese Geräte ins Leere, trug nichts nach, quittierte nichts und meldete die Zeile
    obendrein als Fehler. Gefragt werden muss nach {"$ne": True}.
    """
    await geraet_ohne_poolfeld(welt, "g1", "bg_meda", itnr="IT100")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel(
            [("IT100", "SNg1", "K7", "mit Apple Pencil", "Apple iPad 9. Gen, 64 GB", "2024", "ok")],
            spalten=SPALTEN_VOLL,
        )),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zeile = antwort.json()["rows"][0]
    assert zeile["outcome"] == "already_assigned", zeile
    assert "quittiert" in zeile["note"], zeile["note"]
    assert antwort.json()["summary"]["quittiert_count"] == 1

    nachher = await welt.ipads.find_one({"id": "g1"})
    assert nachher["karton"] == "K7"
    assert nachher["pencil"] == "mit Apple Pencil"
    assert nachher["typ"] == "Apple iPad 9. Gen, 64 GB"
    assert nachher["ansch_jahr"] == "2024"
    assert nachher["bildungsgang_id"] == "bg_meda", "am Besitz ändert sich nichts"

    verlauf = await client.get("/api/ipads/g1/history", headers=kopf)
    assert verlauf.status_code == 200, verlauf.text
    quittungen = [h for h in verlauf.json()["pool_history"] if h["uebergeben_an"] == "bakenecker"]
    assert quittungen, "die körperliche Übergabe muss auch hier festgehalten werden"
    assert quittungen[-1]["bildungsgang_name"] == "MEDA"
    assert frisch(quittungen[-1]["at"])


async def test_fremder_bildungsgang_bekommt_keine_stammdaten(welt, client):
    """Im fremden Bestand wird nichts angefasst - auch keine harmlos wirkende Typangabe.

    Hinter einer ITNr in einer fremden Liste steckt meist ein Zahlendreher. Die Stammdaten
    landeten dann unsichtbar bei einem Bildungsgang, der die Lieferung nie bekommen hat.
    """
    await geraet(welt, "g1", "bg_gym", itnr="IT100")
    vorher = await welt.ipads.find_one({"id": "g1"})
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel(
            [("IT100", "SNg1", "K7", "mit Apple Pencil", "Apple iPad 9. Gen, 64 GB", "2024", "defekt")],
            spalten=SPALTEN_VOLL,
        )),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zeile = antwort.json()["rows"][0]
    assert zeile["outcome"] == "already_assigned"
    assert zeile["assigned_to"] == "GYM"

    assert await welt.ipads.find_one({"id": "g1"}) == vorher, "kein einziges Feld darf sich geändert haben"


async def test_fremdes_geraet_behaelt_anleger_und_historie(welt, client):
    """Auch die Historie bleibt unberührt: es gab keine Übergabe, also gibt es keine Quittung."""
    await geraet(welt, "g1", "bg_gym", itnr="IT100", angelegt_von="u_wieners")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel(
            [("IT100", "SNg1", "K7", "mit Apple Pencil", "Apple iPad 9. Gen, 64 GB", "2024", "ok")],
            spalten=SPALTEN_VOLL,
        )),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text

    nachher = await welt.ipads.find_one({"id": "g1"})
    assert nachher["user_id"] == "u_wieners"
    assert nachher["pool_history"] == []


async def test_abweichende_snr_wird_gemeldet_statt_uebernommen(welt, client):
    """Zwei Seriennummern unter einer ITNr heißen vertauschte Hardware oder einen Zahlendreher.

    Beides klärt nur, wer die Geräte vor sich hat - die Route entscheidet es nicht still.
    """
    await poolgeraet(welt, "g1", itnr="IT100")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT100", "SN999")])),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zeile = antwort.json()["rows"][0]
    assert zeile["outcome"] == "from_pool"
    assert "SNg1" in zeile["note"] and "SN999" in zeile["note"], zeile["note"]

    assert (await welt.ipads.find_one({"id": "g1"}))["snr"] == "SNg1"


async def test_leere_snr_im_bestand_wird_ergaenzt(welt, client):
    """Fehlt die Seriennummer im Bestand, ist die Liste die bessere Quelle - sie wird übernommen."""
    await poolgeraet(welt, "g1", itnr="IT100")
    await welt.ipads.update_one({"id": "g1"}, {"$set": {"snr": ""}})
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT100", "SN100")])),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert "SNr" in antwort.json()["rows"][0]["note"]

    assert (await welt.ipads.find_one({"id": "g1"}))["snr"] == "SN100"


async def test_unbekannter_status_wird_zu_ok_und_gemeldet(welt, client):
    """Ein Tippfehler in der Status-Spalte darf das Gerät nicht aus der Lieferung werfen.

    Es wird angelegt, der Status auf "ok" gesetzt - und die Zeile sagt, dass nachgesehen
    werden muss.
    """
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT500", "SN500", "kaputt")], spalten=("ITNr", "SNr", "Status"))),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zeile = antwort.json()["rows"][0]
    assert zeile["outcome"] == "created"
    assert "kaputt" in zeile["note"], zeile["note"]

    assert (await welt.ipads.find_one({"itnr": "IT500"}))["status"] == "ok"


async def test_unbekannter_status_wird_auch_am_vorhandenen_geraet_gemeldet(welt, client):
    """"kaputt" in der Liste ist der Grund, warum jemand das Gerät ansehen soll.

    Am Bestand ändert die Spalte bei einem vorhandenen Gerät nichts - gerade deshalb muss die
    Zeile sagen, dass dort etwas stand, das sie nicht deuten konnte. Gemeldet wurde der
    ungedeutete Wert bisher nur beim NEU angelegten Gerät; bei allen schon erfassten
    verschwand er stillschweigend.
    """
    await poolgeraet(welt, "g1", itnr="IT100")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT100", "SNg1", "kaputt")], spalten=("ITNr", "SNr", "Status"))),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zeile = antwort.json()["rows"][0]
    assert zeile["outcome"] == "from_pool"
    assert "kaputt" in zeile["note"], zeile["note"]

    assert (await welt.ipads.find_one({"id": "g1"}))["status"] == "ok", "der Bestand bleibt stehen"


async def test_abweichender_status_wird_gemeldet_statt_uebernommen(welt, client):
    """In der Liste steht "defekt", im Bestand "ok" - der Bestand bleibt stehen, die Zeile sagt es.

    Derselbe Grund wie bei der SNr: der Bestand kam zentral herein und wurde seitdem in der
    App gepflegt, die Lieferliste ist älter als diese Korrekturen. Welche der beiden Angaben
    stimmt, klärt nur, wer das Gerät vor sich hat - stillschweigend verschwinden darf die aus
    der Liste deshalb nicht.
    """
    await poolgeraet(welt, "g1", itnr="IT100")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT100", "SNg1", "defekt")], spalten=("ITNr", "SNr", "Status"))),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zeile = antwort.json()["rows"][0]
    assert zeile["outcome"] == "from_pool"
    assert zeile["note"] == "Status weicht ab: im Bestand 'ok', in der Liste 'defekt'", zeile["note"]

    assert (await welt.ipads.find_one({"id": "g1"}))["status"] == "ok", "der Bestand bleibt stehen"


async def test_abweichender_status_wird_auch_bei_der_nachlieferung_gemeldet(welt, client):
    """Das Gerät gehört MEDA schon: es wird quittiert und nachgetragen - der Status trotzdem nicht.

    Diese Zeile trägt bereits eine Meldung, die Quittung. Der Hinweis muss daneben treten,
    nicht an ihre Stelle - sonst erfährt der Admin je Zeile nur das, was zufällig zuerst
    gemeldet wurde.
    """
    await geraet(welt, "g1", "bg_meda", itnr="IT100")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT100", "SNg1", "defekt")], spalten=("ITNr", "SNr", "Status"))),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zeile = antwort.json()["rows"][0]
    assert zeile["outcome"] == "already_assigned"
    assert zeile["note"] == (
        "Bereits zugeordnet zu MEDA - Übergabe quittiert"
        " - Status weicht ab: im Bestand 'ok', in der Liste 'defekt'"
    ), zeile["note"]

    assert (await welt.ipads.find_one({"id": "g1"}))["status"] == "ok", "der Bestand bleibt stehen"


async def test_gleicher_status_bleibt_unerwaehnt(welt, client):
    """Liste und Bestand sagen dasselbe - dazu gibt es nichts zu melden.

    Das ist der Normalfall jeder Lieferliste. Stünde auch hier ein Hinweis, trüge ihn fast
    jede Zeile, und die wenigen Zeilen, auf die es ankommt, gingen darin unter.
    """
    await poolgeraet(welt, "g1", itnr="IT100")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT100", "SNg1", "ok")], spalten=("ITNr", "SNr", "Status"))),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zeile = antwort.json()["rows"][0]
    assert zeile["outcome"] == "from_pool"
    assert zeile["note"] is None, zeile["note"]


async def test_leere_statusspalte_meldet_keine_abweichung(welt, client):
    """Eine leere Zelle ist keine Angabe - sie kann vom Bestand nicht abweichen.

    Ungeprüft in den Vergleich gegeben, meldete sie "in der Liste 'None'", und zwar an jeder
    einzelnen Zeile einer Liste, in der die Spalte schlicht nicht ausgefüllt wurde.
    """
    await poolgeraet(welt, "g1", itnr="IT100")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT100", "SNg1", "")], spalten=("ITNr", "SNr", "Status"))),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zeile = antwort.json()["rows"][0]
    assert zeile["outcome"] == "from_pool"
    assert zeile["note"] is None, zeile["note"]


async def test_grossschreibung_allein_ist_keine_abweichung(welt, client):
    """"Defekt" und "defekt" sind dieselbe Angabe - auf beiden Seiten des Vergleichs.

    Der Wert aus der Datei wird schon beim Lesen kleingeschrieben, der aus dem Bestand erst im
    Vergleich. Beides wird gebraucht: die erste Zeile kommt großgeschrieben aus der Liste, die
    zweite trifft auf ein großgeschriebenes "Defekt" in der Kartei, wie es der zentrale Import
    hinterlassen hat. Keine der beiden ist eine Abweichung.
    """
    await poolgeraet(welt, "g1", itnr="IT100")
    await poolgeraet(welt, "g2", itnr="IT101")
    await welt.ipads.update_one({"id": "g1"}, {"$set": {"status": "defekt"}})
    await welt.ipads.update_one({"id": "g2"}, {"$set": {"status": "Defekt"}})
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel(
            [("IT100", "SNg1", "Defekt"), ("IT101", "SNg2", "defekt")],
            spalten=("ITNr", "SNr", "Status"),
        )),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zeilen = antwort.json()["rows"]
    assert [z["outcome"] for z in zeilen] == ["from_pool", "from_pool"], zeilen
    assert [z["note"] for z in zeilen] == [None, None], zeilen


async def test_unbekannter_status_meldet_nicht_zusaetzlich_eine_abweichung(welt, client):
    """"kaputt" weicht nicht vom Bestand ab - es ist überhaupt kein Status.

    Die beiden Meldungen beantworten verschiedene Fragen: die eine sagt, dass in der Liste
    etwas steht, das niemand deuten kann, die andere, dass zwei deutbare Angaben auseinander-
    gehen. An derselben Zeile zugleich wären sie nur Lärm.
    """
    await poolgeraet(welt, "g1", itnr="IT100")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT100", "SNg1", "kaputt")], spalten=("ITNr", "SNr", "Status"))),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zeile = antwort.json()["rows"][0]
    assert zeile["outcome"] == "from_pool"
    assert zeile["note"] == "Status 'kaputt' unbekannt - im Bestand steht 'ok'", zeile["note"]


async def test_neues_geraet_uebernimmt_den_status_aus_der_liste(welt, client):
    """Ein Gerät, das es noch nicht gibt, kann von nichts abweichen.

    Hier ist die Liste die einzige Quelle: "defekt" wird übernommen, und die Zeile bleibt
    stumm. Ein Abweichungshinweis verwiese auf einen Bestand, der in derselben Sekunde aus
    eben dieser Liste entstanden ist.

    Dieser Zweig baut seine Meldung selbst und läuft NICHT durch _hinweis() - der Test
    sichert also den created-Zweig ab, nicht die Abweichungsmeldung. Der frühere Name
    ("...ohne_hinweis") las sich andersherum.
    """
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT500", "SN500", "defekt")], spalten=("ITNr", "SNr", "Status"))),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zeile = antwort.json()["rows"][0]
    assert zeile["outcome"] == "created"
    assert zeile["note"] is None, zeile["note"]

    assert (await welt.ipads.find_one({"itnr": "IT500"}))["status"] == "defekt"


async def test_geraet_ohne_statusfeld_gilt_als_ok(welt, client):
    """Fehlt das Feld ganz, gilt "ok" - und zwar ohne dass der Lauf darüber stolpert.

    Der zentrale Altimport hat nachweislich Felder weggelassen (349 von 430 Geräten tragen
    kein is_in_pool), ein Datensatz ohne status ist also nicht ausgedacht. Ohne den Rückfall
    liefe der Vergleich auf None und risse mit einem AttributeError den ganzen Upload mit -
    nicht nur diese eine Zeile.
    """
    kopf = await anmelden(client, "admin")
    await poolgeraet(welt, "i_ohne_status", itnr="IT501")
    await welt.ipads.update_one({"id": "i_ohne_status"}, {"$unset": {"status": ""}})

    # Dieselbe SNr wie im Bestand, damit die Zeile nur den Status meldet und nichts sonst.
    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT501", "SNi_ohne_status", "defekt")], spalten=("ITNr", "SNr", "Status"))),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zeile = antwort.json()["rows"][0]
    assert zeile["note"] == "Status weicht ab: im Bestand 'ok', in der Liste 'defekt'", zeile["note"]
    # Und der Bestand bleibt, wie er war - auch ein fehlendes Feld wird nicht nachgetragen.
    assert "status" not in await welt.ipads.find_one({"itnr": "IT501"})


async def test_mehrere_hinweise_stehen_nebeneinander_in_einer_zeile(welt, client):
    """Abweichende SNr, abweichender Status und ein ergänztes Feld - alle drei in einer Note.

    Je Zeile bekommt der Admin genau ein Feld Text zu lesen. Verdrängt ein Hinweis einen
    anderen, erfährt er von der Hälfte dessen nichts, weswegen er das Gerät in die Hand nehmen
    müsste - und gemerkt würde es niemand, weil die Zeile ja eine Meldung trägt.
    """
    await poolgeraet(welt, "g1", itnr="IT100")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel(
            [("IT100", "SN999", "K7", "", "", "", "defekt")],
            spalten=SPALTEN_VOLL,
        )),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    zeile = antwort.json()["rows"][0]
    assert zeile["outcome"] == "from_pool"
    assert zeile["note"] == (
        "SNr weicht ab: im Bestand SNg1, in der Liste SN999"
        " - Status weicht ab: im Bestand 'ok', in der Liste 'defekt'"
        " - Karton ergänzt"
    ), zeile["note"]

    nachher = await welt.ipads.find_one({"id": "g1"})
    assert nachher["snr"] == "SNg1", "die abweichende SNr wird gemeldet, nicht übernommen"
    assert nachher["status"] == "ok", "der Bestand bleibt stehen"
    assert nachher["karton"] == "K7", "das leere Feld wird ergänzt"


async def test_liste_aus_itnr_und_snr_wirkt_wie_vor_dem_ausbau(welt, client):
    """Der Rückwärtsgang: die alten Listen ohne Stammdatenspalten müssen unverändert laufen.

    Nicht genannte Felder bleiben None. Stünde dort "", wäre die Spalte für immer belegt -
    eine spätere Lieferliste könnte sie nicht mehr nachtragen.
    """
    await einstellungen(welt, ipad_typ="Apple iPad 10. Gen", pencil="ohne Apple Pencil")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT500", "SN500")])),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["rows"][0]["note"] is None

    neu = await welt.ipads.find_one({"itnr": "IT500"})
    assert neu["snr"] == "SN500"
    assert neu["typ"] == "Apple iPad 10. Gen"
    assert neu["pencil"] == "ohne Apple Pencil"
    assert neu["status"] == "ok"
    assert neu["karton"] is None
    assert neu["ansch_jahr"] is None


async def test_anschaffungsjahr_als_zahl_bleibt_eine_jahreszahl(welt, client):
    """Excel liefert Zahlenspalten als Fließkommazahl - aus 2024 würde sonst "2024.0".

    Die zweite Zeile mit leerer Zelle ist kein Beiwerk: erst sie macht die Spalte in der Datei
    zu einer Fließkommaspalte, und genau so kommt die echte Liste herein. Ihr leeres Feld muss
    dabei None bleiben, nicht "nan".
    """
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel(
            [("IT500", "SN500", 2024), ("IT501", "SN501", "")], spalten=("ITNr", "SNr", "AnschJahr")
        )),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text

    assert (await welt.ipads.find_one({"itnr": "IT500"}))["ansch_jahr"] == "2024"
    assert (await welt.ipads.find_one({"itnr": "IT501"}))["ansch_jahr"] is None


async def test_seriennummer_als_zahl_bleibt_ohne_nachkommastelle(welt, client):
    """Eine rein numerische SNr kommt als Fließkommazahl herein - "123456789.0" wäre falsch.

    Dieselbe Falle wie beim Anschaffungsjahr, nur folgenschwerer: unter der verfälschten
    Nummer findet niemand das Gerät wieder, und auf dem Leihvertrag steht sie gedruckt. Die
    zweite Zeile mit leerer Zelle macht die Spalte in der Datei überhaupt erst zu einer
    Fließkommaspalte - genau so kommt die echte Liste herein.
    """
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(excel([("IT500", 123456789), ("IT501", "")])),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text

    assert (await welt.ipads.find_one({"itnr": "IT500"}))["snr"] == "123456789"


# --- Die Vorlage für den Upload ----------------------------------------------------------
#
# Vorlage und Upload sind ein Paar: was die eine ausgibt, muss die andere lesen. Laufen sie
# auseinander, füllt jemand gewissenhaft eine Spalte aus, die niemand mehr liest.


def vorlage_lesen(inhalt: bytes) -> pd.DataFrame:
    """Die heruntergeladene Vorlage so einlesen, wie der Upload sie läse."""
    return pd.read_excel(io.BytesIO(inhalt))


# Eine Beispielnummer ist als Beispiel erkennbar, wenn sie sich selbst als eine ausweist -
# daran und an nichts anderem. Andersherum zu prüfen, also gegen die Form echter Nummern
# ("IT" und dahinter Ziffern), hat genau hier versagt: "IT-001" trug einen Bindestrich und
# kam deshalb an diesem Muster vorbei, obwohl es der Wert war, vor dem die Prüfung schützen
# sollte. Sie konnte danach nicht mehr fehlschlagen, gleich was in der Vorlage stand.
BEISPIEL_WOERTER = ("beispiel", "muster", "example", "sample", "dummy")


def als_beispiel_erkennbar(nummer: str) -> bool:
    """Weist die Nummer sich in einer Lieferliste selbst als Beispiel aus?"""
    return any(wort in nummer.casefold() for wort in BEISPIEL_WOERTER)


# Die Werte, an denen die Prüfung nachweislich anschlägt. Der Test unten führt sie mit,
# damit der Nachweis nicht bloß behauptet bleibt: "IT-001" stand wirklich in der Vorlage,
# "IT001" und "IT 001" sind dieselbe Nummer in anderer Schreibweise, "IT-0815" eine
# beliebige weitere, und "001" zeigt, dass auch eine Nummer ohne Präfix nicht durchkommt.
# Setzt jemand die Beispielwerte auf einen dieser Werte, wird der Test rot.
NUMMERN_OHNE_BEISPIELCHARAKTER = ("IT-001", "IT001", "IT 001", "IT-0815", "001")


async def test_admin_bekommt_die_vorlage_zum_batch_upload(welt, client):
    kopf = await anmelden(client, "admin")

    antwort = await client.get("/api/admin/ipads/batch-assign-template", headers=kopf)
    assert antwort.status_code == 200, antwort.text
    assert antwort.headers["content-type"] == EXCEL_TYP
    assert antwort.content, "die Vorlage darf nicht leer sein"


async def test_lehrkraft_bekommt_die_vorlage_nicht(welt, client):
    """Die Vorlage ist so beschränkt wie der Upload - sonst wäre die Beschränkung nur Zierde."""
    kopf = await anmelden(client, "schaubach")

    antwort = await client.get("/api/admin/ipads/batch-assign-template", headers=kopf)
    assert antwort.status_code == 403


async def test_die_vorlage_fuehrt_genau_die_spalten_des_uploads(welt, client):
    """Der eigentliche Zweck dieses Tests: er bricht, wenn Vorlage und Upload auseinanderlaufen.

    Verglichen wird gegen SPALTEN_VOLL - dieselbe Liste, mit der die Upload-Tests oben ihre
    Dateien bauen. Bekommt der Upload eine Spalte dazu, ohne dass die Vorlage sie ausgibt
    (oder umgekehrt), fällt genau hier auf, dass die ausgefüllte Vorlage nicht mehr das
    liefert, was sie verspricht. Die Reihenfolge gehört dazu: die Vorlage soll sich lesen
    lassen wie die Lieferliste des Trägers.
    """
    kopf = await anmelden(client, "admin")

    antwort = await client.get("/api/admin/ipads/batch-assign-template", headers=kopf)
    assert antwort.status_code == 200, antwort.text
    assert list(vorlage_lesen(antwort.content).columns) == list(SPALTEN_VOLL)


async def test_die_zweite_beispielzeile_enthaelt_nur_die_itnr(welt, client):
    """Die karge zweite Zeile ist Absicht, keine halb vergessene.

    Sie sagt dem Admin, was die Vorlage sonst nirgends sagt: außer der ITNr muss nichts
    ausgefüllt werden. Wer sie "vervollständigt", nimmt der Vorlage genau die Auskunft, die
    den meisten Listen die Arbeit erspart.
    """
    kopf = await anmelden(client, "admin")

    antwort = await client.get("/api/admin/ipads/batch-assign-template", headers=kopf)
    assert antwort.status_code == 200, antwort.text

    zeile = vorlage_lesen(antwort.content).iloc[1]
    assert str(zeile["ITNr"]).strip(), "die ITNr ist die eine Angabe, die stehen muss"
    gefuellt = [spalte for spalte in SPALTEN_VOLL if spalte != "ITNr" and not pd.isna(zeile[spalte])]
    assert gefuellt == [], f"diese Zellen müssen leer bleiben: {gefuellt}"


async def test_die_beispielnummern_sind_als_beispiel_erkennbar(welt, client):
    """Die unverändert hochgeladene Vorlage darf nicht wie eine echte Lieferliste aussehen.

    Geprüft wird die Absicht, nicht eine bestimmte Zeichenkette: jede Beispielnummer muss
    sich selbst als Beispiel ausweisen. Ob in der Vorlage "BEISPIEL-1" oder "MUSTER-A"
    steht, ist gleichgültig. "IT-001" war es nicht: wer die Vorlage unverändert hochlud,
    legte zwei Geistergeräte an, die anschließend niemand mehr als Beispielzeilen erkannte.

    Die erste Schleife ist der Nachweis, dass die Prüfung überhaupt anschlagen KANN. Der
    Vorgänger prüfte gegen die Form echter Nummern und ging an "IT-001" vorbei - er war
    immer grün, gleich was in der Vorlage stand, und damit schlimmer als gar keiner.
    """
    kopf = await anmelden(client, "admin")

    for nummer in NUMMERN_OHNE_BEISPIELCHARAKTER:
        assert not als_beispiel_erkennbar(nummer), f"{nummer} dürfte hier nicht durchgehen"

    antwort = await client.get("/api/admin/ipads/batch-assign-template", headers=kopf)
    assert antwort.status_code == 200, antwort.text

    nummern = [str(wert).strip() for wert in vorlage_lesen(antwort.content)["ITNr"]]
    assert len(nummern) == 2, nummern
    for nummer in nummern:
        assert nummer, "eine leere Beispielnummer wäre keine Vorlage"
        assert als_beispiel_erkennbar(nummer), f"{nummer} ist in einer Liste nicht als Beispiel zu erkennen"


async def test_die_unveraendert_hochgeladene_vorlage_legt_kein_geraet_an(welt, client):
    """Die Vorlage auszuprobieren heißt, sie herunterzuladen und wieder hochzuladen.

    Genau das legte bis vor kurzem zwei Geräte an, die es nie gab. Erkennbar unecht zu sein
    reicht nicht - der Upload muss dieselben Nummern kennen und solche Zeilen überspringen.

    Deshalb wird die Vorlage hier über den Endpunkt geholt und unverändert weitergereicht,
    nicht von Hand nachgebaut: nur so prüft der Test die Kopplung, um die es geht. Zwei
    getrennt gepflegte Listen liefen auseinander, ohne dass eine nachgebaute Datei das je
    bemerkt hätte.

    Beispielzeilen zählen nicht als Fehler: unter "ungültig / Fehler" geführt schickten sie
    den Admin auf die Suche nach einem Problem, das es nicht gibt.
    """
    kopf = await anmelden(client, "admin")

    vorlage = await client.get("/api/admin/ipads/batch-assign-template", headers=kopf)
    assert vorlage.status_code == 200, vorlage.text

    antwort = await client.post(
        "/api/admin/ipads/batch-assign-import",
        data={"bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        files=anhang(vorlage.content, name="batch_zuordnung_vorlage.xlsx"),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text

    daten = antwort.json()
    assert [zeile["outcome"] for zeile in daten["rows"]] == ["beispielzeile", "beispielzeile"], daten["rows"]

    zusammenfassung = daten["summary"]
    assert zusammenfassung["beispielzeile_count"] == 2
    assert zusammenfassung["created_count"] == 0
    assert zusammenfassung["invalid_rows"] == 0, "eine Beispielzeile ist kein Mangel der Liste"
    assert zusammenfassung["error_count"] == 0
    assert await welt.ipads.count_documents({}) == 0, "die Vorlage darf kein Gerät hinterlassen"


# --- Beim Anlegen und Bearbeiten: gekürzt speichern, leeren Typ auffüllen -----------------


async def test_itnr_mit_leerzeichen_wird_gekuerzt_gespeichert(welt, client):
    """Ein Leerzeichen am Rand macht das Gerät unauffindbar, ohne dass man es sieht.

    In der Liste ist " IT900" von jeder anderen Nummer nicht zu unterscheiden - gesucht wird
    aber nach der Nummer, gespeichert war Leerzeichen plus Nummer. Der Excel-Import kürzt seit
    jeher, das Eingabeformular tat es nicht.
    """
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/ipads",
        json={"itnr": "  IT900  ", "snr": " SN900 ", "bildungsgang_id": "bg_meda"},
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["itnr"] == "IT900"
    assert antwort.json()["snr"] == "SN900"
    assert await welt.ipads.count_documents({"itnr": "IT900"}) == 1


async def test_ausleihe_datum_wird_beim_anlegen_gekuerzt(welt, client):
    """Dasselbe Leerzeichen, dieselbe Folge - nur fällt sie beim Datum noch später auf.

    " 2026-09-01" ist in jeder Ansicht von "2026-09-01" nicht zu unterscheiden, aber jeder
    Vergleich und jede Sortierung über das Feld sieht einen anderen Wert. Die ITNr darüber
    wurde gekürzt, das Datum daneben nicht.
    """
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/ipads",
        json={
            "itnr": "IT900",
            "snr": "SN900",
            "ausleihe_datum": "  2026-09-01  ",
            "bildungsgang_id": "bg_meda",
        },
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["ausleihe_datum"] == "2026-09-01"
    assert (await welt.ipads.find_one({"itnr": "IT900"}))["ausleihe_datum"] == "2026-09-01"


async def test_anlegen_mit_erfundenem_status_wird_abgelehnt(welt, client):
    """Was das Bearbeiten zurückweist, darf das Anlegen nicht herstellen können.

    "kaputt" klingt richtig und steht nicht im Katalog (ok/defekt/gestohlen). Angelegt
    wurde es gespeichert - und das Gerät ließ sich anschließend nicht mehr bearbeiten, ohne
    dass jemand den erfundenen Status bemerkt und mitkorrigiert hätte.
    """
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/ipads",
        json={"itnr": "IT900", "snr": "SN900", "status": "kaputt", "bildungsgang_id": "bg_meda"},
        headers=kopf,
    )
    assert antwort.status_code == 400, antwort.text
    assert "Status" in antwort.json()["detail"]
    assert await welt.ipads.count_documents({}) == 0, "das Gerät darf gar nicht erst entstehen"


async def test_typ_aus_lauter_leerzeichen_bekommt_die_vorgabe(welt, client):
    """Ein mit der Leertaste "geleertes" Feld ist für jeden Leser leer - also auch hier.

    Gekürzt wird vor der Prüfung auf leer. Sonst gälte " " als ausgefüllt, die Vorgabe griffe
    nicht, und im Bestand stünde ein Typ, den keine Ansicht anzeigen kann.
    """
    await einstellungen(welt, ipad_typ="Apple iPad 10. Gen", pencil="ohne Apple Pencil")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/ipads",
        json={"itnr": "IT900", "snr": "SN900", "typ": "   ", "bildungsgang_id": "bg_meda"},
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["typ"] == "Apple iPad 10. Gen"


async def test_vorgabe_aus_lauter_leerzeichen_ist_keine_vorgabe(welt, client):
    """Auch die Einstellung selbst kann mit der Leertaste "gefüllt" sein.

    Dann trüge ab diesem Moment jedes neu angelegte Gerät " " als Typ - und zwar genau
    dort, wo der leere Typ eigentlich aufgefangen wird. Welche Bezeichnung stattdessen
    einspringt, ist zweitrangig; sie muss nur etwas sein, das eine Ansicht anzeigen kann.
    """
    await einstellungen(welt, ipad_typ="   ", pencil="ohne Apple Pencil")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/ipads",
        json={"itnr": "IT900", "snr": "SN900", "bildungsgang_id": "bg_meda"},
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    typ = antwort.json()["typ"]
    assert typ.strip(), f"für jeden Leser ein leerer Typ: {typ!r}"
    assert (await welt.ipads.find_one({"itnr": "IT900"}))["typ"] == typ


async def test_geleerter_typ_faellt_beim_bearbeiten_auf_die_vorgabe_zurueck(welt, client):
    """Auch das Leeren führt auf die Vorgabe zurück, nicht auf ein leeres Feld.

    Solange ein leerer Typ im Bestand stehen bleiben konnte, beantwortete ihn jede Ansicht
    anders: der Export setzte die Vorgabe ein, die Vertragsvorbereitung meldete "Typ fehlt",
    die Detailansicht zeigte "N/A". Ist das Feld nie leer, stellt sich die Frage nicht mehr.
    """
    await einstellungen(welt, ipad_typ="Apple iPad 10. Gen", pencil="ohne Apple Pencil")
    await geraet(welt, "g1", "bg_meda", itnr="IT100")
    await welt.ipads.update_one({"id": "g1"}, {"$set": {"typ": "Apple iPad 9. Gen, 64 GB"}})
    kopf = await anmelden(client, "admin")

    antwort = await client.put("/api/ipads/g1", json={"typ": ""}, headers=kopf)
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["ipad"]["typ"] == "Apple iPad 10. Gen"

    assert (await welt.ipads.find_one({"id": "g1"}))["typ"] == "Apple iPad 10. Gen"


# --- Empfänger ist Pflicht ---------------------------------------------------------------

async def test_zuweisung_ohne_empfaenger_wird_abgelehnt(welt, client):
    """Ein Gerät geht körperlich an jemanden - ohne diese Angabe bleibt später offen, an wen.

    Der Besitz liegt beim Bildungsgang; die Übergabe ist eine getrennte, aber verpflichtende
    Angabe. Ohne sie wäre genau die Frage unbeantwortbar, die im Schuljahr aufkommt.
    """
    await poolgeraet(welt, "g1")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/assign-to-bildungsgang",
        json={"ipad_ids": ["g1"], "bildungsgang_id": "bg_meda"},
        headers=kopf,
    )
    assert antwort.status_code == 422, antwort.text
    assert (await welt.ipads.find_one({"id": "g1"}))["is_in_pool"] is True, "Gerät darf nicht bewegt worden sein"


async def test_zuweisung_an_unbekannten_empfaenger_wird_abgelehnt(welt, client):
    await poolgeraet(welt, "g1")
    kopf = await anmelden(client, "admin")

    antwort = await client.post(
        "/api/admin/ipads/assign-to-bildungsgang",
        json={"ipad_ids": ["g1"], "bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "gibtsnicht"},
        headers=kopf,
    )
    assert antwort.status_code == 404
    assert (await welt.ipads.find_one({"id": "g1"}))["is_in_pool"] is True


async def test_uebergabe_steht_in_der_geraetehistorie(welt, client):
    """Die Quittung muss später auffindbar sein - sonst nützt sie nichts."""
    await poolgeraet(welt, "g1")
    kopf = await anmelden(client, "admin")

    await client.post(
        "/api/admin/ipads/assign-to-bildungsgang",
        json={"ipad_ids": ["g1"], "bildungsgang_id": "bg_meda", "uebergeben_an_user_id": "u_bakenecker"},
        headers=kopf,
    )
    historie = (await client.get("/api/ipads/g1/history", headers=kopf)).json()["pool_history"]
    letzter = historie[-1]
    assert letzter["uebergeben_an"] == "bakenecker", historie
    assert letzter["bildungsgang_name"] == "MEDA"
    assert letzter["at"], "Zeitstempel fehlt"
