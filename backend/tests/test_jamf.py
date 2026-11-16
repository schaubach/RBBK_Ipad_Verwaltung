"""Jamf-Anbindung (core/jamf.py, routes/jamf.py) gegen ein nachgebautes Jamf.

Kein Test spricht das echte Jamf an: ``core.jamf._transport`` wird auf einen
httpx.MockTransport gesetzt, der die wenigen Endpunkte nachbildet, die die App nutzt.
Geprüft wird vor allem, was schiefgehen darf, ohne dass es teuer wird:

- Der Login wird nur gespeichert, wenn Jamf ihn annimmt, und das Passwort steht nirgends lesbar.
- Ein später abgelehnter Login wird gesperrt statt immer wieder probiert (Jamf sperrt sonst
  das Konto der Person).
- Kein Jamf-Fehler kommt als 401 an - das hieße für das Frontend "App-Sitzung abgelaufen".
- Status gibt es nur für iPads, die man in der App sehen darf.
- Die App liest nur: An Jamf geht außer der Anmeldung nie etwas Schreibendes.
"""

import json

import httpx
import pytest
import pytest_asyncio

from tests.conftest import anmelden

JAMF = "https://schule.jamfcloud.com"


class FalschesJamf:
    """Merkt sich jede Anfrage; Verhalten über Attribute steuerbar."""

    def __init__(self):
        self.passwort = "jamf-geheim"
        self.anfragen = []
        self.geraete = {
            "DMPDF2X3NR73": {
                "mobileDeviceId": "9916",
                "general": {
                    "displayName": "RBB-iPad01",
                    "osVersion": "18.1",
                    "managementId": "b68d71f7-37c3-4b58-94f5-4cc54670a27d",
                    "managed": True,
                    "supervised": True,
                },
                "hardware": {"batteryLevel": 80},
                "security": {"activationLockEnabled": True, "lostModeEnabled": False},
            }
        }

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.anfragen.append(request)
        pfad = request.url.path
        if pfad == "/api/v1/auth/token":
            erwartet = httpx.BasicAuth("sschaubach", self.passwort)._auth_header
            if request.headers.get("Authorization") != erwartet:
                return httpx.Response(401, json={"httpStatus": 401, "errors": []})
            return httpx.Response(200, json={"token": "tok", "expires": "2999-01-01T00:00:00.000Z"})
        if request.headers.get("Authorization") != "Bearer tok":
            return httpx.Response(401)
        if pfad == "/api/v2/mobile-devices/detail":
            filter_ = request.url.params.get("filter")
            snr = filter_.split('"')[1]
            treffer = [self.geraete[snr]] if snr in self.geraete else []
            return httpx.Response(200, json={"totalCount": len(treffer), "results": treffer})
        return httpx.Response(404)


@pytest_asyncio.fixture
async def jamf(welt):
    import core.jamf

    falsch = FalschesJamf()
    core.jamf._transport = httpx.MockTransport(falsch)
    core.jamf._tokens.clear()
    await welt.global_settings.insert_one({"type": "jamf", "url": JAMF})
    await welt.ipads.insert_many(
        [
            {"id": "ip_meda", "itnr": "100", "snr": "DMPDF2X3NR73", "bildungsgang_id": "bg_meda", "status": "ok"},
            {"id": "ip_gym", "itnr": "200", "snr": "DMPDF2X3NR73", "bildungsgang_id": "bg_gym", "status": "ok"},
        ]
    )
    yield falsch
    core.jamf._transport = None
    core.jamf._tokens.clear()


async def _verknuepfen(client, kopf, passwort="jamf-geheim"):
    return await client.put("/api/jamf/zugang", headers=kopf, json={"benutzername": "sschaubach", "passwort": passwort})


async def test_login_wird_nur_gespeichert_wenn_jamf_ihn_annimmt(client, jamf, welt):
    kopf = await anmelden(client, "schaubach")

    falsch = await _verknuepfen(client, kopf, "falsch")
    assert falsch.status_code == 400, falsch.text
    assert await welt.jamf_zugaenge.count_documents({}) == 0

    richtig = await _verknuepfen(client, kopf)
    assert richtig.status_code == 200, richtig.text
    daten = richtig.json()
    assert daten["verknuepft"] is True

    gespeichert = await welt.jamf_zugaenge.find_one({"user_id": "u_schaubach"})
    assert "jamf-geheim" not in json.dumps(gespeichert, default=str)
    assert "jamf-geheim" not in richtig.text


async def test_ohne_login_sieht_man_nichts_von_jamf(client, jamf):
    kopf = await anmelden(client, "schaubach")
    stand = (await client.get("/api/jamf/zugang", headers=kopf)).json()
    assert stand == {**stand, "eingerichtet": True, "verknuepft": False}

    antwort = await client.get("/api/ipads/ip_meda/jamf", headers=kopf)
    assert antwort.status_code == 409


async def test_status_eines_eigenen_ipads(client, jamf):
    kopf = await anmelden(client, "schaubach")
    await _verknuepfen(client, kopf)

    antwort = await client.get("/api/ipads/ip_meda/jamf", headers=kopf)
    assert antwort.status_code == 200, antwort.text
    geraet = antwort.json()["geraet"]
    assert geraet["jamf_id"] == "9916"
    assert geraet["aktivierungssperre"] is True
    assert geraet["jamf_link"] == f"{JAMF}/mobileDevices.html?id=9916&o=r"


async def test_fremde_ipads_bleiben_tabu(client, jamf, welt):
    """Jamf würde das Gerät liefern - die App lässt es trotzdem nicht durch."""
    kopf = await anmelden(client, "schaubach")
    await _verknuepfen(client, kopf)

    assert (await client.get("/api/ipads/ip_gym/jamf", headers=kopf)).status_code == 404
    assert not any(a.url.path == "/api/v2/mobile-devices/detail" for a in jamf.anfragen)


async def test_die_app_schickt_jamf_nur_lesende_anfragen(client, jamf):
    """Befehle sind bewusst ausgebaut - es gibt keinen Weg, ein iPad über die App zu verändern."""
    kopf = await anmelden(client, "schaubach")
    await _verknuepfen(client, kopf)
    await client.get("/api/ipads/ip_meda/jamf", headers=kopf)

    befehl = await client.post("/api/ipads/ip_meda/jamf/befehl", headers=kopf, json={"befehl": "sperren"})
    assert befehl.status_code in (404, 405)
    schreibend = [a for a in jamf.anfragen if a.method != "GET" and a.url.path != "/api/v1/auth/token"]
    assert schreibend == []


async def test_spaeter_abgelehnter_login_wird_gesperrt_statt_wiederholt(client, jamf):
    """Passwort in Jamf geändert: einmal versuchen, dann nicht mehr - Jamf sperrt sonst das Konto."""
    import core.jamf

    kopf = await anmelden(client, "schaubach")
    await _verknuepfen(client, kopf)
    core.jamf._tokens.clear()
    jamf.passwort = "neu"

    for _ in range(3):
        antwort = await client.get("/api/ipads/ip_meda/jamf", headers=kopf)
        assert antwort.status_code == 409, antwort.text
    anmeldungen = [a for a in jamf.anfragen if a.url.path == "/api/v1/auth/token"]
    assert len(anmeldungen) == 2  # einmal beim Verknüpfen, einmal danach - dann nie wieder
    assert (await client.get("/api/jamf/zugang", headers=kopf)).json()["gesperrt"] is True


async def test_unbekannte_seriennummer(client, jamf, welt):
    kopf = await anmelden(client, "schaubach")
    await _verknuepfen(client, kopf)
    await welt.ipads.update_one({"id": "ip_meda"}, {"$set": {"snr": "XYZ12345"}})

    antwort = await client.get("/api/ipads/ip_meda/jamf", headers=kopf)
    assert antwort.status_code == 200
    assert antwort.json()["geraet"] is None


@pytest.mark.parametrize("snr", ['AB"C123', "", "S DMP DF2"])
async def test_seriennummer_kommt_nicht_ungeprueft_in_den_filter(client, jamf, welt, snr):
    kopf = await anmelden(client, "schaubach")
    await _verknuepfen(client, kopf)
    await welt.ipads.update_one({"id": "ip_meda"}, {"$set": {"snr": snr}})

    antwort = await client.get("/api/ipads/ip_meda/jamf", headers=kopf)
    assert antwort.status_code == 400
    assert not any(a.url.path == "/api/v2/mobile-devices/detail" for a in jamf.anfragen)


async def test_nur_admins_stellen_die_adresse_ein(client, jamf):
    kopf = await anmelden(client, "schaubach")
    assert (await client.put("/api/jamf/einstellungen", headers=kopf, json={"url": JAMF})).status_code == 403

    admin = await anmelden(client, "admin")
    falsch = await client.put("/api/jamf/einstellungen", headers=admin, json={"url": "http://unsicher.example"})
    assert falsch.status_code == 400
    ok = await client.put("/api/jamf/einstellungen", headers=admin, json={"url": "https://dosys.jamfcloud.com/"})
    assert ok.json() == {"url": "https://dosys.jamfcloud.com"}


async def test_entfernte_person_verliert_ihren_jamf_login(client, jamf, welt):
    kopf = await anmelden(client, "schaubach")
    await _verknuepfen(client, kopf)

    admin = await anmelden(client, "admin")
    antwort = await client.delete("/api/admin/users/u_schaubach", headers=admin)
    assert antwort.status_code == 200, antwort.text
    assert await welt.jamf_zugaenge.count_documents({}) == 0
