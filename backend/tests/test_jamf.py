"""Jamf-Anbindung (core/jamf.py, routes/jamf.py) gegen ein nachgebautes Jamf.

Kein Test spricht das echte Jamf an: ``core.jamf._transport`` wird auf einen
httpx.MockTransport gesetzt, der die wenigen Endpunkte nachbildet, die die App nutzt.
Geprüft wird vor allem, was schiefgehen darf, ohne dass es teuer wird:

- Der Login wird nur gespeichert, wenn Jamf ihn annimmt, und das Passwort steht nirgends lesbar.
- Ein später abgelehnter Login wird gesperrt statt immer wieder probiert (Jamf sperrt sonst
  das Konto der Person).
- Kein Jamf-Fehler kommt als 401 an - das hieße für das Frontend "App-Sitzung abgelaufen".
- Befehle gibt es nur für iPads, die man in der App sehen darf.
"""

import json

import httpx
import pytest
import pytest_asyncio

from tests.conftest import anmelden

JAMF = "https://schule.jamfcloud.com"
RECHTE = [
    "Read Mobile Devices",
    "Send Mobile Device Remote Lock Command",
    "Send Mobile Device Lost Mode Command",
    "Send Inventory Requests to Mobile Devices",
]


class FalschesJamf:
    """Merkt sich jede Anfrage; Verhalten über Attribute steuerbar."""

    def __init__(self):
        self.passwort = "jamf-geheim"
        self.anfragen = []
        self.befehl_status = 201
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
        if pfad == "/api/v1/auth":
            return httpx.Response(200, json={"account": {"privilegesBySite": {"1": RECHTE}}, "accountGroups": []})
        if pfad == "/api/v2/mobile-devices/detail":
            filter_ = request.url.params.get("filter")
            snr = filter_.split('"')[1]
            treffer = [self.geraete[snr]] if snr in self.geraete else []
            return httpx.Response(200, json={"totalCount": len(treffer), "results": treffer})
        if pfad == "/api/v2/mdm/commands":
            return httpx.Response(self.befehl_status, json=[{"id": "1", "href": "x"}])
        if pfad.startswith("/JSSResource/mobiledevicecommands/command/UpdateInventory/id/"):
            return httpx.Response(201)
        return httpx.Response(404)

    def befehle(self):
        return [json.loads(a.content) for a in self.anfragen if a.url.path == "/api/v2/mdm/commands"]


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
    assert {b["name"] for b in daten["befehle"]} == {
        "sperren",
        "verloren_an",
        "verloren_aus",
        "verloren_ton",
        "inventar",
    }

    gespeichert = await welt.jamf_zugaenge.find_one({"user_id": "u_schaubach"})
    assert "jamf-geheim" not in json.dumps(gespeichert, default=str)
    assert "jamf-geheim" not in richtig.text


async def test_ohne_login_sieht_man_nichts_von_jamf(client, jamf):
    kopf = await anmelden(client, "schaubach")
    stand = (await client.get("/api/jamf/zugang", headers=kopf)).json()
    assert stand == {**stand, "eingerichtet": True, "verknuepft": False, "befehle": []}

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
    befehl = await client.post("/api/ipads/ip_gym/jamf/befehl", headers=kopf, json={"befehl": "sperren"})
    assert befehl.status_code == 404
    assert jamf.befehle() == []
    assert await welt.jamf_protokoll.count_documents({}) == 0


async def test_sperren_geht_an_jamf_und_wird_protokolliert(client, jamf, welt):
    kopf = await anmelden(client, "schaubach")
    await _verknuepfen(client, kopf)

    antwort = await client.post(
        "/api/ipads/ip_meda/jamf/befehl",
        headers=kopf,
        json={"befehl": "sperren", "nachricht": "Bitte im Sekretariat abgeben"},
    )
    assert antwort.status_code == 200, antwort.text
    assert jamf.befehle() == [
        {
            "clientData": [{"managementId": "b68d71f7-37c3-4b58-94f5-4cc54670a27d"}],
            "commandData": {"commandType": "DEVICE_LOCK", "message": "Bitte im Sekretariat abgeben"},
        }
    ]
    eintrag = await welt.jamf_protokoll.find_one({"ipad_id": "ip_meda"})
    assert eintrag["erfolg"] is True and eintrag["username"] == "schaubach"


async def test_befehl_ohne_jamf_recht_wird_nicht_gesendet(client, jamf):
    kopf = await anmelden(client, "schaubach")
    await _verknuepfen(client, kopf)

    antwort = await client.post("/api/ipads/ip_meda/jamf/befehl", headers=kopf, json={"befehl": "code_entfernen"})
    assert antwort.status_code == 403
    assert jamf.befehle() == []


async def test_verloren_modus_braucht_nachricht_oder_telefon(client, jamf):
    kopf = await anmelden(client, "schaubach")
    await _verknuepfen(client, kopf)

    leer = await client.post("/api/ipads/ip_meda/jamf/befehl", headers=kopf, json={"befehl": "verloren_an"})
    assert leer.status_code == 400
    mit = await client.post(
        "/api/ipads/ip_meda/jamf/befehl", headers=kopf, json={"befehl": "verloren_an", "telefon": "0231 123"}
    )
    assert mit.status_code == 200, mit.text
    assert jamf.befehle()[-1]["commandData"] == {"commandType": "ENABLE_LOST_MODE", "lostModePhone": "0231 123"}


async def test_inventar_laeuft_ueber_die_classic_api(client, jamf):
    kopf = await anmelden(client, "schaubach")
    await _verknuepfen(client, kopf)

    antwort = await client.post("/api/ipads/ip_meda/jamf/befehl", headers=kopf, json={"befehl": "inventar"})
    assert antwort.status_code == 200, antwort.text
    assert any(a.url.path.endswith("/UpdateInventory/id/9916") for a in jamf.anfragen)


async def test_abgelehnter_befehl_wird_protokolliert_und_ist_kein_401(client, jamf, welt):
    kopf = await anmelden(client, "schaubach")
    await _verknuepfen(client, kopf)
    jamf.befehl_status = 403

    antwort = await client.post("/api/ipads/ip_meda/jamf/befehl", headers=kopf, json={"befehl": "sperren"})
    assert antwort.status_code == 403
    eintrag = await welt.jamf_protokoll.find_one({"ipad_id": "ip_meda"})
    assert eintrag["erfolg"] is False and eintrag["fehler"]


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
