"""Anbindung an Jamf Pro: Anmeldung, Geräteabfrage und MDM-Befehle.

Jede Person hinterlegt ihren EIGENEN Jamf-Login. Jamf prüft also selbst, was sie darf und
welche Geräte sie sieht (Site-Beschränkung) - die App fügt nur ihre eigene Grenze hinzu:
Befehle gehen ausschließlich an iPads, auf die die Person auch in der App Zugriff hat.

Das Passwort liegt verpackt (core.crypto.wrap_secret) in ``jamf_zugaenge``, getrennt von
``users``. Damit landet es nicht in den Backups: Nach einer Wiederherstellung trägt jede
Person ihren Login neu ein, statt dass Zugangsdaten zu einem Fremdsystem in Sicherungsdateien
herumliegen.

Zwei Regeln, an denen hier alles hängt:

- Nie 401 an die Oberfläche durchreichen. Der Axios-Abfänger im Frontend versteht 401 als
  "App-Sitzung abgelaufen" und meldet die Person ab. Ein abgelehnter Jamf-Login ist etwas
  anderes - deshalb 409 (Login neu eintragen), 403 (Recht fehlt) oder 502 (Jamf gestört).
- Lehnt Jamf den gespeicherten Login ab, wird er gesperrt und nicht wieder versucht. Sonst
  probierte die App bei jedem Öffnen eines iPads erneut ein falsches Passwort, bis Jamf das
  Konto der Person sperrt.
"""

import logging
import re
from datetime import UTC, datetime, timedelta
from typing import Optional
from urllib.parse import urlparse

import httpx

from core.config import db
from core.crypto import unwrap_secret, wrap_secret

logger = logging.getLogger(__name__)

TIMEOUT_SEKUNDEN = 15.0
# Für die Tests: ein httpx.MockTransport statt echter Netzwerkzugriffe.
_transport: Optional[httpx.AsyncBaseTransport] = None

# Zwischengespeicherte Jamf-Tokens je App-Benutzer: user_id -> (jamf_url, token, gültig_bis).
# Nur im Arbeitsspeicher; nach einem Neustart holt die App sich einfach ein neues.
_tokens: dict = {}


# Die Befehle, die die App anbietet. "recht" ist der Name des Jamf-Rechts, so wie
# /api/v1/auth ihn liefert - fehlt es, zeigt die Oberfläche den Knopf nicht an.
BEFEHLE = {
    "sperren": {"titel": "Sperren", "recht": "Send Mobile Device Remote Lock Command", "typ": "DEVICE_LOCK"},
    "verloren_an": {
        "titel": "Verloren-Modus einschalten",
        "recht": "Send Mobile Device Lost Mode Command",
        "typ": "ENABLE_LOST_MODE",
    },
    "verloren_aus": {
        "titel": "Verloren-Modus ausschalten",
        "recht": "Send Mobile Device Lost Mode Command",
        "typ": "DISABLE_LOST_MODE",
    },
    "verloren_ton": {
        "titel": "Ton abspielen (Verloren-Modus)",
        "recht": "Send Mobile Device Lost Mode Command",
        "typ": "PLAY_LOST_MODE_SOUND",
    },
    "code_entfernen": {
        "titel": "Code-Sperre entfernen",
        "recht": "Send Mobile Device Remove Passcode Command",
        "typ": "CLEAR_PASSCODE",
    },
    "neustart": {"titel": "Neustart", "recht": "Send Mobile Device Restart Device Command", "typ": "RESTART_DEVICE"},
    # Die Jamf Pro API kennt dafür keinen MDM-Befehl, nur die Classic API.
    "inventar": {"titel": "Inventar aktualisieren", "recht": "Send Inventory Requests to Mobile Devices", "typ": None},
}


class JamfFehler(Exception):
    """Ein Fehler, dessen Text so an die Oberfläche gehen darf. status ist nie 401."""

    def __init__(self, meldung: str, status: int = 502):
        super().__init__(meldung)
        self.meldung = meldung
        self.status = status


class _AnmeldungAbgelehnt(Exception):
    pass


def normalisiere_url(url: str) -> str:
    """https://name.jamfcloud.com - ohne Pfad und Schrägstrich am Ende. Sonst ValueError."""
    url = (url or "").strip().rstrip("/")
    teile = urlparse(url)
    if teile.scheme != "https" or not teile.hostname:
        raise ValueError("Bitte die Jamf-Adresse vollständig mit https:// angeben, z. B. https://schule.jamfcloud.com")
    if teile.path or teile.query or teile.fragment or teile.username or teile.password:
        raise ValueError(
            "Bitte nur die Adresse des Jamf-Servers angeben, ohne Pfad (z. B. https://schule.jamfcloud.com)"
        )
    return f"https://{teile.netloc}"


async def jamf_url() -> Optional[str]:
    eintrag = await db.global_settings.find_one({"type": "jamf"})
    return (eintrag or {}).get("url") or None


def _client(basis: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=basis, timeout=TIMEOUT_SEKUNDEN, transport=_transport, headers={"Accept": "application/json"}
    )


def _fehlertext(antwort: httpx.Response) -> str:
    """Die Beschreibung aus Jamfs Fehlerantwort, falls es eine gibt."""
    try:
        daten = antwort.json()
    except ValueError:
        return ""
    if isinstance(daten, dict):
        texte = [
            f.get("description") for f in daten.get("errors") or [] if isinstance(f, dict) and f.get("description")
        ]
        return "; ".join(texte)
    return ""


def _ablaufzeit(text) -> datetime:
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(UTC) + timedelta(minutes=15)


async def _token_holen(basis: str, benutzer: str, passwort: str) -> tuple:
    try:
        async with _client(basis) as c:
            antwort = await c.post("/api/v1/auth/token", auth=(benutzer, passwort))
    except httpx.HTTPError as e:
        logger.warning("Jamf nicht erreichbar: %s", e)
        raise JamfFehler("Jamf ist gerade nicht erreichbar. Bitte später erneut versuchen.", 502)
    if antwort.status_code in (401, 403):
        raise _AnmeldungAbgelehnt(_fehlertext(antwort))
    if antwort.status_code != 200:
        raise JamfFehler(f"Jamf hat die Anmeldung mit Status {antwort.status_code} beantwortet.", 502)
    daten = antwort.json()
    return daten["token"], _ablaufzeit(daten.get("expires"))


def _rechte_aus_auth(daten: dict) -> set:
    """Alle Rechte der Person, gleich wo Jamf sie ablegt.

    Bei Site-Konten stehen sie je nach Version unter account.privileges,
    account.privilegesBySite oder accountGroups[].privileges - für die Frage "welche Knöpfe
    zeigen wir an" ist die Vereinigung richtig. Jamf prüft beim Befehl ohnehin selbst.
    """
    konto = daten.get("account") or {}
    rechte = set(konto.get("privileges") or [])
    for liste in (konto.get("privilegesBySite") or {}).values():
        rechte.update(liste or [])
    for gruppe in daten.get("accountGroups") or []:
        rechte.update(gruppe.get("privileges") or [])
    return rechte


def erlaubte_befehle(rechte: set) -> list:
    return [name for name, b in BEFEHLE.items() if b["recht"] in rechte]


async def zugang_pruefen_und_speichern(user: dict, benutzer: str, passwort: str) -> dict:
    """Login bei Jamf ausprobieren, Rechte lesen und erst dann speichern."""
    basis = await jamf_url()
    if not basis:
        raise JamfFehler("Die Jamf-Anbindung ist noch nicht eingerichtet (Adresse fehlt).", 409)
    try:
        token, gueltig_bis = await _token_holen(basis, benutzer, passwort)
    except _AnmeldungAbgelehnt:
        raise JamfFehler("Jamf hat die Anmeldung abgelehnt. Bitte Benutzername und Passwort prüfen.", 400)

    try:
        async with _client(basis) as c:
            antwort = await c.get("/api/v1/auth", headers={"Authorization": f"Bearer {token}"})
    except httpx.HTTPError:
        raise JamfFehler("Jamf ist gerade nicht erreichbar. Bitte später erneut versuchen.", 502)
    rechte = _rechte_aus_auth(antwort.json()) if antwort.status_code == 200 else set()

    jetzt = datetime.now(UTC).isoformat()
    zugang = {
        "user_id": user["id"],
        "benutzer": benutzer,
        "passwort": wrap_secret(passwort),
        "jamf_url": basis,
        "befehle": erlaubte_befehle(rechte),
        "gesperrt": False,
        "gesperrt_grund": None,
        "aktualisiert_am": jetzt,
    }
    await db.jamf_zugaenge.update_one({"user_id": user["id"]}, {"$set": zugang}, upsert=True)
    _tokens[user["id"]] = (basis, token, gueltig_bis)
    return zugang


async def zugang_entfernen(user_id: str) -> None:
    _tokens.pop(user_id, None)
    await db.jamf_zugaenge.delete_one({"user_id": user_id})


async def _token_fuer(user: dict, frisch: bool = False) -> tuple:
    basis = await jamf_url()
    if not basis:
        raise JamfFehler("Die Jamf-Anbindung ist noch nicht eingerichtet (Adresse fehlt).", 409)

    if not frisch:
        zwischen = _tokens.get(user["id"])
        if zwischen and zwischen[0] == basis and zwischen[2] - timedelta(seconds=60) > datetime.now(UTC):
            return basis, zwischen[1]

    zugang = await db.jamf_zugaenge.find_one({"user_id": user["id"]})
    if not zugang:
        raise JamfFehler("Kein Jamf-Login hinterlegt. Bitte unter Einstellungen eintragen.", 409)
    if zugang.get("gesperrt"):
        raise JamfFehler("Jamf hat den hinterlegten Login abgelehnt. Bitte unter Einstellungen neu eintragen.", 409)
    passwort = unwrap_secret(zugang.get("passwort"))
    if passwort is None:
        # Typisch nach einem Serverumzug mit neuem SECRET_KEY.
        raise JamfFehler("Der hinterlegte Jamf-Login lässt sich nicht mehr lesen. Bitte neu eintragen.", 409)

    try:
        token, gueltig_bis = await _token_holen(basis, zugang["benutzer"], passwort)
    except _AnmeldungAbgelehnt as e:
        await db.jamf_zugaenge.update_one(
            {"user_id": user["id"]},
            {"$set": {"gesperrt": True, "gesperrt_grund": str(e) or "Anmeldung abgelehnt"}},
        )
        _tokens.pop(user["id"], None)
        raise JamfFehler(
            "Jamf hat den hinterlegten Login abgelehnt (Passwort geändert?). Bitte unter Einstellungen neu eintragen.",
            409,
        )
    _tokens[user["id"]] = (basis, token, gueltig_bis)
    return basis, token


async def _anfrage(user: dict, methode: str, pfad: str, **kwargs) -> httpx.Response:
    """Anfrage mit dem Token der Person; ein abgelaufenes Token wird einmal erneuert."""
    for versuch in (0, 1):
        basis, token = await _token_fuer(user, frisch=versuch == 1)
        try:
            async with _client(basis) as c:
                antwort = await c.request(methode, pfad, headers={"Authorization": f"Bearer {token}"}, **kwargs)
        except httpx.HTTPError as e:
            logger.warning("Jamf-Anfrage %s %s gescheitert: %s", methode, pfad, e)
            raise JamfFehler("Jamf ist gerade nicht erreichbar. Bitte später erneut versuchen.", 502)
        if antwort.status_code != 401:
            return antwort
        _tokens.pop(user["id"], None)
    raise JamfFehler("Jamf hat die Anfrage nicht angenommen (Anmeldung abgelaufen).", 502)


def _pruefe_antwort(antwort: httpx.Response, erwartet=(200, 201, 202, 204)) -> None:
    if antwort.status_code in erwartet:
        return
    text = _fehlertext(antwort)
    if antwort.status_code == 403:
        raise JamfFehler(
            "Jamf hat das abgelehnt: Ihrem Jamf-Konto fehlt das Recht dafür." + (f" ({text})" if text else ""), 403
        )
    if antwort.status_code == 404:
        raise JamfFehler("Jamf kennt dieses Gerät nicht (mehr)." + (f" ({text})" if text else ""), 404)
    raise JamfFehler(f"Jamf hat mit Status {antwort.status_code} geantwortet." + (f" {text}" if text else ""), 502)


_SERIENNUMMER = re.compile(r"^[A-Z0-9]{5,20}$")


def _seriennummer(snr: str) -> str:
    """Nur Buchstaben und Ziffern - die Nummer landet in einem RSQL-Filter."""
    wert = (snr or "").strip().upper()
    if not _SERIENNUMMER.match(wert):
        raise JamfFehler("Dieses iPad hat keine gültige Seriennummer, darüber findet es die App in Jamf.", 400)
    return wert


async def geraet_suchen(user: dict, snr: str) -> Optional[dict]:
    """Das Gerät mit dieser Seriennummer, aufbereitet für die Oberfläche - oder None."""
    wert = _seriennummer(snr)
    antwort = await _anfrage(
        user,
        "GET",
        "/api/v2/mobile-devices/detail",
        params=[
            ("section", "GENERAL"),
            ("section", "HARDWARE"),
            ("section", "SECURITY"),
            ("page-size", "1"),
            ("filter", f'serialNumber=="{wert}"'),
        ],
    )
    _pruefe_antwort(antwort, (200,))
    treffer = (antwort.json() or {}).get("results") or []
    if not treffer:
        return None
    d = treffer[0]
    allgemein = d.get("general") or {}
    hardware = d.get("hardware") or {}
    sicherheit = d.get("security") or {}
    standort = sicherheit.get("lostModeLocation") or {}
    jamf_id = str(d.get("mobileDeviceId") or d.get("id") or "")
    basis = await jamf_url()
    return {
        "jamf_id": jamf_id,
        "management_id": allgemein.get("managementId"),
        "name": allgemein.get("displayName"),
        "os_version": allgemein.get("osVersion"),
        "letzte_inventur": allgemein.get("lastInventoryUpdateDate"),
        "verwaltet": allgemein.get("managed"),
        "betreut": allgemein.get("supervised"),
        "akku": hardware.get("batteryLevel"),
        "kapazitaet_mb": hardware.get("capacityMb"),
        "frei_mb": hardware.get("availableSpaceMb"),
        "aktivierungssperre": sicherheit.get("activationLockEnabled"),
        "code_gesetzt": sicherheit.get("passcodePresent"),
        "verloren_modus": sicherheit.get("lostModeEnabled"),
        "verloren_nachricht": sicherheit.get("lostModeMessage"),
        "standort": (
            {
                "breite": standort.get("latitude"),
                "laenge": standort.get("longitude"),
                "stand": standort.get("lastLocationUpdate"),
            }
            if standort.get("latitude") is not None and standort.get("longitude") is not None
            else None
        ),
        "jamf_link": f"{basis}/mobileDevices.html?id={jamf_id}&o=r" if basis and jamf_id else None,
    }


async def befehl_senden(user: dict, geraet: dict, befehl: str, nachricht: str = "", telefon: str = "") -> None:
    """Einen der BEFEHLE an das Gerät schicken. Wirft JamfFehler, wenn Jamf ablehnt."""
    eintrag = BEFEHLE[befehl]

    if befehl == "inventar":
        antwort = await _anfrage(
            user, "POST", f"/JSSResource/mobiledevicecommands/command/UpdateInventory/id/{geraet['jamf_id']}"
        )
        _pruefe_antwort(antwort)
        return

    if not geraet.get("management_id"):
        raise JamfFehler("Jamf liefert für dieses Gerät keine Management-ID; es ist vermutlich nicht verwaltet.", 409)

    daten: dict = {"commandType": eintrag["typ"]}
    if befehl == "sperren":
        if nachricht:
            daten["message"] = nachricht
        if telefon:
            daten["phoneNumber"] = telefon
    elif befehl == "verloren_an":
        if not nachricht and not telefon:
            raise JamfFehler("Für den Verloren-Modus bitte eine Nachricht oder Telefonnummer angeben.", 400)
        if nachricht:
            daten["lostModeMessage"] = nachricht
        if telefon:
            daten["lostModePhone"] = telefon
    elif befehl == "code_entfernen":
        # Ohne den Entsperr-Token des Geräts nimmt Jamf den Befehl nicht an.
        detail = await _anfrage(user, "GET", f"/api/v2/mobile-devices/{geraet['jamf_id']}/detail")
        _pruefe_antwort(detail, (200,))
        token = ((detail.json() or {}).get("ios") or {}).get("unlockToken")
        if not token:
            raise JamfFehler(
                "Jamf hat für dieses iPad keinen Entsperr-Token gespeichert; die Code-Sperre lässt sich so nicht entfernen.",
                409,
            )
        daten["unlockToken"] = token

    antwort = await _anfrage(
        user,
        "POST",
        "/api/v2/mdm/commands",
        json={"clientData": [{"managementId": geraet["management_id"]}], "commandData": daten},
    )
    _pruefe_antwort(antwort)
