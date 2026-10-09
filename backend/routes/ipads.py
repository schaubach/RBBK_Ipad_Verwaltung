"""iPad CRUD, pool and history routes (/api/ipads/*, /api/admin/ipads/*)

Auto-extracted from monolithic server.py during refactor (Session 12).
"""

import io
from collections import Counter
from datetime import UTC, datetime
from typing import List, Optional

import pandas as pd
from core.config import (
    db,
    limiter,
)
from core.mongo import parse_from_mongo, prepare_for_mongo
from core.router import api_router
from core.security import (
    get_current_user,
    get_ipad_filter,
    mit_ansicht,
    get_user_filter,
    resolve_bildungsgang,
    require_admin_user,
)
from core.validators import read_excel_upload, safe_str, validate_uploaded_file
from fastapi import Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from models.assignment import (
    Assignment,
)
from models.ipad import iPad
from pydantic import BaseModel
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from starlette.requests import Request

# iPad management endpoints


async def _claim_pool_ipad_for_bildungsgang(
    ipad_id: str,
    bildungsgang_id: str,
    action: str,
    by_user_id: str,
    uebergeben_an: Optional[dict] = None,
    *,
    nachtrag: Optional[dict] = None,
) -> Optional[dict]:
    """Atomically move an iPad out of the pool into new_owner_id's inventory.

    Only succeeds if the iPad is still in the pool (guards against a double-claim
    race). Returns the pre-update document on success, or None if it was no longer
    available. `action` unterscheidet Selbstabholung ("claimed") von einer durch einen
    Admin veranlassten Zuweisung ("assigned_by_admin").

    user_id bleibt unberuehrt: es sagt, wer das Geraet angelegt hat, nicht wem es gehoert.
    Wer die Uebernahme ausgeloest hat, steht in der pool_history.

    ``nachtrag`` sind Stammdaten aus einer Lieferliste. Sie gehoeren in dasselbe $set wie die
    Uebernahme: ein zweites update_one liefe ausserhalb der Wettlaufsicherung und schriebe
    auch dann, wenn ein paralleler Lauf das Geraet eine Sekunde frueher geholt hat.
    """
    now_iso = datetime.now(UTC).isoformat()
    return await db.ipads.find_one_and_update(
        {"id": ipad_id, "is_in_pool": True},
        {
            # Der Nachtrag steht vorn: die Felder der Uebernahme darf er nicht verdraengen.
            "$set": {
                **(nachtrag or {}),
                "is_in_pool": False,
                "bildungsgang_id": bildungsgang_id,
                "updated_at": now_iso,
            },
            "$push": {
                "pool_history": {
                    "action": action,
                    "by": by_user_id,
                    "bildungsgang_id": bildungsgang_id,
                    # Quittung der koerperlichen Uebergabe, nicht Besitz - siehe batch_assign_import.
                    "uebergeben_an": uebergeben_an,
                    "at": now_iso,
                }
            },
        },
    )


async def _geraet_mit_itnr(
    itnr: str, bildungsgang_id: Optional[str], is_in_pool: bool, ausser_id: Optional[str] = None
) -> Optional[dict]:
    """Das Geraet, das diese ITNr schon belegt - oder None, wenn sie frei ist.

    Eine ITNr bezeichnet ein Stueck Hardware und ist deshalb SCHULWEIT eindeutig - unabhaengig
    von Bildungsgang und Pool. Die Alternative (ein eigener Nummernkreis je Bildungsgang) waere
    denkbar, ist hier aber ausdruecklich nicht gewollt: dieselbe Nummer in zwei Bildungsgaengen
    bezeichnete zwei verschiedene Geraete, und jede Suche ueber die ITNr - Vertragsabgleich,
    Inventur, Rueckfrage aus dem Sekretariat - haette ab dann zwei Antworten.

    Die Pruefung gilt fuer Anlegen wie Umbenennen. Ein Endzustand, der sich ueber das Anlegen
    erreichen laesst, darf beim Korrigieren eines Tippfehlers nicht verboten sein - und
    umgekehrt; genau dieser Widerspruch bestand hier vorher.

    ``bildungsgang_id`` und ``is_in_pool`` bleiben in der Signatur, weil die Aufrufer sie fuer
    die Fehlermeldung brauchen (``_itnr_belegt_meldung``), nicht fuer die Regel selbst.
    """
    suche = {"itnr": itnr}
    if ausser_id:
        suche["id"] = {"$ne": ausser_id}
    return await db.ipads.find_one(suche)


def _itnr_belegt_meldung(itnr: str, vorhanden: dict, is_in_pool: bool) -> str:
    """Sagt, WO die Nummer schon liegt - sonst sucht der Admin im falschen Bestand."""
    if vorhanden.get("is_in_pool"):
        return f"iPad mit ITNr {itnr} liegt bereits im Pool"
    if is_in_pool:
        return f"iPad mit ITNr {itnr} existiert bereits (im Pool muss die ITNr global eindeutig sein)"
    return f"iPad mit ITNr {itnr} existiert bereits"


async def _vorgabe_ipad_typ() -> str:
    """Die Geraetebezeichnung aus den Admin-Einstellungen.

    Sie wird beim SCHREIBEN eingesetzt, nicht beim Lesen: solange ein leerer typ im Bestand
    stehen bleiben konnte, beantwortete ihn jede Ansicht anders - der Export setzte die
    Vorgabe ein, die Vertragsvorbereitung meldete "Typ fehlt", die Detailansicht zeigte
    "N/A". Ist das Feld nie leer, stellt sich die Frage gar nicht mehr.

    Gekuerzt wird, BEVOR der Wert als Vorgabe gilt - aus demselben Grund wie in _getrimmt:
    eine Einstellung aus lauter Leerzeichen ist wahr, aber keine Geraetebezeichnung. Ohne das
    Kuerzen truege ab dann jedes neue Geraet " " als Typ, und zwar genau dort, wo der leere
    Typ eigentlich aufgefangen werden sollte.
    """
    einstellungen = await db.global_settings.find_one({"type": "app_settings"})
    return _getrimmt(einstellungen.get("ipad_typ") if einstellungen else None) or "Apple iPad"


def _getrimmt(wert) -> str:
    """Ein Textfeld aus dem Eingabeformular - ohne Leerzeichen am Rand.

    Der Excel-Import kuerzt seit jeher (safe_str), das Formular tat es nicht. Im Bestand steht
    deshalb eine ITNr mit fuehrendem Leerzeichen: in der Liste ist sie von jeder anderen Nummer
    nicht zu unterscheiden, aber keine Suche, kein Vertragsabgleich und keine Lieferliste findet
    sie noch - gesucht wird nach der Nummer, gespeichert ist Leerzeichen plus Nummer.

    Gekuerzt wird, BEVOR auf leer geprueft wird. Sonst gilt " " als ausgefuellt: die
    Pflichtpruefung laesst es durch und die Typ-Vorgabe greift nicht, obwohl das Feld fuer
    jeden Leser leer ist.
    """
    return "" if wert is None else str(wert).strip()


@api_router.post("/ipads", response_model=iPad)
async def create_ipad(ipad_data: dict, current_user: dict = Depends(require_admin_user)):
    """Manuell ein neues iPad anlegen (nur Admins). Optional: is_in_pool=true für Pool-Anlage.

    Das Anlegen von Geräten ist Verwaltungsaufgabe: der Gerätebestand wird zentral gepflegt,
    damit ITNr/SNr eindeutig bleiben und niemand versehentlich Karteileichen erzeugt. Normale
    Benutzer erhalten iPads über die Zuweisung durch einen Admin, nicht durch Selbstanlage.
    """
    try:
        # Erst kuerzen, dann pruefen - siehe _getrimmt. Die Reihenfolge ist der ganze Punkt:
        # " " ist damit keine ITNr mehr, und die Dublettenpruefung unten vergleicht Gekuerztes
        # mit Gekuerztem statt an einem Leerzeichen vorbeizusuchen.
        itnr = _getrimmt(ipad_data.get("itnr"))
        snr = _getrimmt(ipad_data.get("snr"))

        # Validate required fields
        if not itnr or not snr:
            raise HTTPException(status_code=400, detail="ITNr und SNr sind erforderlich")

        # Derselbe Katalog und dieselbe Meldung wie in update_ipad. Vorher prueften nur die
        # Bearbeiten-Wege den Status: ein Anlegen mit "kaputt" speicherte "kaputt", und das
        # Geraet liess sich anschliessend nicht mehr bearbeiten, ohne dass jemand den
        # erfundenen Status bemerkt und mitkorrigiert haette. Was das Bearbeiten zurueckweist,
        # darf das Anlegen nicht herstellen koennen.
        # Leer heisst hier wie ueberall "keine Angabe" (siehe _getrimmt) und bleibt bei der
        # Vorbelegung des Datenmodells.
        status = _getrimmt(ipad_data.get("status")) or "ok"
        valid_statuses = ["ok", "defekt", "gestohlen"]
        if status not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"Ungültiger Status. Erlaubt: {valid_statuses}")

        is_in_pool = bool(ipad_data.get("is_in_pool", False))
        # Poolgeraete gehoeren keinem Bildungsgang - sie liegen zentral, bis jemand sie holt.
        bildungsgang_id = None if is_in_pool else await resolve_bildungsgang(
            current_user, ipad_data.get("bildungsgang_id")
        )

        # Die ITNr bezeichnet ein Stueck Hardware und ist schulweit eindeutig - siehe
        # _geraet_mit_itnr; der Index itnr_eindeutig haelt dieselbe Regel in der Datenbank.
        existing = await _geraet_mit_itnr(itnr, bildungsgang_id, is_in_pool)
        if existing:
            raise HTTPException(status_code=400, detail=_itnr_belegt_meldung(itnr, existing, is_in_pool))

        # Create iPad object
        ipad = iPad(
            user_id=current_user["id"],  # angelegt von
            bildungsgang_id=bildungsgang_id,
            itnr=itnr,
            snr=snr,
            karton=_getrimmt(ipad_data.get("karton")),
            pencil=_getrimmt(ipad_data.get("pencil")),
            # Ein leerer Typ bekommt die Vorgabe - siehe _vorgabe_ipad_typ. Gekuerzt heisst:
            # auch ein mit der Leertaste "geleertes" Feld landet hier auf der Vorgabe.
            typ=_getrimmt(ipad_data.get("typ")) or await _vorgabe_ipad_typ(),
            ansch_jahr=_getrimmt(ipad_data.get("ansch_jahr")),
            ausleihe_datum=_getrimmt(ipad_data.get("ausleihe_datum")),
            status=status,
            is_in_pool=is_in_pool,
            pool_history=[{"action": "imported_to_pool", "by": current_user["id"], "at": datetime.now(UTC).isoformat()}]
            if is_in_pool
            else [],
        )

        ipad_dict = prepare_for_mongo(ipad.dict())
        result = await db.ipads.insert_one(ipad_dict)

        # Fetch and return created iPad
        created_ipad = await db.ipads.find_one({"_id": result.inserted_id})
        return iPad(**parse_from_mongo(created_ipad))

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Anlegen: {str(e)}")


@api_router.get("/ipads", response_model=List[iPad])
@limiter.limit("60/minute")
async def get_ipads(
    request: Request,
    bildungsgang_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    # Admin: everything incl. pool. Regular user: own non-pool iPads only.
    ipad_filter = await get_ipad_filter(current_user)
    ipad_filter = mit_ansicht(ipad_filter, bildungsgang_id)
    ipads = await db.ipads.find(ipad_filter).to_list(length=None)
    return [iPad(**parse_from_mongo(ipad)) for ipad in ipads]


@api_router.post("/ipads/{ipad_id}/claim")
@limiter.limit("60/minute")
async def claim_ipad_from_pool(
    ipad_id: str, request: Request, payload: Optional[dict] = None, current_user: dict = Depends(require_admin_user)
):
    """Geraet aus dem Pool in den eigenen Bildungsgang holen (atomar). Nur Admin."""
    bildungsgang_id = await resolve_bildungsgang(current_user, (payload or {}).get("bildungsgang_id"))
    result = await _claim_pool_ipad_for_bildungsgang(ipad_id, bildungsgang_id, "claimed", current_user["id"])

    if not result:
        # Either iPad doesn't exist or was already claimed by someone else
        existing = await db.ipads.find_one({"id": ipad_id})
        if not existing:
            raise HTTPException(status_code=404, detail="iPad nicht gefunden")
        raise HTTPException(status_code=409, detail="iPad ist nicht (mehr) im Pool verfügbar")

    return {"message": f"iPad {result.get('itnr')} erfolgreich übernommen", "itnr": result.get("itnr")}


class BulkClaimRequest(BaseModel):
    ipad_ids: List[str]
    bildungsgang_id: Optional[str] = None  # noetig, wer fuer mehrere zustaendig ist


class AdminAssignToBildungsgangRequest(BaseModel):
    ipad_ids: List[str]
    bildungsgang_id: str
    # Pflicht: ein Geraet geht koerperlich an jemanden. Ohne diese Angabe laesst sich spaeter
    # nicht mehr klaeren, bei wem eine Kiste gelandet ist - und genau das ist die Frage, die
    # im Schuljahr aufkommt. Der Besitz liegt davon unberuehrt beim Bildungsgang.
    uebergeben_an_user_id: str


@api_router.post("/admin/ipads/assign-to-bildungsgang")
@limiter.limit("30/minute")
async def admin_assign_ipads_to_bildungsgang(
    payload: AdminAssignToBildungsgangRequest, request: Request, current_user: dict = Depends(require_admin_user)
):
    """Poolgeraete einem Bildungsgang zuschlagen (nur Admin).

    Hiess frueher assign-to-user. Geraete gehoeren der Einheit, nicht der Person: wer sie
    betreut, wechselt, der Bildungsgang nicht. Eine Uebergabe an eine Person zeigte nach
    deren Ausscheiden auf ein totes Konto.
    """
    if not payload.ipad_ids:
        raise HTTPException(status_code=400, detail="Keine iPads ausgewählt")

    bildungsgang = await db.bildungsgaenge.find_one({"id": payload.bildungsgang_id})
    if not bildungsgang:
        raise HTTPException(status_code=404, detail="Bildungsgang nicht gefunden")

    empfaenger = await db.users.find_one({"id": payload.uebergeben_an_user_id})
    if not empfaenger:
        raise HTTPException(status_code=404, detail="Empfänger nicht gefunden")
    uebergeben_an = {"user_id": empfaenger["id"], "username": empfaenger.get("username")}

    success = []
    failed = []

    for ipad_id in payload.ipad_ids:
        result = await _claim_pool_ipad_for_bildungsgang(
            ipad_id, payload.bildungsgang_id, "assigned_by_admin", current_user["id"], uebergeben_an
        )
        if result:
            success.append(result.get("itnr"))
        else:
            failed.append(ipad_id)

    return {
        "success_count": len(success),
        "failed_count": len(failed),
        "assigned_itnrs": success,
        "bildungsgang_name": bildungsgang["name"],
        "uebergeben_an": uebergeben_an["username"],
    }


# Welche Spalte der Lieferliste in welches Bestandsfeld gehoert, mit dem Beispielwert der
# Vorlage - in der Reihenfolge der Datei, damit der Hinweis "Karton, Typ ergänzt" so klingt,
# wie der Admin die Liste liest.
#
# Beide Seiten holen ihre SPALTENNAMEN aus dieser Tabelle: die Vorlage
# (download_batch_assign_template) ihre Ueberschriften, der Upload (batch_assign_import) die
# Namen, unter denen er die Zellen liest. Eine hier umbenannte Spalte wandert damit in beide
# - frueher stand der Name im Upload noch einmal als Zeichenkette, und eine Umbenennung
# aenderte nur die Ueberschrift der Vorlage, waehrend der Upload die neue Spalte stumm
# ueberging.
# Was die Tabelle NICHT leistet: eine hier ergaenzte Spalte wird zwar gelesen und an einem
# vorhandenen Geraet nachgetragen, aber nicht an ein neu angelegtes geschrieben - die Felder
# des neuen Geraets stehen in batch_assign_import einzeln aufgefuehrt (iPad(...)).
#
# Das Beispiel steht bewusst NEBEN der Spalte und nicht in der Vorlage: wer eine Spalte
# ergaenzt, muss ihren Beispielwert mitschreiben. Stuenden die Beispiele getrennt davon,
# bekaeme die "vollstaendig ausgefuellte" Zeile der Vorlage bei einer neuen Spalte
# stillschweigend eine leere Zelle - und die Vorlage zeigte nicht mehr, was sie verspricht.
#
# Die ITNr fehlt hier, weil sie kein nachzutragendes Feld ist, sondern die Zeile ueberhaupt
# erst einem Geraet zuordnet; ihr Spaltenname steht in _SPALTE_ITNR, ihre Beispielwerte in
# _VORLAGE_BEISPIEL_ITNRN - die braucht naemlich auch der Upload.
_LIEFERLISTE_SPALTEN = [
    # (Bestandsfeld, Spalte der Datei, Beispielwert der Vorlage)
    ("snr", "SNr", "SN-BEISPIEL-12345"),
    ("karton", "Karton", "K-12"),
    ("pencil", "Pencil", "mit Apple Pencil"),
    ("typ", "Typ", "Apple iPad 9. Gen, 64 GB"),
    ("ansch_jahr", "AnschJahr", "2024"),
    ("status", "Status", "ok"),
]

_SPALTE_JE_FELD = {feld: spalte for feld, spalte, _ in _LIEFERLISTE_SPALTEN}

# Die Schluesselspalte steht nicht in der Tabelle, weil sie kein nachzutragendes Feld traegt -
# den Namen brauchen Vorlage und Upload aber genauso gemeinsam wie die uebrigen.
_SPALTE_ITNR = "ITNr"

# Die Spalten der Vorlage: die Schluesselspalte und dahinter die gelesenen Spalten in der
# Reihenfolge der Datei - siehe download_batch_assign_template.
_VORLAGE_SPALTEN = [_SPALTE_ITNR, *_SPALTE_JE_FELD.values()]

_VORLAGE_BEISPIEL_JE_SPALTE = {spalte: beispiel for _, spalte, beispiel in _LIEFERLISTE_SPALTEN}

# Die ITNrn der beiden Beispielzeilen - erste Zeile vollstaendig, zweite nur mit der ITNr.
# Sie stehen hier und nicht in download_batch_assign_template, weil der Upload sie ebenso
# braucht wie die Vorlage: er erkennt an ihnen die unveraendert hochgeladene Vorlage. Zwei
# getrennte Listen liefen auseinander, und ab dem ersten Auseinanderlaufen legte die Vorlage
# wieder Geistergeraete an, ohne dass jemand die Aenderung mit dem Upload in Verbindung
# braechte.
_VORLAGE_BEISPIEL_ITNRN = ("BEISPIEL-1", "BEISPIEL-2")

# Verglichen wird ohne Ruecksicht auf die Schreibweise, wie beim Status: wer die Vorlage durch
# Excel und eine Zwischenablage schickt, reicht auch mal "beispiel-1" ein - und das waere
# genauso wenig eine Lieferung.
_BEISPIEL_ITNRN_VERGLEICH = frozenset(itnr.casefold() for itnr in _VORLAGE_BEISPIEL_ITNRN)


def _zelle(row, spalte: str) -> Optional[str]:
    """Den Wert einer Importspalte lesen - None, wenn die Zelle leer ist.

    "" und None sind hier nicht dasselbe: eine leere Zelle ist keine Angabe und muss das Feld
    so lassen, wie es ohne Datei waere. safe_str allein liefert "" und wuerde ein leeres Feld
    mit einem Leerstring belegen.
    """
    wert = row.get(spalte, "")
    # Excel liefert Zahlenspalten als float. Aus dem Anschaffungsjahr 2024 wuerde sonst
    # "2024.0" - im Bestand und auf dem gedruckten Leihvertrag.
    if isinstance(wert, float) and wert.is_integer():
        wert = int(wert)
    return safe_str(wert) or None


def _nachzutragen(vorhanden: dict, aus_datei: dict) -> dict:
    """Die Felder, die im Bestand leer sind und in der Datei stehen - mehr nicht.

    Der Poolbestand wurde zentral importiert, ohne Karton und ohne genaue Typangabe; die
    Lieferliste ist das erste Dokument, das beides kennt. Sie ist aber auch das erste, das
    einen in der App korrigierten Wert plattmachen koennte - deshalb nur fuellen, nie
    ueberschreiben.
    """
    return {feld: wert for feld, wert in aus_datei.items() if wert is not None and not vorhanden.get(feld)}


def _hinweis(vorhanden: dict, nachtrag: dict, snr: str, status_unbekannt: Optional[str] = None) -> Optional[str]:
    """Meldet, was tatsaechlich passiert ist - und nur das.

    Typ, Pencil und Status sind bei allen Geraeten belegt. Wuerde jedes nicht ueberschriebene
    Feld gemeldet, truege jede Zeile eine Meldung und niemand laese sie mehr.

    ``status_unbekannt`` ist der ungedeutete Wert aus der Status-Spalte, sonst None.
    """
    teile = []
    # Zwei Seriennummern unter einer ITNr heissen vertauschte Hardware oder einen Zahlendreher
    # in der Liste. Beides klaert nur, wer die Geraete vor sich hat.
    if snr and vorhanden.get("snr") and snr != vorhanden["snr"]:
        teile.append(f"SNr weicht ab: im Bestand {vorhanden['snr']}, in der Liste {snr}")
    # "kaputt" in der Lieferliste ist der Grund, warum jemand das Geraet in die Hand nehmen
    # soll. Am Bestand aendert die Spalte bei einem vorhandenen Geraet nichts - gerade deshalb
    # muss die Zeile sagen, dass dort etwas stand, das sie nicht deuten konnte.
    if status_unbekannt:
        teile.append(f"Status '{status_unbekannt}' unbekannt - im Bestand steht '{vorhanden.get('status') or 'ok'}'")
    if nachtrag:
        teile.append(", ".join(_SPALTE_JE_FELD[feld] for feld in nachtrag) + " ergänzt")
    return " - ".join(teile) or None


async def _geraet_anlegen_oder_lesen(itnr: str, neues_geraet: iPad) -> Optional[dict]:
    """Das Geraet zu dieser ITNr lesen und, falls es fehlt, in derselben Operation anlegen.

    Rueckgabe ist das Dokument VOR der Operation: None heisst "gerade neu angelegt", alles
    andere "war schon da" - ein Durchgang statt Suchen-und-dann-Anlegen.

    Im Update steht ausschliesslich $setOnInsert: ein $set daneben traefe wegen des Filters
    {"itnr": itnr} auch Geraete fremder Bildungsgaenge, bevor ueberhaupt geprueft ist, wem das
    Geraet gehoert. Nachgetragen wird in den Zweigen des Aufrufers.

    Dass zwei gleichzeitige Laeufe dieselbe neue ITNr nicht zweimal anlegen, besorgt nicht der
    Upsert, sondern der eindeutige Index itnr_eindeutig (siehe main.py): ohne ihn sehen beide
    "nicht vorhanden" und beide fuegen ein. Genau dieser Index laesst das Wettrennen nun als
    DuplicateKeyError auffliegen, statt es still durchzulassen.

    EIN Wiederholungsversuch genuegt: der Fehler kann nur auf dem Einfuegeweg entstehen, und
    danach IST das Geraet da. Der zweite Durchgang findet es, $setOnInsert greift nicht mehr,
    und die Zeile laeuft in den regulaeren Zweig. Scheitert auch er, liegt die Ursache
    woanders - dann meldet der Aufrufer die ZEILE als Fehler. Ungefangen beendete der
    DuplicateKeyError die ganze Anfrage mit 500: der Admin verloere das Zeilenprotokoll des
    GESAMTEN Uploads und wuesste nicht mehr, welche Zeilen bereits gebucht sind.
    """

    async def versuch() -> Optional[dict]:
        return await db.ipads.find_one_and_update(
            {"itnr": itnr},
            {"$setOnInsert": prepare_for_mongo(neues_geraet.dict())},
            upsert=True,
            # return_document=BEFORE lets us tell "we just created it" (None) apart from
            # "it already existed" (the pre-update document) with a single round-trip.
            return_document=ReturnDocument.BEFORE,
        )

    try:
        return await versuch()
    except DuplicateKeyError:
        return await versuch()


@api_router.post("/admin/ipads/batch-assign-import")
@limiter.limit("10/minute")
async def batch_assign_import(
    request: Request,
    file: UploadFile = File(...),
    bildungsgang_id: str = Form(...),
    uebergeben_an_user_id: str = Form(...),
    current_user: dict = Depends(require_admin_user),
):
    """
    Admin-only: Upload a list of ITNr/SNr and assign each iPad to a Bildungsgang.

    Gelesen werden ITNr, SNr, Karton, Pencil, Typ, AnschJahr und Status - genau die Spalten,
    die download_batch_assign_template ausgibt.

    Zeilen mit den Beispiel-ITNrn der eigenen Vorlage werden uebersprungen - die unveraendert
    hochgeladene Vorlage ist keine Lieferliste, sondern der erste Versuch.

    Per row (matched globally by ITNr, atomically so concurrent runs can't create
    duplicate ITNr records for a brand-new device):
    - Not found: a new iPad is created and directly assigned to the target user - mit allen
      Angaben der Datei. Leere Zellen: Typ und Pencil bekommen die Vorgabe aus den
      Einstellungen, der Status "ok".
    - Found, in pool: the iPad is atomically claimed out of the pool and assigned; dabei
      werden LEERE Felder des Bestands aus der Datei nachgetragen.
    - Found, not in pool, already in the target Bildungsgang: ownership stays as it is,
      aber die koerperliche Uebergabe wird quittiert - eine Nachlieferung an denselben
      Bildungsgang muss sich spaeter genauso beantworten lassen wie die erste Lieferung.
      Leere Felder werden auch hier nachgetragen.
    - Found, not in pool, anderer Bildungsgang: left untouched - the current owner is
      reported so the admin can see who already has it. Auch keine Stammdaten: bei einem
      Zahlendreher in der ITNr landeten sie sonst unsichtbar in fremdem Bestand.

    An einem vorhandenen Geraet wird nie ein Wert ueberschrieben. Der Bestand kam zentral
    herein und wurde seitdem in der App gepflegt; die Lieferliste ist aelter als diese
    Korrekturen. Eine abweichende SNr wird deshalb gemeldet statt uebernommen, und der Status
    eines vorhandenen Geraets bleibt stehen - ein unbekannter Wert in der Spalte wird gemeldet.
    """
    bildungsgang = await db.bildungsgaenge.find_one({"id": bildungsgang_id})
    if not bildungsgang:
        raise HTTPException(status_code=404, detail="Bildungsgang nicht gefunden")
    bildungsgang_name = bildungsgang["name"]

    # An wen die Geraete koerperlich uebergeben wurden. Das ist KEIN Besitz - der liegt beim
    # Bildungsgang - sondern eine Quittung: wer hat die Kiste tatsaechlich bekommen, und wann.
    # Ohne das laesst sich spaeter nicht mehr klaeren, bei wem ein Geraet gelandet ist.
    empfaenger = await db.users.find_one({"id": uebergeben_an_user_id})
    if not empfaenger:
        raise HTTPException(status_code=404, detail="Empfänger nicht gefunden")
    uebergeben_an = {"user_id": uebergeben_an_user_id, "username": empfaenger.get("username")}

    if not file.filename.lower().endswith((".xlsx", ".xls")):
        raise HTTPException(status_code=400, detail="Nur Excel-Dateien (.xlsx, .xls) sind erlaubt")

    contents = await file.read()
    validate_uploaded_file(contents, file.filename, max_size_mb=10, allowed_types=[".xlsx", ".xls"])
    df = read_excel_upload(contents, file.filename)

    global_settings = await db.global_settings.find_one({"type": "app_settings"})
    default_pencil = global_settings.get("pencil", "ohne Apple Pencil") if global_settings else "ohne Apple Pencil"
    default_ipad_typ = await _vorgabe_ipad_typ()

    # Pre-load usernames so "already assigned to X" can be reported without N+1 queries.
    # Wem ein bereits vergebenes Geraet gehoert, ist jetzt eine Frage des Bildungsgangs -
    # "liegt schon bei GYM" ist fuer die Rueckmeldung brauchbarer als ein Kontoname.
    bg_map = {b["id"]: b["name"] async for b in db.bildungsgaenge.find({}, {"id": 1, "name": 1})}

    rows_out = []
    valid_statuses = ["ok", "defekt", "gestohlen"]
    # Die already_assigned-Zeilen zerfallen in zwei sehr verschiedene Faelle, die der Zaehler
    # ueber das outcome allein nicht auseinanderhaelt: im EIGENEN Bildungsgang wird quittiert
    # und nachgetragen, im fremden passiert nichts. Nur der zweite Fall ist "unveraendert".
    quittiert_im_eigenen_bildungsgang = 0

    for index, row in df.iterrows():
        row_number = index + 2  # account for header row
        now_iso = datetime.now(UTC).isoformat()
        # Auch ITNr und SNr ueber _zelle: eine rein numerische Spalte mit einer Luecke kommt
        # als float herein, und safe_str allein machte aus der Nummer 123456 ein "123456.0" -
        # im Bestand gaelte sie dann als abweichend, bei einem neuen Geraet landete der
        # Nachkommateil in der Kartei. Die leere Zelle bleibt hier "" statt None: beide Werte
        # gehen unveraendert in die Pflichtpruefung, in die Meldung und ins Geraet.
        itnr = _zelle(row, _SPALTE_ITNR) or ""
        snr = _zelle(row, _SPALTE_JE_FELD["snr"]) or ""

        if not itnr:
            rows_out.append(
                {
                    "row": row_number,
                    "itnr": itnr,
                    "snr": snr,
                    "outcome": "invalid_row",
                    "assigned_to": None,
                    "note": "ITNr fehlt",
                    "at": now_iso,
                }
            )
            continue

        # Die Vorlage auszuprobieren heisst, sie herunterzuladen und wieder hochzuladen - und
        # bis hierher legte genau das zwei Geraete an, die es nie gab. Erkennbar unecht zu
        # sein reicht nicht: der Upload liest die Nummer, er liest sie nicht gegen.
        # Eigenes outcome statt "invalid_row": die Zeile ist kein Mangel der Liste, sondern
        # bedeutungslos. Unter "ungültig / Fehler" gezaehlt schickte sie den Admin auf die
        # Suche nach einem Problem, das es nicht gibt.
        if itnr.casefold() in _BEISPIEL_ITNRN_VERGLEICH:
            rows_out.append(
                {
                    "row": row_number,
                    "itnr": itnr,
                    "snr": snr,
                    "outcome": "beispielzeile",
                    "assigned_to": None,
                    "note": "Beispielzeile der Vorlage - übersprungen",
                    "at": now_iso,
                }
            )
            continue

        # Gross-/Kleinschreibung egal, wie im allgemeinen Import. Eine leere Status-Spalte ist
        # kein Fehler; nur ein ausgefuellter, unbekannter Wert wird gemeldet.
        status_roh = _zelle(row, _SPALTE_JE_FELD["status"])
        status = status_roh.lower() if status_roh and status_roh.lower() in valid_statuses else None
        # Der ungedeutete Wert, sonst None. Er gehoert in JEDEN Zweig, in dem die Zeile
        # verarbeitet wird: bisher wurde er nur beim neu angelegten Geraet gemeldet, und
        # "kaputt" verschwand ausgerechnet bei den Geraeten, die es schon gibt.
        status_unbekannt = status_roh if status_roh and status is None else None

        # Welche Spalte welches Feld traegt, sagt _SPALTE_JE_FELD - dieselbe Tabelle, aus der
        # die Vorlage ihre Ueberschriften nimmt. Damit liest der Upload, was die Vorlage
        # ausgibt, auch wenn eine Spalte spaeter einmal anders heisst.
        #
        # Der Status ist bewusst ausgenommen: er ist im Datenmodell mit "ok" vorbelegt und
        # damit bei jedem vorhandenen Geraet gesetzt - "nur leere Felder fuellen" haette ihn
        # nie angefasst. Fuer ein NEUES Geraet wird er direkt aus `status` uebernommen, fuer
        # ein vorhandenes meldet ihn der Hinweis, statt ihn stillschweigend zu schlucken.
        aus_datei = {feld: _zelle(row, spalte) for feld, spalte in _SPALTE_JE_FELD.items() if feld != "status"}

        # Atomic upsert: if no document with this itnr exists yet, create it in the
        # same operation that checks for it - siehe _geraet_anlegen_oder_lesen.
        new_ipad = iPad(
            user_id=current_user["id"],  # angelegt von
            bildungsgang_id=bildungsgang_id,
            itnr=itnr,
            snr=snr,
            karton=aus_datei["karton"],
            pencil=aus_datei["pencil"] or default_pencil,
            typ=aus_datei["typ"] or default_ipad_typ,
            ansch_jahr=aus_datei["ansch_jahr"],
            status=status or "ok",
            is_in_pool=False,
            pool_history=[
                {
                    "action": "created_and_assigned_by_admin",
                    "by": current_user["id"],
                    "bildungsgang_id": bildungsgang_id,
                    "uebergeben_an": uebergeben_an,
                    "at": now_iso,
                }
            ],
        )
        try:
            existing = await _geraet_anlegen_oder_lesen(itnr, new_ipad)
        except DuplicateKeyError:
            # Auch der zweite Versuch gescheitert: die Zeile faellt aus, der Lauf nicht.
            rows_out.append(
                {
                    "row": row_number,
                    "itnr": itnr,
                    "snr": snr,
                    "outcome": "error",
                    "assigned_to": None,
                    "note": "ITNr wurde zeitgleich angelegt - Zeile nicht verarbeitet, bitte erneut hochladen",
                    "at": now_iso,
                }
            )
            continue

        if existing is None:
            rows_out.append(
                {
                    "row": row_number,
                    "itnr": itnr,
                    "snr": snr,
                    "outcome": "created",
                    "assigned_to": bildungsgang_name,
                    # Neu angelegt heisst: der Status aus der Datei wird uebernommen - nur
                    # eben der gedeutete. Deshalb hier eine andere Meldung als in den
                    # Zweigen, in denen der Bestand unberuehrt bleibt.
                    "note": (
                        f"Status '{status_unbekannt}' unbekannt - als 'ok' übernommen" if status_unbekannt else None
                    ),
                    "at": now_iso,
                }
            )
        elif existing.get("is_in_pool"):
            nachtrag = _nachzutragen(existing, aus_datei)
            result = await _claim_pool_ipad_for_bildungsgang(
                existing["id"],
                bildungsgang_id,
                "assigned_by_admin",
                current_user["id"],
                uebergeben_an,
                nachtrag=nachtrag,
            )
            if result:
                rows_out.append(
                    {
                        "row": row_number,
                        "itnr": itnr,
                        "snr": snr,
                        "outcome": "from_pool",
                        "assigned_to": bildungsgang_name,
                        "note": _hinweis(existing, nachtrag, snr, status_unbekannt),
                        "at": now_iso,
                    }
                )
            else:
                rows_out.append(
                    {
                        "row": row_number,
                        "itnr": itnr,
                        "snr": snr,
                        "outcome": "error",
                        "assigned_to": None,
                        "note": "iPad wurde zwischenzeitlich bereits vergeben",
                        "at": now_iso,
                    }
                )
        else:
            owner_name = bg_map.get(existing.get("bildungsgang_id"), "ohne Bildungsgang")
            note = f"Bereits zugeordnet zu {owner_name}"
            # Im fremden Bestand wird nichts angefasst, auch keine Stammdaten.
            nachtrag = {}
            if existing.get("bildungsgang_id") == bildungsgang_id:
                # Das Geraet gehoert dem Ziel-Bildungsgang schon: am Besitz aendert sich nichts,
                # koerperlich uebergeben wird es trotzdem. Ohne diese Quittung bliebe bei einer
                # Nachlieferung an denselben Bildungsgang offen, wer die Kiste bekommen hat -
                # und genau dafuer ist der Empfaenger ein Pflichtfeld.
                # Dieselbe action wie bei den anderen Zeilen des Laufs: die Zuordnung IST
                # erfolgt, sie war nur schon da.
                nachtrag = _nachzutragen(existing, aus_datei)
                ergebnis = await db.ipads.update_one(
                    # Derselbe Schutz wie im Pool-Zweig: der Filter prueft die Lage mit, auf
                    # die sich dieser Zweig stuetzt. Zwischen dem lesenden find_one_and_update
                    # und hier kann ein anderer Admin das Geraet in den Pool freigeben - der
                    # Nachtrag landete dann in einem Poolgeraet und haengte ihm eine
                    # Uebergabe-Quittung an, die so nie stattgefunden hat.
                    #
                    # $ne statt False, und zwar zwingend: is_in_pool ist ein spaet
                    # hinzugekommenes Feld, das den meisten Bestandsgeraeten schlicht fehlt.
                    # {"is_in_pool": False} findet ein FEHLENDES Feld nicht - der Filter traf
                    # damit nur die Geraete, die das Feld tragen, und eine Nachlieferung an
                    # einen bestehenden Bildungsgang lief fuer alle anderen ins Leere: kein
                    # Nachtrag, keine Quittung, und die Zeile meldete faelschlich einen
                    # Fehler. Der Rest des Projekts (get_ipad_filter, assignments) fragt
                    # laengst so; hier war es uebersehen worden.
                    {"id": existing["id"], "is_in_pool": {"$ne": True}, "bildungsgang_id": bildungsgang_id},
                    {
                        "$set": {**nachtrag, "updated_at": now_iso},
                        "$push": {
                            "pool_history": {
                                "action": "assigned_by_admin",
                                "by": current_user["id"],
                                "bildungsgang_id": bildungsgang_id,
                                "uebergeben_an": uebergeben_an,
                                "at": now_iso,
                            }
                        },
                    },
                )
                if ergebnis.matched_count == 0:
                    # Nicht getroffen heisst: geschrieben wurde nichts. Die Zeile als Erfolg
                    # zu melden, waere schlimmer als der Fehler selbst - der Admin haelt die
                    # Uebergabe dann fuer quittiert.
                    rows_out.append(
                        {
                            "row": row_number,
                            "itnr": itnr,
                            "snr": snr,
                            "outcome": "error",
                            "assigned_to": None,
                            "note": "iPad wurde zwischenzeitlich verschoben - nichts geändert",
                            "at": now_iso,
                        }
                    )
                    continue
                quittiert_im_eigenen_bildungsgang += 1
                note = f"Bereits zugeordnet zu {owner_name} - Übergabe quittiert"
            # Auch im fremden Bildungsgang: am Geraet wird nichts angefasst, die Zeile wird
            # aber gemeldet - und ein ungedeuteter Status ist ein Mangel der LISTE, nicht des
            # Geraets. Wer die Liste geschrieben hat, soll ihn erfahren.
            hinweis = _hinweis(existing, nachtrag, snr, status_unbekannt)
            if hinweis:
                note = f"{note} - {hinweis}"
            rows_out.append(
                {
                    "row": row_number,
                    "itnr": itnr,
                    "snr": snr,
                    "outcome": "already_assigned",
                    "assigned_to": owner_name,
                    "note": note,
                    "at": now_iso,
                }
            )

    counts = Counter(r["outcome"] for r in rows_out)
    # Was vom eigenen Bildungsgang uebrig bleibt, lag im fremden - dort allein stimmt
    # "unveraendert".
    fremder_bildungsgang = counts["already_assigned"] - quittiert_im_eigenen_bildungsgang

    return {
        # "bereits vorhanden (unverändert)" war fuer die Zeilen im eigenen Bildungsgang
        # schlicht falsch: dort werden leere Felder nachgetragen und eine Uebergabe-Quittung
        # in die pool_history geschrieben. Bei 40 Nachlieferungszeilen las der Admin
        # "40 unverändert", waehrend 40 Geraete Stammdaten und 40 Historieneintraege bekamen -
        # die Meldung widersprach genau dem, wofuer der Pflicht-Empfaenger da ist.
        "message": (
            f"{counts['from_pool']} aus Pool zugeordnet, {counts['created']} neu erstellt & zugeordnet, "
            f"{quittiert_im_eigenen_bildungsgang} bereits im Bildungsgang (Übergabe quittiert), "
            f"{fremder_bildungsgang} in fremdem Bildungsgang (unverändert)"
        ),
        "bildungsgang_name": bildungsgang_name,
        "uebergeben_an": uebergeben_an["username"],
        "summary": {
            "from_pool_count": counts["from_pool"],
            "created_count": counts["created"],
            # Die Summe beider Faelle, unter dem Namen des outcome. Sie bleibt, weil das
            # Frontend sie anzeigt; die beiden Zahlen darunter sagen, woraus sie besteht.
            "already_assigned_count": counts["already_assigned"],
            "quittiert_count": quittiert_im_eigenen_bildungsgang,
            "fremder_bildungsgang_count": fremder_bildungsgang,
            # Getrennt von invalid_rows: die Oberflaeche zaehlt invalid_rows und error_count
            # zu "ungültig / Fehler" zusammen, und dort haben die Beispielzeilen nichts zu
            # suchen. Ohne eigenen Zaehler fielen sie aus der Zusammenfassung heraus und die
            # Zahlen ergaeben nicht mehr die Zahl der Zeilen.
            "beispielzeile_count": counts["beispielzeile"],
            "invalid_rows": counts["invalid_row"],
            "error_count": counts["error"],
        },
        "rows": rows_out,
    }


@api_router.get("/admin/ipads/batch-assign-template")
async def download_batch_assign_template(current_user: dict = Depends(require_admin_user)):
    """Die Excel-Vorlage fuer die Batch-Zuordnung (nur Admins, wie der Upload selbst).

    Die grosse Importvorlage (/imports/template) fuehrt alle Schuelerspalten mit; davon liest
    dieser Upload keine einzige. Welche Spalten hier stehen und in welcher Reihenfolge, sagt
    _SPALTE_JE_FELD - damit Vorlage und Upload nicht auseinanderlaufen koennen.
    """
    # Die Beispiel-ITNrn muessen als Beispiel ERKENNBAR sein. "IT-001" war von den echten
    # Nummern dieser Schule (die Form "IT" + Ziffern) nicht zu unterscheiden: wer die Vorlage
    # unveraendert wieder hochlud, legte zwei Geistergeraete an, die anschliessend niemand
    # als Beispielzeilen erkannte. Erkennbar sein ist aber nur die halbe Sicherung - die
    # andere ist, dass der Upload dieselben Nummern kennt und solche Zeilen ueberspringt;
    # deshalb stehen sie in _VORLAGE_BEISPIEL_ITNRN und nicht hier.
    beispiel_voll, beispiel_nur_itnr = _VORLAGE_BEISPIEL_ITNRN
    beispiele = [
        # Eine vollstaendig ausgefuellte Zeile: so sieht die Lieferliste des Traegers aus.
        # Die Werte kommen aus derselben Tabelle wie die Spalten (_LIEFERLISTE_SPALTEN),
        # koennen ihr also nicht davonlaufen.
        {_SPALTE_ITNR: beispiel_voll, **_VORLAGE_BEISPIEL_JE_SPALTE},
        # Und eine mit nichts als der ITNr. Das ist Absicht, keine halb vergessene Zeile:
        # ausser der ITNr muss nichts ausgefuellt werden. Wer sie "repariert", nimmt der
        # Vorlage genau die Auskunft, die den meisten Listen die Arbeit erspart.
        {**{spalte: "" for spalte in _VORLAGE_SPALTEN}, _SPALTE_ITNR: beispiel_nur_itnr},
    ]

    df = pd.DataFrame(beispiele, columns=_VORLAGE_SPALTEN)

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, sheet_name="Geräte-Zuordnung", index=False)

    output.seek(0)

    return StreamingResponse(
        io.BytesIO(output.read()),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=batch_zuordnung_vorlage.xlsx"},
    )


@api_router.post("/ipads/bulk-claim")
@limiter.limit("30/minute")
async def bulk_claim_ipads(payload: BulkClaimRequest, request: Request, current_user: dict = Depends(require_admin_user)):
    """Claim multiple iPads from the pool. Reports success and failure counts. Admin-only."""
    if not payload.ipad_ids:
        raise HTTPException(status_code=400, detail="Keine iPads ausgewählt")

    success = []
    failed = []

    bildungsgang_id = await resolve_bildungsgang(current_user, payload.bildungsgang_id)
    for ipad_id in payload.ipad_ids:
        result = await _claim_pool_ipad_for_bildungsgang(
            ipad_id, bildungsgang_id, "claimed", current_user["id"]
        )
        if result:
            success.append(result.get("itnr"))
        else:
            failed.append(ipad_id)

    return {"success_count": len(success), "failed_count": len(failed), "claimed_itnrs": success}


@api_router.post("/ipads/{ipad_id}/release-to-pool")
@limiter.limit("60/minute")
async def release_ipad_to_pool(ipad_id: str, request: Request, current_user: dict = Depends(require_admin_user)):
    """Release an iPad to the shared pool. Auto-dissolves active assignment. Admin-only."""
    ipad = await db.ipads.find_one({"id": ipad_id})
    if not ipad:
        raise HTTPException(status_code=404, detail="iPad nicht gefunden oder kein Zugriff")

    if ipad.get("is_in_pool"):
        raise HTTPException(status_code=400, detail="iPad ist bereits im Pool")

    # Auto-dissolve active assignment if exists
    dissolved_assignment = False
    if ipad.get("current_assignment_id"):
        assignment_id = ipad["current_assignment_id"]
        await db.assignments.update_one(
            {"id": assignment_id}, {"$set": {"is_active": False, "dissolved_at": datetime.now(UTC).isoformat()}}
        )
        # Mark contracts inactive
        await db.contracts.update_many(
            {"assignment_id": assignment_id},
            {"$set": {"is_active": False, "updated_at": datetime.now(UTC).isoformat()}},
        )
        dissolved_assignment = True

    now_iso = datetime.now(UTC).isoformat()
    await db.ipads.update_one(
        {"id": ipad_id},
        {
            "$set": {
                "is_in_pool": True,
                # Ein freigegebenes Geraet gehoert niemandem mehr - genau wie ein von Anfang an
                # im Pool angelegtes. Bliebe der Bildungsgang stehen, erschiene es in dessen
                # Ansicht weiter als Bestand und liesse sich dort ausgeben, obwohl die zentrale
                # Verwaltung es als Poolbestand fuehrt. Woher es kam, haelt die pool_history fest.
                "bildungsgang_id": None,
                "current_assignment_id": None,
                "updated_at": now_iso,
            },
            "$push": {
                "pool_history": {
                    "action": "released",
                    "by": current_user["id"],
                    # Der frueher zustaendige Bildungsgang: die einzige Spur, aus welchem
                    # Bestand das Geraet zurueckkam, nachdem das Feld geleert wurde.
                    "bildungsgang_id": ipad.get("bildungsgang_id"),
                    "at": now_iso,
                }
            },
        },
    )

    return {
        "message": f"iPad {ipad['itnr']} in den Pool freigegeben",
        "itnr": ipad["itnr"],
        "dissolved_assignment": dissolved_assignment,
    }


@api_router.delete("/ipads/{ipad_id}")
async def delete_ipad(ipad_id: str, current_user: dict = Depends(get_current_user)):
    """
    Delete an iPad permanently from the database.
    If the iPad is currently assigned, the active assignment is dissolved
    automatically as part of the deletion (student keeps their contract on
    file, just no longer linked to this now-gone iPad/assignment).
    Admin can delete any iPad including pool iPads.
    """
    # Admin: any iPad. Regular user: own non-pool iPads only.
    ipad_filter = await get_ipad_filter(current_user)
    ipad = await db.ipads.find_one({"id": ipad_id, **ipad_filter})

    if not ipad:
        raise HTTPException(status_code=404, detail="iPad not found or access denied")

    had_active_assignment = bool(ipad.get("current_assignment_id"))

    # Update contracts: entferne ipad_id und assignment_id Referenz (student_id bleibt,
    # Vertrag ist weiterhin ueber den Schueler auffindbar - gleiche Logik wie beim
    # regulaeren Aufloesen einer Zuordnung, nur zusaetzlich ipad_id entfernt, da das
    # iPad selbst gleich mitgeloescht wird)
    await db.contracts.update_many(
        {"ipad_id": ipad_id},
        {"$set": {"ipad_id": None, "assignment_id": None, "updated_at": datetime.now(UTC).isoformat()}},
    )

    # Delete orphaned contracts (no ipad_id, no student_id, no assignment_id)
    contracts_deleted = await db.contracts.delete_many(
        {
            "$and": [
                {"$or": [{"student_id": None}, {"student_id": {"$exists": False}}]},
                {"$or": [{"ipad_id": None}, {"ipad_id": {"$exists": False}}]},
                {"$or": [{"assignment_id": None}, {"assignment_id": {"$exists": False}}]},
            ]
        }
    )

    # Delete all assignments history for this iPad (includes the active one, if any)
    assignments_result = await db.assignments.delete_many({"ipad_id": ipad_id})

    # Delete the iPad
    await db.ipads.delete_one({"id": ipad_id})

    return {
        "message": f"iPad {ipad['itnr']} erfolgreich gelöscht"
        + (" (aktive Zuordnung wurde aufgelöst)" if had_active_assignment else ""),
        "deleted_assignments": assignments_result.deleted_count,
        "deleted_contracts": contracts_deleted.deleted_count,
        "dissolved_active_assignment": had_active_assignment,
    }


# Student management endpoints


class IPadStatusUpdate(BaseModel):
    status: str


@api_router.put("/ipads/{ipad_id}/status")
async def update_ipad_status(ipad_id: str, payload: IPadStatusUpdate, current_user: dict = Depends(get_current_user)):
    """
    Update iPad physical status (ok, defekt, gestohlen).
    Status indicates the physical condition, not assignment state.
    Assignment state is managed separately via current_assignment_id.
    """
    status_value = payload.status
    valid_statuses = ["ok", "defekt", "gestohlen"]
    if status_value not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    # Admin: any iPad. Regular user: own non-pool iPads only.
    ipad_filter = await get_ipad_filter(current_user)
    ipad = await db.ipads.find_one({"id": ipad_id, **ipad_filter})
    if not ipad:
        raise HTTPException(status_code=404, detail="iPad not found")

    # Update iPad status (does not affect assignment)
    await db.ipads.update_one(
        {"id": ipad_id}, {"$set": {"status": status_value, "updated_at": datetime.now(UTC).isoformat()}}
    )

    return {"message": f"iPad status updated to {status_value}"}


class IPadUpdateRequest(BaseModel):
    itnr: Optional[str] = None
    snr: Optional[str] = None
    karton: Optional[str] = None
    pencil: Optional[str] = None
    typ: Optional[str] = None
    ansch_jahr: Optional[str] = None
    ausleihe_datum: Optional[str] = None
    status: Optional[str] = None


@api_router.put("/ipads/{ipad_id}")
async def update_ipad(ipad_id: str, request: IPadUpdateRequest, current_user: dict = Depends(get_current_user)):
    """Update iPad information"""
    ipad_filter = await get_ipad_filter(current_user)
    ipad = await db.ipads.find_one({"id": ipad_id, **ipad_filter})
    if not ipad:
        raise HTTPException(status_code=404, detail="iPad not found")

    # Build update dict with only provided fields.
    # Die Textfelder werden gekuerzt uebernommen, genau wie beim Anlegen - ein Tippfehler
    # soll hier korrigiert und nicht durch ein unsichtbares Leerzeichen ersetzt werden
    # koennen (siehe _getrimmt).
    update_data = {}
    if request.itnr is not None:
        itnr = _getrimmt(request.itnr)
        # Dieselbe Dublettenregel wie beim Anlegen (siehe _geraet_mit_itnr): die ITNr
        # bezeichnet ein Stueck Hardware und ist schulweit eindeutig. Eine abweichende
        # Regel beim Umbenennen verbot genau die Zustaende, die sich ueber das Anlegen
        # herstellen lassen - ein Tippfehler war dann nicht mehr korrigierbar. Gesucht wird mit der gekuerzten
        # Nummer, sonst vergliche die Pruefung Gekuerztes mit Ungekuerztem.
        existing = await _geraet_mit_itnr(
            itnr, ipad.get("bildungsgang_id"), bool(ipad.get("is_in_pool")), ausser_id=ipad_id
        )
        if existing:
            raise HTTPException(
                status_code=400,
                detail=_itnr_belegt_meldung(itnr, existing, bool(ipad.get("is_in_pool"))),
            )
        update_data["itnr"] = itnr
    if request.snr is not None:
        update_data["snr"] = _getrimmt(request.snr)
    if request.karton is not None:
        update_data["karton"] = _getrimmt(request.karton)
    if request.pencil is not None:
        update_data["pencil"] = _getrimmt(request.pencil)
    if request.typ is not None:
        # Auch das Leeren fuehrt auf die Vorgabe zurueck, nicht auf ein leeres Feld - siehe
        # _vorgabe_ipad_typ. Gekuerzt heisst: das gilt auch fuer ein Feld, das jemand mit der
        # Leertaste statt mit der Ruecktaste geleert hat.
        update_data["typ"] = _getrimmt(request.typ) or await _vorgabe_ipad_typ()
    if request.ansch_jahr is not None:
        update_data["ansch_jahr"] = _getrimmt(request.ansch_jahr)
    if request.ausleihe_datum is not None:
        update_data["ausleihe_datum"] = _getrimmt(request.ausleihe_datum)
    if request.status is not None:
        valid_statuses = ["ok", "defekt", "gestohlen"]
        # Auch hier gekuerzt, sonst entscheidet ein unsichtbares Leerzeichen darueber, ob
        # derselbe Wert angenommen oder abgewiesen wird.
        status = _getrimmt(request.status)
        if status not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"Ungültiger Status. Erlaubt: {valid_statuses}")
        update_data["status"] = status

    if not update_data:
        raise HTTPException(status_code=400, detail="Keine Änderungen angegeben")

    update_data["updated_at"] = datetime.now(UTC).isoformat()

    await db.ipads.update_one({"id": ipad_id}, {"$set": update_data})

    # If ITNr changed, update related assignments and contracts
    if "itnr" in update_data:
        await db.assignments.update_many({"ipad_id": ipad_id}, {"$set": {"itnr": update_data["itnr"]}})
        await db.contracts.update_many({"ipad_id": ipad_id}, {"$set": {"itnr": update_data["itnr"]}})

    # Get updated iPad
    updated_ipad = await db.ipads.find_one({"id": ipad_id})
    return {
        "message": "iPad erfolgreich aktualisiert",
        "ipad": {
            "id": updated_ipad["id"],
            "itnr": updated_ipad["itnr"],
            "snr": updated_ipad.get("snr"),
            "karton": updated_ipad.get("karton"),
            "pencil": updated_ipad.get("pencil"),
            "typ": updated_ipad.get("typ"),
            "ansch_jahr": updated_ipad.get("ansch_jahr"),
            "ausleihe_datum": updated_ipad.get("ausleihe_datum"),
            "status": updated_ipad.get("status", "ok"),
        },
    }


@api_router.post("/ipads/migrate-status")
async def migrate_ipad_status(current_user: dict = Depends(get_current_user)):
    """
    Migration endpoint to update old status values to new ones:
    - 'verfügbar' -> 'ok'
    - 'zugewiesen' -> 'ok'
    """
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admins can run migrations")

    try:
        # Update verfügbar and zugewiesen to ok
        result1 = await db.ipads.update_many(
            {"status": {"$in": ["verfügbar", "zugewiesen"]}}, {"$set": {"status": "ok"}}
        )

        return {"message": "iPad status migration completed", "updated_count": result1.modified_count}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Migration error: {str(e)}")


# iPad history and details
@api_router.get("/ipads/{ipad_id}/history")
async def get_ipad_history(ipad_id: str, current_user: dict = Depends(get_current_user)):
    # Admin: any iPad. Regular user: own non-pool iPads only.
    ipad_filter = await get_ipad_filter(current_user)
    ipad = await db.ipads.find_one({"id": ipad_id, **ipad_filter})
    if not ipad:
        raise HTTPException(status_code=404, detail="iPad not found")

    # Get all assignments (active and inactive)
    assignments = await db.assignments.find({"ipad_id": ipad_id}).to_list(length=None)

    # Get all contracts for this iPad via ipad_id (new) or itnr (legacy).
    # Der Besitzerfilter ist zwingend: die ITNr ist nur je Besitzer eindeutig (siehe create_ipad),
    # dieselbe Nummer existiert also legitim mehrfach. Ohne ihn liefert die Geraetehistorie die
    # form_fields eines fremden Vertrags - darin stehen Anschrift des Schuelers sowie Namen und
    # Anschriften beider Erziehungsberechtigten.
    user_filter = await get_user_filter(current_user)
    contracts = await db.contracts.find(
        {**user_filter, "$or": [{"ipad_id": ipad_id}, {"itnr": ipad["itnr"]}]}
    ).to_list(length=None)

    # Parse data safely
    try:
        ipad_data = iPad(**parse_from_mongo(ipad))
    except Exception as e:
        print(f"Error parsing iPad data: {e}")
        ipad_data = {
            "id": ipad.get("id"),
            "itnr": ipad.get("itnr"),
            "snr": ipad.get("snr", ""),
            "karton": ipad.get("karton", ""),
            "pencil": ipad.get("pencil", ""),
            "typ": ipad.get("typ", ""),
            "ansch_jahr": ipad.get("ansch_jahr", ""),
            "ausleihe_datum": ipad.get("ausleihe_datum", ""),
            "status": ipad.get("status", "ok"),
            "current_assignment_id": ipad.get("current_assignment_id"),
            "created_at": ipad.get("created_at"),
            "updated_at": ipad.get("updated_at"),
        }

    try:
        assignment_data = [Assignment(**parse_from_mongo(a)) for a in assignments]
    except Exception as e:
        print(f"Error parsing assignment data: {e}")
        assignment_data = []
        for a in assignments:
            try:
                assignment_data.append(Assignment(**parse_from_mongo(a)))
            except Exception as ae:
                print(f"Skipping assignment {a.get('id')}: {ae}")
                continue

    try:
        contract_data = []
        for c in contracts:
            try:
                # Handle contracts without file_data for display
                contract_dict = {
                    "id": c.get("id"),
                    "assignment_id": c.get("assignment_id"),
                    "ipad_id": c.get("ipad_id"),
                    "student_id": c.get("student_id"),
                    "itnr": c.get("itnr"),
                    "student_name": c.get("student_name"),
                    "filename": c.get("filename"),
                    "form_fields": c.get("form_fields", {}),
                    "uploaded_at": c.get("uploaded_at"),
                    "is_active": c.get("is_active", True),
                }
                contract_data.append(contract_dict)
            except Exception as ce:
                print(f"Skipping contract {c.get('id')}: {ce}")
                continue
    except Exception as e:
        print(f"Error parsing contract data: {e}")
        contract_data = []

    # Get owner info (current user_id of iPad)
    owner_username = None
    if ipad.get("user_id"):
        owner = await db.users.find_one({"id": ipad["user_id"]})
        if owner:
            owner_username = owner.get("username")

    # Enrich pool_history with username info
    raw_history = ipad.get("pool_history", []) or []
    user_id_set = set()
    for h in raw_history:
        if h.get("by"):
            user_id_set.add(h["by"])
        if h.get("target"):
            user_id_set.add(h["target"])
    user_map = {}
    if user_id_set:
        async for u in db.users.find({"id": {"$in": list(user_id_set)}}):
            user_map[u["id"]] = u.get("username", "?")
    bg_map = {b["id"]: b["name"] async for b in db.bildungsgaenge.find({}, {"id": 1, "name": 1})}
    pool_history = [
        {
            "action": h.get("action"),
            "by_user_id": h.get("by"),
            "by_username": user_map.get(h.get("by"), "Gelöschter User"),
            "target_username": user_map.get(h.get("target")) if h.get("target") else None,
            # Wem das Geraet zugeschlagen wurde (Besitz) und wer es koerperlich bekommen hat
            # (Quittung) - zwei verschiedene Dinge, die hier beide sichtbar sein muessen.
            "bildungsgang_name": bg_map.get(h.get("bildungsgang_id")),
            "uebergeben_an": (h.get("uebergeben_an") or {}).get("username"),
            "at": h.get("at"),
        }
        for h in raw_history
    ]

    return {
        "ipad": ipad_data,
        "assignments": assignment_data,
        "contracts": contract_data,
        "owner_username": owner_username,
        "pool_history": pool_history,
    }


# Assignment dissolution
