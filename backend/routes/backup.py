"""Backup routes (/api/backup/*, /api/settings/backup-encryption).

Auto-extracted from monolithic server.py during refactor (Session 12), later extended with
backup encryption, pre-restore safety backups and daily server-side backups.

Backups leave the server as files, not as e-mail: the contract PDFs live inside the MongoDB
documents, so the archive grows with every contract and passed the usual ~25MB attachment
limit long ago. The daily backup is written to a host-mounted directory from where a sync on
the operating-system level moves it off site - see scripts/BACKUP-OFFSITE.md.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo

from bson import ObjectId
from bson.binary import Binary
from fastapi import Depends, File, HTTPException, UploadFile
from fastapi.responses import Response
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pydantic import BaseModel

from core.config import ROOT_DIR, db
from core.crypto import (
    decrypt_backup_bytes,
    encrypt_backup_bytes,
    is_encrypted_backup,
    unwrap_secret,
    wrap_secret,
)
from core.router import api_router
from core.security import get_current_user, require_admin

logger = logging.getLogger(__name__)

# Jede Sammlung, die in ein Backup gehoert. Wer hier eine vergisst, merkt es erst beim
# Zurueckspielen - und dann fehlt sie. bildungsgaenge und zustaendigkeiten sind zwingend:
# ohne sie haette nach einer Wiederherstellung kein Datensatz mehr einen Besitzer und
# niemand mehr Zugriff ausser den Admins.
COLLECTIONS = [
    "users",
    "bildungsgaenge",
    "zustaendigkeiten",
    "students",
    "ipads",
    "assignments",
    "contracts",
    "global_settings",
]
BACKUP_TYPE_KEY = "__rbbk_backup_type"
# Bewusst NICHT in COLLECTIONS: hier steht, dass gerade eine Wiederherstellung laeuft. Stuende
# der Riegel in einer gesicherten Sammlung, raeumte die Wiederherstellung ihn mitten im eigenen
# Lauf weg - genau in dem Moment, in dem er gebraucht wird.
SYSTEM_STATE = "system_state"
# Laenger als jede Wiederherstellung dauert. Stirbt der Prozess mittendrin, bliebe der Riegel
# sonst fuer immer liegen und spaerrte die Ersteinrichtung auf einem frischen Server aus.
RESTORE_RIEGEL_MAX_SEKUNDEN = 1800
# Eintraege in global_settings, die das Backup ueber sich selbst fuehrt. Sie gehoeren ins
# Backup, zaehlen aber nicht als inhaltliche Aenderung - siehe _serialize_and_encrypt.
BACKUP_EIGENE_ZUSTAENDE = {"server_backup_state"}

# Nur in diesen Sammlungen haengt der Besitz am Bildungsgang. Fehlt dort die bildungsgang_id,
# ist der Datensatz herrenlos: keine Lehrkraft sieht ihn mehr, nur noch Admins. Der Anzeigename
# steht daneben, weil die Zahlen in einer Meldung an den Admin landen.
BILDUNGSGANG_SAMMLUNGEN = {
    "students": "Schüler",
    "ipads": "Geräte",
    "assignments": "Zuordnungen",
    "contracts": "Verträge",
}

# Die drei Zustaende des zentralen Backup-Passworts. PASSWORT_UNLESBAR ist der heimtueckische:
# in global_settings liegt ein Eintrag, er laesst sich mit dem aktuellen SECRET_KEY aber nicht
# mehr entpacken. Vorher galt allein das Vorhandensein als "Passwort gesetzt" - die Oberflaeche
# meldete gruen, waehrend der Tagesjob stuendlich scheiterte.
PASSWORT_BEREIT = "bereit"
PASSWORT_FEHLT = "fehlt"
PASSWORT_UNLESBAR = "unlesbar"

PASSWORT_MELDUNG = {
    PASSWORT_BEREIT: "Backup-Passwort gesetzt und lesbar - alle Backups werden damit verschlüsselt.",
    PASSWORT_FEHLT: (
        "Kein Backup-Passwort hinterlegt. Da Backups Schülerdaten enthalten, ist ein Backup-Passwort "
        "erforderlich (siehe Admin-Tab > Backup-Sicherheit: Backup-Passwort setzen)."
    ),
    PASSWORT_UNLESBAR: (
        "Es ist ein Backup-Passwort hinterlegt, der Server kann es aber nicht mehr entpacken - bitte "
        "im Admin-Tab > Backup-Sicherheit ein neues Backup-Passwort setzen. Bis dahin entsteht kein "
        "Backup. (Ursache ist ein anderer SECRET_KEY als beim Setzen, etwa weil der Eintrag aus einer "
        "älteren Sicherung zurückgespielt wurde.)"
    ),
}


def serialize_backup_value(value):
    """Convert Mongo values into JSON-safe values while preserving type information."""
    if isinstance(value, ObjectId):
        return {BACKUP_TYPE_KEY: "object_id", "value": str(value)}
    if isinstance(value, datetime):
        return {BACKUP_TYPE_KEY: "datetime", "value": value.isoformat()}
    if isinstance(value, (bytes, bytearray, Binary)):
        return {
            BACKUP_TYPE_KEY: "binary",
            "encoding": "base64",
            "value": base64.b64encode(bytes(value)).decode("ascii"),
        }
    if isinstance(value, list):
        return [serialize_backup_value(item) for item in value]
    if isinstance(value, dict):
        return {key: serialize_backup_value(item) for key, item in value.items()}
    return value


def deserialize_backup_value(value):
    """Restore values encoded by serialize_backup_value before inserting into Mongo."""
    if isinstance(value, list):
        return [deserialize_backup_value(item) for item in value]
    if isinstance(value, dict):
        marker = value.get(BACKUP_TYPE_KEY)
        if marker == "object_id":
            return ObjectId(value["value"])
        if marker == "datetime":
            return datetime.fromisoformat(value["value"])
        if marker == "binary":
            if value.get("encoding") != "base64":
                raise ValueError("Unsupported binary encoding in backup")
            return base64.b64decode(value["value"])
        return {key: deserialize_backup_value(item) for key, item in value.items()}
    return value


async def build_backup_payload() -> dict:
    """Build the full JSON-safe backup payload for all COLLECTIONS."""
    backup_data = {}
    for coll_name in COLLECTIONS:
        collection = db[coll_name]
        cursor = collection.find({})
        records = await cursor.to_list(length=None)
        backup_data[coll_name] = [serialize_backup_value(record) for record in records]
    return backup_data


async def restore_backup_payload(backup_data: dict):
    """Overwrite COLLECTIONS with the given (already deserialized-ready) backup payload.

    Sammlungen, die in der Datei gar nicht vorkommen, bleiben unberuehrt stehen - darauf weist
    pruefe_backup_inhalt vor dem Einspielen ausdruecklich hin.
    """
    # Das Backup-Passwort wird NICHT aus der Datei uebernommen, sondern bleibt, wie es auf
    # diesem Server steht: der Eintrag sagt, womit DIESER Server seine Sicherungen
    # verschluesselt, und gehoert damit zum Server, nicht zum Datenbestand der Schule. Genau
    # sein Zurueckschreiben hat die Anlage im Oktober lahmgelegt - der Eintrag stammte aus
    # einer Zeit mit anderem SECRET_KEY und war danach nicht mehr zu entpacken, waehrend die
    # Oberflaeche weiter "Passwort gesetzt" meldete. Fuer einen Umzug auf neue Hardware kostet
    # das nichts: wer eine verschluesselte Sicherung einspielen will, muss das Passwort dort
    # ohnehin vorher von Hand setzen, sonst laesst sich die Datei nicht einmal oeffnen
    # (siehe decrypt_uploaded_backup).
    eigenes_passwort = await db.global_settings.find_one({"type": "backup_encryption"})
    # Zwischen delete_many und insert_many ist die Benutzersammlung leer - und genau auf diesen
    # Zustand wartet der Einrichtungs-Endpunkt, um ein Standardkonto anzulegen. Ohne diesen
    # Riegel reichte ein Aufruf im richtigen Augenblick, um waehrend einer Wiederherstellung
    # admin/admin123 zu bekommen.
    await db[SYSTEM_STATE].update_one(
        {"type": "restore_running"},
        {"$set": {"type": "restore_running", "seit": datetime.now(UTC).isoformat()}},
        upsert=True,
    )
    try:
        await _restore_sammlungen(backup_data, eigenes_passwort)
    finally:
        await db[SYSTEM_STATE].delete_one({"type": "restore_running"})


async def laeuft_wiederherstellung() -> bool:
    """Ob gerade eine Wiederherstellung schreibt - und der Bestand deshalb nichts aussagt.

    Ein liegengebliebener Riegel (abgestuerzter Prozess) verfaellt, sonst kaeme man auf einem
    frisch aufgesetzten Server nicht mehr in die Ersteinrichtung.
    """
    eintrag = await db[SYSTEM_STATE].find_one({"type": "restore_running"})
    if not eintrag:
        return False
    seit = _parse_iso_utc(eintrag.get("seit"))
    if seit is None:
        return True
    return (datetime.now(UTC) - seit).total_seconds() < RESTORE_RIEGEL_MAX_SEKUNDEN


async def _restore_sammlungen(backup_data: dict, eigenes_passwort: Optional[dict]):
    for coll_name, records in backup_data.items():
        if coll_name not in COLLECTIONS:
            continue
        decoded_records = []
        for record in records:
            decoded_record = deserialize_backup_value(record)
            if "_id" in decoded_record and isinstance(decoded_record["_id"], str):
                try:
                    decoded_record["_id"] = ObjectId(decoded_record["_id"])
                except Exception:
                    del decoded_record["_id"]
            decoded_records.append(decoded_record)
        if coll_name == "global_settings":
            decoded_records = [
                r for r in decoded_records if not (isinstance(r, dict) and r.get("type") == "backup_encryption")
            ]
            if eigenes_passwort is not None:
                decoded_records.append(eigenes_passwort)
        collection = db[coll_name]
        await collection.delete_many({})
        if decoded_records:
            await collection.insert_many(decoded_records)


def _parse_iso_utc(value: Optional[str]) -> Optional[datetime]:
    """Parse a stored ISO timestamp. Legacy naive values are treated as UTC so that
    comparing them against an aware ``datetime.now(timezone.utc)`` cannot raise."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


async def get_backup_password_state() -> tuple:
    """(Zustand, Passwort) des zentralen Backup-Passworts; Passwort ist None, wenn unbrauchbar.

    Gesetzt ist ein Passwort erst, wenn es sich auch ENTPACKEN laesst. Ein Eintrag, den
    unwrap_secret nicht mehr oeffnet, ist fuer jeden Backup-Lauf dasselbe wie gar keiner - nur
    sieht man es ihm nicht an. Deshalb bekommt der Fall einen eigenen Zustand und eine eigene
    Meldung, statt als "fehlt" durchzugehen: zu tun ist etwas anderes (neu setzen) als beim
    erstmaligen Einrichten.
    """
    settings = await db.global_settings.find_one({"type": "backup_encryption"})
    if not settings or not settings.get("wrapped_password"):
        return PASSWORT_FEHLT, None
    passwort = unwrap_secret(settings["wrapped_password"])
    if not passwort:
        return PASSWORT_UNLESBAR, None
    return PASSWORT_BEREIT, passwort


def _serialize_and_encrypt(backup_data: dict, password: str) -> tuple:
    """Blocking JSON serialisation + encryption (run via ``asyncio.to_thread``).

    Returns (encrypted_bytes, sha256_of_plaintext). The checksum is taken BEFORE encryption on
    purpose: every encryption uses a fresh random salt and IV, so two backups of byte-identical
    data produce completely different ciphertext of identical length. Comparing the encrypted
    files - or their sizes - can therefore never tell duplicates apart.
    """
    json_bytes = json.dumps(backup_data, ensure_ascii=False, sort_keys=True).encode("utf-8")

    # Die Pruefsumme laeuft ueber den Bestand OHNE die Buchfuehrung des Backups selbst.
    # server_backup_state haelt last_run_at fest und aendert sich damit bei jedem Lauf -
    # ohne diese Ausnahme gaelte der Bestand immer als veraendert und die Entdoppelung
    # koennte nie greifen. Das Backup enthaelt die Eintraege weiterhin, sie zaehlen nur
    # nicht als inhaltliche Aenderung.
    fuer_pruefsumme = dict(backup_data)
    fuer_pruefsumme["global_settings"] = [
        g for g in backup_data.get("global_settings", []) if g.get("type") not in BACKUP_EIGENE_ZUSTAENDE
    ]
    pruef_bytes = json.dumps(fuer_pruefsumme, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return encrypt_backup_bytes(json_bytes, password), hashlib.sha256(pruef_bytes).hexdigest()


async def build_backup_export_bytes() -> tuple:
    """Build the current backup as encrypted bytes. Raises ValueError if no backup password is
    configured - backups contain student data (Schülerdaten) and must never leave the server
    (download, server-side archive) unencrypted.
    Returns (content_bytes, filename, is_encrypted, sha256_of_plaintext)."""
    zustand, password = await get_backup_password_state()
    if not password:
        raise ValueError(PASSWORT_MELDUNG[zustand])
    backup_data = await build_backup_payload()
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    # JSON dump + PBKDF2/Fernet are CPU-bound and grow with the data set - keep them off the
    # event loop so a running backup does not stall every other request (and the healthcheck).
    content_bytes, payload_sha256 = await asyncio.to_thread(_serialize_and_encrypt, backup_data, password)
    return content_bytes, f"rbbk_ipad_verwaltung_backup_{timestamp}.json.enc", True, payload_sha256


async def decrypt_uploaded_backup(content: bytes) -> bytes:
    """Decrypt an uploaded backup if it looks encrypted; pass plain JSON through unchanged."""
    if not is_encrypted_backup(content):
        return content
    zustand, password = await get_backup_password_state()
    if not password:
        raise ValueError("Diese Datei ist verschlüsselt. " + PASSWORT_MELDUNG[zustand])
    return decrypt_backup_bytes(content, password)


# --- Pre-restore safety backups: written to disk before every /backup/import so a failed
# or unwanted restore can be rolled back / manually recovered. ---
PRE_RESTORE_BACKUPS_DIR = ROOT_DIR / "uploads" / "backups"
PRE_RESTORE_FILENAME_RE = re.compile(r"^pre_restore_backup_\d{8}_\d{6}\.json(\.enc)?$")
PRE_RESTORE_KEEP_COUNT = 5


def _pre_restore_backups_dir() -> Path:
    PRE_RESTORE_BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    return PRE_RESTORE_BACKUPS_DIR


def _write_pre_restore_backup(content_bytes: bytes) -> str:
    """Persist a pre-restore snapshot to disk and prune old ones. Returns the filename.

    Immer verschluesselt - das Sicherheitsnetz ist ein vollstaendiges Abbild samt Namen,
    Adressen und unterschriebenen Vertraegen. Das Muster erlaubt weiterhin Dateinamen ohne
    ".enc", weil aus der Zeit davor noch solche im Verzeichnis liegen koennen.
    """
    backups_dir = _pre_restore_backups_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"pre_restore_backup_{timestamp}.json.enc"
    (backups_dir / filename).write_bytes(content_bytes)

    existing = sorted(backups_dir.glob("pre_restore_backup_*.json*"))
    for old_file in existing[:-PRE_RESTORE_KEEP_COUNT]:
        try:
            old_file.unlink()
        except OSError:
            pass

    return filename


@api_router.get("/backup/export")
async def export_backup(current_user: dict = Depends(get_current_user)):
    """Creates a full backup of all relevant collections (encrypted if a backup password is
    configured - always required, see build_backup_export_bytes). Only accessible by administrators."""
    require_admin(current_user)
    try:
        content_bytes, filename, is_encrypted, _sha = await build_backup_export_bytes()
        media_type = "application/octet-stream" if is_encrypted else "application/json"
        return Response(
            content=content_bytes,
            media_type=media_type,
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Access-Control-Expose-Headers": "Content-Disposition",
            },
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Backup export error: {str(e)}")
        raise HTTPException(status_code=500, detail="Fehler beim Erstellen des Backups.")


# --- Pruefungen vor dem Einspielen ------------------------------------------------------


def _itnr_schluessel(itnr) -> tuple:
    """Zwei ITNr so vergleichbar machen, wie der eindeutige Index auf ipads.itnr sie vergleicht.

    Ein fehlendes Feld legt die Datenbank als denselben Schluessel ab wie eine ausdrueckliche
    None - zwei Geraete ohne ITNr sind fuer sie dieselbe Nummer und die zweite Einfuegung
    scheitert. Zahlen vergleicht sie numerisch (1 und 1.0 sind eine), Zeichenkette und Zahl
    dagegen nicht ("1" ist nicht 1); deshalb traegt der Schluessel die Art mit, sonst wuerde
    eine Datei abgelehnt, die sich einwandfrei einspielen laesst.
    """
    if itnr is None:
        return ("fehlt", None)
    if isinstance(itnr, (int, float)) and not isinstance(itnr, bool):
        return ("zahl", float(itnr))
    if isinstance(itnr, str):
        return ("text", itnr)
    return ("sonstiges", repr(itnr))


def _itnr_anzeige(itnr) -> str:
    """Wie eine ITNr in einer Meldung erscheint - auch dann, wenn sie fehlt oder keine ist."""
    if itnr is None:
        return "ohne ITNr"
    if isinstance(itnr, str):
        return itnr if itnr.strip() else "leere ITNr"
    if isinstance(itnr, (int, float)) and not isinstance(itnr, bool):
        return f"{itnr} (als Zahl, nicht als Text)"
    return f"{itnr!r} (keine ITNr)"


def _doppelte_itnr(records) -> list:
    """ITNr, die in der Datei mehr als einmal vorkommen, in der Reihenfolge des Auftretens.

    Verglichen wird ueber _itnr_schluessel, also auch dort, wo gar keine Nummer steht. Vorher
    uebersprang die Pruefung jeden Wert, der keine nichtleere Zeichenkette war: zwei Geraete mit
    None, "" oder einer Zahl kamen durch und liefen erst beim Schreiben in den Index - der Admin
    bekam den rohen Mongo-Text zu lesen, und das bei halb ersetztem Bestand.
    """
    gesehen = set()
    gemeldet = set()
    doppelt = []
    for record in records or []:
        if not isinstance(record, dict):
            continue
        itnr = record.get("itnr")
        schluessel = _itnr_schluessel(itnr)
        if schluessel in gesehen and schluessel not in gemeldet:
            doppelt.append(_itnr_anzeige(itnr))
            gemeldet.add(schluessel)
        gesehen.add(schluessel)
    return doppelt


def _geraete_ohne_itnr(records) -> int:
    """Wie viele Geraete in der Datei ohne brauchbare ITNr ankommen.

    Einzeln nimmt die Datenbank das an, deshalb wird deswegen nichts abgelehnt - gemeldet
    gehoert es trotzdem: ein Geraet ohne Nummer ist in der Verwaltung nicht wiederzufinden,
    und der Batch-Abgleich sucht ueber genau diese Nummer.
    """
    anzahl = 0
    for record in records or []:
        if not isinstance(record, dict):
            continue
        itnr = record.get("itnr")
        if itnr is None or (isinstance(itnr, str) and not itnr.strip()):
            anzahl += 1
    return anzahl


def _doppelte_benutzernamen_in_datei(records) -> list:
    """Benutzernamen, die in der Datei mehrfach vorkommen - in der Reihenfolge ihres Auftretens.

    Gegen denselben Index geprueft, den die Datenbank anlegt: fehlender Name und None sind
    derselbe Schluessel, sonst liesse sich eine Datei einspielen, die beim Schreiben scheitert.
    """
    if not isinstance(records, list):
        return []
    gesehen, doppelt = set(), []
    for record in records:
        if not isinstance(record, dict):
            continue
        name = record.get("username")
        schluessel = name if isinstance(name, str) and name else None
        if schluessel in gesehen and (schluessel or "") not in doppelt:
            doppelt.append(schluessel or "(ohne Benutzernamen)")
        gesehen.add(schluessel)
    return doppelt


def pruefe_backup_inhalt(backup_data: dict) -> dict:
    """Bestandsaufnahme einer hochgeladenen Datei: was fehlt, was ist herrenlos, wie alt ist sie.

    Es wird gewarnt statt abgelehnt. Eine Sicherung, die sich nicht mehr einspielen laesst, ist
    wertlos - und gerade die alte Datei ist die, nach der im Notfall gegriffen wird. Der Weg
    zurueck bleibt ueber das Sicherheitsnetz offen, die Warnung sagt, was danach noch zu tun
    ist. Abgelehnt wird nur, was mitten im Schreiben scheitern wuerde (doppelte ITNr).
    """
    fehlende = [name for name in COLLECTIONS if name not in backup_data]
    ohne_bildungsgang = {}
    for name in BILDUNGSGANG_SAMMLUNGEN:
        anzahl = sum(
            1
            for record in backup_data.get(name) or []
            if isinstance(record, dict) and not record.get("bildungsgang_id")
        )
        if anzahl:
            ohne_bildungsgang[name] = anzahl

    ohne_itnr = _geraete_ohne_itnr(backup_data.get("ipads"))

    # "departments" hiess die Sammlung vor dem Umbau, "bildungsgaenge" gibt es erst seitdem.
    # Beides zusammen erkennt auch eine Datei, in der nur eines der Merkmale steht.
    vor_dem_umbau = "departments" in backup_data or "bildungsgaenge" not in backup_data

    warnungen = []
    if vor_dem_umbau:
        warnungen.append(
            "ACHTUNG: Diese Datei stammt aus der Zeit vor der Umstellung auf Bildungsgänge (sie "
            'enthält "departments" bzw. keine "bildungsgaenge"). Geräte und Schüler gehören '
            "danach zu keinem Bildungsgang, und ausser Admins sieht niemand mehr etwas. Bitte "
            "anschließend das Wanderungsskript scripts/migrate-to-bildungsgang.py laufen lassen."
        )
    if fehlende:
        # Welche Sammlungen es sind, steht im Feld fehlende_sammlungen daneben - die Oberflaeche
        # zeigt sie dort mit ihren deutschen Namen. Stuenden sie hier noch einmal, laese der
        # Admin dieselbe Auskunft zweimal, einmal als "Zustaendigkeiten" und einmal als
        # "zustaendigkeiten".
        warnungen.append(
            f"ACHTUNG: In der Datei fehlen {len(fehlende)} erwartete Sammlungen"
            if len(fehlende) != 1
            else "ACHTUNG: In der Datei fehlt eine erwartete Sammlung"
        )
        warnungen[-1] += (
            " (unten aufgezaehlt). Sie werden beim Einspielen nicht angefasst - dort bleibt der "
            "heutige Stand stehen."
        )
    if ohne_bildungsgang:
        aufzaehlung = ", ".join(
            f"{anzahl} {BILDUNGSGANG_SAMMLUNGEN[name]}" for name, anzahl in ohne_bildungsgang.items()
        )
        warnungen.append(f"ACHTUNG: Ohne Bildungsgang kommen an: {aufzaehlung}.")
    if ohne_itnr:
        warnungen.append(
            f"ACHTUNG: {ohne_itnr} {'Gerät kommt' if ohne_itnr == 1 else 'Geräte kommen'} ohne ITNr an. "
            "Ohne Nummer ist ein Gerät weder in der Verwaltung noch beim Batch-Abgleich "
            "wiederzufinden - bitte die ITNr nachtragen."
        )

    return {
        "fehlende_sammlungen": fehlende,
        "ohne_bildungsgang": ohne_bildungsgang,
        "geraete_ohne_itnr": ohne_itnr,
        "vor_dem_umbau": vor_dem_umbau,
        "warnungen": warnungen,
    }


def _dubletten_satz(anzahl: int) -> str:
    """ "1 ITNr kommt mehrfach vor" bzw. "N ITNr kommen mehrfach vor"."""
    return f"{anzahl} ITNr {'kommt' if anzahl == 1 else 'kommen'} mehrfach vor"


async def _doppelte_itnr_im_bestand() -> Optional[int]:
    """Wie viele ITNr im Bestand mehrfach vorkommen; None, wenn sich das nicht zaehlen laesst."""
    try:
        gruppen = await db.ipads.aggregate(
            [
                {"$group": {"_id": "$itnr", "anzahl": {"$sum": 1}}},
                {"$match": {"anzahl": {"$gt": 1}}},
                {"$count": "doppelte"},
            ]
        ).to_list(length=1)
    except Exception as e:
        logger.error(f"Doppelte ITNr konnten nicht gezaehlt werden: {str(e)}")
        return None
    return gruppen[0]["doppelte"] if gruppen else 0


async def ensure_itnr_index() -> dict:
    """Den eindeutigen Index auf ipads.itnr anlegen und berichten, ob er steht.

    Zwei Aufrufer: der Start (main.py) und jede Wiederherstellung. Letzteres ist noetig, weil
    der Index in der Datenbank steht und nicht in der Backup-Datei: wird in eine frische
    Datenbank eingespielt, gibt es ihn danach nicht. Fehlt er, nimmt die Datenbank Dubletten
    klaglos auf - und der naechste Start scheitert dann dauerhaft am Anlegen.

    Scheitert es, sagt die Meldung WIE VIELE Nummern doppelt sind. "Bitte bereinigen" ohne
    Zahl laesst denjenigen, der es liest, ratlos zurueck.

    Dubletten sind der haeufige, aber nicht der einzige Grund (eine Datenbank laesst sich auch
    nur lesend einbinden). Vorher stand in jeder Meldung, es gaebe welche - auch bei null
    gezaehlten. Das schickt jemanden auf die Suche nach etwas, das es nicht gibt; deshalb nennt
    die Meldung jetzt den Fall, der tatsaechlich vorliegt.
    """
    try:
        await db.ipads.create_index("itnr", unique=True, name="itnr_eindeutig")
        return {"ok": True, "duplikate": 0, "meldung": None}
    except Exception as e:
        duplikate = await _doppelte_itnr_im_bestand()
        if duplikate:
            meldung = (
                "ACHTUNG: Der eindeutige Index auf ipads.itnr konnte nicht angelegt werden - "
                f"{_dubletten_satz(duplikate)}. Bitte die Dubletten bereinigen; bis dahin können "
                "zwei gleichzeitige Batch-Läufe dieselbe ITNr doppelt anlegen."
            )
        else:
            befund = (
                "doppelte ITNr gibt es dabei keine"
                if duplikate == 0
                else "ob ITNr mehrfach vorkommen, ließ sich nicht feststellen"
            )
            meldung = (
                "ACHTUNG: Der eindeutige Index auf ipads.itnr konnte nicht angelegt werden - "
                f"{befund}. Die Datenbank meldet: {str(e)}. Bis der Index steht, können zwei "
                "gleichzeitige Batch-Läufe dieselbe ITNr doppelt anlegen."
            )
        logger.error(f"{meldung} ({str(e)})")
        return {"ok": False, "duplikate": duplikate, "meldung": meldung}


async def itnr_index_status() -> dict:
    """Steht der eindeutige Index? Nur wenn nicht, wird gezaehlt - das spart den Durchlauf
    ueber den Bestand im Normalfall.

    Wie bei ensure_itnr_index gilt: ohne gezaehlte Dubletten wird auch keine behauptet. Fehlt
    der Index ohne Dubletten, liegt es an etwas anderem - und dann ist das Log vom letzten
    Start die Spur, nicht der Bestand.
    """
    try:
        vorhanden = "itnr_eindeutig" in await db.ipads.index_information()
    except Exception as e:
        logger.error(f"Index-Auskunft zu ipads.itnr fehlgeschlagen: {str(e)}")
        return {"ok": None, "duplikate": None, "meldung": None}
    if vorhanden:
        return {"ok": True, "duplikate": 0, "meldung": None}
    duplikate = await _doppelte_itnr_im_bestand()
    if duplikate:
        meldung = (
            f"ACHTUNG: Der eindeutige Index auf ipads.itnr fehlt - {_dubletten_satz(duplikate)}. "
            "Bitte die Dubletten bereinigen; der Index wird beim nächsten Start erneut angelegt."
        )
    elif duplikate == 0:
        meldung = (
            "ACHTUNG: Der eindeutige Index auf ipads.itnr fehlt, doppelte ITNr gibt es aber keine. "
            "Warum das Anlegen scheiterte, steht im Server-Protokoll des letzten Starts; bis der "
            "Index steht, können zwei gleichzeitige Batch-Läufe dieselbe ITNr doppelt anlegen."
        )
    else:
        meldung = (
            "ACHTUNG: Der eindeutige Index auf ipads.itnr fehlt; ob ITNr mehrfach vorkommen, ließ "
            "sich nicht feststellen (siehe Server-Protokoll). Bis der Index steht, können zwei "
            "gleichzeitige Batch-Läufe dieselbe ITNr doppelt anlegen."
        )
    return {"ok": False, "duplikate": duplikate, "meldung": meldung}


@api_router.post("/backup/import")
async def import_backup(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """Restores the database from a backup file (plain .json or encrypted .json.enc). Only
    accessible by administrators. Warning: this overwrites existing data. A pre-restore safety
    snapshot is always written first (verschlüsselt, siehe unten) and used to automatically roll
    back on failure.

    Der Rueckgabewert nennt ausserdem, was an der Datei auffaellt: fehlende Sammlungen,
    Datensaetze ohne Bildungsgang, eine Datei von vor dem Umbau - und ob der eindeutige Index
    auf ipads.itnr danach steht."""
    require_admin(current_user)
    if not (file.filename.endswith(".json") or file.filename.endswith(".json.enc")):
        raise HTTPException(
            status_code=400, detail="Es muss eine .json oder verschlüsselte .json.enc Datei hochgeladen werden."
        )

    # Ohne entpackbares Passwort gibt es keine Wiederherstellung. Das Sicherheitsnetz weiter
    # unten ist ein vollstaendiges Abbild samt Namen, Adressen und unterschriebenen Vertraegen;
    # ohne Passwort landete es frueher als reines JSON in uploads/backups. Der Export verweigert
    # aus genau diesem Grund jedes unverschluesselte Backup (siehe build_backup_export_bytes) -
    # hier darf es nicht anders sein, nur weil der Weg ein anderer ist.
    passwort_zustand, backup_password = await get_backup_password_state()
    if not backup_password:
        raise HTTPException(
            status_code=400,
            detail=(
                "Vor dem Einspielen wird der aktuelle Bestand als Sicherheitsnetz gespeichert, und das "
                "muss verschlüsselt geschehen - es enthält Schülerdaten. " + PASSWORT_MELDUNG[passwort_zustand]
            ),
        )

    raw_content = await file.read()
    try:
        content = await decrypt_uploaded_backup(raw_content)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        backup_data = json.loads(content.decode("utf-8"))
        if not isinstance(backup_data, dict):
            raise ValueError("Ungueltiges Backup-Format.")
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Die hochgeladene Datei ist kein gueltiges (entschlüsselte) JSON.")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # insert_many schreibt der Reihe nach: bei einer doppelten ITNr bricht es mittendrin ab und
    # der Admin saehe den rohen Mongo-Text ("E11000 duplicate key"). Lieber vorher pruefen und
    # die betroffene Nummer nennen - bereinigen muss er die Datei ohnehin.
    doppelte = _doppelte_itnr(backup_data.get("ipads"))
    if doppelte:
        gezeigt = ", ".join(doppelte[:10])
        rest = f" (und {len(doppelte) - 10} weitere)" if len(doppelte) > 10 else ""
        raise HTTPException(
            status_code=400,
            detail=(
                f"Die Datei enthält dieselbe ITNr mehrfach: {gezeigt}{rest}. Eine ITNr bezeichnet genau "
                "ein Gerät, deshalb wird nichts eingespielt. Bitte die Dubletten in der Datei bereinigen. "
                "Geräte ohne ITNr zählen dabei mit: für den eindeutigen Index sind auch zwei leere "
                "Felder dieselbe Nummer."
            ),
        )

    # Seit username_eindeutig (siehe main.py) gilt fuer Benutzernamen dasselbe wie fuer die
    # ITNr: eine Datei mit demselben Namen zweimal brachte die Wiederherstellung sonst mitten
    # im Schreiben zu Fall, mit rohem Mongo-Text als Begruendung.
    doppelte_namen = _doppelte_benutzernamen_in_datei(backup_data.get("users"))
    if doppelte_namen:
        gezeigt = ", ".join(doppelte_namen[:10])
        rest = f" (und {len(doppelte_namen) - 10} weitere)" if len(doppelte_namen) > 10 else ""
        raise HTTPException(
            status_code=400,
            detail=(
                f"Die Datei enthält denselben Benutzernamen mehrfach: {gezeigt}{rest}. Ein Name "
                "bezeichnet genau ein Konto, deshalb wird nichts eingespielt. Bitte die Dubletten "
                "in der Datei bereinigen."
            ),
        )

    befund = pruefe_backup_inhalt(backup_data)

    # Safety net: snapshot current data BEFORE touching anything, so a failed or unwanted
    # restore can be rolled back / manually recovered afterwards.
    pre_restore_payload = await build_backup_payload()
    pre_restore_json = json.dumps(pre_restore_payload, ensure_ascii=False).encode("utf-8")
    pre_restore_content = encrypt_backup_bytes(pre_restore_json, backup_password)
    try:
        pre_restore_filename = _write_pre_restore_backup(pre_restore_content)
    except OSError as e:
        logger.error(f"Could not write pre-restore backup: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Sicherheits-Backup konnte nicht gespeichert werden. Wiederherstellung abgebrochen."
        )

    try:
        await restore_backup_payload(backup_data)
        # Der Index gehoert zur Datenbank, nicht zur Datei - nach dem Einspielen in eine frische
        # Datenbank fehlt er. Jetzt anlegen, solange noch jemand davorsitzt und es liest.
        index = await ensure_itnr_index()
        # Derselbe Grund fuer die Benutzernamen: scheiterte der Index beim Start an Dubletten
        # und bringt die Datei saubere Daten mit, versucht es sonst nie wieder jemand - und
        # die Ersteinrichtung koennte ein zweites Konto "admin" anlegen.
        # Lokal importiert: routes.auth holt sich laeuft_wiederherstellung von hier, ein
        # Import am Dateikopf waere also ein Ringschluss.
        from routes.auth import ensure_username_index

        # Sie meldet ihr Ergebnis nur ins Log, anders als ensure_itnr_index - fuer die
        # Antwort gibt es hier also nichts nachzutragen.
        await ensure_username_index()
        meldungen = list(befund["warnungen"])
        if index["meldung"]:
            meldungen.append(index["meldung"])
        return {
            # Die Warnungen stehen in "message" UND im Feld daneben: die Oberflaeche zeigt
            # inzwischen beides, und wer die Antwort auswertet, soll sie nicht aus einem Satz
            # heraussuchen muessen.
            "message": " ".join(["System-Backup erfolgreich wiederhergestellt."] + meldungen),
            "pre_restore_backup": pre_restore_filename,
            "warnungen": meldungen,
            "fehlende_sammlungen": befund["fehlende_sammlungen"],
            "ohne_bildungsgang": befund["ohne_bildungsgang"],
            "geraete_ohne_itnr": befund["geraete_ohne_itnr"],
            "vor_dem_umbau": befund["vor_dem_umbau"],
            "itnr_index_ok": index["ok"],
            "itnr_duplikate": index["duplikate"],
        }
    except Exception as e:
        logger.error(f"Backup import error, attempting rollback: {str(e)}")
        try:
            await restore_backup_payload(pre_restore_payload)
            raise HTTPException(
                status_code=500,
                detail=(
                    f"Fehler beim Wiederherstellen: {str(e)}. "
                    f"Die vorherigen Daten wurden automatisch wiederhergestellt (Sicherheits-Backup: {pre_restore_filename})."
                ),
            )
        except HTTPException:
            raise
        except Exception as rollback_error:
            logger.error(f"Rollback after failed restore also failed: {str(rollback_error)}")
            raise HTTPException(
                status_code=500,
                detail=(
                    f"Fehler beim Wiederherstellen: {str(e)}. "
                    f"WARNUNG: Automatisches Rollback ist ebenfalls fehlgeschlagen ({str(rollback_error)}). "
                    f"Bitte manuell das Sicherheits-Backup '{pre_restore_filename}' wiederherstellen."
                ),
            )


@api_router.get("/backup/pre-restore-backups")
async def list_pre_restore_backups(current_user: dict = Depends(get_current_user)):
    """List automatically created pre-restore safety backups (admin only)."""
    require_admin(current_user)
    backups_dir = _pre_restore_backups_dir()
    items = []
    for path in sorted(backups_dir.glob("pre_restore_backup_*.json*"), reverse=True):
        stat = path.stat()
        items.append(
            {
                "filename": path.name,
                "size_bytes": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
                "encrypted": path.name.endswith(".enc"),
            }
        )
    return items


@api_router.get("/backup/pre-restore-backups/{filename}/download")
async def download_pre_restore_backup(filename: str, current_user: dict = Depends(get_current_user)):
    """Download a specific pre-restore safety backup (admin only)."""
    require_admin(current_user)
    if not PRE_RESTORE_FILENAME_RE.match(filename):
        raise HTTPException(status_code=400, detail="Ungültiger Dateiname.")

    backups_dir = _pre_restore_backups_dir()
    file_path = (backups_dir / filename).resolve()
    if backups_dir.resolve() not in file_path.parents or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Backup-Datei nicht gefunden.")

    media_type = "application/octet-stream" if filename.endswith(".enc") else "application/json"
    return Response(
        content=file_path.read_bytes(),
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# --- Central backup encryption password (any admin may view its status and set it) ---


@api_router.get("/settings/backup-encryption")
async def get_backup_encryption_settings(current_user: dict = Depends(get_current_user)):
    """Get the backup encryption status (admin only). Never returns the actual password.

    "Gesetzt" heisst: entpackbar. Dass ein Eintrag da ist, sagt noch nichts - siehe
    get_backup_password_state. ``message`` nennt den Fall beim Namen und sagt, was zu tun ist.
    """
    require_admin(current_user)
    zustand, _passwort = await get_backup_password_state()
    return {
        "password_configured": zustand == PASSWORT_BEREIT,
        "password_state": zustand,
        "message": PASSWORT_MELDUNG[zustand],
    }


class BackupPasswordUpdate(BaseModel):
    password: str


def _sicherung_laesst_sich_oeffnen(inhalt: bytes, passwort: str) -> bool:
    """Laesst sich diese Sicherung mit ``passwort`` oeffnen? Blockierend (asyncio.to_thread).

    Eine unverschluesselte Datei aus der Zeit davor zaehlt als lesbar - sie haengt an keinem
    Passwort. Geprueft wird mit decrypt_backup_bytes, also auf demselben Weg, den auch die
    Wiederherstellung geht: eine zweite, eigene Pruefmechanik koennte anderes behaupten als
    das, was spaeter tatsaechlich passiert.
    """
    if not is_encrypted_backup(inhalt):
        return True
    try:
        decrypt_backup_bytes(inhalt, passwort)
        return True
    except ValueError:
        return False


def _sicherungen_satz(anzahl: int) -> str:
    """ "1 vorhandene Sicherung lässt sich" bzw. "N vorhandene Sicherungen lassen sich"."""
    if anzahl == 1:
        return "1 vorhandene Sicherung lässt sich"
    return f"{anzahl} vorhandene Sicherungen lassen sich"


async def _sicherungen_mit_passwort_pruefen(passwort: str) -> dict:
    """Zaehlen, wie viele vorhandene Sicherungen sich mit ``passwort`` noch oeffnen lassen.

    Geprueft wird, was dieser Server selbst vorhaelt: die Tagesbackups in GridFS und die
    Sicherheitsnetze auf der Platte. Die Dateikopien in SERVER_BACKUP_FILE_DIR bleiben aussen
    vor: sie sind Byte fuer Byte dasselbe wie der GridFS-Stand und wuerden die Zahl verdoppeln.
    Betroffen sind sie genauso, deshalb nennt die Meldung sie ausdruecklich.

    Jede Datei traegt ihr eigenes Salz, also braucht jede ihre eigene Schluesselableitung
    (PBKDF2, bewusst langsam). Bezahlbar bleibt das nur, weil das Aufraeumen die Zahl der
    Sicherungen begrenzt (SERVER_BACKUP_RETENTION_DAYS, PRE_RESTORE_KEEP_COUNT) und weil ein
    Admin ein Backup-Passwort selten setzt. Die Ableitung laeuft im Thread, damit der
    Tagesjob und der Healthcheck waehrenddessen weiterkommen.
    """
    gesamt = 0
    unlesbar = 0
    ungeprueft = 0

    bucket = _backups_gridfs_bucket()
    async for doc in db["backups.files"].find({}, {"_id": 1}).sort("uploadDate", -1):
        gesamt += 1
        try:
            stream = await bucket.open_download_stream(doc["_id"])
            inhalt = await stream.read()
        except Exception as e:
            logger.error(f"Sicherung {doc['_id']} liess sich zum Pruefen nicht lesen: {str(e)}")
            ungeprueft += 1
            continue
        if not await asyncio.to_thread(_sicherung_laesst_sich_oeffnen, inhalt, passwort):
            unlesbar += 1

    for pfad in sorted(_pre_restore_backups_dir().glob("pre_restore_backup_*.json*"), reverse=True):
        gesamt += 1
        try:
            inhalt = pfad.read_bytes()
        except OSError as e:
            logger.error(f"Sicherheitsnetz {pfad.name} liess sich zum Pruefen nicht lesen: {str(e)}")
            ungeprueft += 1
            continue
        if not await asyncio.to_thread(_sicherung_laesst_sich_oeffnen, inhalt, passwort):
            unlesbar += 1

    return {"gesamt": gesamt, "unlesbar": unlesbar, "ungeprueft": ungeprueft}


@api_router.put("/settings/backup-encryption")
async def set_backup_encryption_password(payload: BackupPasswordUpdate, current_user: dict = Depends(get_current_user)):
    """Set/update the central backup encryption password (any admin may do this).

    Die Antwort sagt ausserdem, was der Wechsel das Archiv kostet. Ein neues Passwort repariert
    zwar den Backup-Lauf, macht aber jede vorhandene Sicherung dauerhaft unlesbar: sie ist mit
    dem alten Passwort verschluesselt, und nachtraeglich umschluesseln kann das niemand. "Backup-
    Passwort erfolgreich gesetzt" allein verschweigt genau das. Wer dasselbe Passwort wie zuvor
    setzt - der Weg, um einen nicht mehr entpackbaren Eintrag zu reparieren -, behaelt sein
    Archiv; dann darf auch keine Warnung kommen. Beides laesst sich nur sagen, indem die
    vorhandenen Sicherungen mit dem NEUEN Passwort probeweise geoeffnet werden: der hinterlegte
    Eintrag ist in genau diesem Fall ja nicht mehr zu entpacken und taugt nicht zum Vergleich.
    """
    require_admin(current_user)
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Das Backup-Passwort muss mindestens 8 Zeichen lang sein")

    await db.global_settings.update_one(
        {"type": "backup_encryption"},
        {"$set": {"wrapped_password": wrap_secret(payload.password), "updated_at": datetime.now(UTC).isoformat()}},
        upsert=True,
    )

    # Erst setzen, dann pruefen und berichten: das Setzen ist die Reparatur und darf an einer
    # Auskunft nicht scheitern - auch nicht daran, dass sich eine einzelne Sicherung nicht
    # lesen laesst.
    try:
        befund = await _sicherungen_mit_passwort_pruefen(payload.password)
    except Exception as e:
        logger.error(f"Vorhandene Sicherungen konnten nicht geprüft werden: {str(e)}")
        befund = {"gesamt": None, "unlesbar": None, "ungeprueft": None}

    meldung = "Backup-Passwort erfolgreich gesetzt. Zukünftige Backups werden damit verschlüsselt."
    if befund["unlesbar"] is None:
        meldung += (
            " Ob sich die vorhandenen Sicherungen mit dem neuen Passwort noch öffnen lassen, konnte "
            "nicht geprüft werden (siehe Server-Protokoll)."
        )
    elif befund["unlesbar"]:
        meldung += (
            f" ACHTUNG: {_sicherungen_satz(befund['unlesbar'])} mit dem neuen Passwort nicht mehr "
            "öffnen - dafür wird weiterhin das vorherige gebraucht, und nachträglich umschlüsseln "
            "lässt sich nichts. Das gilt auch für die Dateikopien außer Haus. Bitte das alte "
            "Passwort aufbewahren, solange diese Sicherungen noch von Wert sind."
        )
    else:
        lesbar = befund["gesamt"] - befund["ungeprueft"]
        if lesbar:
            meldung += f" {_sicherungen_satz(lesbar)} damit weiterhin öffnen."
    if befund["ungeprueft"]:
        meldung += f" Bei {befund['ungeprueft']} Sicherungen ließ sich das nicht prüfen (siehe Server-Protokoll)."

    return {
        "message": meldung,
        "sicherungen_gesamt": befund["gesamt"],
        "sicherungen_unlesbar": befund["unlesbar"],
        "sicherungen_ungeprueft": befund["ungeprueft"],
    }


BACKUP_SCHEDULE_CHECK_INTERVAL_SECONDS = 3600  # check hourly whether the daily backup is due


async def _record_schedule_failure(settings_type: str, message: str):
    """Record a failed scheduled run without touching ``last_run_at`` or ``last_completed_at``,
    so the next hourly tick retries instead of the failure silently counting as "done for
    today"."""
    await db.global_settings.update_one(
        {"type": settings_type},
        {
            "$set": {
                "last_attempt_at": datetime.now(UTC).isoformat(),
                "last_status": "error",
                "last_error": message,
            }
        },
        upsert=True,
    )


# --- Daily server-side backup, stored in MongoDB via GridFS and as a file copy on the host. ---

SERVER_BACKUP_RETENTION_DAYS = 20
# Dritter Wert neben "success" und "error": der Tageslauf ist durchgelaufen, hat aber nichts
# geschrieben, weil sich seit der letzten Sicherung nichts geaendert hat. Als "success" verbucht
# haette er behauptet, es sei heute eine Sicherung entstanden - und genau darauf sieht, wer
# wissen will, wie frisch die neueste ist.
SERVER_BACKUP_STATUS_UNVERAENDERT = "unveraendert"
# Beim Aufraeumen immer behalten, unabhaengig vom Alter. Noetig wegen der Entdoppelung weiter
# unten: aendert sich ueber Wochen nichts (Ferien), entstehen keine neuen Backups - ohne diese
# Untergrenze wuerden die vorhandenen nacheinander wegaltern, bis gar keines mehr da ist.
SERVER_BACKUP_KEEP_MINIMUM = 3

# Feste Uhrzeit statt "24 Stunden nach dem letzten Lauf": letzteres liess die Uhrzeit taeglich
# um bis zu eine Stunde wandern, wodurch das Backup irgendwann hinter die Abholung durch den
# Mac rutschte. Der Container laeuft auf UTC, deshalb ausdruecklich die hiesige Zeitzone.
SERVER_BACKUP_HOUR = int(os.environ.get("SERVER_BACKUP_HOUR", 16))
SERVER_BACKUP_TIMEZONE = ZoneInfo(os.environ.get("SERVER_BACKUP_TZ", "Europe/Berlin"))
# Nach laengerem Ausfall sofort nachholen, statt bis zur naechsten Uhrzeit zu warten.
SERVER_BACKUP_CATCHUP_AFTER_DAYS = 2


def _server_backup_due(state: dict, now_local: Optional[datetime] = None) -> bool:
    """True if today's run is still open and the configured hour has passed.

    Massgeblich ist ``last_completed_at``, nicht ``last_run_at``: ein Lauf, der nichts
    geschrieben hat, weil der Bestand unveraendert war, ist fuer heute trotzdem erledigt.
    Wuerde hier der Zeitpunkt der letzten geschriebenen Sicherung zaehlen, baute der Job in
    unveraenderten Wochen (Ferien) zu jedem stuendlichen Tick den gesamten Bestand neu
    zusammen und verschluesselte ihn, nur um ihn wieder wegzuwerfen.

    Ein fehlgeschlagener Lauf laesst beide Zeitpunkte unberuehrt (siehe
    _record_schedule_failure) und gilt hier deshalb weiter als "heute noch nichts" - er wird
    beim naechsten stuendlichen Tick erneut versucht. ``now_local`` dient nur dem Test.
    """
    now_local = now_local or datetime.now(SERVER_BACKUP_TIMEZONE)
    # Vor diesem Feld stand nur last_run_at im Bestand; ohne den Rueckgriff liefe nach dem
    # Aufspielen einmal ein Lauf los, der nicht faellig ist.
    last = _parse_iso_utc(state.get("last_completed_at") or state.get("last_run_at"))
    if last is None:
        return True
    last_local = last.astimezone(SERVER_BACKUP_TIMEZONE)
    if (now_local.date() - last_local.date()).days >= SERVER_BACKUP_CATCHUP_AFTER_DAYS:
        return True
    if now_local.hour < SERVER_BACKUP_HOUR:
        return False
    return last_local.date() < now_local.date()


# Zusaetzliche Dateikopie jedes Tagesbackups. Das Verzeichnis ist aus dem Host in den
# Container gemountet, damit ein Sync-Werkzeug auf Betriebssystemebene (rclone/rsync)
# die Dateien abholen und ausser Haus schieben kann - siehe scripts/sync-backups.sh.
# Bewusst ausserhalb der Anwendung: der Transport muss auch dann noch funktionieren,
# wenn die Anwendung selbst defekt ist, und die Zugangsdaten bleiben im Betriebssystem.
SERVER_BACKUP_FILE_DIR = Path(os.environ.get("SERVER_BACKUP_DIR", "/app/backups"))
SERVER_BACKUP_FILENAME_RE = re.compile(r"^rbbk_ipad_verwaltung_backup_.+\.json(\.enc)?$")


def _backups_gridfs_bucket() -> AsyncIOMotorGridFSBucket:
    return AsyncIOMotorGridFSBucket(db, bucket_name="backups")


def _prune_server_backup_files():
    """Delete file copies older than the retention window, but never below the minimum count."""
    cutoff = datetime.now(UTC) - timedelta(days=SERVER_BACKUP_RETENTION_DAYS)
    candidates = sorted(
        (
            f
            for f in SERVER_BACKUP_FILE_DIR.glob("rbbk_ipad_verwaltung_backup_*")
            if SERVER_BACKUP_FILENAME_RE.match(f.name)
        ),
        key=lambda f: f.name,
    )
    # Die jüngsten nach Dateinamen (der traegt den Zeitstempel) sind geschuetzt.
    protected = set(candidates[-SERVER_BACKUP_KEEP_MINIMUM:])
    for old in candidates:
        if old in protected:
            continue
        try:
            if datetime.fromtimestamp(old.stat().st_mtime, UTC) < cutoff:
                old.unlink()
        except OSError as e:
            logger.error(f"Could not prune old backup file {old}: {str(e)}")


def _write_server_backup_file(content_bytes: bytes, filename: str) -> str:
    """Write the backup to the host-mounted directory the off-site sync picks up.

    Blocking (run via ``asyncio.to_thread``). Raises OSError; callers treat a failure here as
    a warning rather than a failed backup, because the GridFS copy already succeeded.
    """
    SERVER_BACKUP_FILE_DIR.mkdir(parents=True, exist_ok=True)
    target = SERVER_BACKUP_FILE_DIR / filename
    target.write_bytes(content_bytes)
    # 640 statt 600: die Anwendung schreibt als root, abgeholt werden die Backups aber von
    # einem unprivilegierten Konto (siehe scripts/BACKUP-OFFSITE.md). Damit das traegt, muss
    # das Verzeichnis setgid sein und der passenden Gruppe gehoeren - dann erbt jede neue
    # Datei diese Gruppe. Ohne setgid waere sie root:root und fuer die Abholung unlesbar.
    target.chmod(0o640)
    _prune_server_backup_files()
    return str(target)


async def save_server_backup(skip_if_unchanged: bool = False) -> dict:
    """Create a server-side backup snapshot in GridFS plus a file copy, and prune old ones.

    With ``skip_if_unchanged`` the run is skipped when the data is byte-identical to the last
    backup - compared via a checksum of the plaintext, since the encrypted files differ every
    time (random salt/IV) and their size says nothing about their content. Used by the daily
    job; the manual button always writes, so "Jetzt erstellen" does what it says.
    """
    content_bytes, filename, is_encrypted, payload_sha256 = await build_backup_export_bytes()

    if skip_if_unchanged:
        state = await db.global_settings.find_one({"type": "server_backup_state"}) or {}
        if state.get("last_payload_sha256") == payload_sha256:
            logger.info("Daily server-side backup skipped: data unchanged since the last backup")
            return {"skipped": True, "reason": "unveraendert", "payload_sha256": payload_sha256}

    bucket = _backups_gridfs_bucket()
    file_id = await bucket.upload_from_stream(
        filename,
        content_bytes,
        metadata={"encrypted": is_encrypted, "created_at": datetime.now(UTC).isoformat()},
    )

    cutoff = datetime.now(UTC) - timedelta(days=SERVER_BACKUP_RETENTION_DAYS)
    newest = (
        await db["backups.files"].find({}, {"_id": 1}).sort("uploadDate", -1).to_list(length=SERVER_BACKUP_KEEP_MINIMUM)
    )
    protected = {d["_id"] for d in newest}
    cursor = db["backups.files"].find({"uploadDate": {"$lt": cutoff}}, {"_id": 1})
    async for old_file in cursor:
        if old_file["_id"] in protected:
            continue
        try:
            await bucket.delete(old_file["_id"])
        except Exception as e:
            logger.error(f"Could not prune old server backup {old_file['_id']}: {str(e)}")

    result = {
        "file_id": str(file_id),
        "filename": filename,
        "encrypted": is_encrypted,
        "skipped": False,
        "payload_sha256": payload_sha256,
    }

    # Dateikopie fuer die Uebertragung ausser Haus. Schlaegt sie fehl, ist das Backup selbst
    # trotzdem gelungen (GridFS) - deshalb nur vermerken, nicht den ganzen Lauf scheitern lassen.
    try:
        result["file_path"] = await asyncio.to_thread(_write_server_backup_file, content_bytes, filename)
        result["file_error"] = None
    except OSError as e:
        logger.error(f"Could not write backup file copy to {SERVER_BACKUP_FILE_DIR}: {str(e)}")
        result["file_path"] = None
        result["file_error"] = f"Dateikopie nach {SERVER_BACKUP_FILE_DIR} fehlgeschlagen: {str(e)}"

    return result


def _mit_zeitzone_iso(wert):
    """Einen Zeitstempel aus der Datenbank mit Zeitzone ausliefern.

    GridFS legt uploadDate als UTC OHNE Zeitzone ab, und so kommt es auch aus dem Treiber
    zurueck. Ohne Kennzeichen liest der Browser den Zeitstempel als Ortszeit, waehrend
    last_run_at daneben "+00:00" traegt und richtig umgerechnet wird - dieselbe Sicherung
    erschien dadurch an zwei um den Zeitzonenversatz verschobenen Zeitpunkten. Was keine
    Zeitangabe ist, geht unveraendert durch.
    """
    if isinstance(wert, datetime):
        return (wert if wert.tzinfo else wert.replace(tzinfo=UTC)).isoformat()
    return wert


@api_router.get("/backup/server-backups")
async def list_server_backups(current_user: dict = Depends(get_current_user)):
    """List the daily server-side backups stored in MongoDB (admin only).

    Wie weit die Liste zurueckreicht, sagt das Aufraeumen in save_server_backup:
    SERVER_BACKUP_RETENTION_DAYS, mindestens aber SERVER_BACKUP_KEEP_MINIMUM Sicherungen.
    """
    require_admin(current_user)
    items = []
    cursor = db["backups.files"].find({}).sort("uploadDate", -1)
    async for doc in cursor:
        items.append(
            {
                "id": str(doc["_id"]),
                "filename": doc["filename"],
                "size_bytes": doc.get("length", 0),
                "created_at": _mit_zeitzone_iso(doc.get("uploadDate")),
                "encrypted": bool((doc.get("metadata") or {}).get("encrypted")),
            }
        )
    return items


@api_router.get("/backup/server-backups/{file_id}/download")
async def download_server_backup(file_id: str, current_user: dict = Depends(get_current_user)):
    """Download a specific server-side backup from MongoDB (admin only)."""
    require_admin(current_user)
    try:
        object_id = ObjectId(file_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Ungültige Backup-ID.")

    doc = await db["backups.files"].find_one({"_id": object_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Server-Backup nicht gefunden.")

    bucket = _backups_gridfs_bucket()
    try:
        stream = await bucket.open_download_stream(object_id)
        content = await stream.read()
    except Exception:
        raise HTTPException(status_code=404, detail="Server-Backup nicht gefunden.")

    is_encrypted = bool((doc.get("metadata") or {}).get("encrypted"))
    media_type = "application/octet-stream" if is_encrypted else "application/json"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={doc['filename']}"},
    )


@api_router.get("/backup/server-backups/status")
async def get_server_backup_status(current_user: dict = Depends(get_current_user)):
    """Last run/result of the daily server-side backup (admin only).

    Without this the daily job could fail every night without anything surfacing in the UI -
    the backup list simply stayed empty.

    Die drei Zeitpunkte sagen Verschiedenes: ``last_run_at`` ist die letzte GESCHRIEBENE
    Sicherung, ``last_completed_at`` der letzte Lauf, der ohne Fehler durchkam (auch der
    uebersprungene, siehe SERVER_BACKUP_STATUS_UNVERAENDERT), ``last_attempt_at`` auch der
    gescheiterte Versuch. Wie frisch die neueste Sicherung ist, sagt allein last_run_at.
    """
    require_admin(current_user)
    state = await db.global_settings.find_one({"type": "server_backup_state"}) or {}
    # Fehlt der eindeutige Index - etwa nach einer Wiederherstellung in eine frische Datenbank -,
    # steht das sonst nur als Logzeile vom letzten Start irgendwo im Container.
    index = await itnr_index_status()
    return {
        "last_run_at": state.get("last_run_at"),
        "last_completed_at": state.get("last_completed_at"),
        "last_attempt_at": state.get("last_attempt_at"),
        "last_status": state.get("last_status"),
        "last_error": state.get("last_error"),
        "last_file_path": state.get("last_file_path"),
        "last_file_error": state.get("last_file_error"),
        "itnr_index_ok": index["ok"],
        "itnr_duplikate": index["duplikate"],
        "itnr_index_meldung": index["meldung"],
    }


@api_router.post("/backup/server-backups/run-now")
async def run_server_backup_now(current_user: dict = Depends(get_current_user)):
    """Manually trigger the daily server-side backup immediately (admin only)."""
    require_admin(current_user)
    try:
        result = await save_server_backup()
        now_iso = datetime.now(UTC).isoformat()
        await db.global_settings.update_one(
            {"type": "server_backup_state"},
            {
                "$set": {
                    "last_run_at": now_iso,
                    "last_attempt_at": now_iso,
                    # Von Hand ausgeloest, aber ein geschriebener Lauf wie jeder andere: damit ist
                    # der Tag erledigt und der Job um 16 Uhr faengt nicht noch einmal an.
                    "last_completed_at": now_iso,
                    "last_status": "success",
                    "last_error": None,
                    "last_file_path": result.get("file_path"),
                    "last_file_error": result.get("file_error"),
                    "last_payload_sha256": result.get("payload_sha256"),
                }
            },
            upsert=True,
        )
        return {"message": "Server-Backup erfolgreich erstellt.", **result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Manual server backup failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Fehler beim Erstellen des Server-Backups: {str(e)}")


async def run_scheduled_server_backup_check():
    """Create the daily server-side backup once per day from SERVER_BACKUP_HOUR onwards
    (always on). A failed run is retried on the next hourly tick.

    Ist der Bestand unveraendert, entsteht keine neue Sicherung; der Lauf wird dann auch nicht
    als geschriebener verbucht (SERVER_BACKUP_STATUS_UNVERAENDERT)."""
    state = await db.global_settings.find_one({"type": "server_backup_state"}) or {}
    if not _server_backup_due(state):
        return

    try:
        result = await save_server_backup(skip_if_unchanged=True)
        now_iso = datetime.now(UTC).isoformat()
        # Erledigt ist der Tageslauf in beiden Faellen - danach richtet sich, ob der naechste
        # stuendliche Tick noch einmal anfaengt. Geschrieben wurde nur im einen, und nur dann
        # darf last_run_at vorruecken: sonst meldete der Status eine Sicherung von heute,
        # waehrend die neueste in Wirklichkeit Wochen alt ist. Dasselbe gilt fuer die
        # Dateikopie - ohne neue Sicherung gibt es auch keinen neuen Pfad und keinen neuen
        # Fehler dazu, der alte Vermerk bleibt stehen.
        update = {
            "last_attempt_at": now_iso,
            "last_completed_at": now_iso,
            "last_error": None,
            "last_payload_sha256": result.get("payload_sha256"),
        }
        if result.get("skipped"):
            update["last_status"] = SERVER_BACKUP_STATUS_UNVERAENDERT
        else:
            update["last_run_at"] = now_iso
            update["last_status"] = "success"
            update["last_file_path"] = result.get("file_path")
            update["last_file_error"] = result.get("file_error")
        await db.global_settings.update_one({"type": "server_backup_state"}, {"$set": update}, upsert=True)
        if result.get("skipped"):
            logger.info("Daily server-side backup: data unchanged, no new snapshot written")
        else:
            logger.info(f"Daily server-side backup created ({result.get('file_path') or 'nur GridFS'})")
    except Exception as e:
        logger.error(f"Daily server-side backup failed: {str(e)}")
        await _record_schedule_failure("server_backup_state", str(e))


async def backup_scheduler_loop():
    """Background task: hourly check whether the daily server-side backup is due."""
    await asyncio.sleep(60)  # let the app finish starting up first
    while True:
        try:
            await run_scheduled_server_backup_check()
        except Exception as e:
            logger.error(f"Server backup scheduler loop error: {str(e)}")
        await asyncio.sleep(BACKUP_SCHEDULE_CHECK_INTERVAL_SECONDS)
