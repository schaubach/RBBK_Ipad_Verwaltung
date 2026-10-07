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
import json
import hashlib
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from bson import ObjectId
from bson.binary import Binary
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
from fastapi import Depends, File, HTTPException, UploadFile
from fastapi.responses import Response
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pydantic import BaseModel

logger = logging.getLogger(__name__)

COLLECTIONS = ["users", "students", "ipads", "assignments", "contracts", "global_settings"]
BACKUP_TYPE_KEY = "__rbbk_backup_type"


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
    """Overwrite COLLECTIONS with the given (already deserialized-ready) backup payload."""
    for coll_name, records in backup_data.items():
        if coll_name in COLLECTIONS:
            decoded_records = []
            for record in records:
                decoded_record = deserialize_backup_value(record)
                if "_id" in decoded_record and isinstance(decoded_record["_id"], str):
                    try:
                        decoded_record["_id"] = ObjectId(decoded_record["_id"])
                    except Exception:
                        del decoded_record["_id"]
                decoded_records.append(decoded_record)
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
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


async def get_active_backup_password() -> Optional[str]:
    """Return the currently configured (central) backup encryption password, unwrapped, or None if unset."""
    settings = await db.global_settings.find_one({"type": "backup_encryption"})
    if not settings or not settings.get("wrapped_password"):
        return None
    return unwrap_secret(settings["wrapped_password"])


def _serialize_and_encrypt(backup_data: dict, password: str) -> tuple:
    """Blocking JSON serialisation + encryption (run via ``asyncio.to_thread``).

    Returns (encrypted_bytes, sha256_of_plaintext). The checksum is taken BEFORE encryption on
    purpose: every encryption uses a fresh random salt and IV, so two backups of byte-identical
    data produce completely different ciphertext of identical length. Comparing the encrypted
    files - or their sizes - can therefore never tell duplicates apart.
    """
    json_bytes = json.dumps(backup_data, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return encrypt_backup_bytes(json_bytes, password), hashlib.sha256(json_bytes).hexdigest()


async def build_backup_export_bytes() -> tuple:
    """Build the current backup as encrypted bytes. Raises ValueError if no backup password is
    configured - backups contain student data (Schülerdaten) and must never leave the server
    (download, server-side archive) unencrypted.
    Returns (content_bytes, filename, is_encrypted, sha256_of_plaintext)."""
    password = await get_active_backup_password()
    if not password:
        raise ValueError(
            "Kein Backup-Passwort konfiguriert. Da Backups Schülerdaten enthalten, ist ein Backup-Passwort "
            "erforderlich (siehe Admin-Tab > Backup-Sicherheit: Backup-Passwort setzen)."
        )
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
    password = await get_active_backup_password()
    if not password:
        raise ValueError(
            "Diese Datei ist verschlüsselt, aber es ist aktuell kein Backup-Passwort konfiguriert "
            "(siehe Admin-Tab > Backup-Sicherheit)."
        )
    return decrypt_backup_bytes(content, password)


# --- Pre-restore safety backups: written to disk before every /backup/import so a failed
# or unwanted restore can be rolled back / manually recovered. ---
PRE_RESTORE_BACKUPS_DIR = ROOT_DIR / "uploads" / "backups"
PRE_RESTORE_FILENAME_RE = re.compile(r"^pre_restore_backup_\d{8}_\d{6}\.json(\.enc)?$")
PRE_RESTORE_KEEP_COUNT = 5


def _pre_restore_backups_dir() -> Path:
    PRE_RESTORE_BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    return PRE_RESTORE_BACKUPS_DIR


def _write_pre_restore_backup(content_bytes: bytes, encrypted: bool = False) -> str:
    """Persist a pre-restore snapshot to disk and prune old ones. Returns the filename."""
    backups_dir = _pre_restore_backups_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"pre_restore_backup_{timestamp}.json" + (".enc" if encrypted else "")
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


@api_router.post("/backup/import")
async def import_backup(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """Restores the database from a backup file (plain .json or encrypted .json.enc). Only
    accessible by administrators. Warning: this overwrites existing data. A pre-restore safety
    snapshot is always written first and used to automatically roll back on failure."""
    require_admin(current_user)
    if not (file.filename.endswith(".json") or file.filename.endswith(".json.enc")):
        raise HTTPException(status_code=400, detail="Es muss eine .json oder verschlüsselte .json.enc Datei hochgeladen werden.")

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

    # Safety net: snapshot current data BEFORE touching anything, so a failed or unwanted
    # restore can be rolled back / manually recovered afterwards.
    pre_restore_payload = await build_backup_payload()
    pre_restore_json = json.dumps(pre_restore_payload, ensure_ascii=False).encode("utf-8")
    backup_password = await get_active_backup_password()
    pre_restore_content = encrypt_backup_bytes(pre_restore_json, backup_password) if backup_password else pre_restore_json
    try:
        pre_restore_filename = _write_pre_restore_backup(pre_restore_content, encrypted=bool(backup_password))
    except OSError as e:
        logger.error(f"Could not write pre-restore backup: {str(e)}")
        raise HTTPException(status_code=500, detail="Sicherheits-Backup konnte nicht gespeichert werden. Wiederherstellung abgebrochen.")

    try:
        await restore_backup_payload(backup_data)
        return {
            "message": "System-Backup erfolgreich wiederhergestellt.",
            "pre_restore_backup": pre_restore_filename,
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
        items.append({
            "filename": path.name,
            "size_bytes": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "encrypted": path.name.endswith(".enc"),
        })
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
    """Get the backup encryption status (admin only). Never returns the actual password."""
    require_admin(current_user)
    settings = await db.global_settings.find_one({"type": "backup_encryption"})
    return {"password_configured": bool(settings and settings.get("wrapped_password"))}


class BackupPasswordUpdate(BaseModel):
    password: str


@api_router.put("/settings/backup-encryption")
async def set_backup_encryption_password(payload: BackupPasswordUpdate, current_user: dict = Depends(get_current_user)):
    """Set/update the central backup encryption password (any admin may do this)."""
    require_admin(current_user)
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Das Backup-Passwort muss mindestens 8 Zeichen lang sein")

    await db.global_settings.update_one(
        {"type": "backup_encryption"},
        {"$set": {"wrapped_password": wrap_secret(payload.password), "updated_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True,
    )
    return {"message": "Backup-Passwort erfolgreich gesetzt. Zukünftige Backups werden damit verschlüsselt."}


BACKUP_SCHEDULE_CHECK_INTERVAL_SECONDS = 3600  # check hourly whether the daily backup is due
BACKUP_RETRY_AFTER_ERROR = timedelta(hours=1)  # a failed run retries on the next tick, not a day later
async def _record_schedule_failure(settings_type: str, message: str):
    """Record a failed scheduled run without touching ``last_run_at``, so the next hourly tick
    retries instead of the failure silently counting as "done for today"."""
    await db.global_settings.update_one(
        {"type": settings_type},
        {"$set": {
            "last_attempt_at": datetime.now(timezone.utc).isoformat(),
            "last_status": "error",
            "last_error": message,
        }},
        upsert=True,
    )


def _is_due(state: dict, interval: timedelta) -> bool:
    """True if the job is due: never succeeded, last success older than ``interval``, or the last
    attempt failed and the retry delay has passed."""
    now = datetime.now(timezone.utc)
    if state.get("last_status") == "error":
        last_attempt = _parse_iso_utc(state.get("last_attempt_at")) or _parse_iso_utc(state.get("last_run_at"))
        return last_attempt is None or now - last_attempt >= BACKUP_RETRY_AFTER_ERROR
    last_run = _parse_iso_utc(state.get("last_run_at"))
    return last_run is None or now - last_run >= interval


# --- Daily server-side backup, stored in MongoDB via GridFS (survives independently of the
# host filesystem/volume). Always runs regardless of the e-mail schedule; retains 7 days. ---

SERVER_BACKUP_RETENTION_DAYS = 20
# Beim Aufraeumen immer behalten, unabhaengig vom Alter. Noetig wegen der Entdoppelung weiter
# unten: aendert sich ueber Wochen nichts (Ferien), entstehen keine neuen Backups - ohne diese
# Untergrenze wuerden die vorhandenen nacheinander wegaltern, bis gar keines mehr da ist.
SERVER_BACKUP_KEEP_MINIMUM = 3

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
    cutoff = datetime.now(timezone.utc) - timedelta(days=SERVER_BACKUP_RETENTION_DAYS)
    candidates = sorted(
        (f for f in SERVER_BACKUP_FILE_DIR.glob("rbbk_ipad_verwaltung_backup_*")
         if SERVER_BACKUP_FILENAME_RE.match(f.name)),
        key=lambda f: f.name,
    )
    # Die jüngsten nach Dateinamen (der traegt den Zeitstempel) sind geschuetzt.
    protected = set(candidates[-SERVER_BACKUP_KEEP_MINIMUM:])
    for old in candidates:
        if old in protected:
            continue
        try:
            if datetime.fromtimestamp(old.stat().st_mtime, timezone.utc) < cutoff:
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
        metadata={"encrypted": is_encrypted, "created_at": datetime.now(timezone.utc).isoformat()},
    )

    cutoff = datetime.now(timezone.utc) - timedelta(days=SERVER_BACKUP_RETENTION_DAYS)
    newest = await db["backups.files"].find({}, {"_id": 1}).sort("uploadDate", -1).to_list(
        length=SERVER_BACKUP_KEEP_MINIMUM
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

    result = {"file_id": str(file_id), "filename": filename, "encrypted": is_encrypted,
              "skipped": False, "payload_sha256": payload_sha256}

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


@api_router.get("/backup/server-backups")
async def list_server_backups(current_user: dict = Depends(get_current_user)):
    """List the daily server-side backups stored in MongoDB (admin only, last 7 days retained)."""
    require_admin(current_user)
    items = []
    cursor = db["backups.files"].find({}).sort("uploadDate", -1)
    async for doc in cursor:
        items.append({
            "id": str(doc["_id"]),
            "filename": doc["filename"],
            "size_bytes": doc.get("length", 0),
            "created_at": doc["uploadDate"].isoformat() if hasattr(doc["uploadDate"], "isoformat") else doc["uploadDate"],
            "encrypted": bool((doc.get("metadata") or {}).get("encrypted")),
        })
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
    """
    require_admin(current_user)
    state = await db.global_settings.find_one({"type": "server_backup_state"}) or {}
    return {
        "last_run_at": state.get("last_run_at"),
        "last_attempt_at": state.get("last_attempt_at"),
        "last_status": state.get("last_status"),
        "last_error": state.get("last_error"),
        "last_file_path": state.get("last_file_path"),
        "last_file_error": state.get("last_file_error"),
    }


@api_router.post("/backup/server-backups/run-now")
async def run_server_backup_now(current_user: dict = Depends(get_current_user)):
    """Manually trigger the daily server-side backup immediately (admin only)."""
    require_admin(current_user)
    try:
        result = await save_server_backup()
        now_iso = datetime.now(timezone.utc).isoformat()
        await db.global_settings.update_one(
            {"type": "server_backup_state"},
            {"$set": {
                "last_run_at": now_iso,
                "last_attempt_at": now_iso,
                "last_status": "success",
                "last_error": None,
                "last_file_path": result.get("file_path"),
                "last_file_error": result.get("file_error"),
                "last_payload_sha256": result.get("payload_sha256"),
            }},
            upsert=True,
        )
        return {"message": "Server-Backup erfolgreich erstellt.", **result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Manual server backup failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Fehler beim Erstellen des Server-Backups: {str(e)}")


async def run_scheduled_server_backup_check():
    """Create the daily server-side backup if the last successful one is more than a day old
    (always on). A failed run is retried on the next hourly tick."""
    state = await db.global_settings.find_one({"type": "server_backup_state"}) or {}
    if not _is_due(state, timedelta(days=1)):
        return

    try:
        result = await save_server_backup(skip_if_unchanged=True)
        now_iso = datetime.now(timezone.utc).isoformat()
        update = {
            "last_run_at": now_iso,
            "last_attempt_at": now_iso,
            "last_status": "success",
            "last_error": None,
            "last_payload_sha256": result.get("payload_sha256"),
        }
        if not result.get("skipped"):
            update["last_file_path"] = result.get("file_path")
            update["last_file_error"] = result.get("file_error")
        await db.global_settings.update_one(
            {"type": "server_backup_state"}, {"$set": update}, upsert=True
        )
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
