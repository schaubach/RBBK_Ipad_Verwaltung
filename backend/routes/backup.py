"""Backup routes (/api/backup/*, /api/settings/backup-schedule, /api/settings/smtp-config,
/api/settings/backup-encryption).

Auto-extracted from monolithic server.py during refactor (Session 12), later extended with
backup encryption, SMTP-config-in-DB, pre-restore safety backups and daily server-side
(GridFS) backups.
"""

import asyncio
import base64
import json
import logging
import re
import smtplib
from datetime import datetime, timedelta, timezone
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
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
from pydantic import BaseModel, EmailStr

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


async def get_active_backup_password() -> Optional[str]:
    """Return the currently configured (central) backup encryption password, unwrapped, or None if unset."""
    settings = await db.global_settings.find_one({"type": "backup_encryption"})
    if not settings or not settings.get("wrapped_password"):
        return None
    return unwrap_secret(settings["wrapped_password"])


async def build_backup_export_bytes() -> tuple:
    """Build the current backup as encrypted bytes. Raises ValueError if no backup password is
    configured - backups contain student data (Schülerdaten) and must never leave the server
    (download, e-mail, server-side archive) unencrypted. Returns (content_bytes, filename, is_encrypted)."""
    password = await get_active_backup_password()
    if not password:
        raise ValueError(
            "Kein Backup-Passwort konfiguriert. Da Backups Schülerdaten enthalten, ist ein Backup-Passwort "
            "erforderlich (siehe Admin-Tab > Backup-Sicherheit: Backup-Passwort setzen)."
        )
    backup_data = await build_backup_payload()
    json_bytes = json.dumps(backup_data, ensure_ascii=False).encode("utf-8")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return encrypt_backup_bytes(json_bytes, password), f"rbbk_ipad_verwaltung_backup_{timestamp}.json.enc", True


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
        content_bytes, filename, is_encrypted = await build_backup_export_bytes()
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


# --- Central backup encryption password (any admin may view status / set it, same pattern as
# the SMTP configuration below) ---

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


# --- SMTP configuration (DB-backed, falls back to backend/.env) ---

def _smtp_config_from_env() -> dict:
    import os

    return {
        "host": os.environ.get("SMTP_HOST", ""),
        "port": int(os.environ.get("SMTP_PORT") or 587),
        "user": os.environ.get("SMTP_USER", ""),
        "password": os.environ.get("SMTP_PASSWORD", ""),
        "from_addr": os.environ.get("SMTP_FROM") or os.environ.get("SMTP_USER", ""),
        "use_tls": os.environ.get("SMTP_USE_TLS", "true").lower() != "false",
    }


async def get_smtp_config() -> dict:
    """SMTP config, preferring the DB (settable via the Admin UI) over backend/.env."""
    settings = await db.global_settings.find_one({"type": "smtp_config"})
    if settings and settings.get("host"):
        return {
            "host": settings.get("host", ""),
            "port": int(settings.get("port") or 587),
            "user": settings.get("user", ""),
            "password": unwrap_secret(settings["wrapped_password"]) if settings.get("wrapped_password") else "",
            "from_addr": settings.get("from_addr") or settings.get("user", ""),
            "use_tls": settings.get("use_tls", True),
        }
    return _smtp_config_from_env()


@api_router.get("/settings/smtp-config")
async def get_smtp_config_settings(current_user: dict = Depends(get_current_user)):
    """Get the SMTP configuration (admin only). Never returns the actual password."""
    require_admin(current_user)
    settings = await db.global_settings.find_one({"type": "smtp_config"})
    if settings and settings.get("host"):
        return {
            "host": settings.get("host", ""),
            "port": settings.get("port", 587),
            "user": settings.get("user", ""),
            "from_addr": settings.get("from_addr", ""),
            "use_tls": settings.get("use_tls", True),
            "password_configured": bool(settings.get("wrapped_password")),
            "source": "database",
        }
    env_config = _smtp_config_from_env()
    return {
        "host": env_config["host"],
        "port": env_config["port"],
        "user": env_config["user"],
        "from_addr": env_config["from_addr"],
        "use_tls": env_config["use_tls"],
        "password_configured": bool(env_config["password"]),
        "source": "env" if env_config["host"] else "none",
    }


class SmtpConfigUpdate(BaseModel):
    host: str
    port: int = 587
    user: str = ""
    password: Optional[str] = None  # omitted/blank = keep existing stored password
    from_addr: str = ""
    use_tls: bool = True


@api_router.put("/settings/smtp-config")
async def update_smtp_config_settings(payload: SmtpConfigUpdate, current_user: dict = Depends(get_current_user)):
    """Update the SMTP configuration (admin only). Stored in the DB, password kept wrapped at rest."""
    require_admin(current_user)

    update_data = {
        "host": payload.host.strip(),
        "port": payload.port,
        "user": payload.user.strip(),
        "from_addr": payload.from_addr.strip() or payload.user.strip(),
        "use_tls": payload.use_tls,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if payload.password:
        update_data["wrapped_password"] = wrap_secret(payload.password)

    await db.global_settings.update_one({"type": "smtp_config"}, {"$set": update_data}, upsert=True)
    return {"message": "SMTP-Konfiguration gespeichert."}


def send_backup_email(recipient_email: str, content_bytes: bytes, filename: str, config: dict):
    """Send a backup file as an e-mail attachment. Blocking (run via asyncio.to_thread)."""
    if not config["host"] or not config["user"]:
        raise RuntimeError("SMTP ist nicht konfiguriert (siehe Admin-Tab > Backup-Sicherheit oder backend/.env).")

    msg = MIMEMultipart()
    msg["From"] = config["from_addr"]
    msg["To"] = recipient_email
    msg["Subject"] = f"iPad-Verwaltung: Automatisches Backup vom {datetime.now().strftime('%d.%m.%Y %H:%M')}"
    is_encrypted = filename.endswith(".enc")
    body_text = (
        "Im Anhang befindet sich das automatisch erstellte System-Backup der iPad-Verwaltung.\n\n"
        + ("Der Anhang ist verschlüsselt (Backup-Passwort erforderlich zum Öffnen).\n\n" if is_encrypted else "")
        + "Diese E-Mail wurde automatisch generiert."
    )
    msg.attach(MIMEText(body_text, "plain"))
    part = MIMEBase("application", "octet-stream" if is_encrypted else "json")
    part.set_payload(content_bytes)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f"attachment; filename={filename}")
    msg.attach(part)

    with smtplib.SMTP(config["host"], config["port"], timeout=30) as server:
        if config["use_tls"]:
            server.starttls()
        if config["user"]:
            try:
                server.login(config["user"], config["password"])
            except smtplib.SMTPAuthenticationError as e:
                error_text = str(e)
                if "application-specific password" in error_text.lower() or "5.7.9" in error_text:
                    raise RuntimeError(
                        "SMTP-Anmeldung fehlgeschlagen: Gmail verlangt ein App-Passwort anstelle des normalen "
                        "Kontopassworts, sobald die 2-Faktor-Authentifizierung aktiv ist. Unter "
                        "https://myaccount.google.com/apppasswords ein App-Passwort erstellen und dieses hier "
                        "als SMTP-Passwort hinterlegen."
                    ) from e
                raise RuntimeError(f"SMTP-Anmeldung fehlgeschlagen: {error_text}") from e
        server.sendmail(config["from_addr"], [recipient_email], msg.as_string())


@api_router.get("/settings/backup-schedule")
async def get_backup_schedule_settings(current_user: dict = Depends(get_current_user)):
    """Get the automatic backup e-mail schedule (admin only)."""
    require_admin(current_user)
    settings = await db.global_settings.find_one({"type": "backup_schedule"})
    if not settings:
        return {
            "enabled": False,
            "frequency": "daily",
            "recipient_email": "",
            "last_run_at": None,
            "last_status": None,
            "last_error": None,
        }
    return {
        "enabled": settings.get("enabled", False),
        "frequency": settings.get("frequency", "daily"),
        "recipient_email": settings.get("recipient_email", ""),
        "last_run_at": settings.get("last_run_at"),
        "last_status": settings.get("last_status"),
        "last_error": settings.get("last_error"),
    }


class BackupScheduleUpdate(BaseModel):
    enabled: bool
    frequency: str  # "daily" | "weekly" | "monthly"
    recipient_email: Optional[EmailStr] = None


@api_router.put("/settings/backup-schedule")
async def update_backup_schedule_settings(payload: BackupScheduleUpdate, current_user: dict = Depends(get_current_user)):
    """Update the automatic backup e-mail schedule (admin only)."""
    require_admin(current_user)
    if payload.frequency not in ("daily", "weekly", "monthly"):
        raise HTTPException(status_code=400, detail="Ungültige Frequenz. Erlaubt: daily, weekly, monthly")
    if payload.enabled and not payload.recipient_email:
        raise HTTPException(status_code=400, detail="Für aktivierte automatische Backups ist eine Ziel-E-Mail-Adresse erforderlich.")

    update_data = {
        "enabled": payload.enabled,
        "frequency": payload.frequency,
        "recipient_email": payload.recipient_email or "",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.global_settings.update_one({"type": "backup_schedule"}, {"$set": update_data}, upsert=True)
    return {"message": "Backup-Zeitplan gespeichert.", **update_data}


class SendBackupNowRequest(BaseModel):
    recipient_email: Optional[EmailStr] = None


@api_router.post("/backup/send-now")
async def send_backup_now(payload: SendBackupNowRequest, current_user: dict = Depends(get_current_user)):
    """Immediately send a backup e-mail (admin only) - useful to test SMTP configuration."""
    require_admin(current_user)

    recipient = payload.recipient_email
    if not recipient:
        settings = await db.global_settings.find_one({"type": "backup_schedule"})
        recipient = settings.get("recipient_email") if settings else None
    if not recipient:
        raise HTTPException(status_code=400, detail="Keine Ziel-E-Mail-Adresse angegeben oder konfiguriert.")

    try:
        content_bytes, filename, is_encrypted = await build_backup_export_bytes()
        config = await get_smtp_config()
        await asyncio.to_thread(send_backup_email, recipient, content_bytes, filename, config)
        suffix = " (verschlüsselt)" if is_encrypted else ""
        return {"message": f"Backup wurde erfolgreich an {recipient} gesendet{suffix}."}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        # SMTP config/auth problems (missing config, wrong password, Gmail app-password requirement, ...) -
        # a client-side configuration error, not a server bug.
        raise HTTPException(status_code=400, detail=f"Fehler beim Senden der Backup-E-Mail: {str(e)}")
    except Exception as e:
        logger.error(f"Manual backup email failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Fehler beim Senden der Backup-E-Mail: {str(e)}")


BACKUP_SCHEDULE_CHECK_INTERVAL_SECONDS = 3600  # check hourly whether a scheduled backup is due
BACKUP_SCHEDULE_FREQUENCY_TO_TIMEDELTA = {
    "daily": timedelta(days=1),
    "weekly": timedelta(days=7),
    "monthly": timedelta(days=30),
}


async def run_scheduled_backup_check():
    """Send the automatic backup e-mail if one is enabled and due."""
    settings = await db.global_settings.find_one({"type": "backup_schedule"})
    if not settings or not settings.get("enabled"):
        return
    recipient_email = settings.get("recipient_email")
    if not recipient_email:
        return

    interval = BACKUP_SCHEDULE_FREQUENCY_TO_TIMEDELTA.get(settings.get("frequency", "daily"), timedelta(days=1))
    last_run_at = settings.get("last_run_at")
    if last_run_at:
        last_run_dt = datetime.fromisoformat(last_run_at)
        if datetime.now(timezone.utc) - last_run_dt < interval:
            return

    try:
        content_bytes, filename, _is_encrypted = await build_backup_export_bytes()
        config = await get_smtp_config()
        await asyncio.to_thread(send_backup_email, recipient_email, content_bytes, filename, config)
        await db.global_settings.update_one(
            {"type": "backup_schedule"},
            {"$set": {
                "last_run_at": datetime.now(timezone.utc).isoformat(),
                "last_status": "success",
                "last_error": None,
            }},
        )
        logger.info(f"Scheduled backup email sent to {recipient_email}")
    except Exception as e:
        logger.error(f"Scheduled backup email failed: {str(e)}")
        await db.global_settings.update_one(
            {"type": "backup_schedule"},
            {"$set": {
                "last_run_at": datetime.now(timezone.utc).isoformat(),
                "last_status": "error",
                "last_error": str(e),
            }},
        )


# --- Daily server-side backup, stored in MongoDB via GridFS (survives independently of the
# host filesystem/volume). Always runs regardless of the e-mail schedule; retains 7 days. ---

SERVER_BACKUP_RETENTION_DAYS = 7


def _backups_gridfs_bucket() -> AsyncIOMotorGridFSBucket:
    return AsyncIOMotorGridFSBucket(db, bucket_name="backups")


async def save_server_backup() -> dict:
    """Create a server-side backup snapshot in GridFS and prune snapshots older than the retention window."""
    content_bytes, filename, is_encrypted = await build_backup_export_bytes()
    bucket = _backups_gridfs_bucket()
    file_id = await bucket.upload_from_stream(
        filename,
        content_bytes,
        metadata={"encrypted": is_encrypted, "created_at": datetime.now(timezone.utc).isoformat()},
    )

    cutoff = datetime.now(timezone.utc) - timedelta(days=SERVER_BACKUP_RETENTION_DAYS)
    cursor = db["backups.files"].find({"uploadDate": {"$lt": cutoff}}, {"_id": 1})
    async for old_file in cursor:
        try:
            await bucket.delete(old_file["_id"])
        except Exception as e:
            logger.error(f"Could not prune old server backup {old_file['_id']}: {str(e)}")

    return {"file_id": str(file_id), "filename": filename, "encrypted": is_encrypted}


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


@api_router.post("/backup/server-backups/run-now")
async def run_server_backup_now(current_user: dict = Depends(get_current_user)):
    """Manually trigger the daily server-side backup immediately (admin only)."""
    require_admin(current_user)
    try:
        result = await save_server_backup()
        await db.global_settings.update_one(
            {"type": "server_backup_state"},
            {"$set": {"last_run_at": datetime.now(timezone.utc).isoformat(), "last_status": "success", "last_error": None}},
            upsert=True,
        )
        return {"message": "Server-Backup erfolgreich erstellt.", **result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Manual server backup failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Fehler beim Erstellen des Server-Backups: {str(e)}")


async def run_scheduled_server_backup_check():
    """Create the daily server-side backup if the last one is more than a day old (always on)."""
    state = await db.global_settings.find_one({"type": "server_backup_state"})
    last_run_at = state.get("last_run_at") if state else None
    if last_run_at:
        last_run_dt = datetime.fromisoformat(last_run_at)
        if datetime.now(timezone.utc) - last_run_dt < timedelta(days=1):
            return

    try:
        await save_server_backup()
        await db.global_settings.update_one(
            {"type": "server_backup_state"},
            {"$set": {"last_run_at": datetime.now(timezone.utc).isoformat(), "last_status": "success", "last_error": None}},
            upsert=True,
        )
        logger.info("Daily server-side backup created")
    except Exception as e:
        logger.error(f"Daily server-side backup failed: {str(e)}")
        await db.global_settings.update_one(
            {"type": "server_backup_state"},
            {"$set": {"last_run_at": datetime.now(timezone.utc).isoformat(), "last_status": "error", "last_error": str(e)}},
            upsert=True,
        )


async def backup_scheduler_loop():
    """Background task: hourly check for due e-mail schedule + daily server-side backup."""
    await asyncio.sleep(60)  # let the app finish starting up first
    while True:
        try:
            await run_scheduled_backup_check()
        except Exception as e:
            logger.error(f"Backup scheduler loop error: {str(e)}")
        try:
            await run_scheduled_server_backup_check()
        except Exception as e:
            logger.error(f"Server backup scheduler loop error: {str(e)}")
        await asyncio.sleep(BACKUP_SCHEDULE_CHECK_INTERVAL_SECONDS)
