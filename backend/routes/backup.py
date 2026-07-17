import base64
import json
import logging
from datetime import datetime

from bson import ObjectId
from bson.binary import Binary
from fastapi import Depends, File, HTTPException, UploadFile
from fastapi.responses import Response

from core.config import db
from core.router import api_router
from core.security import get_current_user, require_admin

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


@api_router.get("/backup/export")
async def export_backup(current_user: dict = Depends(get_current_user)):
    """
    Creates a full JSON backup of all relevant collections.
    Only accessible by administrators.
    """
    require_admin(current_user)
    try:
        backup_data = {}
        for coll_name in COLLECTIONS:
            collection = db[coll_name]
            cursor = collection.find({})
            records = await cursor.to_list(length=None)
            backup_data[coll_name] = [serialize_backup_value(record) for record in records]

        json_data = json.dumps(backup_data, ensure_ascii=False)

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"rbbk_ipad_verwaltung_backup_{timestamp}.json"

        return Response(
            content=json_data,
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Access-Control-Expose-Headers": "Content-Disposition",
            },
        )
    except Exception as e:
        logger.error(f"Backup export error: {str(e)}")
        raise HTTPException(status_code=500, detail="Fehler beim Erstellen des Backups.")


@api_router.post("/backup/import")
async def import_backup(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """
    Restores the database from a JSON backup file.
    Only accessible by administrators.
    Warning: This will overwrite existing data.
    """
    require_admin(current_user)
    if not file.filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="Es muss eine .json Datei hochgeladen werden.")

    try:
        content = await file.read()
        backup_data = json.loads(content.decode("utf-8"))

        if not isinstance(backup_data, dict):
            raise ValueError("Ungueltiges Backup-Format.")

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

        return {"message": "System-Backup erfolgreich wiederhergestellt."}

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Die hochgeladene Datei ist kein gueltiges JSON.")
    except Exception as e:
        logger.error(f"Backup import error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Fehler beim Wiederherstellen: {str(e)}")
