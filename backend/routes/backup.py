import json
import logging
from datetime import datetime
from typing import Dict, Any

from fastapi import Depends, HTTPException, UploadFile, File
from fastapi.responses import Response

from core.auth import get_current_admin_user
from core.config import db
from core.router import api_router

logger = logging.getLogger(__name__)

COLLECTIONS = ["users", "students", "ipads", "assignments", "contracts", "global_settings"]

@api_router.get("/backup/export")
async def export_backup(current_user: dict = Depends(get_current_admin_user)):
    """
    Creates a full JSON backup of all relevant collections.
    Only accessible by administrators.
    """
    try:
        backup_data = {}
        for coll_name in COLLECTIONS:
            collection = db[coll_name]
            cursor = collection.find({})
            records = await cursor.to_list(length=None)
            
            # ObjectId zu String konvertieren für JSON
            for record in records:
                if "_id" in record:
                    record["_id"] = str(record["_id"])
            
            backup_data[coll_name] = records
            
        json_data = json.dumps(backup_data, ensure_ascii=False)
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"rbbk_ipad_verwaltung_backup_{timestamp}.json"
        
        return Response(
            content=json_data,
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Access-Control-Expose-Headers": "Content-Disposition"
            }
        )
    except Exception as e:
        logger.error(f"Backup export error: {str(e)}")
        raise HTTPException(status_code=500, detail="Fehler beim Erstellen des Backups.")

@api_router.post("/backup/import")
async def import_backup(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_admin_user)
):
    """
    Restores the database from a JSON backup file.
    Only accessible by administrators.
    Warning: This will overwrite existing data.
    """
    if not file.filename.endswith('.json'):
        raise HTTPException(status_code=400, detail="Es muss eine .json Datei hochgeladen werden.")
        
    try:
        content = await file.read()
        backup_data = json.loads(content.decode("utf-8"))
        
        if not isinstance(backup_data, dict):
            raise ValueError("Ungültiges Backup-Format.")
            
        for coll_name, records in backup_data.items():
            if coll_name in COLLECTIONS:
                for record in records:
                    if "_id" in record:
                        from bson.objectid import ObjectId
                        try:
                            record["_id"] = ObjectId(record["_id"])
                        except:
                            del record["_id"]
                            
                collection = db[coll_name]
                # Alte Daten leeren
                await collection.delete_many({})
                # Backup-Daten einfügen
                if records:
                    await collection.insert_many(records)
                    
        return {"message": "System-Backup erfolgreich wiederhergestellt."}
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Die hochgeladene Datei ist kein gültiges JSON.")
    except Exception as e:
        logger.error(f"Backup import error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Fehler beim Wiederherstellen: {str(e)}")
