"""Global settings (/api/settings/*)

Auto-extracted from monolithic server.py during refactor (Session 12).
"""

from datetime import UTC, datetime

from core.config import (
    db,
)
from core.router import api_router
from core.security import (
    get_current_user,
    require_admin,
)
from fastapi import Depends, HTTPException


# Global Settings endpoints
@api_router.get("/settings/global")
async def get_global_settings(current_user: dict = Depends(get_current_user)):
    """Get global application settings"""
    try:
        settings = await db.global_settings.find_one({"type": "app_settings"})
        if not settings:
            # Create default settings if they don't exist
            default_settings = {
                "type": "app_settings",
                "ipad_typ": "Apple iPad",
                "pencil": "ohne Apple Pencil",
                "created_at": datetime.now(UTC).isoformat(),
                "updated_at": datetime.now(UTC).isoformat(),
            }
            await db.global_settings.insert_one(default_settings)
            settings = default_settings

        return {
            "ipad_typ": settings.get("ipad_typ", "Apple iPad"),
            "pencil": settings.get("pencil", "ohne Apple Pencil"),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting settings: {str(e)}")


@api_router.put("/settings/global")
async def update_global_settings(settings: dict, current_user: dict = Depends(get_current_user)):
    """Update global application settings (Admin only)"""
    require_admin(current_user)
    try:
        ipad_typ = settings.get("ipad_typ", "Apple iPad")
        pencil = settings.get("pencil", "ohne Apple Pencil")

        update_data = {"ipad_typ": ipad_typ, "pencil": pencil, "updated_at": datetime.now(UTC).isoformat()}

        await db.global_settings.update_one({"type": "app_settings"}, {"$set": update_data}, upsert=True)

        return {"message": "Einstellungen erfolgreich aktualisiert", "ipad_typ": ipad_typ, "pencil": pencil}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating settings: {str(e)}")
