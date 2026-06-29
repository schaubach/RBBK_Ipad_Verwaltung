"""Data protection / cleanup (/api/data-protection/*)

Auto-extracted from monolithic server.py during refactor (Session 12).
"""

from datetime import UTC, datetime, timedelta

from core.config import (
    db,
)
from core.router import api_router
from core.security import (
    get_current_user,
    require_admin,
)
from fastapi import Depends, HTTPException


@api_router.post("/data-protection/cleanup-old-data")
async def cleanup_old_data(current_user: dict = Depends(get_current_user)):
    """Delete students and contracts older than 5 years (Admin only)."""
    require_admin(current_user)
    try:
        five_years_ago = datetime.now(UTC) - timedelta(days=5 * 365)

        # Add timestamps to existing records if missing
        await add_missing_timestamps()

        # Delete old students (but keep those with active assignments)
        active_student_ids = []
        active_assignments = await db.assignments.find({"is_active": True}).to_list(length=None)
        active_student_ids = [a["student_id"] for a in active_assignments]

        old_students_result = await db.students.delete_many(
            {"created_at": {"$lt": five_years_ago.isoformat()}, "id": {"$nin": active_student_ids}}
        )

        # Delete old contracts
        old_contracts_result = await db.contracts.delete_many({"uploaded_at": {"$lt": five_years_ago.isoformat()}})

        return {
            "message": "Data protection cleanup completed",
            "deleted_students": old_students_result.deleted_count,
            "deleted_contracts": old_contracts_result.deleted_count,
            "cutoff_date": five_years_ago.isoformat(),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during cleanup: {str(e)}")


async def add_missing_timestamps():
    """Add created_at timestamps to records that don't have them"""
    try:
        # Update students without created_at
        await db.students.update_many(
            {"created_at": {"$exists": False}}, {"$set": {"created_at": datetime.now(UTC).isoformat()}}
        )

        # Update contracts without uploaded_at
        await db.contracts.update_many(
            {"uploaded_at": {"$exists": False}}, {"$set": {"uploaded_at": datetime.now(UTC).isoformat()}}
        )

        # Update iPads without created_at
        await db.ipads.update_many(
            {"created_at": {"$exists": False}}, {"$set": {"created_at": datetime.now(UTC).isoformat()}}
        )

        # Update assignments without assigned_at
        await db.assignments.update_many(
            {"assigned_at": {"$exists": False}}, {"$set": {"assigned_at": datetime.now(UTC).isoformat()}}
        )

    except Exception as e:
        print(f"Error adding missing timestamps: {e}")
