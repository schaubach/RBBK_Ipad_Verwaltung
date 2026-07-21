"""Contract PDF/ZIP generation (/api/assignments/generate-contracts)

Auto-extracted from monolithic server.py during refactor (Session 12).
"""

import io
import re
from datetime import datetime
from typing import List, Optional

from contract_generator import create_contracts_from_assignments
from core.config import (
    db,
)
from core.router import api_router
from core.security import (
    get_current_user,
    get_user_filter,
)
from fastapi import Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel


# Contract Generation
class GenerateContractsRequest(BaseModel):
    assignment_ids: Optional[List[str]] = None


@api_router.post("/assignments/generate-contracts")
async def generate_contracts(
    request: Optional[GenerateContractsRequest] = None,
    sus_vorn: Optional[str] = None,
    sus_nachn: Optional[str] = None,
    sus_kl: Optional[str] = None,
    itnr: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """
    Generate PDF contracts as encrypted ZIP archives.

    Supports two modes:
    1. Filter-based: Use query parameters (sus_vorn, sus_nachn, sus_kl, itnr)
    2. Selection-based: Pass assignment_ids in request body
    """
    try:
        # Apply user filter - CRITICAL for RBAC!
        user_filter = await get_user_filter(current_user)

        # Mode 1: Selection-based (assignment_ids provided)
        if request and request.assignment_ids:
            assignment_filter = {"id": {"$in": request.assignment_ids}, "is_active": True, **user_filter}
            assignments = await db.assignments.find(assignment_filter).to_list(length=None)
        else:
            # Mode 2: Filter-based (query parameters)
            # Build filter query for students (with user filter!)
            student_filter = user_filter.copy()
            if sus_vorn:
                student_filter["sus_vorn"] = {"$regex": re.escape(sus_vorn), "$options": "i"}
            if sus_nachn:
                student_filter["sus_nachn"] = {"$regex": re.escape(sus_nachn), "$options": "i"}
            if sus_kl:
                student_filter["sus_kl"] = {"$regex": re.escape(sus_kl), "$options": "i"}

            # Build filter query for assignments (IT-Nummer) with user filter!
            assignment_filter = user_filter.copy()
            assignment_filter["is_active"] = True
            if itnr:
                assignment_filter["itnr"] = {"$regex": re.escape(itnr), "$options": "i"}

            if sus_vorn or sus_nachn or sus_kl:
                # Get matching students (filtered by user_id!)
                students = await db.students.find(student_filter).to_list(length=None)
                student_ids = [s["id"] for s in students]

                if not student_ids:
                    raise HTTPException(status_code=404, detail="Keine passenden Zuordnungen gefunden")

                # Add student filter to assignment filter
                assignment_filter["student_id"] = {"$in": student_ids}

            # Get assignments matching all filters (filtered by user_id!)
            assignments = await db.assignments.find(assignment_filter).to_list(length=None)

        if not assignments:
            raise HTTPException(status_code=404, detail="Keine Zuordnungen gefunden")

        # Prepare data for contract generation
        contract_data = []
        for assignment in assignments:
            # Get student data
            student = await db.students.find_one({"id": assignment["student_id"]})
            # Get iPad data
            ipad = await db.ipads.find_one({"id": assignment["ipad_id"]})

            if student and ipad:
                # Format Geburtstag to DD.MM.YYYY
                geburtstag_formatted = ""
                if student.get("sus_geb"):
                    try:
                        geb_str = str(student["sus_geb"]).strip()
                        if geb_str and geb_str.lower() != "nan":
                            if "." in geb_str:
                                parts = geb_str.split(".")
                                if len(parts) == 3:
                                    day, month, year = parts
                                    date_obj = datetime(int(year), int(month), int(day))
                                    geburtstag_formatted = date_obj.strftime("%d.%m.%Y")
                            elif "-" in geb_str:
                                if " " in geb_str:
                                    geb_str = geb_str.split(" ")[0]
                                date_obj = datetime.strptime(geb_str, "%Y-%m-%d")
                                geburtstag_formatted = date_obj.strftime("%d.%m.%Y")
                            else:
                                geburtstag_formatted = geb_str
                    except:
                        pass

                # Format AusleiheDatum
                ausleihe_datum_formatted = ""
                if assignment.get("assigned_at"):
                    try:
                        assigned_str = str(assignment["assigned_at"])
                        if "T" in assigned_str:
                            date_obj = datetime.fromisoformat(assigned_str.replace("Z", "+00:00"))
                            ausleihe_datum_formatted = date_obj.strftime("%d.%m.%Y")
                    except:
                        pass

                row_data = {
                    "sus_vorn": student.get("sus_vorn", ""),
                    "sus_nachn": student.get("sus_nachn", ""),
                    "sus_kl": student.get("sus_kl", ""),
                    "sus_geb": geburtstag_formatted,
                    "sus_str_hnr": student.get("sus_str_hnr", ""),
                    "sus_plz": student.get("sus_plz", ""),
                    "sus_ort": student.get("sus_ort", ""),
                    "erz1_vorn": student.get("erz1_vorn", ""),
                    "erz1_nachn": student.get("erz1_nachn", ""),
                    "erz1_str_hnr": student.get("erz1_str_hnr", ""),
                    "erz1_plz": student.get("erz1_plz", ""),
                    "erz1_ort": student.get("erz1_ort", ""),
                    "erz2_vorn": student.get("erz2_vorn", ""),
                    "erz2_nachn": student.get("erz2_nachn", ""),
                    "erz2_str_hnr": student.get("erz2_str_hnr", ""),
                    "erz2_plz": student.get("erz2_plz", ""),
                    "erz2_ort": student.get("erz2_ort", ""),
                    "itnr": ipad.get("itnr", ""),
                    "snr": ipad.get("snr", ""),
                    "typ": ipad.get("typ", ""),
                    "pencil": ipad.get("pencil", ""),
                    "ansch_jahr": ipad.get("ansch_jahr", ""),
                    "ausleihe_datum": ausleihe_datum_formatted,
                }
                contract_data.append(row_data)

        if not contract_data:
            raise HTTPException(status_code=404, detail="Keine gültigen Daten für Vertragserstellung gefunden")

        # Generate contracts
        zip_bytes, success_count, error_count, errors = create_contracts_from_assignments(contract_data)

        if success_count == 0:
            raise HTTPException(status_code=500, detail=f"Keine Verträge erstellt. Fehler: {'; '.join(errors[:5])}")

        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Vertraege_{timestamp}.zip"

        return StreamingResponse(
            io.BytesIO(zip_bytes),
            media_type="application/zip",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "X-Success-Count": str(success_count),
                "X-Error-Count": str(error_count),
            },
        )

    except HTTPException:
        raise
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=f"Vorlagendatei nicht gefunden: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler bei der Vertragserstellung: {str(e)}")
