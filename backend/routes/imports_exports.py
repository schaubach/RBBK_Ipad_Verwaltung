"""Inventory imports + Excel exports (/api/imports/*, /api/exports/*, /api/assignments/export*)

Auto-extracted from monolithic server.py during refactor (Session 12).
"""

import io
from datetime import UTC, datetime
from typing import Dict, List, Optional

import pandas as pd
from core.config import (
    MAX_IPADS_PER_STUDENT,
    db,
    limiter,
)
from core.mongo import prepare_for_mongo
from core.router import api_router
from core.security import (
    get_current_user,
    get_user_filter,
)
from core.validators import is_contract_validated, validate_uploaded_file
from fastapi import Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from models.assignment import (
    Assignment,
)
from models.ipad import iPad
from models.student import Student
from pydantic import BaseModel
from starlette.requests import Request

# ---------------------------------------------------------------------------
# Shared export helpers (used by all 3 Excel-export endpoints)
# ---------------------------------------------------------------------------


def _format_birthday(geb_value) -> str:
    """Normalize a student birthday value to ``DD.MM.YYYY`` (or '' if unparsable)."""
    if not geb_value:
        return ""
    try:
        geb_str = str(geb_value).strip()
        if not geb_str or geb_str.lower() == "nan":
            return ""
        if "." in geb_str:
            parts = geb_str.split(".")
            if len(parts) == 3:
                day, month, year = parts
                return datetime(int(year), int(month), int(day)).strftime("%d.%m.%Y")
            return geb_str
        if "-" in geb_str:
            if " " in geb_str:
                geb_str = geb_str.split(" ")[0]
            return datetime.strptime(geb_str, "%Y-%m-%d").strftime("%d.%m.%Y")
        if len(geb_str) == 8 and geb_str.isdigit():
            return datetime.strptime(geb_str, "%Y%m%d").strftime("%d.%m.%Y")
        if "/" in geb_str:
            parts = geb_str.split("/")
            if len(parts) == 3:
                day, month, year = parts
                return datetime(int(year), int(month), int(day)).strftime("%d.%m.%Y")
        return geb_str
    except Exception:
        return str(geb_value)


def _format_iso_date(iso_value) -> str:
    """Return ``DD.MM.YYYY`` for an ISO-8601 timestamp (or '' on failure)."""
    if not iso_value:
        return ""
    try:
        return datetime.fromisoformat(str(iso_value).replace("Z", "+00:00")).strftime("%d.%m.%Y")
    except Exception:
        return ""


# Canonical column order used by ALL three Excel-export endpoints.
# Frontend uses the same list to render the column-selection dialog.
EXPORT_COLUMNS: List[str] = [
    # Schüler
    "Sname",
    "SuSNachn",
    "SuSVorn",
    "SuSKl",
    "SuSStrHNr",
    "SuSPLZ",
    "SuSOrt",
    "SuSGeb",
    "Erz1Nachn",
    "Erz1Vorn",
    "Erz1StrHNr",
    "Erz1PLZ",
    "Erz1Ort",
    "Erz2Nachn",
    "Erz2Vorn",
    "Erz2StrHNr",
    "Erz2PLZ",
    "Erz2Ort",
    # iPad
    "Pencil",
    "ITNr",
    "SNr",
    "Typ",
    "Modell",
    "Status",
    "AnschJahr",
    "AusleiheDatum",
    "Rückgabe",
    # Vertrag
    "Vertrag vorhanden",
    "Vertrag validiert",
]


def _build_assignment_row(
    student: Optional[dict],
    ipad: Optional[dict],
    assignment: Optional[dict],
    contracts_by_id: Dict[str, dict],
    *,
    ipad_typ_default: str = "",
    pencil_default: str = "",
    selected_columns: Optional[List[str]] = None,
) -> dict:
    """Build a single Excel row covering student + iPad + assignment columns.

    All three export endpoints share the SAME canonical column set
    (`EXPORT_COLUMNS`). The optional ``selected_columns`` argument filters
    the row down to the user-chosen subset, preserving canonical order.

    Args:
        student / ipad / assignment: source documents (any may be ``None``).
        contracts_by_id: preloaded ``{contract_id: contract_doc}`` lookup
            for the Vertrag-Spalten.
        ipad_typ_default / pencil_default: fallback values (from global
            settings) used when the iPad document itself has no `typ`
            or `pencil` populated.
        selected_columns: when given, only those keys are returned.
    """
    contract = None
    if assignment and assignment.get("contract_id"):
        contract = contracts_by_id.get(assignment["contract_id"])

    pencil = ""
    typ = ""
    if ipad:
        pencil = ipad.get("pencil") or pencil_default
        typ = ipad.get("typ") or ipad_typ_default

    full_row = {
        # Schüler
        "Sname": student.get("sname", "") if student else "",
        "SuSNachn": student.get("sus_nachn", "") if student else "",
        "SuSVorn": student.get("sus_vorn", "") if student else "",
        "SuSKl": student.get("sus_kl", "") if student else "",
        "SuSStrHNr": student.get("sus_str_hnr", "") if student else "",
        "SuSPLZ": student.get("sus_plz", "") if student else "",
        "SuSOrt": student.get("sus_ort", "") if student else "",
        "SuSGeb": _format_birthday(student.get("sus_geb")) if student else "",
        "Erz1Nachn": student.get("erz1_nachn", "") if student else "",
        "Erz1Vorn": student.get("erz1_vorn", "") if student else "",
        "Erz1StrHNr": student.get("erz1_str_hnr", "") if student else "",
        "Erz1PLZ": student.get("erz1_plz", "") if student else "",
        "Erz1Ort": student.get("erz1_ort", "") if student else "",
        "Erz2Nachn": student.get("erz2_nachn", "") if student else "",
        "Erz2Vorn": student.get("erz2_vorn", "") if student else "",
        "Erz2StrHNr": student.get("erz2_str_hnr", "") if student else "",
        "Erz2PLZ": student.get("erz2_plz", "") if student else "",
        "Erz2Ort": student.get("erz2_ort", "") if student else "",
        # iPad
        "Pencil": pencil,
        "ITNr": ipad.get("itnr", "") if ipad else "",
        "SNr": ipad.get("snr", "") if ipad else "",
        "Typ": typ,
        "Modell": (ipad.get("modell") or "") if ipad else "",
        "Status": ipad.get("status", "ok") if ipad else "",
        "AnschJahr": ipad.get("ansch_jahr", "") if ipad else "",
        "AusleiheDatum": _format_iso_date(assignment.get("assigned_at")) if assignment else "",
        "Rückgabe": "",
        # Vertrag
        "Vertrag vorhanden": "Ja" if contract else "Nein",
        "Vertrag validiert": "Ja" if is_contract_validated(contract) else "Nein",
    }

    if selected_columns is None:
        return full_row
    # Preserve canonical column order while filtering
    return {col: full_row[col] for col in EXPORT_COLUMNS if col in selected_columns and col in full_row}


def _parse_columns_param(columns_csv: Optional[str]) -> Optional[List[str]]:
    """Parse a comma-separated ``columns`` query parameter into a sanitized list.

    Returns ``None`` (= all columns) when the parameter is missing or empty.
    Unknown column names are silently ignored.
    """
    if not columns_csv:
        return None
    requested = {c.strip() for c in columns_csv.split(",") if c.strip()}
    if not requested:
        return None
    valid = [c for c in EXPORT_COLUMNS if c in requested]
    return valid or None


# Frontend uses this to render the column-selection dialog without hardcoding
# the list.  Columns are grouped (student / ipad / contract) for nicer UI.
EXPORT_COLUMN_GROUPS = {
    "student": [
        "Sname",
        "SuSNachn",
        "SuSVorn",
        "SuSKl",
        "SuSStrHNr",
        "SuSPLZ",
        "SuSOrt",
        "SuSGeb",
        "Erz1Nachn",
        "Erz1Vorn",
        "Erz1StrHNr",
        "Erz1PLZ",
        "Erz1Ort",
        "Erz2Nachn",
        "Erz2Vorn",
        "Erz2StrHNr",
        "Erz2PLZ",
        "Erz2Ort",
    ],
    "ipad": [
        "Pencil",
        "ITNr",
        "SNr",
        "Typ",
        "Modell",
        "Status",
        "AnschJahr",
        "AusleiheDatum",
        "Rückgabe",
    ],
    "contract": [
        "Vertrag vorhanden",
        "Vertrag validiert",
    ],
}


@api_router.get("/exports/columns")
async def get_export_columns(current_user: dict = Depends(get_current_user)):
    """Return the canonical column list + group structure for the export-columns picker."""
    return {
        "columns": EXPORT_COLUMNS,
        "groups": EXPORT_COLUMN_GROUPS,
    }


@api_router.post("/imports/inventory")
async def import_inventory(
    file: UploadFile = File(...), import_to_pool: bool = Form(False), current_user: dict = Depends(get_current_user)
):
    """
    Import complete inventory list with iPads and student assignments from Excel file.

    Supports 1:n relationships - if a student appears multiple times with different iPads,
    all iPads will be assigned to that student (up to MAX_IPADS_PER_STUDENT limit).

    Compatible with both old (1:1) and new (1:n) export formats.

    Pool import (import_to_pool=true): Only iPads will be imported into the shared pool.
    Student/assignment rows are ignored. iPads must have globally unique ITNr.
    """
    try:
        # Load global settings for default values
        global_settings = await db.global_settings.find_one({"type": "app_settings"})
        default_ipad_typ = global_settings.get("ipad_typ", "Apple iPad") if global_settings else "Apple iPad"
        default_pencil = global_settings.get("pencil", "ohne Apple Pencil") if global_settings else "ohne Apple Pencil"

        # Validate file type
        if not file.filename.lower().endswith((".xlsx", ".xls")):
            raise HTTPException(status_code=400, detail="Only Excel files (.xlsx, .xls) are allowed")

        # Read Excel file
        contents = await file.read()
        # Security: Validate uploaded file
        validate_uploaded_file(contents, file.filename, max_size_mb=10, allowed_types=[".xlsx", ".xls"])

        # Try to read with different engines for .xls/.xlsx support
        try:
            if file.filename.lower().endswith(".xlsx"):
                df = pd.read_excel(io.BytesIO(contents), engine="openpyxl")
            else:
                df = pd.read_excel(io.BytesIO(contents), engine="xlrd")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error reading Excel file: {str(e)}")

        # No strict column validation - we handle all cases:
        # 1. Only iPad data (ITNr present, no student data)
        # 2. Only student data (SuSVorn+SuSNachn present, no ITNr)
        # 3. Both (iPad + student + assignment)

        # Counters for different operations
        ipads_created = 0
        ipads_skipped = 0
        students_created = 0
        students_skipped = 0
        students_only_created = 0  # Students without iPad
        assignments_created = 0
        assignments_skipped_limit = 0
        rows_skipped_empty = 0
        error_count = 0
        errors = []

        # Helper function to safely convert values and handle NaN
        def safe_str(value):
            if pd.isna(value) or value is None:
                return ""
            str_val = str(value).strip()
            return "" if str_val == "nan" else str_val

        # Cache for students to avoid repeated lookups (key: (vorn, nachn))
        student_cache = {}

        for index, row in df.iterrows():
            try:
                # Extract data from row
                itnr = safe_str(row.get("ITNr", ""))
                sus_vorn = safe_str(row.get("SuSVorn", ""))
                sus_nachn = safe_str(row.get("SuSNachn", ""))
                sus_kl = safe_str(row.get("SuSKl", ""))

                has_ipad_data = bool(itnr)
                has_student_data = bool(sus_vorn and sus_nachn)

                # Skip completely empty rows
                if not has_ipad_data and not has_student_data:
                    rows_skipped_empty += 1
                    continue

                ipad_id = None
                student_id = None
                ipad_already_assigned = False

                # Process iPad data if present
                if has_ipad_data:
                    if import_to_pool:
                        # Pool-Import: global uniqueness check (across all users)
                        existing_pool_ipad = await db.ipads.find_one({"itnr": itnr})
                        if existing_pool_ipad:
                            ipads_skipped += 1
                            ipad_id = existing_pool_ipad["id"]
                            ipad_already_assigned = existing_pool_ipad.get("current_assignment_id") is not None
                        else:
                            # Create new pool iPad
                            imported_status = safe_str(row.get("Status", ""))
                            valid_statuses = ["ok", "defekt", "gestohlen"]
                            ipad_status = imported_status.lower() if imported_status.lower() in valid_statuses else "ok"

                            imported_typ = safe_str(row.get("Typ", ""))
                            imported_pencil = safe_str(row.get("Pencil", ""))
                            imported_modell = safe_str(row.get("Modell", "")) or None

                            new_ipad = iPad(
                                user_id=current_user["id"],
                                itnr=itnr,
                                snr=safe_str(row.get("SNr", "")),
                                typ=imported_typ if imported_typ else default_ipad_typ,
                                pencil=imported_pencil if imported_pencil else default_pencil,
                                modell=imported_modell,
                                ansch_jahr=safe_str(row.get("AnschJahr", "")),
                                status=ipad_status,
                                is_in_pool=True,
                                pool_history=[
                                    {
                                        "action": "imported_to_pool",
                                        "by": current_user["id"],
                                        "at": datetime.now(UTC).isoformat(),
                                    }
                                ],
                            )
                            ipad_dict = prepare_for_mongo(new_ipad.dict())
                            await db.ipads.insert_one(ipad_dict)
                            ipad_id = new_ipad.id
                            ipads_created += 1
                            ipad_already_assigned = False
                    else:
                        # Check if iPad already exists for this user
                        existing_ipad = await db.ipads.find_one({"itnr": itnr, "user_id": current_user["id"]})

                        if existing_ipad:
                            ipads_skipped += 1
                            ipad_id = existing_ipad["id"]
                            ipad_already_assigned = existing_ipad.get("current_assignment_id") is not None
                        else:
                            # Create new iPad - Status aus Import oder Default 'ok'
                            imported_status = safe_str(row.get("Status", ""))
                            # Validiere Status-Wert
                            valid_statuses = ["ok", "defekt", "gestohlen"]
                            ipad_status = imported_status.lower() if imported_status.lower() in valid_statuses else "ok"

                            # Use global settings as defaults if fields are empty
                            imported_typ = safe_str(row.get("Typ", ""))
                            imported_pencil = safe_str(row.get("Pencil", ""))
                            imported_modell = safe_str(row.get("Modell", "")) or None

                            new_ipad = iPad(
                                user_id=current_user["id"],
                                itnr=itnr,
                                snr=safe_str(row.get("SNr", "")),
                                typ=imported_typ if imported_typ else default_ipad_typ,
                                pencil=imported_pencil if imported_pencil else default_pencil,
                                modell=imported_modell,
                                ansch_jahr=safe_str(row.get("AnschJahr", "")),
                                status=ipad_status,
                            )

                            ipad_dict = prepare_for_mongo(new_ipad.dict())
                            await db.ipads.insert_one(ipad_dict)
                            ipad_id = new_ipad.id
                            ipads_created += 1
                            ipad_already_assigned = False

                # Process student data if present (skip when pool import)
                if has_student_data and not import_to_pool:
                    # Use cache key based on name only (not class) for 1:n support
                    # This allows the same student to receive multiple iPads
                    cache_key = (sus_vorn, sus_nachn)

                    if cache_key in student_cache:
                        student_id = student_cache[cache_key]
                        students_skipped += 1
                    else:
                        # Check if student already exists for this user (by name only for 1:n)
                        existing_student = await db.students.find_one(
                            {"sus_vorn": sus_vorn, "sus_nachn": sus_nachn, "user_id": current_user["id"]}
                        )

                        if existing_student:
                            students_skipped += 1
                            student_id = existing_student["id"]
                        else:
                            # Create new student with proper NaN handling
                            new_student = Student(
                                user_id=current_user["id"],
                                sname=safe_str(row.get("Sname", "")),
                                sus_vorn=sus_vorn,
                                sus_nachn=sus_nachn,
                                sus_kl=sus_kl,
                                sus_str_hnr=safe_str(row.get("SuSStrHNr", "")),
                                sus_plz=safe_str(row.get("SuSPLZ", "")),
                                sus_ort=safe_str(row.get("SuSOrt", "")),
                                sus_geb=safe_str(row.get("SuSGeb", "")),
                                erz1_nachn=safe_str(row.get("Erz1Nachn", "")),
                                erz1_vorn=safe_str(row.get("Erz1Vorn", "")),
                                erz1_str_hnr=safe_str(row.get("Erz1StrHNr", "")),
                                erz1_plz=safe_str(row.get("Erz1PLZ", "")),
                                erz1_ort=safe_str(row.get("Erz1Ort", "")),
                                erz2_nachn=safe_str(row.get("Erz2Nachn", "")),
                                erz2_vorn=safe_str(row.get("Erz2Vorn", "")),
                                erz2_str_hnr=safe_str(row.get("Erz2StrHNr", "")),
                                erz2_plz=safe_str(row.get("Erz2PLZ", "")),
                                erz2_ort=safe_str(row.get("Erz2Ort", "")),
                            )

                            student_dict = prepare_for_mongo(new_student.dict())
                            await db.students.insert_one(student_dict)
                            student_id = new_student.id
                            students_created += 1

                        # Cache the student ID
                        student_cache[cache_key] = student_id

                    # Only create assignment if both iPad AND student data present
                    if has_ipad_data and ipad_id:
                        # Check if iPad is already assigned (skip assignment if so)
                        if ipad_already_assigned:
                            continue

                        # Check current assignment count for this student (1:n limit)
                        current_assignment_count = await db.assignments.count_documents(
                            {"student_id": student_id, "is_active": True}
                        )

                        if current_assignment_count >= MAX_IPADS_PER_STUDENT:
                            assignments_skipped_limit += 1
                            errors.append(
                                f"Row {index + 2}: Student {sus_vorn} {sus_nachn} hat bereits {MAX_IPADS_PER_STUDENT} iPads - übersprungen"
                            )
                            continue

                        # Check if assignment already exists for this iPad
                        existing_assignment = await db.assignments.find_one({"ipad_id": ipad_id, "is_active": True})

                        if not existing_assignment:
                            # Create new assignment
                            ausleibe_datum = safe_str(row.get("AusleiheDatum", ""))
                            assigned_at = datetime.now(UTC).isoformat()

                            # Try to parse AusleiheDatum if provided
                            if ausleibe_datum:
                                try:
                                    # Parse DD.MM.YYYY format
                                    date_obj = datetime.strptime(ausleibe_datum, "%d.%m.%Y")
                                    assigned_at = date_obj.replace(tzinfo=UTC).isoformat()
                                except:
                                    pass  # Use current datetime if parsing fails

                            new_assignment = Assignment(
                                user_id=current_user["id"],
                                ipad_id=ipad_id,
                                student_id=student_id,
                                itnr=itnr,
                                student_name=f"{sus_vorn} {sus_nachn}",
                                assigned_at=assigned_at,
                            )

                            assignment_dict = prepare_for_mongo(new_assignment.dict())
                            await db.assignments.insert_one(assignment_dict)

                            # Update iPad assignment reference (keep original status like ok, defekt, gestohlen)
                            await db.ipads.update_one(
                                {"id": ipad_id},
                                {
                                    "$set": {
                                        "current_assignment_id": new_assignment.id,
                                        "updated_at": datetime.now(UTC).isoformat(),
                                    }
                                },
                            )

                            # Update student timestamp
                            await db.students.update_one(
                                {"id": student_id}, {"$set": {"updated_at": datetime.now(UTC).isoformat()}}
                            )

                            assignments_created += 1
                    else:
                        # Student without iPad - count separately
                        if student_id and cache_key not in student_cache:
                            students_only_created += 1

                # If only iPad data (no student), iPad remains available
                elif has_ipad_data and not has_student_data:
                    # iPad without student - already created above, nothing more to do
                    pass

            except Exception as e:
                error_count += 1
                errors.append(f"Row {index + 2}: {str(e)}")
                continue

        # Prepare response message
        parts = []
        if ipads_created > 0:
            parts.append(f"{ipads_created} iPads erstellt")
        if ipads_skipped > 0:
            parts.append(f"{ipads_skipped} iPads übersprungen")
        if students_created > 0:
            parts.append(f"{students_created} Schüler erstellt")
        if students_skipped > 0:
            parts.append(f"{students_skipped} Schüler wiederverwendet")
        if assignments_created > 0:
            parts.append(f"{assignments_created} Zuordnungen erstellt")
        if assignments_skipped_limit > 0:
            parts.append(f"{assignments_skipped_limit} Zuordnungen übersprungen (Limit {MAX_IPADS_PER_STUDENT})")
        if rows_skipped_empty > 0:
            parts.append(f"{rows_skipped_empty} leere Zeilen übersprungen")
        if error_count > 0:
            parts.append(f"{error_count} Fehler")

        message = "Import abgeschlossen: " + ", ".join(parts) if parts else "Import abgeschlossen: Keine Änderungen"

        total_processed = ipads_created + ipads_skipped + students_created + students_skipped

        return {
            "message": message,
            "total_processed": total_processed,
            "ipads_created": ipads_created,
            "ipads_skipped": ipads_skipped,
            "students_created": students_created,
            "students_skipped": students_skipped,
            "students_only_created": students_only_created,
            "assignments_created": assignments_created,
            "assignments_skipped_limit": assignments_skipped_limit,
            "rows_skipped_empty": rows_skipped_empty,
            "max_ipads_per_student": MAX_IPADS_PER_STUDENT,
            "error_count": error_count,
            "errors": errors[:20] if errors else [],
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing inventory import: {str(e)}")


@api_router.get("/imports/template")
async def download_import_template(current_user: dict = Depends(get_current_user)):
    """
    Download an Excel template for data import.
    The template contains all supported columns with example data.
    """
    try:
        # Create template data with example rows
        template_data = [
            {
                "Sname": "",
                "SuSNachn": "Mustermann",
                "SuSVorn": "Max",
                "SuSKl": "10a",
                "SuSStrHNr": "Musterstraße 1",
                "SuSPLZ": "12345",
                "SuSOrt": "Musterstadt",
                "SuSGeb": "01.01.2008",
                "Erz1Nachn": "Mustermann",
                "Erz1Vorn": "Hans",
                "Erz1StrHNr": "Musterstraße 1",
                "Erz1PLZ": "12345",
                "Erz1Ort": "Musterstadt",
                "Erz2Nachn": "",
                "Erz2Vorn": "",
                "Erz2StrHNr": "",
                "Erz2PLZ": "",
                "Erz2Ort": "",
                "Pencil": "ohne Apple Pencil",
                "ITNr": "IT-001",
                "SNr": "SN-12345",
                "Typ": "Apple iPad",
                "Status": "ok",
                "AnschJahr": "2024",
                "AusleiheDatum": "15.09.2024",
                "Rückgabe": "",
            },
            # Beispiel: Gleicher Schüler mit 2. iPad (1:n Beziehung)
            {
                "Sname": "",
                "SuSNachn": "Mustermann",
                "SuSVorn": "Max",
                "SuSKl": "10a",
                "SuSStrHNr": "Musterstraße 1",
                "SuSPLZ": "12345",
                "SuSOrt": "Musterstadt",
                "SuSGeb": "01.01.2008",
                "Erz1Nachn": "Mustermann",
                "Erz1Vorn": "Hans",
                "Erz1StrHNr": "Musterstraße 1",
                "Erz1PLZ": "12345",
                "Erz1Ort": "Musterstadt",
                "Erz2Nachn": "",
                "Erz2Vorn": "",
                "Erz2StrHNr": "",
                "Erz2PLZ": "",
                "Erz2Ort": "",
                "Pencil": "mit Apple Pencil",
                "ITNr": "IT-002",
                "SNr": "SN-67890",
                "Typ": "Apple iPad Pro",
                "Status": "ok",
                "AnschJahr": "2024",
                "AusleiheDatum": "20.09.2024",
                "Rückgabe": "",
            },
            # Beispiel: Nur Schüler ohne iPad
            {
                "Sname": "",
                "SuSNachn": "Schmidt",
                "SuSVorn": "Anna",
                "SuSKl": "10b",
                "SuSStrHNr": "Schulweg 5",
                "SuSPLZ": "12345",
                "SuSOrt": "Musterstadt",
                "SuSGeb": "15.03.2008",
                "Erz1Nachn": "Schmidt",
                "Erz1Vorn": "Maria",
                "Erz1StrHNr": "Schulweg 5",
                "Erz1PLZ": "12345",
                "Erz1Ort": "Musterstadt",
                "Erz2Nachn": "",
                "Erz2Vorn": "",
                "Erz2StrHNr": "",
                "Erz2PLZ": "",
                "Erz2Ort": "",
                "Pencil": "",
                "ITNr": "",
                "SNr": "",
                "Typ": "",
                "Status": "",
                "AnschJahr": "",
                "AusleiheDatum": "",
                "Rückgabe": "",
            },
            # Beispiel: Nur iPad ohne Schüler
            {
                "Sname": "",
                "SuSNachn": "",
                "SuSVorn": "",
                "SuSKl": "",
                "SuSStrHNr": "",
                "SuSPLZ": "",
                "SuSOrt": "",
                "SuSGeb": "",
                "Erz1Nachn": "",
                "Erz1Vorn": "",
                "Erz1StrHNr": "",
                "Erz1PLZ": "",
                "Erz1Ort": "",
                "Erz2Nachn": "",
                "Erz2Vorn": "",
                "Erz2StrHNr": "",
                "Erz2PLZ": "",
                "Erz2Ort": "",
                "Pencil": "ohne Apple Pencil",
                "ITNr": "IT-003",
                "SNr": "SN-11111",
                "Typ": "Apple iPad",
                "Status": "defekt",
                "AnschJahr": "2023",
                "AusleiheDatum": "",
                "Rückgabe": "",
            },
        ]

        df = pd.DataFrame(template_data)

        # Create Excel file in memory
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, sheet_name="Import-Vorlage", index=False)

        output.seek(0)

        return StreamingResponse(
            io.BytesIO(output.read()),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment; filename=import_vorlage.xlsx"},
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating template: {str(e)}")


@api_router.get("/exports/inventory")
@limiter.limit("10/minute")  # Stricter limit for exports
async def export_inventory(
    request: Request,
    columns: Optional[str] = None,
    group: Optional[str] = None,
    sus_vorn: Optional[str] = None,
    sus_nachn: Optional[str] = None,
    sus_kl: Optional[str] = None,
    itnr: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """Export complete data backup: all students, all iPads, and all assignments (1:n support).

    Optional ``columns`` query parameter is a comma-separated list of column
    names from EXPORT_COLUMNS. Defaults to all columns when omitted.

    Optional ``group`` query parameter narrows the result to a subset of the
    three row groups this endpoint normally combines (assigned pairs /
    students without an iPad / iPads without a student). Used by the
    Schüler- and iPad-Ansicht toggle ("Alle" / "Nur zugeordnete" / "Nur
    freie") to export exactly the rows currently shown:
      - "assigned_students": assigned rows + students without an iPad
      - "assigned_ipads": assigned rows + iPads without a student
      - "unassigned_students": only students without an iPad
      - "unassigned_ipads": only iPads without a student
      - omitted / anything else: all three groups combined (default, unchanged)

    Optional ``sus_vorn`` / ``sus_nachn`` / ``sus_kl`` / ``itnr`` filter the
    underlying students / iPads (same regex semantics as
    ``/assignments/export``), so the export matches the view's active filter.
    """
    selected_columns = _parse_columns_param(columns)
    include_assigned = group in (None, "assigned_students", "assigned_ipads")
    include_unassigned_students = group in (None, "assigned_students", "unassigned_students")
    include_unassigned_ipads = group in (None, "assigned_ipads", "unassigned_ipads")
    try:
        # Apply user filter - CRITICAL for RBAC!
        user_filter = await get_user_filter(current_user)

        student_filter = user_filter.copy()
        if sus_vorn:
            student_filter["sus_vorn"] = {"$regex": sus_vorn, "$options": "i"}
        if sus_nachn:
            student_filter["sus_nachn"] = {"$regex": sus_nachn, "$options": "i"}
        if sus_kl:
            student_filter["sus_kl"] = {"$regex": sus_kl, "$options": "i"}

        ipad_filter = user_filter.copy()
        if itnr:
            ipad_filter["itnr"] = {"$regex": itnr, "$options": "i"}

        # Get global settings
        settings = await db.global_settings.find_one({"type": "app_settings"})
        ipad_typ = settings.get("ipad_typ", "Apple iPad") if settings else "Apple iPad"
        pencil = settings.get("pencil", "ohne Apple Pencil") if settings else "ohne Apple Pencil"

        # Get all students (filtered by user + optional name/class filter)
        all_students = await db.students.find(student_filter).to_list(length=None)
        students_by_id = {s["id"]: s for s in all_students}

        # Get all iPads (filtered by user + optional ITNr filter)
        all_ipads = await db.ipads.find(ipad_filter).to_list(length=None)
        ipads_by_id = {i["id"]: i for i in all_ipads}

        # Get all active assignments (filtered by user)
        all_assignments = await db.assignments.find({**user_filter, "is_active": True}).to_list(length=None)

        # Preload contracts for assignments (for "Vertrag vorhanden" / "Vertrag validiert" columns)
        assignment_ids_with_contract = [a.get("contract_id") for a in all_assignments if a.get("contract_id")]
        contracts_by_id = {}
        if assignment_ids_with_contract:
            all_contracts = await db.contracts.find({"id": {"$in": assignment_ids_with_contract}}).to_list(length=None)
            contracts_by_id = {c["id"]: c for c in all_contracts}

        # Track which students and iPads are in assignments
        students_with_assignments = set()
        ipads_with_assignments = set()

        export_data = []

        # 1. Process all assignments (creates rows for students WITH iPads - respects 1:n)
        # Only rows where BOTH sides pass the active student/iPad filter are included.
        for assignment in all_assignments:
            student_id = assignment.get("student_id")
            ipad_id = assignment.get("ipad_id")

            student = students_by_id.get(student_id)
            ipad = ipads_by_id.get(ipad_id)

            if student:
                students_with_assignments.add(student_id)
            if ipad:
                ipads_with_assignments.add(ipad_id)

            if not include_assigned or not student or not ipad:
                continue

            export_data.append(
                _build_assignment_row(
                    student,
                    ipad,
                    assignment,
                    contracts_by_id,
                    ipad_typ_default=ipad_typ,
                    pencil_default=pencil,
                    selected_columns=selected_columns,
                )
            )

        # 2. Add students WITHOUT any iPad assignment
        if include_unassigned_students:
            for student_id, student in students_by_id.items():
                if student_id not in students_with_assignments:
                    export_data.append(
                        _build_assignment_row(
                            student,
                            None,
                            None,
                            contracts_by_id,
                            ipad_typ_default=ipad_typ,
                            pencil_default=pencil,
                            selected_columns=selected_columns,
                        )
                    )

        # 3. Add iPads WITHOUT any assignment
        if include_unassigned_ipads:
            for ipad_id, ipad in ipads_by_id.items():
                if ipad_id not in ipads_with_assignments:
                    export_data.append(
                        _build_assignment_row(
                            None,
                            ipad,
                            None,
                            contracts_by_id,
                            ipad_typ_default=ipad_typ,
                            pencil_default=pencil,
                            selected_columns=selected_columns,
                        )
                    )

        # Create DataFrame and export to Excel (canonical headers even on empty result)
        columns_for_df = selected_columns if selected_columns else EXPORT_COLUMNS
        df = pd.DataFrame(export_data, columns=columns_for_df)

        # Create Excel file in memory
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, sheet_name="Datensicherung", index=False)

        output.seek(0)

        # Return as downloadable file
        filename = f"datensicherung_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

        return StreamingResponse(
            io.BytesIO(output.read()),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating data backup: {str(e)}")


@api_router.get("/assignments/export")
@limiter.limit("10/minute")  # Stricter limit for exports
async def export_assignments(
    request: Request,
    sus_vorn: Optional[str] = None,
    sus_nachn: Optional[str] = None,
    sus_kl: Optional[str] = None,
    itnr: Optional[str] = None,
    columns: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """Export assignments to Excel (all or filtered).

    Optional ``columns`` query param: comma-separated list of column names
    from EXPORT_COLUMNS. Defaults to all columns when omitted.
    """
    selected_columns = _parse_columns_param(columns)
    # Apply user filter - CRITICAL for RBAC!
    user_filter = await get_user_filter(current_user)

    # Global settings for Pencil/Typ fallback (when iPad has no value of its own)
    settings = await db.global_settings.find_one({"type": "app_settings"})
    ipad_typ_default = settings.get("ipad_typ", "Apple iPad") if settings else "Apple iPad"
    pencil_default = settings.get("pencil", "ohne Apple Pencil") if settings else "ohne Apple Pencil"

    # Build filter query for students (with user filter!)
    student_filter = user_filter.copy()
    if sus_vorn:
        student_filter["sus_vorn"] = {"$regex": sus_vorn, "$options": "i"}
    if sus_nachn:
        student_filter["sus_nachn"] = {"$regex": sus_nachn, "$options": "i"}
    if sus_kl:
        student_filter["sus_kl"] = {"$regex": sus_kl, "$options": "i"}

    # Build filter query for assignments (IT-Nummer) with user filter!
    assignment_filter = user_filter.copy()
    assignment_filter["is_active"] = True
    if itnr:
        assignment_filter["itnr"] = {"$regex": itnr, "$options": "i"}

    if sus_vorn or sus_nachn or sus_kl:
        # Get matching students (filtered by user_id!)
        students = await db.students.find(student_filter).to_list(length=None)
        student_ids = [s["id"] for s in students]

        # Add student filter to assignment filter
        assignment_filter["student_id"] = {"$in": student_ids}

    # Get assignments matching all filters (filtered by user_id!)
    assignments = await db.assignments.find(assignment_filter).to_list(length=None)

    # Preload contracts for the assignment set (for Vertrag-Spalten)
    contract_ids = [a.get("contract_id") for a in assignments if a.get("contract_id")]
    contracts_by_id = {}
    if contract_ids:
        contracts = await db.contracts.find({"id": {"$in": contract_ids}}).to_list(length=None)
        contracts_by_id = {c["id"]: c for c in contracts}

    export_data = []
    for assignment in assignments:
        student = await db.students.find_one({"id": assignment["student_id"]})
        ipad = await db.ipads.find_one({"id": assignment["ipad_id"]})
        if student and ipad:
            export_data.append(
                _build_assignment_row(
                    student,
                    ipad,
                    assignment,
                    contracts_by_id,
                    ipad_typ_default=ipad_typ_default,
                    pencil_default=pencil_default,
                    selected_columns=selected_columns,
                )
            )

    # Create Excel file — ensure canonical headers even when no rows match
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        columns_for_df = selected_columns if selected_columns else EXPORT_COLUMNS
        df = pd.DataFrame(export_data, columns=columns_for_df)
        df.to_excel(writer, sheet_name="Zuordnungen", index=False)

    output.seek(0)

    return StreamingResponse(
        io.BytesIO(output.read()),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=zuordnungen_export.xlsx"},
    )


class ExportSelectedRequest(BaseModel):
    assignment_ids: List[str]
    columns: Optional[List[str]] = None


@api_router.post("/assignments/export-selected")
@limiter.limit("10/minute")
async def export_selected_assignments(
    request: Request, body: ExportSelectedRequest, current_user: dict = Depends(get_current_user)
):
    """Export selected assignments to Excel (by checkbox selection)."""
    if not body.assignment_ids:
        raise HTTPException(status_code=400, detail="Keine Zuordnungen ausgewählt")

    selected_columns = _parse_columns_param(",".join(body.columns)) if body.columns else None
    # Apply user filter - CRITICAL for RBAC!
    user_filter = await get_user_filter(current_user)

    # Global settings for Pencil/Typ fallback
    settings = await db.global_settings.find_one({"type": "app_settings"})
    ipad_typ_default = settings.get("ipad_typ", "Apple iPad") if settings else "Apple iPad"
    pencil_default = settings.get("pencil", "ohne Apple Pencil") if settings else "ohne Apple Pencil"

    # Get selected assignments (respecting user filter)
    assignments = await db.assignments.find(
        {"id": {"$in": body.assignment_ids}, "is_active": True, **user_filter}
    ).to_list(length=None)

    if not assignments:
        raise HTTPException(status_code=404, detail="Keine gültigen Zuordnungen gefunden")

    # Preload contracts for the selected assignments
    contract_ids = [a.get("contract_id") for a in assignments if a.get("contract_id")]
    contracts_by_id = {}
    if contract_ids:
        contracts = await db.contracts.find({"id": {"$in": contract_ids}}).to_list(length=None)
        contracts_by_id = {c["id"]: c for c in contracts}

    # Build export data
    export_data = []
    for assignment in assignments:
        student = await db.students.find_one({"id": assignment["student_id"], **user_filter})
        ipad = await db.ipads.find_one({"id": assignment["ipad_id"], **user_filter})
        if student and ipad:
            export_data.append(
                _build_assignment_row(
                    student,
                    ipad,
                    assignment,
                    contracts_by_id,
                    ipad_typ_default=ipad_typ_default,
                    pencil_default=pencil_default,
                    selected_columns=selected_columns,
                )
            )

    # Create Excel file
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        columns_for_df = selected_columns if selected_columns else EXPORT_COLUMNS
        df = pd.DataFrame(export_data, columns=columns_for_df)
        df.to_excel(writer, sheet_name="Zuordnungen", index=False)

    output.seek(0)

    return StreamingResponse(
        io.BytesIO(output.read()),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=zuordnungen_auswahl_export.xlsx"},
    )
