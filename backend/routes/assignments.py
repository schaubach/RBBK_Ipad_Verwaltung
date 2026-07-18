"""Assignment routes (/api/assignments/* plus /api/ipads/available-for-assignment)

Auto-extracted from monolithic server.py during refactor (Session 12).
"""

import io
from datetime import UTC, datetime
from typing import List, Optional

import PyPDF2
from core.config import (
    MAX_IPADS_PER_STUDENT,
    db,
    limiter,
)
from core.mongo import parse_from_mongo, prepare_for_mongo
from core.router import api_router
from core.security import (
    get_current_user,
    get_ipad_filter_with_pool,
    get_user_filter,
    is_admin,
    validate_resource_ownership,
)
from core.validators import validate_uploaded_file
from fastapi import Depends, File, HTTPException, UploadFile
from models.assignment import (
    Assignment,
    AssignmentResponse,
    ManualAssignmentRequest,
)
from models.contract import Contract
from starlette.requests import Request


@api_router.post("/assignments/auto-assign", response_model=AssignmentResponse)
async def auto_assign_ipads(current_user: dict = Depends(get_current_user)):
    """
    Automatische Zuordnung: Weist nur Schülern OHNE jegliche iPad-Zuordnung ein iPad zu.
    Schüler mit bereits 1, 2 oder 3 iPads werden NICHT berücksichtigt.
    """
    # Apply user filter
    user_filter = await get_user_filter(current_user)

    # Get all students for this user
    all_students = await db.students.find(user_filter).to_list(length=None)

    # Filter: Nur Schüler OHNE aktive Zuordnungen (nicht 1, nicht 2, nicht 3 - gar keine!)
    # und ohne "iPad verweigert"-Vermerk (die sollen nicht immer wieder automatisch bedacht werden).
    unassigned_students = []
    for student in all_students:
        if student.get("ipad_refused"):
            continue
        active_assignments = await db.assignments.count_documents({"student_id": student["id"], "is_active": True})
        if active_assignments == 0:
            unassigned_students.append(student)

    # Get available iPads for this user (not currently assigned, status = 'ok')
    ipad_filter = {**user_filter, "current_assignment_id": None, "status": "ok"}

    assigned_count = 0
    details = []

    for student in unassigned_students:
        now_iso = datetime.now(UTC).isoformat()

        # We need an assignment ID first so we can assign atomically
        assignment = Assignment(
            user_id=current_user["id"],
            student_id=student["id"],
            ipad_id="temp",
            itnr="temp",
            student_name=f"{student['sus_vorn']} {student['sus_nachn']}",
        )

        # Atomically find and claim an available iPad
        ipad = await db.ipads.find_one_and_update(
            ipad_filter, {"$set": {"current_assignment_id": assignment.id, "updated_at": now_iso}}
        )

        if not ipad:
            # No more available iPads
            break

        # Update assignment with actual iPad data
        assignment.ipad_id = ipad["id"]
        assignment.itnr = ipad["itnr"]

        assignment_dict = prepare_for_mongo(assignment.dict())
        await db.assignments.insert_one(assignment_dict)

        # Update student (just updated_at)
        await db.students.update_one({"id": student["id"]}, {"$set": {"updated_at": now_iso}})

        assigned_count += 1
        details.append(f"Assigned iPad {ipad['itnr']} to {student['sus_vorn']} {student['sus_nachn']}")

    return AssignmentResponse(
        message=f"Successfully assigned {assigned_count} iPads", assigned_count=assigned_count, details=details
    )


@api_router.post("/assignments/manual")
async def manual_assign(request: ManualAssignmentRequest, current_user: dict = Depends(get_current_user)):
    """
    Manually assign an iPad to a student without creating a contract.
    Only allowed if iPad is not currently assigned.
    If iPad is in pool, it will be auto-claimed by the current user first.
    """
    try:
        # Apply user filter for security
        user_filter = await get_user_filter(current_user)

        # Validate student ownership
        student = await db.students.find_one({"id": request.student_id, **user_filter})
        if not student:
            raise HTTPException(status_code=404, detail="Student not found or access denied")

        # Check if student already has maximum number of iPads (1:n relationship)
        student_assignments = await db.assignments.count_documents({"student_id": student["id"], "is_active": True})
        if student_assignments >= MAX_IPADS_PER_STUDENT:
            raise HTTPException(
                status_code=400,
                detail=f"Schüler hat bereits {MAX_IPADS_PER_STUDENT} iPad(s) zugewiesen (Maximum erreicht)",
            )

        # Validate iPad - either own or in pool
        ipad_filter = await get_ipad_filter_with_pool(current_user)
        ipad = await db.ipads.find_one({"id": request.ipad_id, **ipad_filter})
        if not ipad:
            raise HTTPException(status_code=404, detail="iPad not found or access denied")

        if ipad.get("current_assignment_id"):
            raise HTTPException(status_code=400, detail="iPad ist bereits zugewiesen")

        was_in_pool = ipad.get("is_in_pool", False)
        now_iso = datetime.now(UTC).isoformat()

        # Create assignment (without contract)
        assignment = Assignment(
            user_id=current_user["id"],
            student_id=student["id"],
            ipad_id=ipad["id"],
            itnr=ipad["itnr"],
            student_name=f"{student['sus_vorn']} {student['sus_nachn']}",
            contract_id=None,  # No contract for manual assignments
        )

        # ATOMIC CLAIM AND ASSIGN
        update_doc = {"$set": {"current_assignment_id": assignment.id, "updated_at": now_iso}}

        if was_in_pool:
            update_doc["$set"]["is_in_pool"] = False
            update_doc["$set"]["user_id"] = current_user["id"]
            update_doc["$push"] = {"pool_history": {"action": "claimed", "by": current_user["id"], "at": now_iso}}
            query = {"id": request.ipad_id, "is_in_pool": True, "current_assignment_id": None}
        else:
            # Admins may assign any owned iPad (regardless of owner);
            # regular users are already scoped to their own iPads by get_ipad_filter_with_pool above.
            query = {"id": request.ipad_id, "current_assignment_id": None}
            if not is_admin(current_user):
                query["user_id"] = current_user["id"]

        claim_result = await db.ipads.find_one_and_update(query, update_doc)

        if not claim_result:
            raise HTTPException(
                status_code=409, detail="iPad wurde gerade von einem anderen Benutzer übernommen oder zugewiesen"
            )

        assignment_dict = prepare_for_mongo(assignment.dict())
        await db.assignments.insert_one(assignment_dict)

        # Student update removed - no current_assignment_id field anymore (1:n relationship)
        # Assigning an iPad clears a prior "verweigert" mark - the person now has a device.
        await db.students.update_one(
            {"id": student["id"]}, {"$set": {"updated_at": now_iso, "ipad_refused": False}}
        )

        return {
            "message": f"iPad {ipad['itnr']} erfolgreich {student['sus_vorn']} {student['sus_nachn']} zugewiesen",
            "assignment_id": assignment.id,
            "student_name": f"{student['sus_vorn']} {student['sus_nachn']}",
            "itnr": ipad["itnr"],
            "claimed_from_pool": was_in_pool,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler bei manueller Zuordnung: {str(e)}")


@api_router.get("/ipads/available-for-assignment")
@limiter.limit("60/minute")
async def get_available_ipads(request: Request, current_user: dict = Depends(get_current_user)):
    """Get iPads without current assignment. Includes pool iPads."""
    ipad_filter = await get_ipad_filter_with_pool(current_user)
    ipads = await db.ipads.find({**ipad_filter, "current_assignment_id": None}, {"_id": 0}).to_list(length=None)

    return [
        {
            "id": i["id"],
            "itnr": i["itnr"],
            "snr": i.get("snr", "N/A"),
            "status": i.get("status", "ok"),
            "is_in_pool": i.get("is_in_pool", False),
        }
        for i in ipads
    ]


@api_router.get("/assignments", response_model=List[Assignment])
@limiter.limit("60/minute")
async def get_assignments(request: Request, current_user: dict = Depends(get_current_user)):
    # Apply user filter
    user_filter = await get_user_filter(current_user)
    assignment_filter = {**user_filter, "is_active": True}
    assignments = await db.assignments.find(assignment_filter).to_list(length=None)

    # Add contract validation warnings
    for assignment in assignments:
        assignment["contract_warning"] = False
        assignment["warning_dismissed"] = False

        if assignment.get("contract_id"):
            contract = await db.contracts.find_one({"id": assignment["contract_id"]})
            if contract and contract.get("form_fields"):
                fields = contract["form_fields"]

                # Validierungslogik für Vertrags-Checkboxen:
                # 1. Beide Nutzungs-Checkboxen MÜSSEN angekreuzt sein
                # 2. Bei Ausgabe MUSS genau eine angekreuzt sein (neu ODER gebraucht)

                nutzung_einhaltung = fields.get("NutzungEinhaltung") == "/Yes"
                # Note: The actual field name in contracts is 'NutzungKenntnisname', not 'NutzungKenntnisnahme'
                nutzung_kenntnisnahme_field = fields.get("NutzungKenntnisnahme") or fields.get(
                    "NutzungKenntnisname", ""
                )
                nutzung_kenntnisnahme = nutzung_kenntnisnahme_field == "/Yes" or bool(
                    nutzung_kenntnisnahme_field and nutzung_kenntnisnahme_field not in ["", "/Off"]
                )
                ausgabe_neu = fields.get("ausgabeNeu") == "/Yes"
                ausgabe_gebraucht = fields.get("ausgabeGebraucht") == "/Yes"

                # Validierung:
                # - nutzung_ok: Beide Nutzungs-Checkboxen müssen angekreuzt sein
                # - ausgabe_ok: Genau eine Ausgabe-Checkbox muss angekreuzt sein (XOR)
                nutzung_ok = nutzung_einhaltung and nutzung_kenntnisnahme
                ausgabe_ok = ausgabe_neu != ausgabe_gebraucht  # XOR: genau eine muss True sein

                warning_needed = not (nutzung_ok and ausgabe_ok)

                if warning_needed:
                    assignment["contract_warning"] = True
                    # Get warning_dismissed status from database
                    assignment["warning_dismissed"] = assignment.get("warning_dismissed", False)
                else:
                    assignment["contract_warning"] = False
                    assignment["warning_dismissed"] = False

    return [Assignment(**parse_from_mongo(assignment)) for assignment in assignments]


@api_router.post("/assignments/{assignment_id}/dismiss-warning")
async def dismiss_contract_warning(assignment_id: str, current_user: dict = Depends(get_current_user)):
    result = await db.assignments.update_one({"id": assignment_id}, {"$set": {"warning_dismissed": True}})

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Assignment not found")

    return {"message": "Warning dismissed"}


@api_router.post("/assignments/{assignment_id}/upload-contract")
async def upload_contract_for_assignment(
    assignment_id: str, file: UploadFile = File(...), current_user: dict = Depends(get_current_user)
):
    """Upload a new contract for a specific assignment (replaces existing contract)"""
    if not file.filename.endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only .pdf files are allowed")

    # Validate resource ownership
    await validate_resource_ownership("assignment", assignment_id, current_user)

    # Get the assignment
    assignment = await db.assignments.find_one({"id": assignment_id})
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")

    try:
        contents = await file.read()
        # Security: Validate uploaded file
        validate_uploaded_file(contents, file.filename, max_size_mb=15, allowed_types=[".pdf"])

        # Extract form fields from PDF
        reader = PyPDF2.PdfReader(io.BytesIO(contents))
        form_fields = {}

        try:
            if "/AcroForm" in reader.trailer["/Root"]:
                form = reader.trailer["/Root"]["/AcroForm"]
                if "/Fields" in form:
                    for field in form["/Fields"]:
                        field_obj = field.get_object()
                        field_name = field_obj.get("/T")
                        field_value = field_obj.get("/V")

                        if field_name:
                            form_fields[field_name] = field_value
        except:
            form_fields = {}

        # If assignment has an existing contract, mark it as inactive
        if assignment.get("contract_id"):
            await db.contracts.update_one(
                {"id": assignment["contract_id"]},
                {"$set": {"is_active": False, "updated_at": datetime.now(UTC).isoformat()}},
            )

        # Create new contract
        new_contract = Contract(
            user_id=current_user["id"],
            assignment_id=assignment_id,
            itnr=assignment["itnr"],
            student_name=assignment["student_name"],
            filename=file.filename,
            file_data=contents,
            form_fields=form_fields,
        )

        contract_dict = prepare_for_mongo(new_contract.dict())
        await db.contracts.insert_one(contract_dict)

        # Update assignment with new contract reference
        await db.assignments.update_one({"id": assignment_id}, {"$set": {"contract_id": new_contract.id}})

        # Apply validation logic to determine if warning should be shown
        contract_warning = False

        if form_fields:
            # Validierungslogik für Vertrags-Checkboxen:
            # 1. Beide Nutzungs-Checkboxen MÜSSEN angekreuzt sein
            # 2. Bei Ausgabe MUSS genau eine angekreuzt sein (neu ODER gebraucht)

            nutzung_einhaltung = form_fields.get("NutzungEinhaltung") == "/Yes"
            nutzung_kenntnisnahme_field = form_fields.get("NutzungKenntnisnahme") or form_fields.get(
                "NutzungKenntnisname", ""
            )
            nutzung_kenntnisnahme = nutzung_kenntnisnahme_field == "/Yes" or bool(
                nutzung_kenntnisnahme_field and nutzung_kenntnisnahme_field not in ["", "/Off"]
            )
            ausgabe_neu = form_fields.get("ausgabeNeu") == "/Yes"
            ausgabe_gebraucht = form_fields.get("ausgabeGebraucht") == "/Yes"

            # Validierung:
            # - nutzung_ok: Beide Nutzungs-Checkboxen müssen angekreuzt sein
            # - ausgabe_ok: Genau eine Ausgabe-Checkbox muss angekreuzt sein (XOR)
            nutzung_ok = nutzung_einhaltung and nutzung_kenntnisnahme
            ausgabe_ok = ausgabe_neu != ausgabe_gebraucht  # XOR: genau eine muss True sein

            warning_needed = not (nutzung_ok and ausgabe_ok)

            if warning_needed:
                contract_warning = True
        else:
            # No form fields = no validation issues (triangle disappears)
            contract_warning = False

        # Reset warning dismissed status for new contract
        await db.assignments.update_one({"id": assignment_id}, {"$set": {"warning_dismissed": False}})

        validation_status = "validation_warning" if contract_warning else "no_validation_issues"
        message = f"Contract uploaded successfully for assignment {assignment['itnr']} → {assignment['student_name']}"

        if not form_fields:
            message += " (No form fields found - validation warning cleared)"
        elif contract_warning:
            message += " (Validation warning: checkbox validation failed)"
        else:
            message += " (Contract validation passed)"

        return {
            "message": message,
            "contract_id": new_contract.id,
            "has_form_fields": bool(form_fields),
            "validation_status": validation_status,
            "contract_warning": contract_warning,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing contract: {str(e)}")


@api_router.delete("/assignments/{assignment_id}")
async def dissolve_assignment(assignment_id: str, current_user: dict = Depends(get_current_user)):
    """Dissolve an assignment"""
    # Validate resource ownership
    await validate_resource_ownership("assignment", assignment_id, current_user)

    assignment = await db.assignments.find_one({"id": assignment_id})
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")

    # Vertrag bleibt bestehen, nur assignment_id wird auf null gesetzt
    # Vertrag ist weiterhin über ipad_id und student_id findbar
    if assignment.get("contract_id"):
        await db.contracts.update_one(
            {"id": assignment["contract_id"]},
            {
                "$set": {
                    "assignment_id": None,  # Assignment-Referenz entfernen
                    # ipad_id und student_id bleiben erhalten!
                    "updated_at": datetime.now(UTC).isoformat(),
                }
            },
        )

    # Mark assignment as inactive
    await db.assignments.update_one(
        {"id": assignment_id},
        {
            "$set": {
                "is_active": False,
                "unassigned_at": datetime.now(UTC).isoformat(),
                "updated_at": datetime.now(UTC).isoformat(),
            }
        },
    )

    # Update iPad status to available
    await db.ipads.update_one(
        {"id": assignment["ipad_id"]},
        {"$set": {"current_assignment_id": None, "updated_at": datetime.now(UTC).isoformat()}},
    )

    # Student update - no current_assignment_id field anymore (1:n relationship)
    await db.students.update_one(
        {"id": assignment["student_id"]}, {"$set": {"updated_at": datetime.now(UTC).isoformat()}}
    )

    return {"message": "Assignment dissolved successfully"}


@api_router.post("/assignments/batch-dissolve")
async def batch_dissolve_assignments(filter_params: dict, current_user: dict = Depends(get_current_user)):
    """
    Dissolve multiple assignments at once (filtered or all)

    filter_params can include:
    - "all": true (dissolves all user's assignments)
    - "sus_vorn": string (filter by student first name)
    - "sus_nachn": string (filter by student last name)
    - "sus_kl": string (filter by class)
    - "itnr": string (filter by iPad IT number)
    """
    try:
        # Apply user filter - CRITICAL for RBAC!
        user_filter = await get_user_filter(current_user)

        # Build assignment filter
        assignment_filter = user_filter.copy()
        assignment_filter["is_active"] = True

        # If not "all", apply specific filters
        if not filter_params.get("all", False):
            # Build student filter if student-related params exist
            student_filter = user_filter.copy()
            has_student_filter = False

            if filter_params.get("sus_vorn"):
                student_filter["sus_vorn"] = {"$regex": filter_params["sus_vorn"], "$options": "i"}
                has_student_filter = True
            if filter_params.get("sus_nachn"):
                student_filter["sus_nachn"] = {"$regex": filter_params["sus_nachn"], "$options": "i"}
                has_student_filter = True
            if filter_params.get("sus_kl"):
                student_filter["sus_kl"] = {"$regex": filter_params["sus_kl"], "$options": "i"}
                has_student_filter = True

            # Apply iPad filter if provided
            if filter_params.get("itnr"):
                assignment_filter["itnr"] = {"$regex": filter_params["itnr"], "$options": "i"}

            # If student filters exist, get matching student IDs
            if has_student_filter:
                students = await db.students.find(student_filter).to_list(length=None)
                student_ids = [s["id"] for s in students]

                if not student_ids:
                    return {"message": "No assignments match the filter criteria", "dissolved_count": 0, "details": []}

                assignment_filter["student_id"] = {"$in": student_ids}

        # Get all matching assignments
        assignments = await db.assignments.find(assignment_filter).to_list(length=None)

        if not assignments:
            return {"message": "No active assignments found to dissolve", "dissolved_count": 0, "details": []}

        dissolved_count = 0
        details = []

        # Dissolve each assignment
        for assignment in assignments:
            try:
                # Move contract to history if exists
                if assignment.get("contract_id"):
                    await db.contracts.update_one(
                        {"id": assignment["contract_id"]},
                        {"$set": {"is_active": False, "updated_at": datetime.now(UTC).isoformat()}},
                    )

                # Mark assignment as inactive
                await db.assignments.update_one(
                    {"id": assignment["id"]},
                    {
                        "$set": {
                            "is_active": False,
                            "unassigned_at": datetime.now(UTC).isoformat(),
                            "updated_at": datetime.now(UTC).isoformat(),
                        }
                    },
                )

                # Update iPad status to available
                await db.ipads.update_one(
                    {"id": assignment["ipad_id"]},
                    {"$set": {"current_assignment_id": None, "updated_at": datetime.now(UTC).isoformat()}},
                )

                # Update student
                await db.students.update_one(
                    {"id": assignment["student_id"]},
                    {"$set": {"current_assignment_id": None, "updated_at": datetime.now(UTC).isoformat()}},
                )

                dissolved_count += 1
                details.append(f"Assignment {assignment.get('itnr', 'Unknown')} dissolved")

            except Exception as e:
                details.append(f"Error dissolving assignment {assignment.get('itnr', 'Unknown')}: {str(e)}")

        return {
            "message": f"Successfully dissolved {dissolved_count} assignment(s)",
            "dissolved_count": dissolved_count,
            "total_found": len(assignments),
            "details": details,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during batch dissolve: {str(e)}")


@api_router.get("/assignments/filtered")
async def get_filtered_assignments(
    sus_vorn: Optional[str] = None,
    sus_nachn: Optional[str] = None,
    sus_kl: Optional[str] = None,
    itnr: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    try:
        # Apply user filter - CRITICAL for RBAC!
        user_filter = await get_user_filter(current_user)

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

            if not student_ids:
                # No matching students found
                return []

            # Add student filter to assignment filter
            assignment_filter["student_id"] = {"$in": student_ids}

        # Get assignments matching all filters (filtered by user_id!)
        assignments = await db.assignments.find(assignment_filter).to_list(length=None)

        # Safe parsing
        result = []
        for assignment in assignments:
            try:
                result.append(Assignment(**parse_from_mongo(assignment)))
            except Exception as e:
                print(f"Error parsing assignment {assignment.get('id')}: {e}")
                continue

        return result

    except Exception as e:
        print(f"Filter error: {e}")
        raise HTTPException(status_code=500, detail=f"Filter error: {str(e)}")
