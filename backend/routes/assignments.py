"""Assignment routes (/api/assignments/* plus /api/ipads/available-for-assignment)

Auto-extracted from monolithic server.py during refactor (Session 12).
"""

import io
from datetime import UTC, datetime
from typing import List, Optional

import PyPDF2
from fastapi import Depends, File, HTTPException, UploadFile
from starlette.requests import Request

from core.config import (
    MAX_IPADS_PER_STUDENT,
    db,
    limiter,
)
from core.mongo import parse_from_mongo, prepare_for_mongo
from core.router import api_router
from core.security import (
    get_current_user,
    get_ipad_filter,
    get_user_filter,
    mit_ansicht,
    validate_resource_ownership,
)
from core.validators import validate_uploaded_file
from models.assignment import (
    Assignment,
    ManualAssignmentRequest,
)
from models.contract import Contract


@api_router.post("/assignments/manual")
async def manual_assign(request: ManualAssignmentRequest, current_user: dict = Depends(get_current_user)):
    """
    Manually assign an iPad to a student without creating a contract.
    Only allowed if iPad is not currently assigned.

    Poolgeraete gehen hier NICHT direkt an einen Schueler. Aus dem Pool fuehrt ein einziger
    Weg: "BG zuordnen" (assign-to-bildungsgang) mit festgehaltener Uebergabe an eine Person -
    danach ordnet der Bildungsgang das Geraet seinen Schuelern zu. Frueher holte diese Route
    ein Poolgeraet still in den Bildungsgang des Schuelers, ohne dass je jemand quittiert
    haette, wer es bekommen hat.
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
                detail=f"Diese lernende Person hat bereits {MAX_IPADS_PER_STUDENT} iPad(s) zugewiesen (Maximum erreicht)",
            )

        # Validate iPad
        ipad_filter = await get_ipad_filter(current_user)
        ipad = await db.ipads.find_one({"id": request.ipad_id, **ipad_filter})
        if not ipad:
            raise HTTPException(status_code=404, detail="iPad not found or access denied")

        if ipad.get("current_assignment_id"):
            raise HTTPException(status_code=400, detail="iPad ist bereits zugewiesen")

        if ipad.get("is_in_pool"):
            raise HTTPException(
                status_code=400,
                detail="Dieses iPad liegt im Pool. Bitte zuerst per „BG zuordnen“ einem Bildungsgang "
                "zuordnen - danach kann es Lernenden zugeordnet werden.",
            )

        # Die Zuordnung erbt den Bildungsgang des Schuelers - ohne einen solchen gibt es nichts
        # zu erben, und der Datensatz waere hinterher fuer niemanden sichtbar.
        student_bildungsgang_id = student.get("bildungsgang_id")
        if not student_bildungsgang_id:
            raise HTTPException(
                status_code=400,
                detail="Diese lernende Person ist keinem Bildungsgang zugeordnet. "
                "Bitte sie zuerst einem Bildungsgang zuordnen.",
            )

        # Schueler und Geraet muessen zum selben Bildungsgang gehoeren. Ein Geraet aus fremdem
        # Bestand auszugeben, entzoege es dort der Verwaltung, ohne dass es jemand bemerkt.
        if ipad.get("bildungsgang_id") != student_bildungsgang_id:
            raise HTTPException(
                status_code=400,
                detail="Dieses iPad gehört zu einem anderen Bildungsgang als die lernende Person. "
                "Bitte ein Gerät aus ihrem Bildungsgang wählen.",
            )

        now_iso = datetime.now(UTC).isoformat()

        # Create assignment (without contract). Die Zuordnung gehoert dem Bildungsgang des
        # Schuelers; user_id haelt nur noch fest, wer sie angelegt hat.
        assignment = Assignment(
            user_id=current_user["id"],  # angelegt von
            bildungsgang_id=student_bildungsgang_id,
            student_id=student["id"],
            ipad_id=ipad["id"],
            itnr=ipad["itnr"],
            student_name=f"{student['sus_vorn']} {student['sus_nachn']}",
            contract_id=None,  # No contract for manual assignments
        )

        # ATOMIC CLAIM AND ASSIGN
        update_doc = {"$set": {"current_assignment_id": assignment.id, "updated_at": now_iso}}

        # Der Bildungsgang wird im atomaren Schreiben erneut geprueft: zwischen Lesen und
        # Schreiben kann das Geraet in den Pool gegangen oder umgehaengt worden sein. Fuer
        # Admins gilt das genauso - sie duerfen jeden Bestand bedienen, aber nicht quer ueber
        # Bildungsgaenge hinweg.
        query = {
            "id": request.ipad_id,
            "current_assignment_id": None,
            "bildungsgang_id": student_bildungsgang_id,
            "is_in_pool": {"$ne": True},
        }

        claim_result = await db.ipads.find_one_and_update(query, update_doc)

        if not claim_result:
            raise HTTPException(
                status_code=409, detail="iPad wurde gerade von einem anderen Benutzer übernommen oder zugewiesen"
            )

        assignment_dict = prepare_for_mongo(assignment.dict())
        await db.assignments.insert_one(assignment_dict)

        # Student update removed - no current_assignment_id field anymore (1:n relationship)
        # Assigning an iPad clears a prior "verweigert" mark - the person now has a device.
        await db.students.update_one({"id": student["id"]}, {"$set": {"updated_at": now_iso, "ipad_refused": False}})

        return {
            "message": f"iPad {ipad['itnr']} erfolgreich {student['sus_vorn']} {student['sus_nachn']} zugewiesen",
            "assignment_id": assignment.id,
            "student_name": f"{student['sus_vorn']} {student['sus_nachn']}",
            "itnr": ipad["itnr"],
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler bei manueller Zuordnung: {str(e)}")


@api_router.get("/ipads/available-for-assignment")
@limiter.limit("60/minute")
async def get_available_ipads(request: Request, current_user: dict = Depends(get_current_user)):
    """iPads ohne aktive Zuordnung - ohne Poolgeraete: die gehen erst per "BG zuordnen" an einen
    Bildungsgang, bevor sie einem Schueler zugeordnet werden koennen."""
    ipad_filter = await get_ipad_filter(current_user)
    ipads = await db.ipads.find(
        {**ipad_filter, "current_assignment_id": None, "is_in_pool": {"$ne": True}}, {"_id": 0}
    ).to_list(length=None)

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
async def get_assignments(
    request: Request,
    bildungsgang_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    # Apply user filter
    user_filter = await get_user_filter(current_user)
    # Der Parameter wurde bisher entgegengenommen und stillschweigend verworfen: wer die
    # Ansicht auf einen Bildungsgang eingeengt hatte, bekam hier trotzdem alles. Die drei
    # vergleichbaren Listen (iPads, Schueler, Vertraege) engen darueber ein, diese jetzt
    # auch - eine Liste, die als einzige der Ansicht nicht folgt, erklaert niemand zweimal.
    # Rein zur Ansicht: die Rechte stehen im user_filter und bleiben unberuehrt.
    user_filter = mit_ansicht(user_filter, bildungsgang_id)
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
    await validate_resource_ownership("assignment", assignment_id, current_user)
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

        # Create new contract. Der Vertrag gehoert dem Bildungsgang seiner Zuordnung - geerbt,
        # nicht neu bestimmt: wer fuer mehrere Bildungsgaenge zustaendig ist, wuerde sonst beim
        # Hochladen den Vertrag vom Schueler weg in einen anderen Bestand schieben.
        # Ohne Bildungsgang entstuende ein Vertrag, den ausser Admins niemand mehr sieht - und
        # Vertrags-PDFs gibt es nirgends sonst. Die Nachbarpfade dieser Datei lehnen denselben
        # Fall ab, statt ihn durchzureichen.
        if not assignment.get("bildungsgang_id"):
            raise HTTPException(
                status_code=400,
                detail="Diese Zuordnung gehört noch keinem Bildungsgang. Bitte zuerst den "
                "Bildungsgang der Zuordnung setzen, sonst wäre der Vertrag anschließend "
                "für niemanden auffindbar.",
            )

        new_contract = Contract(
            user_id=current_user["id"],  # angelegt von
            bildungsgang_id=assignment["bildungsgang_id"],
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

    except HTTPException:
        # Die eigenen Meldungen dieses Pfades (fehlender Bildungsgang, zu grosse oder falsche
        # Datei) sagen, was zu tun ist. Ohne diese Zeile faengt der generische Block sie mit und
        # liefert sie als "Error processing contract: 400: ..." mit Status 500 aus - die
        # Anwendung meldete einen Serverfehler statt der Handlungsanweisung.
        raise
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
