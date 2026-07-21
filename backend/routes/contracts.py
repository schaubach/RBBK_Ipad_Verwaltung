"""Contract routes (/api/contracts/*, contract upload)

Auto-extracted from monolithic server.py during refactor (Session 12).
"""

import io
import os
import re
from datetime import UTC, datetime
from typing import List

import PyPDF2
from core.config import (
    MAX_CONTRACTS_PER_STUDENT,
    db,
    limiter,
)
from core.mongo import prepare_for_mongo
from core.router import api_router
from core.security import (
    get_current_user,
    get_user_filter,
    validate_resource_ownership,
)
from core.validators import validate_uploaded_file
from fastapi import Depends, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from models.contract import Contract
from pydantic import BaseModel
from starlette.requests import Request


@api_router.post("/contracts/upload-multiple")
async def upload_multiple_contracts(
    files: List[UploadFile] = File(...), current_user: dict = Depends(get_current_user)
):
    results = []
    processed_count = 0
    unassigned_count = 0

    # Allowed file types
    allowed_extensions = [".pdf", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"]

    for file in files[:50]:  # Limit to 50 files max
        file_ext = os.path.splitext(file.filename.lower())[1]
        if file_ext not in allowed_extensions:
            results.append(
                {
                    "filename": file.filename,
                    "status": "error",
                    "message": f"Nur PDF und Bilder erlaubt ({', '.join(allowed_extensions)})",
                }
            )
            continue

        try:
            contents = await file.read()
            # Security: Validate uploaded file (10MB for images, 15MB for PDF)
            max_size = 10 if file_ext != ".pdf" else 15
            validate_uploaded_file(contents, file.filename, max_size_mb=max_size, allowed_types=allowed_extensions)

            # Extract form fields from PDF (only for PDFs)
            form_fields = {}
            itnr = None
            sus_vorn = None
            sus_nachn = None

            if file_ext == ".pdf":
                try:
                    reader = PyPDF2.PdfReader(io.BytesIO(contents))
                    if "/AcroForm" in reader.trailer["/Root"]:
                        form = reader.trailer["/Root"]["/AcroForm"]
                        if "/Fields" in form:
                            for field in form["/Fields"]:
                                field_obj = field.get_object()
                                field_name = field_obj.get("/T")
                                field_value = field_obj.get("/V")

                                if field_name:
                                    form_fields[field_name] = field_value

                    # Check if contract has required fields for auto-assignment (PDF form fields)
                    itnr = form_fields.get("ITNr")
                    sus_vorn = form_fields.get("SuSVorn")
                    sus_nachn = form_fields.get("SuSNachn")
                except:
                    form_fields = {}

            assignment_found = False
            assignment_method = ""

            if itnr and sus_vorn and sus_nachn:
                # Try auto-assignment by PDF form fields (user's assignments only)
                user_filter = await get_user_filter(current_user)
                assignment = await db.assignments.find_one({**user_filter, "itnr": str(itnr), "is_active": True})

                if assignment:
                    assignment_found = True
                    assignment_method = f"PDF form fields (iPad {itnr})"

                    # Check if assignment already has a contract
                    if assignment.get("contract_id"):
                        results.append(
                            {
                                "filename": file.filename,
                                "status": "skipped",
                                "message": "Assignment hat bereits einen Vertrag",
                            }
                        )
                        continue

                    # Create contract with all 3 references
                    contract = Contract(
                        user_id=current_user["id"],
                        assignment_id=assignment["id"],
                        ipad_id=assignment.get("ipad_id"),
                        student_id=assignment.get("student_id"),
                        itnr=str(itnr),
                        student_name=f"{sus_vorn} {sus_nachn}",
                        filename=file.filename,
                        file_data=contents,
                        form_fields=form_fields,
                    )

                    contract_dict = prepare_for_mongo(contract.dict())
                    await db.contracts.insert_one(contract_dict)

                    # Update assignment with contract reference
                    await db.assignments.update_one({"id": assignment["id"]}, {"$set": {"contract_id": contract.id}})

                    processed_count += 1
                    results.append(
                        {"filename": file.filename, "status": "assigned", "message": f"Assigned by {assignment_method}"}
                    )
                    continue

            # If PDF form fields didn't work, try filename-based auto-assignment (Vorname_Nachname.pdf)
            if not assignment_found:
                filename_without_ext = file.filename.replace(".pdf", "").replace(".PDF", "")
                if "_" in filename_without_ext:
                    parts = filename_without_ext.split("_")
                    if len(parts) == 2:
                        vorname_file, nachname_file = parts[0].strip(), parts[1].strip()

                        # Search for student with matching name in active assignments (user's assignments only)
                        user_filter = await get_user_filter(current_user)
                        match_filter = {
                            **user_filter,
                            "is_active": True,
                            "student.sus_vorn": {"$regex": f"^{re.escape(vorname_file)}$", "$options": "i"},
                            "student.sus_nachn": {"$regex": f"^{re.escape(nachname_file)}$", "$options": "i"},
                        }

                        pipeline = [
                            {
                                "$lookup": {
                                    "from": "students",
                                    "localField": "student_id",
                                    "foreignField": "id",
                                    "as": "student",
                                }
                            },
                            {"$match": match_filter},
                        ]

                        assignment_results = await db.assignments.aggregate(pipeline).to_list(length=None)

                        if assignment_results:
                            assignment = assignment_results[0]
                            student_data = assignment["student"][0] if assignment["student"] else None

                            if student_data:
                                # Check if assignment already has a contract
                                if assignment.get("contract_id"):
                                    results.append(
                                        {
                                            "filename": file.filename,
                                            "status": "skipped",
                                            "message": "Assignment hat bereits einen Vertrag",
                                        }
                                    )
                                    continue

                                assignment_found = True
                                assignment_method = f"filename pattern ({vorname_file}_{nachname_file})"

                                # Create contract with all 3 references
                                contract = Contract(
                                    user_id=current_user["id"],
                                    assignment_id=assignment["id"],
                                    ipad_id=assignment.get("ipad_id"),
                                    student_id=assignment.get("student_id"),
                                    itnr=assignment["itnr"],
                                    student_name=f"{student_data['sus_vorn']} {student_data['sus_nachn']}",
                                    filename=file.filename,
                                    file_data=contents,
                                    form_fields=form_fields,
                                )

                                contract_dict = prepare_for_mongo(contract.dict())
                                await db.contracts.insert_one(contract_dict)

                                # Update assignment with contract reference
                                await db.assignments.update_one(
                                    {"id": assignment["id"]}, {"$set": {"contract_id": contract.id}}
                                )

                                processed_count += 1
                                results.append(
                                    {
                                        "filename": file.filename,
                                        "status": "assigned",
                                        "message": f"Assigned by {assignment_method}",
                                    }
                                )
                                continue

            # Create unassigned contract
            contract = Contract(
                user_id=current_user["id"],
                filename=file.filename,
                file_data=contents,
                form_fields=form_fields,
                is_active=False,  # Unassigned contracts are inactive
            )

            contract_dict = prepare_for_mongo(contract.dict())
            await db.contracts.insert_one(contract_dict)

            unassigned_count += 1
            results.append(
                {"filename": file.filename, "status": "unassigned", "message": "Contract saved as unassigned"}
            )

        except Exception as e:
            results.append({"filename": file.filename, "status": "error", "message": f"Error: {str(e)}"})

    return {
        "message": f"Processed {len(files)} contracts: {processed_count} assigned, {unassigned_count} unassigned",
        "processed_count": processed_count,
        "unassigned_count": unassigned_count,
        "results": results,
    }


@api_router.get("/contracts")
@limiter.limit("60/minute")
async def get_all_contracts(request: Request, current_user: dict = Depends(get_current_user)):
    """Get all contracts (assigned and unassigned)"""
    user_filter = await get_user_filter(current_user)
    contracts = await db.contracts.find(user_filter, {"_id": 0, "file_data": 0}).to_list(length=None)

    result = []
    for contract in contracts:
        try:
            contract_dict = {
                "id": contract.get("id"),
                "assignment_id": contract.get("assignment_id"),
                "ipad_id": contract.get("ipad_id"),
                "student_id": contract.get("student_id"),
                "itnr": contract.get("itnr"),
                "student_name": contract.get("student_name"),
                "filename": contract.get("filename"),
                "form_fields": contract.get("form_fields", {}),
                "uploaded_at": contract.get("uploaded_at"),
                "is_active": contract.get("is_active", True),
            }
            result.append(contract_dict)
        except Exception as e:
            print(f"Error processing contract {contract.get('id')}: {e}")
            continue

    return result


@api_router.get("/contracts/unassigned")
@limiter.limit("60/minute")
async def get_unassigned_contracts(request: Request, current_user: dict = Depends(get_current_user)):
    # Apply user filter - unassigned = no assignment_id
    user_filter = await get_user_filter(current_user)
    contract_filter = {**user_filter, "$or": [{"assignment_id": None}, {"assignment_id": {"$exists": False}}]}
    contracts = await db.contracts.find(contract_filter, {"_id": 0, "file_data": 0}).to_list(length=None)

    # Return contracts without file_data to avoid encoding issues
    result = []
    for contract in contracts:
        try:
            contract_dict = {
                "id": contract.get("id"),
                "assignment_id": contract.get("assignment_id"),
                "ipad_id": contract.get("ipad_id"),
                "student_id": contract.get("student_id"),
                "itnr": contract.get("itnr"),
                "student_name": contract.get("student_name"),
                "filename": contract.get("filename"),
                "form_fields": contract.get("form_fields", {}),
                "uploaded_at": contract.get("uploaded_at"),
                "is_active": contract.get("is_active", False),
            }
            result.append(contract_dict)
        except Exception as e:
            print(f"Error processing contract {contract.get('id')}: {e}")
            continue

    return result


@api_router.get("/assignments/available-for-contracts")
async def get_assignments_available_for_contracts(current_user: dict = Depends(get_current_user)):
    """Get assignments that don't have a contract yet AND where student hasn't reached limit"""
    user_filter = await get_user_filter(current_user)

    # Get assignments without contracts
    assignments = await db.assignments.find(
        {**user_filter, "is_active": True, "$or": [{"contract_id": None}, {"contract_id": {"$exists": False}}]}
    ).to_list(length=None)

    # Count contracts per student
    student_contract_count = {}
    for assignment in assignments:
        student_id = assignment.get("student_id")
        if student_id and student_id not in student_contract_count:
            count = await db.contracts.count_documents({**user_filter, "student_id": student_id, "is_active": True})
            student_contract_count[student_id] = count

    # Filter: Assignment hat keinen Vertrag UND Schüler hat Limit nicht erreicht
    available = []
    for a in assignments:
        student_id = a.get("student_id")
        if student_id and student_contract_count.get(student_id, 0) < MAX_CONTRACTS_PER_STUDENT:
            # Get student data for filtering (vorname, nachname, klasse)
            student = await db.students.find_one({"id": student_id})
            # Get iPad data for completeness warnings
            ipad = await db.ipads.find_one({"id": a.get("ipad_id")})

            missing_fields = []
            if not (ipad and (ipad.get("typ") or "").strip()):
                missing_fields.append("Typ")
            if not (ipad and (ipad.get("snr") or "").strip()):
                missing_fields.append("SNr")
            if not (student and (student.get("sus_geb") or "").strip()):
                missing_fields.append("Geburtsdatum")

            available.append(
                {
                    "assignment_id": a["id"],
                    "itnr": a["itnr"],
                    "student_name": a["student_name"],
                    "sus_vorn": student.get("sus_vorn", "") if student else "",
                    "sus_nachn": student.get("sus_nachn", "") if student else "",
                    "sus_kl": student.get("sus_kl", "") if student else "",
                    "ipad_typ": ipad.get("typ", "") if ipad else "",
                    "ipad_snr": ipad.get("snr", "") if ipad else "",
                    "missing_fields": missing_fields,
                    "contracts_count": student_contract_count.get(student_id, 0),
                    "max_contracts": MAX_CONTRACTS_PER_STUDENT,
                }
            )

    return available


@api_router.post("/contracts/{contract_id}/assign/{assignment_id}")
async def assign_contract_to_assignment(
    contract_id: str, assignment_id: str, current_user: dict = Depends(get_current_user)
):
    # Validate ownership of both resources
    await validate_resource_ownership("contract", contract_id, current_user)
    await validate_resource_ownership("assignment", assignment_id, current_user)

    # Get contract and assignment
    contract = await db.contracts.find_one({"id": contract_id})
    assignment = await db.assignments.find_one({"id": assignment_id})

    if not contract or not assignment:
        raise HTTPException(status_code=404, detail="Contract or assignment not found")

    # Check if assignment already has a contract
    if assignment.get("contract_id"):
        raise HTTPException(status_code=400, detail="Diese Zuordnung hat bereits einen Vertrag")

    # Get student and iPad info
    student_id = assignment.get("student_id")
    ipad_id = assignment.get("ipad_id")

    # Check contract limit for student
    if student_id:
        user_filter = await get_user_filter(current_user)
        existing_contracts = await db.contracts.count_documents(
            {**user_filter, "student_id": student_id, "is_active": True}
        )

        if existing_contracts >= MAX_CONTRACTS_PER_STUDENT:
            raise HTTPException(
                status_code=400,
                detail=f"Schüler hat bereits {MAX_CONTRACTS_PER_STUDENT} Vertrag/Verträge (Maximum erreicht)",
            )

    # Update contract with all 3 references
    await db.contracts.update_one(
        {"id": contract_id},
        {
            "$set": {
                "assignment_id": assignment_id,
                "ipad_id": ipad_id,
                "student_id": student_id,
                "itnr": assignment["itnr"],
                "student_name": assignment["student_name"],
                "is_active": True,
                "updated_at": datetime.now(UTC).isoformat(),
            }
        },
    )

    # Update assignment with contract reference
    await db.assignments.update_one({"id": assignment_id}, {"$set": {"contract_id": contract_id}})

    return {"message": "Contract assigned successfully"}


@api_router.get("/contracts/{contract_id}")
async def get_contract(contract_id: str, current_user: dict = Depends(get_current_user)):
    await validate_resource_ownership("contract", contract_id, current_user)
    contract = await db.contracts.find_one({"id": contract_id})
    if not contract:
        raise HTTPException(status_code=404, detail="Contract not found")

    return {
        "id": contract["id"],
        "filename": contract["filename"],
        "student_name": contract.get("student_name"),
        "itnr": contract.get("itnr"),
        "uploaded_at": contract["uploaded_at"],
        "form_fields": contract.get("form_fields", {}),
        "is_active": contract.get("is_active", True),
    }


@api_router.get("/contracts/{contract_id}/download")
@limiter.limit("30/minute")
async def download_contract(request: Request, contract_id: str, current_user: dict = Depends(get_current_user)):
    await validate_resource_ownership("contract", contract_id, current_user)
    contract = await db.contracts.find_one({"id": contract_id})
    if not contract:
        raise HTTPException(status_code=404, detail="Contract not found")

    return StreamingResponse(
        io.BytesIO(contract["file_data"]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={contract['filename']}"},
    )


@api_router.delete("/contracts/{contract_id}")
async def delete_contract(contract_id: str, current_user: dict = Depends(get_current_user)):
    await validate_resource_ownership("contract", contract_id, current_user)
    contract = await db.contracts.find_one({"id": contract_id})
    if not contract:
        raise HTTPException(status_code=404, detail="Contract not found")

    # If contract was assigned to an assignment, remove the reference
    if contract.get("assignment_id"):
        await db.assignments.update_one(
            {"id": contract["assignment_id"]},
            {"$set": {"contract_id": None, "updated_at": datetime.now(UTC).isoformat()}},
        )

    # Delete the contract
    result = await db.contracts.delete_one({"id": contract_id})

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Contract not found")

    return {"message": "Contract deleted successfully"}


@api_router.post("/contracts/{contract_id}/unassign")
async def unassign_contract(contract_id: str, current_user: dict = Depends(get_current_user)):
    """Remove the assignment from a contract (keeps the contract but removes the link)"""
    await validate_resource_ownership("contract", contract_id, current_user)
    contract = await db.contracts.find_one({"id": contract_id})
    if not contract:
        raise HTTPException(status_code=404, detail="Contract not found")

    if not contract.get("assignment_id"):
        raise HTTPException(status_code=400, detail="Contract is not assigned")

    assignment_id = contract["assignment_id"]

    # Update the assignment to remove contract reference
    await db.assignments.update_one(
        {"id": assignment_id}, {"$set": {"contract_id": None, "updated_at": datetime.now(UTC).isoformat()}}
    )

    # Update the contract to remove assignment reference (keep student_id and ipad_id for historical purposes)
    await db.contracts.update_one(
        {"id": contract_id}, {"$set": {"assignment_id": None, "updated_at": datetime.now(UTC).isoformat()}}
    )

    return {"message": "Contract unassigned successfully"}


class BatchDeleteContractsRequest(BaseModel):
    contract_ids: List[str]


@api_router.post("/contracts/batch-delete")
async def batch_delete_contracts(request: BatchDeleteContractsRequest, current_user: dict = Depends(get_current_user)):
    """Delete multiple contracts at once"""
    if not request.contract_ids:
        raise HTTPException(status_code=400, detail="No contract IDs provided")

    if len(request.contract_ids) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 contracts can be deleted at once")

    deleted_count = 0
    errors = []
    user_filter = await get_user_filter(current_user)

    for contract_id in request.contract_ids:
        try:
            contract = await db.contracts.find_one({"id": contract_id, **user_filter})
            if not contract:
                errors.append({"contract_id": contract_id, "error": "Not found"})
                continue

            # If contract was assigned to an assignment, remove the reference
            if contract.get("assignment_id"):
                await db.assignments.update_one(
                    {"id": contract["assignment_id"]},
                    {"$set": {"contract_id": None, "updated_at": datetime.now(UTC).isoformat()}},
                )

            # Delete the contract
            result = await db.contracts.delete_one({"id": contract_id})
            if result.deleted_count > 0:
                deleted_count += 1
            else:
                errors.append({"contract_id": contract_id, "error": "Delete failed"})
        except Exception as e:
            errors.append({"contract_id": contract_id, "error": str(e)})

    return {
        "message": f"{deleted_count} contracts deleted successfully",
        "deleted_count": deleted_count,
        "errors": errors,
    }
