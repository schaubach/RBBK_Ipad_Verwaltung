"""Student CRUD routes (/api/students/*)

Auto-extracted from monolithic server.py during refactor (Session 12).
"""

import re
from datetime import UTC, datetime
from typing import List, Optional

from core.config import (
    MAX_IPADS_PER_STUDENT,
    db,
    limiter,
)
from core.mongo import parse_from_mongo, prepare_for_mongo
from core.router import api_router
from core.security import (
    get_current_user,
    get_user_filter,
    is_admin,
    validate_resource_ownership,
)
from fastapi import Depends, HTTPException
from models.student import Student, StudentWithAssignmentCount
from pydantic import BaseModel
from starlette.requests import Request


@api_router.post("/students", response_model=Student)
async def create_student(student_data: dict, current_user: dict = Depends(get_current_user)):
    """Manuell einen neuen Schüler anlegen"""
    try:
        # Validate required fields
        if not student_data.get("sus_vorn") or not student_data.get("sus_nachn"):
            raise HTTPException(status_code=400, detail="Vorname und Nachname sind erforderlich")

        # Check if student already exists for this user
        existing = await db.students.find_one(
            {
                "sus_vorn": student_data["sus_vorn"],
                "sus_nachn": student_data["sus_nachn"],
                "user_id": current_user["id"],
            }
        )
        if existing:
            raise HTTPException(
                status_code=400,
                detail=f"Schüler {student_data['sus_vorn']} {student_data['sus_nachn']} existiert bereits",
            )

        # Create Student object. Field names must match models.student.Student exactly -
        # Pydantic silently discards unknown kwargs (extra="ignore" by default), so a
        # mismatch here doesn't error, it just quietly drops the data on the floor.
        student = Student(
            user_id=current_user["id"],
            sus_vorn=student_data["sus_vorn"],
            sus_nachn=student_data["sus_nachn"],
            sus_kl=student_data.get("sus_kl", ""),
            sus_geb=student_data.get("sus_geb", ""),
            sus_str_hnr=student_data.get("sus_str", ""),
            sus_ort=student_data.get("sus_ort", ""),
        )

        student_dict = prepare_for_mongo(student.dict())
        result = await db.students.insert_one(student_dict)

        # Fetch and return created student
        created_student = await db.students.find_one({"_id": result.inserted_id})
        return Student(**parse_from_mongo(created_student))

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Anlegen: {str(e)}")


@api_router.get("/students", response_model=List[StudentWithAssignmentCount])
@limiter.limit("60/minute")
async def get_students(request: Request, current_user: dict = Depends(get_current_user)):
    # Apply user filter
    user_filter = await get_user_filter(current_user)
    students = await db.students.find(user_filter).to_list(length=None)

    # Add assignment_count to each student
    students_with_count = []
    for student in students:
        # Count active assignments for this student
        assignment_count = await db.assignments.count_documents({"student_id": student["id"], "is_active": True})

        student_dict = parse_from_mongo(student)
        student_dict["assignment_count"] = assignment_count
        students_with_count.append(StudentWithAssignmentCount(**student_dict))

    return students_with_count


@api_router.get("/students/available-for-assignment")
@limiter.limit("60/minute")
async def get_available_students(request: Request, current_user: dict = Depends(get_current_user)):
    """Get students that can still receive iPads (haven't reached MAX_IPADS_PER_STUDENT limit)"""
    user_filter = await get_user_filter(current_user)
    students = await db.students.find(user_filter, {"_id": 0}).to_list(length=None)

    # Filter students who haven't reached the limit
    available_students = []
    for student in students:
        # Count active assignments for this student
        assignment_count = await db.assignments.count_documents({"student_id": student["id"], "is_active": True})

        if assignment_count < MAX_IPADS_PER_STUDENT:
            available_students.append(
                {
                    "id": student["id"],
                    "name": f"{student['sus_vorn']} {student['sus_nachn']}",
                    "klasse": student.get("sus_kl", "N/A"),
                    "current_ipads": assignment_count,
                    "max_ipads": MAX_IPADS_PER_STUDENT,
                }
            )

    return available_students


@api_router.get("/students/{student_id}")
@limiter.limit("60/minute")
async def get_student_details(request: Request, student_id: str, current_user: dict = Depends(get_current_user)):
    """Get detailed information about a specific student"""
    # Validate resource ownership
    await validate_resource_ownership("student", student_id, current_user)

    student = await db.students.find_one({"id": student_id}, {"_id": 0})
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")

    # Get all active assignments for this student (1:n relationship)
    active_assignments = await db.assignments.find({"student_id": student_id, "is_active": True}, {"_id": 0}).to_list(
        length=None
    )

    # Get assignment history
    assignment_history = await db.assignments.find({"student_id": student_id}, {"_id": 0}).to_list(length=None)

    # Get contracts related to this student via student_id (new way) or student_name/assignment_id (legacy)
    contracts = await db.contracts.find(
        {
            "$or": [
                {"student_id": student_id},
                {
                    "student_name": {
                        "$regex": f"{re.escape(student['sus_vorn'])} {re.escape(student['sus_nachn'])}",
                        "$options": "i",
                    }
                },
                {"assignment_id": {"$in": [a["id"] for a in assignment_history]}},
            ]
        },
        {"_id": 0, "file_data": 0},  # Exclude _id and file_data
    ).to_list(length=None)

    # Prepare contract data
    contract_data = []
    for contract in contracts:
        contract_dict = {
            "id": contract.get("id"),
            "assignment_id": contract.get("assignment_id"),
            "ipad_id": contract.get("ipad_id"),
            "student_id": contract.get("student_id"),
            "itnr": contract.get("itnr"),
            "student_name": contract.get("student_name"),
            "filename": contract.get("filename"),
            "uploaded_at": contract.get("uploaded_at"),
            "is_active": contract.get("is_active", True),
        }
        contract_data.append(contract_dict)

    # Prepare current assignment (first active one)
    current_assignment_data = active_assignments[0] if active_assignments else None

    return {
        "student": student,
        "current_assignment": current_assignment_data,
        "assignment_history": assignment_history,
        "contracts": contract_data,
    }


class StudentUpdateRequest(BaseModel):
    sname: Optional[str] = None
    sus_nachn: Optional[str] = None
    sus_vorn: Optional[str] = None
    sus_kl: Optional[str] = None
    sus_str_hnr: Optional[str] = None
    sus_plz: Optional[str] = None
    sus_ort: Optional[str] = None
    sus_geb: Optional[str] = None
    erz1_nachn: Optional[str] = None
    erz1_vorn: Optional[str] = None
    erz1_str_hnr: Optional[str] = None
    erz1_plz: Optional[str] = None
    erz1_ort: Optional[str] = None
    erz2_nachn: Optional[str] = None
    erz2_vorn: Optional[str] = None
    erz2_str_hnr: Optional[str] = None
    erz2_plz: Optional[str] = None
    erz2_ort: Optional[str] = None


@api_router.put("/students/{student_id}")
async def update_student(
    student_id: str, request: StudentUpdateRequest, current_user: dict = Depends(get_current_user)
):
    """Update student information"""
    await validate_resource_ownership("student", student_id, current_user)
    student = await db.students.find_one({"id": student_id})
    if not student:
        raise HTTPException(status_code=404, detail="Schüler nicht gefunden")

    # Build update dict with only provided fields
    update_data = {}
    fields_to_check = [
        "sname",
        "sus_nachn",
        "sus_vorn",
        "sus_kl",
        "sus_str_hnr",
        "sus_plz",
        "sus_ort",
        "sus_geb",
        "erz1_nachn",
        "erz1_vorn",
        "erz1_str_hnr",
        "erz1_plz",
        "erz1_ort",
        "erz2_nachn",
        "erz2_vorn",
        "erz2_str_hnr",
        "erz2_plz",
        "erz2_ort",
    ]

    for field in fields_to_check:
        value = getattr(request, field, None)
        if value is not None:
            update_data[field] = value

    if not update_data:
        raise HTTPException(status_code=400, detail="Keine Änderungen angegeben")

    update_data["updated_at"] = datetime.now(UTC).isoformat()

    await db.students.update_one({"id": student_id}, {"$set": update_data})

    # If name changed, update related assignments and contracts
    if "sus_vorn" in update_data or "sus_nachn" in update_data:
        updated_student = await db.students.find_one({"id": student_id})
        new_name = f"{updated_student.get('sus_vorn', '')} {updated_student.get('sus_nachn', '')}"
        await db.assignments.update_many({"student_id": student_id}, {"$set": {"student_name": new_name}})
        await db.contracts.update_many({"student_id": student_id}, {"$set": {"student_name": new_name}})

    # Get updated student
    updated_student = await db.students.find_one({"id": student_id})
    return {
        "message": "Schüler erfolgreich aktualisiert",
        "student": {
            "id": updated_student["id"],
            "sname": updated_student.get("sname"),
            "sus_nachn": updated_student.get("sus_nachn"),
            "sus_vorn": updated_student.get("sus_vorn"),
            "sus_kl": updated_student.get("sus_kl"),
            "sus_str_hnr": updated_student.get("sus_str_hnr"),
            "sus_plz": updated_student.get("sus_plz"),
            "sus_ort": updated_student.get("sus_ort"),
            "sus_geb": updated_student.get("sus_geb"),
            "erz1_nachn": updated_student.get("erz1_nachn"),
            "erz1_vorn": updated_student.get("erz1_vorn"),
            "erz1_str_hnr": updated_student.get("erz1_str_hnr"),
            "erz1_plz": updated_student.get("erz1_plz"),
            "erz1_ort": updated_student.get("erz1_ort"),
            "erz2_nachn": updated_student.get("erz2_nachn"),
            "erz2_vorn": updated_student.get("erz2_vorn"),
            "erz2_str_hnr": updated_student.get("erz2_str_hnr"),
            "erz2_plz": updated_student.get("erz2_plz"),
            "erz2_ort": updated_student.get("erz2_ort"),
        },
    }


@api_router.put("/students/{student_id}/ipad-refused")
async def set_student_ipad_refused(
    student_id: str, request: dict, current_user: dict = Depends(get_current_user)
):
    """Mark/unmark that this person generally declines being given an iPad.

    Independent of any concrete assignment - used to distinguish "nicht zugeordnet"
    (nobody has offered/handled this yet) from "zugeordnet, aber verweigert" (offered,
    declined). Only meaningful while the person has no active assignment; assigning an
    iPad to them (manual or auto) automatically clears this flag again.
    """
    await validate_resource_ownership("student", student_id, current_user)

    refused = bool(request.get("refused", False))

    student = await db.students.find_one({"id": student_id})
    if not student:
        raise HTTPException(status_code=404, detail="Schüler nicht gefunden")

    if refused:
        active_assignment = await db.assignments.find_one({"student_id": student_id, "is_active": True})
        if active_assignment:
            raise HTTPException(
                status_code=400,
                detail="Diese Person hat bereits ein zugeordnetes iPad - Zuordnung zuerst auflösen, "
                "bevor eine Verweigerung vermerkt werden kann.",
            )

    await db.students.update_one(
        {"id": student_id},
        {"$set": {"ipad_refused": refused, "updated_at": datetime.now(UTC).isoformat()}},
    )

    return {
        "message": "iPad-Verweigerung vermerkt" if refused else "iPad-Verweigerung aufgehoben",
        "ipad_refused": refused,
    }


@api_router.delete("/students/{student_id}")
async def delete_student(student_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a student and handle related data"""
    # Validate resource ownership
    await validate_resource_ownership("student", student_id, current_user)

    student = await db.students.find_one({"id": student_id})
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")

    student_name = f"{student['sus_vorn']} {student['sus_nachn']}"

    # Step 1: Dissolve ALL active assignments (1:n - student can have multiple iPads)
    active_assignments = await db.assignments.find({"student_id": student_id, "is_active": True}).to_list(length=None)

    for active_assignment in active_assignments:
        # Update contract: entferne student_id Referenz
        if active_assignment.get("contract_id"):
            await db.contracts.update_one(
                {"id": active_assignment["contract_id"]},
                {"$set": {"student_id": None, "assignment_id": None, "updated_at": datetime.now(UTC).isoformat()}},
            )

        # Mark assignment as inactive
        await db.assignments.update_one(
            {"id": active_assignment["id"]},
            {
                "$set": {
                    "is_active": False,
                    "unassigned_at": datetime.now(UTC).isoformat(),
                    "updated_at": datetime.now(UTC).isoformat(),
                }
            },
        )

        # Free iPad (remove assignment)
        await db.ipads.update_one(
            {"id": active_assignment["ipad_id"]},
            {"$set": {"current_assignment_id": None, "updated_at": datetime.now(UTC).isoformat()}},
        )

    # Step 2: Update all contracts for this student - set student_id to null
    await db.contracts.update_many(
        {"student_id": student_id}, {"$set": {"student_id": None, "updated_at": datetime.now(UTC).isoformat()}}
    )

    # Step 3: Delete orphaned contracts (no ipad_id, no student_id, no assignment_id)
    contracts_deleted = await db.contracts.delete_many(
        {
            "$and": [
                {"$or": [{"student_id": None}, {"student_id": {"$exists": False}}]},
                {"$or": [{"ipad_id": None}, {"ipad_id": {"$exists": False}}]},
                {"$or": [{"assignment_id": None}, {"assignment_id": {"$exists": False}}]},
            ]
        }
    )

    # Step 4: Delete all assignments for this student
    assignments_result = await db.assignments.delete_many({"student_id": student_id})

    # Step 5: Delete the student
    await db.students.delete_one({"id": student_id})

    return {
        "message": f"Schüler {student_name} erfolgreich gelöscht",
        "deleted_assignments": assignments_result.deleted_count,
        "deleted_contracts": contracts_deleted.deleted_count,
    }


@api_router.post("/students/batch-delete")
async def batch_delete_students(filter_params: dict, current_user: dict = Depends(get_current_user)):
    """
    Delete multiple students at once

    filter_params can include:
    - "all": true (deletes all user's students)
    - "sus_vorn": string (filter by first name)
    - "sus_nachn": string (filter by last name)
    - "sus_kl": string (filter by class)

    Cascading deletes:
    - Dissolves active assignments
    - Frees assigned iPads
    - Deletes all assignment history
    - Deletes all contracts
    """
    try:
        # Apply user filter - CRITICAL for RBAC!
        user_filter = await get_user_filter(current_user)

        # Build student filter
        student_filter = user_filter.copy()

        # If not "all", apply specific filters
        if not filter_params.get("all", False):
            if filter_params.get("sus_vorn"):
                student_filter["sus_vorn"] = {"$regex": re.escape(filter_params["sus_vorn"]), "$options": "i"}
            if filter_params.get("sus_nachn"):
                student_filter["sus_nachn"] = {"$regex": re.escape(filter_params["sus_nachn"]), "$options": "i"}
            if filter_params.get("sus_kl"):
                student_filter["sus_kl"] = {"$regex": re.escape(filter_params["sus_kl"]), "$options": "i"}

        # Get all matching students
        students = await db.students.find(student_filter).to_list(length=None)

        if not students:
            return {"message": "No students found to delete", "deleted_count": 0, "freed_ipads": 0, "details": []}

        deleted_count = 0
        freed_ipads = 0
        details = []

        # Delete each student with cascading
        for student in students:
            try:
                student_id = student["id"]
                student_name = f"{student.get('sus_vorn', 'Unknown')} {student.get('sus_nachn', 'Unknown')}"

                # Step 1: Dissolve ALL active assignments (1:n - student can have multiple iPads)
                # Admin sees ALL assignments for that student; regular user only theirs.
                assignment_filter = {"student_id": student_id, "is_active": True}
                if not is_admin(current_user):
                    assignment_filter["user_id"] = current_user["id"]
                active_assignments = await db.assignments.find(assignment_filter).to_list(length=None)

                for active_assignment in active_assignments:
                    # Move contract to inactive if exists
                    if active_assignment.get("contract_id"):
                        await db.contracts.update_one(
                            {"id": active_assignment["contract_id"]},
                            {"$set": {"is_active": False, "updated_at": datetime.now(UTC).isoformat()}},
                        )

                    # Mark assignment as inactive
                    await db.assignments.update_one(
                        {"id": active_assignment["id"]},
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
                        {"id": active_assignment["ipad_id"]},
                        {"$set": {"current_assignment_id": None, "updated_at": datetime.now(UTC).isoformat()}},
                    )

                    freed_ipads += 1
                    details.append(f"Student {student_name} - iPad {active_assignment.get('itnr', 'Unknown')} freed")

                if not active_assignments:
                    details.append(f"Student {student_name} - no active assignment")

                # Step 2: Delete all assignments (history) for this student
                await db.assignments.delete_many({"student_id": student_id})

                # Step 3: Delete all contracts for this student
                await db.contracts.delete_many({"student_id": student_id})

                # Step 4: Delete the student
                await db.students.delete_one({"id": student_id})

                deleted_count += 1

            except Exception as e:
                details.append(f"Error deleting student {student.get('sus_vorn', 'Unknown')}: {str(e)}")

        return {
            "message": f"Successfully deleted {deleted_count} student(s) and freed {freed_ipads} iPad(s)",
            "deleted_count": deleted_count,
            "freed_ipads": freed_ipads,
            "total_found": len(students),
            "details": details,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during batch delete: {str(e)}")
