import os
import uuid
from datetime import datetime, timezone

import pytest
import requests
from bson import ObjectId
from bson.binary import Binary
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "http://127.0.0.1:8001").rstrip("/")
API = f"{BASE_URL}/api"
MONGO_URL = os.environ.get("MONGO_URL", "mongodb://mongodb:27017")


def _mongo_db():
    client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=2000)
    try:
        client.admin.command("ping")
    except ServerSelectionTimeoutError as exc:
        pytest.skip(f"MongoDB not reachable for backup roundtrip test: {exc}")
    return client["iPadDatabase"]


def _admin_headers():
    requests.post(f"{API}/auth/setup", timeout=30)
    response = requests.post(
        f"{API}/auth/login",
        json={"username": "admin", "password": "admin123"},
        timeout=30,
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_json_backup_roundtrips_binary_objectid_and_datetime():
    db = _mongo_db()
    headers = _admin_headers()

    contract_id = f"TEST_BACKUP_{uuid.uuid4().hex}"
    pdf_bytes = b"%PDF-1.4\nbackup binary payload\n%%EOF"
    uploaded_at = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
    nested_id = ObjectId()

    db.contracts.delete_many({"id": contract_id})
    db.contracts.insert_one(
        {
            "id": contract_id,
            "user_id": "backup-test-user",
            "filename": "backup-test.pdf",
            "file_data": pdf_bytes,
            "form_fields": {
                "nested_object_id": nested_id,
                "nested_binary": Binary(b"nested-bytes"),
                "nested_datetime": uploaded_at,
            },
            "uploaded_at": uploaded_at,
            "is_active": False,
        }
    )

    export_response = requests.get(f"{API}/backup/export", headers=headers, timeout=60)
    assert export_response.status_code == 200, export_response.text
    backup_data = export_response.json()

    exported_contract = next(c for c in backup_data["contracts"] if c["id"] == contract_id)
    assert exported_contract["file_data"]["__rbbk_backup_type"] == "binary"
    assert exported_contract["_id"]["__rbbk_backup_type"] == "object_id"
    assert exported_contract["uploaded_at"]["__rbbk_backup_type"] == "datetime"
    assert exported_contract["form_fields"]["nested_binary"]["__rbbk_backup_type"] == "binary"
    assert exported_contract["form_fields"]["nested_object_id"]["__rbbk_backup_type"] == "object_id"

    db.contracts.delete_one({"id": contract_id})
    assert db.contracts.count_documents({"id": contract_id}) == 0

    import_response = requests.post(
        f"{API}/backup/import",
        headers=headers,
        files={"file": ("backup.json", export_response.content, "application/json")},
        timeout=60,
    )
    assert import_response.status_code == 200, import_response.text

    restored_contract = db.contracts.find_one({"id": contract_id})
    assert restored_contract is not None
    assert bytes(restored_contract["file_data"]) == pdf_bytes
    assert isinstance(restored_contract["_id"], ObjectId)
    assert isinstance(restored_contract["uploaded_at"], datetime)
    assert bytes(restored_contract["form_fields"]["nested_binary"]) == b"nested-bytes"
    assert restored_contract["form_fields"]["nested_object_id"] == nested_id
    assert isinstance(restored_contract["form_fields"]["nested_datetime"], datetime)

    db.contracts.delete_one({"id": contract_id})
