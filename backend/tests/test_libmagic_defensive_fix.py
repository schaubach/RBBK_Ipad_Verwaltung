"""
Iteration 9 – Sanity check that Backend survived the libmagic outage fix.

Focus:
  * /api/auth/me returns 401 (server is UP, not 502/504)
  * /api/auth/login admin/admin123 => 200 + HttpOnly cookie
  * validators.py has defensive try/except ImportError/OSError for magic
  * File-upload endpoints still work when libmagic IS installed
  * Excel import + export endpoints still respond correctly
"""

import io
import os
import time
import uuid

import openpyxl
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://vertraege-lab.preview.emergentagent.com").rstrip("/")


# -----------------------------------------------------------------------------
# fixtures
# -----------------------------------------------------------------------------
@pytest.fixture(scope="module")
def admin_token():
    # Serialize with a short sleep to avoid the 5/min login rate limit
    time.sleep(3)
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"username": "admin", "password": "admin123"},
        timeout=15,
    )
    assert r.status_code == 200, f"admin login failed: {r.status_code} {r.text[:200]}"
    body = r.json()
    assert "access_token" in body
    return body["access_token"], r.cookies


@pytest.fixture(scope="module")
def auth_headers(admin_token):
    token, _ = admin_token
    return {"Authorization": f"Bearer {token}"}


# -----------------------------------------------------------------------------
# 1) Server health - PRIMARY check
# -----------------------------------------------------------------------------
class TestServerAlive:
    """The whole point of this iteration - backend must be UP (401, not 502/504)."""

    def test_auth_me_returns_401_unauthenticated(self):
        r = requests.get(f"{BASE_URL}/api/auth/me", timeout=15)
        # 401 = server alive but unauthenticated. 502/504 = pod dead.
        assert r.status_code == 401, f"Expected 401, got {r.status_code}: {r.text[:200]}"

    def test_login_returns_cookie_and_token(self, admin_token):
        token, cookies = admin_token
        assert token
        # HttpOnly cookie should be present
        assert "access_token" in cookies, f"cookies: {cookies}"

    def test_auth_me_with_token_returns_user(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/auth/me", headers=auth_headers, timeout=15)
        assert r.status_code == 200
        body = r.json()
        assert body.get("username") == "admin"


# -----------------------------------------------------------------------------
# 2) Defensive-import code review
# -----------------------------------------------------------------------------
class TestDefensiveMagicImport:
    """Verify /app/backend/core/validators.py has the try/except ImportError/OSError guard."""

    def test_validators_has_defensive_magic_import(self):
        path = "/app/backend/core/validators.py"
        with open(path) as f:
            content = f.read()
        # These three signals must all be present
        assert "try:" in content
        assert "import magic" in content
        assert "_HAS_MAGIC = True" in content
        assert (
            "except (ImportError, OSError)" in content
        ), "Defensive except-clause must catch both ImportError AND OSError"
        assert "_HAS_MAGIC = False" in content
        # And validate_uploaded_file must early-return when magic is unavailable
        assert "if not _HAS_MAGIC" in content


# -----------------------------------------------------------------------------
# 3) File-upload endpoints - core of libmagic fix
# -----------------------------------------------------------------------------
class TestFileUploadEndpoints:
    """PDF upload path exercises validate_uploaded_file() incl. libmagic branch."""

    def _make_min_pdf(self) -> bytes:
        # Absolute-minimal but valid enough PDF that starts with %PDF- header
        return (
            b"%PDF-1.4\n"
            b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            b"2 0 obj << /Type /Pages /Count 0 /Kids [] >> endobj\n"
            b"xref\n0 3\n"
            b"0000000000 65535 f \n"
            b"0000000009 00000 n \n"
            b"0000000058 00000 n \n"
            b"trailer << /Size 3 /Root 1 0 R >>\n"
            b"startxref\n112\n%%EOF\n"
        )

    def test_upload_contract_rejects_missing_assignment(self, auth_headers):
        """We don't need a valid assignment id — we only want to prove:
        the endpoint reaches validate_uploaded_file successfully (i.e. libmagic
        path didn't crash the process). A 404 for a bogus assignment id proves that."""
        pdf_bytes = self._make_min_pdf()
        files = {"file": ("test.pdf", io.BytesIO(pdf_bytes), "application/pdf")}
        r = requests.post(
            f"{BASE_URL}/api/assignments/00000000-0000-0000-0000-000000000000/upload-contract",
            headers=auth_headers,
            files=files,
            timeout=30,
        )
        # 404 (assignment not found) OR 400 (validation) are both PROOF that server processed the request.
        # 502/500 would mean the import broke.
        assert r.status_code in (400, 404), f"Unexpected {r.status_code}: {r.text[:300]}"

    def test_upload_contract_rejects_non_pdf_extension(self, auth_headers):
        # extension guard fires before libmagic — proves validator is reachable
        files = {"file": ("not_a_pdf.txt", io.BytesIO(b"hello world"), "text/plain")}
        r = requests.post(
            f"{BASE_URL}/api/assignments/00000000-0000-0000-0000-000000000000/upload-contract",
            headers=auth_headers,
            files=files,
            timeout=30,
        )
        # We expect 400 File type not allowed. Server must NOT 5xx.
        assert r.status_code == 400, f"Unexpected {r.status_code}: {r.text[:300]}"
        # Accept any of the possible rejection messages coming from the endpoint
        # ("Only .pdf files are allowed" | "File type not allowed")
        low = r.text.lower()
        assert "allowed" in low or "pdf" in low


# -----------------------------------------------------------------------------
# 4) Excel Import
# -----------------------------------------------------------------------------
class TestExcelImportEndpoint:
    def test_import_inventory_accepts_xlsx(self, auth_headers):
        wb = openpyxl.Workbook()
        ws = wb.active
        # Header + 1 dummy row (must at least be a valid xlsx, real ingest may reject content)
        ws.append(["Serial Number", "Model", "Anschaffungsdatum", "Preis"])
        ws.append([f"TEST_SN_{uuid.uuid4().hex[:6]}", "iPad Test", "2024-01-01", "500"])
        buf = io.BytesIO()
        wb.save(buf)
        buf.seek(0)

        files = {
            "file": (
                "test.xlsx",
                buf,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        }
        r = requests.post(
            f"{BASE_URL}/api/imports/inventory",
            headers=auth_headers,
            files=files,
            timeout=60,
        )
        # 200 (imported) OR 400 (validation on business rules) prove endpoint runs.
        # 500/502 would mean validator crashed.
        assert r.status_code in (200, 400), f"Unexpected {r.status_code}: {r.text[:400]}"


# -----------------------------------------------------------------------------
# 5) Excel Export – 3 endpoints
# -----------------------------------------------------------------------------
class TestExcelExportEndpoints:
    XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    def test_export_inventory_returns_xlsx(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/exports/inventory", headers=auth_headers, timeout=60)
        assert r.status_code == 200, f"Unexpected {r.status_code}: {r.text[:200]}"
        assert self.XLSX_MIME in r.headers.get("content-type", "")
        assert len(r.content) > 100  # non-empty xlsx

    def test_export_assignments_returns_xlsx(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/assignments/export", headers=auth_headers, timeout=60)
        assert r.status_code == 200, f"Unexpected {r.status_code}: {r.text[:200]}"
        assert self.XLSX_MIME in r.headers.get("content-type", "")
        assert len(r.content) > 100

    def test_export_selected_assignments_returns_xlsx(self, auth_headers):
        # Pull one assignment id (if present) so the endpoint has something to export
        list_r = requests.get(f"{BASE_URL}/api/assignments", headers=auth_headers, timeout=30)
        assert list_r.status_code == 200
        items = list_r.json() if isinstance(list_r.json(), list) else list_r.json().get("items", [])
        if not items:
            pytest.skip("No assignments in DB to export-selected")
        aid = items[0].get("id") or items[0].get("_id")
        r = requests.post(
            f"{BASE_URL}/api/assignments/export-selected",
            headers={**auth_headers, "Content-Type": "application/json"},
            json={"assignment_ids": [aid]},
            timeout=60,
        )
        assert r.status_code == 200, f"Unexpected {r.status_code}: {r.text[:200]}"
        assert self.XLSX_MIME in r.headers.get("content-type", "")
        assert len(r.content) > 100
