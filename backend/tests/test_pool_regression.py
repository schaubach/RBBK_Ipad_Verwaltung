"""
Regression test suite for iPad-Pool feature, modell field, RBAC, contracts encryption.

Covers:
- AUTH (admin login, normal user login, logout)
- RBAC admin vs user permissions
- iPad Pool: create, list, claim, bulk-claim, release-to-pool, race-condition
- One-step manual assign claim+assign
- Pool import via Excel
- modell field CRUD + import/export
- iPad history endpoint with owner_username + pool_history
- Contract generation: zipfile readable, inner ZIP password-protected (ZipCrypto)
- User deletion preserving pool iPads
"""

import io
import os
import time
import uuid
import zipfile

import pandas as pd
import pyminizip  # noqa: F401  (ensures backend deps available)
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://vertraege-lab.preview.emergentagent.com").rstrip("/")
API = f"{BASE_URL}/api"

ADMIN_USER = "admin"
ADMIN_PASS = "admin123"


# ---------- Fixtures ----------


def _login(username, password):
    r = requests.post(f"{API}/auth/login", json={"username": username, "password": password}, timeout=30)
    return r


@pytest.fixture(scope="session")
def admin_token():
    # retry on 429
    for _ in range(5):
        r = _login(ADMIN_USER, ADMIN_PASS)
        if r.status_code == 200:
            return r.json()["access_token"]
        if r.status_code == 429:
            time.sleep(3)
            continue
        pytest.fail(f"Admin login failed: {r.status_code} {r.text}")
    pytest.fail("Admin login rate limited")


@pytest.fixture(scope="session")
def admin_client(admin_token):
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"})
    return s


@pytest.fixture(scope="session")
def test_user(admin_client):
    """Create a temporary normal user; delete in teardown."""
    username = f"TEST_reg_{uuid.uuid4().hex[:6]}"
    password = "Test1234!"
    payload = {"username": username, "password": password, "role": "user"}
    r = admin_client.post(f"{API}/admin/users", json=payload)
    assert r.status_code in (200, 201), f"User create failed: {r.status_code} {r.text}"
    user_data = r.json()
    user_id = user_data.get("id")

    # Login (may require force password change) -> change if needed
    login_r = _login(username, password)
    if login_r.status_code == 200 and login_r.json().get("force_password_change"):
        token = login_r.json()["access_token"]
        cr = requests.put(
            f"{API}/auth/change-password-forced",
            json={"current_password": password, "new_password": "Test1234!new"},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        if cr.status_code == 200:
            password = "Test1234!new"
            login_r = _login(username, password)

    assert login_r.status_code == 200, f"User login failed: {login_r.status_code} {login_r.text}"
    token = login_r.json()["access_token"]

    yield {"id": user_id, "username": username, "password": password, "token": token}

    # Teardown - permanently delete user
    try:
        admin_client.delete(f"{API}/admin/users/{user_id}/complete")
    except Exception:
        pass


@pytest.fixture(scope="session")
def user_client(test_user):
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {test_user['token']}", "Content-Type": "application/json"})
    return s


# Tracked test resources for cleanup
_created_ipads = []
_created_students = []


@pytest.fixture(scope="session", autouse=True)
def cleanup_after(admin_client):
    yield
    # cleanup any leftover test ipads / students
    for ipad_id in _created_ipads:
        try:
            admin_client.delete(f"{API}/ipads/{ipad_id}")
        except Exception:
            pass
    for student_id in _created_students:
        try:
            admin_client.delete(f"{API}/students/{student_id}")
        except Exception:
            pass


# ---------- AUTH ----------


class TestAuth:
    def test_admin_login(self):
        r = _login(ADMIN_USER, ADMIN_PASS)
        assert r.status_code == 200
        body = r.json()
        assert body["role"] == "admin"
        assert "access_token" in body

    def test_user_login_role(self, test_user):
        r = _login(test_user["username"], test_user["password"])
        assert r.status_code == 200
        assert r.json()["role"] == "user"

    def test_logout_clears_cookie(self):
        s = requests.Session()
        r = s.post(f"{API}/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
        assert r.status_code == 200
        # /api/auth/me requires Authorization header OR cookie - test cookie path
        me = s.get(f"{API}/auth/me")
        # Accept 200 (cookie OK) or document issue
        cookie_works = me.status_code == 200
        out = s.post(f"{API}/auth/logout")
        assert out.status_code == 200
        me2 = s.get(f"{API}/auth/me")
        # After logout, cookie should be cleared → unauthorized
        assert me2.status_code in (401, 403), f"After logout expected 401/403 got {me2.status_code}"
        if not cookie_works:
            pytest.skip(f"Cookie-based /auth/me returned {me.status_code}, not 200 - investigate cookie auth")


# ---------- RBAC ----------


class TestRBAC:
    def test_user_cannot_update_global_settings(self, user_client):
        r = user_client.put(f"{API}/settings/global", json={"ipad_typ": "x"})
        assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"

    def test_user_can_delete_nonexistent_assignment(self, user_client):
        r = user_client.delete(f"{API}/assignments/nonexistent-id-{uuid.uuid4()}")
        assert r.status_code in (200, 404), f"Should be 200/404, got {r.status_code}"

    def test_user_can_auto_assign(self, user_client):
        # auto-assign endpoint with no data → should be 200/400/404 (not 403)
        r = user_client.post(f"{API}/assignments/auto-assign", json={})
        assert r.status_code != 403, f"User should be allowed (not 403): got {r.status_code} {r.text}"

    def test_user_can_delete_nonexistent_student(self, user_client):
        r = user_client.delete(f"{API}/students/nonexistent-id-{uuid.uuid4()}")
        assert r.status_code in (200, 404)

    def test_user_can_batch_delete_students(self, user_client):
        r = user_client.post(f"{API}/students/batch-delete", json={"student_ids": []})
        assert r.status_code != 403

    def test_user_can_delete_nonexistent_ipad(self, user_client):
        r = user_client.delete(f"{API}/ipads/nonexistent-id-{uuid.uuid4()}")
        assert r.status_code in (200, 404)

    def test_user_can_batch_delete_contracts(self, user_client):
        r = user_client.post(f"{API}/contracts/batch-delete", json={"contract_ids": []})
        assert r.status_code != 403


# ---------- Pool Feature ----------


class TestPool:
    def test_admin_create_pool_ipad(self, admin_client):
        itnr = f"TEST_POOL_{uuid.uuid4().hex[:8]}"
        r = admin_client.post(
            f"{API}/ipads",
            json={"itnr": itnr, "snr": f"SN-{uuid.uuid4().hex[:6]}", "is_in_pool": True, "modell": "iPad 9. Gen"},
        )
        assert r.status_code == 200, r.text
        ipad = r.json()
        _created_ipads.append(ipad["id"])
        assert ipad["is_in_pool"] is True
        assert ipad["modell"] == "iPad 9. Gen"

    def test_pool_ipad_visible_to_both(self, admin_client, user_client):
        itnr = f"TEST_POOL_VIS_{uuid.uuid4().hex[:6]}"
        r = admin_client.post(
            f"{API}/ipads", json={"itnr": itnr, "snr": f"SN-{uuid.uuid4().hex[:6]}", "is_in_pool": True}
        )
        assert r.status_code == 200
        ipad_id = r.json()["id"]
        _created_ipads.append(ipad_id)

        admin_list = admin_client.get(f"{API}/ipads").json()
        user_list = user_client.get(f"{API}/ipads").json()
        admin_ids = {i["id"] for i in admin_list}
        user_ids = {i["id"] for i in user_list}
        assert ipad_id in admin_ids
        assert ipad_id in user_ids

    def test_user_claim_pool_ipad(self, admin_client, user_client, test_user):
        itnr = f"TEST_POOL_CLAIM_{uuid.uuid4().hex[:6]}"
        r = admin_client.post(
            f"{API}/ipads", json={"itnr": itnr, "snr": f"SN-{uuid.uuid4().hex[:6]}", "is_in_pool": True}
        )
        assert r.status_code == 200
        ipad_id = r.json()["id"]
        _created_ipads.append(ipad_id)

        cl = user_client.post(f"{API}/ipads/{ipad_id}/claim")
        assert cl.status_code == 200, cl.text

        hist = admin_client.get(f"{API}/ipads/{ipad_id}/history").json()
        ipad_data = hist["ipad"]
        assert ipad_data["is_in_pool"] is False
        assert ipad_data["user_id"] == test_user["id"]
        # owner_username should match
        assert hist["owner_username"] == test_user["username"]
        actions = [h["action"] for h in hist["pool_history"]]
        assert "claimed" in actions

    def test_race_condition_claim(self, admin_client, user_client):
        from concurrent.futures import ThreadPoolExecutor

        itnr = f"TEST_RACE_{uuid.uuid4().hex[:6]}"
        r = admin_client.post(
            f"{API}/ipads", json={"itnr": itnr, "snr": f"SN-{uuid.uuid4().hex[:6]}", "is_in_pool": True}
        )
        ipad_id = r.json()["id"]
        _created_ipads.append(ipad_id)

        def claim(client):
            return client.post(f"{API}/ipads/{ipad_id}/claim")

        with ThreadPoolExecutor(max_workers=2) as ex:
            f1 = ex.submit(claim, admin_client)
            f2 = ex.submit(claim, user_client)
            r1, r2 = f1.result(), f2.result()
        codes = sorted([r1.status_code, r2.status_code])
        # One must succeed (200), the other must fail (409)
        assert codes == [200, 409], f"Race result codes: {codes}, r1={r1.text}, r2={r2.text}"

    def test_release_to_pool_dissolves_assignment(self, admin_client, user_client, test_user):
        # Create iPad owned by user (via pool claim)
        itnr = f"TEST_REL_{uuid.uuid4().hex[:6]}"
        r = admin_client.post(
            f"{API}/ipads", json={"itnr": itnr, "snr": f"SN-{uuid.uuid4().hex[:6]}", "is_in_pool": True}
        )
        ipad_id = r.json()["id"]
        _created_ipads.append(ipad_id)
        user_client.post(f"{API}/ipads/{ipad_id}/claim")

        # Create student for user
        student_payload = {"sus_vorn": "TestRel", "sus_nachn": f"Reg{uuid.uuid4().hex[:4]}", "sus_geb": "01.01.2010"}
        sr = user_client.post(f"{API}/students", json=student_payload)
        assert sr.status_code == 200, sr.text
        student_id = sr.json()["id"]
        _created_students.append(student_id)

        # Manual assign
        ar = user_client.post(f"{API}/assignments/manual", json={"ipad_id": ipad_id, "student_id": student_id})
        assert ar.status_code == 200, ar.text

        # Release to pool
        rel = user_client.post(f"{API}/ipads/{ipad_id}/release-to-pool")
        assert rel.status_code == 200, rel.text
        body = rel.json()
        assert body["dissolved_assignment"] is True

    def test_bulk_claim(self, admin_client, user_client):
        ids = []
        for _ in range(3):
            itnr = f"TEST_BULK_{uuid.uuid4().hex[:6]}"
            r = admin_client.post(
                f"{API}/ipads", json={"itnr": itnr, "snr": f"SN-{uuid.uuid4().hex[:6]}", "is_in_pool": True}
            )
            ipad_id = r.json()["id"]
            ids.append(ipad_id)
            _created_ipads.append(ipad_id)

        # Also include a fake one
        bogus = "nonexistent-id"
        b = user_client.post(f"{API}/ipads/bulk-claim", json={"ipad_ids": ids + [bogus]})
        assert b.status_code == 200, b.text
        body = b.json()
        assert body["success_count"] == 3
        assert body["failed_count"] == 1

    def test_one_step_claim_and_assign(self, admin_client, user_client):
        itnr = f"TEST_ONESTEP_{uuid.uuid4().hex[:6]}"
        r = admin_client.post(
            f"{API}/ipads", json={"itnr": itnr, "snr": f"SN-{uuid.uuid4().hex[:6]}", "is_in_pool": True}
        )
        ipad_id = r.json()["id"]
        _created_ipads.append(ipad_id)

        sr = user_client.post(
            f"{API}/students",
            json={"sus_vorn": "One", "sus_nachn": f"Step{uuid.uuid4().hex[:4]}", "sus_geb": "02.02.2010"},
        )
        assert sr.status_code == 200
        student_id = sr.json()["id"]
        _created_students.append(student_id)

        ar = user_client.post(f"{API}/assignments/manual", json={"ipad_id": ipad_id, "student_id": student_id})
        assert ar.status_code == 200, ar.text
        body = ar.json()
        assert body.get("claimed_from_pool") is True

    def test_pool_import_via_excel(self, admin_client):
        df = pd.DataFrame(
            [
                {"ITNr": f"TEST_PIMP_{uuid.uuid4().hex[:6]}", "SNr": f"S{uuid.uuid4().hex[:6]}", "Modell": "iPad Air"},
                {
                    "ITNr": f"TEST_PIMP_{uuid.uuid4().hex[:6]}",
                    "SNr": f"S{uuid.uuid4().hex[:6]}",
                    "Modell": "iPad Pro 11",
                },
            ]
        )
        buf = io.BytesIO()
        df.to_excel(buf, index=False, engine="openpyxl")
        buf.seek(0)

        files = {
            "file": ("import.xlsx", buf.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        }
        headers = {"Authorization": admin_client.headers["Authorization"]}
        r = requests.post(f"{API}/imports/inventory", files=files, data={"import_to_pool": "true"}, headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body.get("ipads_created", 0) >= 2
        # No assignments or students should have been created
        assert body.get("assignments_created", 0) == 0
        assert body.get("students_created", 0) == 0

        # Track for cleanup
        ipads = admin_client.get(f"{API}/ipads").json()
        for itnr in df["ITNr"].tolist():
            for ipad in ipads:
                if ipad["itnr"] == itnr:
                    _created_ipads.append(ipad["id"])

    def test_pool_import_global_unique(self, admin_client):
        itnr = f"TEST_UNQ_{uuid.uuid4().hex[:6]}"
        df = pd.DataFrame([{"ITNr": itnr, "SNr": "S1"}])
        buf = io.BytesIO()
        df.to_excel(buf, index=False, engine="openpyxl")
        buf.seek(0)
        files = {
            "file": ("imp.xlsx", buf.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        }
        headers = {"Authorization": admin_client.headers["Authorization"]}
        r1 = requests.post(f"{API}/imports/inventory", files=files, data={"import_to_pool": "true"}, headers=headers)
        assert r1.status_code == 200
        # second import same itnr → skipped
        buf2 = io.BytesIO()
        df.to_excel(buf2, index=False, engine="openpyxl")
        buf2.seek(0)
        files2 = {
            "file": ("imp.xlsx", buf2.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        }
        r2 = requests.post(f"{API}/imports/inventory", files=files2, data={"import_to_pool": "true"}, headers=headers)
        assert r2.status_code == 200, r2.text
        body = r2.json()
        assert body.get("ipads_skipped", 0) >= 1

        ipads = admin_client.get(f"{API}/ipads").json()
        for ipad in ipads:
            if ipad["itnr"] == itnr:
                _created_ipads.append(ipad["id"])
                break

    def test_user_delete_preserves_pool_ipads(self, admin_client):
        # Create temp user
        uname = f"TEST_orphan_{uuid.uuid4().hex[:6]}"
        cr = admin_client.post(f"{API}/admin/users", json={"username": uname, "password": "Pwd123!!", "role": "user"})
        assert cr.status_code in (200, 201)
        uid = cr.json()["id"]
        # login user
        lr = _login(uname, "Pwd123!!")
        if lr.json().get("force_password_change"):
            tk = lr.json()["access_token"]
            requests.put(
                f"{API}/auth/change-password-forced",
                json={"current_password": "Pwd123!!", "new_password": "Pwd123!!new"},
                headers={"Authorization": f"Bearer {tk}"},
            )
            lr = _login(uname, "Pwd123!!new")
        user_token = lr.json()["access_token"]
        user_sess = requests.Session()
        user_sess.headers.update({"Authorization": f"Bearer {user_token}", "Content-Type": "application/json"})

        # Create a pool iPad as that user
        itnr = f"TEST_ORPH_{uuid.uuid4().hex[:6]}"
        ipad_r = user_sess.post(f"{API}/ipads", json={"itnr": itnr, "snr": "S-orph", "is_in_pool": True})
        assert ipad_r.status_code == 200, ipad_r.text
        ipad_id = ipad_r.json()["id"]
        _created_ipads.append(ipad_id)

        # Delete user completely
        dr = admin_client.delete(f"{API}/admin/users/{uid}/complete")
        assert dr.status_code == 200, dr.text
        body = dr.json()
        assert body["deleted_resources"]["pool_ipads_orphaned"] >= 1

        # Pool iPad must still exist with user_id=null
        hist = admin_client.get(f"{API}/ipads/{ipad_id}/history")
        assert hist.status_code == 200
        ipad_data = hist.json()["ipad"]
        assert ipad_data.get("user_id") in (None, "")
        assert ipad_data.get("is_in_pool") is True


# ---------- modell field ----------


class TestModellField:
    def test_create_with_modell(self, admin_client):
        itnr = f"TEST_M_{uuid.uuid4().hex[:6]}"
        r = admin_client.post(f"{API}/ipads", json={"itnr": itnr, "snr": "S", "modell": "iPad 9. Gen"})
        assert r.status_code == 200
        _created_ipads.append(r.json()["id"])
        assert r.json()["modell"] == "iPad 9. Gen"

    def test_update_modell(self, admin_client):
        itnr = f"TEST_MU_{uuid.uuid4().hex[:6]}"
        r = admin_client.post(f"{API}/ipads", json={"itnr": itnr, "snr": "S"})
        assert r.status_code == 200
        ipad_id = r.json()["id"]
        _created_ipads.append(ipad_id)
        u = admin_client.put(f"{API}/ipads/{ipad_id}", json={"modell": "iPad Pro 11"})
        assert u.status_code == 200, u.text
        # NOTE: PUT response wrapper does NOT include modell field. Verify via GET history.
        hist = admin_client.get(f"{API}/ipads/{ipad_id}/history").json()
        assert hist["ipad"]["modell"] == "iPad Pro 11"

    def test_empty_modell_becomes_null(self, admin_client):
        itnr = f"TEST_ME_{uuid.uuid4().hex[:6]}"
        r = admin_client.post(f"{API}/ipads", json={"itnr": itnr, "snr": "S", "modell": "iPad Pro 11"})
        ipad_id = r.json()["id"]
        _created_ipads.append(ipad_id)
        u = admin_client.put(f"{API}/ipads/{ipad_id}", json={"modell": ""})
        assert u.status_code == 200, u.text
        # Verify via history
        hist = admin_client.get(f"{API}/ipads/{ipad_id}/history").json()
        assert hist["ipad"]["modell"] is None, f"Expected None, got {hist['ipad']['modell']!r}"

    def test_export_has_modell_column(self, admin_client):
        # ensure at least one ipad with modell
        itnr = f"TEST_EXP_{uuid.uuid4().hex[:6]}"
        r = admin_client.post(f"{API}/ipads", json={"itnr": itnr, "snr": "S", "modell": "iPad Air 5"})
        _created_ipads.append(r.json()["id"])

        exp = requests.get(f"{API}/exports/inventory", headers={"Authorization": admin_client.headers["Authorization"]})
        assert exp.status_code == 200, exp.text
        df = pd.read_excel(io.BytesIO(exp.content), engine="openpyxl")
        assert "Modell" in df.columns, f"Modell column missing, got: {list(df.columns)}"


# ---------- Contract Generation ----------


class TestContracts:
    def test_generate_contracts_zip(self, admin_client):
        # Need at least one assignment with all required fields. Use admin context.
        # Create student + ipad + assign
        student_payload = {
            "sus_vorn": "TESTC",
            "sus_nachn": f"Reg{uuid.uuid4().hex[:4]}",
            "sus_kl": "10A",
            "sus_geb": "15.05.2008",
            "sus_str_hnr": "Teststr 1",
            "sus_plz": "12345",
            "sus_ort": "Berlin",
            "erz1_vorn": "Mom",
            "erz1_nachn": "Test",
            "erz1_str_hnr": "Teststr 1",
            "erz1_plz": "12345",
            "erz1_ort": "Berlin",
        }
        sr = admin_client.post(f"{API}/students", json=student_payload)
        assert sr.status_code == 200, sr.text
        student_id = sr.json()["id"]
        _created_students.append(student_id)

        itnr = f"TEST_CT_{uuid.uuid4().hex[:6]}"
        ipr = admin_client.post(
            f"{API}/ipads",
            json={
                "itnr": itnr,
                "snr": f"SN-{uuid.uuid4().hex[:6]}",
                "modell": "iPad 9. Gen",
                "ansch_jahr": "2024",
                "ausleihe_datum": "01.09.2024",
                "typ": "Apple iPad",
            },
        )
        assert ipr.status_code == 200, ipr.text
        ipad_id = ipr.json()["id"]
        _created_ipads.append(ipad_id)

        ar = admin_client.post(f"{API}/assignments/manual", json={"ipad_id": ipad_id, "student_id": student_id})
        assert ar.status_code == 200, ar.text
        assignment_id = ar.json()["assignment_id"]

        # Pass assignment_ids to limit generation to our test data (with sus_geb='15.05.2008')
        gen = admin_client.post(f"{API}/assignments/generate-contracts", json={"assignment_ids": [assignment_id]})
        assert gen.status_code == 200, gen.text[:500]
        assert gen.headers.get("content-type", "").startswith("application/"), gen.headers
        outer = zipfile.ZipFile(io.BytesIO(gen.content))
        names = outer.namelist()
        assert names, "Outer ZIP is empty"

        # Find an inner ZIP for our student
        inner_zip_data = None
        for name in names:
            if name.lower().endswith(".zip"):
                inner_zip_data = outer.read(name)
                break
        assert inner_zip_data, f"No inner ZIP found. Names: {names}"
        inner = zipfile.ZipFile(io.BytesIO(inner_zip_data))
        inner_names = inner.namelist()
        assert inner_names, "Inner zip is empty"
        # Verify inner zip entries are flagged encrypted
        infos = inner.infolist()
        assert any(
            bool(i.flag_bits & 0x1) for i in infos
        ), f"Inner ZIP not encrypted! flag_bits: {[hex(i.flag_bits) for i in infos]}"

        # Wrong password should fail
        try:
            inner.read(inner_names[0], pwd=b"wrongpwd")
            wrong_pw_failed = False
        except (RuntimeError, zipfile.BadZipFile):
            wrong_pw_failed = True
        assert wrong_pw_failed, "Wrong password should fail"

        # Correct password = Geburtsdatum 15.05.2008
        last_err = None
        for pwd in (b"15.05.2008", b"15052008", b"20080515"):
            try:
                data = inner.read(inner_names[0], pwd=pwd)
                if data and len(data) > 100:
                    return  # success
            except Exception as e:
                last_err = e
                continue
        pytest.fail(f"Could not decrypt with expected passwords. Last error: {last_err}")

    def test_available_for_contracts_missing_fields(self, admin_client):
        # Create an iPad without modell + student without sus_geb → missing_fields should report
        student_payload = {"sus_vorn": "MissTest", "sus_nachn": f"Reg{uuid.uuid4().hex[:4]}"}  # no sus_geb
        sr = admin_client.post(f"{API}/students", json=student_payload)
        student_id = sr.json()["id"]
        _created_students.append(student_id)

        itnr = f"TEST_MFX_{uuid.uuid4().hex[:6]}"
        ipr = admin_client.post(
            f"{API}/ipads", json={"itnr": itnr, "snr": ""}
        )  # snr empty triggers missing? snr required
        # snr is required → cannot create. Use a valid SNr + missing modell instead
        if ipr.status_code != 200:
            ipr = admin_client.post(f"{API}/ipads", json={"itnr": itnr, "snr": "x"})
        assert ipr.status_code == 200, ipr.text
        ipad_id = ipr.json()["id"]
        _created_ipads.append(ipad_id)

        ar = admin_client.post(f"{API}/assignments/manual", json={"ipad_id": ipad_id, "student_id": student_id})
        assert ar.status_code == 200, ar.text

        avail = admin_client.get(f"{API}/assignments/available-for-contracts")
        assert avail.status_code == 200, avail.text
        items = avail.json()
        target = next((a for a in items if a.get("itnr") == itnr), None)
        assert target is not None, f"Assignment for {itnr} not in available list"
        assert "missing_fields" in target
        assert isinstance(target["missing_fields"], list)
        assert "Geburtsdatum" in target["missing_fields"], f"Missing 'Geburtsdatum': {target['missing_fields']}"
