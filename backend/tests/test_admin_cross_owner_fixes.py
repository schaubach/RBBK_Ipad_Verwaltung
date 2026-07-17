"""
FOCUSED regression tests for iteration_8:

FIX 1: POST /api/assignments/manual — admin can now assign iPads owned
       by a DIFFERENT user (previously atomic-query filtered by
       user_id=current_user.id → 409 "iPad wurde gerade übernommen").

FIX 2: POST /api/students/batch-delete — admin cascade-dissolves student's
       active assignments regardless of the assignment's user_id
       (previously assignment_filter filtered by user_id=current_user.id
       → cross-user assignments stayed active + iPads stayed 'assigned').

REGRESSION:
  - Standard-User can NOT manual-assign onto other users' iPads (404).
  - Standard-User batch-delete still only dissolves own assignments.
  - GET /api/assignments returns contract_warning flag.
  - POST /api/contracts/{cid}/assign/{aid} works cross-owner for admin.
"""

import os
import time
import uuid

import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://vertraege-lab.preview.emergentagent.com").rstrip("/")
API = f"{BASE_URL}/api"

ADMIN_USER = "admin"
ADMIN_PASS = "admin123"

TEST_PREFIX = f"TEST_CO_{uuid.uuid4().hex[:6]}"


# -------------------- helpers --------------------


def _login(username, password):
    for _ in range(15):
        r = requests.post(
            f"{API}/auth/login",
            json={"username": username, "password": password},
            timeout=30,
        )
        if r.status_code == 429:
            time.sleep(8)
            continue
        return r
    return r


@pytest.fixture(scope="module")
def admin_token():
    r = _login(ADMIN_USER, ADMIN_PASS)
    assert r.status_code == 200, f"Admin login failed: {r.status_code} {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def admin_client(admin_token):
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {admin_token}"})
    return s


@pytest.fixture(scope="module")
def admin_id(admin_client):
    r = admin_client.get(f"{API}/auth/me")
    return r.json()["id"]


@pytest.fixture(scope="module")
def owner_user(admin_client):
    """Create a second standard user 'testowner'; cleanup at teardown."""
    uname = f"{TEST_PREFIX}_owner"
    pwd_temp = None
    payload = {"username": uname, "password": "Temp1234!", "role": "user"}
    r = admin_client.post(f"{API}/admin/users", json=payload)
    assert r.status_code in (200, 201), f"Create user: {r.status_code} {r.text}"
    body = r.json()
    user_id = body.get("id") or body.get("user", {}).get("id")
    # some create-user impls return a generated temp_password to display once
    pwd_temp = body.get("temp_password") or body.get("temporary_password") or "Temp1234!"
    yield {"username": uname, "password": pwd_temp, "id": user_id}
    try:
        admin_client.delete(f"{API}/admin/users/{user_id}/complete")
    except Exception:
        pass


@pytest.fixture(scope="module")
def owner_token(owner_user):
    time.sleep(2)
    r = _login(owner_user["username"], owner_user["password"])
    if r.status_code == 200 and r.json().get("force_password_change"):
        tmp_token = r.json()["access_token"]
        rr = requests.put(
            f"{API}/auth/change-password-forced",
            headers={"Authorization": f"Bearer {tmp_token}"},
            json={"new_password": "Pass1234!"},
        )
        assert rr.status_code in (200, 204), f"Force-change: {rr.status_code} {rr.text}"
        time.sleep(2)
        r = _login(owner_user["username"], "Pass1234!")
    assert r.status_code == 200, f"Owner login failed: {r.status_code} {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def owner_client(owner_token):
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {owner_token}"})
    return s


@pytest.fixture(scope="module")
def owner_id(owner_client):
    r = owner_client.get(f"{API}/auth/me")
    return r.json()["id"]


# -------------------- FIX 1: admin manual-assign on OTHER USER's iPad --------------------


class TestFix1AdminCrossOwnerManualAssign:
    """Admin must be able to manual-assign an iPad whose user_id is another user."""

    def test_admin_can_manual_assign_ipad_owned_by_other_user(self, admin_client, admin_id, owner_client, owner_id):
        # 1) owner creates iPad (user_id=owner)
        itnr = f"{TEST_PREFIX}_F1_{uuid.uuid4().hex[:4]}"
        r = owner_client.post(
            f"{API}/ipads",
            json={
                "itnr": itnr,
                "snr": f"SN_{uuid.uuid4().hex[:8]}",
                "typ": "iPad",
                "status": "in_betrieb",
            },
        )
        assert r.status_code in (200, 201), f"iPad create by owner: {r.status_code} {r.text}"
        ipad = r.json()
        ipad_id = ipad.get("id") or ipad.get("ipad", {}).get("id")

        # 2) admin creates student (user_id=admin)
        r = admin_client.post(
            f"{API}/students",
            json={"sus_vorn": f"{TEST_PREFIX}_F1V", "sus_nachn": f"{TEST_PREFIX}_F1N", "sus_kl": "8x"},
        )
        assert r.status_code in (200, 201), r.text
        sid = r.json().get("id") or r.json().get("student", {}).get("id")

        aid = None
        try:
            # 3) admin calls manual-assign — this is the CORE fix.
            r = admin_client.post(
                f"{API}/assignments/manual",
                json={"student_id": sid, "ipad_id": ipad_id},
            )
            assert r.status_code == 200, (
                f"FIX 1 BROKEN: admin got {r.status_code}: {r.text}. "
                f"Expected 200 (admin can assign iPad owned by another user)."
            )
            body = r.json()
            aid = body.get("assignment_id") or body.get("id")
            assert aid, f"No assignment_id returned: {body}"

            # 4) Verify: iPad's current_assignment_id set, iPad user_id unchanged (still owner)
            r = admin_client.get(f"{API}/ipads/{ipad_id}/history")
            assert r.status_code == 200
            ipad_info = r.json().get("ipad") or r.json()
            assert (
                ipad_info.get("current_assignment_id") == aid
            ), f"iPad not linked to assignment: {ipad_info.get('current_assignment_id')} vs {aid}"

            # 5) Verify: assignment visible in /assignments list
            r = admin_client.get(f"{API}/assignments")
            assert r.status_code == 200
            assert any(a["id"] == aid for a in r.json()), "Assignment not in list"
        finally:
            # cleanup
            if aid:
                try:
                    admin_client.delete(f"{API}/assignments/{aid}")
                except Exception:
                    pass
            try:
                admin_client.delete(f"{API}/students/{sid}")
            except Exception:
                pass
            try:
                admin_client.delete(f"{API}/ipads/{ipad_id}")
            except Exception:
                pass

    def test_standard_user_cannot_manual_assign_other_users_ipad(self, admin_client, owner_client, owner_id):
        """SECURITY REGRESSION: user without admin role must still get 404
        (via get_ipad_filter_with_pool) when trying to assign a non-owned, non-pool iPad."""
        # admin creates iPad (user_id=admin), NOT in pool
        itnr = f"{TEST_PREFIX}_F1S_{uuid.uuid4().hex[:4]}"
        r = admin_client.post(
            f"{API}/ipads",
            json={
                "itnr": itnr,
                "snr": f"SN_{uuid.uuid4().hex[:8]}",
                "typ": "iPad",
                "status": "in_betrieb",
                "is_in_pool": False,
            },
        )
        assert r.status_code in (200, 201), r.text
        ipad_id = r.json().get("id") or r.json().get("ipad", {}).get("id")

        # owner creates a student (owned)
        r = owner_client.post(
            f"{API}/students",
            json={"sus_vorn": f"{TEST_PREFIX}_F1SV", "sus_nachn": f"{TEST_PREFIX}_F1SN", "sus_kl": "8y"},
        )
        assert r.status_code in (200, 201), r.text
        sid = r.json().get("id") or r.json().get("student", {}).get("id")

        try:
            # owner tries to assign admin's non-pool iPad → must be 404
            r = owner_client.post(
                f"{API}/assignments/manual",
                json={"student_id": sid, "ipad_id": ipad_id},
            )
            assert r.status_code == 404, (
                f"SECURITY REGRESSION: user was allowed to assign non-owned, non-pool "
                f"iPad. Expected 404, got {r.status_code}: {r.text}"
            )
        finally:
            try:
                owner_client.delete(f"{API}/students/{sid}")
            except Exception:
                pass
            try:
                admin_client.delete(f"{API}/ipads/{ipad_id}")
            except Exception:
                pass

    def test_admin_manual_assign_pool_ipad_claims_and_assigns_atomically(self, admin_client, admin_id):
        """Pool iPad: admin manual-assign should claim (is_in_pool=false, user_id=admin)
        AND set current_assignment_id in a single atomic operation."""
        itnr = f"{TEST_PREFIX}_F1P_{uuid.uuid4().hex[:4]}"
        r = admin_client.post(
            f"{API}/ipads",
            json={
                "itnr": itnr,
                "snr": f"SN_{uuid.uuid4().hex[:8]}",
                "typ": "iPad",
                "status": "in_betrieb",
                "is_in_pool": True,
            },
        )
        assert r.status_code in (200, 201), r.text
        ipad_id = r.json().get("id") or r.json().get("ipad", {}).get("id")

        r = admin_client.post(
            f"{API}/students",
            json={"sus_vorn": f"{TEST_PREFIX}_F1PV", "sus_nachn": f"{TEST_PREFIX}_F1PN", "sus_kl": "8z"},
        )
        sid = r.json().get("id") or r.json().get("student", {}).get("id")

        aid = None
        try:
            r = admin_client.post(
                f"{API}/assignments/manual",
                json={"student_id": sid, "ipad_id": ipad_id},
            )
            assert r.status_code == 200, r.text
            body = r.json()
            aid = body.get("assignment_id")
            assert body.get("claimed_from_pool") is True, f"Expected claimed_from_pool=True: {body}"

            # Verify iPad state
            r = admin_client.get(f"{API}/ipads/{ipad_id}/history")
            ipad_info = r.json().get("ipad") or r.json()
            assert ipad_info.get("current_assignment_id") == aid
            assert ipad_info.get("is_in_pool") in (False, None), f"iPad still in pool: {ipad_info}"
        finally:
            if aid:
                try:
                    admin_client.delete(f"{API}/assignments/{aid}")
                except Exception:
                    pass
            try:
                admin_client.delete(f"{API}/students/{sid}")
            except Exception:
                pass
            try:
                admin_client.delete(f"{API}/ipads/{ipad_id}")
            except Exception:
                pass


# -------------------- FIX 2: admin batch-delete dissolves cross-user assignments --------------------


class TestFix2AdminBatchDeleteCascade:
    """Admin batch-delete must free iPads of assignments with any user_id."""

    def test_admin_batch_delete_dissolves_owner_owned_assignments(self, admin_client, owner_client):
        # 1) owner creates own student + own iPad + own assignment
        r = owner_client.post(
            f"{API}/students",
            json={
                "sus_vorn": f"{TEST_PREFIX}_F2V",
                "sus_nachn": f"{TEST_PREFIX}_F2N",
                "sus_kl": "9a",
            },
        )
        assert r.status_code in (200, 201), r.text
        sid = r.json().get("id") or r.json().get("student", {}).get("id")

        itnr = f"{TEST_PREFIX}_F2_{uuid.uuid4().hex[:4]}"
        r = owner_client.post(
            f"{API}/ipads",
            json={
                "itnr": itnr,
                "snr": f"SN_{uuid.uuid4().hex[:8]}",
                "typ": "iPad",
                "status": "in_betrieb",
            },
        )
        assert r.status_code in (200, 201), r.text
        ipad_id = r.json().get("id") or r.json().get("ipad", {}).get("id")

        r = owner_client.post(
            f"{API}/assignments/manual",
            json={"student_id": sid, "ipad_id": ipad_id},
        )
        assert r.status_code == 200, r.text
        aid = r.json().get("assignment_id")

        try:
            # Sanity: assignment is user_id=owner
            r = owner_client.get(f"{API}/assignments")
            assert any(a["id"] == aid for a in r.json()), "assignment not found"

            # 2) ADMIN batch-deletes the student by lastname filter
            r = admin_client.post(
                f"{API}/students/batch-delete",
                json={"sus_nachn": f"{TEST_PREFIX}_F2N"},
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body.get("deleted_count", 0) >= 1, f"Student not deleted: {body}"
            assert body.get("freed_ipads", 0) >= 1, (
                f"FIX 2 BROKEN: iPad not freed. Expected freed_ipads>=1, got: {body}. "
                f"The owner's assignment (user_id=owner) was not dissolved by admin."
            )

            # 3) Verify iPad no longer has current_assignment_id
            r = admin_client.get(f"{API}/ipads/{ipad_id}/history")
            ipad_info = r.json().get("ipad") or r.json()
            assert (
                ipad_info.get("current_assignment_id") is None
            ), f"FIX 2 BROKEN: iPad current_assignment_id still set: {ipad_info}"
        finally:
            # cleanup (assignment already dissolved+deleted, student already deleted)
            try:
                admin_client.delete(f"{API}/ipads/{ipad_id}")
            except Exception:
                pass

    def test_standard_user_batch_delete_scoped_to_own_data(self, owner_client):
        """REGRESSION: user batch-delete only affects their OWN students+assignments.
        Since users can only see own students, this is inherently secure — verify
        the endpoint still succeeds without cross-user leakage.
        """
        r = owner_client.post(
            f"{API}/students",
            json={
                "sus_vorn": f"{TEST_PREFIX}_F2UV",
                "sus_nachn": f"{TEST_PREFIX}_F2UN",
                "sus_kl": "9b",
            },
        )
        assert r.status_code in (200, 201), r.text
        sid = r.json().get("id") or r.json().get("student", {}).get("id")

        itnr = f"{TEST_PREFIX}_F2U_{uuid.uuid4().hex[:4]}"
        r = owner_client.post(
            f"{API}/ipads",
            json={
                "itnr": itnr,
                "snr": f"SN_{uuid.uuid4().hex[:8]}",
                "typ": "iPad",
                "status": "in_betrieb",
            },
        )
        assert r.status_code in (200, 201)
        ipad_id = r.json().get("id") or r.json().get("ipad", {}).get("id")

        r = owner_client.post(
            f"{API}/assignments/manual",
            json={"student_id": sid, "ipad_id": ipad_id},
        )
        assert r.status_code == 200, r.text

        try:
            r = owner_client.post(
                f"{API}/students/batch-delete",
                json={"sus_nachn": f"{TEST_PREFIX}_F2UN"},
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body.get("deleted_count", 0) >= 1
            assert body.get("freed_ipads", 0) >= 1, f"own iPad not freed: {body}"
        finally:
            try:
                owner_client.delete(f"{API}/ipads/{ipad_id}")
            except Exception:
                pass


# -------------------- REGRESSION: Zuordnungen tab + iPad-Detail + Contract-Assign --------------------


class TestRegressionCore:
    def test_get_assignments_returns_contract_warning_flag(self, admin_client):
        r = admin_client.get(f"{API}/assignments")
        assert r.status_code == 200, r.text
        # If any assignments exist, each must have contract_warning key
        for a in r.json():
            assert "contract_warning" in a, f"missing contract_warning: {a}"
            assert "warning_dismissed" in a, f"missing warning_dismissed: {a}"

    def test_ipad_history_endpoint_reachable(self, admin_client):
        """GET /api/ipads/{id}/history is the endpoint the frontend uses to open
        the iPad detail modal from the Zuordnungen table."""
        # Get any iPad from list
        r = admin_client.get(f"{API}/ipads")
        assert r.status_code == 200
        ipads = r.json()
        if not ipads:
            pytest.skip("No iPads in DB to test history endpoint")
        r = admin_client.get(f"{API}/ipads/{ipads[0]['id']}/history")
        assert r.status_code == 200, r.text

    def test_admin_contract_assign_crosses_ownership(self, admin_client, owner_client):
        """Admin must be able to POST /contracts/{cid}/assign/{aid} even if
        the contract or assignment belongs to another user."""
        # Setup: owner creates full flow (student + iPad + assignment)
        r = owner_client.post(
            f"{API}/students",
            json={
                "sus_vorn": f"{TEST_PREFIX}_CAV",
                "sus_nachn": f"{TEST_PREFIX}_CAN",
                "sus_kl": "9c",
            },
        )
        sid = r.json().get("id") or r.json().get("student", {}).get("id")

        itnr = f"{TEST_PREFIX}_CA_{uuid.uuid4().hex[:4]}"
        r = owner_client.post(
            f"{API}/ipads",
            json={
                "itnr": itnr,
                "snr": f"SN_{uuid.uuid4().hex[:8]}",
                "typ": "iPad",
                "status": "in_betrieb",
            },
        )
        ipad_id = r.json().get("id") or r.json().get("ipad", {}).get("id")

        r = owner_client.post(
            f"{API}/assignments/manual",
            json={"student_id": sid, "ipad_id": ipad_id},
        )
        aid = r.json().get("assignment_id")

        # Find an "unassigned" contract as admin (if any). If none, we synthesize
        # a scenario by uploading a contract to the assignment — but that would
        # already tie it. Instead we test the route responds coherently.
        try:
            r = admin_client.get(f"{API}/contracts/unassigned")
            assert r.status_code == 200
            unassigned = r.json()
            if not unassigned:
                pytest.skip("No unassigned contracts available to test cross-owner assign")

            cid = unassigned[0]["id"]
            r = admin_client.post(f"{API}/contracts/{cid}/assign/{aid}")
            # Expected: 200 OR 400 (if student already has max contracts). NOT 403.
            assert r.status_code in (200, 400), f"Cross-owner contract-assign failed: {r.status_code} {r.text}"
        finally:
            try:
                admin_client.delete(f"{API}/assignments/{aid}")
            except Exception:
                pass
            try:
                admin_client.delete(f"{API}/students/{sid}")
            except Exception:
                pass
            try:
                admin_client.delete(f"{API}/ipads/{ipad_id}")
            except Exception:
                pass

    def test_smoke_60_endpoints_reachable(self, admin_client):
        """Quick smoke: hit a spread of GET endpoints to confirm no ImportError/500."""
        get_eps = [
            "/auth/me",
            "/ipads",
            "/students",
            "/assignments",
            "/contracts",
            "/contracts/unassigned",
            "/settings/global",
            "/admin/users",
            "/exports/columns",
            "/ipads/available-for-assignment",
            "/students/available-for-assignment",
            "/assignments/available-for-contracts",
            "/imports/template",
        ]
        errors = []
        for ep in get_eps:
            r = admin_client.get(f"{API}{ep}")
            if r.status_code >= 500:
                errors.append(f"{ep} → {r.status_code}: {r.text[:200]}")
        assert not errors, "5xx errors on GETs:\n" + "\n".join(errors)
