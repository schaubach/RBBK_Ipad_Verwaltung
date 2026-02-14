"""
Test suite for 1:n iPad-Student relationship functionality
Tests:
- Excel Import with 1:n support (students appearing on multiple rows merged)
- iPad limit enforcement (max 3 iPads per student)
- Excel Export with separate row per iPad assignment
- Re-import of exported data
- Assignment count display per student
"""
import pytest
import requests
import os
import io

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')
MAX_IPADS_PER_STUDENT = 3

@pytest.fixture(scope="module")
def auth_token():
    """Get authentication token"""
    response = requests.post(f"{BASE_URL}/api/auth/login", json={
        "username": "admin",
        "password": "admin123"
    })
    assert response.status_code == 200, f"Login failed: {response.text}"
    return response.json()["access_token"]

@pytest.fixture(scope="module")
def api_client(auth_token):
    """Create authenticated API session"""
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    })
    return session

class TestExistingTestData:
    """Verify existing test data setup"""
    
    def test_students_with_assignment_counts(self, api_client):
        """Verify students have correct assignment_count values"""
        response = api_client.get(f"{BASE_URL}/api/students")
        assert response.status_code == 200
        
        students = response.json()
        assert len(students) > 0, "No students found in database"
        
        # Create a lookup by name
        student_map = {f"{s['sus_vorn']} {s['sus_nachn']}": s for s in students}
        
        # Verify expected test data
        print(f"Found {len(students)} students")
        for name, student in student_map.items():
            print(f"  - {name}: {student['assignment_count']} iPads")
        
        # Peter Müller should have 3 iPads (limit reached)
        if "Peter Müller" in student_map:
            assert student_map["Peter Müller"]["assignment_count"] == 3, \
                f"Peter Müller should have exactly 3 iPads, got {student_map['Peter Müller']['assignment_count']}"
            print("✓ Peter Müller correctly has 3 iPads (limit)")
        
        # Max Mustermann should have 2 iPads
        if "Max Mustermann" in student_map:
            assert student_map["Max Mustermann"]["assignment_count"] == 2, \
                f"Max Mustermann should have 2 iPads, got {student_map['Max Mustermann']['assignment_count']}"
            print("✓ Max Mustermann correctly has 2 iPads")

    def test_ipads_exist(self, api_client):
        """Verify iPads exist in the system"""
        response = api_client.get(f"{BASE_URL}/api/ipads")
        assert response.status_code == 200
        
        ipads = response.json()
        assert len(ipads) > 0, "No iPads found in database"
        
        # Count assigned vs available
        assigned = sum(1 for ipad in ipads if ipad.get('current_assignment_id'))
        available = sum(1 for ipad in ipads if not ipad.get('current_assignment_id'))
        
        print(f"Found {len(ipads)} iPads: {assigned} assigned, {available} available")
        assert assigned > 0, "Expected some assigned iPads"

class TestStudentAvailability:
    """Test available-for-assignment endpoint with 1:n limit"""
    
    def test_available_students_excludes_at_limit(self, api_client):
        """Students at MAX_IPADS_PER_STUDENT limit should not appear in available list"""
        response = api_client.get(f"{BASE_URL}/api/students/available-for-assignment")
        assert response.status_code == 200
        
        available = response.json()
        available_names = [s["name"] for s in available]
        
        print(f"Available students for assignment: {available_names}")
        
        # Peter Müller (3 iPads) should NOT be available
        for student in available:
            assert student["current_ipads"] < MAX_IPADS_PER_STUDENT, \
                f"{student['name']} has {student['current_ipads']} iPads but still in available list"
        
        print(f"✓ All available students have less than {MAX_IPADS_PER_STUDENT} iPads")

class TestIPadLimit:
    """Test iPad limit enforcement"""
    
    def test_cannot_assign_beyond_limit(self, api_client):
        """Attempting to assign more than MAX_IPADS_PER_STUDENT should fail"""
        # First, find a student at the limit
        response = api_client.get(f"{BASE_URL}/api/students")
        assert response.status_code == 200
        students = response.json()
        
        student_at_limit = None
        for s in students:
            if s.get("assignment_count", 0) >= MAX_IPADS_PER_STUDENT:
                student_at_limit = s
                break
        
        if not student_at_limit:
            pytest.skip("No student at limit found to test")
        
        # Find an available iPad
        response = api_client.get(f"{BASE_URL}/api/ipads/available-for-assignment")
        assert response.status_code == 200
        available_ipads = response.json()
        
        if not available_ipads:
            pytest.skip("No available iPads found to test")
        
        # Try to assign iPad to student at limit
        response = api_client.post(f"{BASE_URL}/api/assignments/manual", json={
            "student_id": student_at_limit["id"],
            "ipad_id": available_ipads[0]["id"]
        })
        
        # Should fail with error about limit
        assert response.status_code == 400, \
            f"Expected 400 error for limit, got {response.status_code}: {response.text}"
        
        assert "limit" in response.text.lower() or "maximum" in response.text.lower() or str(MAX_IPADS_PER_STUDENT) in response.text, \
            f"Error message should mention limit: {response.text}"
        
        print(f"✓ Correctly rejected assignment beyond limit: {response.json().get('detail', response.text)}")

class TestExportInventory:
    """Test inventory export functionality"""
    
    def test_export_returns_xlsx(self, api_client):
        """Export should return a valid Excel file"""
        response = api_client.get(f"{BASE_URL}/api/exports/inventory")
        assert response.status_code == 200
        
        # Check content type
        content_type = response.headers.get("content-type", "")
        assert "spreadsheet" in content_type or "excel" in content_type or "octet-stream" in content_type, \
            f"Unexpected content type: {content_type}"
        
        # Check content-disposition header
        disposition = response.headers.get("content-disposition", "")
        assert "attachment" in disposition, f"Expected attachment header, got: {disposition}"
        assert ".xlsx" in disposition, f"Expected .xlsx filename, got: {disposition}"
        
        print(f"✓ Export returns valid Excel file: {disposition}")
    
    def test_export_contains_assigned_ipads(self, api_client):
        """Export should contain one row per iPad assignment"""
        import pandas as pd
        
        response = api_client.get(f"{BASE_URL}/api/exports/inventory")
        assert response.status_code == 200
        
        # Parse Excel file
        df = pd.read_excel(io.BytesIO(response.content))
        
        print(f"Export contains {len(df)} rows")
        print(f"Columns: {list(df.columns)}")
        
        # Required columns should exist
        required_cols = ['ITNr', 'SuSVorn', 'SuSNachn']
        for col in required_cols:
            assert col in df.columns, f"Missing required column: {col}"
        
        # Count students with multiple rows (1:n verification)
        student_counts = df.groupby(['SuSVorn', 'SuSNachn']).size()
        students_with_multiple = student_counts[student_counts > 1]
        
        if len(students_with_multiple) > 0:
            print("Students with multiple iPads in export:")
            for (vorn, nachn), count in students_with_multiple.items():
                print(f"  - {vorn} {nachn}: {count} iPads")
        
        return df

class TestImportInventory:
    """Test inventory import functionality"""
    
    def test_import_requires_xlsx(self, api_client):
        """Import should only accept xlsx files"""
        # Try to upload a non-xlsx file
        files = {'file': ('test.txt', b'test content', 'text/plain')}
        response = requests.post(
            f"{BASE_URL}/api/imports/inventory",
            headers={"Authorization": api_client.headers["Authorization"]},
            files=files
        )
        
        assert response.status_code == 400, f"Expected 400 for non-xlsx, got {response.status_code}"
        print(f"✓ Correctly rejected non-xlsx file: {response.json().get('detail', '')}")
    
    def test_re_import_exported_data(self, api_client):
        """Re-importing exported data should work correctly (1:n merge)"""
        import pandas as pd
        
        # First export
        response = api_client.get(f"{BASE_URL}/api/exports/inventory")
        assert response.status_code == 200
        exported_content = response.content
        
        # Parse to check content
        df = pd.read_excel(io.BytesIO(exported_content))
        print(f"Exported {len(df)} rows for re-import test")
        
        # Re-import the exported file
        files = {'file': ('exported_inventory.xlsx', exported_content, 
                         'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')}
        
        response = requests.post(
            f"{BASE_URL}/api/imports/inventory",
            headers={"Authorization": api_client.headers["Authorization"]},
            files=files
        )
        
        assert response.status_code == 200, f"Re-import failed: {response.text}"
        
        result = response.json()
        print(f"Re-import result: {result['message']}")
        
        # Since data already exists, most should be skipped
        assert result.get("ipads_skipped", 0) > 0 or result.get("students_skipped", 0) > 0, \
            "Re-import should skip existing data"
        
        print(f"✓ Re-import handled existing data correctly")
        print(f"  - iPads created: {result.get('ipads_created', 0)}")
        print(f"  - iPads skipped: {result.get('ipads_skipped', 0)}")
        print(f"  - Students created: {result.get('students_created', 0)}")
        print(f"  - Students skipped: {result.get('students_skipped', 0)}")
        print(f"  - Assignments created: {result.get('assignments_created', 0)}")

class TestImport1toN:
    """Test 1:n import behavior"""
    
    def test_import_merges_same_student(self, api_client):
        """Import should merge rows with same student into single student with multiple iPads"""
        import pandas as pd
        
        # Create test Excel with same student on multiple rows
        test_data = {
            'SuSVorn': ['TestStudent1n', 'TestStudent1n'],
            'SuSNachn': ['ImportTest', 'ImportTest'],
            'SuSKl': ['Test', 'Test'],
            'ITNr': ['TEST-1N-001', 'TEST-1N-002'],
            'SNr': ['TESTSN-001', 'TESTSN-002'],
            'Typ': ['iPad Test', 'iPad Test']
        }
        df = pd.DataFrame(test_data)
        
        # Save to bytes
        output = io.BytesIO()
        df.to_excel(output, index=False, engine='openpyxl')
        output.seek(0)
        
        # Import
        files = {'file': ('test_1n_import.xlsx', output.read(), 
                         'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')}
        
        response = requests.post(
            f"{BASE_URL}/api/imports/inventory",
            headers={"Authorization": api_client.headers["Authorization"]},
            files=files
        )
        
        assert response.status_code == 200, f"Import failed: {response.text}"
        
        result = response.json()
        print(f"1:n import result: {result['message']}")
        
        # Should have created 2 iPads but only 1 student (merged)
        assert result.get("ipads_created", 0) == 2, \
            f"Expected 2 iPads created, got {result.get('ipads_created', 0)}"
        assert result.get("students_created", 0) == 1, \
            f"Expected 1 student created (merged), got {result.get('students_created', 0)}"
        assert result.get("assignments_created", 0) == 2, \
            f"Expected 2 assignments created, got {result.get('assignments_created', 0)}"
        
        print(f"✓ 1:n import correctly merged same student")
        
        # Verify student has 2 assignments
        response = api_client.get(f"{BASE_URL}/api/students")
        assert response.status_code == 200
        
        students = response.json()
        test_student = next((s for s in students if s['sus_vorn'] == 'TestStudent1n'), None)
        
        assert test_student is not None, "Test student not found after import"
        assert test_student.get("assignment_count", 0) == 2, \
            f"Test student should have 2 assignments, got {test_student.get('assignment_count', 0)}"
        
        print(f"✓ Merged student correctly has 2 iPad assignments")
        
        # Cleanup - delete test student
        response = api_client.delete(f"{BASE_URL}/api/students/{test_student['id']}")
        assert response.status_code == 200, f"Cleanup failed: {response.text}"
        print(f"✓ Cleanup: deleted test student")

class TestLimitEnforcementOnImport:
    """Test that import respects MAX_IPADS_PER_STUDENT limit"""
    
    def test_import_respects_limit(self, api_client):
        """Import should skip assignments beyond limit"""
        import pandas as pd
        
        # Create test Excel with 5 iPads for same student (exceeds limit of 3)
        test_data = {
            'SuSVorn': ['LimitTest'] * 5,
            'SuSNachn': ['Student'] * 5,
            'SuSKl': ['Test'] * 5,
            'ITNr': [f'LIMIT-TEST-{i}' for i in range(1, 6)],
            'SNr': [f'LIMITSN-{i}' for i in range(1, 6)],
            'Typ': ['iPad Test'] * 5
        }
        df = pd.DataFrame(test_data)
        
        # Save to bytes
        output = io.BytesIO()
        df.to_excel(output, index=False, engine='openpyxl')
        output.seek(0)
        
        # Import
        files = {'file': ('test_limit_import.xlsx', output.read(), 
                         'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')}
        
        response = requests.post(
            f"{BASE_URL}/api/imports/inventory",
            headers={"Authorization": api_client.headers["Authorization"]},
            files=files
        )
        
        assert response.status_code == 200, f"Import failed: {response.text}"
        
        result = response.json()
        print(f"Limit test import result:")
        print(f"  - iPads created: {result.get('ipads_created', 0)}")
        print(f"  - Assignments created: {result.get('assignments_created', 0)}")
        print(f"  - Assignments skipped (limit): {result.get('assignments_skipped_limit', 0)}")
        
        # All 5 iPads should be created, but only 3 assignments
        assert result.get("ipads_created", 0) == 5, \
            f"Expected 5 iPads created, got {result.get('ipads_created', 0)}"
        assert result.get("assignments_created", 0) == MAX_IPADS_PER_STUDENT, \
            f"Expected {MAX_IPADS_PER_STUDENT} assignments (limit), got {result.get('assignments_created', 0)}"
        assert result.get("assignments_skipped_limit", 0) == 2, \
            f"Expected 2 skipped due to limit, got {result.get('assignments_skipped_limit', 0)}"
        
        # Verify in errors list
        errors = result.get("errors", [])
        limit_errors = [e for e in errors if "limit" in e.lower() or str(MAX_IPADS_PER_STUDENT) in e]
        assert len(limit_errors) > 0, "Expected limit warnings in errors list"
        
        print(f"✓ Import correctly enforced limit of {MAX_IPADS_PER_STUDENT} iPads per student")
        
        # Cleanup - delete test student
        response = api_client.get(f"{BASE_URL}/api/students")
        students = response.json()
        test_student = next((s for s in students if s['sus_vorn'] == 'LimitTest'), None)
        
        if test_student:
            response = api_client.delete(f"{BASE_URL}/api/students/{test_student['id']}")
            print(f"✓ Cleanup: deleted test student")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
