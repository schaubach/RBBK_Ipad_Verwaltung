"""
Test suite for iPad and Student Update (PUT) endpoints
Tests the new edit functionality for iPads and Students in detail view

Features tested:
- PUT /api/ipads/{ipad_id} - Full iPad update (all fields)
- PUT /api/students/{student_id} - Full Student update (all fields including guardians)
- Name change propagation to Assignments and Contracts
- ITNr change propagation to Assignments and Contracts
"""

import pytest
import requests
import os
import uuid

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestAuth:
    """Authentication helper tests"""
    
    @pytest.fixture(scope="class")
    def auth_token(self):
        """Get authentication token"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "username": "admin",
            "password": "admin123"
        })
        assert response.status_code == 200, f"Login failed: {response.text}"
        return response.json().get("access_token")
    
    @pytest.fixture(scope="class")
    def auth_headers(self, auth_token):
        """Get headers with auth token"""
        return {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json"
        }


class TestIPadUpdate(TestAuth):
    """Tests for PUT /api/ipads/{ipad_id} endpoint"""
    
    @pytest.fixture(scope="class")
    def test_ipad(self, auth_headers):
        """Create a test iPad for update tests"""
        unique_id = str(uuid.uuid4())[:8]
        ipad_data = {
            "itnr": f"TEST-IPAD-{unique_id}",
            "snr": f"SNR-{unique_id}",
            "karton": "Karton-Original",
            "pencil": "Pencil-Original",
            "typ": "iPad Pro",
            "ansch_jahr": "2024",
            "ausleihe_datum": "2024-01-15",
            "status": "ok"
        }
        response = requests.post(f"{BASE_URL}/api/ipads", json=ipad_data, headers=auth_headers)
        assert response.status_code == 200, f"Failed to create test iPad: {response.text}"
        ipad = response.json()
        yield ipad
        # Cleanup
        requests.delete(f"{BASE_URL}/api/ipads/{ipad['id']}", headers=auth_headers)
    
    def test_update_ipad_all_fields(self, auth_headers, test_ipad):
        """Test updating all iPad fields"""
        unique_id = str(uuid.uuid4())[:8]
        update_data = {
            "itnr": f"UPDATED-IPAD-{unique_id}",
            "snr": f"UPDATED-SNR-{unique_id}",
            "karton": "Karton-Updated",
            "pencil": "Pencil-Updated",
            "typ": "iPad Air",
            "ansch_jahr": "2025",
            "ausleihe_datum": "2025-01-20",
            "status": "ok"
        }
        
        response = requests.put(
            f"{BASE_URL}/api/ipads/{test_ipad['id']}", 
            json=update_data, 
            headers=auth_headers
        )
        
        assert response.status_code == 200, f"Update failed: {response.text}"
        data = response.json()
        assert "message" in data
        assert "ipad" in data
        
        # Verify all fields were updated
        updated_ipad = data["ipad"]
        assert updated_ipad["itnr"] == update_data["itnr"]
        assert updated_ipad["snr"] == update_data["snr"]
        assert updated_ipad["karton"] == update_data["karton"]
        assert updated_ipad["pencil"] == update_data["pencil"]
        assert updated_ipad["typ"] == update_data["typ"]
        assert updated_ipad["ansch_jahr"] == update_data["ansch_jahr"]
        assert updated_ipad["ausleihe_datum"] == update_data["ausleihe_datum"]
        assert updated_ipad["status"] == update_data["status"]
        print(f"✓ iPad update all fields: PASS")
    
    def test_update_ipad_partial_fields(self, auth_headers, test_ipad):
        """Test updating only some iPad fields"""
        update_data = {
            "karton": "Karton-Partial-Update",
            "pencil": "Pencil-Partial-Update"
        }
        
        response = requests.put(
            f"{BASE_URL}/api/ipads/{test_ipad['id']}", 
            json=update_data, 
            headers=auth_headers
        )
        
        assert response.status_code == 200, f"Partial update failed: {response.text}"
        data = response.json()
        assert data["ipad"]["karton"] == "Karton-Partial-Update"
        assert data["ipad"]["pencil"] == "Pencil-Partial-Update"
        print(f"✓ iPad partial update: PASS")
    
    def test_update_ipad_status_valid(self, auth_headers, test_ipad):
        """Test updating iPad status with valid values"""
        for status in ["ok", "defekt", "gestohlen"]:
            response = requests.put(
                f"{BASE_URL}/api/ipads/{test_ipad['id']}", 
                json={"status": status}, 
                headers=auth_headers
            )
            assert response.status_code == 200, f"Status update to '{status}' failed: {response.text}"
            assert response.json()["ipad"]["status"] == status
        print(f"✓ iPad status update (ok, defekt, gestohlen): PASS")
    
    def test_update_ipad_status_invalid(self, auth_headers, test_ipad):
        """Test updating iPad status with invalid value"""
        response = requests.put(
            f"{BASE_URL}/api/ipads/{test_ipad['id']}", 
            json={"status": "invalid_status"}, 
            headers=auth_headers
        )
        assert response.status_code == 400, f"Expected 400 for invalid status, got {response.status_code}"
        print(f"✓ iPad invalid status rejected: PASS")
    
    def test_update_ipad_not_found(self, auth_headers):
        """Test updating non-existent iPad"""
        response = requests.put(
            f"{BASE_URL}/api/ipads/non-existent-id", 
            json={"karton": "test"}, 
            headers=auth_headers
        )
        assert response.status_code == 404, f"Expected 404, got {response.status_code}"
        print(f"✓ iPad not found returns 404: PASS")
    
    def test_update_ipad_empty_request(self, auth_headers, test_ipad):
        """Test updating iPad with empty request body"""
        response = requests.put(
            f"{BASE_URL}/api/ipads/{test_ipad['id']}", 
            json={}, 
            headers=auth_headers
        )
        assert response.status_code == 400, f"Expected 400 for empty update, got {response.status_code}"
        print(f"✓ iPad empty update rejected: PASS")
    
    def test_update_ipad_duplicate_itnr(self, auth_headers, test_ipad):
        """Test updating iPad with duplicate ITNr"""
        # Create another iPad
        unique_id = str(uuid.uuid4())[:8]
        other_ipad_data = {
            "itnr": f"OTHER-IPAD-{unique_id}",
            "snr": f"OTHER-SNR-{unique_id}"
        }
        create_response = requests.post(f"{BASE_URL}/api/ipads", json=other_ipad_data, headers=auth_headers)
        assert create_response.status_code == 200
        other_ipad = create_response.json()
        
        try:
            # Try to update test_ipad with other_ipad's ITNr
            response = requests.put(
                f"{BASE_URL}/api/ipads/{test_ipad['id']}", 
                json={"itnr": other_ipad["itnr"]}, 
                headers=auth_headers
            )
            assert response.status_code == 400, f"Expected 400 for duplicate ITNr, got {response.status_code}"
            print(f"✓ iPad duplicate ITNr rejected: PASS")
        finally:
            # Cleanup
            requests.delete(f"{BASE_URL}/api/ipads/{other_ipad['id']}", headers=auth_headers)


class TestStudentUpdate(TestAuth):
    """Tests for PUT /api/students/{student_id} endpoint"""
    
    @pytest.fixture(scope="class")
    def test_student(self, auth_headers):
        """Create a test student for update tests"""
        unique_id = str(uuid.uuid4())[:8]
        student_data = {
            "sus_vorn": f"TestVorname-{unique_id}",
            "sus_nachn": f"TestNachname-{unique_id}",
            "sus_kl": "10A",
            "sus_geb": "2010-05-15",
            "sus_str_hnr": "Teststraße 1",
            "sus_plz": "12345",
            "sus_ort": "Teststadt",
            "erz1_vorn": "Erz1Vorname",
            "erz1_nachn": "Erz1Nachname",
            "erz1_str_hnr": "Erz1Straße 1",
            "erz1_plz": "12345",
            "erz1_ort": "Erz1Stadt",
            "erz2_vorn": "Erz2Vorname",
            "erz2_nachn": "Erz2Nachname",
            "erz2_str_hnr": "Erz2Straße 2",
            "erz2_plz": "54321",
            "erz2_ort": "Erz2Stadt"
        }
        response = requests.post(f"{BASE_URL}/api/students", json=student_data, headers=auth_headers)
        assert response.status_code == 200, f"Failed to create test student: {response.text}"
        student = response.json()
        yield student
        # Cleanup
        requests.delete(f"{BASE_URL}/api/students/{student['id']}", headers=auth_headers)
    
    def test_update_student_personal_data(self, auth_headers, test_student):
        """Test updating student personal data"""
        unique_id = str(uuid.uuid4())[:8]
        update_data = {
            "sus_vorn": f"UpdatedVorname-{unique_id}",
            "sus_nachn": f"UpdatedNachname-{unique_id}",
            "sus_kl": "11B",
            "sus_geb": "2009-03-20",
            "sus_str_hnr": "Neue Straße 5",
            "sus_plz": "67890",
            "sus_ort": "Neue Stadt"
        }
        
        response = requests.put(
            f"{BASE_URL}/api/students/{test_student['id']}", 
            json=update_data, 
            headers=auth_headers
        )
        
        assert response.status_code == 200, f"Update failed: {response.text}"
        data = response.json()
        assert "message" in data
        assert "student" in data
        
        # Verify fields were updated
        updated_student = data["student"]
        assert updated_student["sus_vorn"] == update_data["sus_vorn"]
        assert updated_student["sus_nachn"] == update_data["sus_nachn"]
        assert updated_student["sus_kl"] == update_data["sus_kl"]
        assert updated_student["sus_str_hnr"] == update_data["sus_str_hnr"]
        assert updated_student["sus_plz"] == update_data["sus_plz"]
        assert updated_student["sus_ort"] == update_data["sus_ort"]
        print(f"✓ Student personal data update: PASS")
    
    def test_update_student_guardian1(self, auth_headers, test_student):
        """Test updating guardian 1 data"""
        update_data = {
            "erz1_vorn": "NeuerErz1Vorname",
            "erz1_nachn": "NeuerErz1Nachname",
            "erz1_str_hnr": "Neue Erz1 Straße 10",
            "erz1_plz": "11111",
            "erz1_ort": "Neue Erz1 Stadt"
        }
        
        response = requests.put(
            f"{BASE_URL}/api/students/{test_student['id']}", 
            json=update_data, 
            headers=auth_headers
        )
        
        assert response.status_code == 200, f"Guardian 1 update failed: {response.text}"
        data = response.json()
        updated_student = data["student"]
        assert updated_student["erz1_vorn"] == update_data["erz1_vorn"]
        assert updated_student["erz1_nachn"] == update_data["erz1_nachn"]
        assert updated_student["erz1_str_hnr"] == update_data["erz1_str_hnr"]
        assert updated_student["erz1_plz"] == update_data["erz1_plz"]
        assert updated_student["erz1_ort"] == update_data["erz1_ort"]
        print(f"✓ Student guardian 1 update: PASS")
    
    def test_update_student_guardian2(self, auth_headers, test_student):
        """Test updating guardian 2 data"""
        update_data = {
            "erz2_vorn": "NeuerErz2Vorname",
            "erz2_nachn": "NeuerErz2Nachname",
            "erz2_str_hnr": "Neue Erz2 Straße 20",
            "erz2_plz": "22222",
            "erz2_ort": "Neue Erz2 Stadt"
        }
        
        response = requests.put(
            f"{BASE_URL}/api/students/{test_student['id']}", 
            json=update_data, 
            headers=auth_headers
        )
        
        assert response.status_code == 200, f"Guardian 2 update failed: {response.text}"
        data = response.json()
        updated_student = data["student"]
        assert updated_student["erz2_vorn"] == update_data["erz2_vorn"]
        assert updated_student["erz2_nachn"] == update_data["erz2_nachn"]
        assert updated_student["erz2_str_hnr"] == update_data["erz2_str_hnr"]
        assert updated_student["erz2_plz"] == update_data["erz2_plz"]
        assert updated_student["erz2_ort"] == update_data["erz2_ort"]
        print(f"✓ Student guardian 2 update: PASS")
    
    def test_update_student_not_found(self, auth_headers):
        """Test updating non-existent student"""
        response = requests.put(
            f"{BASE_URL}/api/students/non-existent-id", 
            json={"sus_kl": "12C"}, 
            headers=auth_headers
        )
        assert response.status_code == 404, f"Expected 404, got {response.status_code}"
        print(f"✓ Student not found returns 404: PASS")
    
    def test_update_student_empty_request(self, auth_headers, test_student):
        """Test updating student with empty request body"""
        response = requests.put(
            f"{BASE_URL}/api/students/{test_student['id']}", 
            json={}, 
            headers=auth_headers
        )
        assert response.status_code == 400, f"Expected 400 for empty update, got {response.status_code}"
        print(f"✓ Student empty update rejected: PASS")


class TestNameChangePropagation(TestAuth):
    """Tests for name change propagation to Assignments and Contracts"""
    
    def test_student_name_change_updates_assignments(self, auth_headers):
        """Test that student name change updates related assignments"""
        unique_id = str(uuid.uuid4())[:8]
        
        # Create student
        student_data = {
            "sus_vorn": f"OriginalVorname-{unique_id}",
            "sus_nachn": f"OriginalNachname-{unique_id}"
        }
        student_response = requests.post(f"{BASE_URL}/api/students", json=student_data, headers=auth_headers)
        assert student_response.status_code == 200
        student = student_response.json()
        
        # Create iPad
        ipad_data = {
            "itnr": f"PROP-IPAD-{unique_id}",
            "snr": f"PROP-SNR-{unique_id}"
        }
        ipad_response = requests.post(f"{BASE_URL}/api/ipads", json=ipad_data, headers=auth_headers)
        assert ipad_response.status_code == 200
        ipad = ipad_response.json()
        
        # Create assignment
        assign_response = requests.post(
            f"{BASE_URL}/api/assignments/manual",
            json={"student_id": student["id"], "ipad_id": ipad["id"]},
            headers=auth_headers
        )
        assert assign_response.status_code == 200, f"Assignment failed: {assign_response.text}"
        
        # Update student name
        new_name_data = {
            "sus_vorn": f"NewVorname-{unique_id}",
            "sus_nachn": f"NewNachname-{unique_id}"
        }
        update_response = requests.put(
            f"{BASE_URL}/api/students/{student['id']}", 
            json=new_name_data, 
            headers=auth_headers
        )
        assert update_response.status_code == 200
        
        # Verify assignment has updated student_name
        assignments_response = requests.get(f"{BASE_URL}/api/assignments", headers=auth_headers)
        assert assignments_response.status_code == 200
        assignments = assignments_response.json()
        
        student_assignment = next((a for a in assignments if a["student_id"] == student["id"]), None)
        assert student_assignment is not None, "Assignment not found"
        expected_name = f"{new_name_data['sus_vorn']} {new_name_data['sus_nachn']}"
        assert student_assignment["student_name"] == expected_name, f"Expected '{expected_name}', got '{student_assignment['student_name']}'"
        
        print(f"✓ Student name change propagates to assignments: PASS")
        
        # Cleanup
        requests.delete(f"{BASE_URL}/api/students/{student['id']}", headers=auth_headers)
        requests.delete(f"{BASE_URL}/api/ipads/{ipad['id']}", headers=auth_headers)


class TestIPadITNrChangePropagation(TestAuth):
    """Tests for iPad ITNr change propagation to Assignments and Contracts"""
    
    def test_ipad_itnr_change_updates_assignments(self, auth_headers):
        """Test that iPad ITNr change updates related assignments"""
        unique_id = str(uuid.uuid4())[:8]
        
        # Create student
        student_data = {
            "sus_vorn": f"ITNrTestVorname-{unique_id}",
            "sus_nachn": f"ITNrTestNachname-{unique_id}"
        }
        student_response = requests.post(f"{BASE_URL}/api/students", json=student_data, headers=auth_headers)
        assert student_response.status_code == 200
        student = student_response.json()
        
        # Create iPad
        original_itnr = f"ORIG-ITNR-{unique_id}"
        ipad_data = {
            "itnr": original_itnr,
            "snr": f"ITNR-SNR-{unique_id}"
        }
        ipad_response = requests.post(f"{BASE_URL}/api/ipads", json=ipad_data, headers=auth_headers)
        assert ipad_response.status_code == 200
        ipad = ipad_response.json()
        
        # Create assignment
        assign_response = requests.post(
            f"{BASE_URL}/api/assignments/manual",
            json={"student_id": student["id"], "ipad_id": ipad["id"]},
            headers=auth_headers
        )
        assert assign_response.status_code == 200, f"Assignment failed: {assign_response.text}"
        
        # Update iPad ITNr
        new_itnr = f"NEW-ITNR-{unique_id}"
        update_response = requests.put(
            f"{BASE_URL}/api/ipads/{ipad['id']}", 
            json={"itnr": new_itnr}, 
            headers=auth_headers
        )
        assert update_response.status_code == 200
        
        # Verify assignment has updated itnr
        assignments_response = requests.get(f"{BASE_URL}/api/assignments", headers=auth_headers)
        assert assignments_response.status_code == 200
        assignments = assignments_response.json()
        
        ipad_assignment = next((a for a in assignments if a["ipad_id"] == ipad["id"]), None)
        assert ipad_assignment is not None, "Assignment not found"
        assert ipad_assignment["itnr"] == new_itnr, f"Expected '{new_itnr}', got '{ipad_assignment['itnr']}'"
        
        print(f"✓ iPad ITNr change propagates to assignments: PASS")
        
        # Cleanup
        requests.delete(f"{BASE_URL}/api/students/{student['id']}", headers=auth_headers)
        requests.delete(f"{BASE_URL}/api/ipads/{ipad['id']}", headers=auth_headers)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
