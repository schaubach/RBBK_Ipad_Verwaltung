"""
Backend API tests for Contracts functionality.
Tests: batch-delete, unassign, single delete (with contract_id nullification)
"""
import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestContractsAPI:
    """Tests for Contracts API endpoints"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup: Login and get auth token"""
        # Setup admin
        requests.post(f"{BASE_URL}/api/auth/setup")
        
        # Login
        login_response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "username": "admin",
            "password": "admin123"
        })
        assert login_response.status_code == 200, f"Login failed: {login_response.text}"
        self.token = login_response.json()["access_token"]
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
    
    # ===== GET /api/contracts Tests =====
    def test_get_contracts_list(self):
        """Test: GET /api/contracts - List all contracts"""
        response = requests.get(f"{BASE_URL}/api/contracts", headers=self.headers)
        assert response.status_code == 200, f"Get contracts failed: {response.text}"
        contracts = response.json()
        assert isinstance(contracts, list), "Response should be a list"
        print(f"PASS: GET /api/contracts - {len(contracts)} contracts found")
    
    # ===== POST /api/contracts/batch-delete Tests =====
    def test_batch_delete_empty_list(self):
        """Test: POST /api/contracts/batch-delete - Empty list should fail"""
        response = requests.post(
            f"{BASE_URL}/api/contracts/batch-delete",
            headers=self.headers,
            json={"contract_ids": []}
        )
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"
        assert "No contract IDs provided" in response.json().get("detail", "")
        print("PASS: Batch delete with empty list returns 400")
    
    def test_batch_delete_nonexistent_contracts(self):
        """Test: POST /api/contracts/batch-delete - Non-existent IDs should return errors array"""
        response = requests.post(
            f"{BASE_URL}/api/contracts/batch-delete",
            headers=self.headers,
            json={"contract_ids": ["nonexistent-id-1", "nonexistent-id-2"]}
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        data = response.json()
        assert data["deleted_count"] == 0, "Should delete 0 contracts"
        assert len(data["errors"]) == 2, "Should have 2 errors"
        print("PASS: Batch delete with nonexistent IDs returns errors array")
    
    def test_batch_delete_max_limit(self):
        """Test: POST /api/contracts/batch-delete - Max 100 contracts limit"""
        # Create list of 101 fake IDs
        fake_ids = [f"fake-id-{i}" for i in range(101)]
        response = requests.post(
            f"{BASE_URL}/api/contracts/batch-delete",
            headers=self.headers,
            json={"contract_ids": fake_ids}
        )
        assert response.status_code == 400, f"Expected 400 for >100 contracts, got {response.status_code}"
        assert "Maximum 100 contracts" in response.json().get("detail", "")
        print("PASS: Batch delete with >100 IDs returns 400")
    
    # ===== POST /api/contracts/{id}/unassign Tests =====
    def test_unassign_nonexistent_contract(self):
        """Test: POST /api/contracts/{id}/unassign - Nonexistent contract"""
        response = requests.post(
            f"{BASE_URL}/api/contracts/nonexistent-id/unassign",
            headers=self.headers
        )
        assert response.status_code == 404, f"Expected 404, got {response.status_code}"
        assert "Contract not found" in response.json().get("detail", "")
        print("PASS: Unassign nonexistent contract returns 404")
    
    # ===== DELETE /api/contracts/{id} Tests =====
    def test_delete_nonexistent_contract(self):
        """Test: DELETE /api/contracts/{id} - Nonexistent contract"""
        response = requests.delete(
            f"{BASE_URL}/api/contracts/nonexistent-id",
            headers=self.headers
        )
        assert response.status_code == 404, f"Expected 404, got {response.status_code}"
        print("PASS: Delete nonexistent contract returns 404")
    
    # ===== Full Integration Test: Create -> Assign -> Delete -> Verify Assignment Cleared =====
    def test_full_contract_workflow(self):
        """
        Integration Test: Create student, iPad, assignment, upload contract, 
        then delete contract and verify assignment.contract_id is nullified
        """
        print("\n--- Starting Full Contract Workflow Test ---")
        
        # Step 1: Create test student
        student_response = requests.post(
            f"{BASE_URL}/api/students",
            headers=self.headers,
            json={
                "sus_vorn": "TEST_ContractWorkflow",
                "sus_nachn": "Student",
                "sus_kl": "TEST-Class"
            }
        )
        if student_response.status_code != 200:
            print(f"WARN: Student creation failed (may exist): {student_response.text}")
            # Try to find existing test student
            students_response = requests.get(f"{BASE_URL}/api/students", headers=self.headers)
            students = students_response.json()
            test_student = next((s for s in students if s.get("sus_vorn") == "TEST_ContractWorkflow"), None)
            if test_student:
                student_id = test_student["id"]
                print(f"Using existing test student: {student_id}")
            else:
                pytest.skip("Could not create or find test student")
        else:
            student_id = student_response.json()["id"]
            print(f"Step 1: Created test student: {student_id}")
        
        # Step 2: Create test iPad
        import uuid
        test_itnr = f"TEST-CW-{uuid.uuid4().hex[:6]}"
        ipad_response = requests.post(
            f"{BASE_URL}/api/ipads",
            headers=self.headers,
            json={
                "itnr": test_itnr,
                "snr": f"SNR-{uuid.uuid4().hex[:8]}",
                "status": "ok"
            }
        )
        if ipad_response.status_code != 200:
            print(f"WARN: iPad creation failed: {ipad_response.text}")
            pytest.skip("Could not create test iPad")
        
        ipad_id = ipad_response.json()["id"]
        print(f"Step 2: Created test iPad: {ipad_id} (ITNR: {test_itnr})")
        
        # Step 3: Create manual assignment
        assignment_response = requests.post(
            f"{BASE_URL}/api/assignments/manual",
            headers=self.headers,
            json={
                "student_id": student_id,
                "ipad_id": ipad_id
            }
        )
        if assignment_response.status_code != 200:
            print(f"WARN: Assignment creation failed: {assignment_response.text}")
            # Cleanup iPad
            requests.delete(f"{BASE_URL}/api/ipads/{ipad_id}", headers=self.headers)
            pytest.skip("Could not create test assignment")
        
        assignment_id = assignment_response.json()["assignment_id"]
        print(f"Step 3: Created test assignment: {assignment_id}")
        
        # Step 4: Upload a test contract (create simple PDF-like content)
        # For now, just upload a dummy file as the API accepts .pdf
        import io
        # Create a minimal PDF
        pdf_content = b"%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n2 0 obj\n<<\n/Type /Pages\n/Kids []\n/Count 0\n>>\nendobj\nxref\n0 3\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\ntrailer\n<<\n/Size 3\n/Root 1 0 R\n>>\nstartxref\n115\n%%EOF"
        
        files = {
            'file': (f'TEST_Contract_{test_itnr}.pdf', io.BytesIO(pdf_content), 'application/pdf')
        }
        upload_headers = {"Authorization": f"Bearer {self.token}"}
        
        upload_response = requests.post(
            f"{BASE_URL}/api/assignments/{assignment_id}/upload-contract",
            headers=upload_headers,
            files=files
        )
        
        if upload_response.status_code != 200:
            print(f"WARN: Contract upload failed: {upload_response.text}")
            # Cleanup
            requests.delete(f"{BASE_URL}/api/ipads/{ipad_id}", headers=self.headers)
            pytest.skip("Could not upload test contract")
        
        contract_id = upload_response.json().get("contract_id")
        print(f"Step 4: Uploaded test contract: {contract_id}")
        
        # Step 5: Verify assignment has contract_id
        assignments_response = requests.get(f"{BASE_URL}/api/assignments", headers=self.headers)
        assignments = assignments_response.json()
        test_assignment = next((a for a in assignments if a["id"] == assignment_id), None)
        
        assert test_assignment is not None, "Test assignment not found"
        assert test_assignment.get("contract_id") == contract_id, f"Assignment should have contract_id={contract_id}"
        print(f"Step 5: Verified assignment has contract_id: {test_assignment.get('contract_id')}")
        
        # Step 6: DELETE the contract
        delete_response = requests.delete(
            f"{BASE_URL}/api/contracts/{contract_id}",
            headers=self.headers
        )
        assert delete_response.status_code == 200, f"Delete contract failed: {delete_response.text}"
        print(f"Step 6: Deleted contract: {contract_id}")
        
        # Step 7: Verify assignment.contract_id is now null
        assignments_response = requests.get(f"{BASE_URL}/api/assignments", headers=self.headers)
        assignments = assignments_response.json()
        test_assignment_after = next((a for a in assignments if a["id"] == assignment_id), None)
        
        assert test_assignment_after is not None, "Test assignment not found after contract deletion"
        assert test_assignment_after.get("contract_id") is None, \
            f"BUG: Assignment contract_id should be null after contract deletion, got: {test_assignment_after.get('contract_id')}"
        
        print(f"Step 7: PASS - Assignment contract_id is null after contract deletion")
        
        # Cleanup: Dissolve assignment and delete iPad
        # First dissolve assignment
        dissolve_response = requests.post(
            f"{BASE_URL}/api/assignments/{assignment_id}/dissolve",
            headers=self.headers
        )
        print(f"Cleanup: Dissolved assignment: {dissolve_response.status_code}")
        
        # Delete iPad
        delete_ipad_response = requests.delete(
            f"{BASE_URL}/api/ipads/{ipad_id}",
            headers=self.headers
        )
        print(f"Cleanup: Deleted iPad: {delete_ipad_response.status_code}")
        
        print("--- Full Contract Workflow Test PASSED ---\n")


class TestContractsBatchDeleteWithRealData:
    """Tests for batch delete with real contract data"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup: Login and get auth token"""
        requests.post(f"{BASE_URL}/api/auth/setup")
        login_response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "username": "admin",
            "password": "admin123"
        })
        assert login_response.status_code == 200
        self.token = login_response.json()["access_token"]
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
    
    def test_batch_delete_with_assigned_contracts(self):
        """
        Test batch delete with contracts that are assigned to assignments.
        Verifies that assignment.contract_id is set to null for each deleted contract.
        """
        import uuid
        import io
        
        print("\n--- Starting Batch Delete with Assigned Contracts Test ---")
        
        # Step 1: Create test student
        student_response = requests.post(
            f"{BASE_URL}/api/students",
            headers=self.headers,
            json={
                "sus_vorn": f"TEST_Batch_{uuid.uuid4().hex[:4]}",
                "sus_nachn": "Student",
                "sus_kl": "TEST-Batch"
            }
        )
        if student_response.status_code != 200:
            pytest.skip(f"Could not create student: {student_response.text}")
        student_id = student_response.json()["id"]
        print(f"Created test student: {student_id}")
        
        created_contracts = []
        created_assignments = []
        created_ipads = []
        
        try:
            # Create 2 iPads and assignments
            for i in range(2):
                # Create iPad
                test_itnr = f"TEST-BD-{uuid.uuid4().hex[:6]}"
                ipad_response = requests.post(
                    f"{BASE_URL}/api/ipads",
                    headers=self.headers,
                    json={
                        "itnr": test_itnr,
                        "snr": f"SNR-{uuid.uuid4().hex[:8]}",
                        "status": "ok"
                    }
                )
                if ipad_response.status_code != 200:
                    print(f"WARN: iPad {i} creation failed: {ipad_response.text}")
                    continue
                ipad_id = ipad_response.json()["id"]
                created_ipads.append(ipad_id)
                
                # Create assignment
                assignment_response = requests.post(
                    f"{BASE_URL}/api/assignments/manual",
                    headers=self.headers,
                    json={
                        "student_id": student_id,
                        "ipad_id": ipad_id
                    }
                )
                if assignment_response.status_code != 200:
                    print(f"WARN: Assignment {i} creation failed: {assignment_response.text}")
                    continue
                assignment_id = assignment_response.json()["assignment_id"]
                created_assignments.append(assignment_id)
                
                # Upload contract
                pdf_content = b"%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n2 0 obj\n<<\n/Type /Pages\n/Kids []\n/Count 0\n>>\nendobj\nxref\n0 3\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\ntrailer\n<<\n/Size 3\n/Root 1 0 R\n>>\nstartxref\n115\n%%EOF"
                files = {
                    'file': (f'TEST_BatchContract_{i}.pdf', io.BytesIO(pdf_content), 'application/pdf')
                }
                upload_headers = {"Authorization": f"Bearer {self.token}"}
                upload_response = requests.post(
                    f"{BASE_URL}/api/assignments/{assignment_id}/upload-contract",
                    headers=upload_headers,
                    files=files
                )
                if upload_response.status_code == 200:
                    contract_id = upload_response.json().get("contract_id")
                    if contract_id:
                        created_contracts.append(contract_id)
                        print(f"Created contract {i}: {contract_id}")
            
            if len(created_contracts) < 2:
                pytest.skip("Could not create enough test contracts")
            
            # Verify assignments have contract_ids
            assignments_response = requests.get(f"{BASE_URL}/api/assignments", headers=self.headers)
            assignments = assignments_response.json()
            for assignment_id in created_assignments:
                assignment = next((a for a in assignments if a["id"] == assignment_id), None)
                if assignment:
                    assert assignment.get("contract_id") is not None, f"Assignment {assignment_id} should have contract_id"
            print("Verified all assignments have contract_ids")
            
            # Step 2: Batch delete contracts
            batch_response = requests.post(
                f"{BASE_URL}/api/contracts/batch-delete",
                headers=self.headers,
                json={"contract_ids": created_contracts}
            )
            assert batch_response.status_code == 200, f"Batch delete failed: {batch_response.text}"
            batch_data = batch_response.json()
            assert batch_data["deleted_count"] == len(created_contracts), f"Expected {len(created_contracts)} deleted"
            print(f"Batch deleted {batch_data['deleted_count']} contracts")
            
            # Step 3: Verify assignments now have contract_id = null
            assignments_response = requests.get(f"{BASE_URL}/api/assignments", headers=self.headers)
            assignments = assignments_response.json()
            
            for assignment_id in created_assignments:
                assignment = next((a for a in assignments if a["id"] == assignment_id), None)
                if assignment:
                    assert assignment.get("contract_id") is None, \
                        f"BUG: Assignment {assignment_id} should have contract_id=null after batch delete"
            
            print("PASS: All assignments have contract_id=null after batch delete")
            
        finally:
            # Cleanup
            for assignment_id in created_assignments:
                requests.post(f"{BASE_URL}/api/assignments/{assignment_id}/dissolve", headers=self.headers)
            for ipad_id in created_ipads:
                requests.delete(f"{BASE_URL}/api/ipads/{ipad_id}", headers=self.headers)
            requests.delete(f"{BASE_URL}/api/students/{student_id}", headers=self.headers)
            print("Cleanup completed")
        
        print("--- Batch Delete with Assigned Contracts Test PASSED ---\n")


class TestContractsUnassign:
    """Tests for unassign contract endpoint"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup: Login and get auth token"""
        requests.post(f"{BASE_URL}/api/auth/setup")
        login_response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "username": "admin",
            "password": "admin123"
        })
        assert login_response.status_code == 200
        self.token = login_response.json()["access_token"]
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
    
    def test_unassign_contract_not_assigned(self):
        """Test unassign on a contract that has no assignment (should return 400)"""
        # First, get contracts list and find one without assignment
        contracts_response = requests.get(f"{BASE_URL}/api/contracts", headers=self.headers)
        contracts = contracts_response.json()
        
        unassigned_contract = next((c for c in contracts if not c.get("assignment_id")), None)
        
        if unassigned_contract:
            response = requests.post(
                f"{BASE_URL}/api/contracts/{unassigned_contract['id']}/unassign",
                headers=self.headers
            )
            assert response.status_code == 400, f"Expected 400 for unassigned contract, got {response.status_code}"
            assert "not assigned" in response.json().get("detail", "").lower()
            print(f"PASS: Unassign on unassigned contract returns 400")
        else:
            print("INFO: No unassigned contracts found to test - skipping")
    
    def test_unassign_full_workflow(self):
        """Test full unassign workflow: create assignment with contract, unassign, verify"""
        import uuid
        import io
        
        print("\n--- Starting Unassign Full Workflow Test ---")
        
        # Create student
        student_response = requests.post(
            f"{BASE_URL}/api/students",
            headers=self.headers,
            json={
                "sus_vorn": f"TEST_Unassign_{uuid.uuid4().hex[:4]}",
                "sus_nachn": "Student",
                "sus_kl": "TEST-UA"
            }
        )
        if student_response.status_code != 200:
            pytest.skip(f"Could not create student: {student_response.text}")
        student_id = student_response.json()["id"]
        
        # Create iPad
        test_itnr = f"TEST-UA-{uuid.uuid4().hex[:6]}"
        ipad_response = requests.post(
            f"{BASE_URL}/api/ipads",
            headers=self.headers,
            json={"itnr": test_itnr, "snr": f"SNR-{uuid.uuid4().hex[:8]}", "status": "ok"}
        )
        if ipad_response.status_code != 200:
            pytest.skip(f"Could not create iPad: {ipad_response.text}")
        ipad_id = ipad_response.json()["id"]
        
        try:
            # Create assignment
            assignment_response = requests.post(
                f"{BASE_URL}/api/assignments/manual",
                headers=self.headers,
                json={"student_id": student_id, "ipad_id": ipad_id}
            )
            assert assignment_response.status_code == 200
            assignment_id = assignment_response.json()["assignment_id"]
            
            # Upload contract
            pdf_content = b"%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n2 0 obj\n<<\n/Type /Pages\n/Kids []\n/Count 0\n>>\nendobj\nxref\n0 3\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\ntrailer\n<<\n/Size 3\n/Root 1 0 R\n>>\nstartxref\n115\n%%EOF"
            files = {'file': ('TEST_Unassign.pdf', io.BytesIO(pdf_content), 'application/pdf')}
            upload_response = requests.post(
                f"{BASE_URL}/api/assignments/{assignment_id}/upload-contract",
                headers={"Authorization": f"Bearer {self.token}"},
                files=files
            )
            assert upload_response.status_code == 200
            contract_id = upload_response.json().get("contract_id")
            print(f"Created contract: {contract_id}")
            
            # Verify contract has assignment_id
            contract_response = requests.get(f"{BASE_URL}/api/contracts/{contract_id}", headers=self.headers)
            contract = contract_response.json()
            assert contract.get("id") == contract_id
            print("Verified contract exists")
            
            # Now unassign the contract
            unassign_response = requests.post(
                f"{BASE_URL}/api/contracts/{contract_id}/unassign",
                headers=self.headers
            )
            assert unassign_response.status_code == 200, f"Unassign failed: {unassign_response.text}"
            print("Unassigned contract successfully")
            
            # Verify assignment now has contract_id = null
            assignments_response = requests.get(f"{BASE_URL}/api/assignments", headers=self.headers)
            assignments = assignments_response.json()
            test_assignment = next((a for a in assignments if a["id"] == assignment_id), None)
            assert test_assignment is not None
            assert test_assignment.get("contract_id") is None, \
                f"Assignment should have contract_id=null after unassign, got: {test_assignment.get('contract_id')}"
            
            # Verify contract still exists but has assignment_id = null
            contracts_response = requests.get(f"{BASE_URL}/api/contracts", headers=self.headers)
            contracts = contracts_response.json()
            test_contract = next((c for c in contracts if c["id"] == contract_id), None)
            assert test_contract is not None, "Contract should still exist after unassign"
            assert test_contract.get("assignment_id") is None, "Contract should have assignment_id=null"
            
            print("PASS: Unassign workflow completed successfully")
            
            # Cleanup: delete contract
            requests.delete(f"{BASE_URL}/api/contracts/{contract_id}", headers=self.headers)
            
        finally:
            # Cleanup
            requests.post(f"{BASE_URL}/api/assignments/{assignment_id}/dissolve", headers=self.headers)
            requests.delete(f"{BASE_URL}/api/ipads/{ipad_id}", headers=self.headers)
            requests.delete(f"{BASE_URL}/api/students/{student_id}", headers=self.headers)
        
        print("--- Unassign Full Workflow Test PASSED ---\n")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
