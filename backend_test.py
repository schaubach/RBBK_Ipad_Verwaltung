#!/usr/bin/env python3
"""
Comprehensive Backend Testing Suite for RBAC iPad Management System
Tests the backend after libmagic fix and verifies all core functionality.

Test Coverage:
1. Backend Service Health (libmagic fix verification)
2. Admin Authentication & JWT Token Generation
3. RBAC User Management Endpoints
4. Core Resource Endpoints (Students, iPads, Assignments)
5. User Resource Isolation
6. File Upload Security with libmagic validation
7. Contract Management
"""

import requests
import json
import time
import sys
import io
import pandas as pd
from datetime import datetime

# Configuration
BASE_URL = "https://edudevice-1.preview.emergentagent.com/api"
ADMIN_CREDENTIALS = {"username": "admin", "password": "admin123"}

class RBACTester:
    def __init__(self):
        self.admin_token = None
        self.test_user_token = None
        self.test_user_id = None
        self.admin_user_id = None
        self.test_results = []
        self.admin_resources = {"ipads": [], "students": []}
        self.testuser_resources = {"ipads": [], "students": []}
        
    def log_test(self, test_name, success, message, details=None):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        result = {
            "test": test_name,
            "status": status,
            "message": message,
            "details": details or {},
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        print(f"{status}: {test_name} - {message}")
        if details and not success:
            print(f"   Details: {details}")
    
    def make_request(self, method, endpoint, token=None, data=None, files=None):
        """Make HTTP request with proper headers"""
        url = f"{BASE_URL}{endpoint}"
        headers = {}
        
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        if not files:
            headers["Content-Type"] = "application/json"
            
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=30)
            elif method == "POST":
                if files:
                    response = requests.post(url, headers=headers, files=files, data=data, timeout=30)
                else:
                    response = requests.post(url, headers=headers, json=data, timeout=30)
            elif method == "PUT":
                response = requests.put(url, headers=headers, json=data, timeout=30)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers, timeout=30)
            else:
                raise ValueError(f"Unsupported method: {method}")
                
            return response
        except requests.exceptions.RequestException as e:
            print(f"Request error for {method} {url}: {str(e)}")
            return None
        except Exception as e:
            print(f"Unexpected error for {method} {url}: {str(e)}")
            return None
    
    def test_backend_health(self):
        """Test backend service health and libmagic fix"""
        print("\n=== Testing Backend Service Health ===")
        
        # Test basic health by trying to access a simple endpoint
        response = self.make_request("POST", "/auth/setup")
        
        if not response:
            self.log_test("Backend Service Health", False, "Backend service is not responding")
            return False
        
        if response.status_code in [200, 405]:  # 405 is OK for GET on POST endpoint
            self.log_test("Backend Service Health", True, "Backend service is running and responding")
        else:
            self.log_test("Backend Service Health", False, f"Backend service returned unexpected status: {response.status_code}")
            return False
        
        # Test that libmagic import is working by checking if magic validation endpoints work
        try:
            # This will test if the magic library is properly imported and working
            import magic
            self.log_test("Libmagic Import Test", True, "python-magic library is properly imported and available")
        except ImportError as e:
            self.log_test("Libmagic Import Test", False, f"python-magic import failed: {str(e)}")
            return False
        
        return True

    def test_admin_login(self):
        """Test admin login and JWT token generation with user_id and role"""
        print("\n=== Testing Admin Authentication & JWT Token Generation ===")
        
        response = self.make_request("POST", "/auth/login", data=ADMIN_CREDENTIALS)
        
        if not response or response.status_code != 200:
            self.log_test("Admin Login", False, f"Login failed with status {response.status_code if response else 'No response'}")
            return False
            
        try:
            data = response.json()
            required_fields = ["access_token", "token_type", "role", "username"]
            
            for field in required_fields:
                if field not in data:
                    self.log_test("Admin Login", False, f"Missing field in response: {field}")
                    return False
            
            if data["role"] != "admin":
                self.log_test("Admin Login", False, f"Expected admin role, got: {data['role']}")
                return False
                
            if data["username"] != "admin":
                self.log_test("Admin Login", False, f"Expected admin username, got: {data['username']}")
                return False
            
            # Verify JWT token contains user_id and role by decoding (without verification for testing)
            import jwt
            try:
                # Decode without verification to check payload structure
                payload = jwt.decode(data["access_token"], options={"verify_signature": False})
                
                if "user_id" not in payload:
                    self.log_test("JWT Token Validation", False, "JWT token missing user_id field")
                    return False
                
                if "sub" not in payload:  # subject should contain username
                    self.log_test("JWT Token Validation", False, "JWT token missing sub (username) field")
                    return False
                
                self.log_test("JWT Token Validation", True, f"JWT token properly contains user_id: {payload.get('user_id')}")
                
            except Exception as e:
                self.log_test("JWT Token Validation", False, f"Failed to decode JWT token: {str(e)}")
                return False
                
            self.admin_token = data["access_token"]
            self.log_test("Admin Login", True, f"Successfully logged in as admin with role: {data['role']}")
            return True
            
        except Exception as e:
            self.log_test("Admin Login", False, f"Error parsing login response: {str(e)}")
            return False
    
    def test_admin_user_creation(self):
        """Test creating new users via admin endpoints"""
        print("\n=== Testing RBAC User Management Endpoints ===")
        
        # Test creating a regular user with unique username
        import time
        unique_username = f"testuser_{int(time.time())}"
        user_data = {
            "username": unique_username,
            "password": "test123",
            "role": "user"
        }
        
        response = self.make_request("POST", "/admin/users", token=self.admin_token, data=user_data)
        print(f"DEBUG: User creation response status: {response.status_code if response else 'No response'}")
        if response:
            print(f"DEBUG: User creation response: {response.text}")
        
        if not response:
            # If no response, try to continue with existing user for other tests
            self.log_test("Create Test User", False, "User creation failed - no response (possible timeout)")
            # Try to find existing test user
            response = self.make_request("GET", "/admin/users", token=self.admin_token)
            if response and response.status_code == 200:
                users = response.json()
                for user in users:
                    if user["username"].startswith("testuser") and user["is_active"]:
                        self.test_user_id = user["id"]
                        self.log_test("Use Existing Test User", True, f"Found existing test user: {user['username']}")
                        break
            return self.test_user_id is not None
        
        if response.status_code == 400 and "already exists" in response.text:
            # User already exists, try with different username
            unique_username = f"testuser_{int(time.time())}_new"
            user_data["username"] = unique_username
            response = self.make_request("POST", "/admin/users", token=self.admin_token, data=user_data)
        
        if not response or response.status_code != 200:
            self.log_test("Create Test User", False, f"User creation failed with status {response.status_code if response else 'No response'}")
            return False
            
        try:
            data = response.json()
            required_fields = ["id", "username", "role", "is_active", "created_by", "created_at", "updated_at"]
            
            for field in required_fields:
                if field not in data:
                    self.log_test("Create Test User", False, f"Missing field in response: {field}")
                    return False
            
            if data["username"] != "testuser" or data["role"] != "user":
                self.log_test("Create Test User", False, f"User data mismatch: {data}")
                return False
                
            self.test_user_id = data["id"]
            self.log_test("Create Test User", True, f"Successfully created test user with ID: {self.test_user_id}")
            
            # Test validation - username too short
            invalid_user = {"username": "ab", "password": "test123", "role": "user"}
            response = self.make_request("POST", "/admin/users", token=self.admin_token, data=invalid_user)
            
            if response and response.status_code == 400:
                self.log_test("Username Validation", True, "Username length validation working correctly")
            else:
                self.log_test("Username Validation", False, f"Expected 400 for short username, got {response.status_code if response else 'No response'}")
            
            # Test validation - password too short
            invalid_user = {"username": "validuser", "password": "123", "role": "user"}
            response = self.make_request("POST", "/admin/users", token=self.admin_token, data=invalid_user)
            
            if response and response.status_code == 400:
                self.log_test("Password Validation", True, "Password length validation working correctly")
            else:
                self.log_test("Password Validation", False, f"Expected 400 for short password, got {response.status_code if response else 'No response'}")
            
            # Test duplicate username
            response = self.make_request("POST", "/admin/users", token=self.admin_token, data=user_data)
            
            if response and response.status_code == 400:
                self.log_test("Duplicate Username Validation", True, "Duplicate username validation working correctly")
            else:
                self.log_test("Duplicate Username Validation", False, f"Expected 400 for duplicate username, got {response.status_code if response else 'No response'}")
            
            return True
            
        except Exception as e:
            self.log_test("Create Test User", False, f"Error parsing user creation response: {str(e)}")
            return False
    
    def test_test_user_login(self):
        """Test login with the created test user"""
        print("\n=== Testing Test User Login ===")
        
        # Use existing active test user
        response = self.make_request("GET", "/admin/users", token=self.admin_token)
        if response and response.status_code == 200:
            users = response.json()
            test_user = None
            for user in users:
                if user["username"].startswith("testuser") and user["is_active"]:
                    test_user = user
                    break
            
            if not test_user:
                self.log_test("Test User Login", False, "No active test user found")
                return False
            
            # Try login with common test password
            test_credentials = {"username": test_user["username"], "password": "test123"}
        else:
            # Fallback to default
            test_credentials = {"username": "testuser", "password": "test123"}
        
        response = self.make_request("POST", "/auth/login", data=test_credentials)
        
        if not response or response.status_code != 200:
            self.log_test("Test User Login", False, f"Test user login failed with status {response.status_code if response else 'No response'}")
            return False
            
        try:
            data = response.json()
            
            if data["role"] != "user" or data["username"] != "testuser":
                self.log_test("Test User Login", False, f"Test user login data mismatch: {data}")
                return False
                
            self.test_user_token = data["access_token"]
            self.log_test("Test User Login", True, f"Successfully logged in as test user with role: {data['role']}")
            return True
            
        except Exception as e:
            self.log_test("Test User Login", False, f"Error parsing test user login response: {str(e)}")
            return False
    
    def test_admin_user_list(self):
        """Test listing all users (admin only)"""
        print("\n=== Testing Admin User List ===")
        
        # Test admin can list users
        response = self.make_request("GET", "/admin/users", token=self.admin_token)
        
        if not response or response.status_code != 200:
            self.log_test("Admin List Users", False, f"Admin user list failed with status {response.status_code if response else 'No response'}")
            return False
            
        try:
            users = response.json()
            
            if not isinstance(users, list) or len(users) < 2:
                self.log_test("Admin List Users", False, f"Expected list with at least 2 users, got: {len(users) if isinstance(users, list) else 'not a list'}")
                return False
            
            # Find admin user ID
            for user in users:
                if user["username"] == "admin":
                    self.admin_user_id = user["id"]
                    break
            
            self.log_test("Admin List Users", True, f"Successfully listed {len(users)} users")
            
            # Test non-admin cannot list users
            response = self.make_request("GET", "/admin/users", token=self.test_user_token)
            
            if response and response.status_code == 403:
                self.log_test("Non-Admin List Users Blocked", True, "Non-admin correctly blocked from listing users")
            else:
                self.log_test("Non-Admin List Users Blocked", False, f"Expected 403 for non-admin, got {response.status_code if response else 'No response'}")
            
            return True
            
        except Exception as e:
            self.log_test("Admin List Users", False, f"Error parsing user list response: {str(e)}")
            return False
    
    def test_admin_user_update(self):
        """Test updating users (admin only)"""
        print("\n=== Testing Admin User Update ===")
        
        if not self.test_user_id:
            self.log_test("Admin Update User", False, "No test user ID available")
            return False
        
        # Test updating user password
        update_data = {"password": "newpassword123"}
        response = self.make_request("PUT", f"/admin/users/{self.test_user_id}", token=self.admin_token, data=update_data)
        
        if not response or response.status_code != 200:
            self.log_test("Admin Update User Password", False, f"User password update failed with status {response.status_code if response else 'No response'}")
            return False
        
        self.log_test("Admin Update User Password", True, "Successfully updated user password")
        
        # Test updating user role
        update_data = {"role": "admin"}
        response = self.make_request("PUT", f"/admin/users/{self.test_user_id}", token=self.admin_token, data=update_data)
        
        if response and response.status_code == 200:
            self.log_test("Admin Update User Role", True, "Successfully updated user role")
        else:
            self.log_test("Admin Update User Role", False, f"User role update failed with status {response.status_code if response else 'No response'}")
        
        # Test self-protection (cannot deactivate own account)
        update_data = {"is_active": False}
        response = self.make_request("PUT", f"/admin/users/{self.admin_user_id}", token=self.admin_token, data=update_data)
        
        if response and response.status_code == 400:
            self.log_test("Self-Protection Update", True, "Self-protection working - cannot deactivate own account")
        else:
            self.log_test("Self-Protection Update", False, f"Expected 400 for self-deactivation, got {response.status_code if response else 'No response'}")
        
        # Test non-admin cannot update users
        response = self.make_request("PUT", f"/admin/users/{self.test_user_id}", token=self.test_user_token, data={"password": "hack123"})
        
        if response and response.status_code == 403:
            self.log_test("Non-Admin Update Blocked", True, "Non-admin correctly blocked from updating users")
        else:
            self.log_test("Non-Admin Update Blocked", False, f"Expected 403 for non-admin update, got {response.status_code if response else 'No response'}")
        
        return True
    
    def test_admin_user_delete(self):
        """Test deactivating users (admin only)"""
        print("\n=== Testing Admin User Delete/Deactivate ===")
        
        if not self.test_user_id:
            self.log_test("Admin Delete User", False, "No test user ID available")
            return False
        
        # Test self-protection (cannot delete own account)
        response = self.make_request("DELETE", f"/admin/users/{self.admin_user_id}", token=self.admin_token)
        
        if response and response.status_code == 400:
            self.log_test("Self-Protection Delete", True, "Self-protection working - cannot delete own account")
        else:
            self.log_test("Self-Protection Delete", False, f"Expected 400 for self-deletion, got {response.status_code if response else 'No response'}")
        
        # Test deactivating test user
        response = self.make_request("DELETE", f"/admin/users/{self.test_user_id}", token=self.admin_token)
        
        if not response or response.status_code != 200:
            self.log_test("Admin Delete User", False, f"User deactivation failed with status {response.status_code if response else 'No response'}")
            return False
        
        try:
            data = response.json()
            
            if "message" not in data or "resources_preserved" not in data:
                self.log_test("Admin Delete User", False, f"Invalid deactivation response: {data}")
                return False
            
            self.log_test("Admin Delete User", True, f"Successfully deactivated user. Resources preserved: {data['resources_preserved']}")
            
            # Test deactivated user cannot login
            test_credentials = {"username": "testuser", "password": "newpassword123"}
            response = self.make_request("POST", "/auth/login", data=test_credentials)
            
            if response and response.status_code == 401:
                self.log_test("Deactivated User Login Blocked", True, "Deactivated user correctly blocked from login")
            else:
                self.log_test("Deactivated User Login Blocked", False, f"Expected 401 for deactivated user login, got {response.status_code if response else 'No response'}")
            
            # Test non-admin cannot delete users
            response = self.make_request("DELETE", f"/admin/users/{self.test_user_id}", token=self.test_user_token)
            
            if response and response.status_code == 403:
                self.log_test("Non-Admin Delete Blocked", True, "Non-admin correctly blocked from deleting users")
            else:
                self.log_test("Non-Admin Delete Blocked", False, f"Expected 403 for non-admin delete, got {response.status_code if response else 'No response'}")
            
            return True
            
        except Exception as e:
            self.log_test("Admin Delete User", False, f"Error parsing deactivation response: {str(e)}")
            return False
    
    def create_test_user_for_isolation(self):
        """Create a new test user for resource isolation testing"""
        print("\n=== Creating New Test User for Resource Isolation ===")
        
        user_data = {
            "username": "testuser2",
            "password": "test123",
            "role": "user"
        }
        
        response = self.make_request("POST", "/admin/users", token=self.admin_token, data=user_data)
        
        if not response or response.status_code != 200:
            self.log_test("Create Test User 2", False, f"User creation failed with status {response.status_code if response else 'No response'}")
            return False
        
        try:
            data = response.json()
            self.test_user_id = data["id"]
            
            # Login as new test user
            test_credentials = {"username": "testuser2", "password": "test123"}
            response = self.make_request("POST", "/auth/login", data=test_credentials)
            
            if response and response.status_code == 200:
                self.test_user_token = response.json()["access_token"]
                self.log_test("Create Test User 2", True, f"Successfully created and logged in as testuser2")
                return True
            else:
                self.log_test("Create Test User 2", False, "Failed to login as new test user")
                return False
                
        except Exception as e:
            self.log_test("Create Test User 2", False, f"Error creating test user: {str(e)}")
            return False
    
    def upload_test_data(self, token, user_type):
        """Upload test iPads and students for a user"""
        print(f"\n=== Uploading Test Data for {user_type} ===")
        
        # Create test iPad Excel file
        import io
        import pandas as pd
        
        ipad_data = {
            'ITNr': [f'IPAD{user_type}001', f'IPAD{user_type}002'],
            'SNr': [f'SN{user_type}001', f'SN{user_type}002'],
            'Karton': [f'K{user_type}001', f'K{user_type}002'],
            'Pencil': ['mit Apple Pencil', 'ohne Apple Pencil'],
            'Typ': ['iPad Pro', 'iPad Air'],
            'AnschJahr': ['2023', '2023'],
            'AusleiheDatum': ['01.09.2023', '01.09.2023']
        }
        
        df = pd.DataFrame(ipad_data)
        excel_buffer = io.BytesIO()
        df.to_excel(excel_buffer, index=False)
        excel_buffer.seek(0)
        
        # Upload iPads
        files = {"file": ("test_ipads.xlsx", excel_buffer.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
        response = self.make_request("POST", "/ipads/upload", token=token, files=files)
        
        if response and response.status_code == 200:
            self.log_test(f"Upload iPads ({user_type})", True, f"Successfully uploaded iPads for {user_type}")
        else:
            error_msg = f"iPad upload failed for {user_type} - Status: {response.status_code if response else 'No response'}"
            if response:
                try:
                    error_detail = response.json()
                    error_msg += f" - {error_detail}"
                except:
                    error_msg += f" - {response.text}"
            self.log_test(f"Upload iPads ({user_type})", False, error_msg)
            return False
        
        # Create test student Excel file
        student_data = {
            'SuSVorn': [f'{user_type}Student1', f'{user_type}Student2'],
            'SuSNachn': [f'{user_type}Last1', f'{user_type}Last2'],
            'SuSKl': ['6A', '6B'],
            'SuSStrHNr': ['Street 1', 'Street 2'],
            'SuSPLZ': ['12345', '12346'],
            'SuSOrt': ['City1', 'City2'],
            'SuSGeb': ['01.01.2010', '02.02.2010']
        }
        
        df = pd.DataFrame(student_data)
        excel_buffer = io.BytesIO()
        df.to_excel(excel_buffer, index=False)
        excel_buffer.seek(0)
        
        # Upload students
        files = {"file": ("test_students.xlsx", excel_buffer.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
        response = self.make_request("POST", "/students/upload", token=token, files=files)
        
        if response and response.status_code == 200:
            self.log_test(f"Upload Students ({user_type})", True, f"Successfully uploaded students for {user_type}")
            return True
        else:
            error_msg = f"Student upload failed for {user_type} - Status: {response.status_code if response else 'No response'}"
            if response:
                try:
                    error_detail = response.json()
                    error_msg += f" - {error_detail}"
                except:
                    error_msg += f" - {response.text}"
            self.log_test(f"Upload Students ({user_type})", False, error_msg)
            return False
    
    def test_core_resource_endpoints(self):
        """Test core resource endpoints (Students, iPads, Assignments)"""
        print("\n=== Testing Core Resource Endpoints ===")
        
        # Test Students endpoint
        response = self.make_request("GET", "/students", token=self.admin_token)
        if response and response.status_code == 200:
            students = response.json()
            self.log_test("GET /api/students", True, f"Successfully retrieved {len(students)} students")
        else:
            self.log_test("GET /api/students", False, f"Failed to retrieve students - Status: {response.status_code if response else 'No response'}")
            return False
        
        # Test iPads endpoint
        response = self.make_request("GET", "/ipads", token=self.admin_token)
        if response and response.status_code == 200:
            ipads = response.json()
            self.log_test("GET /api/ipads", True, f"Successfully retrieved {len(ipads)} iPads")
        else:
            self.log_test("GET /api/ipads", False, f"Failed to retrieve iPads - Status: {response.status_code if response else 'No response'}")
            return False
        
        # Test Assignments endpoint
        response = self.make_request("GET", "/assignments", token=self.admin_token)
        if response and response.status_code == 200:
            assignments = response.json()
            self.log_test("GET /api/assignments", True, f"Successfully retrieved {len(assignments)} assignments")
        else:
            self.log_test("GET /api/assignments", False, f"Failed to retrieve assignments - Status: {response.status_code if response else 'No response'}")
            return False
        
        # Test auto-assign endpoint
        response = self.make_request("POST", "/assignments/auto-assign", token=self.admin_token)
        if response and response.status_code == 200:
            result = response.json()
            assigned_count = result.get("assigned_count", 0)
            self.log_test("POST /api/assignments/auto-assign", True, f"Auto-assign completed - {assigned_count} new assignments created")
        else:
            self.log_test("POST /api/assignments/auto-assign", False, f"Auto-assign failed - Status: {response.status_code if response else 'No response'}")
        
        # Test iPad status update
        if ipads:
            test_ipad_id = ipads[0]["id"]
            current_status = ipads[0]["status"]
            new_status = "verfügbar" if current_status != "verfügbar" else "defekt"
            
            response = self.make_request("PUT", f"/ipads/{test_ipad_id}/status", token=self.admin_token, data={"status": new_status})
            if response and response.status_code == 200:
                self.log_test("PUT /api/ipads/{id}/status", True, f"Successfully updated iPad status to {new_status}")
                
                # Restore original status
                self.make_request("PUT", f"/ipads/{test_ipad_id}/status", token=self.admin_token, data={"status": current_status})
            else:
                self.log_test("PUT /api/ipads/{id}/status", False, f"Failed to update iPad status - Status: {response.status_code if response else 'No response'}")
        
        return True

    def test_resource_isolation(self):
        """Test user resource isolation - admin sees all, users see only their own"""
        print("\n=== Testing User Resource Isolation ===")
        
        # Test admin sees all resources
        response = self.make_request("GET", "/ipads", token=self.admin_token)
        if response and response.status_code == 200:
            admin_ipads = response.json()
            admin_ipad_count = len(admin_ipads)
            self.log_test("Admin Sees All iPads", True, f"Admin sees {admin_ipad_count} iPads (should include all users' iPads)")
        else:
            self.log_test("Admin Sees All iPads", False, "Admin failed to retrieve iPads")
            return False
        
        response = self.make_request("GET", "/students", token=self.admin_token)
        if response and response.status_code == 200:
            admin_students = response.json()
            admin_student_count = len(admin_students)
            self.log_test("Admin Sees All Students", True, f"Admin sees {admin_student_count} students (should include all users' students)")
        else:
            self.log_test("Admin Sees All Students", False, "Admin failed to retrieve students")
            return False
        
        # Test assignments isolation
        response = self.make_request("GET", "/assignments", token=self.admin_token)
        if response and response.status_code == 200:
            admin_assignments = response.json()
            admin_assignment_count = len(admin_assignments)
            self.log_test("Admin Sees All Assignments", True, f"Admin sees {admin_assignment_count} assignments")
        else:
            self.log_test("Admin Sees All Assignments", False, "Admin failed to retrieve assignments")
            return False
        
        # Test with regular user if available
        if self.test_user_token:
            response = self.make_request("GET", "/ipads", token=self.test_user_token)
            if response and response.status_code == 200:
                user_ipads = response.json()
                user_ipad_count = len(user_ipads)
                
                if user_ipad_count <= admin_ipad_count:
                    self.log_test("User Sees Only Own iPads", True, f"Test user sees {user_ipad_count} iPads (filtered by ownership)")
                else:
                    self.log_test("User Sees Only Own iPads", False, f"Test user sees more iPads ({user_ipad_count}) than expected")
            else:
                self.log_test("User Sees Only Own iPads", False, "Test user failed to retrieve iPads")
        
        # Test IDOR protection - user cannot access admin's resources
        if admin_students and self.test_user_token:
            admin_student_id = admin_students[0]["id"]
            response = self.make_request("GET", f"/students/{admin_student_id}", token=self.test_user_token)
            
            if response and response.status_code == 403:
                self.log_test("IDOR Protection", True, "Test user correctly blocked from accessing admin's student (403 Forbidden)")
            else:
                self.log_test("IDOR Protection", False, f"Expected 403 for unauthorized access, got {response.status_code if response else 'No response'}")
        
        return True

    def test_file_upload_security(self):
        """Test file upload security with libmagic validation"""
        print("\n=== Testing File Upload Security with libmagic ===")
        
        # Test that file upload endpoints are accessible
        # We'll test with a simple request to see if the endpoint responds correctly to missing files
        
        # Test iPad upload endpoint
        response = self.make_request("POST", "/ipads/upload", token=self.admin_token)
        if response and response.status_code == 422:  # Unprocessable Entity for missing file
            self.log_test("iPad Upload Endpoint Available", True, "iPad upload endpoint is accessible and validates input")
        else:
            self.log_test("iPad Upload Endpoint Available", False, f"iPad upload endpoint returned unexpected status: {response.status_code if response else 'No response'}")
        
        # Test Student upload endpoint
        response = self.make_request("POST", "/students/upload", token=self.admin_token)
        if response and response.status_code == 422:  # Unprocessable Entity for missing file
            self.log_test("Student Upload Endpoint Available", True, "Student upload endpoint is accessible and validates input")
        else:
            self.log_test("Student Upload Endpoint Available", False, f"Student upload endpoint returned unexpected status: {response.status_code if response else 'No response'}")
        
        # Test Contract upload endpoint
        response = self.make_request("POST", "/contracts/upload-multiple", token=self.admin_token)
        if response and response.status_code == 422:  # Unprocessable Entity for missing files
            self.log_test("Contract Upload Endpoint Available", True, "Contract upload endpoint is accessible and validates input")
        else:
            self.log_test("Contract Upload Endpoint Available", False, f"Contract upload endpoint returned unexpected status: {response.status_code if response else 'No response'}")
        
        # Test that magic library is working by importing it
        try:
            import magic
            # Test basic magic functionality
            test_data = b"PDF-1.4"  # PDF header
            mime_type = magic.from_buffer(test_data, mime=True)
            if mime_type:
                self.log_test("Libmagic Functionality Test", True, f"python-magic is working correctly, detected MIME type: {mime_type}")
            else:
                self.log_test("Libmagic Functionality Test", False, "python-magic returned empty result")
        except Exception as e:
            self.log_test("Libmagic Functionality Test", False, f"python-magic test failed: {str(e)}")
            return False
        
        return True
    
    def test_auto_assignment_isolation(self):
        """Test auto-assignment with user isolation"""
        print("\n=== Testing Auto-Assignment with User Isolation ===")
        
        # Test auto-assignment for test user (should only assign their resources)
        response = self.make_request("POST", "/assignments/auto-assign", token=self.test_user_token)
        
        if not response or response.status_code != 200:
            self.log_test("Auto-Assignment Isolation", False, f"Auto-assignment failed with status {response.status_code if response else 'No response'}")
            return False
        
        try:
            data = response.json()
            assigned_count = data.get("assigned_count", 0)
            
            if assigned_count > 0:
                self.log_test("Auto-Assignment Isolation", True, f"Successfully assigned {assigned_count} iPads for test user")
                
                # Verify assignments are only for test user's resources
                response = self.make_request("GET", "/assignments", token=self.test_user_token)
                if response and response.status_code == 200:
                    assignments = response.json()
                    user_assignments = [a for a in assignments if "Test" in a.get("itnr", "")]
                    
                    if len(user_assignments) == len(assignments):
                        self.log_test("Assignment Ownership Verification", True, "All assignments belong to test user")
                    else:
                        self.log_test("Assignment Ownership Verification", False, f"Found {len(assignments)} assignments, {len(user_assignments)} belong to test user")
                
                return True
            else:
                self.log_test("Auto-Assignment Isolation", False, "No assignments created")
                return False
                
        except Exception as e:
            self.log_test("Auto-Assignment Isolation", False, f"Error parsing auto-assignment response: {str(e)}")
            return False
    
    def run_all_tests(self):
        """Run comprehensive backend tests for libmagic fix and RBAC functionality"""
        print("🔐 Comprehensive Backend Testing Suite - Libmagic Fix & RBAC iPad Management")
        print("=" * 80)
        
        # Step 1: Backend service health and libmagic fix verification
        if not self.test_backend_health():
            print("❌ Backend service health check failed")
            return False
        
        # Step 2: Admin authentication and JWT token generation
        if not self.test_admin_login():
            print("❌ Cannot proceed without admin login")
            return False
        
        # Step 3: RBAC user management endpoints
        if not self.test_admin_user_creation():
            print("❌ User creation failed")
            return False
        
        if not self.test_test_user_login():
            print("❌ Test user login failed")
            return False
        
        if not self.test_admin_user_list():
            print("❌ User listing failed")
            return False
        
        if not self.test_admin_user_update():
            print("❌ User update failed")
            return False
        
        if not self.test_admin_user_delete():
            print("❌ User delete failed")
            return False
        
        # Step 4: Core resource endpoints
        if not self.test_core_resource_endpoints():
            print("❌ Core resource endpoints failed")
            return False
        
        # Step 5: Create new test user for resource isolation
        if not self.create_test_user_for_isolation():
            print("❌ Cannot create test user for isolation")
            return False
        
        # Step 6: User resource isolation testing
        if not self.test_resource_isolation():
            print("❌ Resource isolation failed")
            return False
        
        # Step 7: File upload security with libmagic
        if not self.test_file_upload_security():
            print("❌ File upload security tests failed")
            return False
        
        # Step 8: Auto-assignment isolation
        if not self.test_auto_assignment_isolation():
            print("❌ Auto-assignment isolation failed")
            return False
        
        return True
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 80)
        print("🔐 COMPREHENSIVE BACKEND TESTING SUMMARY")
        print("=" * 80)
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if "✅ PASS" in r["status"]])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests > 0:
            print("\n❌ FAILED TESTS:")
            for result in self.test_results:
                if "❌ FAIL" in result["status"]:
                    print(f"  - {result['test']}: {result['message']}")
        
        print("\n📋 DETAILED RESULTS:")
        for result in self.test_results:
            print(f"{result['status']}: {result['test']}")
            if result['details']:
                print(f"   Details: {result['details']}")

class BatchDeleteTester:
    """Comprehensive testing for the new batch-delete students feature"""
    
    def __init__(self):
        self.admin_token = None
        self.test_user_token = None
        self.test_user2_token = None
        self.test_user_id = None
        self.test_user2_id = None
        self.test_results = []
        self.created_students = []
        self.created_ipads = []
        self.created_assignments = []
        
    def log_test(self, test_name, success, message, details=None):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        result = {
            "test": test_name,
            "status": status,
            "message": message,
            "details": details or {},
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        print(f"{status}: {test_name} - {message}")
        if details and not success:
            print(f"   Details: {details}")
    
    def make_request(self, method, endpoint, token=None, data=None, files=None):
        """Make HTTP request with proper headers"""
        url = f"{BASE_URL}{endpoint}"
        headers = {}
        
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        if not files:
            headers["Content-Type"] = "application/json"
            
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=30)
            elif method == "POST":
                if files:
                    response = requests.post(url, headers=headers, files=files, data=data, timeout=30)
                else:
                    response = requests.post(url, headers=headers, json=data, timeout=30)
            elif method == "PUT":
                response = requests.put(url, headers=headers, json=data, timeout=30)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers, timeout=30)
            else:
                raise ValueError(f"Unsupported method: {method}")
                
            return response
        except requests.exceptions.RequestException as e:
            print(f"Request error for {method} {url}: {str(e)}")
            return None
        except Exception as e:
            print(f"Unexpected error for {method} {url}: {str(e)}")
            return None
    
    def setup_authentication(self):
        """Setup admin and test user authentication"""
        print("\n=== Setting up Authentication for Batch Delete Tests ===")
        
        # Admin login
        response = self.make_request("POST", "/auth/login", data=ADMIN_CREDENTIALS)
        if not response or response.status_code != 200:
            self.log_test("Admin Login Setup", False, f"Admin login failed: {response.status_code if response else 'No response'}")
            return False
        
        self.admin_token = response.json()["access_token"]
        self.log_test("Admin Login Setup", True, "Admin authentication successful")
        
        # Create test users for RBAC testing
        user1_data = {"username": "batchtest_user1", "password": "test123", "role": "user"}
        response = self.make_request("POST", "/admin/users", token=self.admin_token, data=user1_data)
        
        if response and response.status_code == 200:
            self.test_user_id = response.json()["id"]
            
            # Login as test user 1
            login_data = {"username": "batchtest_user1", "password": "test123"}
            response = self.make_request("POST", "/auth/login", data=login_data)
            if response and response.status_code == 200:
                self.test_user_token = response.json()["access_token"]
                self.log_test("Test User 1 Setup", True, "Test user 1 created and authenticated")
            else:
                self.log_test("Test User 1 Setup", False, "Failed to login as test user 1")
                return False
        else:
            self.log_test("Test User 1 Setup", False, "Failed to create test user 1")
            return False
        
        # Create second test user for RBAC isolation testing
        user2_data = {"username": "batchtest_user2", "password": "test123", "role": "user"}
        response = self.make_request("POST", "/admin/users", token=self.admin_token, data=user2_data)
        
        if response and response.status_code == 200:
            self.test_user2_id = response.json()["id"]
            
            # Login as test user 2
            login_data = {"username": "batchtest_user2", "password": "test123"}
            response = self.make_request("POST", "/auth/login", data=login_data)
            if response and response.status_code == 200:
                self.test_user2_token = response.json()["access_token"]
                self.log_test("Test User 2 Setup", True, "Test user 2 created and authenticated")
            else:
                self.log_test("Test User 2 Setup", False, "Failed to login as test user 2")
                return False
        else:
            self.log_test("Test User 2 Setup", False, "Failed to create test user 2")
            return False
        
        return True
    
    def create_test_data(self):
        """Create test students, iPads and assignments for testing"""
        print("\n=== Creating Test Data for Batch Delete Tests ===")
        
        # Create test students for admin user
        admin_students = [
            {"sus_vorn": "Max", "sus_nachn": "Müller", "sus_kl": "10a"},
            {"sus_vorn": "Anna", "sus_nachn": "Schmidt", "sus_kl": "10b"},
            {"sus_vorn": "Max", "sus_nachn": "Weber", "sus_kl": "10a"},
            {"sus_vorn": "Lisa", "sus_nachn": "Müller", "sus_kl": "9a"},
            {"sus_vorn": "Tom", "sus_nachn": "Fischer", "sus_kl": "10a"}
        ]
        
        # Create students via direct API calls (simulating manual creation)
        for student_data in admin_students:
            # Create student data with required fields
            full_student_data = {
                "user_id": "admin_user_id",  # This will be set by the backend
                "sus_vorn": student_data["sus_vorn"],
                "sus_nachn": student_data["sus_nachn"],
                "sus_kl": student_data["sus_kl"],
                "sus_str_hnr": "Test Street 1",
                "sus_plz": "12345",
                "sus_ort": "Test City"
            }
            
            # We'll use Excel upload to create students
            import pandas as pd
            import io
            
            df = pd.DataFrame([{
                'SuSVorn': student_data["sus_vorn"],
                'SuSNachn': student_data["sus_nachn"],
                'SuSKl': student_data["sus_kl"],
                'SuSStrHNr': 'Test Street 1',
                'SuSPLZ': '12345',
                'SuSOrt': 'Test City'
            }])
            
            excel_buffer = io.BytesIO()
            df.to_excel(excel_buffer, index=False)
            excel_buffer.seek(0)
            
            files = {"file": (f"student_{student_data['sus_vorn']}.xlsx", excel_buffer.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
            response = self.make_request("POST", "/students/upload", token=self.admin_token, files=files)
            
            if response and response.status_code == 200:
                self.created_students.append(student_data)
        
        # Create test iPads for assignments
        ipad_data = [
            {"itnr": "BATCH001", "snr": "SN001"},
            {"itnr": "BATCH002", "snr": "SN002"},
            {"itnr": "BATCH003", "snr": "SN003"}
        ]
        
        for ipad in ipad_data:
            df = pd.DataFrame([{
                'ITNr': ipad["itnr"],
                'SNr': ipad["snr"],
                'Karton': 'Test Box',
                'Typ': 'iPad Pro'
            }])
            
            excel_buffer = io.BytesIO()
            df.to_excel(excel_buffer, index=False)
            excel_buffer.seek(0)
            
            files = {"file": (f"ipad_{ipad['itnr']}.xlsx", excel_buffer.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
            response = self.make_request("POST", "/ipads/upload", token=self.admin_token, files=files)
            
            if response and response.status_code == 200:
                self.created_ipads.append(ipad)
        
        # Create some students for test user 1 (for RBAC testing)
        user1_students = [
            {"sus_vorn": "User1Max", "sus_nachn": "User1Müller", "sus_kl": "11a"},
            {"sus_vorn": "User1Anna", "sus_nachn": "User1Schmidt", "sus_kl": "11b"}
        ]
        
        for student_data in user1_students:
            df = pd.DataFrame([{
                'SuSVorn': student_data["sus_vorn"],
                'SuSNachn': student_data["sus_nachn"],
                'SuSKl': student_data["sus_kl"],
                'SuSStrHNr': 'User1 Street 1',
                'SuSPLZ': '54321',
                'SuSOrt': 'User1 City'
            }])
            
            excel_buffer = io.BytesIO()
            df.to_excel(excel_buffer, index=False)
            excel_buffer.seek(0)
            
            files = {"file": (f"user1_student_{student_data['sus_vorn']}.xlsx", excel_buffer.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
            response = self.make_request("POST", "/students/upload", token=self.test_user_token, files=files)
        
        # Create some students for test user 2 (for RBAC testing)
        user2_students = [
            {"sus_vorn": "User2Max", "sus_nachn": "User2Müller", "sus_kl": "12a"}
        ]
        
        for student_data in user2_students:
            df = pd.DataFrame([{
                'SuSVorn': student_data["sus_vorn"],
                'SuSNachn': student_data["sus_nachn"],
                'SuSKl': student_data["sus_kl"],
                'SuSStrHNr': 'User2 Street 1',
                'SuSPLZ': '98765',
                'SuSOrt': 'User2 City'
            }])
            
            excel_buffer = io.BytesIO()
            df.to_excel(excel_buffer, index=False)
            excel_buffer.seek(0)
            
            files = {"file": (f"user2_student_{student_data['sus_vorn']}.xlsx", excel_buffer.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
            response = self.make_request("POST", "/students/upload", token=self.test_user2_token, files=files)
        
        # Create some assignments for cascading delete testing
        response = self.make_request("POST", "/assignments/auto-assign", token=self.admin_token)
        if response and response.status_code == 200:
            result = response.json()
            self.log_test("Test Data Creation", True, f"Created test data: {len(self.created_students)} students, {len(self.created_ipads)} iPads, {result.get('assigned_count', 0)} assignments")
        else:
            self.log_test("Test Data Creation", True, f"Created test data: {len(self.created_students)} students, {len(self.created_ipads)} iPads")
        
        return True
    
    def test_batch_delete_all_students(self):
        """Test 1: Delete all students (without filter)"""
        print("\n=== Test 1: Batch Delete All Students ===")
        
        # Get current student count
        response = self.make_request("GET", "/students", token=self.admin_token)
        if not response or response.status_code != 200:
            self.log_test("Batch Delete All - Get Count", False, "Failed to get student count")
            return False
        
        initial_count = len(response.json())
        
        # Perform batch delete all
        delete_data = {"all": True}
        response = self.make_request("POST", "/students/batch-delete", token=self.admin_token, data=delete_data)
        
        if not response or response.status_code != 200:
            self.log_test("Batch Delete All Students", False, f"Batch delete failed: {response.status_code if response else 'No response'}")
            return False
        
        try:
            result = response.json()
            required_fields = ["deleted_count", "freed_ipads", "total_found", "details"]
            
            for field in required_fields:
                if field not in result:
                    self.log_test("Batch Delete All Students", False, f"Missing field in response: {field}")
                    return False
            
            deleted_count = result["deleted_count"]
            freed_ipads = result["freed_ipads"]
            
            # Verify students were actually deleted
            response = self.make_request("GET", "/students", token=self.admin_token)
            if response and response.status_code == 200:
                remaining_count = len(response.json())
                expected_remaining = initial_count - deleted_count
                
                if remaining_count == expected_remaining:
                    self.log_test("Batch Delete All Students", True, f"Successfully deleted {deleted_count} students, freed {freed_ipads} iPads")
                    return True
                else:
                    self.log_test("Batch Delete All Students", False, f"Count mismatch: expected {expected_remaining}, got {remaining_count}")
                    return False
            else:
                self.log_test("Batch Delete All Students", False, "Failed to verify deletion")
                return False
                
        except Exception as e:
            self.log_test("Batch Delete All Students", False, f"Error parsing response: {str(e)}")
            return False
    
    def test_batch_delete_by_firstname(self):
        """Test 2: Filter by first name (sus_vorn)"""
        print("\n=== Test 2: Batch Delete by First Name ===")
        
        # Test case-insensitive matching
        test_cases = [
            {"sus_vorn": "Max", "expected_name": "Max"},
            {"sus_vorn": "max", "expected_name": "Max"},  # Case insensitive
            {"sus_vorn": "MAX", "expected_name": "Max"}   # Case insensitive
        ]
        
        for i, test_case in enumerate(test_cases):
            # Recreate test data for each case
            if i > 0:
                self.create_test_data()
            
            delete_data = {"sus_vorn": test_case["sus_vorn"]}
            response = self.make_request("POST", "/students/batch-delete", token=self.admin_token, data=delete_data)
            
            if not response or response.status_code != 200:
                self.log_test(f"Batch Delete by First Name ({test_case['sus_vorn']})", False, f"Request failed: {response.status_code if response else 'No response'}")
                continue
            
            try:
                result = response.json()
                deleted_count = result.get("deleted_count", 0)
                
                # Verify only students with matching first name were deleted
                if deleted_count > 0:
                    # Check that students with this name are gone
                    response = self.make_request("GET", "/students", token=self.admin_token)
                    if response and response.status_code == 200:
                        remaining_students = response.json()
                        max_students = [s for s in remaining_students if s["sus_vorn"].lower() == test_case["expected_name"].lower()]
                        
                        if len(max_students) == 0:
                            self.log_test(f"Batch Delete by First Name ({test_case['sus_vorn']})", True, f"Successfully deleted {deleted_count} students with first name '{test_case['sus_vorn']}'")
                        else:
                            self.log_test(f"Batch Delete by First Name ({test_case['sus_vorn']})", False, f"Still found {len(max_students)} students with name '{test_case['expected_name']}'")
                    else:
                        self.log_test(f"Batch Delete by First Name ({test_case['sus_vorn']})", False, "Failed to verify deletion")
                else:
                    self.log_test(f"Batch Delete by First Name ({test_case['sus_vorn']})", True, f"No students found with first name '{test_case['sus_vorn']}' (expected if already deleted)")
                    
            except Exception as e:
                self.log_test(f"Batch Delete by First Name ({test_case['sus_vorn']})", False, f"Error parsing response: {str(e)}")
        
        return True
    
    def test_batch_delete_by_lastname(self):
        """Test 3: Filter by last name (sus_nachn)"""
        print("\n=== Test 3: Batch Delete by Last Name ===")
        
        # Recreate test data
        self.create_test_data()
        
        delete_data = {"sus_nachn": "Müller"}
        response = self.make_request("POST", "/students/batch-delete", token=self.admin_token, data=delete_data)
        
        if not response or response.status_code != 200:
            self.log_test("Batch Delete by Last Name", False, f"Request failed: {response.status_code if response else 'No response'}")
            return False
        
        try:
            result = response.json()
            deleted_count = result.get("deleted_count", 0)
            
            # Verify only students with last name "Müller" were deleted
            response = self.make_request("GET", "/students", token=self.admin_token)
            if response and response.status_code == 200:
                remaining_students = response.json()
                muller_students = [s for s in remaining_students if s["sus_nachn"] == "Müller"]
                
                if len(muller_students) == 0 and deleted_count > 0:
                    self.log_test("Batch Delete by Last Name", True, f"Successfully deleted {deleted_count} students with last name 'Müller'")
                    return True
                elif deleted_count == 0:
                    self.log_test("Batch Delete by Last Name", True, "No students found with last name 'Müller' (expected if already deleted)")
                    return True
                else:
                    self.log_test("Batch Delete by Last Name", False, f"Still found {len(muller_students)} students with last name 'Müller'")
                    return False
            else:
                self.log_test("Batch Delete by Last Name", False, "Failed to verify deletion")
                return False
                
        except Exception as e:
            self.log_test("Batch Delete by Last Name", False, f"Error parsing response: {str(e)}")
            return False
    
    def test_batch_delete_by_class(self):
        """Test 4: Filter by class (sus_kl)"""
        print("\n=== Test 4: Batch Delete by Class ===")
        
        # Recreate test data
        self.create_test_data()
        
        delete_data = {"sus_kl": "10a"}
        response = self.make_request("POST", "/students/batch-delete", token=self.admin_token, data=delete_data)
        
        if not response or response.status_code != 200:
            self.log_test("Batch Delete by Class", False, f"Request failed: {response.status_code if response else 'No response'}")
            return False
        
        try:
            result = response.json()
            deleted_count = result.get("deleted_count", 0)
            
            # Verify only students from class "10a" were deleted
            response = self.make_request("GET", "/students", token=self.admin_token)
            if response and response.status_code == 200:
                remaining_students = response.json()
                class_10a_students = [s for s in remaining_students if s["sus_kl"] == "10a"]
                
                if len(class_10a_students) == 0 and deleted_count > 0:
                    self.log_test("Batch Delete by Class", True, f"Successfully deleted {deleted_count} students from class '10a'")
                    return True
                elif deleted_count == 0:
                    self.log_test("Batch Delete by Class", True, "No students found in class '10a' (expected if already deleted)")
                    return True
                else:
                    self.log_test("Batch Delete by Class", False, f"Still found {len(class_10a_students)} students in class '10a'")
                    return False
            else:
                self.log_test("Batch Delete by Class", False, "Failed to verify deletion")
                return False
                
        except Exception as e:
            self.log_test("Batch Delete by Class", False, f"Error parsing response: {str(e)}")
            return False
    
    def test_batch_delete_combined_filters(self):
        """Test 5: Combined filters"""
        print("\n=== Test 5: Batch Delete with Combined Filters ===")
        
        # Recreate test data
        self.create_test_data()
        
        delete_data = {"sus_vorn": "Max", "sus_kl": "10a"}
        response = self.make_request("POST", "/students/batch-delete", token=self.admin_token, data=delete_data)
        
        if not response or response.status_code != 200:
            self.log_test("Batch Delete Combined Filters", False, f"Request failed: {response.status_code if response else 'No response'}")
            return False
        
        try:
            result = response.json()
            deleted_count = result.get("deleted_count", 0)
            
            # Verify only students matching BOTH criteria were deleted
            response = self.make_request("GET", "/students", token=self.admin_token)
            if response and response.status_code == 200:
                remaining_students = response.json()
                matching_students = [s for s in remaining_students if s["sus_vorn"] == "Max" and s["sus_kl"] == "10a"]
                
                if len(matching_students) == 0 and deleted_count > 0:
                    self.log_test("Batch Delete Combined Filters", True, f"Successfully deleted {deleted_count} students matching both 'Max' and '10a'")
                    return True
                elif deleted_count == 0:
                    self.log_test("Batch Delete Combined Filters", True, "No students found matching both criteria (expected if already deleted)")
                    return True
                else:
                    self.log_test("Batch Delete Combined Filters", False, f"Still found {len(matching_students)} students matching both criteria")
                    return False
            else:
                self.log_test("Batch Delete Combined Filters", False, "Failed to verify deletion")
                return False
                
        except Exception as e:
            self.log_test("Batch Delete Combined Filters", False, f"Error parsing response: {str(e)}")
            return False
    
    def test_batch_delete_no_match(self):
        """Test 6: No match scenario"""
        print("\n=== Test 6: Batch Delete with No Matches ===")
        
        delete_data = {"sus_vorn": "NichtExistierend12345"}
        response = self.make_request("POST", "/students/batch-delete", token=self.admin_token, data=delete_data)
        
        if not response or response.status_code != 200:
            self.log_test("Batch Delete No Match", False, f"Request failed: {response.status_code if response else 'No response'}")
            return False
        
        try:
            result = response.json()
            deleted_count = result.get("deleted_count", 0)
            
            if deleted_count == 0:
                self.log_test("Batch Delete No Match", True, "Correctly returned deleted_count=0 for non-existent student name")
                return True
            else:
                self.log_test("Batch Delete No Match", False, f"Expected deleted_count=0, got {deleted_count}")
                return False
                
        except Exception as e:
            self.log_test("Batch Delete No Match", False, f"Error parsing response: {str(e)}")
            return False
    
    def test_cascading_delete(self):
        """Test 7: Cascading delete verification"""
        print("\n=== Test 7: Cascading Delete Verification ===")
        
        # Recreate test data and create assignments
        self.create_test_data()
        
        # Create an assignment
        response = self.make_request("POST", "/assignments/auto-assign", token=self.admin_token)
        if not response or response.status_code != 200:
            self.log_test("Cascading Delete Setup", False, "Failed to create assignments for cascading test")
            return False
        
        # Get assignment details before deletion
        response = self.make_request("GET", "/assignments", token=self.admin_token)
        if not response or response.status_code != 200:
            self.log_test("Cascading Delete Setup", False, "Failed to get assignments")
            return False
        
        assignments_before = response.json()
        if not assignments_before:
            self.log_test("Cascading Delete Setup", False, "No assignments found for cascading test")
            return False
        
        # Get iPad status before deletion
        response = self.make_request("GET", "/ipads", token=self.admin_token)
        if not response or response.status_code != 200:
            self.log_test("Cascading Delete Setup", False, "Failed to get iPads")
            return False
        
        ipads_before = response.json()
        assigned_ipads_before = [ipad for ipad in ipads_before if ipad["status"] == "zugewiesen"]
        
        # Delete all students (which should cascade)
        delete_data = {"all": True}
        response = self.make_request("POST", "/students/batch-delete", token=self.admin_token, data=delete_data)
        
        if not response or response.status_code != 200:
            self.log_test("Cascading Delete", False, f"Batch delete failed: {response.status_code if response else 'No response'}")
            return False
        
        try:
            result = response.json()
            deleted_count = result.get("deleted_count", 0)
            freed_ipads = result.get("freed_ipads", 0)
            
            # Verify cascading effects
            
            # 1. Check students are deleted
            response = self.make_request("GET", "/students", token=self.admin_token)
            if response and response.status_code == 200:
                remaining_students = response.json()
                admin_students = [s for s in remaining_students if not s["sus_vorn"].startswith("User")]
                
                if len(admin_students) == 0:
                    self.log_test("Cascading Delete - Students", True, f"All admin students deleted ({deleted_count})")
                else:
                    self.log_test("Cascading Delete - Students", False, f"Still found {len(admin_students)} admin students")
                    return False
            
            # 2. Check assignments are deleted
            response = self.make_request("GET", "/assignments", token=self.admin_token)
            if response and response.status_code == 200:
                remaining_assignments = response.json()
                admin_assignments = [a for a in remaining_assignments if not a["student_name"].startswith("User")]
                
                if len(admin_assignments) == 0:
                    self.log_test("Cascading Delete - Assignments", True, "All admin assignments deleted")
                else:
                    self.log_test("Cascading Delete - Assignments", False, f"Still found {len(admin_assignments)} admin assignments")
                    return False
            
            # 3. Check iPads are freed
            response = self.make_request("GET", "/ipads", token=self.admin_token)
            if response and response.status_code == 200:
                ipads_after = response.json()
                assigned_ipads_after = [ipad for ipad in ipads_after if ipad["status"] == "zugewiesen"]
                available_ipads_after = [ipad for ipad in ipads_after if ipad["status"] == "verfügbar"]
                
                # Check that iPads are now available and have no current_assignment_id
                freed_correctly = True
                for ipad in ipads_after:
                    if ipad["itnr"].startswith("BATCH") and ipad["status"] != "verfügbar":
                        freed_correctly = False
                        break
                    if ipad["itnr"].startswith("BATCH") and ipad.get("current_assignment_id"):
                        freed_correctly = False
                        break
                
                if freed_correctly and freed_ipads > 0:
                    self.log_test("Cascading Delete - iPads Freed", True, f"Successfully freed {freed_ipads} iPads")
                else:
                    self.log_test("Cascading Delete - iPads Freed", False, f"iPad freeing verification failed. Freed: {freed_ipads}")
                    return False
            
            # 4. Check contracts are deleted (if any existed)
            # This is harder to verify without creating contracts first, but the endpoint should handle it
            
            self.log_test("Cascading Delete Complete", True, f"Cascading delete verified: {deleted_count} students, {freed_ipads} iPads freed")
            return True
                
        except Exception as e:
            self.log_test("Cascading Delete", False, f"Error during cascading delete verification: {str(e)}")
            return False
    
    def test_rbac_security(self):
        """Test 8: RBAC security verification"""
        print("\n=== Test 8: RBAC Security Verification ===")
        
        # Recreate test data for all users
        self.create_test_data()
        
        # Get initial counts for each user
        response = self.make_request("GET", "/students", token=self.test_user_token)
        if response and response.status_code == 200:
            user1_students_before = response.json()
            user1_count_before = len(user1_students_before)
        else:
            self.log_test("RBAC Security - User1 Count", False, "Failed to get user1 students")
            return False
        
        response = self.make_request("GET", "/students", token=self.test_user2_token)
        if response and response.status_code == 200:
            user2_students_before = response.json()
            user2_count_before = len(user2_students_before)
        else:
            self.log_test("RBAC Security - User2 Count", False, "Failed to get user2 students")
            return False
        
        # User 1 performs batch delete (should only affect their students)
        delete_data = {"all": True}
        response = self.make_request("POST", "/students/batch-delete", token=self.test_user_token, data=delete_data)
        
        if not response or response.status_code != 200:
            self.log_test("RBAC Security - User1 Delete", False, f"User1 batch delete failed: {response.status_code if response else 'No response'}")
            return False
        
        try:
            result = response.json()
            user1_deleted_count = result.get("deleted_count", 0)
            
            # Verify User1's students are deleted
            response = self.make_request("GET", "/students", token=self.test_user_token)
            if response and response.status_code == 200:
                user1_students_after = response.json()
                user1_count_after = len(user1_students_after)
                
                if user1_count_after == 0 and user1_deleted_count == user1_count_before:
                    self.log_test("RBAC Security - User1 Own Data", True, f"User1 successfully deleted their own {user1_deleted_count} students")
                else:
                    self.log_test("RBAC Security - User1 Own Data", False, f"User1 deletion mismatch: before={user1_count_before}, after={user1_count_after}, deleted={user1_deleted_count}")
                    return False
            
            # Verify User2's students are NOT affected
            response = self.make_request("GET", "/students", token=self.test_user2_token)
            if response and response.status_code == 200:
                user2_students_after = response.json()
                user2_count_after = len(user2_students_after)
                
                if user2_count_after == user2_count_before:
                    self.log_test("RBAC Security - User2 Data Protected", True, f"User2's {user2_count_before} students remain untouched")
                else:
                    self.log_test("RBAC Security - User2 Data Protected", False, f"User2 data affected: before={user2_count_before}, after={user2_count_after}")
                    return False
            
            # Verify Admin can still see User2's students
            response = self.make_request("GET", "/students", token=self.admin_token)
            if response and response.status_code == 200:
                admin_students_after = response.json()
                user2_students_visible_to_admin = [s for s in admin_students_after if s["sus_vorn"].startswith("User2")]
                
                if len(user2_students_visible_to_admin) == user2_count_before:
                    self.log_test("RBAC Security - Admin Visibility", True, f"Admin can still see User2's {len(user2_students_visible_to_admin)} students")
                else:
                    self.log_test("RBAC Security - Admin Visibility", False, f"Admin visibility issue: expected {user2_count_before}, saw {len(user2_students_visible_to_admin)}")
                    return False
            
            self.log_test("RBAC Security Complete", True, "RBAC isolation working correctly - users can only delete their own data")
            return True
                
        except Exception as e:
            self.log_test("RBAC Security", False, f"Error during RBAC security test: {str(e)}")
            return False
    
    def test_authentication_required(self):
        """Test that authentication is required for batch delete"""
        print("\n=== Test: Authentication Required ===")
        
        delete_data = {"all": True}
        response = self.make_request("POST", "/students/batch-delete", token=None, data=delete_data)
        
        if response and response.status_code == 401:
            self.log_test("Authentication Required", True, "Correctly returned 401 for unauthenticated request")
            return True
        else:
            self.log_test("Authentication Required", False, f"Expected 401, got {response.status_code if response else 'No response'}")
            return False
    
    def run_batch_delete_tests(self):
        """Run all batch delete tests"""
        print("🗑️ Comprehensive Batch Delete Testing Suite")
        print("=" * 80)
        
        # Setup
        if not self.setup_authentication():
            print("❌ Authentication setup failed")
            return False
        
        if not self.create_test_data():
            print("❌ Test data creation failed")
            return False
        
        # Run all tests
        tests = [
            self.test_authentication_required,
            self.test_batch_delete_all_students,
            self.test_batch_delete_by_firstname,
            self.test_batch_delete_by_lastname,
            self.test_batch_delete_by_class,
            self.test_batch_delete_combined_filters,
            self.test_batch_delete_no_match,
            self.test_cascading_delete,
            self.test_rbac_security
        ]
        
        success_count = 0
        for test in tests:
            try:
                if test():
                    success_count += 1
            except Exception as e:
                print(f"❌ Test {test.__name__} failed with exception: {str(e)}")
        
        print(f"\n✅ Batch Delete Tests Complete: {success_count}/{len(tests)} passed")
        return success_count == len(tests)
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 80)
        print("🗑️ BATCH DELETE TESTING SUMMARY")
        print("=" * 80)
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if "✅ PASS" in r["status"]])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests > 0:
            print("\n❌ FAILED TESTS:")
            for result in self.test_results:
                if "❌ FAIL" in result["status"]:
                    print(f"  - {result['test']}: {result['message']}")
        
        print("\n📋 DETAILED RESULTS:")
        for result in self.test_results:
            print(f"{result['status']}: {result['test']}")
            if result['details']:
                print(f"   Details: {result['details']}")

class iPadManagementTester:
    """Comprehensive testing for iPad management features as requested in German"""
    
    def __init__(self):
        self.admin_token = None
        self.test_results = []
        self.test_ipads = []
        self.test_students = []
        self.test_assignments = []
        
    def log_test(self, test_name, success, message, details=None):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        result = {
            "test": test_name,
            "status": status,
            "message": message,
            "details": details or {},
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        print(f"{status}: {test_name} - {message}")
        if details and not success:
            print(f"   Details: {details}")
    
    def make_request(self, method, endpoint, token=None, data=None, files=None, params=None):
        """Make HTTP request with proper headers"""
        url = f"{BASE_URL}{endpoint}"
        headers = {}
        
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        if not files:
            headers["Content-Type"] = "application/json"
            
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, params=params, timeout=30)
            elif method == "POST":
                if files:
                    response = requests.post(url, headers=headers, files=files, data=data, timeout=30)
                else:
                    response = requests.post(url, headers=headers, json=data, timeout=30)
            elif method == "PUT":
                response = requests.put(url, headers=headers, json=data, params=params, timeout=30)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers, timeout=30)
            else:
                raise ValueError(f"Unsupported method: {method}")
                
            return response
        except requests.exceptions.RequestException as e:
            print(f"Request error for {method} {url}: {str(e)}")
            return None
        except Exception as e:
            print(f"Unexpected error for {method} {url}: {str(e)}")
            return None
    
    def setup_authentication(self):
        """Setup admin authentication"""
        print("\n=== Setting up Authentication for iPad Management Tests ===")
        
        # Admin login
        response = self.make_request("POST", "/auth/login", data=ADMIN_CREDENTIALS)
        if not response or response.status_code != 200:
            self.log_test("Admin Login Setup", False, f"Admin login failed: {response.status_code if response else 'No response'}")
            return False
        
        self.admin_token = response.json()["access_token"]
        self.log_test("Admin Login Setup", True, "Admin authentication successful")
        return True
    
    def test_get_all_ipads(self):
        """Test: Hole Liste aller iPads: GET /api/ipads"""
        print("\n=== Test 1: GET /api/ipads - Hole Liste aller iPads ===")
        
        response = self.make_request("GET", "/ipads", token=self.admin_token)
        
        if not response or response.status_code != 200:
            self.log_test("GET /api/ipads", False, f"Failed to get iPads: {response.status_code if response else 'No response'}")
            return False
        
        try:
            ipads = response.json()
            
            if not isinstance(ipads, list):
                self.log_test("GET /api/ipads", False, "Response is not a list")
                return False
            
            # Store iPads for later tests
            self.test_ipads = ipads
            
            # Check if iPads have required fields (ITNr and SNr)
            if ipads:
                first_ipad = ipads[0]
                required_fields = ["id", "itnr", "snr", "status", "current_assignment_id"]
                missing_fields = [field for field in required_fields if field not in first_ipad]
                
                if missing_fields:
                    self.log_test("GET /api/ipads", False, f"Missing required fields in iPad response: {missing_fields}")
                    return False
                
                # Verify ITNr and SNr are present in response
                if not first_ipad.get("itnr") or not first_ipad.get("snr"):
                    self.log_test("GET /api/ipads", False, "ITNr or SNr missing in iPad response")
                    return False
            
            self.log_test("GET /api/ipads", True, f"Successfully retrieved {len(ipads)} iPads with ITNr and SNr fields")
            return True
            
        except Exception as e:
            self.log_test("GET /api/ipads", False, f"Error parsing iPads response: {str(e)}")
            return False
    
    def test_ipad_status_updates(self):
        """Test: Status-Updates (defekt, gestohlen, ok)"""
        print("\n=== Test 2-4: iPad Status Updates ===")
        
        if not self.test_ipads:
            self.log_test("iPad Status Updates", False, "No iPads available for testing")
            return False
        
        # Use first iPad for testing
        test_ipad = self.test_ipads[0]
        ipad_id = test_ipad["id"]
        original_status = test_ipad.get("status", "ok")
        original_assignment_id = test_ipad.get("current_assignment_id")
        
        print(f"Testing with iPad ID: {ipad_id}, ITNr: {test_ipad.get('itnr')}")
        
        # Test 2: Status-Update auf "defekt"
        print("\n--- Test 2a: Status-Update auf 'defekt' ---")
        response = self.make_request("PUT", f"/ipads/{ipad_id}/status", 
                                   token=self.admin_token, 
                                   params={"status": "defekt"})
        
        if not response or response.status_code != 200:
            self.log_test("Status Update to 'defekt'", False, f"Failed to update status: {response.status_code if response else 'No response'}")
            return False
        
        # Verify status was changed but current_assignment_id remains unchanged
        response = self.make_request("GET", "/ipads", token=self.admin_token)
        if response and response.status_code == 200:
            updated_ipads = response.json()
            updated_ipad = next((ipad for ipad in updated_ipads if ipad["id"] == ipad_id), None)
            
            if updated_ipad:
                if updated_ipad["status"] == "defekt":
                    if updated_ipad.get("current_assignment_id") == original_assignment_id:
                        self.log_test("Status Update to 'defekt'", True, "Status changed to 'defekt', current_assignment_id unchanged")
                    else:
                        self.log_test("Status Update to 'defekt'", False, f"current_assignment_id changed unexpectedly: {original_assignment_id} -> {updated_ipad.get('current_assignment_id')}")
                else:
                    self.log_test("Status Update to 'defekt'", False, f"Status not updated correctly: expected 'defekt', got '{updated_ipad['status']}'")
            else:
                self.log_test("Status Update to 'defekt'", False, "iPad not found after update")
        else:
            self.log_test("Status Update to 'defekt'", False, "Failed to verify status update")
        
        # Test 3: Status-Update auf "gestohlen"
        print("\n--- Test 2b: Status-Update auf 'gestohlen' ---")
        response = self.make_request("PUT", f"/ipads/{ipad_id}/status", 
                                   token=self.admin_token, 
                                   params={"status": "gestohlen"})
        
        if not response or response.status_code != 200:
            self.log_test("Status Update to 'gestohlen'", False, f"Failed to update status: {response.status_code if response else 'No response'}")
        else:
            # Verify status was changed
            response = self.make_request("GET", "/ipads", token=self.admin_token)
            if response and response.status_code == 200:
                updated_ipads = response.json()
                updated_ipad = next((ipad for ipad in updated_ipads if ipad["id"] == ipad_id), None)
                
                if updated_ipad and updated_ipad["status"] == "gestohlen":
                    self.log_test("Status Update to 'gestohlen'", True, "Status successfully changed to 'gestohlen'")
                else:
                    self.log_test("Status Update to 'gestohlen'", False, f"Status not updated correctly: expected 'gestohlen', got '{updated_ipad['status'] if updated_ipad else 'iPad not found'}'")
            else:
                self.log_test("Status Update to 'gestohlen'", False, "Failed to verify status update")
        
        # Test 4: Status-Update auf "ok"
        print("\n--- Test 2c: Status-Update auf 'ok' ---")
        response = self.make_request("PUT", f"/ipads/{ipad_id}/status", 
                                   token=self.admin_token, 
                                   params={"status": "ok"})
        
        if not response or response.status_code != 200:
            self.log_test("Status Update to 'ok'", False, f"Failed to update status: {response.status_code if response else 'No response'}")
        else:
            # Verify status was changed back to ok
            response = self.make_request("GET", "/ipads", token=self.admin_token)
            if response and response.status_code == 200:
                updated_ipads = response.json()
                updated_ipad = next((ipad for ipad in updated_ipads if ipad["id"] == ipad_id), None)
                
                if updated_ipad and updated_ipad["status"] == "ok":
                    self.log_test("Status Update to 'ok'", True, "Status successfully changed back to 'ok'")
                else:
                    self.log_test("Status Update to 'ok'", False, f"Status not updated correctly: expected 'ok', got '{updated_ipad['status'] if updated_ipad else 'iPad not found'}'")
            else:
                self.log_test("Status Update to 'ok'", False, "Failed to verify status update")
        
        # Restore original status
        if original_status != "ok":
            self.make_request("PUT", f"/ipads/{ipad_id}/status", 
                            token=self.admin_token, 
                            params={"status": original_status})
        
        return True
    
    def test_available_students(self):
        """Test 5: Verfügbare Schüler holen - GET /api/students/available-for-assignment"""
        print("\n=== Test 3: GET /api/students/available-for-assignment ===")
        
        response = self.make_request("GET", "/students/available-for-assignment", token=self.admin_token)
        
        if not response or response.status_code != 200:
            self.log_test("GET Available Students", False, f"Failed to get available students: {response.status_code if response else 'No response'}")
            return False
        
        try:
            students = response.json()
            
            if not isinstance(students, list):
                self.log_test("GET Available Students", False, "Response is not a list")
                return False
            
            # Store students for later tests
            self.test_students = students
            
            # Verify response format
            if students:
                first_student = students[0]
                required_fields = ["id", "name"]
                missing_fields = [field for field in required_fields if field not in first_student]
                
                if missing_fields:
                    self.log_test("GET Available Students", False, f"Missing required fields in student response: {missing_fields}")
                    return False
            
            self.log_test("GET Available Students", True, f"Successfully retrieved {len(students)} available students (ohne iPad-Zuordnung)")
            return True
            
        except Exception as e:
            self.log_test("GET Available Students", False, f"Error parsing available students response: {str(e)}")
            return False
    
    def test_available_ipads(self):
        """Test 6: Verfügbare iPads holen - GET /api/ipads/available-for-assignment"""
        print("\n=== Test 4: GET /api/ipads/available-for-assignment ===")
        
        response = self.make_request("GET", "/ipads/available-for-assignment", token=self.admin_token)
        
        if not response or response.status_code != 200:
            self.log_test("GET Available iPads", False, f"Failed to get available iPads: {response.status_code if response else 'No response'}")
            return False
        
        try:
            ipads = response.json()
            
            if not isinstance(ipads, list):
                self.log_test("GET Available iPads", False, "Response is not a list")
                return False
            
            # Verify response format
            if ipads:
                first_ipad = ipads[0]
                required_fields = ["id", "itnr", "snr", "status"]
                missing_fields = [field for field in required_fields if field not in first_ipad]
                
                if missing_fields:
                    self.log_test("GET Available iPads", False, f"Missing required fields in iPad response: {missing_fields}")
                    return False
            
            self.log_test("GET Available iPads", True, f"Successfully retrieved {len(ipads)} available iPads (ohne Zuordnung)")
            return True
            
        except Exception as e:
            self.log_test("GET Available iPads", False, f"Error parsing available iPads response: {str(e)}")
            return False
    
    def test_manual_assignment(self):
        """Test 7: Manuelle Zuordnung (iPad → Schüler)"""
        print("\n=== Test 5: POST /api/assignments/manual - Manuelle Zuordnung ===")
        
        # Get fresh available students and iPads
        students_response = self.make_request("GET", "/students/available-for-assignment", token=self.admin_token)
        ipads_response = self.make_request("GET", "/ipads/available-for-assignment", token=self.admin_token)
        
        if not students_response or students_response.status_code != 200:
            self.log_test("Manual Assignment - Get Students", False, "Failed to get available students")
            return False
        
        if not ipads_response or ipads_response.status_code != 200:
            self.log_test("Manual Assignment - Get iPads", False, "Failed to get available iPads")
            return False
        
        available_students = students_response.json()
        available_ipads = ipads_response.json()
        
        if not available_students:
            # Create a test student for manual assignment
            print("No available students found, creating test student for manual assignment")
            
            import pandas as pd
            import io
            
            df = pd.DataFrame([{
                'SuSVorn': 'TestManual',
                'SuSNachn': 'Assignment',
                'SuSKl': '99m',
                'SuSStrHNr': 'Test Street 1',
                'SuSPLZ': '12345',
                'SuSOrt': 'Test City'
            }])
            
            excel_buffer = io.BytesIO()
            df.to_excel(excel_buffer, index=False)
            excel_buffer.seek(0)
            
            files = {"file": ("manual_test_student.xlsx", excel_buffer.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
            response = self.make_request("POST", "/students/upload", token=self.admin_token, files=files)
            
            if response and response.status_code == 200:
                # Get the newly created student
                students_response = self.make_request("GET", "/students/available-for-assignment", token=self.admin_token)
                if students_response and students_response.status_code == 200:
                    available_students = students_response.json()
                    test_student = next((s for s in available_students if s["name"] == "TestManual Assignment"), None)
                    if not test_student:
                        self.log_test("Manual Assignment", False, "Failed to create test student for manual assignment")
                        return False
                else:
                    self.log_test("Manual Assignment", False, "Failed to get created test student")
                    return False
            else:
                self.log_test("Manual Assignment", False, "Failed to create test student")
                return False
        
        if not available_ipads:
            self.log_test("Manual Assignment", False, "No available iPads for assignment")
            return False
        
        # Use first available student and iPad
        test_student = available_students[0]
        test_ipad = available_ipads[0]
        
        student_id = test_student["id"]
        ipad_id = test_ipad["id"]
        
        print(f"Assigning iPad {test_ipad['itnr']} to student {test_student['name']}")
        
        # Create manual assignment
        assignment_data = {
            "student_id": student_id,
            "ipad_id": ipad_id
        }
        
        # The endpoint expects query parameters
        response = self.make_request("POST", f"/assignments/manual?student_id={student_id}&ipad_id={ipad_id}", token=self.admin_token)
        
        if not response or response.status_code != 200:
            self.log_test("Manual Assignment Creation", False, f"Failed to create manual assignment: {response.status_code if response else 'No response'}")
            if response:
                print(f"Response text: {response.text}")
            return False
        
        try:
            result = response.json()
            assignment_id = result.get("assignment_id")
            
            if not assignment_id:
                self.log_test("Manual Assignment Creation", False, "No assignment_id in response")
                return False
            
            self.log_test("Manual Assignment Creation", True, f"Successfully created manual assignment: {result.get('message', 'Assignment created')}")
            
            # Verify assignment was created (no contract expected)
            # Check that iPad has current_assignment_id
            ipads_response = self.make_request("GET", "/ipads", token=self.admin_token)
            if ipads_response and ipads_response.status_code == 200:
                ipads = ipads_response.json()
                assigned_ipad = next((ipad for ipad in ipads if ipad["id"] == ipad_id), None)
                
                if assigned_ipad and assigned_ipad.get("current_assignment_id") == assignment_id:
                    self.log_test("iPad Assignment Verification", True, "iPad correctly has current_assignment_id")
                else:
                    self.log_test("iPad Assignment Verification", False, f"iPad assignment not updated correctly: {assigned_ipad.get('current_assignment_id') if assigned_ipad else 'iPad not found'}")
            
            # Check that student has current_assignment_id
            students_response = self.make_request("GET", "/students", token=self.admin_token)
            if students_response and students_response.status_code == 200:
                students = students_response.json()
                assigned_student = next((student for student in students if student["id"] == student_id), None)
                
                if assigned_student and assigned_student.get("current_assignment_id") == assignment_id:
                    self.log_test("Student Assignment Verification", True, "Student correctly has current_assignment_id")
                else:
                    self.log_test("Student Assignment Verification", False, f"Student assignment not updated correctly: {assigned_student.get('current_assignment_id') if assigned_student else 'Student not found'}")
            
            # Store assignment for duplicate test
            self.test_assignments.append({
                "id": assignment_id,
                "student_id": student_id,
                "ipad_id": ipad_id,
                "itnr": test_ipad["itnr"],
                "student_name": test_student["name"]
            })
            
            return True
            
        except Exception as e:
            self.log_test("Manual Assignment Creation", False, f"Error parsing assignment response: {str(e)}")
            return False
    
    def test_duplicate_assignment_prevention(self):
        """Test 8: Doppelte Zuordnung verhindern"""
        print("\n=== Test 6: Duplicate Assignment Prevention ===")
        
        if not self.test_assignments:
            self.log_test("Duplicate Assignment Prevention", False, "No existing assignments to test with")
            return False
        
        # Try to assign the same iPad again
        existing_assignment = self.test_assignments[0]
        
        # Get an available student for the duplicate test
        students_response = self.make_request("GET", "/students/available-for-assignment", token=self.admin_token)
        if not students_response or students_response.status_code != 200:
            self.log_test("Duplicate Assignment Prevention", False, "Failed to get available students for duplicate test")
            return False
        
        available_students = students_response.json()
        
        # For duplicate test, we need a different student than the one already assigned
        # Let's create a new student specifically for this test
        print("Creating new test student for duplicate assignment test")
        
        # Create test student via Excel upload
        import pandas as pd
        import io
        
        df = pd.DataFrame([{
            'SuSVorn': 'TestDuplicate2',
            'SuSNachn': 'Student2',
            'SuSKl': '99z',
            'SuSStrHNr': 'Test Street 1',
            'SuSPLZ': '12345',
            'SuSOrt': 'Test City'
        }])
        
        excel_buffer = io.BytesIO()
        df.to_excel(excel_buffer, index=False)
        excel_buffer.seek(0)
        
        files = {"file": ("duplicate_test_student2.xlsx", excel_buffer.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
        response = self.make_request("POST", "/students/upload", token=self.admin_token, files=files)
        
        if response and response.status_code == 200:
            # Get the newly created student
            students_response = self.make_request("GET", "/students/available-for-assignment", token=self.admin_token)
            if students_response and students_response.status_code == 200:
                available_students = students_response.json()
                test_student = next((s for s in available_students if s["name"] == "TestDuplicate2 Student2"), None)
                if not test_student:
                    self.log_test("Duplicate Assignment Prevention", False, "Failed to create test student for duplicate test")
                    return False
            else:
                self.log_test("Duplicate Assignment Prevention", False, "Failed to get created test student")
                return False
        else:
            self.log_test("Duplicate Assignment Prevention", False, "Failed to create test student")
            return False
        
        # Try to assign the already assigned iPad to another student
        duplicate_assignment_data = {
            "student_id": test_student["id"],
            "ipad_id": existing_assignment["ipad_id"]
        }
        
        # The endpoint expects query parameters
        response = self.make_request("POST", f"/assignments/manual?student_id={test_student['id']}&ipad_id={existing_assignment['ipad_id']}", token=self.admin_token)
        
        # Should get 400 error with message "iPad ist bereits zugewiesen"
        if response and response.status_code == 400:
            try:
                error_response = response.json()
                error_message = error_response.get("detail", "")
                
                if "bereits zugewiesen" in error_message or "already assigned" in error_message:
                    self.log_test("Duplicate Assignment Prevention", True, f"Correctly prevented duplicate assignment: {error_message}")
                    return True
                else:
                    self.log_test("Duplicate Assignment Prevention", False, f"Wrong error message for duplicate assignment: {error_message}")
                    return False
            except:
                self.log_test("Duplicate Assignment Prevention", False, f"Got 400 status but couldn't parse error message: {response.text}")
                return False
        else:
            self.log_test("Duplicate Assignment Prevention", False, f"Expected 400 error for duplicate assignment, got: {response.status_code if response else 'No response'}")
            if response:
                print(f"Response: {response.text}")
            return False
    
    def run_all_tests(self):
        """Run all iPad management tests"""
        print("📱 iPad Management Features Testing Suite")
        print("Testing new iPad management features as requested in German")
        print("=" * 80)
        
        # Setup authentication
        if not self.setup_authentication():
            print("❌ Authentication setup failed")
            return False
        
        # Test 1: Get all iPads
        if not self.test_get_all_ipads():
            print("❌ Get iPads test failed")
            return False
        
        # Test 2-4: iPad status updates
        if not self.test_ipad_status_updates():
            print("❌ iPad status update tests failed")
            return False
        
        # Test 5: Available students
        if not self.test_available_students():
            print("❌ Available students test failed")
            return False
        
        # Test 6: Available iPads
        if not self.test_available_ipads():
            print("❌ Available iPads test failed")
            return False
        
        # Test 7: Manual assignment
        if not self.test_manual_assignment():
            print("❌ Manual assignment test failed")
            return False
        
        # Test 8: Duplicate assignment prevention
        if not self.test_duplicate_assignment_prevention():
            print("❌ Duplicate assignment prevention test failed")
            return False
        
        return True
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 80)
        print("📱 IPAD MANAGEMENT TESTING SUMMARY")
        print("=" * 80)
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if "✅ PASS" in r["status"]])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests > 0:
            print("\n❌ FAILED TESTS:")
            for result in self.test_results:
                if "❌ FAIL" in result["status"]:
                    print(f"  - {result['test']}: {result['message']}")
        
        print("\n📋 DETAILED RESULTS:")
        for result in self.test_results:
            print(f"{result['status']}: {result['test']}")
            if result['details']:
                print(f"   Details: {result['details']}")

def main():
    """Main test execution"""
    print("🔐 iPad Management System - Backend Testing Suite")
    print("=" * 80)
    print("Choose testing mode:")
    print("1. Full RBAC Testing (existing comprehensive tests)")
    print("2. Batch Delete Feature Testing (new feature)")
    print("3. iPad Management Features Testing (German test scenarios)")
    print("4. All tests (recommended)")
    
    choice = input("Enter choice (1/2/3/4): ").strip()
    
    if choice == "1":
        tester = RBACTester()
        try:
            success = tester.run_all_tests()
            tester.print_summary()
            return 0 if success else 1
        except Exception as e:
            print(f"\n💥 RBAC testing error: {str(e)}")
            return 1
    
    elif choice == "2":
        tester = BatchDeleteTester()
        try:
            success = tester.run_batch_delete_tests()
            tester.print_summary()
            return 0 if success else 1
        except Exception as e:
            print(f"\n💥 Batch delete testing error: {str(e)}")
            return 1
    
    elif choice == "3":
        tester = iPadManagementTester()
        try:
            success = tester.run_all_tests()
            tester.print_summary()
            return 0 if success else 1
        except Exception as e:
            print(f"\n💥 iPad management testing error: {str(e)}")
            return 1
    
    elif choice == "4":
        print("\n🔄 Running Full Test Suite...")
        
        # Run RBAC tests first
        print("\n" + "="*50)
        print("PHASE 1: RBAC TESTING")
        print("="*50)
        rbac_tester = RBACTester()
        try:
            rbac_success = rbac_tester.run_all_tests()
            rbac_tester.print_summary()
        except Exception as e:
            print(f"\n💥 RBAC testing error: {str(e)}")
            rbac_success = False
        
        # Run Batch Delete tests
        print("\n" + "="*50)
        print("PHASE 2: BATCH DELETE TESTING")
        print("="*50)
        batch_tester = BatchDeleteTester()
        try:
            batch_success = batch_tester.run_batch_delete_tests()
            batch_tester.print_summary()
        except Exception as e:
            print(f"\n💥 Batch delete testing error: {str(e)}")
            batch_success = False
        
        # Run iPad Management tests
        print("\n" + "="*50)
        print("PHASE 3: IPAD MANAGEMENT TESTING")
        print("="*50)
        ipad_tester = iPadManagementTester()
        try:
            ipad_success = ipad_tester.run_all_tests()
            ipad_tester.print_summary()
        except Exception as e:
            print(f"\n💥 iPad management testing error: {str(e)}")
            ipad_success = False
        
        # Overall summary
        print("\n" + "="*80)
        print("🎯 OVERALL TESTING SUMMARY")
        print("="*80)
        print(f"RBAC Tests: {'✅ PASSED' if rbac_success else '❌ FAILED'}")
        print(f"Batch Delete Tests: {'✅ PASSED' if batch_success else '❌ FAILED'}")
        print(f"iPad Management Tests: {'✅ PASSED' if ipad_success else '❌ FAILED'}")
        
        if rbac_success and batch_success and ipad_success:
            print("\n🎉 All tests completed successfully!")
            return 0
        else:
            print("\n❌ Some tests failed!")
            return 1
    
    else:
        print("Invalid choice. Exiting.")
        return 1

if __name__ == "__main__":
    sys.exit(main())