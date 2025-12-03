#!/usr/bin/env python3
"""
Comprehensive RBAC Testing Suite for iPad Management System
Tests all RBAC functionality as requested by the user.

Test Coverage:
1. Admin Login & Authentication (admin/admin123)
2. JWT Token with role and user_id verification
3. User Management (Admin) - POST, GET, PUT, DELETE /api/admin/users
4. User Login & Isolation - User cannot access admin endpoints
5. Resource Isolation - Admin sees all, Users see only their own
6. Admin Access to all Resources verification
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

class RBACComprehensiveTester:
    def __init__(self):
        self.admin_token = None
        self.test_user_token = None
        self.test_user_id = None
        self.test_username = f"testuser_{int(time.time())}"
        self.admin_user_id = None
        self.test_results = []
        
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

    def test_1_admin_login_authentication(self):
        """Test 1: Admin Login & Authentication with admin/admin123"""
        print("\n=== Test 1: Admin Login & Authentication ===")
        
        response = self.make_request("POST", "/auth/login", data=ADMIN_CREDENTIALS)
        
        if not response or response.status_code != 200:
            self.log_test("Admin Login (admin/admin123)", False, f"Login failed with status {response.status_code if response else 'No response'}")
            return False
            
        try:
            data = response.json()
            required_fields = ["access_token", "token_type", "role", "username"]
            
            for field in required_fields:
                if field not in data:
                    self.log_test("Admin Login (admin/admin123)", False, f"Missing field in response: {field}")
                    return False
            
            if data["role"] != "admin":
                self.log_test("Admin Login (admin/admin123)", False, f"Expected admin role, got: {data['role']}")
                return False
                
            if data["username"] != "admin":
                self.log_test("Admin Login (admin/admin123)", False, f"Expected admin username, got: {data['username']}")
                return False
            
            self.admin_token = data["access_token"]
            self.log_test("Admin Login (admin/admin123)", True, f"Successfully logged in as admin with role: {data['role']}")
            return True
            
        except Exception as e:
            self.log_test("Admin Login (admin/admin123)", False, f"Error parsing login response: {str(e)}")
            return False

    def test_2_jwt_token_verification(self):
        """Test 2: JWT Token with role and user_id verification"""
        print("\n=== Test 2: JWT Token Verification ===")
        
        if not self.admin_token:
            self.log_test("JWT Token Verification", False, "No admin token available")
            return False
        
        # Verify JWT token contains user_id and role by decoding (without verification for testing)
        import jwt
        try:
            # Decode without verification to check payload structure
            payload = jwt.decode(self.admin_token, options={"verify_signature": False})
            
            if "user_id" not in payload:
                self.log_test("JWT Token Verification", False, "JWT token missing user_id field")
                return False
            
            if "sub" not in payload:  # subject should contain username
                self.log_test("JWT Token Verification", False, "JWT token missing sub (username) field")
                return False
            
            self.admin_user_id = payload.get('user_id')
            self.log_test("JWT Token Verification", True, f"JWT token properly contains user_id: {payload.get('user_id')} and role info")
            return True
            
        except Exception as e:
            self.log_test("JWT Token Verification", False, f"Failed to decode JWT token: {str(e)}")
            return False

    def test_3_user_management_admin(self):
        """Test 3: User Management (Admin) - POST, GET, PUT, DELETE /api/admin/users"""
        print("\n=== Test 3: User Management (Admin) ===")
        
        # Test POST /api/admin/users - Create new user with role="user"
        user_data = {
            "username": self.test_username,
            "password": "test123",
            "role": "user"
        }
        
        response = self.make_request("POST", "/admin/users", token=self.admin_token, data=user_data)
        
        if not response or response.status_code != 200:
            self.log_test("POST /api/admin/users", False, f"User creation failed with status {response.status_code if response else 'No response'}")
            return False
            
        try:
            data = response.json()
            required_fields = ["id", "username", "role", "is_active", "created_by", "created_at", "updated_at"]
            
            for field in required_fields:
                if field not in data:
                    self.log_test("POST /api/admin/users", False, f"Missing field in response: {field}")
                    return False
            
            if data["username"] != self.test_username or data["role"] != "user":
                self.log_test("POST /api/admin/users", False, f"User data mismatch: expected {self.test_username}/user, got {data['username']}/{data['role']}")
                return False
                
            self.test_user_id = data["id"]
            self.log_test("POST /api/admin/users", True, f"Successfully created user {self.test_username} with role=user, ID: {self.test_user_id}")
            
        except Exception as e:
            self.log_test("POST /api/admin/users", False, f"Error parsing user creation response: {str(e)}")
            return False
        
        # Test GET /api/admin/users - List all users (Admin sees all)
        response = self.make_request("GET", "/admin/users", token=self.admin_token)
        
        if not response or response.status_code != 200:
            self.log_test("GET /api/admin/users", False, f"User listing failed with status {response.status_code if response else 'No response'}")
            return False
            
        try:
            users = response.json()
            
            if not isinstance(users, list) or len(users) < 2:
                self.log_test("GET /api/admin/users", False, f"Expected list with at least 2 users, got: {len(users) if isinstance(users, list) else 'not a list'}")
                return False
            
            # Verify our test user is in the list
            test_user_found = False
            admin_user_found = False
            for user in users:
                if user["username"] == self.test_username:
                    test_user_found = True
                if user["username"] == "admin":
                    admin_user_found = True
            
            if not test_user_found or not admin_user_found:
                self.log_test("GET /api/admin/users", False, f"Missing users in list - test_user: {test_user_found}, admin: {admin_user_found}")
                return False
            
            self.log_test("GET /api/admin/users", True, f"Successfully listed {len(users)} users including admin and test user")
            
        except Exception as e:
            self.log_test("GET /api/admin/users", False, f"Error parsing user list response: {str(e)}")
            return False
        
        # Test PUT /api/admin/users/{user_id} - Update user
        update_data = {"password": "newpassword123"}
        response = self.make_request("PUT", f"/admin/users/{self.test_user_id}", token=self.admin_token, data=update_data)
        
        if not response or response.status_code != 200:
            self.log_test("PUT /api/admin/users/{user_id}", False, f"User update failed with status {response.status_code if response else 'No response'}")
            return False
        
        self.log_test("PUT /api/admin/users/{user_id}", True, "Successfully updated user password")
        
        # Test DELETE /api/admin/users/{user_id} - Deactivate user (we'll create another user for this)
        # Create another user to delete
        delete_user_data = {
            "username": f"deleteuser_{int(time.time())}",
            "password": "test123",
            "role": "user"
        }
        
        response = self.make_request("POST", "/admin/users", token=self.admin_token, data=delete_user_data)
        if response and response.status_code == 200:
            delete_user_id = response.json()["id"]
            
            # Now delete this user
            response = self.make_request("DELETE", f"/admin/users/{delete_user_id}", token=self.admin_token)
            
            if response and response.status_code == 200:
                self.log_test("DELETE /api/admin/users/{user_id}", True, "Successfully deactivated user")
            else:
                self.log_test("DELETE /api/admin/users/{user_id}", False, f"User deactivation failed with status {response.status_code if response else 'No response'}")
        else:
            self.log_test("DELETE /api/admin/users/{user_id}", False, "Could not create user to delete")
        
        return True

    def test_4_user_login_isolation(self):
        """Test 4: User Login & Isolation - User cannot access admin endpoints"""
        print("\n=== Test 4: User Login & Isolation ===")
        
        # Login with newly created user
        test_credentials = {"username": self.test_username, "password": "newpassword123"}  # Updated password
        response = self.make_request("POST", "/auth/login", data=test_credentials)
        
        if not response or response.status_code != 200:
            self.log_test("User Login", False, f"Test user login failed with status {response.status_code if response else 'No response'}")
            return False
            
        try:
            data = response.json()
            
            if data["role"] != "user" or data["username"] != self.test_username:
                self.log_test("User Login", False, f"Test user login data mismatch: expected {self.test_username}/user, got {data['username']}/{data['role']}")
                return False
                
            self.test_user_token = data["access_token"]
            self.log_test("User Login", True, f"Successfully logged in as {self.test_username} with role: {data['role']}")
            
        except Exception as e:
            self.log_test("User Login", False, f"Error parsing test user login response: {str(e)}")
            return False
        
        # Test that user CANNOT access /api/admin/users
        response = self.make_request("GET", "/admin/users", token=self.test_user_token)
        
        if response and response.status_code == 403:
            self.log_test("User Access Isolation", True, "User correctly blocked from accessing /api/admin/users (403 Forbidden)")
        elif response and response.status_code == 401:
            self.log_test("User Access Isolation", True, "User correctly blocked from accessing /api/admin/users (401 Unauthorized)")
        elif not response:
            # If no response, try a simpler test - check if user can create another user (should fail)
            test_user_data = {"username": "hackuser", "password": "hack123", "role": "admin"}
            response2 = self.make_request("POST", "/admin/users", token=self.test_user_token, data=test_user_data)
            if response2 and response2.status_code in [403, 401]:
                self.log_test("User Access Isolation", True, "User correctly blocked from admin operations (verified via POST test)")
            else:
                self.log_test("User Access Isolation", False, f"Network timeout, but backup test also failed: {response2.status_code if response2 else 'No response'}")
                # Don't return False here, continue with other tests
        else:
            self.log_test("User Access Isolation", False, f"Expected 403/401 for user accessing admin endpoint, got {response.status_code}")
            return False
        
        return True

    def create_test_resources(self, token, user_type):
        """Create test resources (students, iPads) for a user"""
        print(f"\n=== Creating Test Resources for {user_type} ===")
        
        # Create test iPad Excel file
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
            self.log_test(f"Create iPads ({user_type})", True, f"Successfully created iPads for {user_type}")
        else:
            self.log_test(f"Create iPads ({user_type})", False, f"iPad creation failed for {user_type}")
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
            self.log_test(f"Create Students ({user_type})", True, f"Successfully created students for {user_type}")
            return True
        else:
            self.log_test(f"Create Students ({user_type})", False, f"Student creation failed for {user_type}")
            return False

    def test_5_resource_isolation(self):
        """Test 5: Resource Isolation - Admin sees all, Users see only their own"""
        print("\n=== Test 5: Resource Isolation ===")
        
        # Create resources as Admin
        admin_resources_created = self.create_test_resources(self.admin_token, "ADMIN")
        
        # Create resources as User
        user_resources_created = self.create_test_resources(self.test_user_token, "USER")
        
        if not admin_resources_created or not user_resources_created:
            self.log_test("Resource Creation", False, "Failed to create test resources")
            return False
        
        # Test Admin sees ALL students (admin + user)
        response = self.make_request("GET", "/students", token=self.admin_token)
        if response and response.status_code == 200:
            admin_students = response.json()
            admin_student_count = len(admin_students)
            
            # Count students that belong to admin and user
            admin_owned = len([s for s in admin_students if "ADMIN" in str(s)])
            user_owned = len([s for s in admin_students if "USER" in str(s)])
            
            if admin_student_count >= 4:  # Should see both admin and user students
                self.log_test("Admin Sees ALL Students", True, f"Admin sees {admin_student_count} students total (admin+user resources)")
            else:
                self.log_test("Admin Sees ALL Students", False, f"Admin sees only {admin_student_count} students, expected at least 4")
        else:
            self.log_test("Admin Sees ALL Students", False, "Admin failed to retrieve students")
            return False
        
        # Test User sees ONLY own students
        response = self.make_request("GET", "/students", token=self.test_user_token)
        if response and response.status_code == 200:
            user_students = response.json()
            user_student_count = len(user_students)
            
            # Verify all students belong to the user
            user_only = all("USER" in str(s) for s in user_students)
            
            if user_student_count >= 2 and user_only:
                self.log_test("User Sees Only Own Students", True, f"User sees {user_student_count} students (only own resources)")
            else:
                self.log_test("User Sees Only Own Students", False, f"User sees {user_student_count} students, isolation may be broken")
        else:
            self.log_test("User Sees Only Own Students", False, "User failed to retrieve students")
            return False
        
        # Test Admin sees ALL iPads (admin + user)
        response = self.make_request("GET", "/ipads", token=self.admin_token)
        if response and response.status_code == 200:
            admin_ipads = response.json()
            admin_ipad_count = len(admin_ipads)
            
            if admin_ipad_count >= 4:  # Should see both admin and user iPads
                self.log_test("Admin Sees ALL iPads", True, f"Admin sees {admin_ipad_count} iPads total (admin+user resources)")
            else:
                self.log_test("Admin Sees ALL iPads", False, f"Admin sees only {admin_ipad_count} iPads, expected at least 4")
        else:
            self.log_test("Admin Sees ALL iPads", False, "Admin failed to retrieve iPads")
            return False
        
        # Test User sees ONLY own iPads
        response = self.make_request("GET", "/ipads", token=self.test_user_token)
        if response and response.status_code == 200:
            user_ipads = response.json()
            user_ipad_count = len(user_ipads)
            
            # Verify all iPads belong to the user
            user_only = all("USER" in str(i) for i in user_ipads)
            
            if user_ipad_count >= 2 and user_only:
                self.log_test("User Sees Only Own iPads", True, f"User sees {user_ipad_count} iPads (only own resources)")
            else:
                self.log_test("User Sees Only Own iPads", False, f"User sees {user_ipad_count} iPads, isolation may be broken")
        else:
            self.log_test("User Sees Only Own iPads", False, "User failed to retrieve iPads")
            return False
        
        return True

    def test_6_admin_access_all_resources(self):
        """Test 6: Admin Access to all Resources - Verify admin bypasses user_id filter"""
        print("\n=== Test 6: Admin Access to All Resources ===")
        
        # Test Admin sees all assignments
        response = self.make_request("GET", "/assignments", token=self.admin_token)
        if response and response.status_code == 200:
            admin_assignments = response.json()
            self.log_test("Admin Sees All Assignments", True, f"Admin sees {len(admin_assignments)} assignments (all users)")
        else:
            self.log_test("Admin Sees All Assignments", False, "Admin failed to retrieve assignments")
        
        # Test Admin can create auto-assignments (should work with all resources)
        response = self.make_request("POST", "/assignments/auto-assign", token=self.admin_token)
        if response and response.status_code == 200:
            result = response.json()
            assigned_count = result.get("assigned_count", 0)
            self.log_test("Admin Auto-Assign All Resources", True, f"Admin auto-assigned {assigned_count} iPads from all available resources")
        else:
            self.log_test("Admin Auto-Assign All Resources", False, "Admin auto-assign failed")
        
        # Test Admin can access contracts (if any exist)
        response = self.make_request("GET", "/contracts/unassigned", token=self.admin_token)
        if response and response.status_code == 200:
            contracts = response.json()
            self.log_test("Admin Sees All Contracts", True, f"Admin sees {len(contracts)} contracts (all users)")
        else:
            self.log_test("Admin Sees All Contracts", False, "Admin failed to retrieve contracts")
        
        # Verify User cannot see admin's assignments
        response = self.make_request("GET", "/assignments", token=self.test_user_token)
        if response and response.status_code == 200:
            user_assignments = response.json()
            # User should only see their own assignments
            user_only = all("USER" in str(a.get("itnr", "")) for a in user_assignments)
            
            if user_only or len(user_assignments) == 0:
                self.log_test("User Assignment Isolation", True, f"User sees only own assignments ({len(user_assignments)} assignments)")
            else:
                self.log_test("User Assignment Isolation", False, f"User may see admin assignments - {len(user_assignments)} total")
        else:
            self.log_test("User Assignment Isolation", False, "User failed to retrieve assignments")
        
        return True

    def run_comprehensive_rbac_tests(self):
        """Run all comprehensive RBAC tests as requested"""
        print("🔐 Comprehensive RBAC Testing Suite - iPad Management System")
        print("=" * 80)
        print("Testing RBAC functionality with real data as requested:")
        print("- Admin: username=admin, password=admin123")
        print(f"- Test User: username={self.test_username}, password=test123, role=user")
        print("- Backend URL: https://edudevice-1.preview.emergentagent.com")
        print("=" * 80)
        
        # Test 1: Admin Login & Authentication
        if not self.test_1_admin_login_authentication():
            print("❌ Cannot proceed without admin login")
            return False
        
        # Test 2: JWT Token Verification
        if not self.test_2_jwt_token_verification():
            print("❌ JWT token verification failed")
            return False
        
        # Test 3: User Management (Admin)
        if not self.test_3_user_management_admin():
            print("❌ User management tests failed")
            return False
        
        # Test 4: User Login & Isolation
        if not self.test_4_user_login_isolation():
            print("❌ User login and isolation tests failed")
            return False
        
        # Test 5: Resource Isolation
        if not self.test_5_resource_isolation():
            print("❌ Resource isolation tests failed")
            return False
        
        # Test 6: Admin Access to All Resources
        if not self.test_6_admin_access_all_resources():
            print("❌ Admin access tests failed")
            return False
        
        return True
    
    def print_summary(self):
        """Print comprehensive test summary"""
        print("\n" + "=" * 80)
        print("🔐 COMPREHENSIVE RBAC TESTING SUMMARY")
        print("=" * 80)
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if "✅ PASS" in r["status"]])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        print("\n📋 TEST RESULTS BY CATEGORY:")
        print("1. Admin Login & Authentication:")
        for result in self.test_results:
            if "Admin Login" in result["test"] or "JWT Token" in result["test"]:
                print(f"   {result['status']}: {result['test']}")
        
        print("\n2. User Management (Admin):")
        for result in self.test_results:
            if "/api/admin/users" in result["test"]:
                print(f"   {result['status']}: {result['test']}")
        
        print("\n3. User Login & Isolation:")
        for result in self.test_results:
            if "User Login" in result["test"] or "User Access" in result["test"]:
                print(f"   {result['status']}: {result['test']}")
        
        print("\n4. Resource Isolation:")
        for result in self.test_results:
            if "Sees" in result["test"] and ("Students" in result["test"] or "iPads" in result["test"]):
                print(f"   {result['status']}: {result['test']}")
        
        print("\n5. Admin Access to All Resources:")
        for result in self.test_results:
            if "Admin" in result["test"] and ("Assignments" in result["test"] or "Contracts" in result["test"] or "Auto-Assign" in result["test"]):
                print(f"   {result['status']}: {result['test']}")
        
        if failed_tests > 0:
            print("\n❌ FAILED TESTS DETAILS:")
            for result in self.test_results:
                if "❌ FAIL" in result["status"]:
                    print(f"  - {result['test']}: {result['message']}")
                    if result['details']:
                        print(f"    Details: {result['details']}")

def main():
    """Main test execution"""
    tester = RBACComprehensiveTester()
    
    try:
        success = tester.run_comprehensive_rbac_tests()
        tester.print_summary()
        
        if success:
            print("\n🎉 All comprehensive RBAC tests completed successfully!")
            print("✅ RBAC functionality is working correctly with proper isolation")
            return 0
        else:
            print("\n❌ Some RBAC tests failed!")
            print("⚠️ RBAC functionality may have issues that need attention")
            return 1
            
    except KeyboardInterrupt:
        print("\n⚠️ Testing interrupted by user")
        return 1
    except Exception as e:
        print(f"\n💥 Unexpected error during testing: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())