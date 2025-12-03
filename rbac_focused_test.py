#!/usr/bin/env python3
"""
Focused RBAC Backend Testing Suite
Tests the critical RBAC implementation features.
"""

import requests
import json
import sys
from datetime import datetime

# Configuration
BASE_URL = "https://edudevice-1.preview.emergentagent.com/api"
ADMIN_CREDENTIALS = {"username": "admin", "password": "admin123"}

class FocusedRBACTester:
    def __init__(self):
        self.admin_token = None
        self.test_user_token = None
        self.test_user_id = None
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
    
    def make_request(self, method, endpoint, token=None, data=None):
        """Make HTTP request with proper headers"""
        url = f"{BASE_URL}{endpoint}"
        headers = {"Content-Type": "application/json"}
        
        if token:
            headers["Authorization"] = f"Bearer {token}"
            
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=10)
            elif method == "POST":
                response = requests.post(url, headers=headers, json=data, timeout=10)
            elif method == "PUT":
                response = requests.put(url, headers=headers, json=data, timeout=10)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers, timeout=10)
            else:
                raise ValueError(f"Unsupported method: {method}")
                
            return response
        except Exception as e:
            print(f"Request error for {method} {url}: {str(e)}")
            return None
    
    def test_enhanced_login(self):
        """Test enhanced login endpoint with role information"""
        print("\n=== Testing Enhanced Login Endpoint ===")
        
        # Test admin login
        response = self.make_request("POST", "/auth/login", data=ADMIN_CREDENTIALS)
        
        if not response or response.status_code != 200:
            self.log_test("Enhanced Login - Admin", False, f"Admin login failed with status {response.status_code if response else 'No response'}")
            return False
            
        try:
            data = response.json()
            required_fields = ["access_token", "token_type", "role", "username"]
            
            for field in required_fields:
                if field not in data:
                    self.log_test("Enhanced Login - Admin", False, f"Missing field in response: {field}")
                    return False
            
            if data["role"] != "admin" or data["username"] != "admin":
                self.log_test("Enhanced Login - Admin", False, f"Invalid admin data: {data}")
                return False
                
            self.admin_token = data["access_token"]
            self.log_test("Enhanced Login - Admin", True, f"Admin login successful with role: {data['role']}")
            return True
            
        except Exception as e:
            self.log_test("Enhanced Login - Admin", False, f"Error parsing login response: {str(e)}")
            return False
    
    def test_admin_user_management(self):
        """Test admin user management endpoints"""
        print("\n=== Testing Admin User Management Endpoints ===")
        
        # 1. Test POST /api/admin/users - Create new user
        user_data = {
            "username": "rbactest",
            "password": "test123",
            "role": "user"
        }
        
        response = self.make_request("POST", "/admin/users", token=self.admin_token, data=user_data)
        
        if not response or response.status_code != 200:
            self.log_test("Create User", False, f"User creation failed with status {response.status_code if response else 'No response'}")
            return False
            
        try:
            data = response.json()
            self.test_user_id = data["id"]
            self.log_test("Create User", True, f"Successfully created user: {data['username']}")
        except Exception as e:
            self.log_test("Create User", False, f"Error parsing user creation response: {str(e)}")
            return False
        
        # 2. Test GET /api/admin/users - List all users
        response = self.make_request("GET", "/admin/users", token=self.admin_token)
        
        if not response or response.status_code != 200:
            self.log_test("List Users", False, f"User listing failed with status {response.status_code if response else 'No response'}")
            return False
            
        try:
            users = response.json()
            if not isinstance(users, list) or len(users) < 2:
                self.log_test("List Users", False, f"Expected list with at least 2 users, got: {len(users) if isinstance(users, list) else 'not a list'}")
                return False
            
            # Find admin user ID
            for user in users:
                if user["username"] == "admin":
                    self.admin_user_id = user["id"]
                    break
            
            self.log_test("List Users", True, f"Successfully listed {len(users)} users")
        except Exception as e:
            self.log_test("List Users", False, f"Error parsing user list response: {str(e)}")
            return False
        
        # 3. Test PUT /api/admin/users/{user_id} - Update user
        update_data = {"password": "newpassword123"}
        response = self.make_request("PUT", f"/admin/users/{self.test_user_id}", token=self.admin_token, data=update_data)
        
        if response and response.status_code == 200:
            self.log_test("Update User", True, "Successfully updated user password")
        else:
            self.log_test("Update User", False, f"User update failed with status {response.status_code if response else 'No response'}")
        
        # 4. Test self-protection (cannot deactivate own account)
        update_data = {"is_active": False}
        response = self.make_request("PUT", f"/admin/users/{self.admin_user_id}", token=self.admin_token, data=update_data)
        
        if response and response.status_code == 400:
            self.log_test("Self-Protection", True, "Self-protection working - cannot deactivate own account")
        else:
            self.log_test("Self-Protection", False, f"Expected 400 for self-deactivation, got {response.status_code if response else 'No response'}")
        
        return True
    
    def test_user_login_and_authorization(self):
        """Test user login and authorization validation"""
        print("\n=== Testing User Login and Authorization ===")
        
        # Test user login
        test_credentials = {"username": "rbactest", "password": "newpassword123"}
        response = self.make_request("POST", "/auth/login", data=test_credentials)
        
        if not response or response.status_code != 200:
            self.log_test("User Login", False, f"User login failed with status {response.status_code if response else 'No response'}")
            return False
            
        try:
            data = response.json()
            
            if data["role"] != "user" or data["username"] != "rbactest":
                self.log_test("User Login", False, f"User login data mismatch: {data}")
                return False
                
            self.test_user_token = data["access_token"]
            self.log_test("User Login", True, f"Successfully logged in as user with role: {data['role']}")
        except Exception as e:
            self.log_test("User Login", False, f"Error parsing user login response: {str(e)}")
            return False
        
        # Test non-admin cannot access admin endpoints
        response = self.make_request("GET", "/admin/users", token=self.test_user_token)
        
        if response and response.status_code == 403:
            self.log_test("Non-Admin Access Blocked", True, "Non-admin correctly blocked from admin endpoints (403 Forbidden)")
        else:
            self.log_test("Non-Admin Access Blocked", False, f"Expected 403 for non-admin access, got {response.status_code if response else 'No response'}")
        
        return True
    
    def test_resource_isolation_basic(self):
        """Test basic resource isolation"""
        print("\n=== Testing Basic Resource Isolation ===")
        
        # Test admin can see all iPads
        response = self.make_request("GET", "/ipads", token=self.admin_token)
        if response and response.status_code == 200:
            admin_ipads = response.json()
            admin_ipad_count = len(admin_ipads)
            self.log_test("Admin Sees All iPads", True, f"Admin sees {admin_ipad_count} iPads")
        else:
            self.log_test("Admin Sees All iPads", False, "Admin failed to retrieve iPads")
            return False
        
        # Test admin can see all students
        response = self.make_request("GET", "/students", token=self.admin_token)
        if response and response.status_code == 200:
            admin_students = response.json()
            admin_student_count = len(admin_students)
            self.log_test("Admin Sees All Students", True, f"Admin sees {admin_student_count} students")
        else:
            self.log_test("Admin Sees All Students", False, "Admin failed to retrieve students")
            return False
        
        # Test user sees only their resources (should be empty for new user)
        response = self.make_request("GET", "/ipads", token=self.test_user_token)
        if response and response.status_code == 200:
            user_ipads = response.json()
            user_ipad_count = len(user_ipads)
            
            if user_ipad_count == 0:
                self.log_test("User Sees Only Own iPads", True, f"New user correctly sees 0 iPads (their own)")
            else:
                self.log_test("User Sees Only Own iPads", False, f"New user should see 0 iPads, but sees {user_ipad_count}")
        else:
            self.log_test("User Sees Only Own iPads", False, "User failed to retrieve iPads")
            return False
        
        response = self.make_request("GET", "/students", token=self.test_user_token)
        if response and response.status_code == 200:
            user_students = response.json()
            user_student_count = len(user_students)
            
            if user_student_count == 0:
                self.log_test("User Sees Only Own Students", True, f"New user correctly sees 0 students (their own)")
            else:
                self.log_test("User Sees Only Own Students", False, f"New user should see 0 students, but sees {user_student_count}")
        else:
            self.log_test("User Sees Only Own Students", False, "User failed to retrieve students")
            return False
        
        # Test IDOR protection - user cannot access admin's resources
        if admin_students:
            admin_student_id = admin_students[0]["id"]
            response = self.make_request("GET", f"/students/{admin_student_id}", token=self.test_user_token)
            
            if response and response.status_code == 403:
                self.log_test("IDOR Protection", True, "User correctly blocked from accessing admin's student (403 Forbidden)")
            else:
                self.log_test("IDOR Protection", False, f"Expected 403 for unauthorized access, got {response.status_code if response else 'No response'}")
        
        return True
    
    def test_user_deactivation(self):
        """Test user deactivation and login blocking"""
        print("\n=== Testing User Deactivation ===")
        
        # Test DELETE /api/admin/users/{user_id} - Deactivate user
        response = self.make_request("DELETE", f"/admin/users/{self.test_user_id}", token=self.admin_token)
        
        if not response or response.status_code != 200:
            self.log_test("Deactivate User", False, f"User deactivation failed with status {response.status_code if response else 'No response'}")
            return False
        
        try:
            data = response.json()
            
            if "message" not in data or "resources_preserved" not in data:
                self.log_test("Deactivate User", False, f"Invalid deactivation response: {data}")
                return False
            
            self.log_test("Deactivate User", True, f"Successfully deactivated user. Resources preserved: {data['resources_preserved']}")
        except Exception as e:
            self.log_test("Deactivate User", False, f"Error parsing deactivation response: {str(e)}")
            return False
        
        # Test deactivated user cannot login
        test_credentials = {"username": "rbactest", "password": "newpassword123"}
        response = self.make_request("POST", "/auth/login", data=test_credentials)
        
        if response and response.status_code == 401:
            self.log_test("Deactivated User Login Blocked", True, "Deactivated user correctly blocked from login")
        else:
            self.log_test("Deactivated User Login Blocked", False, f"Expected 401 for deactivated user login, got {response.status_code if response else 'No response'}")
        
        return True
    
    def run_all_tests(self):
        """Run all focused RBAC tests"""
        print("🔐 Focused RBAC Backend Testing Suite")
        print("=" * 50)
        
        # Step 1: Enhanced login
        if not self.test_enhanced_login():
            print("❌ Cannot proceed without admin login")
            return False
        
        # Step 2: Admin user management
        if not self.test_admin_user_management():
            print("❌ Admin user management failed")
            return False
        
        # Step 3: User login and authorization
        if not self.test_user_login_and_authorization():
            print("❌ User login and authorization failed")
            return False
        
        # Step 4: Basic resource isolation
        if not self.test_resource_isolation_basic():
            print("❌ Resource isolation failed")
            return False
        
        # Step 5: User deactivation
        if not self.test_user_deactivation():
            print("❌ User deactivation failed")
            return False
        
        return True
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 50)
        print("🔐 FOCUSED RBAC TESTING SUMMARY")
        print("=" * 50)
        
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

def main():
    """Main test execution"""
    tester = FocusedRBACTester()
    
    try:
        success = tester.run_all_tests()
        tester.print_summary()
        
        if success:
            print("\n🎉 All focused RBAC tests completed successfully!")
            return 0
        else:
            print("\n❌ Some RBAC tests failed!")
            return 1
            
    except KeyboardInterrupt:
        print("\n⚠️ Testing interrupted by user")
        return 1
    except Exception as e:
        print(f"\n💥 Unexpected error during testing: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())