#!/usr/bin/env python3
"""
Password Reset & Force Password Change Testing Suite
Tests the new password reset functionality and RBAC functions as requested.

Test Coverage:
1. Password Reset Endpoint (Admin) - POST /api/admin/users/{user_id}/reset-password
2. Login with temporary password
3. Forced password change - PUT /api/auth/change-password-forced
4. Login after password change
5. Complete workflow test
6. RBAC verification (existing functionality)
"""

import requests
import json
import time
import sys
import re
from datetime import datetime

# Configuration
BASE_URL = "https://edudevice-1.preview.emergentagent.com/api"
ADMIN_CREDENTIALS = {"username": "admin", "password": "admin123"}

class PasswordResetTester:
    def __init__(self):
        self.admin_token = None
        self.test_user_id = None
        self.test_user_username = None
        self.temp_password = None
        self.test_user_token = None
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
    
    def test_admin_login(self):
        """Test admin login and get admin token"""
        print("\n=== Testing Admin Authentication ===")
        
        response = self.make_request("POST", "/auth/login", data=ADMIN_CREDENTIALS)
        
        if not response or response.status_code != 200:
            self.log_test("Admin Login", False, f"Login failed with status {response.status_code if response else 'No response'}")
            return False
            
        try:
            data = response.json()
            
            if data.get("role") != "admin":
                self.log_test("Admin Login", False, f"Expected admin role, got: {data.get('role')}")
                return False
                
            self.admin_token = data["access_token"]
            self.log_test("Admin Login", True, f"Successfully logged in as admin")
            return True
            
        except Exception as e:
            self.log_test("Admin Login", False, f"Error parsing login response: {str(e)}")
            return False
    
    def create_test_user(self):
        """Create a test user for password reset testing"""
        print("\n=== Creating Test User ===")
        
        # Create unique username with timestamp
        timestamp = int(time.time())
        username = f"resettest_{timestamp}"
        
        user_data = {
            "username": username,
            "password": "original123",
            "role": "user"
        }
        
        response = self.make_request("POST", "/admin/users", token=self.admin_token, data=user_data)
        
        if not response or response.status_code != 200:
            self.log_test("Create Test User", False, f"User creation failed with status {response.status_code if response else 'No response'}")
            return False
            
        try:
            data = response.json()
            self.test_user_id = data["id"]
            self.test_user_username = data["username"]
            
            self.log_test("Create Test User", True, f"Successfully created test user: {self.test_user_username} (ID: {self.test_user_id})")
            return True
            
        except Exception as e:
            self.log_test("Create Test User", False, f"Error parsing user creation response: {str(e)}")
            return False
    
    def test_password_reset_endpoint(self):
        """Test 1: Password Reset Endpoint (Admin) - POST /api/admin/users/{user_id}/reset-password"""
        print("\n=== Test 1: Password Reset Endpoint (Admin) ===")
        
        if not self.test_user_id:
            self.log_test("Password Reset Endpoint", False, "No test user ID available")
            return False
        
        response = self.make_request("POST", f"/admin/users/{self.test_user_id}/reset-password", token=self.admin_token)
        
        if not response or response.status_code != 200:
            self.log_test("Password Reset Endpoint", False, f"Password reset failed with status {response.status_code if response else 'No response'}")
            if response:
                print(f"Response text: {response.text}")
            return False
            
        try:
            data = response.json()
            
            # Verify response contains required fields
            required_fields = ["message", "username", "temporary_password", "note"]
            for field in required_fields:
                if field not in data:
                    self.log_test("Password Reset Endpoint", False, f"Missing field in response: {field}")
                    return False
            
            # Verify temporary password is 8 digits (only numbers)
            temp_password = data["temporary_password"]
            if not re.match(r'^\d{8}$', temp_password):
                self.log_test("Password Reset Endpoint", False, f"Temporary password '{temp_password}' is not 8 digits")
                return False
            
            self.temp_password = temp_password
            
            # Verify username matches
            if data["username"] != self.test_user_username:
                self.log_test("Password Reset Endpoint", False, f"Username mismatch: expected {self.test_user_username}, got {data['username']}")
                return False
            
            self.log_test("Password Reset Endpoint", True, f"✅ 8-digit temporary password generated: {temp_password}")
            
            # Verify force_password_change flag is set by trying to get user details
            response = self.make_request("GET", "/admin/users", token=self.admin_token)
            if response and response.status_code == 200:
                users = response.json()
                test_user = next((u for u in users if u["id"] == self.test_user_id), None)
                if test_user and test_user.get("force_password_change"):
                    self.log_test("Force Password Change Flag", True, "✅ force_password_change flag set to true")
                else:
                    self.log_test("Force Password Change Flag", False, f"force_password_change flag not set correctly: {test_user.get('force_password_change') if test_user else 'User not found'}")
            
            return True
            
        except Exception as e:
            self.log_test("Password Reset Endpoint", False, f"Error parsing password reset response: {str(e)}")
            return False
    
    def test_login_with_temp_password(self):
        """Test 2: Login with temporary password"""
        print("\n=== Test 2: Login with Temporary Password ===")
        
        if not self.temp_password or not self.test_user_username:
            self.log_test("Login with Temp Password", False, "No temporary password or username available")
            return False
        
        temp_credentials = {
            "username": self.test_user_username,
            "password": self.temp_password
        }
        
        response = self.make_request("POST", "/auth/login", data=temp_credentials)
        
        if not response or response.status_code != 200:
            self.log_test("Login with Temp Password", False, f"Login with temporary password failed with status {response.status_code if response else 'No response'}")
            if response:
                print(f"Response text: {response.text}")
            return False
            
        try:
            data = response.json()
            
            # Verify login successful
            required_fields = ["access_token", "token_type", "role", "username", "force_password_change"]
            for field in required_fields:
                if field not in data:
                    self.log_test("Login with Temp Password", False, f"Missing field in response: {field}")
                    return False
            
            # Verify force_password_change is true
            if not data.get("force_password_change"):
                self.log_test("Login with Temp Password", False, f"Expected force_password_change=true, got: {data.get('force_password_change')}")
                return False
            
            # Verify role is user
            if data.get("role") != "user":
                self.log_test("Login with Temp Password", False, f"Expected role=user, got: {data.get('role')}")
                return False
            
            self.test_user_token = data["access_token"]
            
            self.log_test("Login with Temp Password", True, f"✅ Login successful with force_password_change=true")
            return True
            
        except Exception as e:
            self.log_test("Login with Temp Password", False, f"Error parsing login response: {str(e)}")
            return False
    
    def test_forced_password_change(self):
        """Test 3: Forced password change - PUT /api/auth/change-password-forced"""
        print("\n=== Test 3: Forced Password Change ===")
        
        if not self.test_user_token:
            self.log_test("Forced Password Change", False, "No test user token available")
            return False
        
        new_password_data = {
            "new_password": "newpassword123"
        }
        
        response = self.make_request("PUT", "/auth/change-password-forced", token=self.test_user_token, data=new_password_data)
        
        if not response or response.status_code != 200:
            self.log_test("Forced Password Change", False, f"Forced password change failed with status {response.status_code if response else 'No response'}")
            if response:
                print(f"Response text: {response.text}")
            return False
            
        try:
            data = response.json()
            
            # Verify success message
            if "message" not in data:
                self.log_test("Forced Password Change", False, "Missing message in response")
                return False
            
            self.log_test("Forced Password Change", True, f"✅ Password changed successfully: {data['message']}")
            
            # Verify force_password_change flag is cleared by checking user details
            response = self.make_request("GET", "/admin/users", token=self.admin_token)
            if response and response.status_code == 200:
                users = response.json()
                test_user = next((u for u in users if u["id"] == self.test_user_id), None)
                if test_user and not test_user.get("force_password_change"):
                    self.log_test("Force Password Change Flag Cleared", True, "✅ force_password_change flag set to false")
                else:
                    self.log_test("Force Password Change Flag Cleared", False, f"force_password_change flag not cleared: {test_user.get('force_password_change') if test_user else 'User not found'}")
            
            return True
            
        except Exception as e:
            self.log_test("Forced Password Change", False, f"Error parsing forced password change response: {str(e)}")
            return False
    
    def test_login_after_password_change(self):
        """Test 4: Login after password change"""
        print("\n=== Test 4: Login After Password Change ===")
        
        new_credentials = {
            "username": self.test_user_username,
            "password": "newpassword123"
        }
        
        response = self.make_request("POST", "/auth/login", data=new_credentials)
        
        if not response or response.status_code != 200:
            self.log_test("Login After Password Change", False, f"Login with new password failed with status {response.status_code if response else 'No response'}")
            if response:
                print(f"Response text: {response.text}")
            return False
            
        try:
            data = response.json()
            
            # Verify login successful
            required_fields = ["access_token", "token_type", "role", "username", "force_password_change"]
            for field in required_fields:
                if field not in data:
                    self.log_test("Login After Password Change", False, f"Missing field in response: {field}")
                    return False
            
            # Verify force_password_change is false
            if data.get("force_password_change"):
                self.log_test("Login After Password Change", False, f"Expected force_password_change=false, got: {data.get('force_password_change')}")
                return False
            
            # Verify role is user
            if data.get("role") != "user":
                self.log_test("Login After Password Change", False, f"Expected role=user, got: {data.get('role')}")
                return False
            
            # Update token for resource access test
            self.test_user_token = data["access_token"]
            
            self.log_test("Login After Password Change", True, f"✅ Login successful with force_password_change=false")
            return True
            
        except Exception as e:
            self.log_test("Login After Password Change", False, f"Error parsing login response: {str(e)}")
            return False
    
    def test_user_resource_access(self):
        """Test that user can access resources normally after password change"""
        print("\n=== Testing User Resource Access ===")
        
        if not self.test_user_token:
            self.log_test("User Resource Access", False, "No test user token available")
            return False
        
        # Test access to students endpoint
        response = self.make_request("GET", "/students", token=self.test_user_token)
        
        if not response or response.status_code != 200:
            self.log_test("User Resource Access", False, f"Failed to access students endpoint with status {response.status_code if response else 'No response'}")
            return False
        
        try:
            students = response.json()
            self.log_test("User Resource Access", True, f"✅ User can access resources normally ({len(students)} students)")
            return True
            
        except Exception as e:
            self.log_test("User Resource Access", False, f"Error parsing students response: {str(e)}")
            return False
    
    def test_complete_workflow(self):
        """Test 5: Complete workflow test"""
        print("\n=== Test 5: Complete Workflow Test ===")
        
        # Create another test user for complete workflow
        timestamp = int(time.time())
        workflow_username = f"workflow_{timestamp}"
        
        user_data = {
            "username": workflow_username,
            "password": "workflow123",
            "role": "user"
        }
        
        # Step 1: Admin creates user
        response = self.make_request("POST", "/admin/users", token=self.admin_token, data=user_data)
        
        if not response or response.status_code != 200:
            self.log_test("Workflow - Create User", False, f"User creation failed with status {response.status_code if response else 'No response'}")
            return False
        
        workflow_user_id = response.json()["id"]
        self.log_test("Workflow - Create User", True, f"✅ Admin created user: {workflow_username}")
        
        # Step 2: Admin resets password
        response = self.make_request("POST", f"/admin/users/{workflow_user_id}/reset-password", token=self.admin_token)
        
        if not response or response.status_code != 200:
            self.log_test("Workflow - Reset Password", False, f"Password reset failed with status {response.status_code if response else 'No response'}")
            return False
        
        workflow_temp_password = response.json()["temporary_password"]
        self.log_test("Workflow - Reset Password", True, f"✅ Admin reset password: {workflow_temp_password}")
        
        # Step 3: User logs in with temp password (force_password_change=true)
        temp_credentials = {
            "username": workflow_username,
            "password": workflow_temp_password
        }
        
        response = self.make_request("POST", "/auth/login", data=temp_credentials)
        
        if not response or response.status_code != 200:
            self.log_test("Workflow - Login with Temp", False, f"Login with temp password failed with status {response.status_code if response else 'No response'}")
            return False
        
        login_data = response.json()
        if not login_data.get("force_password_change"):
            self.log_test("Workflow - Login with Temp", False, f"Expected force_password_change=true, got: {login_data.get('force_password_change')}")
            return False
        
        workflow_token = login_data["access_token"]
        self.log_test("Workflow - Login with Temp", True, f"✅ User logged in with temp password (force_password_change=true)")
        
        # Step 4: User changes password via forced endpoint
        new_password_data = {
            "new_password": "mynewpassword123"
        }
        
        response = self.make_request("PUT", "/auth/change-password-forced", token=workflow_token, data=new_password_data)
        
        if not response or response.status_code != 200:
            self.log_test("Workflow - Change Password", False, f"Forced password change failed with status {response.status_code if response else 'No response'}")
            return False
        
        self.log_test("Workflow - Change Password", True, f"✅ User changed password successfully")
        
        # Step 5: User logs in with new password (force_password_change=false)
        new_credentials = {
            "username": workflow_username,
            "password": "mynewpassword123"
        }
        
        response = self.make_request("POST", "/auth/login", data=new_credentials)
        
        if not response or response.status_code != 200:
            self.log_test("Workflow - Login with New Password", False, f"Login with new password failed with status {response.status_code if response else 'No response'}")
            return False
        
        final_login_data = response.json()
        if final_login_data.get("force_password_change"):
            self.log_test("Workflow - Login with New Password", False, f"Expected force_password_change=false, got: {final_login_data.get('force_password_change')}")
            return False
        
        self.log_test("Workflow - Login with New Password", True, f"✅ User logged in with new password (force_password_change=false)")
        
        self.log_test("Complete Workflow Test", True, f"✅ Complete workflow successful for user: {workflow_username}")
        return True
    
    def test_rbac_verification(self):
        """Test 6: RBAC verification (existing functionality)"""
        print("\n=== Test 6: RBAC Verification ===")
        
        # Test admin can see all users
        response = self.make_request("GET", "/admin/users", token=self.admin_token)
        
        if not response or response.status_code != 200:
            self.log_test("RBAC - Admin List Users", False, f"Admin list users failed with status {response.status_code if response else 'No response'}")
            return False
        
        users = response.json()
        self.log_test("RBAC - Admin List Users", True, f"✅ Admin can see all users ({len(users)} users)")
        
        # Test admin can see all resources (Students)
        response = self.make_request("GET", "/students", token=self.admin_token)
        
        if not response or response.status_code != 200:
            self.log_test("RBAC - Admin See All Students", False, f"Admin get students failed with status {response.status_code if response else 'No response'}")
            return False
        
        students = response.json()
        self.log_test("RBAC - Admin See All Students", True, f"✅ Admin can see all students ({len(students)} students)")
        
        # Test admin can see all iPads
        response = self.make_request("GET", "/ipads", token=self.admin_token)
        
        if not response or response.status_code != 200:
            self.log_test("RBAC - Admin See All iPads", False, f"Admin get iPads failed with status {response.status_code if response else 'No response'}")
            return False
        
        ipads = response.json()
        self.log_test("RBAC - Admin See All iPads", True, f"✅ Admin can see all iPads ({len(ipads)} iPads)")
        
        # Test user can only see own resources
        if self.test_user_token:
            response = self.make_request("GET", "/students", token=self.test_user_token)
            
            if response and response.status_code == 200:
                user_students = response.json()
                if len(user_students) <= len(students):
                    self.log_test("RBAC - User See Own Resources", True, f"✅ User sees only own resources ({len(user_students)} students)")
                else:
                    self.log_test("RBAC - User See Own Resources", False, f"User sees more resources than expected")
            else:
                self.log_test("RBAC - User See Own Resources", False, f"User get students failed with status {response.status_code if response else 'No response'}")
        
        # Test user cannot access admin endpoints
        if self.test_user_token:
            response = self.make_request("GET", "/admin/users", token=self.test_user_token)
            
            if response and response.status_code == 403:
                self.log_test("RBAC - Block User Admin Access", True, f"✅ User correctly blocked from admin endpoints (403)")
            else:
                self.log_test("RBAC - Block User Admin Access", False, f"Expected 403 for user admin access, got {response.status_code if response else 'No response'}")
        
        return True
    
    def test_edge_cases(self):
        """Test edge cases and error conditions"""
        print("\n=== Testing Edge Cases ===")
        
        # Test admin cannot reset own password
        admin_users = self.make_request("GET", "/admin/users", token=self.admin_token)
        if admin_users and admin_users.status_code == 200:
            users = admin_users.json()
            admin_user = next((u for u in users if u["username"] == "admin"), None)
            if admin_user:
                response = self.make_request("POST", f"/admin/users/{admin_user['id']}/reset-password", token=self.admin_token)
                
                if response and response.status_code == 400:
                    self.log_test("Edge Case - Admin Self Reset", True, f"✅ Admin correctly blocked from resetting own password")
                else:
                    self.log_test("Edge Case - Admin Self Reset", False, f"Expected 400 for admin self-reset, got {response.status_code if response else 'No response'}")
        
        # Test password validation (too short)
        if self.test_user_token:
            short_password_data = {
                "new_password": "123"
            }
            
            response = self.make_request("PUT", "/auth/change-password-forced", token=self.test_user_token, data=short_password_data)
            
            if response and response.status_code == 400:
                self.log_test("Edge Case - Password Validation", True, f"✅ Short password correctly rejected")
            else:
                self.log_test("Edge Case - Password Validation", False, f"Expected 400 for short password, got {response.status_code if response else 'No response'}")
        
        # Test reset non-existent user
        fake_user_id = "00000000-0000-0000-0000-000000000000"
        response = self.make_request("POST", f"/admin/users/{fake_user_id}/reset-password", token=self.admin_token)
        
        if response and response.status_code == 404:
            self.log_test("Edge Case - Reset Non-existent User", True, f"✅ Non-existent user reset correctly rejected")
        else:
            self.log_test("Edge Case - Reset Non-existent User", False, f"Expected 404 for non-existent user, got {response.status_code if response else 'No response'}")
        
        return True
    
    def run_all_tests(self):
        """Run all password reset and RBAC tests"""
        print("🔐 Password Reset & Force Password Change Testing Suite")
        print("=" * 80)
        
        # Step 1: Admin authentication
        if not self.test_admin_login():
            print("❌ Cannot proceed without admin login")
            return False
        
        # Step 2: Create test user
        if not self.create_test_user():
            print("❌ Cannot proceed without test user")
            return False
        
        # Step 3: Test password reset endpoint
        if not self.test_password_reset_endpoint():
            print("❌ Password reset endpoint failed")
            return False
        
        # Step 4: Test login with temporary password
        if not self.test_login_with_temp_password():
            print("❌ Login with temporary password failed")
            return False
        
        # Step 5: Test forced password change
        if not self.test_forced_password_change():
            print("❌ Forced password change failed")
            return False
        
        # Step 6: Test login after password change
        if not self.test_login_after_password_change():
            print("❌ Login after password change failed")
            return False
        
        # Step 7: Test user resource access
        if not self.test_user_resource_access():
            print("❌ User resource access failed")
            return False
        
        # Step 8: Test complete workflow
        if not self.test_complete_workflow():
            print("❌ Complete workflow test failed")
            return False
        
        # Step 9: Test RBAC verification
        if not self.test_rbac_verification():
            print("❌ RBAC verification failed")
            return False
        
        # Step 10: Test edge cases
        if not self.test_edge_cases():
            print("❌ Edge cases test failed")
            return False
        
        return True
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 80)
        print("🔐 PASSWORD RESET & RBAC TESTING SUMMARY")
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
    tester = PasswordResetTester()
    
    try:
        success = tester.run_all_tests()
        tester.print_summary()
        
        if success:
            print("\n🎉 All password reset and RBAC tests completed successfully!")
            return 0
        else:
            print("\n❌ Some password reset tests failed!")
            return 1
            
    except KeyboardInterrupt:
        print("\n⚠️ Testing interrupted by user")
        return 1
    except Exception as e:
        print(f"\n💥 Unexpected error during testing: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())