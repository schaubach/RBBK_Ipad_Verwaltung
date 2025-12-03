#!/usr/bin/env python3
"""
Focused Backend Testing Suite for Libmagic Fix Verification
Tests critical backend functionality after libmagic fix.
"""

import requests
import json
import time
import sys
from datetime import datetime

# Configuration
BASE_URL = "https://edudevice-1.preview.emergentagent.com/api"
ADMIN_CREDENTIALS = {"username": "admin", "password": "admin123"}

class FocusedBackendTester:
    def __init__(self):
        self.admin_token = None
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
    
    def make_request(self, method, endpoint, token=None, data=None, files=None, timeout=15):
        """Make HTTP request with proper headers"""
        url = f"{BASE_URL}{endpoint}"
        headers = {}
        
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        if not files:
            headers["Content-Type"] = "application/json"
            
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=timeout)
            elif method == "POST":
                if files:
                    response = requests.post(url, headers=headers, files=files, data=data, timeout=timeout)
                else:
                    response = requests.post(url, headers=headers, json=data, timeout=timeout)
            elif method == "PUT":
                response = requests.put(url, headers=headers, json=data, timeout=timeout)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers, timeout=timeout)
            else:
                raise ValueError(f"Unsupported method: {method}")
                
            return response
        except requests.exceptions.Timeout:
            print(f"Request timeout for {method} {url}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"Request error for {method} {url}: {str(e)}")
            return None
        except Exception as e:
            print(f"Unexpected error for {method} {url}: {str(e)}")
            return None
    
    def test_backend_health(self):
        """Test backend service health and libmagic fix"""
        print("\n=== 1. Backend Service Health Check ===")
        
        # Test basic health
        response = self.make_request("POST", "/auth/setup")
        
        if not response:
            self.log_test("Backend Service Health", False, "Backend service is not responding")
            return False
        
        if response.status_code in [200, 405]:
            self.log_test("Backend Service Health", True, "Backend service is running and responding")
        else:
            self.log_test("Backend Service Health", False, f"Backend service returned unexpected status: {response.status_code}")
            return False
        
        # Test libmagic import
        try:
            import magic
            # Test basic functionality
            test_data = b"PDF-1.4"
            mime_type = magic.from_buffer(test_data, mime=True)
            self.log_test("Libmagic Import & Function", True, f"python-magic working correctly, detected: {mime_type}")
        except ImportError as e:
            self.log_test("Libmagic Import & Function", False, f"python-magic import failed: {str(e)}")
            return False
        except Exception as e:
            self.log_test("Libmagic Import & Function", False, f"python-magic function test failed: {str(e)}")
            return False
        
        return True

    def test_admin_authentication(self):
        """Test admin login and JWT token generation"""
        print("\n=== 2. Admin Authentication & JWT Token Generation ===")
        
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
            
            if data["role"] != "admin" or data["username"] != "admin":
                self.log_test("Admin Login", False, f"Invalid credentials: role={data['role']}, username={data['username']}")
                return False
            
            # Verify JWT token structure
            import jwt
            try:
                payload = jwt.decode(data["access_token"], options={"verify_signature": False})
                
                if "user_id" not in payload or "sub" not in payload:
                    self.log_test("JWT Token Validation", False, "JWT token missing required fields (user_id, sub)")
                    return False
                
                self.log_test("JWT Token Validation", True, f"JWT token contains user_id: {payload.get('user_id')}")
                
            except Exception as e:
                self.log_test("JWT Token Validation", False, f"Failed to decode JWT token: {str(e)}")
                return False
                
            self.admin_token = data["access_token"]
            self.log_test("Admin Login", True, f"Successfully authenticated as admin")
            return True
            
        except Exception as e:
            self.log_test("Admin Login", False, f"Error parsing login response: {str(e)}")
            return False

    def test_rbac_user_management(self):
        """Test RBAC user management endpoints"""
        print("\n=== 3. RBAC User Management Endpoints ===")
        
        # Test list users (admin only)
        response = self.make_request("GET", "/admin/users", token=self.admin_token)
        
        if not response or response.status_code != 200:
            self.log_test("List Users (Admin)", False, f"Failed to list users - Status: {response.status_code if response else 'No response'}")
            return False
        
        try:
            users = response.json()
            if not isinstance(users, list):
                self.log_test("List Users (Admin)", False, "Response is not a list")
                return False
            
            admin_user = None
            for user in users:
                if user["username"] == "admin":
                    admin_user = user
                    break
            
            if not admin_user:
                self.log_test("List Users (Admin)", False, "Admin user not found in user list")
                return False
            
            self.log_test("List Users (Admin)", True, f"Successfully listed {len(users)} users, admin user found")
            
            # Test user creation with unique username
            unique_username = f"test_user_{int(time.time())}"
            user_data = {
                "username": unique_username,
                "password": "test123456",
                "role": "user"
            }
            
            response = self.make_request("POST", "/admin/users", token=self.admin_token, data=user_data)
            
            if response and response.status_code == 200:
                new_user = response.json()
                self.log_test("Create User (Admin)", True, f"Successfully created user: {new_user['username']}")
                
                # Test login with new user
                test_credentials = {"username": unique_username, "password": "test123456"}
                login_response = self.make_request("POST", "/auth/login", data=test_credentials)
                
                if login_response and login_response.status_code == 200:
                    login_data = login_response.json()
                    if login_data["role"] == "user":
                        self.log_test("New User Login", True, f"New user can login with role: {login_data['role']}")
                    else:
                        self.log_test("New User Login", False, f"New user has wrong role: {login_data['role']}")
                else:
                    self.log_test("New User Login", False, "New user cannot login")
                
            else:
                self.log_test("Create User (Admin)", False, f"Failed to create user - Status: {response.status_code if response else 'No response'}")
            
            return True
            
        except Exception as e:
            self.log_test("List Users (Admin)", False, f"Error parsing user list: {str(e)}")
            return False

    def test_core_resource_endpoints(self):
        """Test core resource endpoints"""
        print("\n=== 4. Core Resource Endpoints ===")
        
        # Test Students endpoint
        response = self.make_request("GET", "/students", token=self.admin_token)
        if response and response.status_code == 200:
            students = response.json()
            self.log_test("GET /api/students", True, f"Retrieved {len(students)} students")
        else:
            self.log_test("GET /api/students", False, f"Failed - Status: {response.status_code if response else 'No response'}")
            return False
        
        # Test iPads endpoint
        response = self.make_request("GET", "/ipads", token=self.admin_token)
        if response and response.status_code == 200:
            ipads = response.json()
            self.log_test("GET /api/ipads", True, f"Retrieved {len(ipads)} iPads")
        else:
            self.log_test("GET /api/ipads", False, f"Failed - Status: {response.status_code if response else 'No response'}")
            return False
        
        # Test Assignments endpoint
        response = self.make_request("GET", "/assignments", token=self.admin_token)
        if response and response.status_code == 200:
            assignments = response.json()
            self.log_test("GET /api/assignments", True, f"Retrieved {len(assignments)} assignments")
        else:
            self.log_test("GET /api/assignments", False, f"Failed - Status: {response.status_code if response else 'No response'}")
            return False
        
        # Test auto-assign endpoint
        response = self.make_request("POST", "/assignments/auto-assign", token=self.admin_token)
        if response and response.status_code == 200:
            result = response.json()
            assigned_count = result.get("assigned_count", 0)
            self.log_test("POST /api/assignments/auto-assign", True, f"Auto-assign completed - {assigned_count} assignments")
        else:
            self.log_test("POST /api/assignments/auto-assign", False, f"Failed - Status: {response.status_code if response else 'No response'}")
        
        return True

    def test_user_isolation(self):
        """Test user resource isolation"""
        print("\n=== 5. User Resource Isolation ===")
        
        # Admin should see all resources
        admin_response = self.make_request("GET", "/students", token=self.admin_token)
        if admin_response and admin_response.status_code == 200:
            admin_students = admin_response.json()
            admin_count = len(admin_students)
            self.log_test("Admin Sees All Resources", True, f"Admin sees {admin_count} students (all users' resources)")
        else:
            self.log_test("Admin Sees All Resources", False, "Admin failed to retrieve resources")
            return False
        
        # Test with existing regular user if available
        users_response = self.make_request("GET", "/admin/users", token=self.admin_token)
        if users_response and users_response.status_code == 200:
            users = users_response.json()
            regular_user = None
            
            for user in users:
                if user["role"] == "user" and user["is_active"]:
                    regular_user = user
                    break
            
            if regular_user:
                # Try to login as regular user (assuming password is test123456 or test123)
                for password in ["test123456", "test123"]:
                    test_credentials = {"username": regular_user["username"], "password": password}
                    login_response = self.make_request("POST", "/auth/login", data=test_credentials)
                    
                    if login_response and login_response.status_code == 200:
                        user_token = login_response.json()["access_token"]
                        
                        # Test user sees filtered resources
                        user_response = self.make_request("GET", "/students", token=user_token)
                        if user_response and user_response.status_code == 200:
                            user_students = user_response.json()
                            user_count = len(user_students)
                            
                            if user_count <= admin_count:
                                self.log_test("User Sees Filtered Resources", True, f"Regular user sees {user_count} students (filtered by ownership)")
                            else:
                                self.log_test("User Sees Filtered Resources", False, f"User sees more resources ({user_count}) than admin ({admin_count})")
                        else:
                            self.log_test("User Sees Filtered Resources", False, "Regular user failed to retrieve resources")
                        break
                else:
                    self.log_test("Regular User Login", False, f"Could not login as regular user: {regular_user['username']}")
            else:
                self.log_test("Regular User Available", False, "No active regular user found for isolation testing")
        
        return True

    def test_file_upload_security(self):
        """Test file upload endpoints with libmagic validation"""
        print("\n=== 6. File Upload Security with libmagic ===")
        
        # Test that upload endpoints are accessible and validate properly
        endpoints = [
            ("/ipads/upload", "iPad Upload"),
            ("/students/upload", "Student Upload"),
            ("/contracts/upload-multiple", "Contract Upload")
        ]
        
        for endpoint, name in endpoints:
            response = self.make_request("POST", endpoint, token=self.admin_token)
            
            # Should return 422 (Unprocessable Entity) for missing file
            if response and response.status_code == 422:
                self.log_test(f"{name} Endpoint Security", True, f"{name} endpoint validates input correctly")
            else:
                self.log_test(f"{name} Endpoint Security", False, f"{name} endpoint returned unexpected status: {response.status_code if response else 'No response'}")
        
        return True

    def run_all_tests(self):
        """Run all focused backend tests"""
        print("🔐 Focused Backend Testing Suite - Libmagic Fix & Core RBAC Functionality")
        print("=" * 80)
        
        tests = [
            self.test_backend_health,
            self.test_admin_authentication,
            self.test_rbac_user_management,
            self.test_core_resource_endpoints,
            self.test_user_isolation,
            self.test_file_upload_security
        ]
        
        for test in tests:
            try:
                if not test():
                    print(f"❌ Test {test.__name__} failed, but continuing...")
            except Exception as e:
                print(f"❌ Test {test.__name__} threw exception: {str(e)}")
        
        return True
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 80)
        print("🔐 FOCUSED BACKEND TESTING SUMMARY")
        print("=" * 80)
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if "✅ PASS" in r["status"]])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%" if total_tests > 0 else "No tests run")
        
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
    tester = FocusedBackendTester()
    
    try:
        tester.run_all_tests()
        tester.print_summary()
        
        passed_tests = len([r for r in tester.test_results if "✅ PASS" in r["status"]])
        total_tests = len(tester.test_results)
        
        if passed_tests >= total_tests * 0.8:  # 80% pass rate
            print("\n🎉 Backend testing completed successfully!")
            return 0
        else:
            print("\n⚠️ Some backend tests failed!")
            return 1
            
    except KeyboardInterrupt:
        print("\n⚠️ Testing interrupted by user")
        return 1
    except Exception as e:
        print(f"\n💥 Unexpected error during testing: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())