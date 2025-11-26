#!/usr/bin/env python3

import requests
import sys
import json
from datetime import datetime

class SOCIOCAnalyzerTester:
    def __init__(self, base_url="https://threat-intel-hub-9.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name, success, details=None, error=None):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name} - PASSED")
        else:
            print(f"❌ {name} - FAILED: {error or 'Unknown error'}")
        
        self.test_results.append({
            'test_name': name,
            'success': success,
            'details': details,
            'error': error
        })

    def run_test(self, name, method, endpoint, expected_status, data=None, timeout=30):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=timeout)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=timeout)
            else:
                raise ValueError(f"Unsupported method: {method}")

            success = response.status_code == expected_status
            
            if success:
                try:
                    response_data = response.json()
                    self.log_test(name, True, response_data)
                    return True, response_data
                except json.JSONDecodeError:
                    self.log_test(name, True, {"raw_response": response.text})
                    return True, {"raw_response": response.text}
            else:
                error_msg = f"Expected {expected_status}, got {response.status_code}"
                try:
                    error_details = response.json()
                    error_msg += f" - {error_details}"
                except:
                    error_msg += f" - {response.text}"
                
                self.log_test(name, False, error=error_msg)
                return False, {}

        except requests.exceptions.Timeout:
            self.log_test(name, False, error=f"Request timeout after {timeout}s")
            return False, {}
        except requests.exceptions.ConnectionError:
            self.log_test(name, False, error="Connection error - server may be down")
            return False, {}
        except Exception as e:
            self.log_test(name, False, error=str(e))
            return False, {}

    def test_health_check(self):
        """Test health check endpoint"""
        success, response = self.run_test(
            "Health Check",
            "GET",
            "health",
            200
        )
        
        if success and 'services' in response:
            print(f"   API Keys Status:")
            for service, available in response['services'].items():
                status = "✅" if available else "❌"
                print(f"     {service}: {status}")
        
        return success

    def test_ioc_detection(self):
        """Test IOC detection for various types"""
        test_cases = [
            ("IP Address Detection", "8.8.8.8", "ipv4", "ip"),
            ("Domain Detection", "google.com", "domain", "domain"),
            ("URL Detection", "https://example.com", "url", "url"),
            ("Email Detection", "test@example.com", "email", "email"),
            ("MD5 Hash Detection", "5d41402abc4b2a76b9719d911017c592", "md5", "hash"),
            ("SHA1 Hash Detection", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", "sha1", "hash"),
            ("SHA256 Hash Detection", "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", "sha256", "hash"),
        ]
        
        all_passed = True
        
        for test_name, ioc, expected_type, expected_category in test_cases:
            success, response = self.run_test(
                test_name,
                "POST",
                "detect",
                200,
                data={"ioc": ioc}
            )
            
            if success:
                if (response.get('ioc_type') == expected_type and 
                    response.get('category') == expected_category):
                    print(f"   ✅ Correctly detected as {expected_type} ({expected_category})")
                else:
                    print(f"   ❌ Expected {expected_type}/{expected_category}, got {response.get('ioc_type')}/{response.get('category')}")
                    all_passed = False
            else:
                all_passed = False
        
        return all_passed

    def test_single_ioc_analysis(self):
        """Test single IOC analysis"""
        test_cases = [
            ("IP Analysis (8.8.8.8)", "8.8.8.8"),
            ("Domain Analysis (google.com)", "google.com"),
        ]
        
        all_passed = True
        
        for test_name, ioc in test_cases:
            success, response = self.run_test(
                test_name,
                "POST",
                "analyze",
                200,
                data={"ioc": ioc},
                timeout=60  # Longer timeout for analysis
            )
            
            if success:
                # Validate response structure
                required_fields = ['ioc', 'ioc_type', 'category', 'vendor_results', 'summary']
                missing_fields = [field for field in required_fields if field not in response]
                
                if missing_fields:
                    print(f"   ❌ Missing fields: {missing_fields}")
                    all_passed = False
                else:
                    print(f"   ✅ Analysis complete - Threat Level: {response['summary'].get('threat_level', 'unknown')}")
                    print(f"   📊 Vendor Results: {len(response['vendor_results'])} sources")
                    
                    # Check vendor results
                    successful_vendors = [v for v in response['vendor_results'] if v['status'] == 'success']
                    print(f"   🔍 Successful queries: {len(successful_vendors)}")
            else:
                all_passed = False
        
        return all_passed

    def test_bulk_analysis(self):
        """Test bulk IOC analysis"""
        test_iocs = ["8.8.8.8", "google.com", "1.1.1.1"]
        
        success, response = self.run_test(
            "Bulk Analysis",
            "POST",
            "analyze/bulk",
            200,
            data={"iocs": test_iocs},
            timeout=120  # Longer timeout for bulk analysis
        )
        
        if success:
            if 'results' in response and 'total' in response:
                print(f"   ✅ Analyzed {response['total']} IOCs")
                print(f"   📊 Results count: {len(response['results'])}")
                
                # Check each result structure
                for i, result in enumerate(response['results']):
                    if 'error' in result:
                        print(f"   ⚠️  IOC {i+1} had error: {result['error']}")
                    else:
                        threat_level = result.get('summary', {}).get('threat_level', 'unknown')
                        print(f"   🔍 IOC {i+1} ({result.get('ioc', 'unknown')}): {threat_level}")
                
                return True
            else:
                print(f"   ❌ Invalid response structure")
                return False
        
        return False

    def test_error_handling(self):
        """Test error handling for invalid inputs"""
        error_tests = [
            ("Empty IOC Detection", "detect", {"ioc": ""}),
            ("Invalid IOC Detection", "detect", {"ioc": "invalid_ioc_12345"}),
            ("Empty IOC Analysis", "analyze", {"ioc": ""}),
            ("Invalid IOC Analysis", "analyze", {"ioc": "invalid_ioc_12345"}),
            ("Empty Bulk Analysis", "analyze/bulk", {"iocs": []}),
            ("Too Many IOCs", "analyze/bulk", {"iocs": ["test"] * 25}),
        ]
        
        all_passed = True
        
        for test_name, endpoint, data in error_tests:
            success, response = self.run_test(
                test_name,
                "POST",
                endpoint,
                400,  # Expecting 400 Bad Request
                data=data
            )
            
            if not success:
                # For error tests, we expect them to fail with 400
                # Check if we got the expected error status
                all_passed = False
        
        return all_passed

    def run_all_tests(self):
        """Run all tests"""
        print("🚀 Starting SOC IOC Analyzer Backend Tests")
        print("=" * 60)
        
        # Test health check first
        if not self.test_health_check():
            print("\n❌ Health check failed - stopping tests")
            return False
        
        # Test IOC detection
        print(f"\n{'='*60}")
        print("🔍 Testing IOC Detection")
        self.test_ioc_detection()
        
        # Test single IOC analysis
        print(f"\n{'='*60}")
        print("🔬 Testing Single IOC Analysis")
        self.test_single_ioc_analysis()
        
        # Test bulk analysis
        print(f"\n{'='*60}")
        print("📊 Testing Bulk IOC Analysis")
        self.test_bulk_analysis()
        
        # Test error handling
        print(f"\n{'='*60}")
        print("⚠️  Testing Error Handling")
        self.test_error_handling()
        
        # Print final results
        print(f"\n{'='*60}")
        print("📋 FINAL TEST RESULTS")
        print(f"Tests Run: {self.tests_run}")
        print(f"Tests Passed: {self.tests_passed}")
        print(f"Success Rate: {(self.tests_passed/self.tests_run*100):.1f}%")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests passed!")
            return True
        else:
            print(f"❌ {self.tests_run - self.tests_passed} tests failed")
            return False

def main():
    tester = SOCIOCAnalyzerTester()
    success = tester.run_all_tests()
    
    # Save detailed results
    results = {
        'timestamp': datetime.now().isoformat(),
        'total_tests': tester.tests_run,
        'passed_tests': tester.tests_passed,
        'success_rate': (tester.tests_passed/tester.tests_run*100) if tester.tests_run > 0 else 0,
        'test_details': tester.test_results
    }
    
    with open('/app/backend_test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n📄 Detailed results saved to: /app/backend_test_results.json")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())