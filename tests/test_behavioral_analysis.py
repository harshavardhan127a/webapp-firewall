"""
Test Suite: Behavioral Bot Detection v2.0
Tests slow-attack detection, session fingerprinting, sequential enumeration
"""
import sys
import os
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from bot_detector import BehavioralBotDetector


class TestBasicBehavior:
    """Test basic behavioral signals"""

    def test_no_score_for_first_request(self, bot_detector):
        score, indicators = bot_detector.analyze("1.2.3.4", {
            'headers': {'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html',
                        'Accept-Language': 'en-US', 'Accept-Encoding': 'gzip'},
            'path': '/', 'method': 'GET',
        })
        # First request with all proper headers should have low/zero score
        assert score < 30

    def test_missing_headers_increases_score(self, bot_detector):
        score, indicators = bot_detector.analyze("5.6.7.8", {
            'headers': {'User-Agent': 'curl/7.68'},
            'path': '/', 'method': 'GET',
        })
        assert score > 0
        assert 'missing_accept_language' in indicators or 'missing_accept' in indicators

    def test_path_scanning_detection(self, bot_detector):
        """Visiting many unique paths raises suspicion"""
        ip = "10.0.0.1"
        for i in range(15):
            score, indicators = bot_detector.analyze(ip, {
                'headers': {'User-Agent': 'Mozilla/5.0'},
                'path': f'/unique/path/{i}', 'method': 'GET',
            })

        assert score > 10
        assert 'path_scanning' in indicators or 'high_path_diversity' in indicators

    def test_method_enumeration(self, bot_detector):
        """Using many HTTP methods raises suspicion"""
        ip = "10.0.0.2"
        for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']:
            score, indicators = bot_detector.analyze(ip, {
                'headers': {'User-Agent': 'Mozilla/5.0'},
                'path': '/api', 'method': method,
            })

        assert 'method_enumeration' in indicators or 'unusual_method_variety' in indicators


class TestSessionFingerprinting:
    """Test session fingerprint consistency (v2.0)"""

    def test_consistent_fingerprint_ok(self, bot_detector):
        """Same headers across requests should not flag"""
        ip = "10.0.0.3"
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'text/html',
            'Accept-Language': 'en-US',
            'Accept-Encoding': 'gzip',
        }
        for i in range(10):
            score, indicators = bot_detector.analyze(ip, {
                'headers': headers, 'path': f'/page/{i}', 'method': 'GET',
            })

        assert 'header_fingerprint_inconsistency' not in indicators

    def test_inconsistent_fingerprint_detected(self, bot_detector):
        """Changing header sets across requests should flag"""
        ip = "10.0.0.4"
        header_sets = [
            {'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html'},
            {'User-Agent': 'Mozilla/5.0', 'Accept-Language': 'en', 'Accept-Encoding': 'gzip'},
            {'User-Agent': 'Chrome', 'cache-control': 'no-cache'},
            {'User-Agent': 'Firefox', 'dnt': '1'},
            {'User-Agent': 'Safari', 'Accept': 'application/json', 'Accept-Language': 'fr'},
            {'User-Agent': 'Edge', 'sec-ch-ua': '"Chromium"'},
        ]
        indicators = []
        for i, headers in enumerate(header_sets):
            score, indicators = bot_detector.analyze(ip, {
                'headers': headers, 'path': f'/page/{i}', 'method': 'GET',
            })

        assert 'header_fingerprint_inconsistency' in indicators


class TestSequentialEnumeration:
    """Test sequential endpoint enumeration (v2.0)"""

    def test_sequential_ids_detected(self, bot_detector):
        """Accessing /user/1, /user/2, /user/3, ... should flag"""
        ip = "10.0.0.5"
        indicators = []
        for i in range(10):
            score, indicators = bot_detector.analyze(ip, {
                'headers': {'User-Agent': 'Mozilla/5.0'},
                'path': f'/api/users/{i}', 'method': 'GET',
            })

        assert 'sequential_enumeration' in indicators

    def test_random_ids_not_flagged(self, bot_detector):
        """Accessing non-sequential IDs should not flag"""
        ip = "10.0.0.6"
        ids = [42, 1337, 7, 999, 55]
        indicators = []
        for user_id in ids:
            score, indicators = bot_detector.analyze(ip, {
                'headers': {'User-Agent': 'Mozilla/5.0'},
                'path': f'/api/users/{user_id}', 'method': 'GET',
            })

        assert 'sequential_enumeration' not in indicators


class TestSlowAttackDetection:
    """Test slow credential stuffing and admin probing (v2.0)"""

    def test_login_attempt_tracking(self, bot_detector):
        """Many POST /login requests should flag credential stuffing"""
        ip = "10.0.0.7"
        indicators = []
        for i in range(25):
            score, indicators = bot_detector.analyze(ip, {
                'headers': {'User-Agent': 'Mozilla/5.0'},
                'path': '/login', 'method': 'POST',
            })

        assert score > 0
        assert 'credential_stuffing' in indicators or 'suspicious_login_volume' in indicators

    def test_sensitive_endpoint_probing(self, bot_detector):
        """Hitting many sensitive endpoints should flag"""
        ip = "10.0.0.8"
        sensitive_paths = [
            '/admin', '/login', '/api/users', '/api/auth',
            '/admin', '/wp-admin', '/login', '/admin',
            '/api/token', '/signin', '/admin', '/login',
        ]
        indicators = []
        for path in sensitive_paths:
            score, indicators = bot_detector.analyze(ip, {
                'headers': {'User-Agent': 'Mozilla/5.0'},
                'path': path, 'method': 'GET',
            })

        assert 'sensitive_endpoint_probing' in indicators

    def test_normal_browsing_not_flagged(self, bot_detector):
        """Normal browsing patterns should not trigger slow-attack"""
        ip = "10.0.0.9"
        paths = ['/home', '/about', '/products', '/contact', '/faq']
        indicators = []
        for path in paths:
            score, indicators = bot_detector.analyze(ip, {
                'headers': {'User-Agent': 'Mozilla/5.0',
                            'Accept': 'text/html', 'Accept-Language': 'en'},
                'path': path, 'method': 'GET',
            })

        assert 'credential_stuffing' not in indicators
        assert 'sensitive_endpoint_probing' not in indicators


class TestMultiUserAgent:
    """Test multiple User-Agent detection (v2.0)"""

    def test_multiple_user_agents(self, bot_detector):
        """Same IP with different User-Agents should flag"""
        ip = "10.0.0.10"
        agents = [
            'Mozilla/5.0 (Windows)', 'Mozilla/5.0 (Mac)',
            'curl/7.68', 'python-requests/2.28',
        ]
        indicators = []
        for ua in agents:
            score, indicators = bot_detector.analyze(ip, {
                'headers': {'User-Agent': ua},
                'path': '/test', 'method': 'GET',
            })

        assert 'multiple_user_agents' in indicators


class TestSessionInfo:
    """Test session info retrieval"""

    def test_get_session_info(self, bot_detector):
        bot_detector.analyze("6.7.8.9", {
            'headers': {'User-Agent': 'test'}, 'path': '/', 'method': 'GET',
        })
        info = bot_detector.get_session_info("6.7.8.9")
        assert info['request_count'] == 1
        assert 'score' in info

    def test_unknown_ip_empty_info(self, bot_detector):
        info = bot_detector.get_session_info("unknown")
        assert info == {}


class TestCleanup:
    """Test session cleanup"""

    def test_cleanup_removes_stale(self, bot_detector):
        bot_detector.analyze("old.ip", {
            'headers': {'User-Agent': 'test'}, 'path': '/', 'method': 'GET',
        })
        # Manually expire the session
        bot_detector._session_data["old.ip"]["last_request"] = time.time() - 7200
        bot_detector.cleanup(max_age_minutes=30)
        assert "old.ip" not in bot_detector._session_data
