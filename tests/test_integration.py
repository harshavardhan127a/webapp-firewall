"""
Test Suite: Integration Tests
Full pipeline tests: attack simulation, multi-stage probing, credential stuffing
"""
import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from waf_engine import WAFEngine, get_all_signals
from decision_engine import (
    DecisionEngine, Signal, SignalCategory, Action,
    risk_signals_to_engine_signals,
)
from anomaly_detector import StatisticalDetector, extract_features
from bot_detector import BehavioralBotDetector
from cache import VerdictCache
from rule_manager import RuleManager
from schema_validator import SchemaValidator


class TestDetectionPipelineIntegration:
    """Test the full detection → scoring → decision pipeline"""

    @pytest.fixture
    def engine(self):
        return WAFEngine(paranoia_level=2)

    def _make_decision(self, engine, request_data, bot_detector=None, ip="1.2.3.4"):
        """Run the full pipeline on a request"""
        de = DecisionEngine(
            block_threshold=80, challenge_threshold=40, log_threshold=15,
        )

        # Pattern detection
        signals = get_all_signals(request_data)
        if signals:
            de.add_signals(risk_signals_to_engine_signals(signals))

        # Bot detection
        if bot_detector:
            bot_score, bot_indicators = bot_detector.analyze(ip, request_data)
            if bot_score > 0:
                de.add_signal(Signal(
                    category=SignalCategory.BEHAVIORAL,
                    source="bot_detector",
                    score=bot_score,
                    confidence=0.8 if bot_score > 50 else 0.4,
                    severity="high" if bot_score > 70 else "medium",
                ))

        return de.evaluate()

    def test_sqli_detected_and_blocked(self, engine):
        """SQL injection should be detected and result in BLOCK"""
        request_data = {
            'headers': {'User-Agent': 'Mozilla/5.0'},
            'params': {'id': "' OR '1'='1"},
            'body': '', 'path': '/api/users', 'method': 'GET',
        }
        decision = self._make_decision(engine, request_data)
        assert decision.action == Action.BLOCK
        assert 'sql' in decision.top_threat.lower()

    def test_xss_detected_and_blocked(self, engine):
        """XSS should be detected and result in BLOCK"""
        request_data = {
            'headers': {'User-Agent': 'Mozilla/5.0'},
            'params': {'q': "<script>alert('XSS')</script>"},
            'body': '', 'path': '/search', 'method': 'GET',
        }
        decision = self._make_decision(engine, request_data)
        assert decision.action == Action.BLOCK

    def test_scanner_detected_and_flagged(self, engine):
        """Scanner User-Agent should be detected and at minimum flagged"""
        request_data = {
            'headers': {'User-Agent': 'sqlmap/1.0'},
            'params': {}, 'body': '', 'path': '/test', 'method': 'GET',
        }
        # WAF engine directly detects scanners
        result = engine.check_request(request_data)
        assert result.is_malicious, "Scanner should be detected by WAF engine"

        # Through the decision engine, scanner signals score based on severity
        decision = self._make_decision(engine, request_data)
        assert decision.action != Action.ALLOW, "Scanner should not be ALLOW"
        assert decision.total_score > 0
        assert "scanner" in decision.top_threat.lower()

    def test_legitimate_request_allowed(self, engine):
        """Normal request should be allowed"""
        request_data = {
            'headers': {'User-Agent': 'Mozilla/5.0'},
            'params': {'q': 'hello world'},
            'body': '', 'path': '/search', 'method': 'GET',
        }
        decision = self._make_decision(engine, request_data)
        assert decision.action in (Action.ALLOW, Action.LOG)

    def test_encoded_sqli_detected(self, engine):
        """URL-encoded SQL injection should still be detected"""
        request_data = {
            'headers': {'User-Agent': 'Mozilla/5.0'},
            'params': {'id': "%27%20OR%20%271%27%3D%271"},
            'body': '', 'path': '/api/users', 'method': 'GET',
        }
        decision = self._make_decision(engine, request_data)
        assert decision.action == Action.BLOCK


class TestMultiStageAttackSimulation:
    """Simulate multi-stage attack scenarios"""

    def test_reconnaissance_then_exploit(self):
        """
        Stage 1: Scanner probing (should be caught by bot detection)
        Stage 2: SQL injection attempt (should be caught by rule detection)
        """
        engine = WAFEngine(paranoia_level=2)
        bot_detector = BehavioralBotDetector()
        ip = "attacker.ip"

        # Stage 1: Reconnaissance
        recon_paths = ['/admin', '/wp-admin', '/phpmyadmin', '/login',
                       '/.env', '/api/debug', '/api/docs', '/api/swagger']

        for path in recon_paths:
            request_data = {
                'headers': {'User-Agent': 'Mozilla/5.0'},
                'params': {}, 'body': '', 'path': path, 'method': 'GET',
            }
            bot_detector.analyze(ip, request_data)

        # Stage 2: Attack
        attack_data = {
            'headers': {'User-Agent': 'Mozilla/5.0'},
            'params': {'id': "' UNION SELECT * FROM users--"},
            'body': '', 'path': '/api/users', 'method': 'GET',
        }

        de = DecisionEngine(block_threshold=80, challenge_threshold=40)

        signals = get_all_signals(attack_data)
        if signals:
            de.add_signals(risk_signals_to_engine_signals(signals))

        bot_score, indicators = bot_detector.analyze(ip, attack_data)
        if bot_score > 0:
            de.add_signal(Signal(
                category=SignalCategory.BEHAVIORAL,
                source="bot_detector",
                score=bot_score,
                confidence=0.8,
                severity="high",
            ))

        decision = de.evaluate()
        # Should definitely be blocked (rule match + behavioral)
        assert decision.action == Action.BLOCK
        assert decision.total_score > 80


class TestSchemaValidationIntegration:
    """Test schema validation in the detection pipeline"""

    def test_valid_body_passes(self, schema_validator):
        errors = schema_validator.validate("POST /api/login", {
            "username": "john", "password": "secureP@ss123"
        })
        assert len(errors) == 0

    def test_missing_required_field_fails(self, schema_validator):
        errors = schema_validator.validate("POST /api/login", {
            "username": "john"
        })
        assert len(errors) > 0
        assert any("password" in str(e) for e in errors)

    def test_invalid_type_fails(self, schema_validator):
        errors = schema_validator.validate("POST /api/login", {
            "username": 12345, "password": "pass"
        })
        assert len(errors) > 0

    def test_unknown_endpoint_skips_validation(self, schema_validator):
        errors = schema_validator.validate("GET /unknown", {"anything": "goes"})
        assert len(errors) == 0


class TestRuleManagerIntegration:
    """Test rule manager hot-reload integration"""

    def test_load_rules(self, rule_manager):
        patterns = rule_manager.get_patterns("sql_injection")
        assert len(patterns) > 0

    def test_reload_detects_changes(self, rule_manager, tmp_path):
        import json
        rules_file = tmp_path / "test_rules.json"
        # Write new rules
        rules_file.write_text(json.dumps({
            "version": "test-2.0",
            "sql_injection": {
                "enabled": True,
                "severity": "critical",
                "patterns": [
                    "(union\\s+select)",
                    "(;\\s*drop\\s+table)",
                    "(sleep\\s*\\()",  # New pattern
                ],
            },
        }))

        success, messages = rule_manager.reload_rules()
        assert success

    def test_rollback(self, rule_manager, tmp_path):
        import json

        # Get initial version
        status1 = rule_manager.get_status()
        v1 = status1["version"]

        # Modify and reload
        rules_file = tmp_path / "test_rules.json"
        rules_file.write_text(json.dumps({
            "version": "test-rollback",
            "sql_injection": {
                "enabled": True,
                "patterns": ["(union)"],
            },
        }))
        rule_manager.reload_rules()

        status2 = rule_manager.get_status()
        assert status2["version"] == "test-rollback"

        # Rollback
        success = rule_manager.rollback()
        assert success

        status3 = rule_manager.get_status()
        assert status3["version"] == v1

    def test_invalid_regex_rejected(self, tmp_path):
        import json
        rules_file = tmp_path / "bad_rules.json"
        rules_file.write_text(json.dumps({
            "version": "bad",
            "sql_injection": {
                "enabled": True,
                "patterns": [
                    "valid_pattern",
                    "([invalid",  # Bad regex
                ],
            },
        }))

        rm = RuleManager(rules_path=str(rules_file))
        ruleset = rm.load_rules()
        # Should still load, but skip the invalid pattern
        patterns = rm.get_patterns("sql_injection")
        assert len(patterns) == 1  # Only the valid one


class TestCacheIntegration:
    """Test verdict cache integration with detection"""

    def test_cache_speeds_up_repeated_checks(self):
        engine = WAFEngine(paranoia_level=2)
        cache = VerdictCache(max_size=100, ttl=60, enabled=True)

        payload = "hello world"
        context = "params"

        # First check — cache miss
        result = cache.get(payload, context)
        assert result is None

        # Perform detection
        request_data = {
            'headers': {}, 'params': {'q': payload},
            'body': '', 'path': '/', 'method': 'GET',
        }
        detection = engine.check_request(request_data)
        cache.put(payload, context, detection)

        # Second check — cache hit
        cached = cache.get(payload, context)
        assert cached is not None
        assert cached.is_malicious == detection.is_malicious

    def test_cache_invalidation_on_rule_change(self):
        cache = VerdictCache(max_size=100, ttl=60, enabled=True)
        cache.put("test", "", "verdict")
        assert cache.get("test", "") == "verdict"

        cache.invalidate_all()
        assert cache.get("test", "") is None
