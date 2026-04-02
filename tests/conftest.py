"""
Shared pytest fixtures for WAF test suite
"""
import sys
import os
import pytest

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))


@pytest.fixture
def waf_engine():
    """Create a WAF engine instance"""
    from waf_engine import WAFEngine
    return WAFEngine(paranoia_level=2)


@pytest.fixture
def decision_engine():
    """Create a fresh decision engine"""
    from decision_engine import DecisionEngine
    return DecisionEngine(
        block_threshold=80.0,
        challenge_threshold=40.0,
        log_threshold=15.0,
    )


@pytest.fixture
def anomaly_detector():
    """Create a statistical anomaly detector"""
    from anomaly_detector import StatisticalDetector
    return StatisticalDetector(anomaly_threshold=60.0)


@pytest.fixture
def verdict_cache():
    """Create a verdict cache"""
    from cache import VerdictCache
    return VerdictCache(max_size=100, ttl=5, enabled=True)


@pytest.fixture
def bot_detector():
    """Create a behavioral bot detector"""
    from bot_detector import BehavioralBotDetector
    return BehavioralBotDetector()


@pytest.fixture
def schema_validator():
    """Create a schema validator with test schemas"""
    from schema_validator import SchemaValidator
    sv = SchemaValidator()
    sv.register("POST /api/login", {
        "type": "object",
        "required": ["username", "password"],
        "properties": {
            "username": {"type": "string", "maxLength": 100},
            "password": {"type": "string", "minLength": 8},
        },
    })
    return sv


@pytest.fixture
def rule_manager(tmp_path):
    """Create a rule manager with a temp rules file"""
    import json
    rules_file = tmp_path / "test_rules.json"
    rules_file.write_text(json.dumps({
        "version": "test-1.0",
        "sql_injection": {
            "enabled": True,
            "severity": "critical",
            "confidence": 0.85,
            "patterns": [
                "(union\\s+select)",
                "(;\\s*drop\\s+table)",
            ],
        },
        "xss": {
            "enabled": True,
            "severity": "high",
            "confidence": 0.8,
            "patterns": [
                "(<script[^>]*>)",
                "(onerror\\s*=)",
            ],
        },
    }))

    from rule_manager import RuleManager
    rm = RuleManager(rules_path=str(rules_file))
    rm.load_rules()
    return rm


@pytest.fixture
def rate_limiter():
    """Create a rate limiter with in-memory storage"""
    from storage import MemoryStorage
    from rate_limiter import AdaptiveRateLimiter
    storage = MemoryStorage()
    return AdaptiveRateLimiter(
        storage=storage,
        requests_per_window=10,
        window_seconds=60,
        burst_limit=5,
        burst_window_seconds=5
    )


@pytest.fixture
def memory_storage():
    """Create in-memory storage"""
    from storage import MemoryStorage
    return MemoryStorage()


@pytest.fixture
def sample_request_data():
    """Standard benign request data"""
    return {
        'headers': {'User-Agent': 'Mozilla/5.0 TestBrowser', 'Accept': 'text/html'},
        'params': {'q': 'hello world'},
        'body': '',
        'path': '/search',
        'method': 'GET',
    }


@pytest.fixture
def sqli_request_data():
    """SQL injection attack request"""
    return {
        'headers': {'User-Agent': 'Mozilla/5.0'},
        'params': {'id': "' OR '1'='1"},
        'body': '',
        'path': '/api/users',
        'method': 'GET',
    }


@pytest.fixture
def xss_request_data():
    """XSS attack request"""
    return {
        'headers': {'User-Agent': 'Mozilla/5.0'},
        'params': {'q': "<script>alert('XSS')</script>"},
        'body': '',
        'path': '/search',
        'method': 'GET',
    }
