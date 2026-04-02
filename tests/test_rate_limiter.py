"""
Test Suite: Rate Limiter
Tests adaptive rate limiting, burst detection, violation-adjusted thresholds
"""
import sys
import os
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from rate_limiter import AdaptiveRateLimiter
from storage import MemoryStorage


class TestBasicRateLimiting:
    """Test basic sliding window rate limiting"""

    def test_allows_under_limit(self, rate_limiter):
        """Requests under the limit should be allowed"""
        for i in range(5):
            is_limited, reason = rate_limiter.is_rate_limited("1.2.3.4")
            assert not is_limited

    def test_blocks_over_limit(self):
        """Requests over the limit should be blocked"""
        storage = MemoryStorage()
        limiter = AdaptiveRateLimiter(
            storage=storage,
            requests_per_window=5,
            window_seconds=60,
        )

        for i in range(5):
            limiter.is_rate_limited("10.0.0.1")

        is_limited, reason = limiter.is_rate_limited("10.0.0.1")
        assert is_limited
        assert "rate" in reason.lower() or "limit" in reason.lower()

    def test_different_ips_independent(self, rate_limiter):
        """Rate limits should be independent per IP"""
        for i in range(8):
            rate_limiter.is_rate_limited("ip1")

        # ip2 should not be affected
        is_limited, reason = rate_limiter.is_rate_limited("ip2")
        assert not is_limited


class TestBurstDetection:
    """Test burst detection"""

    def test_burst_detected(self):
        """Rapid requests within burst window should be detected"""
        storage = MemoryStorage()
        limiter = AdaptiveRateLimiter(
            storage=storage,
            requests_per_window=100,  # high overall limit
            window_seconds=60,
            burst_limit=3,
            burst_window_seconds=1,
        )

        for i in range(4):
            is_limited, reason = limiter.is_rate_limited("burst.ip")

        assert is_limited


class TestViolationBasedThrottling:
    """Test that violation history affects rate limit thresholds"""

    def test_violations_reduce_threshold(self):
        """IPs with violations should have lower rate limits"""
        storage = MemoryStorage()
        limiter = AdaptiveRateLimiter(
            storage=storage,
            requests_per_window=10,
            window_seconds=60,
        )

        # Add some violations
        for _ in range(5):
            storage.increment_violation_count("bad.ip")

        # The threshold should be lower for this IP
        allowed_count = 0
        for i in range(10):
            is_limited, reason = limiter.is_rate_limited("bad.ip")
            if not is_limited:
                allowed_count += 1

        # Should be blocked before reaching the full 10 requests
        assert allowed_count < 10
