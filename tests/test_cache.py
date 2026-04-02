"""
Test Suite: Verdict Cache
Tests LRU eviction, TTL expiry, invalidation, and statistics
"""
import sys
import os
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from cache import VerdictCache


class TestCachePut:
    """Test cache insertion"""

    def test_put_and_get(self, verdict_cache):
        verdict_cache.put("test payload", "params", {"blocked": False})
        result = verdict_cache.get("test payload", "params")
        assert result is not None
        assert result["blocked"] is False

    def test_put_overwrite(self, verdict_cache):
        verdict_cache.put("key", "ctx", "value1")
        verdict_cache.put("key", "ctx", "value2")
        assert verdict_cache.get("key", "ctx") == "value2"


class TestCacheMiss:
    """Test cache miss scenarios"""

    def test_miss_on_unknown_key(self, verdict_cache):
        result = verdict_cache.get("nonexistent", "")
        assert result is None

    def test_miss_when_disabled(self):
        cache = VerdictCache(enabled=False)
        cache.put("key", "", "value")
        assert cache.get("key", "") is None


class TestCacheTTL:
    """Test cache TTL expiration"""

    def test_expired_entry_returns_none(self):
        cache = VerdictCache(max_size=100, ttl=1, enabled=True)
        cache.put("key", "", "value")

        # Should still be there
        assert cache.get("key", "") == "value"

        # Wait for expiry
        time.sleep(1.5)
        assert cache.get("key", "") is None


class TestLRUEviction:
    """Test LRU eviction when cache is full"""

    def test_evicts_oldest_at_capacity(self):
        cache = VerdictCache(max_size=3, ttl=300, enabled=True)

        cache.put("a", "", "1")
        cache.put("b", "", "2")
        cache.put("c", "", "3")
        # Cache is full, adding one more should evict "a"
        cache.put("d", "", "4")

        assert cache.get("a", "") is None  # evicted
        assert cache.get("b", "") == "2"   # still there
        assert cache.get("d", "") == "4"   # newest

    def test_access_refreshes_position(self):
        cache = VerdictCache(max_size=3, ttl=300, enabled=True)

        cache.put("a", "", "1")
        cache.put("b", "", "2")
        cache.put("c", "", "3")

        # Access "a" to refresh it
        cache.get("a", "")

        # Now adding "d" should evict "b" (oldest non-accessed)
        cache.put("d", "", "4")

        assert cache.get("a", "") == "1"  # refreshed, still here
        assert cache.get("b", "") is None  # evicted


class TestCacheInvalidation:
    """Test cache clearing"""

    def test_invalidate_all(self, verdict_cache):
        verdict_cache.put("a", "", "1")
        verdict_cache.put("b", "", "2")
        verdict_cache.invalidate_all()

        assert verdict_cache.get("a", "") is None
        assert verdict_cache.get("b", "") is None

    def test_cleanup_expired(self):
        cache = VerdictCache(max_size=100, ttl=1, enabled=True)
        cache.put("a", "", "1")
        cache.put("b", "", "2")
        time.sleep(1.5)
        cache.cleanup_expired()

        stats = cache.get_stats()
        assert stats["size"] == 0


class TestCacheStatistics:
    """Test cache statistics"""

    def test_stats_tracking(self, verdict_cache):
        verdict_cache.put("key", "", "value")
        verdict_cache.get("key", "")    # hit
        verdict_cache.get("miss", "")   # miss

        stats = verdict_cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["hit_rate_percent"] == 50.0
        assert stats["size"] == 1

    def test_reset_stats(self, verdict_cache):
        verdict_cache.put("key", "", "value")
        verdict_cache.get("key", "")
        verdict_cache.reset_stats()

        stats = verdict_cache.get_stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 0


class TestCacheContext:
    """Test that context separates cache entries"""

    def test_same_payload_different_context(self, verdict_cache):
        verdict_cache.put("payload", "params", "result_params")
        verdict_cache.put("payload", "body", "result_body")

        assert verdict_cache.get("payload", "params") == "result_params"
        assert verdict_cache.get("payload", "body") == "result_body"
