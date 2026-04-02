"""
LRU Verdict Cache v1.0
======================
Thread-safe LRU cache for WAF payload verdicts.

Eliminates redundant detection processing for repeated payloads
(e.g., pagination params, boolean values, common search terms).

Features:
- O(1) lookup and insertion using OrderedDict
- TTL-based expiration (stale verdicts auto-expire)
- Cache invalidation on rule reload
- Thread-safe via RLock
- Configurable max size to bound memory
- Cache statistics (hit/miss ratio)
"""
import time
import hashlib
import threading
from collections import OrderedDict
from typing import Optional, Any, Dict, Tuple
from dataclasses import dataclass


@dataclass
class CacheEntry:
    """A cached verdict"""
    value: Any
    expires_at: float
    created_at: float


class VerdictCache:
    """
    LRU cache with TTL for WAF payload verdicts.

    Usage:
        cache = VerdictCache(max_size=10000, ttl=300)

        # Check cache
        result = cache.get(payload, context)
        if result is not None:
            return result  # cache hit

        # Compute verdict...
        verdict = engine.check(payload)

        # Store in cache
        cache.put(payload, context, verdict)
    """

    def __init__(self, max_size: int = 10000, ttl: int = 300, enabled: bool = True):
        """
        Args:
            max_size: Maximum number of entries
            ttl: Time-to-live in seconds for each entry
            enabled: Whether caching is active
        """
        self.max_size = max_size
        self.ttl = ttl
        self.enabled = enabled
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()

        # Statistics
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._invalidations = 0

    @staticmethod
    def _make_key(payload: str, context: str = "") -> str:
        """
        Create a cache key from payload + context.
        Uses SHA-256 to handle long payloads efficiently.
        """
        raw = f"{context}:{payload}"
        return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:32]

    def get(self, payload: str, context: str = "") -> Optional[Any]:
        """
        Look up a cached verdict.

        Args:
            payload: The payload string to look up
            context: Where in the request (params, body, etc.)

        Returns:
            Cached verdict if found and not expired, else None
        """
        if not self.enabled:
            return None

        key = self._make_key(payload, context)

        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None

            # Check TTL
            if time.time() > entry.expires_at:
                # Expired — remove and return miss
                del self._cache[key]
                self._misses += 1
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self._hits += 1
            return entry.value

    def put(self, payload: str, context: str, value: Any):
        """
        Store a verdict in the cache.

        Args:
            payload: The payload string
            context: Where in the request
            value: The verdict to cache
        """
        if not self.enabled:
            return

        key = self._make_key(payload, context)
        now = time.time()

        with self._lock:
            # If key exists, update it
            if key in self._cache:
                self._cache.move_to_end(key)
                self._cache[key] = CacheEntry(
                    value=value, expires_at=now + self.ttl, created_at=now
                )
                return

            # Evict oldest if at capacity
            while len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)
                self._evictions += 1

            self._cache[key] = CacheEntry(
                value=value, expires_at=now + self.ttl, created_at=now
            )

    def invalidate_all(self):
        """
        Clear the entire cache. Call this after rule reload
        to ensure stale verdicts don't persist.
        """
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._invalidations += count

    def cleanup_expired(self):
        """Remove expired entries (call periodically)"""
        now = time.time()
        with self._lock:
            # Iterate from oldest
            expired_keys = [
                k for k, v in self._cache.items() if now > v.expires_at
            ]
            for k in expired_keys:
                del self._cache[k]

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0.0
            return {
                "enabled": self.enabled,
                "size": len(self._cache),
                "max_size": self.max_size,
                "ttl": self.ttl,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_percent": round(hit_rate, 1),
                "evictions": self._evictions,
                "invalidations": self._invalidations,
            }

    def reset_stats(self):
        """Reset statistics counters"""
        with self._lock:
            self._hits = 0
            self._misses = 0
            self._evictions = 0
            self._invalidations = 0


# =============================================================================
# Module-level cache instance
# =============================================================================

_verdict_cache: Optional[VerdictCache] = None


def get_verdict_cache(
    max_size: int = 10000, ttl: int = 300, enabled: bool = True
) -> VerdictCache:
    """Get or create the global verdict cache"""
    global _verdict_cache
    if _verdict_cache is None:
        _verdict_cache = VerdictCache(max_size=max_size, ttl=ttl, enabled=enabled)
    return _verdict_cache
