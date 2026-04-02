"""
Rate Limiter Module for WAF
Implements token bucket and sliding window algorithms
"""
import time
from typing import Tuple, Optional
from storage import StorageBackend


class RateLimiter:
    """
    Rate limiter using sliding window algorithm
    Supports both regular rate limiting and burst detection
    """
    
    def __init__(
        self,
        storage: StorageBackend,
        requests_per_window: int = 100,
        window_seconds: int = 60,
        burst_limit: int = 20,
        burst_window_seconds: int = 5
    ):
        self.storage = storage
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.burst_limit = burst_limit
        self.burst_window_seconds = burst_window_seconds
    
    def is_rate_limited(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        Check if the IP is rate limited
        Returns (is_limited, reason)
        """
        current_time = time.time()
        
        # Add current request to rate limit tracking
        self.storage.add_rate_limit_entry(ip, current_time)
        
        # Check burst limit (short window)
        burst_window_start = current_time - self.burst_window_seconds
        burst_count = self.storage.get_rate_limit_count(ip, burst_window_start)
        
        if burst_count > self.burst_limit:
            return True, f"Burst limit exceeded: {burst_count}/{self.burst_limit} requests in {self.burst_window_seconds}s"
        
        # Check regular rate limit (longer window)
        window_start = current_time - self.window_seconds
        request_count = self.storage.get_rate_limit_count(ip, window_start)
        
        if request_count > self.requests_per_window:
            return True, f"Rate limit exceeded: {request_count}/{self.requests_per_window} requests in {self.window_seconds}s"
        
        return False, None
    
    def get_remaining_requests(self, ip: str) -> int:
        """Get remaining requests in the current window"""
        window_start = time.time() - self.window_seconds
        current_count = self.storage.get_rate_limit_count(ip, window_start)
        return max(0, self.requests_per_window - current_count)
    
    def get_reset_time(self, ip: str) -> float:
        """Get time until the rate limit resets"""
        return self.window_seconds


class AdaptiveRateLimiter(RateLimiter):
    """
    Adaptive rate limiter that adjusts limits based on behavior
    More aggressive rate limiting for IPs with violations
    """
    
    def __init__(
        self,
        storage: StorageBackend,
        requests_per_window: int = 100,
        window_seconds: int = 60,
        burst_limit: int = 20,
        burst_window_seconds: int = 5
    ):
        super().__init__(
            storage,
            requests_per_window,
            window_seconds,
            burst_limit,
            burst_window_seconds
        )
    
    def is_rate_limited(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        Check rate limit with adaptive thresholds based on violation history
        """
        violation_count = self.storage.get_violation_count(ip)
        
        # Reduce limits based on violation history
        if violation_count > 0:
            # Reduce limits by 20% for each violation, minimum 10% of original
            reduction_factor = max(0.1, 1 - (violation_count * 0.2))
            effective_requests = int(self.requests_per_window * reduction_factor)
            effective_burst = int(self.burst_limit * reduction_factor)
        else:
            effective_requests = self.requests_per_window
            effective_burst = self.burst_limit
        
        current_time = time.time()
        self.storage.add_rate_limit_entry(ip, current_time)
        
        # Check burst limit
        burst_window_start = current_time - self.burst_window_seconds
        burst_count = self.storage.get_rate_limit_count(ip, burst_window_start)
        
        if burst_count > effective_burst:
            return True, f"Burst limit exceeded: {burst_count}/{effective_burst} requests in {self.burst_window_seconds}s (adjusted for {violation_count} violations)"
        
        # Check regular rate limit
        window_start = current_time - self.window_seconds
        request_count = self.storage.get_rate_limit_count(ip, window_start)
        
        if request_count > effective_requests:
            return True, f"Rate limit exceeded: {request_count}/{effective_requests} requests in {self.window_seconds}s (adjusted for {violation_count} violations)"
        
        return False, None
