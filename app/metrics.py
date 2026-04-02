"""
Enhanced Prometheus Metrics Module v2.0
=======================================
Improvements over v1.0:
- Decision distribution metrics (allow/log/challenge/block counts)
- Anomaly detection score histogram
- Cache hit/miss ratio metrics
- Pipeline stage timing metrics
- Signal category distribution
"""
import time
import threading
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class MetricsCollector:
    """Collects and exposes WAF metrics in Prometheus format"""

    # Counters
    _requests_total: int = 0
    _requests_blocked: int = 0
    _requests_allowed: int = 0

    # By attack type
    _blocked_by_type: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # By severity
    _blocked_by_severity: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Rate limiting
    _rate_limited_total: int = 0

    # Decision distribution (v2.0)
    _decisions: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Signal category distribution (v2.0)
    _signal_categories: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Anomaly scores (v2.0)
    _anomaly_scores: list = field(default_factory=list)

    # Cache metrics (v2.0)
    _cache_hits: int = 0
    _cache_misses: int = 0

    # Pipeline stage timings (v2.0)
    _stage_timings: Dict[str, list] = field(default_factory=lambda: defaultdict(list))

    # Response times (histogram buckets)
    _response_times: list = field(default_factory=list)

    # Current state
    _blocked_ips_count: int = 0
    _permanent_blocks_count: int = 0

    # Rule reload count (v2.0)
    _rule_reloads: int = 0

    # Lock for thread safety
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # Start time
    _start_time: float = field(default_factory=time.time)

    def record_request(
        self,
        blocked: bool,
        attack_type: Optional[str] = None,
        severity: Optional[str] = None,
        response_time: Optional[float] = None,
        rate_limited: bool = False
    ):
        """Record a request"""
        with self._lock:
            self._requests_total += 1

            if blocked:
                self._requests_blocked += 1
                if attack_type:
                    self._blocked_by_type[attack_type] += 1
                if severity:
                    self._blocked_by_severity[severity] += 1
            else:
                self._requests_allowed += 1

            if rate_limited:
                self._rate_limited_total += 1

            if response_time is not None:
                self._response_times.append(response_time)
                if len(self._response_times) > 1000:
                    self._response_times = self._response_times[-1000:]

    def record_decision(self, action: str, score: float = 0.0):
        """Record a decision engine result (v2.0)"""
        with self._lock:
            self._decisions[action] = self._decisions.get(action, 0) + 1

    def record_signal(self, category: str):
        """Record a signal category occurrence (v2.0)"""
        with self._lock:
            self._signal_categories[category] = self._signal_categories.get(category, 0) + 1

    def record_anomaly_score(self, score: float):
        """Record an anomaly detection score (v2.0)"""
        with self._lock:
            self._anomaly_scores.append(score)
            if len(self._anomaly_scores) > 1000:
                self._anomaly_scores = self._anomaly_scores[-1000:]

    def record_cache_access(self, hit: bool):
        """Record a cache hit or miss (v2.0)"""
        with self._lock:
            if hit:
                self._cache_hits += 1
            else:
                self._cache_misses += 1

    def record_stage_timing(self, stage_name: str, duration_ms: float):
        """Record pipeline stage timing (v2.0)"""
        with self._lock:
            self._stage_timings[stage_name].append(duration_ms)
            if len(self._stage_timings[stage_name]) > 500:
                self._stage_timings[stage_name] = self._stage_timings[stage_name][-500:]

    def record_rule_reload(self):
        """Record a rule reload event (v2.0)"""
        with self._lock:
            self._rule_reloads += 1

    def update_state(self, blocked_ips: int, permanent_blocks: int):
        """Update current state metrics"""
        with self._lock:
            self._blocked_ips_count = blocked_ips
            self._permanent_blocks_count = permanent_blocks

    def get_prometheus_metrics(self) -> str:
        """Generate Prometheus-compatible metrics output"""
        with self._lock:
            lines = []

            # Request counters
            lines.append("# HELP waf_requests_total Total number of requests processed")
            lines.append("# TYPE waf_requests_total counter")
            lines.append(f"waf_requests_total {self._requests_total}")

            lines.append("# HELP waf_requests_blocked_total Total number of blocked requests")
            lines.append("# TYPE waf_requests_blocked_total counter")
            lines.append(f"waf_requests_blocked_total {self._requests_blocked}")

            lines.append("# HELP waf_requests_allowed_total Total number of allowed requests")
            lines.append("# TYPE waf_requests_allowed_total counter")
            lines.append(f"waf_requests_allowed_total {self._requests_allowed}")

            lines.append("# HELP waf_rate_limited_total Total number of rate limited requests")
            lines.append("# TYPE waf_rate_limited_total counter")
            lines.append(f"waf_rate_limited_total {self._rate_limited_total}")

            # Blocked by attack type
            lines.append("# HELP waf_blocked_by_type_total Blocked requests by attack type")
            lines.append("# TYPE waf_blocked_by_type_total counter")
            for attack_type, count in self._blocked_by_type.items():
                lines.append(f'waf_blocked_by_type_total{{type="{attack_type}"}} {count}')

            # Blocked by severity
            lines.append("# HELP waf_blocked_by_severity_total Blocked requests by severity")
            lines.append("# TYPE waf_blocked_by_severity_total counter")
            for severity, count in self._blocked_by_severity.items():
                lines.append(f'waf_blocked_by_severity_total{{severity="{severity}"}} {count}')

            # Decision distribution (v2.0)
            lines.append("# HELP waf_decisions_total Decision distribution")
            lines.append("# TYPE waf_decisions_total counter")
            for action, count in self._decisions.items():
                lines.append(f'waf_decisions_total{{action="{action}"}} {count}')

            # Signal categories (v2.0)
            lines.append("# HELP waf_signals_total Signal category distribution")
            lines.append("# TYPE waf_signals_total counter")
            for category, count in self._signal_categories.items():
                lines.append(f'waf_signals_total{{category="{category}"}} {count}')

            # Cache metrics (v2.0)
            lines.append("# HELP waf_cache_hits_total Cache hit count")
            lines.append("# TYPE waf_cache_hits_total counter")
            lines.append(f"waf_cache_hits_total {self._cache_hits}")

            lines.append("# HELP waf_cache_misses_total Cache miss count")
            lines.append("# TYPE waf_cache_misses_total counter")
            lines.append(f"waf_cache_misses_total {self._cache_misses}")

            cache_total = self._cache_hits + self._cache_misses
            cache_rate = (self._cache_hits / cache_total * 100) if cache_total > 0 else 0
            lines.append("# HELP waf_cache_hit_rate Cache hit rate percentage")
            lines.append("# TYPE waf_cache_hit_rate gauge")
            lines.append(f"waf_cache_hit_rate {cache_rate:.1f}")

            # Rule reloads (v2.0)
            lines.append("# HELP waf_rule_reloads_total Rule reload count")
            lines.append("# TYPE waf_rule_reloads_total counter")
            lines.append(f"waf_rule_reloads_total {self._rule_reloads}")

            # Current state gauges
            lines.append("# HELP waf_blocked_ips_current Current number of temporarily blocked IPs")
            lines.append("# TYPE waf_blocked_ips_current gauge")
            lines.append(f"waf_blocked_ips_current {self._blocked_ips_count}")

            lines.append("# HELP waf_permanent_blocks_current Current number of permanently blocked IPs")
            lines.append("# TYPE waf_permanent_blocks_current gauge")
            lines.append(f"waf_permanent_blocks_current {self._permanent_blocks_count}")

            # Response time histogram
            if self._response_times:
                lines.append("# HELP waf_response_time_seconds Response time in seconds")
                lines.append("# TYPE waf_response_time_seconds histogram")

                buckets = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
                for bucket in buckets:
                    cumulative = sum(1 for t in self._response_times if t <= bucket)
                    lines.append(f'waf_response_time_seconds_bucket{{le="{bucket}"}} {cumulative}')
                lines.append(f'waf_response_time_seconds_bucket{{le="+Inf"}} {len(self._response_times)}')
                lines.append(f"waf_response_time_seconds_sum {sum(self._response_times):.6f}")
                lines.append(f"waf_response_time_seconds_count {len(self._response_times)}")

            # Pipeline stage timing averages (v2.0)
            if self._stage_timings:
                lines.append("# HELP waf_stage_avg_ms Average pipeline stage processing time in ms")
                lines.append("# TYPE waf_stage_avg_ms gauge")
                for stage, timings in self._stage_timings.items():
                    if timings:
                        avg = sum(timings) / len(timings)
                        lines.append(f'waf_stage_avg_ms{{stage="{stage}"}} {avg:.2f}')

            # Uptime
            uptime = time.time() - self._start_time
            lines.append("# HELP waf_uptime_seconds WAF uptime in seconds")
            lines.append("# TYPE waf_uptime_seconds gauge")
            lines.append(f"waf_uptime_seconds {uptime:.2f}")

            # Block rate
            if self._requests_total > 0:
                block_rate = (self._requests_blocked / self._requests_total) * 100
            else:
                block_rate = 0
            lines.append("# HELP waf_block_rate_percent Percentage of requests blocked")
            lines.append("# TYPE waf_block_rate_percent gauge")
            lines.append(f"waf_block_rate_percent {block_rate:.2f}")

            return "\n".join(lines) + "\n"

    def get_json_metrics(self) -> Dict[str, Any]:
        """Get metrics as JSON (for dashboard API)"""
        with self._lock:
            avg_response_time = (
                sum(self._response_times) / len(self._response_times)
                if self._response_times else 0
            )

            cache_total = self._cache_hits + self._cache_misses

            return {
                "requests": {
                    "total": self._requests_total,
                    "blocked": self._requests_blocked,
                    "allowed": self._requests_allowed,
                    "rate_limited": self._rate_limited_total,
                },
                "blocked_by_type": dict(self._blocked_by_type),
                "blocked_by_severity": dict(self._blocked_by_severity),
                "decisions": dict(self._decisions),
                "signal_categories": dict(self._signal_categories),
                "cache": {
                    "hits": self._cache_hits,
                    "misses": self._cache_misses,
                    "hit_rate_percent": round(
                        (self._cache_hits / cache_total * 100) if cache_total > 0 else 0, 1
                    ),
                },
                "state": {
                    "blocked_ips": self._blocked_ips_count,
                    "permanent_blocks": self._permanent_blocks_count,
                },
                "performance": {
                    "avg_response_time_ms": avg_response_time * 1000,
                    "samples": len(self._response_times),
                },
                "rule_reloads": self._rule_reloads,
                "uptime_seconds": time.time() - self._start_time,
                "block_rate_percent": (
                    (self._requests_blocked / self._requests_total) * 100
                    if self._requests_total > 0 else 0
                ),
            }


# Global metrics collector instance
metrics = MetricsCollector()


def get_metrics() -> MetricsCollector:
    """Get the global metrics collector"""
    return metrics
