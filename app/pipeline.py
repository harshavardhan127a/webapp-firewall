"""
WAF Pipeline Architecture v1.0
===============================
Implements a chain-of-responsibility pattern for request processing.

Each stage processes a RequestContext and either:
  - Adds signals/metadata to the context
  - Short-circuits with a BLOCK/CHALLENGE decision
  - Passes to the next stage

Pipeline stages (in order):
  1. NormalizationStage   — deep payload normalization
  2. ValidationStage      — input validation (size, JSON, schema, file upload)
  3. RuleEngineStage      — pattern-based attack detection
  4. AnomalyStage         — statistical anomaly detection
  5. BehavioralStage      — bot/behavioral analysis
  6. DecisionStage        — centralized decision engine
  7. LoggingStage         — structured logging of decision

Benefits:
  - Each stage is independently testable
  - Stages can be added/removed via configuration
  - RequestContext carries all state — no globals
  - Short-circuit on early block (e.g., permanent ban) avoids wasted computation
"""
import time
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field


@dataclass
class RequestContext:
    """
    Carries all request data and accumulated state through the pipeline.
    Created once per request, passed to each stage.
    """
    # --- Original request data ---
    client_ip: str = ""
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = ""

    # --- Normalized versions ---
    normalized_params: str = ""
    normalized_body: str = ""

    # --- Accumulated signals (from all stages) ---
    signals: List[Any] = field(default_factory=list)

    # --- Decision (set by DecisionStage) ---
    decision: Optional[Any] = None  # Decision object

    # --- Metadata ---
    correlation_id: str = ""
    start_time: float = field(default_factory=time.time)
    processing_times: Dict[str, float] = field(default_factory=dict)

    # --- Short-circuit flag ---
    short_circuit: bool = False
    short_circuit_response: Optional[tuple] = None  # (body, status_code)
    short_circuit_reason: str = ""

    # --- Flags ---
    is_whitelisted: bool = False
    skip_detection: bool = False

    def elapsed_ms(self) -> float:
        """Total elapsed time since request started"""
        return (time.time() - self.start_time) * 1000

    def as_request_data(self) -> Dict[str, Any]:
        """Convert to the dict format expected by WAFEngine"""
        return {
            "headers": self.headers,
            "params": self.params,
            "body": self.body,
            "path": self.path,
            "method": self.method,
        }


class PipelineStage(ABC):
    """Base class for pipeline stages"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable stage name for logging"""
        pass

    @abstractmethod
    def process(self, ctx: RequestContext) -> RequestContext:
        """
        Process the request context.

        Args:
            ctx: The request context to process

        Returns:
            The (possibly modified) context.
            Set ctx.short_circuit = True to stop the pipeline.
        """
        pass

    @property
    def enabled(self) -> bool:
        return True


class WAFPipeline:
    """
    Executes an ordered list of PipelineStages on a RequestContext.

    Usage:
        pipeline = WAFPipeline()
        pipeline.add_stage(NormalizationStage())
        pipeline.add_stage(ValidationStage())
        pipeline.add_stage(RuleEngineStage(engine))
        pipeline.add_stage(AnomalyStage(detector))
        pipeline.add_stage(BehavioralStage(bot_detector))
        pipeline.add_stage(DecisionStage(decision_engine))
        pipeline.add_stage(LoggingStage(logger))

        ctx = RequestContext(client_ip="1.2.3.4", ...)
        result = pipeline.execute(ctx)
    """

    def __init__(self):
        self._stages: List[PipelineStage] = []

    def add_stage(self, stage: PipelineStage):
        """Add a stage to the end of the pipeline"""
        self._stages.append(stage)

    def insert_stage(self, index: int, stage: PipelineStage):
        """Insert a stage at a specific position"""
        self._stages.insert(index, stage)

    def remove_stage(self, stage_name: str):
        """Remove a stage by name"""
        self._stages = [s for s in self._stages if s.name != stage_name]

    def execute(self, ctx: RequestContext) -> RequestContext:
        """
        Execute all pipeline stages in order.
        Stops early if any stage sets ctx.short_circuit = True.
        """
        for stage in self._stages:
            if ctx.short_circuit:
                break

            if not stage.enabled:
                continue

            stage_start = time.perf_counter()
            try:
                ctx = stage.process(ctx)
            except Exception as e:
                # Fail-open: log error but don't block
                print(f"[WAFPipeline] Error in {stage.name}: {e}")
                ctx.processing_times[stage.name] = (
                    (time.perf_counter() - stage_start) * 1000
                )
                continue

            ctx.processing_times[stage.name] = (
                (time.perf_counter() - stage_start) * 1000
            )

        return ctx

    def get_stage_names(self) -> List[str]:
        """Get ordered list of stage names"""
        return [s.name for s in self._stages]


# =============================================================================
# Concrete Pipeline Stages
# =============================================================================

class WhitelistStage(PipelineStage):
    """Check if request is whitelisted (IP or path bypass)"""

    def __init__(self, whitelist_ips, whitelist_paths, metrics_paths=None):
        self._whitelist_ips = set(whitelist_ips or [])
        self._whitelist_paths = list(whitelist_paths or [])
        self._metrics_paths = set(metrics_paths or ["/metrics"])

    @property
    def name(self):
        return "whitelist"

    def process(self, ctx: RequestContext) -> RequestContext:
        if ctx.path in self._metrics_paths:
            ctx.is_whitelisted = True
            ctx.short_circuit = True
            ctx.short_circuit_reason = "Metrics path bypass"
            return ctx

        for wp in self._whitelist_paths:
            if ctx.path.startswith(wp):
                ctx.is_whitelisted = True
                ctx.short_circuit = True
                ctx.short_circuit_reason = f"Whitelisted path: {wp}"
                return ctx

        if ctx.client_ip in self._whitelist_ips:
            ctx.is_whitelisted = True
            ctx.short_circuit = True
            ctx.short_circuit_reason = f"Whitelisted IP: {ctx.client_ip}"
            return ctx

        return ctx


class IPBlockStage(PipelineStage):
    """Check if IP is permanently or temporarily blocked"""

    def __init__(self, storage):
        self._storage = storage

    @property
    def name(self):
        return "ip_block_check"

    def process(self, ctx: RequestContext) -> RequestContext:
        if self._storage.is_permanently_blocked(ctx.client_ip):
            ctx.short_circuit = True
            ctx.short_circuit_response = (
                "403 Forbidden - IP Permanently Blocked",
                403,
            )
            ctx.short_circuit_reason = "IP Permanently Blocked"
            return ctx

        if self._storage.is_blocked_ip(ctx.client_ip):
            ctx.short_circuit = True
            ctx.short_circuit_response = (
                "403 Forbidden - IP Temporarily Blocked",
                403,
            )
            ctx.short_circuit_reason = "IP Temporarily Blocked"
            return ctx

        return ctx


class RateLimitStage(PipelineStage):
    """Check rate limits"""

    def __init__(self, rate_limiter, enabled: bool = True):
        self._limiter = rate_limiter
        self._enabled = enabled

    @property
    def name(self):
        return "rate_limit"

    @property
    def enabled(self):
        return self._enabled

    def process(self, ctx: RequestContext) -> RequestContext:
        is_limited, reason = self._limiter.is_rate_limited(ctx.client_ip)
        if is_limited:
            ctx.short_circuit = True
            ctx.short_circuit_response = (
                f"429 Too Many Requests - {reason}",
                429,
            )
            ctx.short_circuit_reason = reason
            # Also add as signal for logging
            from decision_engine import Signal, SignalCategory
            ctx.signals.append(Signal(
                category=SignalCategory.RATE_LIMIT,
                source="rate_limiter",
                score=100.0,
                confidence=1.0,
                severity="medium",
                context="rate_limit",
                details=reason,
            ))
        return ctx


class ValidationStage(PipelineStage):
    """Input validation (size, JSON, schema, file upload)"""

    def __init__(self, schema_validator=None, max_url_length=2048,
                 max_header_count=100, max_header_size=8192):
        self._schema_validator = schema_validator
        self._max_url_length = max_url_length
        self._max_header_count = max_header_count
        self._max_header_size = max_header_size

    @property
    def name(self):
        return "validation"

    def process(self, ctx: RequestContext) -> RequestContext:
        from decision_engine import Signal, SignalCategory

        # JSON Schema validation (if schema exists for this endpoint)
        if self._schema_validator and ctx.body and ctx.content_type:
            if "json" in ctx.content_type.lower():
                import json
                try:
                    parsed = json.loads(ctx.body)
                    endpoint_key = f"{ctx.method} {ctx.path}"
                    errors = self._schema_validator.validate(endpoint_key, parsed)
                    if errors:
                        ctx.signals.append(Signal(
                            category=SignalCategory.VALIDATION,
                            source="schema_validation",
                            score=70.0,
                            confidence=0.95,
                            severity="medium",
                            context="body",
                            details=f"Schema errors: {'; '.join(str(e) for e in errors[:3])}",
                            metadata={"errors": [e.to_dict() for e in errors[:5]]},
                        ))
                except (json.JSONDecodeError, Exception):
                    pass  # JSON decode errors handled by input_validator

        return ctx


class RuleEngineStage(PipelineStage):
    """Pattern-based attack detection"""

    def __init__(self, waf_engine, cache=None):
        self._engine = waf_engine
        self._cache = cache

    @property
    def name(self):
        return "rule_engine"

    def process(self, ctx: RequestContext) -> RequestContext:
        if ctx.skip_detection:
            return ctx

        request_data = ctx.as_request_data()

        # Get all detection signals
        signals = self._engine.check_request_all_signals(request_data)

        if signals:
            from decision_engine import risk_signals_to_engine_signals
            engine_signals = risk_signals_to_engine_signals(signals)
            ctx.signals.extend(engine_signals)

        return ctx


class AnomalyStage(PipelineStage):
    """Statistical anomaly detection"""

    def __init__(self, anomaly_detector):
        self._detector = anomaly_detector

    @property
    def name(self):
        return "anomaly_detection"

    def process(self, ctx: RequestContext) -> RequestContext:
        from decision_engine import Signal, SignalCategory

        request_data = ctx.as_request_data()
        result = self._detector.score(request_data)

        if result.anomaly_score > 0:
            ctx.signals.append(Signal(
                category=SignalCategory.ANOMALY,
                source="anomaly_detector",
                score=result.anomaly_score,
                confidence=0.7 if result.is_anomalous else 0.3,
                severity="high" if result.anomaly_score > 80 else "medium",
                context="request",
                details=result.details,
                metadata=result.to_dict(),
            ))

        return ctx


class BehavioralStage(PipelineStage):
    """Behavioral bot detection"""

    def __init__(self, bot_detector):
        self._detector = bot_detector

    @property
    def name(self):
        return "behavioral_analysis"

    def process(self, ctx: RequestContext) -> RequestContext:
        from decision_engine import Signal, SignalCategory

        request_data = {
            "headers": ctx.headers,
            "path": ctx.path,
            "method": ctx.method,
        }
        bot_score, indicators = self._detector.analyze(ctx.client_ip, request_data)

        if bot_score > 0:
            ctx.signals.append(Signal(
                category=SignalCategory.BEHAVIORAL,
                source="bot_detector",
                score=bot_score,
                confidence=0.8 if bot_score > 50 else 0.4,
                severity="high" if bot_score > 70 else "medium",
                context="session",
                details=f"Bot indicators: {', '.join(indicators)}",
                metadata={"indicators": indicators, "raw_score": bot_score},
            ))

        return ctx


class DecisionStage(PipelineStage):
    """Centralized decision making"""

    def __init__(
        self,
        block_threshold: float = 80.0,
        challenge_threshold: float = 40.0,
        log_threshold: float = 15.0,
    ):
        self._block_threshold = block_threshold
        self._challenge_threshold = challenge_threshold
        self._log_threshold = log_threshold

    @property
    def name(self):
        return "decision"

    def process(self, ctx: RequestContext) -> RequestContext:
        from decision_engine import DecisionEngine, Action

        engine = DecisionEngine(
            block_threshold=self._block_threshold,
            challenge_threshold=self._challenge_threshold,
            log_threshold=self._log_threshold,
        )
        engine._correlation_id = ctx.correlation_id

        # Feed all collected signals
        engine.add_signals(ctx.signals)

        # Evaluate
        decision = engine.evaluate()
        ctx.decision = decision

        # Short-circuit on block
        if decision.action == Action.BLOCK:
            ctx.short_circuit = True
            ctx.short_circuit_response = (
                f"403 Forbidden - Blocked by WAF ({decision.top_threat})",
                403,
            )
            ctx.short_circuit_reason = decision.reason

        return ctx


class LoggingStage(PipelineStage):
    """Log the final decision"""

    def __init__(self, log_fn=None, metrics_fn=None):
        self._log_fn = log_fn
        self._metrics_fn = metrics_fn

    @property
    def name(self):
        return "logging"

    def process(self, ctx: RequestContext) -> RequestContext:
        # Logging is handled by the caller (main.py) using ctx.decision
        # This stage exists as an extension point for custom logging
        return ctx
