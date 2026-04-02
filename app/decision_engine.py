"""
Centralized Decision Engine v1.0
================================
Replaces fragmented decision logic with a unified multi-signal scoring system.

Instead of independent if-statements for rule detection, rate limiting,
bot detection, and anomaly detection, this engine:
1. Collects typed signals from ALL subsystems
2. Applies configurable weights per signal category
3. Combines scores with cross-signal amplification
4. Returns a single Decision with action, score, and full reasoning

Signal Categories:
    - RULE_MATCH:   Pattern-based detection (SQLi, XSS, etc.)
    - ANOMALY:      Statistical anomaly detection score
    - RATE_LIMIT:   Rate limiting proximity (how close to limit)
    - BEHAVIORAL:   Bot/behavioral analysis score
    - REPUTATION:   IP reputation (geo-block, permanent block history)
    - VALIDATION:   Input validation failures
"""
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class SignalCategory(Enum):
    """Categories of threat signals"""
    RULE_MATCH = "rule_match"
    ANOMALY = "anomaly"
    RATE_LIMIT = "rate_limit"
    BEHAVIORAL = "behavioral"
    REPUTATION = "reputation"
    VALIDATION = "validation"


class Action(Enum):
    """Possible WAF actions"""
    ALLOW = "allow"
    LOG = "log"
    CHALLENGE = "challenge"
    BLOCK = "block"


@dataclass
class Signal:
    """
    A single threat signal from any subsystem.

    Attributes:
        category:    Which subsystem produced this signal
        source:      Specific source identifier (e.g., 'sql_injection', 'bot_timing')
        score:       Raw score from the subsystem (0.0 - 100.0)
        confidence:  How confident the subsystem is (0.0 - 1.0)
        severity:    Severity level string ('low', 'medium', 'high', 'critical')
        context:     Where in the request this was found
        details:     Human-readable description
        metadata:    Any additional structured data
    """
    category: SignalCategory
    source: str
    score: float
    confidence: float = 0.9
    severity: str = "medium"
    context: str = ""
    details: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def weighted_score(self) -> float:
        """Score adjusted by confidence"""
        return self.score * self.confidence


@dataclass
class Decision:
    """
    Final WAF decision for a request.

    Attributes:
        action:          The action to take (ALLOW, LOG, CHALLENGE, BLOCK)
        total_score:     Combined risk score (0 - 100)
        signals:         All signals that contributed to the decision
        correlation_id:  Unique ID for tracing this request
        reason:          Human-readable summary of why this decision was made
        top_threat:      The highest-scoring threat category
        processing_time: Time spent in the decision engine (ms)
    """
    action: Action
    total_score: float
    signals: List[Signal] = field(default_factory=list)
    correlation_id: str = ""
    reason: str = ""
    top_threat: str = ""
    processing_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize decision for logging/API responses"""
        return {
            "action": self.action.value,
            "total_score": round(self.total_score, 1),
            "correlation_id": self.correlation_id,
            "reason": self.reason,
            "top_threat": self.top_threat,
            "processing_time_ms": round(self.processing_time_ms, 2),
            "signal_count": len(self.signals),
            "signals": [
                {
                    "category": s.category.value,
                    "source": s.source,
                    "score": round(s.weighted_score, 1),
                    "severity": s.severity,
                    "context": s.context,
                    "details": s.details[:200],
                }
                for s in self.signals
            ],
        }


# =============================================================================
# Severity multipliers — amplify score for critical threats
# =============================================================================

SEVERITY_MULTIPLIERS = {
    "critical": 1.5,
    "high": 1.2,
    "medium": 1.0,
    "low": 0.7,
}

# =============================================================================
# Category weights — how much each signal category contributes
# =============================================================================

DEFAULT_CATEGORY_WEIGHTS = {
    SignalCategory.RULE_MATCH: 1.0,
    SignalCategory.ANOMALY: 0.6,
    SignalCategory.RATE_LIMIT: 0.5,
    SignalCategory.BEHAVIORAL: 0.7,
    SignalCategory.REPUTATION: 0.8,
    SignalCategory.VALIDATION: 0.9,
}

# =============================================================================
# Cross-signal amplification table
# When signals from DIFFERENT categories appear together, they amplify:
# e.g., a rule match + anomaly = more suspicious than either alone
# =============================================================================

CROSS_SIGNAL_AMPLIFICATION = {
    # (category_a, category_b) -> amplification factor
    (SignalCategory.RULE_MATCH, SignalCategory.ANOMALY): 1.3,
    (SignalCategory.RULE_MATCH, SignalCategory.BEHAVIORAL): 1.25,
    (SignalCategory.ANOMALY, SignalCategory.BEHAVIORAL): 1.2,
    (SignalCategory.RULE_MATCH, SignalCategory.RATE_LIMIT): 1.15,
    (SignalCategory.ANOMALY, SignalCategory.RATE_LIMIT): 1.1,
    (SignalCategory.BEHAVIORAL, SignalCategory.RATE_LIMIT): 1.1,
    (SignalCategory.VALIDATION, SignalCategory.RULE_MATCH): 1.2,
}


class DecisionEngine:
    """
    Centralized decision engine that combines signals from all
    WAF subsystems into a single, scored decision.

    Usage:
        engine = DecisionEngine(block_threshold=80, challenge_threshold=40)
        engine.add_signal(Signal(category=SignalCategory.RULE_MATCH, ...))
        engine.add_signal(Signal(category=SignalCategory.BEHAVIORAL, ...))
        decision = engine.evaluate()
    """

    def __init__(
        self,
        block_threshold: float = 80.0,
        challenge_threshold: float = 40.0,
        log_threshold: float = 15.0,
        category_weights: Dict[SignalCategory, float] = None,
    ):
        self.block_threshold = block_threshold
        self.challenge_threshold = challenge_threshold
        self.log_threshold = log_threshold
        self.category_weights = category_weights or DEFAULT_CATEGORY_WEIGHTS.copy()
        self._signals: List[Signal] = []
        self._correlation_id = str(uuid.uuid4())[:12]

    @property
    def correlation_id(self) -> str:
        return self._correlation_id

    def add_signal(self, signal: Signal):
        """Add a threat signal from any subsystem"""
        self._signals.append(signal)

    def add_signals(self, signals: List[Signal]):
        """Add multiple signals at once"""
        self._signals.extend(signals)

    def evaluate(self) -> Decision:
        """
        Evaluate all collected signals and produce a final decision.

        Scoring algorithm:
        1. Group signals by category
        2. Within each category, apply diminishing returns (50% decay per signal)
        3. Apply category weight
        4. Sum weighted category scores
        5. Apply cross-signal amplification if multiple categories present
        6. Cap at 100, compare against thresholds
        """
        start_time = time.perf_counter()

        if not self._signals:
            return Decision(
                action=Action.ALLOW,
                total_score=0.0,
                signals=[],
                correlation_id=self._correlation_id,
                reason="No threat signals detected",
                processing_time_ms=0.0,
            )

        # Step 1: Group by category
        by_category: Dict[SignalCategory, List[Signal]] = {}
        for signal in self._signals:
            if signal.category not in by_category:
                by_category[signal.category] = []
            by_category[signal.category].append(signal)

        # Step 2 & 3: Score each category with diminishing returns + weight
        category_scores: Dict[SignalCategory, float] = {}
        for category, signals in by_category.items():
            # Sort by weighted score descending
            signals.sort(key=lambda s: s.weighted_score, reverse=True)

            # Apply diminishing returns within category
            cat_score = 0.0
            for i, signal in enumerate(signals):
                severity_mult = SEVERITY_MULTIPLIERS.get(signal.severity, 1.0)
                contribution = signal.weighted_score * severity_mult * (0.5 ** i)
                cat_score += contribution

            # Apply category weight
            weight = self.category_weights.get(category, 0.5)
            category_scores[category] = cat_score * weight

        # Step 4: Sum weighted scores
        raw_total = sum(category_scores.values())

        # Step 5: Cross-signal amplification
        active_categories = set(by_category.keys())
        amplification = 1.0
        for (cat_a, cat_b), factor in CROSS_SIGNAL_AMPLIFICATION.items():
            if cat_a in active_categories and cat_b in active_categories:
                amplification = max(amplification, factor)

        # Apply amplification (only increases, never decreases)
        amplified_total = raw_total * amplification

        # Step 6: Cap and determine action
        total_score = min(amplified_total, 100.0)

        if total_score >= self.block_threshold:
            action = Action.BLOCK
        elif total_score >= self.challenge_threshold:
            action = Action.CHALLENGE
        elif total_score >= self.log_threshold:
            action = Action.LOG
        else:
            action = Action.ALLOW

        # Find top threat
        top_signal = max(self._signals, key=lambda s: s.weighted_score)
        top_threat = top_signal.source

        # Build reason string
        active_sources = sorted(
            set(s.source for s in self._signals),
            key=lambda src: max(
                s.weighted_score for s in self._signals if s.source == src
            ),
            reverse=True,
        )
        reason = (
            f"Score {total_score:.0f}/100 → {action.value.upper()} | "
            f"Signals: {len(self._signals)} from {len(active_categories)} categories | "
            f"Top threats: {', '.join(active_sources[:3])}"
        )
        if amplification > 1.0:
            reason += f" | Cross-signal amplification: {amplification:.2f}x"

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return Decision(
            action=action,
            total_score=total_score,
            signals=self._signals,
            correlation_id=self._correlation_id,
            reason=reason,
            top_threat=top_threat,
            processing_time_ms=elapsed_ms,
        )

    def reset(self):
        """Clear all signals for reuse"""
        self._signals.clear()
        self._correlation_id = str(uuid.uuid4())[:12]


# =============================================================================
# Helper: Convert existing RiskAssessment signals to DecisionEngine signals
# =============================================================================

def risk_signals_to_engine_signals(
    risk_signals: list,
    confidence_fn=None,
) -> List[Signal]:
    """
    Convert detection signals from waf_engine (DetectionResult objects)
    into Signal objects for the DecisionEngine.

    Args:
        risk_signals: List of DetectionResult from waf_engine
        confidence_fn: Function(pattern) -> float for confidence scoring
    """
    from risk_scorer import SEVERITY_WEIGHTS, get_pattern_confidence

    if confidence_fn is None:
        confidence_fn = get_pattern_confidence

    signals = []
    for detection in risk_signals:
        confidence = confidence_fn(detection.pattern_matched or "")
        severity_weight = SEVERITY_WEIGHTS.get(detection.severity, 0.5)

        signals.append(Signal(
            category=SignalCategory.RULE_MATCH,
            source=detection.attack_type or "unknown",
            score=confidence * severity_weight * 100,
            confidence=confidence,
            severity=detection.severity,
            context=detection.context or "request",
            details=detection.details or "",
            metadata={
                "pattern": detection.pattern_matched or "",
                "attack_type": detection.attack_type or "",
            },
        ))

    return signals
