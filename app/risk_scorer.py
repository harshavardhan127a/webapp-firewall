"""
Risk-Based Decision Engine (H2 Fix)
Replaces binary block/allow with accumulated threat scoring.

Instead of blocking on the first regex match, this engine:
1. Accumulates threat signals from multiple detectors
2. Weights each signal by confidence and severity
3. Applies diminishing returns for same-category signals
4. Returns an action: 'block', 'challenge', 'log', or 'allow'

This dramatically reduces false positives by requiring multiple
corroborating signals before blocking.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict


@dataclass
class ThreatSignal:
    """A single detected threat indicator"""
    category: str           # sql_injection, xss, etc.
    pattern: str            # regex pattern that matched
    confidence: float       # 0.0-1.0 — how likely this is a real attack
    severity_weight: float  # multiplier based on attack severity
    context: str            # where it was found: 'params', 'body', 'path', 'headers'

    @property
    def score(self) -> float:
        """Raw score for this signal"""
        return self.confidence * self.severity_weight * 100


@dataclass
class RiskAssessment:
    """Aggregated risk assessment for a request"""
    signals: List[ThreatSignal] = field(default_factory=list)

    # Thresholds (will be overridden from config at runtime)
    block_threshold: float = 80.0
    challenge_threshold: float = 40.0
    log_threshold: float = 15.0

    @property
    def total_score(self) -> float:
        """
        Calculate total risk score with diminishing returns.

        Multiple signals in the SAME category contribute with 50% decay
        per additional signal (prevents a single broad rule from dominating).
        Multiple signals across DIFFERENT categories stack normally.
        """
        if not self.signals:
            return 0.0

        # Group signals by category
        categories: Dict[str, List[float]] = {}
        for s in self.signals:
            if s.category not in categories:
                categories[s.category] = []
            categories[s.category].append(s.score)

        total = 0.0
        for cat, scores in categories.items():
            scores.sort(reverse=True)
            for i, score in enumerate(scores):
                # Each additional signal in same category worth 50% less
                total += score * (0.5 ** i)

        return min(total, 100.0)

    @property
    def action(self) -> str:
        """Determine the recommended action based on risk score"""
        score = self.total_score
        if score >= self.block_threshold:
            return 'block'
        elif score >= self.challenge_threshold:
            return 'challenge'
        elif score >= self.log_threshold:
            return 'log'
        return 'allow'

    @property
    def top_threat(self) -> Optional[str]:
        """Get the highest-scoring attack category"""
        if not self.signals:
            return None
        return max(self.signals, key=lambda s: s.score).category

    @property
    def top_severity(self) -> str:
        """Get the highest severity level across all signals"""
        if not self.signals:
            return 'none'
        max_weight = max(s.severity_weight for s in self.signals)
        if max_weight >= 1.0:
            return 'critical'
        if max_weight >= 0.8:
            return 'high'
        if max_weight >= 0.5:
            return 'medium'
        return 'low'

    @property
    def summary(self) -> str:
        """Human-readable summary of the assessment"""
        if not self.signals:
            return "No threats detected"
        categories = set(s.category for s in self.signals)
        return (
            f"Risk score: {self.total_score:.0f}/100, "
            f"Action: {self.action}, "
            f"Threats: {', '.join(categories)}"
        )


# =============================================================================
# Severity weights — maps severity string to numeric weight
# =============================================================================

SEVERITY_WEIGHTS = {
    'critical': 1.0,
    'high': 0.8,
    'medium': 0.5,
    'low': 0.3,
}

# =============================================================================
# Pattern confidence overrides
# Known false-positive-prone patterns get reduced confidence scores.
# Default confidence for all other patterns is 0.9.
# =============================================================================

LOW_CONFIDENCE_PATTERNS: Dict[str, float] = {
    # SQL injection patterns that commonly match legitimate content
    r'(--)': 0.15,                    # Matches CSS, URLs, markdown
    r'(;\s*$)': 0.10,                # Matches any trailing semicolon
    r'(\bor\b.+\=)': 0.20,          # Matches natural English "or" with equals
    r'(\bOR\b\s+\d+\s*=\s*\d+)': 0.75,  # More specific OR 1=1 pattern
    r'(0x[0-9a-fA-F]{4,})': 0.30,   # Hex values common in many contexts
    r"('\s*;)": 0.25,                # Quote-semicollon common in JS
    r'("\s*;)': 0.25,
    r"(\+\s*')": 0.20,              # String concatenation in JS
    r"(')\s*(\+|\|\|)": 0.20,

    # XSS patterns with high false positive rates
    r'(<style[^>]*>)': 0.15,        # Legitimate HTML
    r'(<link[^>]*>)': 0.10,         # Legitimate HTML
    r'(<base[^>]*>)': 0.20,
    r'(<meta[^>]*http-equiv)': 0.20,
    r'(<\?)': 0.15,                  # PHP short tags, XML declarations
    r'(<%)'  : 0.15,                 # JSP/ASP tags
    r'(&#x?[0-9a-fA-F]+;?)': 0.20, # HTML entities very common

    # SSRF patterns that match legitimate content
    r'(localhost)': 0.20,            # Common in docs, configs
    r'(\.local)': 0.15,             # mDNS domains
    r'(\.localhost)': 0.20,
    r'(127\.0\.0\.1)': 0.40,        # Often in docs but worth flagging

    # XXE patterns with false positive risk
    r'(&[a-zA-Z0-9]+;)': 0.10,     # HTML entities like &amp; are everywhere
    r'(%[a-zA-Z0-9]+;)': 0.15,

    # Command injection broad patterns
    r'(\$\{.*\})': 0.30,            # Shell variables, also template literals
    r'(`.*`)': 0.25,                # Backticks used in markdown

    # Path traversal broad patterns
    r'(\.env)': 0.30,               # Can be part of "environment"
    r'(\.git)': 0.35,
    r'(\.json$)': 0.10,             # JSON file extension is common
    r'(\.xml$)': 0.10,
    r'(\.yml$)': 0.10,
    r'(\.yaml$)': 0.10,
    r'(\.config$)': 0.15,
    r'(config\.php)': 0.40,
    r'(settings\.py)': 0.40,
}


def get_pattern_confidence(pattern: str) -> float:
    """
    Get confidence score for a pattern.
    Returns reduced confidence for known false-positive-prone patterns.
    Default is 0.9 for unrecognized patterns.
    """
    return LOW_CONFIDENCE_PATTERNS.get(pattern, 0.9)
