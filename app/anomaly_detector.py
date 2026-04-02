"""
Anomaly Detection Module v1.0
=============================
Detects zero-day and unknown attacks by identifying requests that deviate
statistically from learned baseline behavior.

Two backends:
1. StatisticalDetector (default) — z-score based, zero dependencies
2. IsolationForestDetector (optional) — sklearn IsolationForest for
   multivariate anomaly detection. Activated if sklearn is installed.

Features extracted per request:
    - payload_length:       Total length of params + body
    - param_count:          Number of query parameters
    - url_length:           Length of the URL path
    - special_char_ratio:   Ratio of non-alphanumeric characters in payload
    - entropy:              Shannon entropy of payload (high entropy = encoded/encrypted)
    - digit_ratio:          Ratio of digits in payload
    - uppercase_ratio:      Ratio of uppercase chars (attack payloads often mixed case)
    - avg_param_length:     Average length per parameter value
    - unique_char_count:    Number of distinct characters used
"""
import math
import time
import threading
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import deque

# Optional sklearn import
try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# =============================================================================
# Feature Extraction
# =============================================================================

FEATURE_NAMES = [
    "payload_length",
    "param_count",
    "url_length",
    "special_char_ratio",
    "entropy",
    "digit_ratio",
    "uppercase_ratio",
    "avg_param_length",
    "unique_char_count",
]


def extract_features(request_data: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract numerical features from a request for anomaly scoring.

    Args:
        request_data: Dict with 'headers', 'params', 'body', 'path', 'method'

    Returns:
        Dict of feature_name -> float value
    """
    params = request_data.get("params", {})
    body = request_data.get("body", "")
    path = request_data.get("path", "")

    # Combine params and body as "payload"
    param_values = " ".join(str(v) for v in params.values()) if params else ""
    payload = param_values + " " + (body or "")
    payload = payload.strip()

    payload_len = len(payload)

    # Special character ratio
    if payload_len > 0:
        special_count = sum(
            1 for c in payload if not c.isalnum() and c != " "
        )
        special_char_ratio = special_count / payload_len
    else:
        special_char_ratio = 0.0

    # Shannon entropy
    entropy = _shannon_entropy(payload) if payload_len > 0 else 0.0

    # Digit ratio
    if payload_len > 0:
        digit_count = sum(1 for c in payload if c.isdigit())
        digit_ratio = digit_count / payload_len
    else:
        digit_ratio = 0.0

    # Uppercase ratio
    if payload_len > 0:
        upper_count = sum(1 for c in payload if c.isupper())
        uppercase_ratio = upper_count / payload_len
    else:
        uppercase_ratio = 0.0

    # Average parameter value length
    if params:
        avg_param_length = sum(len(str(v)) for v in params.values()) / len(params)
    else:
        avg_param_length = 0.0

    return {
        "payload_length": float(payload_len),
        "param_count": float(len(params)),
        "url_length": float(len(path)),
        "special_char_ratio": special_char_ratio,
        "entropy": entropy,
        "digit_ratio": digit_ratio,
        "uppercase_ratio": uppercase_ratio,
        "avg_param_length": avg_param_length,
        "unique_char_count": float(len(set(payload))) if payload else 0.0,
    }


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not data:
        return 0.0
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# =============================================================================
# Running Statistics (Welford's online algorithm)
# =============================================================================

class RunningStats:
    """
    Maintains running mean and variance using Welford's online algorithm.
    Memory-efficient: O(1) per feature, not O(n).
    """

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0  # sum of squares of differences from current mean

    def update(self, value: float):
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        delta2 = value - self.mean
        self.M2 += delta * delta2

    @property
    def variance(self) -> float:
        if self.n < 2:
            return 0.0
        return self.M2 / (self.n - 1)

    @property
    def std_dev(self) -> float:
        return self.variance ** 0.5

    def z_score(self, value: float) -> float:
        """Calculate how many standard deviations value is from mean"""
        if self.std_dev == 0 or self.n < 10:
            return 0.0
        return abs(value - self.mean) / self.std_dev


# =============================================================================
# Statistical Anomaly Detector (zero dependencies)
# =============================================================================

@dataclass
class AnomalyResult:
    """Result of anomaly detection"""
    is_anomalous: bool
    anomaly_score: float         # 0-100
    feature_scores: Dict[str, float]  # per-feature z-scores
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_anomalous": self.is_anomalous,
            "anomaly_score": round(self.anomaly_score, 1),
            "top_features": {
                k: round(v, 2)
                for k, v in sorted(
                    self.feature_scores.items(), key=lambda x: x[1], reverse=True
                )[:3]
            },
            "details": self.details,
        }


class StatisticalDetector:
    """
    Z-score based anomaly detector.

    Learns baseline request characteristics using Welford's online algorithm,
    then flags requests with features that deviate significantly from the baseline.

    Designed for per-endpoint profiling: different endpoints have different
    normal behavior (e.g., /search has long query params, /login has short POST body).
    """

    # Minimum observations before scoring is active
    MIN_OBSERVATIONS = 50

    # Z-score threshold for individual features to be considered anomalous
    FEATURE_ANOMALY_THRESHOLD = 3.0

    # How many anomalous features trigger the overall anomaly flag
    MIN_ANOMALOUS_FEATURES = 2

    def __init__(self, anomaly_threshold: float = 60.0):
        """
        Args:
            anomaly_threshold: Score above which a request is flagged (0-100)
        """
        self.anomaly_threshold = anomaly_threshold
        self._lock = threading.Lock()

        # Per-endpoint running statistics
        # Key: endpoint pattern (e.g. "GET /api/users")
        # Value: Dict[feature_name -> RunningStats]
        self._endpoint_stats: Dict[str, Dict[str, RunningStats]] = {}

        # Global statistics (fallback when endpoint has too few observations)
        self._global_stats: Dict[str, RunningStats] = {
            name: RunningStats() for name in FEATURE_NAMES
        }

    def _get_endpoint_key(self, request_data: Dict) -> str:
        """Generate endpoint key for profiling"""
        method = request_data.get("method", "GET")
        path = request_data.get("path", "/")
        # Normalize path: replace numeric segments with {id}
        # /api/users/123 → /api/users/{id}
        parts = path.strip("/").split("/")
        normalized = []
        for part in parts:
            if part.isdigit():
                normalized.append("{id}")
            else:
                normalized.append(part)
        return f"{method} /{'/'.join(normalized)}"

    def observe(self, request_data: Dict[str, Any]):
        """
        Record a request to update baseline statistics.
        Call this for ALLOWED requests to build the normal profile.
        """
        features = extract_features(request_data)
        endpoint = self._get_endpoint_key(request_data)

        with self._lock:
            # Update endpoint-specific stats
            if endpoint not in self._endpoint_stats:
                self._endpoint_stats[endpoint] = {
                    name: RunningStats() for name in FEATURE_NAMES
                }
            for name, value in features.items():
                if name in self._endpoint_stats[endpoint]:
                    self._endpoint_stats[endpoint][name].update(value)

                # Also update global stats
                if name in self._global_stats:
                    self._global_stats[name].update(value)

    def score(self, request_data: Dict[str, Any]) -> AnomalyResult:
        """
        Score a request for anomalousness.

        Returns AnomalyResult with score 0-100 and per-feature breakdown.
        """
        features = extract_features(request_data)
        endpoint = self._get_endpoint_key(request_data)

        with self._lock:
            # Use endpoint stats if available, else global
            stats = self._endpoint_stats.get(endpoint)
            has_enough_data = (
                stats is not None
                and all(s.n >= self.MIN_OBSERVATIONS for s in stats.values())
            )

            if not has_enough_data:
                # Check global stats
                if all(
                    s.n >= self.MIN_OBSERVATIONS
                    for s in self._global_stats.values()
                ):
                    stats = self._global_stats
                else:
                    # Not enough data yet — cannot score
                    return AnomalyResult(
                        is_anomalous=False,
                        anomaly_score=0.0,
                        feature_scores={},
                        details="Insufficient baseline data for scoring",
                    )

            # Calculate z-scores per feature
            feature_scores = {}
            for name, value in features.items():
                if name in stats:
                    feature_scores[name] = stats[name].z_score(value)
                else:
                    feature_scores[name] = 0.0

        # Calculate overall anomaly score
        # Weighted average of z-scores, normalized to 0-100
        if not feature_scores:
            return AnomalyResult(
                is_anomalous=False,
                anomaly_score=0.0,
                feature_scores={},
                details="No features to score",
            )

        # Features with higher z-scores contribute more
        max_z = max(feature_scores.values())
        avg_z = sum(feature_scores.values()) / len(feature_scores)

        # Count how many features are anomalous
        anomalous_features = [
            name
            for name, z in feature_scores.items()
            if z > self.FEATURE_ANOMALY_THRESHOLD
        ]

        # Score formula: blend of max and average z-score
        # Emphasizes the worst outlier but considers overall deviation
        raw_score = (max_z * 0.6 + avg_z * 0.4) * 15  # Scale to ~0-100 range
        anomaly_score = min(raw_score, 100.0)

        is_anomalous = (
            anomaly_score >= self.anomaly_threshold
            and len(anomalous_features) >= self.MIN_ANOMALOUS_FEATURES
        )

        details_parts = []
        if anomalous_features:
            details_parts.append(
                f"Anomalous features: {', '.join(anomalous_features)}"
            )
        details_parts.append(f"Max z-score: {max_z:.1f}, Avg z-score: {avg_z:.1f}")

        return AnomalyResult(
            is_anomalous=is_anomalous,
            anomaly_score=anomaly_score,
            feature_scores=feature_scores,
            details=" | ".join(details_parts),
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics"""
        with self._lock:
            return {
                "endpoints_profiled": len(self._endpoint_stats),
                "global_observations": (
                    self._global_stats["payload_length"].n
                    if "payload_length" in self._global_stats
                    else 0
                ),
                "ready": all(
                    s.n >= self.MIN_OBSERVATIONS
                    for s in self._global_stats.values()
                ),
            }


# =============================================================================
# Isolation Forest Detector (optional, requires sklearn)
# =============================================================================

class IsolationForestDetector:
    """
    Multivariate anomaly detection using sklearn's IsolationForest.
    Falls back to StatisticalDetector if sklearn is not available.

    Trains on a window of recent normal requests and scores new requests.
    """

    TRAINING_WINDOW = 1000  # Number of samples to keep for retraining
    RETRAIN_INTERVAL = 500  # Retrain every N new observations

    def __init__(self, contamination: float = 0.05, anomaly_threshold: float = 60.0):
        if not SKLEARN_AVAILABLE:
            raise ImportError(
                "scikit-learn is required for IsolationForestDetector. "
                "Install with: pip install scikit-learn"
            )

        self.contamination = contamination
        self.anomaly_threshold = anomaly_threshold
        self._lock = threading.Lock()
        self._training_data: deque = deque(maxlen=self.TRAINING_WINDOW)
        self._model: Optional[IsolationForest] = None
        self._observations_since_train = 0

    def observe(self, request_data: Dict[str, Any]):
        """Add an observation to the training window"""
        features = extract_features(request_data)
        feature_vector = [features.get(name, 0.0) for name in FEATURE_NAMES]

        with self._lock:
            self._training_data.append(feature_vector)
            self._observations_since_train += 1

            # Retrain periodically
            if (
                self._observations_since_train >= self.RETRAIN_INTERVAL
                and len(self._training_data) >= 100
            ):
                self._train()

    def _train(self):
        """Train the Isolation Forest model"""
        X = np.array(list(self._training_data))
        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
        )
        self._model.fit(X)
        self._observations_since_train = 0

    def score(self, request_data: Dict[str, Any]) -> AnomalyResult:
        """Score a request using the trained model"""
        features = extract_features(request_data)
        feature_vector = [features.get(name, 0.0) for name in FEATURE_NAMES]

        with self._lock:
            if self._model is None:
                return AnomalyResult(
                    is_anomalous=False,
                    anomaly_score=0.0,
                    feature_scores={},
                    details="Model not yet trained",
                )

            X = np.array([feature_vector])
            # score_samples returns negative scores; more negative = more anomalous
            raw_score = self._model.score_samples(X)[0]
            # Invert and normalize to 0-100 (typical range is -0.5 to 0.5)
            anomaly_score = min(max((0.5 - raw_score) * 100, 0.0), 100.0)

            # Per-feature contribution (approximate via z-score from training data)
            feature_scores = {}
            training_array = np.array(list(self._training_data))
            means = training_array.mean(axis=0)
            stds = training_array.std(axis=0)
            for i, name in enumerate(FEATURE_NAMES):
                if stds[i] > 0:
                    feature_scores[name] = abs(
                        (feature_vector[i] - means[i]) / stds[i]
                    )
                else:
                    feature_scores[name] = 0.0

        is_anomalous = anomaly_score >= self.anomaly_threshold

        return AnomalyResult(
            is_anomalous=is_anomalous,
            anomaly_score=anomaly_score,
            feature_scores=feature_scores,
            details=f"IsolationForest score: {raw_score:.3f}",
        )

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "training_samples": len(self._training_data),
                "model_trained": self._model is not None,
                "observations_since_train": self._observations_since_train,
            }


# =============================================================================
# Factory: get the best available detector
# =============================================================================

def create_anomaly_detector(
    use_isolation_forest: bool = True,
    anomaly_threshold: float = 60.0,
    **kwargs,
):
    """
    Create the best available anomaly detector.

    Prefers IsolationForest if sklearn is available and requested,
    otherwise falls back to statistical z-score detector.
    """
    if use_isolation_forest and SKLEARN_AVAILABLE:
        try:
            return IsolationForestDetector(
                anomaly_threshold=anomaly_threshold, **kwargs
            )
        except Exception:
            pass

    return StatisticalDetector(anomaly_threshold=anomaly_threshold)
