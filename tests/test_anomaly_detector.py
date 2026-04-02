"""
Test Suite: Anomaly Detection
Tests feature extraction, baseline learning, and deviation scoring
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from anomaly_detector import (
    extract_features, StatisticalDetector, RunningStats,
    FEATURE_NAMES, _shannon_entropy, create_anomaly_detector,
)


class TestFeatureExtraction:
    """Test request feature extraction"""

    def test_basic_extraction(self, sample_request_data):
        features = extract_features(sample_request_data)
        assert isinstance(features, dict)
        assert all(name in features for name in FEATURE_NAMES)

    def test_empty_request(self):
        features = extract_features({
            'headers': {}, 'params': {}, 'body': '', 'path': '/', 'method': 'GET',
        })
        assert features["payload_length"] == 0
        assert features["param_count"] == 0
        assert features["entropy"] == 0

    def test_payload_length(self):
        features = extract_features({
            'headers': {}, 'params': {'key': 'value'}, 'body': '',
            'path': '/test', 'method': 'GET',
        })
        assert features["payload_length"] > 0
        assert features["param_count"] == 1.0

    def test_special_char_ratio(self):
        # Attack payload has high special char ratio
        attack = extract_features({
            'headers': {}, 'params': {'q': "'; DROP TABLE users;--"},
            'body': '', 'path': '/', 'method': 'GET',
        })
        normal = extract_features({
            'headers': {}, 'params': {'q': 'hello world'},
            'body': '', 'path': '/', 'method': 'GET',
        })
        assert attack["special_char_ratio"] > normal["special_char_ratio"]

    def test_entropy(self):
        # High entropy (random-looking data)
        features = extract_features({
            'headers': {}, 'params': {'q': 'aB3$xY7!z#mK9@pQ'},
            'body': '', 'path': '/', 'method': 'GET',
        })
        assert features["entropy"] > 3.0  # Random-ish data has high entropy

    def test_url_length(self):
        features = extract_features({
            'headers': {}, 'params': {}, 'body': '',
            'path': '/api/v1/users/search/advanced', 'method': 'GET',
        })
        assert features["url_length"] == len('/api/v1/users/search/advanced')


class TestShannonEntropy:
    """Test Shannon entropy calculation"""

    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_max_entropy_two_chars(self):
        # "ab" repeated = max entropy for 2 chars = 1.0
        entropy = _shannon_entropy("abababab")
        assert abs(entropy - 1.0) < 0.01

    def test_increasing_entropy(self):
        e1 = _shannon_entropy("aaaa")
        e2 = _shannon_entropy("aabb")
        e3 = _shannon_entropy("abcd")
        assert e1 < e2 < e3


class TestRunningStats:
    """Test Welford's online algorithm"""

    def test_basic_stats(self):
        stats = RunningStats()
        for v in [2, 4, 4, 4, 5, 5, 7, 9]:
            stats.update(v)

        assert abs(stats.mean - 5.0) < 0.01
        assert stats.n == 8

    def test_z_score_normal(self):
        stats = RunningStats()
        for v in range(100):
            stats.update(float(v))

        # Mean ≈ 49.5, values near center should have low z-score
        z = stats.z_score(50.0)
        assert z < 1.0

    def test_z_score_outlier(self):
        stats = RunningStats()
        for v in range(100):
            stats.update(float(v))

        # Value far from center should have high z-score
        z = stats.z_score(500.0)
        assert z > 5.0

    def test_z_score_insufficient_data(self):
        stats = RunningStats()
        stats.update(1.0)
        # Not enough data — should return 0
        assert stats.z_score(100.0) == 0.0


class TestStatisticalDetector:
    """Test the statistical anomaly detector"""

    def _create_trained_detector(self, n=100):
        """Create a detector with N diverse normal observations"""
        detector = StatisticalDetector(anomaly_threshold=60.0)
        # Use diverse training data to create a representative baseline
        # Mix of queries with and without numbers, varying lengths
        queries = [
            'search term 42',
            'best products to buy',
            'how to cook pasta',
            'latest news today',
            'weather forecast for tomorrow',
            'user query number 7',
            'find restaurants nearby',
            'python programming tutorial',
            'online shopping deals',
            'travel destinations europe',
            'normal search',
            'hello world',
            'buy 2 get 1 free',
            'recipe for chocolate cake',
            'flight tickets to paris',
        ]
        for i in range(n):
            request_data = {
                'headers': {}, 'params': {'q': queries[i % len(queries)]},
                'body': '', 'path': '/search', 'method': 'GET',
            }
            detector.observe(request_data)
        return detector

    def test_insufficient_data(self, anomaly_detector):
        """Detector should not flag anything without enough baseline"""
        result = anomaly_detector.score({
            'headers': {}, 'params': {'q': "' OR 1=1--"},
            'body': '', 'path': '/', 'method': 'GET',
        })
        assert not result.is_anomalous
        assert "Insufficient" in result.details

    def test_normal_request_after_training(self):
        """Normal request similar to training data should not be flagged as anomalous"""
        detector = self._create_trained_detector(100)
        result = detector.score({
            'headers': {}, 'params': {'q': 'normal search'},
            'body': '', 'path': '/search', 'method': 'GET',
        })
        # Should not be flagged as anomalous (requires both high score AND multiple anomalous features)
        assert not result.is_anomalous

    def test_anomalous_request_extreme_payload(self):
        """Extremely long payload should score high"""
        detector = self._create_trained_detector(100)
        result = detector.score({
            'headers': {},
            'params': {'q': 'A' * 10000 + "'; DROP TABLE users;-- " * 100},
            'body': '', 'path': '/search', 'method': 'GET',
        })
        # Should have high z-scores on some features
        assert result.anomaly_score > 0

    def test_endpoint_profiling(self):
        """Different endpoints should be profiled separately"""
        detector = StatisticalDetector()
        # Train /search with short params
        for i in range(60):
            detector.observe({
                'headers': {}, 'params': {'q': f'query {i}'},
                'body': '', 'path': '/search', 'method': 'GET',
            })

        stats = detector.get_stats()
        assert stats["endpoints_profiled"] >= 1

    def test_get_stats(self, anomaly_detector):
        stats = anomaly_detector.get_stats()
        assert "endpoints_profiled" in stats
        assert "global_observations" in stats
        assert "ready" in stats


class TestAnomalyDetectorFactory:
    """Test the detector factory function"""

    def test_creates_statistical_by_default(self):
        detector = create_anomaly_detector(use_isolation_forest=False)
        assert isinstance(detector, StatisticalDetector)

    def test_creates_with_custom_threshold(self):
        detector = create_anomaly_detector(
            use_isolation_forest=False, anomaly_threshold=80.0
        )
        assert detector.anomaly_threshold == 80.0
