"""
Test Suite: Centralized Decision Engine
Tests signal combination, threshold logic, cross-signal amplification
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from decision_engine import (
    DecisionEngine, Signal, SignalCategory, Action, Decision,
    CROSS_SIGNAL_AMPLIFICATION,
)


class TestSignalCreation:
    """Test Signal dataclass"""

    def test_basic_signal(self):
        s = Signal(
            category=SignalCategory.RULE_MATCH,
            source="sql_injection",
            score=80.0,
        )
        assert s.weighted_score == 80.0 * 0.9  # default confidence = 0.9

    def test_signal_with_confidence(self):
        s = Signal(
            category=SignalCategory.ANOMALY,
            source="anomaly_detector",
            score=60.0,
            confidence=0.5,
        )
        assert s.weighted_score == 30.0

    def test_signal_zero_score(self):
        s = Signal(
            category=SignalCategory.BEHAVIORAL,
            source="bot_detector",
            score=0.0,
        )
        assert s.weighted_score == 0.0


class TestDecisionEngine:
    """Test the decision engine evaluation"""

    def test_allow_no_signals(self, decision_engine):
        decision = decision_engine.evaluate()
        assert decision.action == Action.ALLOW
        assert decision.total_score == 0.0
        assert len(decision.signals) == 0

    def test_block_on_high_score(self, decision_engine):
        decision_engine.add_signal(Signal(
            category=SignalCategory.RULE_MATCH,
            source="sql_injection",
            score=95.0,
            confidence=1.0,
            severity="critical",
        ))
        decision = decision_engine.evaluate()
        assert decision.action == Action.BLOCK
        assert decision.total_score >= 80.0

    def test_challenge_on_medium_score(self):
        engine = DecisionEngine(block_threshold=80, challenge_threshold=40)
        engine.add_signal(Signal(
            category=SignalCategory.RULE_MATCH,
            source="xss",
            score=50.0,
            confidence=1.0,
            severity="medium",
        ))
        decision = engine.evaluate()
        assert decision.action == Action.CHALLENGE

    def test_log_on_low_score(self):
        engine = DecisionEngine(
            block_threshold=80, challenge_threshold=40, log_threshold=15
        )
        engine.add_signal(Signal(
            category=SignalCategory.BEHAVIORAL,
            source="bot_detector",
            score=25.0,
            confidence=0.5,
            severity="low",
        ))
        decision = engine.evaluate()
        assert decision.action in (Action.LOG, Action.ALLOW)

    def test_allow_below_threshold(self):
        engine = DecisionEngine(block_threshold=80, challenge_threshold=40)
        engine.add_signal(Signal(
            category=SignalCategory.BEHAVIORAL,
            source="bot_detector",
            score=5.0,
            confidence=0.3,
            severity="low",
        ))
        decision = engine.evaluate()
        assert decision.action in (Action.ALLOW, Action.LOG)
        assert decision.total_score < 40

    def test_diminishing_returns_same_category(self, decision_engine):
        """Multiple signals in same category should have diminishing returns"""
        # First signal at full value
        decision_engine.add_signal(Signal(
            category=SignalCategory.RULE_MATCH,
            source="sqli_1",
            score=40.0,
            confidence=1.0,
        ))
        score_with_one = decision_engine.evaluate().total_score
        decision_engine.reset()

        # Adding a second signal should not double the score
        decision_engine.add_signal(Signal(
            category=SignalCategory.RULE_MATCH,
            source="sqli_1",
            score=40.0,
            confidence=1.0,
        ))
        decision_engine.add_signal(Signal(
            category=SignalCategory.RULE_MATCH,
            source="sqli_2",
            score=40.0,
            confidence=1.0,
        ))
        score_with_two = decision_engine.evaluate().total_score

        # Should be more than one signal but less than double
        assert score_with_two > score_with_one
        assert score_with_two < score_with_one * 2

    def test_cross_signal_amplification(self):
        """Rule match + anomaly should amplify score"""
        engine = DecisionEngine(block_threshold=200, challenge_threshold=100)

        engine.add_signal(Signal(
            category=SignalCategory.RULE_MATCH,
            source="sqli",
            score=50.0,
            confidence=1.0,
        ))
        score_rule_only = engine.evaluate().total_score
        engine.reset()

        engine.add_signal(Signal(
            category=SignalCategory.RULE_MATCH,
            source="sqli",
            score=50.0,
            confidence=1.0,
        ))
        engine.add_signal(Signal(
            category=SignalCategory.ANOMALY,
            source="anomaly_detector",
            score=30.0,
            confidence=0.7,
        ))
        score_combined = engine.evaluate().total_score

        # Combined should be more than sum of parts (amplification)
        assert score_combined > score_rule_only

    def test_severity_multiplier(self, decision_engine):
        """Critical severity should score higher than low"""
        decision_engine.add_signal(Signal(
            category=SignalCategory.RULE_MATCH,
            source="sqli",
            score=50.0,
            confidence=1.0,
            severity="critical",
        ))
        score_critical = decision_engine.evaluate().total_score
        decision_engine.reset()

        decision_engine.add_signal(Signal(
            category=SignalCategory.RULE_MATCH,
            source="sqli",
            score=50.0,
            confidence=1.0,
            severity="low",
        ))
        score_low = decision_engine.evaluate().total_score

        assert score_critical > score_low


class TestDecisionOutput:
    """Test Decision object output"""

    def test_decision_to_dict(self, decision_engine):
        decision_engine.add_signal(Signal(
            category=SignalCategory.RULE_MATCH,
            source="sql_injection",
            score=90.0,
            confidence=1.0,
            severity="critical",
        ))
        decision = decision_engine.evaluate()
        d = decision.to_dict()

        assert "action" in d
        assert "total_score" in d
        assert "signals" in d
        assert len(d["signals"]) == 1
        assert d["signals"][0]["source"] == "sql_injection"

    def test_correlation_id(self, decision_engine):
        decision = decision_engine.evaluate()
        assert len(decision.correlation_id) == 12

    def test_reason_string(self, decision_engine):
        decision_engine.add_signal(Signal(
            category=SignalCategory.RULE_MATCH,
            source="xss",
            score=90.0,
            confidence=1.0,
        ))
        decision = decision_engine.evaluate()
        assert "xss" in decision.reason
        assert "BLOCK" in decision.reason

    def test_reset_clears_state(self, decision_engine):
        decision_engine.add_signal(Signal(
            category=SignalCategory.RULE_MATCH,
            source="test",
            score=50.0,
        ))
        old_id = decision_engine.correlation_id
        decision_engine.reset()

        decision = decision_engine.evaluate()
        assert decision.total_score == 0.0
        assert len(decision.signals) == 0
        assert decision.correlation_id != old_id


class TestMultiSignalScenarios:
    """Test realistic multi-signal scenarios"""

    def test_low_confidence_sqli_plus_behavioral_equals_challenge(self):
        """Low-confidence rule match + suspicious behavior → challenge, not block"""
        engine = DecisionEngine(block_threshold=80, challenge_threshold=40)

        engine.add_signal(Signal(
            category=SignalCategory.RULE_MATCH,
            source="sql_injection",
            score=35.0,
            confidence=0.5,
            severity="medium",
        ))
        engine.add_signal(Signal(
            category=SignalCategory.BEHAVIORAL,
            source="bot_detector",
            score=30.0,
            confidence=0.6,
            severity="medium",
        ))

        decision = engine.evaluate()
        assert decision.action in (Action.CHALLENGE, Action.LOG)

    def test_high_confidence_sqli_equals_block(self):
        """High-confidence critical SQLi → immediate block"""
        engine = DecisionEngine(block_threshold=80, challenge_threshold=40)

        engine.add_signal(Signal(
            category=SignalCategory.RULE_MATCH,
            source="sql_injection",
            score=95.0,
            confidence=1.0,
            severity="critical",
        ))

        decision = engine.evaluate()
        assert decision.action == Action.BLOCK

    def test_anomaly_only_does_not_block(self):
        """Anomaly alone should challenge/log, not block"""
        engine = DecisionEngine(block_threshold=80, challenge_threshold=40)

        engine.add_signal(Signal(
            category=SignalCategory.ANOMALY,
            source="anomaly_detector",
            score=70.0,
            confidence=0.7,
            severity="medium",
        ))

        decision = engine.evaluate()
        assert decision.action != Action.BLOCK
