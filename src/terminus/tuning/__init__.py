"""Detection engineering tuning subsystem for Terminus."""

from terminus.tuning.backtest import BacktestResult, RuleBacktestSimulator
from terminus.tuning.metrics import StatisticalConfidenceMetrics, calculate_wilson_score_interval, evaluate_rule_statistical_precision
from terminus.tuning.service import DetectionTuningAdvisor, TuningRecommendation
from terminus.tuning.synthesizer import RuleSeverity, RuleStatus, RuleSynthesizer, SigmaRule, YaraRule

__all__ = [
    "BacktestResult",
    "DetectionTuningAdvisor",
    "RuleBacktestSimulator",
    "RuleSeverity",
    "RuleStatus",
    "RuleSynthesizer",
    "SigmaRule",
    "StatisticalConfidenceMetrics",
    "TuningRecommendation",
    "YaraRule",
    "calculate_wilson_score_interval",
    "evaluate_rule_statistical_precision",
]
