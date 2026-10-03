"""Statistical Precision & Wilson Score Lower Bound Engine for TERMINUS.

Provides empirical confidence interval calculation for detection rule precision,
preventing deployment of overfit or noisy rules.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class StatisticalConfidenceMetrics:
    total_evaluated: int
    true_positives: int
    false_positives: int
    observed_precision: float
    wilson_lower_bound_precision: float
    wilson_upper_bound_precision: float
    false_positive_rate_baseline: float
    is_statistically_sound: bool
    confidence_level: float = 0.95


def calculate_wilson_score_interval(
    successes: int,
    total: int,
    confidence: float = 0.95,
) -> tuple[float, float]:
    """Calculates Wilson score confidence interval.

    Returns (lower_bound, upper_bound) bounded within [0.0, 1.0].
    """
    if total <= 0:
        return 0.0, 0.0

    z_map = {0.90: 1.64485, 0.95: 1.95996, 0.99: 2.57583}
    z = z_map.get(confidence, 1.95996)

    p_hat = successes / total
    z2 = z * z
    denominator = 1.0 + (z2 / total)
    center = p_hat + (z2 / (2.0 * total))
    spread = z * math.sqrt((p_hat * (1.0 - p_hat) / total) + (z2 / (4.0 * total * total)))

    lower = max(0.0, (center - spread) / denominator)
    upper = min(1.0, (center + spread) / denominator)
    return round(lower, 4), round(upper, 4)


def evaluate_rule_statistical_precision(
    historical_tp: int,
    historical_fp: int,
    total_historical_events: int,
    min_wlb_threshold: float = 0.80,
    confidence: float = 0.95,
) -> StatisticalConfidenceMetrics:
    """Evaluates rule precision with statistical rigor using Wilson lower bounds."""
    total_alerts_fired = historical_tp + historical_fp
    if total_alerts_fired == 0:
        return StatisticalConfidenceMetrics(
            total_evaluated=total_historical_events,
            true_positives=0,
            false_positives=0,
            observed_precision=1.0,
            wilson_lower_bound_precision=0.0,
            wilson_upper_bound_precision=1.0,
            false_positive_rate_baseline=0.0,
            is_statistically_sound=False,
            confidence_level=confidence,
        )

    obs_precision = round(historical_tp / total_alerts_fired, 4)
    wlb, wub = calculate_wilson_score_interval(historical_tp, total_alerts_fired, confidence)
    fp_rate = round(historical_fp / max(total_historical_events, 1), 6)
    is_sound = (wlb >= min_wlb_threshold) and (fp_rate <= 0.05)

    return StatisticalConfidenceMetrics(
        total_evaluated=total_historical_events,
        true_positives=historical_tp,
        false_positives=historical_fp,
        observed_precision=obs_precision,
        wilson_lower_bound_precision=wlb,
        wilson_upper_bound_precision=wub,
        false_positive_rate_baseline=fp_rate,
        is_statistically_sound=is_sound,
        confidence_level=confidence,
    )
