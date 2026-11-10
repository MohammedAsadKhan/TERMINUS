# File name: __init__.py
# Author: Team LARP
# Date: 2026-11-09
# Version: 0.1.0
# Purpose: Evaluation and benchmark subsystem for Terminus.

"""Evaluation and benchmark subsystem for Terminus."""

from terminus.eval.benchmark import BENCHMARK_SCENARIOS, run_benchmark

__all__ = ["BENCHMARK_SCENARIOS", "run_benchmark"]
