# File name: __init__.py
# Author: Team LARP
# Date: 2026-11-09
# Version: 0.1.0
# Purpose: Correlation subsystem for Terminus.

"""Correlation subsystem for Terminus."""

from terminus.correlation.stitcher import CampaignStitcher, StitchedCampaign

__all__ = ["CampaignStitcher", "StitchedCampaign"]
