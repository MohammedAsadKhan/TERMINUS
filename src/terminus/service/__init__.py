# File name: __init__.py
# Author: Team LARP
# Date: 2026-11-09
# Version: 0.1.0
# Purpose: Terminus Service Management and Auto-Configuration Module.

"""Terminus Service Management and Auto-Configuration Module."""

from terminus.service.sensor import ServiceConnectionSensor, service_sensor

__all__ = ["ServiceConnectionSensor", "service_sensor"]
