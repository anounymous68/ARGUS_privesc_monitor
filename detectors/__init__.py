"""Detector package — continuous priv-esc / anomaly scanners."""

from detectors.base import BaseDetector, Finding
from detectors.suid_check import SuidCheckDetector

__all__ = ["BaseDetector", "Finding", "SuidCheckDetector"]
