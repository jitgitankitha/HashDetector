"""
hashdetector.detector
======================
Academic hash-type identification package.

Public API:
    identify(value, context=None) -> DetectionResult
    identify_compound(value, context=None) -> list[DetectionResult]
"""

from .detector import identify, identify_compound
from .models import HashMatch, DetectionResult, Tier

__all__ = [
    "identify",
    "identify_compound",
    "HashMatch",
    "DetectionResult",
    "Tier",
]

__version__ = "0.1.0"
