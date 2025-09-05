# SPDX-License-Identifier: MIT
"""
Finding classification system.

Provides automatic classification of findings into:
- actual: Confirmed valid credentials
- expired: Expired or invalid credentials  
- test: Test/mock/sample credentials
- unknown: Classification uncertain
"""

from .rules import classify, FindingCategory

__all__ = ["classify", "FindingCategory"]