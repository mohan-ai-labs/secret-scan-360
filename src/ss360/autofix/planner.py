# SPDX-License-Identifier: MIT
"""
Autofix planning - generates remediation plans for security findings.
"""
from __future__ import annotations

from enum import Enum


class ActionType(Enum):
    """Types of autofix actions."""
    REMOVE_LITERAL = "remove_literal"
    REPLACE_WITH_SECRET_REF = "replace_with_secret_ref"
    REVOKE_TOKEN = "revoke_token"
   