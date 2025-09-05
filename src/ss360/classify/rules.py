# SPDX-License-Identifier: MIT
"""
Classification rules for security findings.

Implements rule-based classification to categorize findings as:
actual, expired, test, or unknown.
"""
from __future__ import annotations

import re
import json
import base64
from datetime import datetime
from typing import Dict, Any, List, Tuple, Literal, Optional
from urllib.parse import parse_qs, urlparse

FindingCategory = Literal["actual", "expired", "test", "unknown"]


def classify(
    finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None
) -> Tuple[FindingCategory, float, List[str]]:
    """
    Classify a finding into a category with confidence and reasons.

    Args:
        finding: The security finding to classify
        context: Optional context (validation results, repo info, etc.)

    Returns:
        Tuple of (category, confidence, reasons)

    Rules (prioritize highest confidence):
    1. Offline expiry: JWT(exp) past => expired; Azure SAS(se) past => expired
    2. Validator signals: confirmed & not expired => actual; explicit invalid(expired) => expired
    3. Test markers: path/filename/value patterns => test
    4. Entropy/placeholder heuristic => test (low confidence)
    """
    context = context or {}

    # Get basic finding info
    match = finding.get("match", "")
    path = finding.get("path", "")
    kind = finding.get("kind", finding.get("id", ""))
    all_reasons = []
    candidates = []

    # Rule 1: Check offline expiry (high confidence)
    expiry_result = _check_offline_expiry(match, kind)
    all_reasons.extend(expiry_result[2])
    if expiry_result[1] > 0.8:  # High confidence expiry check
        return expiry_result
    elif expiry_result[1] > 0.0:
        candidates.append(expiry_result)

    # Rule 2: Check validator signals (high confidence) - prioritize over test markers
    validation_results = context.get("validation_results", [])
    validator_result = _check_validator_signals(validation_results)
    all_reasons.extend(validator_result[2])
    if validator_result[1] > 0.8:  # High confidence from validators
        return validator_result
    elif validator_result[1] > 0.0:
        candidates.append(validator_result)

    # Rule 3: Check test markers (high confidence)
    test_result = _check_test_markers(match, path, kind)
    all_reasons.extend(test_result[2])
    if test_result[1] > 0.8:  # High confidence test markers
        return test_result
    elif test_result[1] > 0.0:
        candidates.append(test_result)

    # Rule 4: Low confidence heuristics
    entropy_result = _check_entropy_placeholder(match)
    all_reasons.extend(entropy_result[2])
    if entropy_result[1] > 0.0:
        candidates.append(entropy_result)

    # Return highest confidence candidate
    if candidates:
        best_candidate = max(candidates, key=lambda x: x[1])
        return best_candidate

    # Default: unknown (include all collected reasons)
    return (
        "unknown",
        0.1,
        all_reasons if all_reasons else ["no_classification_rules_matched"],
    )


def _check_offline_expiry(
    match: str, kind: str
) -> Tuple[FindingCategory, float, List[str]]:
    """Check for offline expiry indicators."""
    reasons = []

    # JWT expiry check
    if "jwt" in kind.lower() or _looks_like_jwt(match):
        try:
            expiry_time = _extract_jwt_expiry(match)
            if expiry_time:
                now = datetime.utcnow()
                if expiry_time < now:
                    reasons.append("offline:jwt_expired")
                    return ("expired", 0.95, reasons)
                else:
                    reasons.append("offline:jwt_valid_future_exp")
                    # Don't return here - could still be test
        except Exception:
            pass

    # Azure SAS expiry check
    if "azure" in kind.lower() or "sas" in kind.lower() or "se=" in match:
        try:
            expiry_time = _extract_azure_sas_expiry(match)
            if expiry_time:
                now = datetime.utcnow()
                if expiry_time < now:
                    reasons.append("offline:azure_sas_expired")
                    return ("expired", 0.95, reasons)
                else:
                    reasons.append("offline:azure_sas_valid_future_exp")
                    # Don't return here - could still be test
        except Exception:
            pass

    return ("unknown", 0.0, reasons)


def _check_test_markers(
    match: str, path: str, kind: str
) -> Tuple[FindingCategory, float, List[str]]:
    """Check for test/sample/demo markers."""
    reasons = []

    # Path-based markers (high confidence)
    test_path_patterns = [
        r"tests?/",
        r"fixtures?/",
        r"examples?/",
        r"samples?/",
        r"mocks?/",
        r"demos?/",
        r"/run_tests\.py$",
        r"test_.*\.py$",
        r".*_test\.py$",
        r"spec/",
        r"__tests__/",
    ]

    path_lower = path.lower()
    for pattern in test_path_patterns:
        if re.search(pattern, path_lower):
            reasons.append(f"path:{pattern}")
            return ("test", 0.9, reasons)

    # Filename markers (high confidence)
    filename = path.split("/")[-1].lower() if path else ""
    test_filename_patterns = [
        "test",
        "sample",
        "example",
        "dummy",
        "fixture",
        "mock",
        "demo",
    ]

    for pattern in test_filename_patterns:
        if pattern in filename:
            reasons.append(f"filename:{pattern}")
            return ("test", 0.85, reasons)

    # Value content markers (medium confidence) - be selective to avoid false positives
    match_upper = match.upper()

    # Primary test markers - these are explicit test indicators
    primary_test_patterns = [
        "TEST",
        "EXAMPLE",
        "DUMMY",
        "SAMPLE",
        "MOCK",
        "FAKE",
        "PLACEHOLDER",
        "XXX",
    ]

    for pattern in primary_test_patterns:
        if pattern in match_upper:
            reasons.append(f"marker:{pattern}")
            return ("test", 0.7, reasons)

    # Repetitive patterns - only for values that are obviously placeholders
    # Check for strings that are mostly or entirely repetitive patterns
    if len(match) >= 10:
        # Pattern: entirely zeros
        if re.match(r"^0+$", match):
            reasons.append("marker:all_zeros")
            return ("test", 0.7, reasons)

        # Pattern: entirely same character repeated
        if len(set(match.upper())) == 1:
            reasons.append("marker:repeated_char")
            return ("test", 0.7, reasons)

        # Pattern: entirely sequential same digit (000000, 111111, etc)
        if re.match(r"^(\d)\1{5,}$", match):
            reasons.append("marker:repeated_digit")
            return ("test", 0.7, reasons)

    # Very obvious placeholder patterns in shorter strings
    if len(match) <= 16:
        obvious_patterns = ["000000", "123456", "ABCDEF"]
        for pattern in obvious_patterns:
            # Only if it's the dominant part of a short string
            if pattern in match_upper and len(pattern) >= len(match) * 0.6:
                reasons.append(f"marker:{pattern}")
                return ("test", 0.7, reasons)

    return ("unknown", 0.0, reasons)


def _check_validator_signals(
    validation_results: List[Dict[str, Any]],
) -> Tuple[FindingCategory, float, List[str]]:
    """Check validator results for classification signals."""
    reasons = []

    # Look for explicit validator signals
    for result in validation_results:
        state = result.get("state", "")
        validator_name = result.get("validator_name", "")
        evidence = result.get("evidence") or ""
        reason = result.get("reason") or ""

        # Confirmed valid
        if state == "valid":
            # Check if validator indicated expiry
            combined_text = (evidence + " " + reason).lower()
            if any(word in combined_text for word in ["expired", "invalid", "revoked"]):
                reasons.append(f"validator:{validator_name}:expired")
                return ("expired", 0.9, reasons)
            else:
                reasons.append(f"validator:{validator_name}:confirmed")
                return ("actual", 0.9, reasons)

        # Explicit invalid due to expiry
        elif state == "invalid":
            combined_text = (evidence + " " + reason).lower()
            if any(word in combined_text for word in ["expired", "expiry"]):
                reasons.append(f"validator:{validator_name}:expired")
                return ("expired", 0.85, reasons)

    return ("unknown", 0.0, reasons)


def _check_entropy_placeholder(match: str) -> Tuple[FindingCategory, float, List[str]]:
    """Check for low entropy or placeholder patterns (low confidence)."""
    reasons = []

    if len(match) < 8:
        return ("unknown", 0.0, reasons)

    # Sequential patterns (check first, most specific)
    if _has_sequential_pattern(match):
        reasons.append("entropy:sequential")
        return ("test", 0.3, reasons)

    # Repeated character patterns
    if len(set(match)) <= 3 and len(match) > 10:
        reasons.append("entropy:repeated_chars")
        return ("test", 0.4, reasons)

    # Very low entropy suggests placeholder (check last, least specific)
    entropy = _calculate_entropy(match)
    if entropy < 2.0:  # Very low entropy
        reasons.append("entropy:low")
        return ("test", 0.3, reasons)

    return ("unknown", 0.0, reasons)


def _looks_like_jwt(token: str) -> bool:
    """Check if string looks like a JWT token."""
    parts = token.split(".")
    return len(parts) == 3 and all(len(part) > 0 for part in parts)


def _extract_jwt_expiry(token: str) -> Optional[datetime]:
    """Extract expiry time from JWT token."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        # Decode payload (second part)
        payload = parts[1]
        # Add padding if needed
        payload += "=" * (4 - len(payload) % 4)

        decoded = base64.b64decode(payload, validate=True)
        data = json.loads(decoded)

        if "exp" in data:
            return datetime.utcfromtimestamp(data["exp"])
    except Exception:
        pass
    return None


def _extract_azure_sas_expiry(sas_url: str) -> Optional[datetime]:
    """Extract expiry time from Azure SAS URL."""
    try:
        parsed = urlparse(sas_url)
        params = parse_qs(parsed.query)

        # Look for 'se' parameter (signed expiry)
        if "se" in params:
            expiry_str = params["se"][0]
            # Azure SAS expiry format: 2023-12-31T23:59:59Z
            return datetime.fromisoformat(expiry_str.replace("Z", "+00:00")).replace(
                tzinfo=None
            )
    except Exception:
        pass
    return None


def _calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of text."""
    if not text:
        return 0.0

    from collections import Counter
    import math

    counts = Counter(text)
    length = len(text)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def _has_sequential_pattern(text: str) -> bool:
    """Check for sequential character patterns."""
    if len(text) < 6:  # Require longer sequences
        return False

    # Check for ascending sequences (abc, 123) - need at least 4 in a row
    ascending_count = 0
    for i in range(len(text) - 1):
        if ord(text[i + 1]) == ord(text[i]) + 1:
            ascending_count += 1
        else:
            ascending_count = 0
        if ascending_count >= 4:  # Increased threshold
            return True

    return False
