from __future__ import annotations

from typing import List, Optional
import yaml

from .base import Detector
from .regex_detector import RegexDetector


class DetectorRegistry:
    """Holds all active detectors and provides iteration helpers."""

    def __init__(self) -> None:
        self._detectors: List[Detector] = []

    def register(self, detector: Detector) -> None:
        if any(d.name == detector.name for d in self._detectors):
            raise ValueError(f"Duplicate detector: {detector.name}")
        self._detectors.append(detector)

    def detectors(self) -> List[Detector]:
        """Preferred: returns a shallow copy of registered detectors."""
        return list(self._detectors)

    def all(self) -> List[Detector]:
        """Deprecated alias kept for backward compatibility."""
        return list(self._detectors)


# ---- Default rules (used when no YAML is provided) ----
DEFAULT_REGEX_RULES: List[dict] = [
    {
        "name": "Private Key (RSA)",
        "kind": "Private Key",
        "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
        "redact": True,
    },
    {
        "name": "Private Key (EC)",
        "kind": "Private Key",
        "pattern": r"-----BEGIN EC PRIVATE KEY-----",
        "redact": True,
    },
    # AWS Access Key ID:
    # Commonly 'AKIA' followed by 16 uppercase alnum chars (total length 20).
    {
        "name": "AWS Access Key",
        "kind": "AWS Access Key",
        "pattern": r"\bAKIA[0-9A-Z]{16}\b",
        "redact": True,
    },
    # Generic API-ish tokens (very broad on purpose; tune with YAML as needed)
    {
        "name": "Generic API Key",
        "kind": "Generic API Key",
        "pattern": r"(?i)\b(api_?key|token|secret)\s*[:=]\s*([A-Za-z0-9_\-]{16,})\b",
        "redact": True,
    },
]


def _load_rules_from_yaml(config_path: str) -> List[dict]:
    """Read rules from detectors.yaml (if present), else return defaults."""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return DEFAULT_REGEX_RULES

    rules = (cfg or {}).get("regex_detector", {}).get("rules")
    if isinstance(rules, list) and rules:
        return rules
    return DEFAULT_REGEX_RULES


def build_registry(config_path: Optional[str] = None) -> DetectorRegistry:
    """Construct a registry with a RegexDetector sourced from YAML or defaults."""
    reg = DetectorRegistry()
    rules = _load_rules_from_yaml(config_path) if config_path else DEFAULT_REGEX_RULES
    reg.register(RegexDetector(rules))
    return reg
