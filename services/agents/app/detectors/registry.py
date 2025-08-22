from __future__ import annotations
from typing import List, Optional
import yaml

from .base import Detector
from .regex_detector import RegexDetector


class DetectorRegistry:
    def __init__(self) -> None:
        self._detectors: List[Detector] = []

    def register(self, detector: Detector) -> None:
        if any(d.name == detector.name for d in self._detectors):
            raise ValueError(f"Duplicate detector: {detector.name}")
        self._detectors.append(detector)

    def all(self) -> List[Detector]:
        return list(self._detectors)


DEFAULT_REGEX_RULES = [
    {
        "name": "Private Key (RSA)",
        "kind": "Private Key",
        "pattern": "-----BEGIN RSA PRIVATE KEY-----",
        "redact": True,
    },
    {
        "name": "Private Key (EC)",
        "kind": "Private Key",
        "pattern": "-----BEGIN EC PRIVATE KEY-----",
        "redact": True,
    },
    {
        "name": "AWS Access Key",
        "kind": "AWS Access Key",
        "pattern": r"\b(AKI[0-9A-Z]{17})\b",
        "redact": True,
    },
    {
        "name": "Generic API Key",
        "kind": "Generic API Key",
        "pattern": r"\b(?i)(api_?key|token|secret)[:=]\s*([A-Za-z0-9_\-]{16,})\b",
        "redact": True,
    },
]


def build_registry(config_path: Optional[str] = None) -> DetectorRegistry:
    reg = DetectorRegistry()
    rules = DEFAULT_REGEX_RULES
    if config_path:
        try:
            with open(config_path, "r") as f:
                cfg = yaml.safe_load(f) or {}
            rules = (cfg or {}).get("regex_detector", {}).get("rules", rules)
        except FileNotFoundError:
            pass
    reg.register(RegexDetector(rules))
    return reg
