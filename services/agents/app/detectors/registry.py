from __future__ import annotations
import os
from typing import List, Optional

import yaml

from .base import Detector
from .regex_detector import RegexDetector


class DetectorRegistry:
    """Light‑weight container keeping track of detector instances."""

    def __init__(self) -> None:
        self._detectors: List[Detector] = []

    # -- registration -------------------------------------------------
    def register(self, detector: Detector) -> None:
        """Add *detector* to the registry.

        We guard against duplicate names so misconfigured tests fail fast
        rather than silently overriding previous detectors.
        """

        if any(d.name == detector.name for d in self._detectors):
            raise ValueError(f"Duplicate detector: {detector.name}")
        self._detectors.append(detector)

    # -- access helpers ----------------------------------------------
    def detectors(self) -> List[Detector]:
        """Return a copy of the registered detectors.

        The older codebase exposed :func:`detectors` while newer bits used
        :func:`all`.  The tests in this kata expect the former so we keep both
        for backwards compatibility.
        """

        return list(self._detectors)

    # Backwards compatible alias used by ``scanner.scan_tree``
    def all(self) -> List[Detector]:  # pragma: no cover - simple wrapper
        return self.detectors()


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
        "pattern": r"\b(AKIA[0-9A-Z]{16})\b",
        "redact": True,
    },
    {
        "name": "Generic API Key",
        "kind": "Generic API Key",
        "pattern": r"\b(?i)(api_?key|token|secret)[:=]\s*([A-Za-z0-9_\-]{16,})\b",
        "redact": True,
    },
]


DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "config", "detectors.yaml"
)


def build_registry(config_path: Optional[str] = None) -> DetectorRegistry:
    """Create a :class:`DetectorRegistry` from configuration.

    ``config_path`` can be ``None`` in which case the built‑in default rules
    are used.  If a YAML configuration file is supplied we attempt to load the
    rules for :class:`RegexDetector` from it, falling back to
    :data:`DEFAULT_REGEX_RULES` if the file cannot be read.
    """

    reg = DetectorRegistry()
    rules = DEFAULT_REGEX_RULES
    if config_path:
        try:
            with open(config_path, "r") as f:
                cfg = yaml.safe_load(f) or {}
            rules = (cfg or {}).get("regex_detector", {}).get("rules", rules)
        except (FileNotFoundError, yaml.YAMLError):
            # Missing or malformed config is not fatal – we simply use the
            # defaults bundled with the package.  Malformed YAML should not
            # cause the application to crash as this would prevent scanning
            # entirely.
            pass
    reg.register(RegexDetector(rules))
    return reg


def load_registry(config_path: Optional[str] = None) -> DetectorRegistry:
    """Helper used by tests and the scanner to load the registry.

    When ``config_path`` is omitted we look for ``detectors.yaml`` relative to
    this file.  This mirrors the behaviour of the real application while
    keeping the function easy to use in isolation.
    """

    path = config_path or DEFAULT_CONFIG_PATH
    return build_registry(path if os.path.exists(path) else None)


def load_detectors(config_path: Optional[str] = None) -> List[Detector]:
    """Return just the detector instances for convenience."""

    return load_registry(config_path).detectors()
