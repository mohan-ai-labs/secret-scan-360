# SPDX-License-Identifier: MIT
# Public API façade re-exporting the internal implementation.
try:
    from services.agents.app.core.scanner import Scanner  # type: ignore
    from services.agents.app.detectors.registry import DetectorRegistry  # type: ignore
except ImportError:
    # Fallback if legacy services unavailable
    Scanner = None  # type: ignore
    DetectorRegistry = None  # type: ignore

__all__ = ["Scanner", "DetectorRegistry"]
