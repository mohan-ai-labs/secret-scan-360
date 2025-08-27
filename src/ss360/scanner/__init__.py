"""Public API for Secret Scan 360 (v0).

Humans can import the scanner layer like:
    from ss360.scanner import Scanner, DetectorRegistry

Internally this still re-exports from the legacy services.* modules.
In Phase 2 the implementation will move under src/ss360/.
"""
from services.agents.app.core.scanner import Scanner
from services.agents.app.detectors.registry import DetectorRegistry

__all__ = ["Scanner", "DetectorRegistry"]
