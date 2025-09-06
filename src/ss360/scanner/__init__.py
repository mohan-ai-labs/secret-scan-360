"""Public API for Secret Scan 360 (v0).

Humans can import the scanner layer like:
    from ss360.scanner import Scanner, DetectorRegistry

Internally this still re-exports from the legacy services.* modules.
In Phase 2 the implementation will move under src/ss360/.
"""

import sys
from pathlib import Path

# Add project root to path for legacy imports
_project_root = str(Path(__file__).parent.parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

try:
    from services.agents.app.core.scanner import Scanner
    from services.agents.app.detectors.registry import DetectorRegistry
except ImportError:
    # Fallback to direct scanning if legacy services unavailable
    Scanner = None
    DetectorRegistry = None

__all__ = ["Scanner", "DetectorRegistry"]
