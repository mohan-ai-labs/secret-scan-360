"""Smoke test for detector registry."""

import sys
import os
from pathlib import Path

# Add src to path for imports
test_dir = Path(__file__).parent
project_root = test_dir.parent.parent
sys.path.insert(0, str(project_root / "src"))

from ss360.detectors import get_detector_registry


def test_registry_has_required_detectors():
    """Assert the registry has at least the 6 core detector keys."""
    registry = get_detector_registry()
    detectors = registry.all_detectors()
    
    required_detectors = {
        "github_pat",
        "azure_sas", 
        "slack_webhook",
        "aws_keypair",
        "jwt_generic",
        "gcp_service_account_key"
    }
    
    loaded_detectors = set(detectors.keys())
    
    print(f"Required detectors: {required_detectors}")
    print(f"Loaded detectors: {loaded_detectors}")
    
    missing = required_detectors - loaded_detectors
    assert not missing, f"Missing required detectors: {missing}"
    
    print("✅ All required detectors are loaded")


if __name__ == "__main__":
    test_registry_has_required_detectors()