"""Unit test for GitHub PAT detector."""

import sys
import os
from pathlib import Path

# Add src to path for imports
test_dir = Path(__file__).parent
project_root = test_dir.parent.parent
sys.path.insert(0, str(project_root / "src"))

from ss360.detectors.github_pat import scan


def test_github_pat_detection():
    """Test GitHub PAT detector with classic and fine-grained samples."""
    
    # Test classic GitHub token
    classic_token = b"GITHUB_TOKEN=ghp_1234567890123456789012345678901234567890"
    findings = scan(classic_token, "secrets.env")
    
    assert len(findings) == 1, f"Expected 1 finding for classic token, got {len(findings)}"
    assert findings[0].rule == "github_pat"
    assert findings[0].severity == "high"
    
    # Test fine-grained GitHub token
    fine_grained_token = b"export TOKEN=github_pat_11ABCDEFGH0123456789012_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEF"
    findings = scan(fine_grained_token, "config.sh")
    
    assert len(findings) == 1, f"Expected 1 finding for fine-grained token, got {len(findings)}"
    assert findings[0].rule == "github_pat"
    
    # Test no match
    no_match = b"This is just regular text without any tokens"
    findings = scan(no_match, "readme.txt")
    
    assert len(findings) == 0, f"Expected 0 findings for no match, got {len(findings)}"
    
    print("✅ GitHub PAT detector working correctly")


if __name__ == "__main__":
    test_github_pat_detection()