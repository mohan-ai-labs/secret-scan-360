"""Unit test for AWS keypair detector."""

import sys
import os
from pathlib import Path

# Add src to path for imports
test_dir = Path(__file__).parent
project_root = test_dir.parent.parent
sys.path.insert(0, str(project_root / "src"))

from ss360.detectors.aws_keypair import scan


def test_aws_keypair_detection():
    """Test AWS keypair detector with AKIA + secret keys."""
    
    # Test AKIA key
    akia_key = b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    findings = scan(akia_key, "aws_creds.env")
    
    assert len(findings) == 1, f"Expected 1 finding for AKIA key, got {len(findings)}"
    assert findings[0].rule == "aws_keypair"
    
    # Test AWS secret access key
    secret_key = b"AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    findings = scan(secret_key, "aws_creds.env")
    
    assert len(findings) == 1, f"Expected 1 finding for secret key, got {len(findings)}"
    assert findings[0].rule == "aws_keypair"
    
    # Test both in same file
    both_keys = b"""AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
    findings = scan(both_keys, "aws_creds.env")
    
    assert len(findings) == 2, f"Expected 2 findings for both keys, got {len(findings)}"
    
    # Test no match
    no_aws = b"NO_AWS_KEYS=this_is_not_aws_format"
    findings = scan(no_aws, "config.env")
    
    assert len(findings) == 0, f"Expected 0 findings for no AWS keys, got {len(findings)}"
    
    print("✅ AWS keypair detector working correctly")


if __name__ == "__main__":
    test_aws_keypair_detection()