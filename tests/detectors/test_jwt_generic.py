"""Unit test for JWT generic detector."""

import sys
import os
from pathlib import Path

# Add src to path for imports
test_dir = Path(__file__).parent
project_root = test_dir.parent.parent
sys.path.insert(0, str(project_root / "src"))

from ss360.detectors.jwt_generic import scan


def test_jwt_generic_detection():
    """Test JWT detector with expired and future exp claims."""
    
    # Test expired JWT (exp in the past - Unix timestamp for 2023-01-01)
    expired_jwt = b"TOKEN=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNjcyNTMxMjAwfQ.example_signature_here"
    findings = scan(expired_jwt, "auth.env")
    
    assert len(findings) == 1, f"Expected 1 finding for expired JWT, got {len(findings)}"
    assert findings[0].rule == "jwt_generic"
    assert findings[0].severity == "medium"
    
    # Test future JWT (exp in the future - Unix timestamp for 2030-01-01)  
    future_jwt = b"AUTH_TOKEN=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxODkzNDU2MDAwfQ.future_signature_example"
    findings = scan(future_jwt, "config.env")
    
    assert len(findings) == 1, f"Expected 1 finding for future JWT, got {len(findings)}"
    assert findings[0].rule == "jwt_generic"
    
    # Test malformed JWT (should not match)
    malformed = b"NOT_JWT=this.is.not.a.valid.jwt.format"
    findings = scan(malformed, "config.txt")
    
    assert len(findings) == 0, f"Expected 0 findings for malformed JWT, got {len(findings)}"
    
    print("✅ JWT detector working correctly")


if __name__ == "__main__":
    test_jwt_generic_detection()