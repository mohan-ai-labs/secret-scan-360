"""
Unit tests for SS360 detectors and core functionality.
Run with: PYTHONPATH=src python tests/test_detectors_unit.py
"""
import os
import sys
from pathlib import Path

# Ensure we're in the right directory
test_dir = Path(__file__).parent
project_root = test_dir.parent
os.chdir(project_root)

# Add src to path for imports
sys.path.insert(0, str(project_root / "src"))

# Add project root for detectors imports
sys.path.insert(0, str(project_root))


def test_github_pat_detector():
    """Test GitHub PAT detector patterns."""
    print("Testing GitHub PAT detector...")
    
    from ss360.detectors import get_detector_registry
    registry = get_detector_registry()
    detectors = registry.all_detectors()
    
    assert "github_pat" in detectors, "GitHub PAT detector not found"
    
    scan_func = detectors["github_pat"]
    
    # Test classic PAT
    findings = scan_func(b"TOKEN=ghp_1234567890123456789012345678901234567890", "test.env")
    assert len(findings) == 1, f"Expected 1 finding for classic PAT, got {len(findings)}"
    assert findings[0].rule == "github_pat"
    
    # Test fine-grained PAT
    findings = scan_func(b"PAT=github_pat_11AAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "test.env")
    assert len(findings) == 1, f"Expected 1 finding for fine-grained PAT, got {len(findings)}"
    assert findings[0].rule == "github_pat"
    
    # Test no match
    findings = scan_func(b"TOKEN=not_a_token", "test.env")
    assert len(findings) == 0, f"Expected 0 findings for non-token, got {len(findings)}"
    
    print("✅ GitHub PAT detector working correctly")


def test_aws_keypair_detector():
    """Test AWS Access Key detector patterns."""
    print("Testing AWS keypair detector...")
    
    from ss360.detectors import get_detector_registry
    registry = get_detector_registry()
    detectors = registry.all_detectors()
    
    assert "aws_keypair" in detectors, "AWS keypair detector not found"
    
    scan_func = detectors["aws_keypair"]
    
    # Test Access Key ID
    findings = scan_func(b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "test.env")
    assert len(findings) == 1, f"Expected 1 finding for AWS key ID, got {len(findings)}"
    assert findings[0].rule == "aws_keypair"
    
    # Test Secret Access Key
    findings = scan_func(b"AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "test.env")
    assert len(findings) == 1, f"Expected 1 finding for AWS secret, got {len(findings)}"
    assert findings[0].rule == "aws_keypair"
    
    # Test no match
    findings = scan_func(b"AWS_REGION=us-east-1", "test.env")
    assert len(findings) == 0, f"Expected 0 findings for non-key, got {len(findings)}"
    
    print("✅ AWS keypair detector working correctly")


def test_azure_sas_detector():
    """Test Azure SAS token detector."""
    print("Testing Azure SAS detector...")
    
    from ss360.detectors import get_detector_registry
    registry = get_detector_registry()
    detectors = registry.all_detectors()
    
    assert "azure_sas" in detectors, "Azure SAS detector not found"
    
    scan_func = detectors["azure_sas"]
    
    # Test SAS URL
    sas_url = b"URL=https://myaccount.blob.core.windows.net/container?sv=2022-11-02&se=2023-01-01T00:00:00Z&sr=b&sp=r&sig=XXXX"
    findings = scan_func(sas_url, "test.env")
    assert len(findings) == 1, f"Expected 1 finding for SAS URL, got {len(findings)}"
    assert findings[0].rule == "azure_sas"
    
    # Test no match
    findings = scan_func(b"URL=https://example.com", "test.env")
    assert len(findings) == 0, f"Expected 0 findings for regular URL, got {len(findings)}"
    
    print("✅ Azure SAS detector working correctly")


def test_slack_webhook_detector():
    """Test Slack webhook detector."""
    print("Testing Slack webhook detector...")
    
    from ss360.detectors import get_detector_registry
    registry = get_detector_registry()
    detectors = registry.all_detectors()
    
    assert "slack_webhook" in detectors, "Slack webhook detector not found"
    
    scan_func = detectors["slack_webhook"]
    
    # Test webhook URL
    webhook_url = b"WEBHOOK=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    findings = scan_func(webhook_url, "test.env")
    assert len(findings) == 1, f"Expected 1 finding for webhook URL, got {len(findings)}"
    assert findings[0].rule == "slack_webhook"
    
    # Test no match
    findings = scan_func(b"URL=https://slack.com", "test.env")
    assert len(findings) == 0, f"Expected 0 findings for regular Slack URL, got {len(findings)}"
    
    print("✅ Slack webhook detector working correctly")


def test_jwt_detector():
    """Test JWT detector."""
    print("Testing JWT detector...")
    
    from ss360.detectors import get_detector_registry
    registry = get_detector_registry()
    detectors = registry.all_detectors()
    
    assert "jwt_generic" in detectors, "JWT detector not found"
    
    scan_func = detectors["jwt_generic"]
    
    # Test JWT token
    jwt_token = b"JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    findings = scan_func(jwt_token, "test.env")
    assert len(findings) == 1, f"Expected 1 finding for JWT token, got {len(findings)}"
    assert findings[0].rule == "jwt_generic"
    
    # Test no match
    findings = scan_func(b"TOKEN=not_a_jwt", "test.env")
    assert len(findings) == 0, f"Expected 0 findings for non-JWT, got {len(findings)}"
    
    print("✅ JWT detector working correctly")


def test_gcp_service_account_detector():
    """Test GCP Service Account detector."""
    print("Testing GCP Service Account detector...")
    
    from ss360.detectors import get_detector_registry
    registry = get_detector_registry()
    detectors = registry.all_detectors()
    
    assert "gcp_service_account_key" in detectors, "GCP Service Account detector not found"
    
    scan_func = detectors["gcp_service_account_key"]
    
    # Test service account JSON
    sa_json = b'{"type": "service_account", "project_id": "test", "private_key_id": "123", "private_key": "-----BEGIN PRIVATE KEY-----\\ntest\\n-----END PRIVATE KEY-----\\n", "client_email": "test@test.iam.gserviceaccount.com"}'
    findings = scan_func(sa_json, "test.json")
    assert len(findings) == 1, f"Expected 1 finding for service account JSON, got {len(findings)}"
    assert findings[0].rule == "gcp_service_account_key"
    
    # Test no match
    findings = scan_func(b'{"type": "user"}', "test.json")
    assert len(findings) == 0, f"Expected 0 findings for non-SA JSON, got {len(findings)}"
    
    print("✅ GCP Service Account detector working correctly")


def test_redaction():
    """Test that secrets are properly redacted."""
    print("Testing redaction...")
    
    from ss360.detectors import get_detector_registry
    registry = get_detector_registry()
    
    secret_value = "ghp_VERYSECRETTOKEN1234567890123456789012"
    findings = registry.scan_with_all(f"TOKEN={secret_value}".encode(), "test.env")
    
    # Ensure no finding contains the full secret
    for finding in findings:
        finding_dict = finding.to_dict()
        for key, value in finding_dict.items():
            if isinstance(value, str):
                assert secret_value not in value, f"Found unredacted secret in {key}: {value}"
    
    print("✅ Redaction working correctly")


def main():
    """Run all tests."""
    print("🧪 Running SS360 Unit Tests")
    print("=" * 50)
    
    test_github_pat_detector()
    test_aws_keypair_detector()
    test_azure_sas_detector()
    test_slack_webhook_detector()
    test_jwt_detector()
    test_gcp_service_account_detector()
    test_redaction()
    
    print("\n🎉 All unit tests passed!")


if __name__ == "__main__":
    main()