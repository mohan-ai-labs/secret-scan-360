"""
Comprehensive test for all detector types using a sample tokens file.

Tests that:
- All 8 secret types are detected (9 findings expected due to AWS key pair)
- Each detector rule appears at least once
- Expired tokens are classified as "expired"
- All evidence is properly redacted
- CLI honors --raw flag and loads policy correctly
"""

import os
import tempfile
import json
from pathlib import Path

import pytest
import sys

# Add src to path for imports
test_dir = Path(__file__).parent
project_root = test_dir.parent.parent
sys.path.insert(0, str(project_root / "src"))

from ss360.scanner.direct import scan_with_policy_and_classification


class TestTokensFile:
    """Test comprehensive secret detection using a sample tokens file."""

    @pytest.fixture
    def sample_tokens_content(self):
        """Sample tokens file content with all 8 secret types."""
        return """# Sample tokens file with 8 different secret types for testing

# 1. Classic GitHub PAT
GITHUB_TOKEN_CLASSIC=ghp_1234567890123456789012345678901234567890

# 2. Fine-grained GitHub PAT  
GITHUB_TOKEN_FINE_GRAINED=github_pat_11AAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB

# 3. Expired Azure SAS token (expired 2022-01-01)
EXPIRED_AZURE_SAS=https://mystorageaccount.blob.core.windows.net/mycontainer?sv=2020-08-04&se=2022-01-01T00:00:00Z&sr=c&sp=r&sig=fakesignatureforexpiredtestingonly

# 4. Future Azure SAS token (expires 2030-01-01)
FUTURE_AZURE_SAS=https://futurestorage.blob.core.windows.net/container?sv=2022-11-02&se=2030-01-01T00:00:00Z&sr=b&sp=r&sig=futuresignatureexample

# 5. Slack webhook URL
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX

# 6. Expired JWT token (expired)
EXPIRED_JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.keH6T3x1z7mmhKL1T3r09-BTSJrKz16gWgcr5XdGJy4

# 7. AWS Access Key and Secret Key pair
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# 8. GCP Service Account Key snippet (JSON format)
GCP_SERVICE_ACCOUNT_KEY={
  "type": "service_account",
  "project_id": "test-project",
  "private_key_id": "1234567890abcdef",
  "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\\n-----END PRIVATE KEY-----\\n",
  "client_email": "test@test-project.iam.gserviceaccount.com",
  "client_id": "123456789012345678901",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token"
}"""

    @pytest.fixture
    def policy_content(self):
        """Permissive policy for testing."""
        return """version: 1
validators:
  allow_network: false
budgets:
  new_findings: 999
  max_risk_score: 999"""

    def test_all_detector_types_detected(self, sample_tokens_content, policy_content):
        """Test that all detector types find their respective secrets."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Write tokens file
            tokens_file = Path(temp_dir) / "tokens.txt"
            tokens_file.write_text(sample_tokens_content)
            
            # Write policy file
            policy_file = Path(temp_dir) / "policy.yml"
            policy_file.write_text(policy_content)
            
            # Scan with raw mode and policy
            result = scan_with_policy_and_classification(
                root_path=str(tokens_file),
                policy_path=str(policy_file),
                raw_mode=True
            )
            
            # Should have at least 8 findings (likely 9 due to AWS key pair)
            assert result["total"] >= 8, f"Expected at least 8 findings, got {result['total']}"
            
            # Collect all detected rules
            detected_rules = set()
            for finding in result["findings"]:
                rule = finding.get("id", finding.get("rule"))
                detected_rules.add(rule)
            
            # Verify each expected rule appears at least once
            expected_rules = {
                "github_pat",
                "azure_sas", 
                "slack_webhook",
                "aws_keypair",
                "jwt_generic",
                "gcp_service_account_key"
            }
            
            missing_rules = expected_rules - detected_rules
            assert not missing_rules, f"Missing detector rules: {missing_rules}"
            
            print(f"✓ All {len(expected_rules)} detector types found secrets")

    def test_expired_tokens_classified_correctly(self, sample_tokens_content, policy_content):
        """Test that expired SAS and JWT tokens are classified as 'expired'."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Write tokens file
            tokens_file = Path(temp_dir) / "tokens.txt"
            tokens_file.write_text(sample_tokens_content)
            
            # Write policy file
            policy_file = Path(temp_dir) / "policy.yml"
            policy_file.write_text(policy_content)
            
            # Scan with raw mode
            result = scan_with_policy_and_classification(
                root_path=str(tokens_file),
                policy_path=str(policy_file),
                raw_mode=True
            )
            
            # Find expired tokens
            expired_findings = [f for f in result["findings"] if f.get("category") == "expired"]
            
            # Should have at least 2 expired findings (Azure SAS + JWT)
            assert len(expired_findings) >= 2, f"Expected at least 2 expired findings, got {len(expired_findings)}"
            
            # Verify we have expired Azure SAS and JWT
            expired_rules = {f.get("id", f.get("rule")) for f in expired_findings}
            assert "azure_sas" in expired_rules, "Expected expired Azure SAS token"
            assert "jwt_generic" in expired_rules, "Expected expired JWT token"
            
            print(f"✓ {len(expired_findings)} expired tokens correctly classified")

    def test_secrets_are_redacted(self, sample_tokens_content, policy_content):
        """Test that no plaintext secrets appear in the output."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Write tokens file
            tokens_file = Path(temp_dir) / "tokens.txt"
            tokens_file.write_text(sample_tokens_content)
            
            # Write policy file
            policy_file = Path(temp_dir) / "policy.yml"
            policy_file.write_text(policy_content)
            
            # Scan with raw mode
            result = scan_with_policy_and_classification(
                root_path=str(tokens_file),
                policy_path=str(policy_file),
                raw_mode=True
            )
            
            # List of full secrets that should NOT appear in output
            plaintext_secrets = [
                "ghp_1234567890123456789012345678901234567890",
                "github_pat_11AAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "fakesignatureforexpiredtestingonly",
                "futuresignatureexample", 
                "XXXXXXXXXXXXXXXXXXXXXXXX",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.keH6T3x1z7mmhKL1T3r09-BTSJrKz16gWgcr5XdGJy4",
            ]
            
            # Convert result to JSON string for checking
            result_json = json.dumps(result)
            
            # Verify no plaintext secrets are in the output
            for secret in plaintext_secrets:
                assert secret not in result_json, f"Found unredacted secret in output: {secret[:10]}..."
            
            # Verify that redacted hints are present instead
            redacted_indicators = [
                "[SAS-TOKEN-REDACTED]",
                "[REDACTED]", 
                "[JWT-REDACTED]",
                "...",  # Indicates truncation
            ]
            
            for indicator in redacted_indicators:
                assert indicator in result_json, f"Expected redaction indicator '{indicator}' not found"
            
            print("✓ All secrets properly redacted in output")

    def test_policy_loading_message(self, sample_tokens_content, policy_content):
        """Test that policy loading message is printed with absolute path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Write tokens file
            tokens_file = Path(temp_dir) / "tokens.txt"
            tokens_file.write_text(sample_tokens_content)
            
            # Write policy file
            policy_file = Path(temp_dir) / "policy.yml"
            policy_file.write_text(policy_content)
            
            # Capture stdout to check for policy loading message
            import io
            import contextlib
            
            stdout_capture = io.StringIO()
            
            with contextlib.redirect_stdout(stdout_capture):
                result = scan_with_policy_and_classification(
                    root_path=str(tokens_file),
                    policy_path=str(policy_file),
                    raw_mode=True
                )
            
            output = stdout_capture.getvalue()
            
            # Check that policy loading message with absolute path is printed
            expected_msg = f"[ss360] Loaded policy: {policy_file.resolve()}"
            assert expected_msg in output, f"Expected policy loading message not found. Output: {output}"
            
            # Verify policy was actually loaded successfully
            assert result["policy_result"]["passed"], "Policy should pass with permissive settings"
            
            print("✓ Policy loading message displayed correctly")

    def test_raw_mode_vs_git_mode(self, sample_tokens_content, policy_content):
        """Test that raw mode finds all secrets while git mode may filter some."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Write tokens file
            tokens_file = Path(temp_dir) / "tokens.txt"
            tokens_file.write_text(sample_tokens_content)
            
            # Write policy file
            policy_file = Path(temp_dir) / "policy.yml"
            policy_file.write_text(policy_content)
            
            # Scan in raw mode
            result_raw = scan_with_policy_and_classification(
                root_path=str(tokens_file),
                policy_path=str(policy_file),
                raw_mode=True
            )
            
            # Scan in git mode (will fallback to direct scanning in our implementation)
            result_git = scan_with_policy_and_classification(
                root_path=str(tokens_file),
                policy_path=str(policy_file),
                raw_mode=False
            )
            
            # Raw mode should find all secrets
            assert result_raw["total"] >= 8, f"Raw mode should find at least 8 secrets, got {result_raw['total']}"
            
            # Git mode might find fewer due to filtering, but should still find some
            # (In our implementation it falls back to direct scanning, so should be similar)
            assert result_git["total"] >= 1, f"Git mode should find at least 1 secret, got {result_git['total']}"
            
            # Raw mode should find at least as many as git mode
            assert result_raw["total"] >= result_git["total"], f"Raw mode ({result_raw['total']}) should find at least as many as git mode ({result_git['total']})"
            
            print(f"✓ Raw mode: {result_raw['total']} findings, Git mode: {result_git['total']} findings")


if __name__ == "__main__":
    # Allow running this test directly
    pytest.main([__file__, "-v"])