# SPDX-License-Identifier: MIT
"""
Tests to ensure no plaintext secrets appear in evidence or logs.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from ss360.validate.core import SlackWebhookValidator, run_validators, _redact_evidence


class TestSecretRedaction:
    """Test secret redaction in validator evidence."""

    def test_slack_webhook_redaction(self):
        """Test that Slack webhook secrets are properly redacted."""
        validator = SlackWebhookValidator()
        webhook_url = "https://hooks.slack.com/services/T12345678/B12345678/1234567890ABCDEF12345678"

        finding = {"match": webhook_url}
        result = validator.validate(finding)

        # Should not contain the full secret
        assert webhook_url not in result.evidence

        # Should only show last 4 characters
        assert "****5678" in result.evidence

        # Should not contain the full token part
        assert "1234567890ABCDEF12345678" not in result.evidence

    def test_short_secret_redaction(self):
        """Test redaction of short secrets."""
        from ss360.validate.core import _redact_secret

        # Test with short secret
        redacted = _redact_secret("abc")
        assert redacted == "****"

        # Test with 4-character secret
        redacted = _redact_secret("abcd")
        assert redacted == "****"

        # Test with longer secret
        redacted = _redact_secret("abcdefghijk")
        assert redacted == "abcdef****hijk"

    def test_evidence_redaction_function(self):
        """Test the general evidence redaction function."""
        evidence_with_secrets = """
        Found potential secret: abc123def456ghi789jkl012mno345pqr678
        Another line with secret: AKIA1234567890123456
        Normal line without secrets
        """

        redacted = _redact_evidence(evidence_with_secrets)

        # Should not contain full secrets
        assert "abc123def456ghi789jkl012mno345pqr678" not in redacted
        assert "AKIA1234567890123456" not in redacted

        # Should contain redacted versions
        assert "****r678" in redacted
        assert "****3456" in redacted

        # Normal lines should be unchanged
        assert "Normal line without secrets" in redacted

    def test_run_validators_redacts_evidence(self):
        """Test that run_validators properly redacts evidence."""
        webhook_url = "https://hooks.slack.com/services/T12345678/B12345678/1234567890ABCDEF12345678"
        finding = {"match": webhook_url}

        config = {"validators": {"allow_network": False, "global_qps": 10.0}}

        results = run_validators(finding, config)

        # Should have 6 results (2 Slack validators + 4 network validators skipped)
        assert len(results) == 6

        # Check that Slack validators have redacted evidence
        slack_results = [
            r for r in results if "slack_webhook" in r.validator_name and r.evidence
        ]
        assert len(slack_results) == 2

        for result in slack_results:
            # Evidence should be redacted
            assert webhook_url not in result.evidence
            assert "****5678" in result.evidence

    def test_no_secrets_in_logs(self):
        """Test that validator names and reasons don't contain secrets."""
        webhook_url = "https://hooks.slack.com/services/T12345678/B12345678/SECRETTOKEN123456789ABC"
        finding = {"match": webhook_url}

        config = {"validators": {"allow_network": False, "global_qps": 10.0}}

        results = run_validators(finding, config)

        for result in results:
            # Validator name should not contain secrets
            if result.validator_name:
                assert "SECRETTOKEN123456789ABC" not in result.validator_name

            # Reason should not contain full secrets
            if result.reason:
                assert "SECRETTOKEN123456789ABC" not in result.reason

    def test_redaction_preserves_first_six_last_four_chars(self):
        """Test that redaction consistently shows first 6 + last 4 characters."""
        from ss360.validate.core import _redact_secret
        
        test_cases = [
            ("abcdefghijklmnop", "abcdef****mnop"),
            ("12345", "****"),  # Shows **** for short strings
            ("123456", "****"),  # Shows **** for 6-char string  
            ("1234567", "****"),  # Shows **** for 7-char string
            ("12345678", "****"),  # Shows **** for 8-char string
            ("123456789", "****"),  # Shows **** for 9-char string
            ("1234567890", "****"),  # Shows **** for 10-char string
            ("12345678901", "123456****8901"),  # Shows first6+last4 for 11+ chars
            ("very_long_secret_token_12345678", "very_l****5678"),
            ("abc", "****"),  # Shows **** for short secrets
            ("abcd", "****"),  # Shows **** for 4-char secrets
        ]

        for secret, expected in test_cases:
            redacted = _redact_secret(secret)
            assert redacted == expected, f"Failed for secret: {secret}, got {redacted}, expected {expected}"

    def test_evidence_does_not_leak_patterns(self):
        """Test that evidence doesn't accidentally leak secret patterns."""
        # Test various secret-like patterns
        test_secrets = [
            "AKIA1234567890123456",  # AWS key format
            "sk_live_1234567890abcdef",  # Stripe key format
            "xoxb-1234567890-1234567890-abcdefghijklmnop",  # Slack bot token
            "github_pat_11ABCDEFG012345678901234567890",  # GitHub PAT
        ]

        for secret in test_secrets:
            evidence = f"Detected secret: {secret}"
            redacted = _redact_evidence(evidence)

            # Full secret should not be present
            assert secret not in redacted

            # Should have some form of redaction
            assert "****" in redacted
