# SPDX-License-Identifier: MIT
"""
Tests for Slack, GCP, and Azure validators.

Tests cover:
- Local format validation
- Network policy compliance (allow_network=false)
- Rate limiting behavior
- Evidence redaction
- Mock success/failure scenarios
"""
from __future__ import annotations

import json
from src.ss360.validate.additional_validators import (
    SlackWebhookLocalValidator,
    GCPServiceAccountKeyLiveValidator,
    AzureSASLiveValidator,
)
from src.ss360.validate.core import (
    ValidationState,
    run_validators,
)


class TestSlackWebhookLocalValidator:
    """Test the local Slack webhook validator."""

    def test_validator_properties(self):
        """Test validator properties."""
        validator = SlackWebhookLocalValidator()
        assert validator.name == "slack_webhook_local"
        assert validator.rate_limit_qps == 10.0
        assert validator.requires_network is False

    def test_valid_slack_webhook(self):
        """Test validation of valid Slack webhook URL."""
        validator = SlackWebhookLocalValidator()
        valid_webhook = "https://hooks.slack.com/services/T12345678/B12345678/1234567890ABCDEF12345678"
        finding = {"match": valid_webhook}

        result = validator.validate(finding)

        assert result.state == ValidationState.VALID
        assert result.validator_name == "slack_webhook_local"
        assert "Valid Slack webhook format" in result.evidence
        assert "****5678" in result.evidence  # Check redaction
        assert "enhanced checks" in result.evidence
        assert "component validation" in result.reason

    def test_invalid_slack_webhook_format(self):
        """Test validation of invalid Slack webhook URL format."""
        validator = SlackWebhookLocalValidator()
        invalid_webhook = "https://hooks.slack.com/services/invalid"
        finding = {"match": invalid_webhook}

        result = validator.validate(finding)

        assert result.state == ValidationState.INVALID
        assert result.validator_name == "slack_webhook_local"
        assert "Does not match Slack webhook URL pattern" in result.reason

    def test_invalid_team_id_format(self):
        """Test validation with invalid team ID format."""
        validator = SlackWebhookLocalValidator()
        # Invalid team ID (should start with T)
        invalid_webhook = "https://hooks.slack.com/services/X12345678/B12345678/1234567890ABCDEF12345678"
        finding = {"match": invalid_webhook}

        result = validator.validate(finding)

        assert result.state == ValidationState.INVALID
        assert "Invalid team ID format" in result.reason

    def test_invalid_channel_id_format(self):
        """Test validation with invalid channel ID format."""
        validator = SlackWebhookLocalValidator()
        # Invalid channel ID (should start with B or C)
        invalid_webhook = "https://hooks.slack.com/services/T12345678/X12345678/1234567890ABCDEF12345678"
        finding = {"match": invalid_webhook}

        result = validator.validate(finding)

        assert result.state == ValidationState.INVALID
        assert "Invalid channel/bot ID format" in result.reason

    def test_invalid_token_length(self):
        """Test validation with invalid token length."""
        validator = SlackWebhookLocalValidator()
        # Token too short (22 chars instead of 24)
        invalid_webhook = "https://hooks.slack.com/services/T12345678/B12345678/1234567890ABCDEF123456"
        finding = {"match": invalid_webhook}

        result = validator.validate(finding)

        assert result.state == ValidationState.INVALID
        # This URL doesn't match the basic pattern so it fails at the regex level
        assert "Does not match Slack webhook URL pattern" in result.reason

    def test_redaction_preserves_last_four(self):
        """Test that redaction shows last 4 characters."""
        validator = SlackWebhookLocalValidator()
        webhook = "https://hooks.slack.com/services/T12345678/B12345678/1234567890ABCDEF12345678"

        redacted = validator._redact_secret(webhook)

        assert redacted == "****5678"
        assert webhook not in redacted

    def test_redaction_short_secret(self):
        """Test redaction of short secrets."""
        validator = SlackWebhookLocalValidator()
        short_secret = "abc"

        redacted = validator._redact_secret(short_secret)

        assert redacted == "****"


class TestGCPServiceAccountKeyLiveValidator:
    """Test the GCP service account key validator."""

    def test_validator_properties(self):
        """Test validator properties."""
        validator = GCPServiceAccountKeyLiveValidator()
        assert validator.name == "gcp_sa_key_live"
        assert validator.rate_limit_qps == 0.5
        assert validator.requires_network is True

    def test_valid_service_account_key_format(self):
        """Test validation of valid service account key format."""
        validator = GCPServiceAccountKeyLiveValidator()
        valid_key = {
            "type": "service_account",
            "project_id": "test-project-123456",
            "private_key_id": "1234567890abcdef",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\n-----END PRIVATE KEY-----\n",
            "client_email": "test-service@test-project-123456.iam.gserviceaccount.com",
            "client_id": "123456789012345678901",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
        finding = {"match": json.dumps(valid_key)}

        result = validator.validate(finding)

        assert (
            result.state == ValidationState.INDETERMINATE
        )  # Format valid but live validation not implemented
        assert result.validator_name == "gcp_sa_key_live"
        assert "format valid" in result.evidence
        assert "****.com" in result.evidence  # Check email redaction
        assert "Format validation passed" in result.reason

    def test_invalid_key_type(self):
        """Test validation with invalid key type."""
        validator = GCPServiceAccountKeyLiveValidator()
        invalid_key = {
            "type": "user_account",  # Wrong type
            "project_id": "test-project-123456",
            "private_key_id": "1234567890abcdef",
            "private_key": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
            "client_email": "test-service@test-project-123456.iam.gserviceaccount.com",
        }
        finding = {"match": json.dumps(invalid_key)}

        result = validator.validate(finding)

        assert result.state == ValidationState.INVALID
        assert "Invalid key type" in result.reason

    def test_missing_required_fields(self):
        """Test validation with missing required fields."""
        validator = GCPServiceAccountKeyLiveValidator()
        incomplete_key = {
            "type": "service_account",
            "project_id": "test-project-123456",
            # Missing other required fields
        }
        finding = {"match": json.dumps(incomplete_key)}

        result = validator.validate(finding)

        assert result.state == ValidationState.INVALID
        assert "Missing required fields" in result.reason

    def test_invalid_json_format(self):
        """Test validation with invalid JSON."""
        validator = GCPServiceAccountKeyLiveValidator()
        finding = {"match": "not valid json"}

        result = validator.validate(finding)

        assert result.state == ValidationState.INVALID
        assert "expected JSON" in result.reason

    def test_invalid_email_format(self):
        """Test validation with invalid service account email."""
        validator = GCPServiceAccountKeyLiveValidator()
        invalid_key = {
            "type": "service_account",
            "project_id": "test-project-123456",
            "private_key_id": "1234567890abcdef",
            "private_key": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
            "client_email": "invalid-email@example.com",  # Wrong domain
        }
        finding = {"match": json.dumps(invalid_key)}

        result = validator.validate(finding)

        assert result.state == ValidationState.INVALID
        assert "Invalid service account email format" in result.reason


class TestAzureSASLiveValidator:
    """Test the Azure SAS token validator."""

    def test_validator_properties(self):
        """Test validator properties."""
        validator = AzureSASLiveValidator()
        assert validator.name == "azure_sas_live"
        assert validator.rate_limit_qps == 1.0
        assert validator.requires_network is True

    def test_valid_sas_token_format(self):
        """Test validation of valid SAS token format."""
        validator = AzureSASLiveValidator()
        valid_sas = "https://mystorageaccount.blob.core.windows.net/mycontainer/myblob?sv=2020-08-04&se=2023-12-31T23%3A59%3A59Z&sr=b&sp=r&sig=abcdef1234567890"
        finding = {"match": valid_sas}

        result = validator.validate(finding)

        assert (
            result.state == ValidationState.INDETERMINATE
        )  # Format valid but live validation not implemented
        assert result.validator_name == "azure_sas_live"
        assert "format valid" in result.evidence
        assert "****.net" in result.evidence  # Check host redaction
        assert "Format validation passed" in result.reason

    def test_invalid_sas_token_no_query(self):
        """Test validation with SAS token missing query parameters."""
        validator = AzureSASLiveValidator()
        invalid_sas = (
            "https://mystorageaccount.blob.core.windows.net/mycontainer/myblob"
        )
        finding = {"match": invalid_sas}

        result = validator.validate(finding)

        assert result.state == ValidationState.INVALID
        assert "Invalid Azure SAS token format" in result.reason

    def test_invalid_sas_token_wrong_scheme(self):
        """Test validation with non-HTTPS scheme."""
        validator = AzureSASLiveValidator()
        invalid_sas = "http://mystorageaccount.blob.core.windows.net/mycontainer/myblob?sv=2020-08-04&se=2023-12-31T23%3A59%3A59Z&sr=b&sp=r&sig=abcdef1234567890"
        finding = {"match": invalid_sas}

        result = validator.validate(finding)

        assert result.state == ValidationState.INVALID
        assert "Invalid Azure SAS token format" in result.reason

    def test_invalid_sas_token_wrong_domain(self):
        """Test validation with non-Azure domain."""
        validator = AzureSASLiveValidator()
        invalid_sas = "https://example.com/mycontainer/myblob?sv=2020-08-04&se=2023-12-31T23%3A59%3A59Z&sr=b&sp=r&sig=abcdef1234567890"
        finding = {"match": invalid_sas}

        result = validator.validate(finding)

        assert result.state == ValidationState.INVALID
        assert "Invalid Azure SAS token format" in result.reason

    def test_invalid_sas_token_missing_required_params(self):
        """Test validation with missing required SAS parameters."""
        validator = AzureSASLiveValidator()
        invalid_sas = "https://mystorageaccount.blob.core.windows.net/mycontainer/myblob?sv=2020-08-04&sr=b&sp=r"  # Missing 'se' and 'sig'
        finding = {"match": invalid_sas}

        result = validator.validate(finding)

        assert result.state == ValidationState.INVALID
        assert "Invalid Azure SAS token format" in result.reason


class TestNetworkPolicyCompliance:
    """Test that validators respect network policy settings."""

    def test_network_disabled_skips_network_validators(self):
        """Test that network validators are skipped when allow_network=False."""
        # Create findings for network validators
        gcp_key = {
            "type": "service_account",
            "project_id": "test-project",
            "private_key_id": "test",
            "private_key": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
            "client_email": "test@test-project.iam.gserviceaccount.com",
        }

        findings = [
            {"match": json.dumps(gcp_key)},  # GCP key
            {
                "match": "https://mystorageaccount.blob.core.windows.net/test?sv=2020-08-04&se=2023-12-31T23%3A59%3A59Z&sr=b&sp=r&sig=test123"
            },  # Azure SAS
        ]

        # Test with network disabled (default)
        config = {"validators": {"allow_network": False, "global_qps": 10.0}}

        for finding in findings:
            results = run_validators(finding, config)

            # Should have results for network validators showing they were skipped
            network_results = [
                r
                for r in results
                if r.validator_name in ["gcp_sa_key_live", "azure_sas_live"]
            ]
            for result in network_results:
                assert result.state == ValidationState.INDETERMINATE
                assert "Network disabled" in result.reason

    def test_network_enabled_allows_network_validators(self):
        """Test that network validators run when allow_network=True."""
        gcp_key = {
            "type": "service_account",
            "project_id": "test-project",
            "private_key_id": "test",
            "private_key": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
            "client_email": "test@test-project.iam.gserviceaccount.com",
        }
        finding = {"match": json.dumps(gcp_key)}

        # Test with network enabled
        config = {"validators": {"allow_network": True, "global_qps": 10.0}}

        results = run_validators(finding, config)

        # Should have a result for GCP validator that actually ran (not skipped)
        gcp_results = [r for r in results if r.validator_name == "gcp_sa_key_live"]
        assert len(gcp_results) == 1
        result = gcp_results[0]
        assert "Network disabled" not in result.reason

    def test_local_validators_always_run(self):
        """Test that local validators run regardless of network setting."""
        webhook = "https://hooks.slack.com/services/T12345678/B12345678/1234567890ABCDEF12345678"
        finding = {"match": webhook}

        # Test with both network settings
        for allow_network in [True, False]:
            config = {
                "validators": {"allow_network": allow_network, "global_qps": 10.0}
            }
            results = run_validators(finding, config)

            # Should have result for local Slack validator
            slack_results = [
                r for r in results if r.validator_name == "slack_webhook_local"
            ]
            assert len(slack_results) == 1
            result = slack_results[0]
            assert "Network disabled" not in result.reason
            assert result.state in [
                ValidationState.VALID,
                ValidationState.INVALID,
            ]  # Should not be indeterminate due to network


class TestRedactionBehavior:
    """Test evidence redaction in validators."""

    def test_slack_webhook_redaction(self):
        """Test that Slack webhook evidence is redacted."""
        webhook = "https://hooks.slack.com/services/T12345678/B12345678/1234567890ABCDEF12345678"
        finding = {"match": webhook}
        config = {"validators": {"allow_network": False, "global_qps": 10.0}}

        results = run_validators(finding, config)

        slack_results = [
            r for r in results if r.validator_name == "slack_webhook_local"
        ]
        assert len(slack_results) == 1
        result = slack_results[0]

        # Evidence should be redacted - should not contain full URL
        assert webhook not in result.evidence
        assert "****5678" in result.evidence

    def test_gcp_key_redaction(self):
        """Test that GCP service account key evidence is redacted."""
        gcp_key = {
            "type": "service_account",
            "project_id": "test-project-123456",
            "private_key_id": "1234567890abcdef",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\n-----END PRIVATE KEY-----\n",
            "client_email": "test-service@test-project-123456.iam.gserviceaccount.com",
        }
        finding = {"match": json.dumps(gcp_key)}
        config = {"validators": {"allow_network": True, "global_qps": 10.0}}

        results = run_validators(finding, config)

        gcp_results = [r for r in results if r.validator_name == "gcp_sa_key_live"]
        assert len(gcp_results) == 1
        result = gcp_results[0]

        # Evidence should be redacted - should not contain full email
        if result.evidence:
            assert gcp_key["client_email"] not in result.evidence
            assert "****" in result.evidence

    def test_azure_sas_redaction(self):
        """Test that Azure SAS token evidence is redacted."""
        sas_url = "https://mystorageaccount.blob.core.windows.net/mycontainer/myblob?sv=2020-08-04&se=2023-12-31T23%3A59%3A59Z&sr=b&sp=r&sig=abcdef1234567890"
        finding = {"match": sas_url}
        config = {"validators": {"allow_network": True, "global_qps": 10.0}}

        results = run_validators(finding, config)

        azure_results = [r for r in results if r.validator_name == "azure_sas_live"]
        assert len(azure_results) == 1
        result = azure_results[0]

        # Evidence should be redacted - should not contain full URL
        if result.evidence:
            assert sas_url not in result.evidence
            assert "****" in result.evidence

    def test_no_secrets_in_validator_names_and_reasons(self):
        """Test that validator names and reasons don't accidentally contain secrets."""
        sensitive_inputs = [
            "https://hooks.slack.com/services/T12345678/B12345678/SECRETTOKEN123456789012",
            json.dumps(
                {
                    "type": "service_account",
                    "client_email": "secret@project.iam.gserviceaccount.com",
                    "private_key": "-----BEGIN PRIVATE KEY-----\nSECRET_KEY_DATA\n-----END PRIVATE KEY-----\n",
                }
            ),
            "https://storage.blob.core.windows.net/container/blob?sig=SECRET_SIG_12345",
        ]

        config = {"validators": {"allow_network": True, "global_qps": 10.0}}

        for sensitive_input in sensitive_inputs:
            finding = {"match": sensitive_input}
            results = run_validators(finding, config)

            for result in results:
                # Check that validator names don't contain secrets
                assert "SECRET" not in result.validator_name
                assert "12345" not in result.validator_name

                # Check that reasons don't contain secrets
                if result.reason:
                    assert "SECRETTOKEN" not in result.reason
                    assert "SECRET_KEY_DATA" not in result.reason
                    assert "SECRET_SIG" not in result.reason


class TestRateLimiting:
    """Test rate limiting behavior."""

    def test_validators_have_appropriate_qps_limits(self):
        """Test that validators have appropriate QPS limits."""
        # Local validators should have higher limits
        slack_local = SlackWebhookLocalValidator()
        assert slack_local.rate_limit_qps == 10.0

        # Network validators should have conservative limits
        gcp_validator = GCPServiceAccountKeyLiveValidator()
        assert gcp_validator.rate_limit_qps == 0.5

        azure_validator = AzureSASLiveValidator()
        assert azure_validator.rate_limit_qps == 1.0
