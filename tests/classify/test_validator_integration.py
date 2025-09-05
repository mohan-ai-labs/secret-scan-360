# SPDX-License-Identifier: MIT
"""
Tests for validator integration in classification.
"""
import pytest

from src.ss360.classify.rules import classify


class TestValidatorIntegration:
    """Test integration between validators and classification."""

    def test_validator_confirmed_actual(self):
        """Test that validator confirmation leads to 'actual' classification."""
        finding = {
            "match": "ghp_1234567890abcdef1234567890abcdef12345678",
            "path": "src/config.py",
            "kind": "GitHub Token",
        }

        validation_results = [
            {
                "state": "valid",
                "evidence": "Token is active and has repo access",
                "reason": "Successfully authenticated with GitHub API",
                "validator_name": "github_live_validator",
            }
        ]

        context = {"validation_results": validation_results}
        category, confidence, reasons = classify(finding, context)

        assert category == "actual"
        assert confidence >= 0.9
        assert "validator:github_live_validator:confirmed" in reasons

    def test_validator_expired_classification(self):
        """Test that validator indicating expiry leads to 'expired' classification."""
        finding = {
            "match": "AKIA1234567890ABCDEF",
            "path": "src/aws_config.py",
            "kind": "AWS Access Key",
        }

        validation_results = [
            {
                "state": "valid",
                "evidence": "Key exists but is expired/revoked",
                "reason": "Authentication failed due to expired credentials",
                "validator_name": "aws_live_validator",
            }
        ]

        context = {"validation_results": validation_results}
        category, confidence, reasons = classify(finding, context)

        assert category == "expired"
        assert confidence >= 0.9
        assert "validator:aws_live_validator:expired" in reasons

    def test_validator_invalid_expired(self):
        """Test that invalid state with expiry reason leads to 'expired' classification."""
        finding = {
            "match": "sk_live_1234567890abcdef",
            "path": "payment/config.py",
            "kind": "Stripe Secret Key",
        }

        validation_results = [
            {
                "state": "invalid",
                "evidence": "Key rejected by API",
                "reason": "Authentication failed: key has expired",
                "validator_name": "stripe_validator",
            }
        ]

        context = {"validation_results": validation_results}
        category, confidence, reasons = classify(finding, context)

        assert category == "expired"
        assert confidence >= 0.8
        assert "validator:stripe_validator:expired" in reasons

    def test_validator_indeterminate_no_classification(self):
        """Test that indeterminate validator results don't affect classification."""
        finding = {
            "match": "api_key_123456789",
            "path": "src/config.py",
            "kind": "API Key",
        }

        validation_results = [
            {
                "state": "indeterminate",
                "evidence": "Rate limit exceeded",
                "reason": "Could not validate due to rate limiting",
                "validator_name": "generic_validator",
            }
        ]

        context = {"validation_results": validation_results}
        category, confidence, reasons = classify(finding, context)

        # Should fall back to other classification rules or unknown
        assert category in ["actual", "expired", "test", "unknown"]
        # Should not have validator-based reasons for indeterminate
        validator_reasons = [r for r in reasons if "validator:" in r]
        assert len(validator_reasons) == 0

    def test_multiple_validators_prioritize_valid(self):
        """Test that valid results are prioritized over invalid when multiple validators run."""
        finding = {
            "match": "mixed_results_token",
            "path": "src/config.py",
            "kind": "API Token",
        }

        validation_results = [
            {
                "state": "invalid",
                "evidence": "First validator failed",
                "reason": "Could not authenticate",
                "validator_name": "validator_1",
            },
            {
                "state": "valid",
                "evidence": "Second validator succeeded",
                "reason": "Successfully authenticated",
                "validator_name": "validator_2",
            },
        ]

        context = {"validation_results": validation_results}
        category, confidence, reasons = classify(finding, context)

        # Should prioritize the valid result
        assert category == "actual"
        assert confidence >= 0.9
        assert "validator:validator_2:confirmed" in reasons

    def test_validator_overrides_test_markers(self):
        """Test that validator confirmation overrides test path markers."""
        finding = {
            "match": "ghp_real_token_in_test_file",
            "path": "tests/integration_test.py",  # Test path
            "kind": "GitHub Token",
        }

        validation_results = [
            {
                "state": "valid",
                "evidence": "Token is active",
                "reason": "Successfully authenticated",
                "validator_name": "github_validator",
            }
        ]

        context = {"validation_results": validation_results}
        category, confidence, reasons = classify(finding, context)

        # Validator should override path-based test classification
        assert category == "actual"
        assert confidence >= 0.9
        assert "validator:github_validator:confirmed" in reasons

    def test_no_validation_results_fallback(self):
        """Test behavior when no validation results are provided."""
        finding = {"match": "some_api_key", "path": "src/config.py", "kind": "API Key"}

        # No validation results
        context = {}
        category, confidence, reasons = classify(finding, context)

        # Should fall back to other classification rules
        assert category in ["actual", "expired", "test", "unknown"]
        # Should not have any validator-based reasons
        validator_reasons = [r for r in reasons if "validator:" in r]
        assert len(validator_reasons) == 0

    def test_empty_validation_results_fallback(self):
        """Test behavior when validation results list is empty."""
        finding = {
            "match": "another_api_key",
            "path": "src/config.py",
            "kind": "API Key",
        }

        context = {"validation_results": []}
        category, confidence, reasons = classify(finding, context)

        # Should fall back to other classification rules
        assert category in ["actual", "expired", "test", "unknown"]
        # Should not have any validator-based reasons
        validator_reasons = [r for r in reasons if "validator:" in r]
        assert len(validator_reasons) == 0

    def test_validator_network_disabled_handling(self):
        """Test handling of network-disabled validator results."""
        finding = {
            "match": "network_disabled_token",
            "path": "src/config.py",
            "kind": "API Token",
        }

        validation_results = [
            {
                "state": "indeterminate",
                "evidence": None,
                "reason": "Network disabled - validator skipped",
                "validator_name": "live_validator",
            }
        ]

        context = {"validation_results": validation_results}
        category, confidence, reasons = classify(finding, context)

        # Should fall back to other rules since validator was skipped
        assert category in ["actual", "expired", "test", "unknown"]
        # Should not treat network-disabled as a classification signal
        validator_reasons = [r for r in reasons if "validator:" in r]
        assert len(validator_reasons) == 0
