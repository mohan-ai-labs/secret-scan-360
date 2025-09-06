# SPDX-License-Identifier: MIT
"""
Tests to verify that all validators return "indeterminate" when allow_network=false.

This ensures that network validators never attempt network calls in CI environments.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from ss360.validate.core import run_validators, ValidationState


class TestValidatorsNoNetwork:
    """Test that all validators respect the network policy."""

    def test_github_pat_validator_no_network(self):
        """Test GitHub PAT validator returns indeterminate when network disabled."""
        github_pat = "ghp_1234567890abcdefghijklmnopqrstuvwxyz012345"
        finding = {"match": github_pat}
        config = {"validators": {"allow_network": False, "global_qps": 10.0}}

        results = run_validators(finding, config)

        # Find GitHub PAT validator result
        github_results = [r for r in results if r.validator_name == "github_pat_live"]
        assert len(github_results) == 1
        
        result = github_results[0]
        assert result.state == ValidationState.INDETERMINATE
        assert "Network disabled" in result.reason

    def test_aws_access_key_validator_no_network(self):
        """Test AWS Access Key validator returns indeterminate when network disabled."""
        aws_key = "AKIA1234567890123456"
        finding = {"match": aws_key}
        config = {"validators": {"allow_network": False, "global_qps": 10.0}}

        results = run_validators(finding, config)

        # Find AWS validator result
        aws_results = [r for r in results if r.validator_name == "aws_ak_live"]
        assert len(aws_results) == 1
        
        result = aws_results[0]
        assert result.state == ValidationState.INDETERMINATE
        assert "Network disabled" in result.reason

    def test_gcp_validator_no_network(self):
        """Test GCP validator returns indeterminate when network disabled."""
        gcp_key = '''{"type": "service_account", "project_id": "test", "private_key_id": "123", "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKB\\n-----END PRIVATE KEY-----\\n", "client_email": "test@example.iam.gserviceaccount.com"}'''
        finding = {"match": gcp_key}
        config = {"validators": {"allow_network": False, "global_qps": 10.0}}

        results = run_validators(finding, config)

        # Find GCP validator result
        gcp_results = [r for r in results if r.validator_name == "gcp_sa_key_live"]
        assert len(gcp_results) == 1
        
        result = gcp_results[0]
        assert result.state == ValidationState.INDETERMINATE
        assert "Network disabled" in result.reason

    def test_azure_sas_validator_no_network(self):
        """Test Azure SAS validator returns indeterminate when network disabled."""
        azure_sas = "https://mystorageaccount.blob.core.windows.net/mycontainer?sv=2020-08-04&ss=bfqt&srt=sco&sp=rwdlacupx&se=2023-12-31T23:59:59Z&st=2023-01-01T00:00:00Z&spr=https&sig=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        finding = {"match": azure_sas}
        config = {"validators": {"allow_network": False, "global_qps": 10.0}}

        results = run_validators(finding, config)

        # Find Azure validator result
        azure_results = [r for r in results if r.validator_name == "azure_sas_live"]
        assert len(azure_results) == 1
        
        result = azure_results[0]
        assert result.state == ValidationState.INDETERMINATE
        assert "Network disabled" in result.reason

    def test_all_network_validators_disabled(self):
        """Test that all network-requiring validators are skipped when network is disabled."""
        # Test with a generic finding that could match multiple validators
        finding = {"match": "ghp_1234567890abcdefghijklmnopqrstuvwxyz012345"}
        config = {"validators": {"allow_network": False, "global_qps": 10.0}}

        results = run_validators(finding, config)

        # All network validators should return INDETERMINATE with "Network disabled" reason
        network_validators = ["github_pat_live", "aws_ak_live", "gcp_sa_key_live", "azure_sas_live"]
        
        for validator_name in network_validators:
            validator_results = [r for r in results if r.validator_name == validator_name]
            assert len(validator_results) == 1
            
            result = validator_results[0]
            assert result.state == ValidationState.INDETERMINATE
            assert "Network disabled" in result.reason

    def test_local_validators_still_work_no_network(self):
        """Test that local validators continue to work when network is disabled."""
        slack_webhook = "https://hooks.slack.com/services/T12345678/B12345678/1234567890ABCDEF12345678"
        finding = {"match": slack_webhook}
        config = {"validators": {"allow_network": False, "global_qps": 10.0}}

        results = run_validators(finding, config)

        # Local Slack validators should still work
        local_validators = ["slack_webhook_format", "slack_webhook_local"]
        
        for validator_name in local_validators:
            validator_results = [r for r in results if r.validator_name == validator_name]
            assert len(validator_results) == 1
            
            result = validator_results[0]
            # Local validators should return VALID, not INDETERMINATE
            assert result.state == ValidationState.VALID
            assert "Network disabled" not in result.reason

    def test_no_network_calls_attempted(self):
        """Test that no actual network calls are attempted when network is disabled."""
        # This is a behavioral test - we can't easily mock network calls here,
        # but we can verify that network validators return the expected state
        # without throwing network-related exceptions
        
        test_findings = [
            {"match": "ghp_1234567890abcdefghijklmnopqrstuvwxyz012345"},  # GitHub PAT
            {"match": "AKIA1234567890123456"},  # AWS key
            {"match": "https://mystorageaccount.blob.core.windows.net/container?sig=test"},  # Azure SAS
        ]
        
        config = {"validators": {"allow_network": False, "global_qps": 10.0}}

        for finding in test_findings:
            results = run_validators(finding, config)
            
            # Should not raise any network-related exceptions
            # All network validators should be gracefully skipped
            network_results = [
                r for r in results 
                if r.validator_name in ["github_pat_live", "aws_ak_live", "gcp_sa_key_live", "azure_sas_live"]
                and r.state == ValidationState.INDETERMINATE
                and "Network disabled" in r.reason
            ]
            
            # At least some network validators should be skipped for each finding
            assert len(network_results) > 0