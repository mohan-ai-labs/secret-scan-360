# SPDX-License-Identifier: MIT
"""
Tests for the validator core functionality.
"""
import time
from unittest.mock import patch

import pytest

from ss360.validate.core import (
    ValidationState,
    ValidationResult,
    TokenBucket,
    ValidatorRegistry,
    SlackWebhookValidator,
    run_validators,
    _get_default_registry
)


class TestTokenBucket:
    """Test token bucket rate limiting."""
    
    def test_token_bucket_basic(self):
        """Test basic token bucket functionality."""
        bucket = TokenBucket(qps=1.0, capacity=2.0)
        
        # Should be able to acquire initial tokens
        assert bucket.acquire(1) is True
        assert bucket.acquire(1) is True
        
        # Should fail when capacity exceeded
        assert bucket.acquire(1) is False
    
    @patch('time.time')
    def test_token_bucket_refill(self, mock_time):
        """Test token bucket refill over time."""
        mock_time.return_value = 0.0
        
        bucket = TokenBucket(qps=2.0, capacity=2.0)
        
        # Consume all tokens
        assert bucket.acquire(2) is True
        assert bucket.acquire(1) is False
        
        # Advance time by 1 second (should add 2 tokens)
        mock_time.return_value = 1.0
        assert bucket.acquire(2) is True
        
        # Should still fail for more tokens
        assert bucket.acquire(1) is False


class TestSlackWebhookValidator:
    """Test Slack webhook validator."""
    
    def test_valid_slack_webhook(self):
        """Test validation of valid Slack webhook."""
        validator = SlackWebhookValidator()
        finding = {
            "match": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
        }
        
        result = validator.validate(finding)
        
        assert result.state == ValidationState.VALID
        assert result.validator_name == "slack_webhook_format"
        assert "****XXXX" in result.evidence  # Should be redacted
        assert "Valid Slack webhook format" in result.evidence
    
    def test_invalid_slack_webhook(self):
        """Test validation of invalid Slack webhook."""
        validator = SlackWebhookValidator()
        finding = {
            "match": "https://invalid.webhook.url"
        }
        
        result = validator.validate(finding)
        
        assert result.state == ValidationState.INVALID
        assert result.validator_name == "slack_webhook_format"
        assert "Does not match Slack webhook format" in result.reason
    
    def test_validator_properties(self):
        """Test validator properties."""
        validator = SlackWebhookValidator()
        
        assert validator.name == "slack_webhook_format"
        assert validator.rate_limit_qps == 10.0
        assert validator.requires_network is False


class TestValidatorRegistry:
    """Test validator registry."""
    
    def test_register_validator(self):
        """Test registering a validator."""
        registry = ValidatorRegistry()
        validator = SlackWebhookValidator()
        
        registry.register(validator)
        
        validators = registry.get_all()
        assert len(validators) == 1
        assert validators[0].name == "slack_webhook_format"
    
    def test_duplicate_registration_fails(self):
        """Test that duplicate registration raises error."""
        registry = ValidatorRegistry()
        validator = SlackWebhookValidator()
        
        registry.register(validator)
        
        with pytest.raises(ValueError, match="already registered"):
            registry.register(validator)
    
    def test_get_bucket(self):
        """Test getting rate limiting bucket."""
        registry = ValidatorRegistry()
        validator = SlackWebhookValidator()
        
        registry.register(validator)
        bucket = registry.get_bucket("slack_webhook_format")
        
        assert isinstance(bucket, TokenBucket)


class TestRunValidators:
    """Test the main run_validators function."""
    
    def test_network_kill_switch(self):
        """Test that network validators are skipped when network is disabled."""
        # Create a mock network validator
        class NetworkValidator:
            @property
            def name(self):
                return "network_test"
            
            @property
            def rate_limit_qps(self):
                return 1.0
            
            @property
            def requires_network(self):
                return True
            
            def validate(self, finding):
                return ValidationResult(
                    state=ValidationState.VALID,
                    validator_name=self.name
                )
        
        registry = ValidatorRegistry()
        registry.register(NetworkValidator())
        
        config = {
            "validators": {
                "allow_network": False,
                "global_qps": 10.0
            }
        }
        
        finding = {"match": "test"}
        results = run_validators(finding, config, registry)
        
        assert len(results) == 1
        assert results[0].state == ValidationState.INDETERMINATE
        assert "Network disabled" in results[0].reason
    
    def test_rate_limiting(self):
        """Test that rate limiting works correctly."""
        config = {
            "validators": {
                "allow_network": False,
                "global_qps": 10.0  # High enough for first call
            }
        }
        
        finding = {"match": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"}
        
        # First call should work
        results1 = run_validators(finding, config)
        assert len(results1) == 1
        assert results1[0].state == ValidationState.VALID
        
        # Now set very low rate limit for second call
        config["validators"]["global_qps"] = 0.01
        
        # Second call should be rate limited
        results2 = run_validators(finding, config)
        assert len(results2) == 1
        assert results2[0].state == ValidationState.INDETERMINATE
        assert "Rate limit exceeded" in results2[0].reason
    
    def test_default_config(self):
        """Test with default configuration."""
        finding = {"match": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"}
        config = {"validators": {"allow_network": False, "global_qps": 10.0}}
        
        results = run_validators(finding, config)
        
        assert len(results) == 1
        assert results[0].state == ValidationState.VALID
        assert results[0].validator_name == "slack_webhook_format"
    
    def test_validator_exception_handling(self):
        """Test that validator exceptions are handled gracefully."""
        class FailingValidator:
            @property
            def name(self):
                return "failing_test"
            
            @property
            def rate_limit_qps(self):
                return 1.0
            
            @property
            def requires_network(self):
                return False
            
            def validate(self, finding):
                raise RuntimeError("Validator error")
        
        registry = ValidatorRegistry()
        registry.register(FailingValidator())
        
        config = {"validators": {"allow_network": False, "global_qps": 10.0}}
        finding = {"match": "test"}
        
        results = run_validators(finding, config, registry)
        
        assert len(results) == 1
        assert results[0].state == ValidationState.INDETERMINATE
        assert "Validation error" in results[0].reason


class TestDefaultRegistry:
    """Test default registry functionality."""
    
    def test_default_registry_has_slack_validator(self):
        """Test that default registry includes Slack validator."""
        registry = _get_default_registry()
        validators = registry.get_all()
        
        assert len(validators) == 1
        assert validators[0].name == "slack_webhook_format"