# SPDX-License-Identifier: MIT
"""
Validator Core with CI-safe network kill-switch.

This module provides a pluggable validation system for candidate findings
with strict network guardrails suitable for CI use.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Protocol, Any


class ValidationState(Enum):
    """Possible states for validation results."""

    VALID = "valid"
    INVALID = "invalid"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class ValidationResult:
    """Result of validating a finding."""

    state: ValidationState
    evidence: Optional[str] = None  # Redacted evidence
    reason: Optional[str] = None
    validator_name: Optional[str] = None


class Validator(Protocol):
    """Protocol for all validators."""

    @property
    def name(self) -> str:
        """Unique validator name."""
        ...

    @property
    def rate_limit_qps(self) -> float:
        """Rate limit in queries per second for this validator."""
        ...

    @property
    def requires_network(self) -> bool:
        """Whether this validator requires network access."""
        ...

    def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        """Validate a finding and return result."""
        ...


class TokenBucket:
    """Token bucket for rate limiting."""

    def __init__(self, qps: float, capacity: Optional[float] = None):
        self.qps = qps
        self.capacity = capacity or qps  # Burst capacity
        self.tokens = self.capacity
        self.last_refill = time.time()

    def acquire(self, tokens: int = 1) -> bool:
        """Try to acquire tokens. Returns True if successful."""
        now = time.time()

        # Add tokens based on elapsed time
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.qps)
        self.last_refill = now

        # Check if we have enough tokens
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


class ValidatorRegistry:
    """Registry for managing validators."""

    def __init__(self):
        self._validators: Dict[str, Validator] = {}
        self._buckets: Dict[str, TokenBucket] = {}

    def register(self, validator: Validator) -> None:
        """Register a validator."""
        if validator.name in self._validators:
            raise ValueError(f"Validator {validator.name} already registered")

        self._validators[validator.name] = validator
        self._buckets[validator.name] = TokenBucket(validator.rate_limit_qps)

    def get_all(self) -> List[Validator]:
        """Get all registered validators."""
        return list(self._validators.values())

    def get_bucket(self, validator_name: str) -> TokenBucket:
        """Get rate limiting bucket for a validator."""
        return self._buckets[validator_name]


class SlackWebhookValidator:
    """Simple local validator for Slack webhooks (format-only, no network)."""

    SLACK_WEBHOOK_PATTERN = re.compile(
        r"https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[A-Za-z0-9]{24}"
    )

    @property
    def name(self) -> str:
        return "slack_webhook_format"

    @property
    def rate_limit_qps(self) -> float:
        return 10.0  # High rate since it's local

    @property
    def requires_network(self) -> bool:
        return False

    def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        """Validate Slack webhook format without network access."""
        match = finding.get("match", "")

        if self.SLACK_WEBHOOK_PATTERN.match(match):
            # Redact the secret using central redaction function
            redacted = _redact_secret(match)
            return ValidationResult(
                state=ValidationState.VALID,
                evidence=f"Valid Slack webhook format: {redacted}",
                reason="Matches Slack webhook URL pattern",
                validator_name=self.name,
            )
        else:
            return ValidationResult(
                state=ValidationState.INVALID,
                reason="Does not match Slack webhook format",
                validator_name=self.name,
            )


def _redact_evidence(evidence: str) -> str:
    """Redact secrets in evidence strings showing first 6 + last 4 chars only."""
    # Use central redaction function for consistency
    from ss360.core.redaction import redact_evidence_string
    return redact_evidence_string(evidence)


def _redact_secret(secret: str) -> str:
    """Redact secret showing first 6 + last 4 characters."""
    # Use central redaction function for consistency  
    from ss360.core.redaction import redact_secret
    return redact_secret(secret)


def run_validators(
    finding: Dict[str, Any],
    config: Dict[str, Any],
    registry: Optional[ValidatorRegistry] = None,
) -> List[ValidationResult]:
    """
    Run validators on a finding according to configuration.

    Args:
        finding: The finding to validate
        config: Configuration dictionary with validators settings
        registry: Optional validator registry (uses default if None)

    Returns:
        List of validation results
    """
    if registry is None:
        registry = _get_default_registry()

    results = []

    # Get validator configuration
    validator_config = config.get("validators", {})
    allow_network = validator_config.get("allow_network", False)
    global_qps = validator_config.get("global_qps", 2.0)

    # Create global rate limiter
    global_bucket = TokenBucket(global_qps)

    for validator in registry.get_all():
        # Skip network validators if network is disabled
        if validator.requires_network and not allow_network:
            results.append(
                ValidationResult(
                    state=ValidationState.INDETERMINATE,
                    reason="Network disabled - validator skipped",
                    validator_name=validator.name,
                )
            )
            continue

        # Check rate limits
        validator_bucket = registry.get_bucket(validator.name)

        if not global_bucket.acquire() or not validator_bucket.acquire():
            results.append(
                ValidationResult(
                    state=ValidationState.INDETERMINATE,
                    reason="Rate limit exceeded",
                    validator_name=validator.name,
                )
            )
            continue

        # Run validation
        try:
            result = validator.validate(finding)

            # Ensure evidence is redacted
            if result.evidence:
                redacted_evidence = _redact_evidence(result.evidence)
                result = ValidationResult(
                    state=result.state,
                    evidence=redacted_evidence,
                    reason=result.reason,
                    validator_name=result.validator_name,
                )

            results.append(result)

        except Exception as e:
            results.append(
                ValidationResult(
                    state=ValidationState.INDETERMINATE,
                    reason=f"Validation error: {str(e)}",
                    validator_name=validator.name,
                )
            )

    return results


def _get_default_registry() -> ValidatorRegistry:
    """Get the default validator registry with built-in validators."""
    registry = ValidatorRegistry()
    registry.register(SlackWebhookValidator())

    # Import and register additional validators
    try:
        from .additional_validators import (
            SlackWebhookLocalValidator,
            GCPServiceAccountKeyLiveValidator,
            AzureSASLiveValidator,
        )

        registry.register(SlackWebhookLocalValidator())
        registry.register(GCPServiceAccountKeyLiveValidator())
        registry.register(AzureSASLiveValidator())
    except ImportError:
        # Additional validators not available, continue with defaults
        pass

    # Import and register live validators
    try:
        from .live_validators import (
            GitHubPATLiveValidator,
            AWSAccessKeyLiveValidator,
        )

        registry.register(GitHubPATLiveValidator())
        registry.register(AWSAccessKeyLiveValidator())
    except ImportError:
        # Live validators not available, continue with defaults
        pass

    return registry
