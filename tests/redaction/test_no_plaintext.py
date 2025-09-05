# SPDX-License-Identifier: MIT
"""
Tests to ensure no plaintext secrets appear in evidence or logs.
"""

from ss360.validate.core import (
    SlackWebhookValidator,
    run_validators,
    _redact_evidence
)


class TestSecretRedaction:
    """Test