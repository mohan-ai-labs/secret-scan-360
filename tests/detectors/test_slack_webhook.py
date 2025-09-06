"""Unit test for Slack webhook detector."""

import sys
import os
from pathlib import Path

# Add src to path for imports
test_dir = Path(__file__).parent
project_root = test_dir.parent.parent
sys.path.insert(0, str(project_root / "src"))

from ss360.detectors.slack_webhook import scan


def test_slack_webhook_detection():
    """Test Slack webhook detector with valid webhook and random URL."""
    
    # Test valid Slack webhook
    valid_webhook = b"SLACK_WEBHOOK=https://hooks.slack.com/services/T1234567A/B1234567B/XXXXXXXXXXXXXXXXXXXXXXXX"
    findings = scan(valid_webhook, "config.env")
    
    assert len(findings) == 1, f"Expected 1 finding for valid webhook, got {len(findings)}"
    assert findings[0].rule == "slack_webhook"
    assert findings[0].severity == "high"
    
    # Test random URL (should not match)
    random_url = b"URL=https://example.com/api/webhooks/random"
    findings = scan(random_url, "config.env")
    
    assert len(findings) == 0, f"Expected 0 findings for random URL, got {len(findings)}"
    
    # Test partial webhook (missing parts)
    partial_webhook = b"https://hooks.slack.com/services/incomplete"
    findings = scan(partial_webhook, "test.txt")
    
    assert len(findings) == 0, f"Expected 0 findings for partial webhook, got {len(findings)}"
    
    print("✅ Slack webhook detector working correctly")


if __name__ == "__main__":
    test_slack_webhook_detection()