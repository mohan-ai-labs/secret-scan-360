#!/usr/bin/env python3
"""
Simple tests for SS360 functionality.
"""


def test_risk_scoring():
    """Test risk scoring functionality."""
    print("Testing risk scoring...")

    from src.ss360.risk.score import calculate_risk_score, get_risk_level, RiskLevel

    # Test base risk scores
    finding = {"id": "github_pat", "path": "config.py", "line": 10}
    score = calculate_risk_score(finding)
    assert (
        70 <= score <= 80
    ), f"Expected score around 70, got {score}"  # Allow for modifiers
    print("✓ Base GitHub PAT risk score in expected range")

    # Test risk levels
    assert get_risk_level(90) == RiskLevel.CRITICAL
    assert get_risk_level(70) == RiskLevel.HIGH
    assert get_risk_level(50) == RiskLevel.MEDIUM
    print("✓ Risk levels correct")

    # Test path modifiers
    test_finding = {"id": "github_pat", "path": "tests/test_auth.py", "line": 10}
    test_score = calculate_risk_score(test_finding)

    prod_finding = {"id": "github_pat", "path": "production/config.py", "line": 10}
    prod_score = calculate_risk_score(prod_finding)

    assert (
        prod_score > test_score
    ), f"Production score {prod_score} should be > test score {test_score}"
    print("✓ Path context modifiers working")

    print("All risk scoring tests passed!")


def test_detectors():
    """Test detector functionality."""
    print("Testing detectors...")

    from detectors.github_pat import detect as github_detect
    from detectors.aws_keypair import detect as aws_detect

    # Test GitHub PAT detection
    lines = ["API_TOKEN = 'ghp_1234567890123456789012345678901234567890'"]
    findings = list(github_detect(lines))
    assert len(findings) == 1, f"Expected 1 GitHub PAT finding, got {len(findings)}"
    assert findings[0]["id"] == "github_pat"
    print("✓ GitHub PAT detector working")

    # Test AWS key detection
    lines = ["AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'"]
    findings = list(aws_detect(lines))
    assert len(findings) == 1, f"Expected 1 AWS finding, got {len(findings)}"
    assert findings[0]["id"] == "aws_keypair"
    print("✓ AWS key detector working")

    print("All detector tests passed!")


def test_autofix_planning():
    """Test autofix planning functionality."""
    print("Testing autofix planning...")

    from src.ss360.autofix.planner import AutofixPlanner, ActionType

    planner = AutofixPlanner()

    findings = [
        {
            "id": "github_pat",
            "kind": "GitHub PAT",  # Add the kind field that planner expects
            "path": "config.py",
            "line": 10,
            "match": "ghp_1234567890123456789012345678901234567890",
            "risk_score": 75,
            "validator_state": "live",  # Add this to trigger revoke action
        }
    ]

    plan = planner.generate_plan(findings)
    assert len(plan) == 2, f"Expected 2 plan items, got {len(plan)}"

    # Check actions
    actions = [item.action for item in plan]
    assert ActionType.REPLACE_LITERAL.value in actions
    assert ActionType.REVOKE_TOKEN.value in actions
    print("✓ GitHub PAT autofix planning working")

    print("All autofix tests passed!")


def test_policy_enforcement():
    """Test policy enforcement functionality."""
    print("Testing policy enforcement...")

    from src.ss360.policy.enforce import PolicyEnforcer

    policy_config = {
        "version": 1,
        "validators": {"allow_network": False, "global_qps": 2.0},
        "budgets": {"new_findings": 0, "max_risk_score": 40},
        "waivers": [],
    }

    enforcer = PolicyEnforcer(policy_config)

    findings = [{"id": "github_pat", "path": "config.py", "line": 10, "risk_score": 30}]

    result = enforcer.enforce(findings)

    # Should violate budget (0 findings allowed, 1 found)
    assert not result.passed, "Expected policy to fail with budget violation"
    assert len(result.violations) > 0, "Expected at least one violation"
    print("✓ Policy budget enforcement working")

    print("All policy tests passed!")


def main():
    """Run all tests."""
    print("🧪 Running SS360 Test Suite")
    print("=" * 50)

    try:
        test_risk_scoring()
        print()

        test_detectors()
        print()

        test_autofix_planning()
        print()

        test_policy_enforcement()
        print()

        print("🎉 All tests passed successfully!")
        return 0

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
