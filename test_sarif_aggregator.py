#!/usr/bin/env python3
"""
Tests for SARIF aggregator functionality.
"""

import json
import tempfile
from pathlib import Path


def test_codeowners_parsing():
    """Test CODEOWNERS parsing and pattern matching."""
    print("Testing CODEOWNERS parsing...")

    import sys

    sys.path.insert(0, str(Path(__file__).parent / "tools"))
    from sarif_aggregate import CodeOwnersParser

    # Test basic parsing
    codeowners_content = """
# Backend team owns most infrastructure
* @backend-team

# Frontend team owns the web UI
/src/ui/ @frontend-team
/src/components/ @frontend-team

# Security team owns sensitive configuration
/src/config.py @security-team
/deployment/ @security-team @devops-team

# Test files are owned by whoever owns the main code
/tests/ @backend-team
"""

    parser = CodeOwnersParser(codeowners_content)

    # Test exact file matches
    assert parser.get_owners("src/config.py") == ["@security-team"]
    print("✓ Exact file matching works")

    # Test directory matches
    assert parser.get_owners("src/ui/login.tsx") == ["@frontend-team"]
    assert parser.get_owners("deployment/secrets.yaml") == [
        "@security-team",
        "@devops-team",
    ]
    print("✓ Directory matching works")

    # Test wildcard fallback (last rule wins)
    assert parser.get_owners("random/file.py") == ["@backend-team"]
    print("✓ Wildcard fallback works")

    # Test that last rule wins
    assert parser.get_owners("deployment/config.yaml") == [
        "@security-team",
        "@devops-team",
    ]  # Not @backend-team
    print("✓ Last rule wins principle works")

    print("All CODEOWNERS parsing tests passed!")


def test_sarif_aggregation():
    """Test SARIF aggregation with fixtures."""
    print("Testing SARIF aggregation...")

    import sys

    sys.path.insert(0, str(Path(__file__).parent / "tools"))
    from sarif_aggregate import SarifAggregator

    # Use our existing test fixtures
    artifacts_dir = Path(".artifacts/org")
    if not artifacts_dir.exists():
        print("Skipping SARIF aggregation test - no test fixtures found")
        return

    aggregator = SarifAggregator(artifacts_dir)
    summary = aggregator.aggregate()

    # Verify basic aggregation
    assert summary["total_findings"] == 3
    assert len(summary["repos_scanned"]) == 2
    assert "repo1" in summary["repos_scanned"]
    assert "repo2" in summary["repos_scanned"]
    print("✓ Basic aggregation metrics correct")

    # Verify owner mapping
    assert "@security-team" in summary["by_owner"]
    assert "@backend-team" in summary["by_owner"]
    assert summary["by_owner"]["@security-team"]["total"] == 2
    assert summary["by_owner"]["@backend-team"]["total"] == 1
    print("✓ Owner mapping correct")

    # Verify rule counts
    assert summary["by_rule"]["github_pat"] == 2
    assert summary["by_rule"]["aws_access_key"] == 1
    print("✓ Rule counts correct")

    # Verify category counts
    assert summary["by_category"]["actual"] == 1
    assert summary["by_category"]["test"] == 1
    assert summary["by_category"]["expired"] == 1
    print("✓ Category counts correct")

    print("All SARIF aggregation tests passed!")


def test_output_generation():
    """Test JSON and Markdown output generation."""
    print("Testing output generation...")

    import sys

    sys.path.insert(0, str(Path(__file__).parent / "tools"))
    from sarif_aggregate import SarifAggregator

    artifacts_dir = Path(".artifacts/org")
    if not artifacts_dir.exists():
        print("Skipping output generation test - no test fixtures found")
        return

    aggregator = SarifAggregator(artifacts_dir)
    aggregator.aggregate()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Test JSON output
        json_output = tmpdir / "test-summary.json"
        aggregator.generate_json_summary(json_output)

        assert json_output.exists()
        with open(json_output) as f:
            data = json.load(f)
        assert data["total_findings"] == 3
        print("✓ JSON output generation works")

        # Test Markdown output
        md_output = tmpdir / "test-summary.md"
        aggregator.generate_markdown_summary(md_output)

        assert md_output.exists()
        content = md_output.read_text()
        assert "Organization Security Summary" in content
        assert "@security-team" in content
        assert "repo1" in content
        print("✓ Markdown output generation works")

    print("All output generation tests passed!")


def test_edge_cases():
    """Test edge cases and error handling."""
    print("Testing edge cases...")

    import sys

    sys.path.insert(0, str(Path(__file__).parent / "tools"))
    from sarif_aggregate import CodeOwnersParser, SarifAggregator

    # Test empty CODEOWNERS
    parser = CodeOwnersParser("")
    assert parser.get_owners("any/file.py") == []
    print("✓ Empty CODEOWNERS handled")

    # Test CODEOWNERS with only comments
    parser = CodeOwnersParser("# Just comments\n# More comments")
    assert parser.get_owners("any/file.py") == []
    print("✓ Comments-only CODEOWNERS handled")

    # Test malformed CODEOWNERS lines
    parser = CodeOwnersParser("incomplete-line\n* @valid-owner")
    assert parser.get_owners("any/file.py") == ["@valid-owner"]
    print("✓ Malformed CODEOWNERS lines ignored")

    # Test aggregator with empty directory
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        aggregator = SarifAggregator(tmpdir)
        summary = aggregator.aggregate()
        assert summary["total_findings"] == 0
        assert len(summary["repos_scanned"]) == 0
        print("✓ Empty directory handled")

    print("All edge case tests passed!")


def main():
    """Run all SARIF aggregator tests."""
    print("🧪 Running SARIF Aggregator Test Suite")
    print("=" * 50)

    try:
        test_codeowners_parsing()
        print()
        test_sarif_aggregation()
        print()
        test_output_generation()
        print()
        test_edge_cases()
        print()
        print("🎉 All SARIF aggregator tests passed!")
        return 0
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
