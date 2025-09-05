#!/usr/bin/env python3
"""
Test for org scan CLI functionality.
"""
import sys
import tempfile
import unittest
from pathlib import Path

# Add source to path  # noqa: E402
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ss360.cli import main  # noqa: E402


class TestOrgScanCLI(unittest.TestCase):
    def test_org_scan_help(self):
        """Test that org scan help works without errors."""
        with self.assertRaises(SystemExit) as cm:
            main(["org", "scan", "--help"])
        # Help should exit with code 0
        self.assertEqual(cm.exception.code, 0)

    def test_org_scan_requires_repos(self):
        """Test that org scan requires --repos argument."""
        with self.assertRaises(SystemExit) as cm:
            main(["org", "scan"])
        # Should exit with error code when missing required argument
        self.assertNotEqual(cm.exception.code, 0)

    def test_org_aggregate_still_works(self):
        """Test that existing org aggregate functionality still works."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create minimal SARIF structure
            org_dir = Path(temp_dir) / "org"
            org_dir.mkdir()

            # Test with empty directory (should not crash)
            result = main(
                ["org", "aggregate", "--in", str(org_dir), "--out", temp_dir]
            )
            # Should complete successfully even with no files
            self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
