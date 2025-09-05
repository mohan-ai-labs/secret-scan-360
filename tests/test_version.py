"""Test version information."""

import importlib.metadata
from ss360 import __version__


def test_version_string():
    """Test that __version__ is a valid version string."""
    assert isinstance(__version__, str)
    assert len(__version__) > 0
    assert "." in __version__  # Should have at least major.minor format


def test_version_matches_package_metadata():
    """Test that __version__ matches the package metadata."""
    try:
        package_version = importlib.metadata.version("secret-scan-360")
        assert __version__ == package_version
    except importlib.metadata.PackageNotFoundError:
        # Package not installed, skip this test
        pass


def test_version_format():
    """Test that version follows semantic versioning pattern."""
    import re

    # Basic semver pattern (major.minor.patch with optional pre-release)
    semver_pattern = r"^\d+\.\d+\.\d+(?:-[a-zA-Z0-9]+(?:\.\d+)?)?$"
    assert re.match(
        semver_pattern, __version__
    ), f"Version {__version__} doesn't follow semver format"
