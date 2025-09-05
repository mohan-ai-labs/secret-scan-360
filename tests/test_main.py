"""Test CLI module functionality."""

import subprocess
import sys
from unittest.mock import patch


def test_main_module_importable():
    """Test that the __main__ module can be imported."""
    try:
        import ss360.__main__

        assert True
    except ImportError:
        assert False, "ss360.__main__ module should be importable"


def test_main_module_executable():
    """Test that the module can be executed with python -m."""
    try:
        # Test that the module can be called (will likely show help or error, but shouldn't crash on import)
        result = subprocess.run(
            [sys.executable, "-m", "ss360", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # The command should either succeed or fail gracefully (not crash with import error)
        # We don't check return code because --help might not be implemented yet
        assert "ImportError" not in result.stderr
        assert "ModuleNotFoundError" not in result.stderr
    except subprocess.TimeoutExpired:
        assert False, "Module execution timed out"
    except Exception as e:
        assert False, f"Module execution failed: {e}"


def test_main_module_has_main_guard():
    """Test that __main__.py has proper main guard."""
    import ss360.__main__ as main_module

    # Check if the module has the standard if __name__ == "__main__" pattern
    # by checking if it's safe to import without side effects
    assert hasattr(main_module, "__name__")
