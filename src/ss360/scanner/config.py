# SPDX-License-Identifier: MIT
"""
Scanner configuration loader for SS360.
"""
from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from ss360.core.exceptions import SS360ConfigError

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    yaml = None
    YAML_AVAILABLE = False


def load_scanner_config(config_path: Optional[str] = None, repo_root: str = ".") -> Dict[str, Any]:
    """
    Load scanner configuration following the specified search order.
    
    Args:
        config_path: Explicit config path from --config CLI flag
        repo_root: Repository root path for searching .ss360.yml/.ss360.yaml
        
    Returns:
        Dictionary containing scanner configuration
        
    Raises:
        SS360ConfigError: If config file is malformed or explicitly provided config is missing
    """
    repo_path = Path(repo_root).resolve()
    
    # 1. If CLI --config provided → load it
    if config_path:
        config_abs_path = Path(config_path).resolve()
        if not config_abs_path.exists():
            raise SS360ConfigError(
                f"Specified config file not found: {config_abs_path}",
                config_path=str(config_abs_path)
            )
        try:
            config = _load_yaml_config(config_abs_path)
            print(f"[ss360] Loaded config: {config_abs_path}")
            return config
        except Exception as e:
            raise SS360ConfigError(
                f"Failed to parse config file: {e}",
                config_path=str(config_abs_path)
            )
    
    # 2. Look for .ss360.yml or .ss360.yaml at repo root
    for config_name in [".ss360.yml", ".ss360.yaml"]:
        config_file = repo_path / config_name
        if config_file.exists():
            try:
                config = _load_yaml_config(config_file)
                print(f"[ss360] Loaded config: {config_file}")
                return config
            except Exception as e:
                raise SS360ConfigError(
                    f"Failed to parse config file: {e}",
                    config_path=str(config_file)
                )
    
    # 3. Use built-in defaults
    print(f"[ss360] Using default scanner config")
    return get_default_scanner_config()


def _load_yaml_config(config_path: Path) -> Dict[str, Any]:
    """Load and validate YAML config file."""
    if not YAML_AVAILABLE:
        raise ImportError("yaml module required for loading config files")
    
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    
    if config is None:
        config = {}
    
    if not isinstance(config, dict):
        raise ValueError("Config must be a dictionary")
    
    return _apply_scanner_defaults(config)


def _apply_scanner_defaults(config: Dict[str, Any]) -> Dict[str, Any]:
    """Apply default values to scanner configuration."""
    # Set include_globs defaults
    if "include_globs" not in config:
        config["include_globs"] = ["**/*"]
    
    # Set exclude_globs defaults
    if "exclude_globs" not in config:
        config["exclude_globs"] = [
            "**/.git/**",
            "**/.svn/**", 
            "**/.hg/**",
            "**/.venv/**",
            "**/venv/**",
            "**/node_modules/**",
            "**/dist/**",
            "**/build/**",
            "**/.pytest_cache/**",
            "**/__pycache__/**",
        ]
    
    # Set other defaults
    if "min_match_length" not in config:
        config["min_match_length"] = 8
    
    if "confidence_threshold" not in config:
        config["confidence_threshold"] = 0.0
    
    if "disabled_detectors" not in config:
        config["disabled_detectors"] = []
    
    return config


def get_default_scanner_config() -> Dict[str, Any]:
    """
    Get the default scanner configuration.
    
    Returns:
        Dictionary with default scanner settings
    """
    return {
        "include_globs": ["**/*"],
        "exclude_globs": [
            "**/.git/**",
            "**/.svn/**",
            "**/.hg/**", 
            "**/.venv/**",
            "**/venv/**",
            "**/node_modules/**",
            "**/dist/**",
            "**/build/**",
            "**/.pytest_cache/**",
            "**/__pycache__/**",
        ],
        "min_match_length": 8,
        "confidence_threshold": 0.0,
        "disabled_detectors": [],
    }


def create_default_config_template() -> str:
    """
    Create a minimal .ss360.yml template with commented examples.
    
    Returns:
        YAML string with default configuration template
    """
    return """# SS360 Scanner Configuration
# This file configures how SS360 scans your repository

# File patterns to include (default: scan everything)
include_globs:
  - "**/*"

# File patterns to exclude
exclude_globs:
  - "**/.git/**"
  - "**/.svn/**"
  - "**/.hg/**"
  - "**/.venv/**"
  - "**/venv/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/.pytest_cache/**"
  - "**/__pycache__/**"
  # Add project-specific paths to exclude:
  # - "docs/**"
  # - "examples/**"

# Minimum match length for detectors (helps reduce noise)
min_match_length: 8

# Confidence threshold for ML-based detectors (future use)
confidence_threshold: 0.0

# Detectors to disable by name
disabled_detectors: []
  # Examples:
  # - "Generic API Key"
  # - "Private Key (RSA)"
"""