# SPDX-License-Identifier: MIT
"""
Policy configuration loader for SS360.
"""
from __future__ import annotations

import yaml
from pathlib import Path
from typing import Dict, Any, Optional


def load_policy_config(config_path: str) -> Dict[str, Any]:
    """
    Load policy configuration from YAML file.
    
    Args:
        config_path: Path to the policy YAML file
        
    Returns:
        Dictionary containing the policy configuration
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid YAML
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Policy config file not found: {config_path}")
    
    with open(path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    if config is None:
        config = {}
    
    # Validate config structure
    if not isinstance(config, dict):
        raise ValueError("Policy config must be a dictionary")
    
    # Set defaults for validators section if missing
    if "validators" not in config:
        config["validators"] = {}
    
    validators = config["validators"]
    if "allow_network" not in validators:
        validators["allow_network"] = False  # Default to safe mode
    
    if "global_qps" not in validators:
        validators["global_qps"] = 2.0
    
    return config


def get_default_policy_config() -> Dict[str, Any]:
    """
    Get the default policy configuration.
    
    Returns:
        Dictionary with default policy settings
    """
    return {
        "version": 1,
        "validators": {
            "allow_network": False,
            "global_qps": 2.0
        }
    }