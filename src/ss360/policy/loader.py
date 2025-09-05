# SPDX-License-Identifier: MIT
"""
Policy configuration loading.
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Dict, Any, List
import fnmatch

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    yaml = None
    YAML_AVAILABLE = False


def load_policy_config(config_path: str = None) -> Dict[str, Any]:
    """
    Load policy configuration from file or use default.
    
    Args:
        config_path: Path to the policy YAML file
        
    Returns:
        Dictionary containing the policy configuration
        
    Raises:
        ImportError: If yaml module is not available
    """
    if not config_path:
        return get_default_policy_config()
    
    if not YAML_AVAILABLE:
        raise ImportError("yaml module required for loading config files")
    
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding="utf-8") as f:
            config = yaml.safe_load(f)
        
        if config is None:
            config = {}
        
        # Validate config structure
        if not isinstance(config, dict):
            raise ValueError("Policy config must be a dictionary")
        
        # Apply defaults
        config = _apply_policy_defaults(config)
        
        # Validate structure
        _validate_policy_config(config)
        
        return config
    
    return get_default_policy_config()


def _apply_policy_defaults(config: Dict[str, Any]) -> Dict[str, Any]:
    """Apply default values to policy configuration."""
    # Set version if missing
    if "version" not in config:
        config["version"] = 1
    
    # Set validators section defaults
    if "validators" not in config:
        config["validators"] = {}
    
    validators = config["validators"]
    if "allow_network" not in validators:
        validators["allow_network"] = False  # Default to safe mode
    if "global_qps" not in validators:
        validators["global_qps"] = 2.0
    
    # Set budgets section defaults
    if "budgets" not in config:
        config["budgets"] = {}
    
    budgets = config["budgets"]
    if "new_findings" not in budgets:
        budgets["new_findings"] = 0  # Strict by default
    if "max_risk_score" not in budgets:
        budgets["max_risk_score"] = 40
    
    # Set waivers section defaults
    if "waivers" not in config:
        config["waivers"] = []
    
    # Set autofix section defaults
    if "autofix" not in config:
        config["autofix"] = {}
    
    autofix = config["autofix"]
    if "min_risk_score" not in autofix:
        autofix["min_risk_score"] = 60
    if "require_confirmation" not in autofix:
        autofix["require_confirmation"] = True
    
    return config


def _validate_policy_config(config: Dict[str, Any]) -> None:
    """Validate policy configuration structure."""
    required_sections = ["version", "validators", "budgets"]
    for section in required_sections:
        if section not in config:
            raise ValueError(f"Missing required section: {section}")
    
    # Validate version
    version = config.get("version")
    if not isinstance(version, int) or version != 1:
        raise ValueError("Policy version must be 1")
    
    # Validate validators section
    validators = config.get("validators", {})
    if not isinstance(validators, dict):
        raise ValueError("validators section must be a dictionary")
    
    # Validate budgets section
    budgets = config.get("budgets", {})
    if not isinstance(budgets, dict):
        raise ValueError("budgets section must be a dictionary")
    
    # Validate waivers section
    waivers = config.get("waivers", [])
    if not isinstance(waivers, list):
        raise ValueError("waivers section must be a list")
    
    for waiver in waivers:
        _validate_waiver(waiver)


def _validate_waiver(waiver: Dict[str, Any]) -> None:
    """Validate a single waiver entry."""
    required_fields = ["rule", "path", "expiry", "reason"]
    for field in required_fields:
        if field not in waiver:
            raise ValueError(f"Waiver missing required field: {field}")
    
    # Validate expiry date format
    try:
        datetime.fromisoformat(waiver["expiry"])
    except ValueError:
        raise ValueError(f"Invalid expiry date format: {waiver['expiry']}")


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
        },
        "budgets": {
            "new_findings": 0,
            "max_risk_score": 40
        },
        "waivers": [],
        "autofix": {
            "min_risk_score": 60,
            "require_confirmation": True
        }
    }


def is_waiver_active(waiver: Dict[str, Any], finding_path: str, rule_id: str) -> bool:
    """
    Check if a waiver is active for a given finding.
    
    Args:
        waiver: Waiver configuration
        finding_path: Path of the finding
        rule_id: Rule/detector ID
        
    Returns:
        True if waiver is active and applicable
    """
    # Check if waiver applies to this rule
    if waiver.get("rule") != rule_id:
        return False
    
    # Check if waiver applies to this path (glob matching)
    waiver_path = waiver.get("path", "")
    if not fnmatch.fnmatch(finding_path, waiver_path):
        return False
    
    # Check if waiver is still valid (not expired)
    expiry_str = waiver.get("expiry", "")
    try:
        expiry_date = datetime.fromisoformat(expiry_str)
        if datetime.now() > expiry_date:
            return False
    except ValueError:
        return False
    
    return True


def get_active_waivers(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Get list of currently active waivers.
    
    Args:
        config: Policy configuration
        
    Returns:
        List of active waiver entries
    """
    waivers = config.get("waivers", [])
    active_waivers = []
    
    for waiver in waivers:
        expiry_str = waiver.get("expiry", "")
        try:
            expiry_date = datetime.fromisoformat(expiry_str)
            if datetime.now() <= expiry_date:
                active_waivers.append(waiver)
        except ValueError:
            # Skip invalid expiry dates
            continue
    
    return active_waivers