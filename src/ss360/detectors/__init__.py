"""Detector registry and discovery for Secret Scan 360."""

from __future__ import annotations
import sys
from pathlib import Path
from typing import List, Dict, Any, Callable
from ss360.core.findings import Finding


# Type alias for detector scan function
DetectorScanFunc = Callable[[bytes, str], List[Finding]]


class DetectorRegistry:
    """Registry for detector modules under ss360.detectors/"""
    
    def __init__(self):
        self._detectors: Dict[str, DetectorScanFunc] = {}
        self._load_detectors()
    
    def _load_detectors(self):
        """Load known detectors that have the scan() interface."""
        import importlib
        import logging
        
        # List of known detectors that have scan() interface
        detector_modules = [
            "github_pat",
            "aws_keypair", 
            "azure_storage_sas",
            "slack_webhook",
            "jwt_generic",
            "gcp_service_account_key",
        ]
        
        for module_name in detector_modules:
            try:
                # Import from ss360.detectors.module_name
                module = importlib.import_module(f"ss360.detectors.{module_name}")
                
                # Check if it has the new scan() interface
                if hasattr(module, "scan") and hasattr(module, "NAME"):
                    self._detectors[module.NAME] = module.scan
                    
            except (ImportError, AttributeError) as e:
                # Log warning but don't crash - skip detectors that can't be imported
                logging.warning(f"Failed to load detector {module_name}: {e}")
                continue
    
    def all_detectors(self) -> Dict[str, DetectorScanFunc]:
        """Return all registered detector scan functions."""
        return self._detectors.copy()
    
    def keys(self):
        """Return detector keys for compatibility with acceptance criteria."""
        return self._detectors.keys()
        
    def scan_with_all(self, blob: bytes, path: str) -> List[Finding]:
        """Run all detectors on the given blob and return all findings."""
        findings = []
        for detector_name, scan_func in self._detectors.items():
            try:
                detector_findings = scan_func(blob, path)
                findings.extend(detector_findings)
            except Exception:
                # Skip detectors that fail to run
                continue
        return findings


# Global registry instance
_registry = None


def get_detector_registry() -> DetectorRegistry:
    """Get the global detector registry."""
    global _registry
    if _registry is None:
        _registry = DetectorRegistry()
    return _registry


def all_detectors() -> Dict[str, DetectorScanFunc]:
    """Convenience function to get all detectors."""
    return get_detector_registry().all_detectors()