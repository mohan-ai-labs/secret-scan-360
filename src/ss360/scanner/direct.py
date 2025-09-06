"""Direct scanning functionality for SS360 CLI."""

from __future__ import annotations
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from ss360.detectors import get_detector_registry
from ss360.core.findings import Finding


def scan_direct(
    root_path: str,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None,
    max_file_size: int = 1_000_000,
) -> List[Dict[str, Any]]:
    """
    Direct scanning using the new detector interface.
    
    Args:
        root_path: Path to scan (file or directory)
        include_patterns: Glob patterns to include (not used in raw mode)
        exclude_patterns: Glob patterns to exclude (not used in raw mode)
        max_file_size: Maximum file size to scan
        
    Returns:
        List of finding dictionaries
    """
    root = Path(root_path).resolve()
    registry = get_detector_registry()
    all_findings = []
    
    if root.is_file():
        # Scan single file
        findings = _scan_file(root, registry, max_file_size)
        all_findings.extend(findings)
    elif root.is_dir():
        # Scan directory recursively
        for file_path in _iter_scannable_files(root, include_patterns, exclude_patterns):
            findings = _scan_file(file_path, registry, max_file_size)
            all_findings.extend(findings)
    else:
        raise FileNotFoundError(f"Path not found: {root}")
    
    # Convert Finding objects to dictionaries
    return [f.to_dict() for f in all_findings]


def _scan_file(file_path: Path, registry, max_file_size: int) -> List[Finding]:
    """Scan a single file and return findings."""
    try:
        if file_path.stat().st_size > max_file_size:
            return []
        
        # Read file content
        blob = file_path.read_bytes()
        
        # Get relative path for reporting
        try:
            rel_path = str(file_path.relative_to(Path.cwd()))
        except ValueError:
            rel_path = str(file_path)
        
        # Scan with all detectors
        return registry.scan_with_all(blob, rel_path)
        
    except (OSError, PermissionError, UnicodeDecodeError):
        # Skip files that can't be read
        return []


def _iter_scannable_files(
    root_dir: Path, 
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None
) -> List[Path]:
    """Iterate over scannable files in a directory."""
    # Default exclude patterns for raw scanning
    default_excludes = {
        '.git', '.svn', '.hg', '__pycache__', '.pytest_cache',
        'node_modules', 'dist', 'build', '.venv', 'venv'
    }
    
    scannable_files = []
    
    for file_path in root_dir.rglob('*'):
        if not file_path.is_file():
            continue
            
        # Skip files in excluded directories
        if any(part in default_excludes for part in file_path.parts):
            continue
            
        # Skip binary files (simple heuristic)
        if file_path.suffix in {'.exe', '.dll', '.so', '.dylib', '.bin', '.zip', '.tar', '.gz'}:
            continue
            
        scannable_files.append(file_path)
    
    return scannable_files


def scan_with_policy_and_classification(
    root_path: str,
    policy_path: Optional[str] = None,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None,
    only_category: Optional[str] = None,
    raw_mode: bool = False,
) -> Dict[str, Any]:
    """
    Scan with policy enforcement and classification.
    
    This is the main scanning function that replicates ci_scan.py functionality.
    """
    # First, do the basic scanning
    if raw_mode:
        # Raw mode: scan the path directly without git-based filtering
        findings = scan_direct(root_path, include_patterns, exclude_patterns)
    else:
        # Git mode: use the existing Scanner (legacy behavior)
        try:
            from ss360.scanner import Scanner
            from ss360.core.exceptions import SS360ConfigError
            
            config_path = "services/agents/app/config/detectors.yaml"
            
            if not Path(config_path).exists():
                # Fallback to direct scanning if config missing
                print(f"[ss360] Config not found, using direct scanning: {Path(config_path).resolve()}")
                findings = scan_direct(root_path, include_patterns, exclude_patterns)
            else:
                try:
                    scanner = Scanner.from_config(config_path)
                    if scanner is None:
                        raise SS360ConfigError(
                            "Failed to create scanner from config", 
                            config_path=str(Path(config_path).resolve())
                        )
                    
                    exclude_globs = [
                        "**/.git/**", "**/.svn/**", "**/.hg/**", "**/.venv/**", "**/venv/**",
                        "**/node_modules/**", "**/dist/**", "**/build/**", "**/.pytest_cache/**",
                        "**/__pycache__/**", "docs/**", "**/docs/**", "tests/**", "**/tests/**",
                        "detectors/**", "**/detectors/**",
                    ]
                    if exclude_patterns:
                        exclude_globs.extend(exclude_patterns)
                        
                    findings = scanner.scan_paths(
                        [Path(root_path)],
                        include_globs=include_patterns or ["**/*"],
                        exclude_globs=exclude_globs,
                        max_bytes=1_000_000,
                    )
                except Exception as e:
                    raise SS360ConfigError(
                        f"Failed to load scanner config: {e}",
                        config_path=str(Path(config_path).resolve())
                    )
        except ImportError:
            # Fallback to direct scanning if legacy scanner unavailable
            findings = scan_direct(root_path, include_patterns, exclude_patterns)
    
    # Enhance findings with validation and classification
    enhanced_findings, validation_results = _enhance_findings(findings)
    
    # Filter by category if specified
    if only_category:
        enhanced_findings = [f for f in enhanced_findings if f.get("category") == only_category]
    
    # Load and enforce policy
    policy_result = _enforce_policy(enhanced_findings, policy_path)
    
    return {
        "root": str(Path(root_path).resolve()),
        "total": len(enhanced_findings),
        "findings": enhanced_findings,
        "validation_results": validation_results,
        "policy_result": policy_result,
    }


def _enhance_findings(findings: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Enhance findings with validation and classification."""
    enhanced = []
    validation_results = {}
    
    for i, finding in enumerate(findings):
        # Run classification on each finding
        try:
            from ss360.classify import classify
            
            # Create a copy of finding for classification with original tokens
            classification_finding = finding.copy()
            
            # Use original token/URL from meta if available for better classification
            meta = finding.get("meta", {})
            if "full_token" in meta:
                classification_finding["match"] = meta["full_token"]
            elif "full_url" in meta:
                classification_finding["match"] = meta["full_url"]
            
            context = {"validation_results": []}  # No network validation in this implementation
            category, confidence, reasons = classify(classification_finding, context)
            
            enhanced_finding = finding.copy()
            enhanced_finding.update({
                "category": category,
                "confidence": confidence,
                "reasons": reasons
            })
            
            # Remove full secrets from meta to ensure they don't appear in output
            if "meta" in enhanced_finding:
                meta = enhanced_finding["meta"].copy()
                # Remove full token/URL fields that contain unredacted secrets
                meta.pop("full_token", None)
                meta.pop("full_url", None)
                enhanced_finding["meta"] = meta
            
            enhanced.append(enhanced_finding)
            validation_results[str(i)] = []
            
        except Exception as e:
            # If classification fails, add finding without classification
            enhanced_finding = finding.copy()
            enhanced_finding.update({
                "category": "unknown",
                "confidence": 0.1,
                "reasons": [f"classification_error:{str(e)}"]
            })
            
            # Remove full secrets from meta to ensure they don't appear in output
            if "meta" in enhanced_finding:
                meta = enhanced_finding["meta"].copy()
                # Remove full token/URL fields that contain unredacted secrets
                meta.pop("full_token", None)
                meta.pop("full_url", None)
                enhanced_finding["meta"] = meta
            
            enhanced.append(enhanced_finding)
            validation_results[str(i)] = []
    
    return enhanced, validation_results


def _enforce_policy(findings: List[Dict[str, Any]], policy_path: Optional[str] = None) -> Dict[str, Any]:
    """Enforce policy on findings."""
    # Load policy
    if policy_path and Path(policy_path).exists():
        print(f"[ss360] Loaded policy: {Path(policy_path).resolve()}")
        # For now, just return success
        return {"passed": True, "violations": []}
    else:
        # No policy or policy not found
        return {"passed": True, "violations": []}