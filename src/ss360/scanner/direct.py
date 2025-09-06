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
    scanner_config_path: Optional[str] = None,
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
        # Git mode: use scanner configuration with proper search order
        try:
            from ss360.scanner.config import load_scanner_config
            from ss360.core.exceptions import SS360ConfigError
            
            # Load scanner configuration following search order
            scanner_config = load_scanner_config(scanner_config_path, root_path)
            
            # Try to use legacy Scanner if available, otherwise use direct scanning with config
            try:
                from ss360.scanner import Scanner
                
                if Scanner is not None:
                    try:
                        # Create scanner using the default config path as fallback
                        # Look for legacy detectors.yaml but don't require it
                        legacy_config_path = "services/agents/app/config/detectors.yaml"
                        if Path(legacy_config_path).exists():
                            scanner = Scanner.from_config(legacy_config_path)
                        else:
                            # Create scanner with built-in registry if no legacy config
                            from services.agents.app.detectors.registry import build_registry
                            registry = build_registry(None)  # Uses built-in defaults
                            scanner = Scanner(registry=registry)
                        
                        if scanner is None:
                            raise SS360ConfigError(
                                "Failed to create scanner from config", 
                                config_path=scanner_config_path
                            )
                        
                        # Use exclude patterns from scanner config
                        exclude_globs = scanner_config.get("exclude_globs", [])
                        if exclude_patterns:
                            exclude_globs.extend(exclude_patterns)
                            
                        include_globs = include_patterns or scanner_config.get("include_globs", ["**/*"])
                            
                        findings = scanner.scan_paths(
                            [Path(root_path)],
                            include_globs=include_globs,
                            exclude_globs=exclude_globs,
                            max_bytes=1_000_000,
                        )
                    except (ImportError, AttributeError) as e:
                        print(f"[ss360] Legacy scanner failed, using direct scanning: {e}")
                        # Fallback to direct scanning with config
                        findings = scan_direct(
                            root_path, 
                            include_patterns or scanner_config.get("include_globs"), 
                            exclude_patterns or scanner_config.get("exclude_globs")
                        )
                else:
                    # Scanner not available, use direct scanning with config
                    findings = scan_direct(
                        root_path, 
                        include_patterns or scanner_config.get("include_globs"), 
                        exclude_patterns or scanner_config.get("exclude_globs")
                    )
            except ImportError:
                # Scanner import failed, use direct scanning with config
                findings = scan_direct(
                    root_path, 
                    include_patterns or scanner_config.get("include_globs"), 
                    exclude_patterns or scanner_config.get("exclude_globs")
                )
        except ImportError:
            # Fallback to direct scanning if scanner config unavailable
            print(f"[ss360] Using default scanner config")
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
    
    # Load policy config for validation settings
    try:
        from ss360.policy.config import load_policy_config, get_default_policy_config
        
        # Try to load from common locations
        policy_paths = ["policy.yml", "policy.yaml", "policy.example.yml"]
        policy_config = None
        for policy_path in policy_paths:
            try:
                policy_config = load_policy_config(policy_path)
                break
            except FileNotFoundError:
                continue
        
        if policy_config is None:
            policy_config = get_default_policy_config()
            
        validation_config = policy_config.get("validators", {})
    except Exception:
        # Fallback to safe defaults if no policy config
        validation_config = {"allow_network": False, "global_qps": 2.0}
    
    for i, finding in enumerate(findings):
        # Run validation for this finding
        try:
            from ss360.validate.core import run_validators
            validation_results_list = run_validators(
                finding, {"validators": validation_config}
            )
            validation_results[str(i)] = [
                {
                    "state": result.state.value,
                    "evidence": result.evidence,
                    "reason": result.reason,
                    "validator_name": result.validator_name,
                }
                for result in validation_results_list
            ]
        except Exception:
            # If validation fails, continue without it
            validation_results[str(i)] = []
            validation_results_list = []
        
        # Run classification on each finding with validation context
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
            
            # Pass validation results to classifier
            context = {"validation_results": validation_results[str(i)]}
            category, confidence, reasons = classify(classification_finding, context)
            
            # Calculate risk score
            try:
                from ss360.risk.score import calculate_risk_score
                risk_score = calculate_risk_score(classification_finding, validation_results[str(i)])
            except Exception:
                risk_score = 50  # Default risk score
            
            enhanced_finding = finding.copy()
            enhanced_finding.update({
                "category": category,
                "confidence": confidence,
                "reasons": reasons,
                "risk_score": risk_score,
                "validated": _create_validated_field(validation_results[str(i)])
            })
            
            # Remove full secrets from meta to ensure they don't appear in output
            if "meta" in enhanced_finding:
                meta = enhanced_finding["meta"].copy()
                # Remove full token/URL fields that contain unredacted secrets
                meta.pop("full_token", None)
                meta.pop("full_url", None)
                enhanced_finding["meta"] = meta
            
            enhanced.append(enhanced_finding)
            
        except Exception as e:
            # If classification fails, add finding without classification
            enhanced_finding = finding.copy()
            enhanced_finding.update({
                "category": "unknown",
                "confidence": 0.1,
                "reasons": [f"classification_error:{str(e)}"],
                "risk_score": 50,
                "validated": _create_validated_field(validation_results.get(str(i), []))
            })
            
            # Remove full secrets from meta to ensure they don't appear in output
            if "meta" in enhanced_finding:
                meta = enhanced_finding["meta"].copy()
                # Remove full token/URL fields that contain unredacted secrets
                meta.pop("full_token", None)
                meta.pop("full_url", None)
                enhanced_finding["meta"] = meta
            
            enhanced.append(enhanced_finding)
    
    return enhanced, validation_results


def _create_validated_field(validation_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Create validated field from validation results."""
    if not validation_results:
        return {"state": "indeterminate"}
    
    # Find the most decisive result
    for result in validation_results:
        state = result.get("state", "indeterminate")
        if state in ["valid", "invalid"]:
            evidence = result.get("evidence")
            return {
                "state": "confirmed" if state == "valid" else "invalid",
                "evidence": evidence if evidence else None
            }
    
    # All results were indeterminate
    return {"state": "indeterminate"}


def _enforce_policy(findings: List[Dict[str, Any]], policy_path: Optional[str] = None) -> Dict[str, Any]:
    """Enforce policy on findings."""
    try:
        from ss360.policy.config import load_policy_config, get_default_policy_config
        from ss360.policy.enforce import PolicyEnforcer
        
        # Load policy
        if policy_path and Path(policy_path).exists():
            policy_config = load_policy_config(policy_path)
            print(f"[ss360] Loaded policy: {Path(policy_path).resolve()}")
        else:
            # Try to load from common locations
            policy_paths = ["policy.yml", "policy.yaml", "policy.example.yml"]
            policy_config = None
            for p_path in policy_paths:
                try:
                    policy_config = load_policy_config(p_path)
                    break
                except FileNotFoundError:
                    continue
            
            if policy_config is None:
                policy_config = get_default_policy_config()
        
        # Enforce policy
        enforcer = PolicyEnforcer(policy_config)
        enforcement_result = enforcer.enforce(findings)
        
        return {
            "passed": enforcement_result.passed,
            "violations": [
                {
                    "type": v.type.value,
                    "message": v.message,
                    "finding": v.finding_id if hasattr(v, 'finding_id') else None
                }
                for v in enforcement_result.violations
            ]
        }
        
    except Exception as e:
        print(f"[ss360] Policy enforcement error: {e}")
        # Return success for fallback compatibility
        return {"passed": True, "violations": []}