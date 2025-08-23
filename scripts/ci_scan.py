from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # YAML is optional; defaults will be used if missing

# --- Defaults & config --------------------------------------------------------

DEFAULT_RULES: List[Dict] = [
    {
        "name": "Private Key (RSA)",
        "kind": "Private Key",
        "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
        "redact": True,
    },
    {
        "name": "Private Key (EC)",
        "kind": "Private Key",
        "pattern": r"-----BEGIN EC PRIVATE KEY-----",
        "redact": True,
    },
    {
        "name": "AWS Access Key",
        "kind": "AWS Access Key",
        "pattern": r"\b(AKIA[0-9A-Z]{16})\b",
        "redact": True,
    },
    {
        "name": "GitHub Token (classic/pat)",
        "kind": "GitHub Token",
        "pattern": r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b",
        "redact": True,
    },
    {
        "name": "Generic API Key",
        "kind": "Generic API Key",
        "pattern": r"\b(?i)(api_?key|token|secret)[:=]\s*([A-Za-z0-9_\-]{16,})\b",
        "redact": True,
    },
]

DEFAULT_EXCLUDES = [
    "**/.git/**",
    "**/.venv/**",
    "**/node_modules/**",
    "**/dist/**",
    "**/build/**",
    "**/.pytest_cache/**",
    "**/__pycache__/**",
    "**/*.png",
    "**/*.jpg",
    "**/*.jpeg",
    "**/*.gif",
    "**/*.pdf",
    "**/*.zip",
    "**/*.gz",
    "**/*.tar",
    "**/*.7z",
]


# --- Helpers ------------------------------------------------------------------


def load_rules(config_path: Optional[Path]) -> List[Dict]:
    """Load regex rules from detectors.yaml if present, else use defaults."""
    if config_path and config_path.exists() and yaml is not None:
        cfg = yaml.safe_load(config_path.read_text()) or {}
        rules = (cfg.get("regex_detector") or {}).get("rules") or []
        if isinstance(rules, list) and rules:
            return rules
    return DEFAULT_RULES


def iter_paths(
    roots: Iterable[Path],
    excludes: Optional[List[str]] = None,
) -> Iterable[Path]:
    """Yield files under roots, skipping common junk paths."""
    exclude_globs = excludes or DEFAULT_EXCLUDES
    for root in roots:
        base = root.resolve()
        if base.is_file():
            if not any(base.match(p) for p in exclude_globs):
                yield base
            continue
        for p in base.rglob("*"):
            if not p.is_file():
                continue
            if any(p.match(pattern) for pattern in exclude_globs):
                continue
            yield p


def read_text_safely(path: Path, max_bytes: int = 1_000_000) -> Optional[str]:
    """Read small text files; skip obvious binary or very large files."""
    try:
        if path.stat().st_size > max_bytes:
            return None
        data = path.read_bytes()
        if b"\x00" in data:
            return None
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return None


# --- Scanner ------------------------------------------------------------------


def scan_repo(
    roots: List[Path],
    rules: List[Dict],
    max_findings: int,
) -> Dict:
    """
    Very lightweight scanner for CI:
    - applies regex rules
    - stops early after max_findings
    - returns JSON-serializable summary
    """
    import re

    compiled = []
    for r in rules:
        pat = r.get("pattern") or ""
        try:
            compiled.append(
                (
                    re.compile(pat, re.MULTILINE),
                    r.get("name") or "Unnamed",
                    r.get("kind") or "Unknown",
                    bool(r.get("redact", True)),
                )
            )
        except re.error:
            # Ignore invalid patterns to avoid failing CI on a broken rule
            continue

    findings: List[Dict] = []
    for p in iter_paths(roots):
        text = read_text_safely(p)
        if text is None:
            continue
        for rx, name, kind, _redact in compiled:
            for m in rx.finditer(text):
                match_str = m.group(0)
                # Redact long secrets in CI logs
                display = (
                    (match_str[:4] + "..." + match_str[-4:])
                    if len(match_str) > 12
                    else match_str
                )
                findings.append(
                    {
                        "path": str(p),
                        "kind": kind,
                        "rule": name,
                        "match": display,
                    }
                )
                if len(findings) >= max_findings:
                    return {"ok": False, "findings": findings, "truncated": True}
    return {"ok": len(findings) == 0, "findings": findings, "truncated": False}


# --- CLI ----------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Minimal CI secret scan")
    parser.add_argument(
        "--root", action="append", default=["."], help="Root(s) to scan (repeatable)"
    )
    parser.add_argument(
        "--config",
        default="services/agents/app/config/detectors.yaml",
        help="Path to detectors.yaml",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=50,
        help="Stop after N findings (default: 50)",
    )
    parser.add_argument(
        "--json-out", default="", help="Path to write JSON results (optional)"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    roots = [Path(r) for r in args.root]
    cfg_path = Path(args.config)
    rules = load_rules(cfg_path if cfg_path.exists() else None)

    result = scan_repo(roots, rules, max_findings=max(1, args.max_findings))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, indent=2))

    # Print a short human summary for the CI log
    print(
        json.dumps({"count": len(result["findings"]), "truncated": result["truncated"]})
    )
    if not result["ok"]:
        # Show first few findings for context
        for item in result["findings"][:10]:
            print(f"[secret] {item['kind']} in {item['path']} :: {item['match']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
