#!/usr/bin/env python3
"""
Fail CI if code changed but tests did not.

Robust against shallow clones: we resolve a concrete base SHA from origin/<base>.
"""

from __future__ import annotations

import os
import subprocess
import sys

TEST_DIRS: tuple[str, ...] = ("tests/",)
CODE_PREFIXES: tuple[str, ...] = (
    "src/",
    "services/",
    "detectors/",
    "scripts/ci_scan.py",
)

# Exclude auto-generated packaging files
EXCLUDE_PATTERNS: tuple[str, ...] = (
    "src/secret_scan_360.egg-info/",
    ".egg-info/",
)


def sh(args: list[str], check: bool = True) -> str:
    return subprocess.run(
        args, text=True, check=check, capture_output=True
    ).stdout.strip()


def rev(ref: str) -> str:
    try:
        return sh(["git", "rev-parse", ref])
    except Exception:
        return ""


def main() -> int:
    base_branch = os.getenv("GITHUB_BASE_REF") or "main"
    head_ref = os.getenv("GITHUB_SHA") or "HEAD"

    # Make sure we have the base branch in this shallow clone
    subprocess.run(["git", "fetch", "--depth=50", "origin", base_branch], check=False)

    # Resolve a concrete base SHA with sane fallbacks
    base = (
        rev(f"origin/{base_branch}")
        or rev(base_branch)
        or rev("origin/main")
        or rev("main")
    )
    if not base:
        print(
            f"[guard] Could not resolve base for '{base_branch}', "
            "skipping tests-required check.",
            file=sys.stderr,
        )
        return 0

    changed = sh(["git", "diff", "--name-only", f"{base}...{head_ref}"]).splitlines()
    if not changed:
        print("[guard] No changed files; skipping.")
        return 0

    changed_tests = any(f.startswith(TEST_DIRS) for f in changed)

    def is_code(f: str) -> bool:
        # Check if file should be excluded
        if any(f.startswith(pattern) for pattern in EXCLUDE_PATTERNS):
            return False
        return any(f.startswith(p.rstrip("/")) or f == p for p in CODE_PREFIXES)

    changed_code = any(is_code(f) for f in changed)

    if changed_code and not changed_tests:
        print("[guard] Changed code without matching tests:", file=sys.stderr)
        for f in changed:
            if is_code(f) and not any(f.startswith(t) for t in TEST_DIRS):
                print(f"  - {f}", file=sys.stderr)
        print("\nPlease add/update tests under tests/.", file=sys.stderr)
        return 1

    print("[guard] Tests check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
