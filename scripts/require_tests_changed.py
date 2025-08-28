#!/usr/bin/env python3
"""
Fail CI if code changed but tests did not.

- Looks at diff between the PR base and head.
- If any code-y paths changed and nothing in tests/ changed, exit 1.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Iterable, List  # noqa: F401  (intentionally kept out; remove if not needed)

TEST_DIRS: tuple[str, ...] = ("tests/",)
# Treat these as “code changed” indicators for your repo
CODE_PREFIXES: tuple[str, ...] = (
    "src/",
    "services/",
    "detectors/",
    "scripts/ci_scan.py",
)


def _run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True).strip()


def _diff_names(base: str, head: str) -> list[str]:
    out = _run(["git", "diff", "--name-only", f"{base}...{head}"])
    return [ln for ln in out.splitlines() if ln]


def main() -> int:
    base_ref = os.getenv("GITHUB_BASE_REF") or "origin/main"
    head_ref = os.getenv("GITHUB_SHA") or "HEAD"

    # Ensure we can diff against base (checkout@v4 defaults to depth=1)
    subprocess.run(["git", "fetch", "--depth=1", "origin", base_ref], check=False)

    files = _diff_names(base_ref, head_ref)
    if not files:
        print("No changed files; skipping tests-required check.")
        return 0

    changed_tests = any(f.startswith(TEST_DIRS) for f in files)
    changed_code = any(
        f.startswith(prefix.rstrip("/")) or f == prefix for f in files for prefix in CODE_PREFIXES
    )

    if changed_code and not changed_tests:
        print("Changed code without matching tests:", file=sys.stderr)
        for f in files:
            if not f.startswith(TEST_DIRS) and any(
                f.startswith(p.rstrip("/")) or f == p for p in CODE_PREFIXES
            ):
                print(f"  - {f}", file=sys.stderr)
        print("\nPlease add/update tests under tests/.", file=sys.stderr)
        return 1

    print("Tests check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
