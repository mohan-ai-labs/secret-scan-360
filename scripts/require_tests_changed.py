#!/usr/bin/env python3
"""Fail CI when src/ changes but tests/ do not."""
from __future__ import annotations

import shlex
import subprocess
import sys
from typing import List

def _changed_files(base_ref: str) -> list[str]:
    cmd = f"git diff --name-only origin/{base_ref}...HEAD"
    out = subprocess.check_output(shlex.split(cmd), text=True)
    return [line.strip() for line in out.splitlines() if line.strip()]

def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv
    base = argv[1] if len(argv) > 1 else ""
    if not base:
        print("No base ref; skipping guardrail.")
        return 0
    files = _changed_files(base)
    src_changed   = any(p.startswith("src/")   for p in files)
    tests_changed = any(p.startswith("tests/") for p in files)
    if src_changed and not tests_changed:
        print("ERROR: src/ changed but no tests/ changed; please add or modify tests.")
        return 1
    print("Guardrail OK.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
