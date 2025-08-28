#!/usr/bin/env python3
import os, subprocess, sys, shlex

def changed(base_ref: str) -> list[str]:
    # Compare PR head against fetched base
    cmd = f"git diff --name-only origin/{base_ref}...HEAD"
    out = subprocess.check_output(shlex.split(cmd), text=True)
    return [l.strip() for l in out.splitlines() if l.strip()]

def main():
    base = sys.argv[1] if len(sys.argv) > 1 else ""
    if not base:
        print("No base ref; skipping.")
        return
    files = changed(base)
    src_changed    = any(p.startswith("src/")    for p in files)
    tests_changed  = any(p.startswith("tests/")  for p in files)
    if src_changed and not tests_changed:
        print("ERROR: src/ changed but no tests/ changed; please add/modify tests.")
        sys.exit(1)
    print("Guardrail OK.")
if __name__ == "__main__":
    main()
