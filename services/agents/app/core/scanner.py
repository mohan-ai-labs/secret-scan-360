import os
from typing import List, Dict, Any
from .utils import should_skip
from ..detectors.registry import load_detectors
from ..detectors.base import Finding
from .llm import can_use_llm, verify_with_llm_snippet


def scan_tree(root_dir: str) -> Dict[str, Any]:
    detectors = load_detectors()
    findings: List[Finding] = []
    for base, dirs, files in os.walk(root_dir):
        # prune ignored dirs
        dirs[:] = [d for d in dirs if not should_skip(os.path.join(base, d))]
        for fn in files:
            path = os.path.join(base, fn)
            rel = os.path.relpath(path, root_dir)
            if should_skip(rel):
                continue
            try:
                # only text-ish
                with open(path, "rb") as f:
                    data = f.read(2_000_000)  # cap at 2MB
                try:
                    text = data.decode("utf-8", errors="ignore")
                except Exception:
                    continue
            except Exception:
                continue
            for det in detectors:
                for f in det.scan_file(rel, text):
                    findings.append(f)

    # dedupe by (path, kind, match, line)
    uniq = {}
    for f in findings:
        key = (f.path, f.kind, f.match, f.line)
        if key not in uniq:
            uniq[key] = f
    findings = list(uniq.values())

    # optional verification
    if can_use_llm():
        for f in findings:
            ok, reason = verify_with_llm_snippet(f.kind, f.match)
            f.is_secret = ok
            f.reason = reason
    else:
        # fallback: mark known strong patterns true
        for f in findings:
            if f.kind in {
                "Private Key",
                "AWS Access Key",
                "AWS Secret Key",
                "GitHub Token",
            }:
                f.is_secret = True
                f.reason = "Pattern-based verification (no LLM)"
    true_hits = sum(1 for f in findings if f.is_secret)
    # serialize
    return {
        "findings": [
            dict(
                path=f.path,
                kind=f.kind,
                match=f.match,
                line=f.line,
                is_secret=f.is_secret,
                reason=f.reason,
            )
            for f in findings
        ],
        "true_hits": true_hits,
    }
