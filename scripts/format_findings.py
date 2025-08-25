from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List


def load_findings(path: str | Path) -> Dict:
    with open(path, "r") as f:
        return json.load(f)


def to_markdown(findings: List[Dict]) -> str:
    if not findings:
        return "### Secret Scan\n\nNo findings 🎉"

    lines = [
        "### Secret Scan Findings",
        "",
        "| Kind | Path | Snippet |",
        "|---|---|---|",
    ]
    for f in findings[:200]:
        kind = f.get("kind", "?")
        path = f.get("path", "?")
        snippet = (f.get("match", "") or "").replace("\n", " ")[:120]
        lines.append(f"| {kind} | {path} | `{snippet}` |")
    return "\n".join(lines)


def main() -> None:
    src = Path("findings.json")
    out = Path("findings.md")
    data = load_findings(src)
    md = to_markdown(data.get("findings", []))
    out.write_text(md, encoding="utf-8")
    print(f"[format-findings] wrote {out} ({len(md)} bytes)")


if __name__ == "__main__":
    main()
