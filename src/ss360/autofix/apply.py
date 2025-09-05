from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict

from .planner import PlanItem


def _gh_available() -> bool:
    return shutil.which("gh") is not None


def apply_plan(
    plan: List[PlanItem],
    *,
    repo_path: str | Path = ".",
    dry_run: bool = True,
    i_know_what_im_doing: bool = False,
    pr_title: str = "SS360: Secret remediation",
    pr_body: str = "",
) -> Dict[str, object]:
    repo_path = Path(repo_path)
    preview = {
        "plan_items": [p.__dict__ for p in plan],
        "note": "Replacements contain only template refs; no plaintext secrets.",
    }
    preview_path = repo_path / "ss360_autofix_plan.json"
    preview_path.write_text(json.dumps(preview, indent=2))

    if dry_run or not plan:
        return {"applied": False, "pr_url": None, "preview": str(preview_path)}

    if not i_know_what_im_doing:
        return {
            "applied": False,
            "error": "--i-know-what-im-doing required for apply",
            "preview": str(preview_path),
        }

    branch = "ss360/autofix-" + os.getenv("GITHUB_RUN_ID", "local")
    try:
        subprocess.check_call(["git", "checkout", "-b", branch], cwd=repo_path)
    except subprocess.CalledProcessError:
        subprocess.check_call(["git", "checkout", branch], cwd=repo_path)

    subprocess.check_call(["git", "add", str(preview_path)], cwd=repo_path)
    subprocess.check_call(
        ["git", "commit", "-m", "SS360: add autofix plan preview"], cwd=repo_path
    )
    subprocess.check_call(["git", "push", "-u", "origin", branch], cwd=repo_path)

    pr_url = None
    if _gh_available():
        body = pr_body or (
            "This PR includes an SS360-generated remediation plan.\n\n"
            "- [ ] Remove literals\n- [ ] Replace with secret refs\n- [ ] Rotate/revoke credentials\n"
        )
        out = subprocess.check_output(
            [
                "gh",
                "pr",
                "create",
                "--title",
                pr_title,
                "--body",
                body,
                "--head",
                branch,
            ],
            cwd=repo_path,
            text=True,
        ).strip()
        pr_url = out

    return {"applied": True, "pr_url": pr_url, "preview": str(preview_path)}
