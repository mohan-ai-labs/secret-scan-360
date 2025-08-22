import os, subprocess, requests, json, datetime


def sh(cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(
            f"cmd failed: {cmd}\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"
        )
    return r.stdout.strip()


def ensure_branch(repo_dir: str, branch: str):
    sh("git fetch origin", repo_dir)
    sh(f"git checkout -B {branch}", repo_dir)


def commit_push_as_user(repo_dir: str, branch: str, message: str):
    name = os.getenv(
        "GIT_AUTHOR_NAME", os.getenv("GIT_COMMITTER_NAME", "Mohan Krishna Alavala")
    )
    email = os.getenv(
        "GIT_AUTHOR_EMAIL", os.getenv("GIT_COMMITTER_EMAIL", "you@example.com")
    )
    sh("git add -A", repo_dir)
    sh(
        f'git -c user.name="{name}" -c user.email="{email}" commit -m "{message}" || true',
        repo_dir,
    )
    sh(f"git push -u origin {branch}", repo_dir)


def call_api_scan(api_base: str, repo_url: str, token: str | None = None, timeout=1800):
    headers = {"content-type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.post(
        f"{api_base}/scan",
        headers=headers,
        json={"repo_url": repo_url},
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json()


def write_report(repo_dir: str, result: dict):
    reports_dir = os.path.join(repo_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    json_path = os.path.join(reports_dir, f"scan-{ts}.json")
    md_path = os.path.join(reports_dir, f"scan-{ts}.md")

    # Save JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    # Save a short Markdown summary
    true_hits = result.get(
        "true_hits", sum(1 for f in result.get("findings", []) if f.get("is_secret"))
    )
    total = len(result.get("findings", []))
    scan_id = result.get("scan_id", "N/A")
    lines = [
        f"# SS360 Scan Report",
        f"- **Repo**: {result.get('repo')}",
        f"- **Scan ID**: {scan_id}",
        f"- **True hits**: {true_hits} / **Total findings**: {total}",
        "",
        "## Top findings (first 10)",
    ]
    for f in result.get("findings", [])[:10]:
        lines.append(
            f"- `{f.get('path')}` — **{f.get('kind')}** — secret={f.get('is_secret')} — {f.get('reason','')[:120]}"
        )
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return json_path, md_path
