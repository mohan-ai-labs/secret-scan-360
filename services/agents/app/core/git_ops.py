import os, shutil, subprocess, tempfile, uuid


def shallow_clone(repo_url: str) -> str:
    work = os.path.join("/tmp", f"scan-{uuid.uuid4().hex[:8]}")
    os.makedirs(work, exist_ok=True)
    subprocess.check_call(
        ["git", "clone", "--depth", "1", repo_url, work],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return work


def cleanup(path: str):
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass
