import os

IGNORE_DIRS = {
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "target",
    ".next",
    ".vercel",
    "coverage",
}
IGNORE_FILE_EXT = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".mp3",
    ".mp4",
    ".mov",
    ".webm",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".dll",
    ".so",
}


def should_skip(path: str) -> bool:
    parts = path.split(os.sep)
    if any(p in IGNORE_DIRS for p in parts):
        return True
    ext = os.path.splitext(path)[1].lower()
    if ext in IGNORE_FILE_EXT:
        return True
    # ignore fixtures/examples by default
    lowered = path.lower()
    if "test-fixtures" in lowered or "fixtures" in lowered or "examples" in lowered:
        return True
    return False
