from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Dict, Optional

# Registry lives here
from services.agents.app.detectors.registry import DetectorRegistry


# Basic file helpers
TEXT_EXTS = {
    ".txt",
    ".md",
    ".yaml",
    ".yml",
    ".json",
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".sh",
    ".bash",
    ".zsh",
    ".conf",
    ".sql",
    ".go",
    ".rs",
    ".java",
    ".gradle",
    ".kt",
    ".kts",
    ".cs",
    ".cpp",
    ".hpp",
    ".c",
    ".h",
    ".m",
    ".mm",
    ".rb",
    ".php",
    ".pl",
    ".r",
    ".jl",
}

BINARY_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".tgz",
    ".7z",
    ".xz",
    ".dmg",
    ".exe",
    ".dll",
    ".so",
    ".a",
    ".o",
}


def _likely_text_path(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in TEXT_EXTS:
        return True
    if suffix in BINARY_EXTS:
        return False
    # Default: treat unknown as text (we still protect with max_bytes + decode)
    return True


def _read_text_safely(path: Path, max_bytes: int = 1_000_000) -> Optional[str]:
    """
    Read small files safely as text. Returns None on obvious binary or oversized file.
    """
    try:
        if not path.is_file():
            return None
        if path.stat().st_size > max_bytes:
            return None
        if not _likely_text_path(path):
            return None

        data = path.read_bytes()
        # Heuristic: if many NUL bytes, treat as binary
        if data.count(b"\x00") > 0:
            return None
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return None


@dataclass
class Scanner:
    """
    Scanner orchestrates running all registered detectors against
    a set of files and returns consolidated findings.
    """

    registry: DetectorRegistry

    def iter_files(
        self,
        roots: Iterable[Path | str],
        include_globs: Optional[List[str]] = None,
        exclude_globs: Optional[List[str]] = None,
    ) -> Iterable[Path]:
        include_globs = include_globs or ["**/*"]
        exclude_globs = exclude_globs or [
            "**/.git/**",
            "**/.venv/**",
            "**/node_modules/**",
            "**/dist/**",
            "**/build/**",
            "**/.pytest_cache/**",
            "**/__pycache__/**",
        ]

        def matches_any(p: Path, patterns: List[str]) -> bool:
            str(p)
            return any(
                Path().glob(pattern) and p.match(pattern) for pattern in patterns
            )  # fallback glob+match

        for root in roots:
            root_path = Path(root).resolve()
            if root_path.is_file():
                # Yield the single file if not excluded
                skip = any(root_path.match(pat) for pat in exclude_globs)
                if not skip:
                    yield root_path
                continue

            for path in root_path.rglob("*"):
                if not path.is_file():
                    continue
                if any(path.match(pat) for pat in exclude_globs):
                    continue
                if include_globs and not any(path.match(pat) for pat in include_globs):
                    continue
                yield path

    def scan_paths(
        self,
        paths: Iterable[Path | str],
        max_bytes: int = 1_000_000,
    ) -> List[Dict]:
        findings: List[Dict] = []
        for p in self.iter_files(paths):
            text = _read_text_safely(p, max_bytes=max_bytes)
            if text is None:
                continue
            for f in self.registry.detect(str(p), text):
                # Normalize minimal shape
                fnorm = {
                    "path": f.get("path") or str(p),
                    "kind": f.get("kind") or "Unknown",
                    "match": f.get("match") or "",
                    "line": f.get("line", None),
                    "is_secret": bool(f.get("is_secret", False)),
                    "reason": f.get("reason", ""),
                }
                findings.append(fnorm)
        return findings

    @classmethod
    def from_config(cls, yaml_path: str | Path) -> "Scanner":
        reg = DetectorRegistry.load_from_yaml(str(yaml_path))
        return cls(registry=reg)
