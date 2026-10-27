"""Repository discovery: walk the tree, detect languages, find dependency manifests."""
import os
from pathlib import Path

from .models import RepoInfo, SourceFile

LANGUAGES = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript", ".java": "java",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".php": "php",
    ".go": "go", ".rb": "ruby", ".kt": "kotlin", ".rs": "rust", ".cs": "csharp",
}
# Scanned for secrets only
CONFIG_EXTS = {".env", ".yml", ".yaml", ".json", ".ini", ".cfg", ".conf", ".toml",
               ".properties", ".xml", ".sh", ".ps1", ".tf"}
CONFIG_NAMES = {".env", "dockerfile", ".npmrc", ".pypirc"}
MANIFESTS = {"requirements.txt", "pyproject.toml", "pipfile", "setup.py", "package.json",
             "pom.xml", "build.gradle", "go.mod", "cargo.toml", "composer.json", "gemfile"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
             ".next", ".idea", ".vscode", "target", "vendor", ".mypy_cache", ".pytest_cache",
             "coverage", ".tox", "site-packages"}
MAX_BYTES = 1_000_000


def discover(root):
    root = Path(root).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path not found: {root}")
    info = RepoInfo(root=str(root))
    paths = [root] if root.is_file() else _walk(root)
    base = root.parent if root.is_file() else root
    for p in paths:
        name = p.name.lower()
        ext = p.suffix.lower()
        if name in MANIFESTS:
            info.dependencies.append(p.relative_to(base).as_posix())
        lang = LANGUAGES.get(ext)
        if lang is None and (ext in CONFIG_EXTS or name in CONFIG_NAMES or name.startswith(".env")):
            lang = "config"
        if lang is None:
            continue
        try:
            if p.stat().st_size > MAX_BYTES or _is_binary(p):
                info.skipped += 1
                continue
            loc = sum(1 for line in p.open(encoding="utf-8", errors="ignore") if line.strip())
        except OSError:
            info.skipped += 1
            continue
        info.files.append(SourceFile(str(p), p.relative_to(base).as_posix(), lang, loc))
        info.languages[lang] = info.languages.get(lang, 0) + 1
        info.total_loc += loc
    return info


def _walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        for f in filenames:
            yield Path(dirpath) / f


def _is_binary(p):
    with p.open("rb") as fh:
        return b"\0" in fh.read(4096)
