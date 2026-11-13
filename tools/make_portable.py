"""Build a portable zip: source only, no venv, no artifacts, no 11 GB lab cache.

    python tools/make_portable.py
    -> dist/websec-lab-portable-<date>.zip

A teammate unzips it, runs `python start.py setup` once, then `python start.py demo`.
"""

from __future__ import annotations

import hashlib
import zipfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

# Ship these (paths relative to the project root).
INCLUDE_FILES = [
    "start.py",
    "pyproject.toml",
    "requirements.txt",
    "README.md",
    "README_快速开始.md",
    "LICENSE",
    "CONTRIBUTING.md",
    "THIRD_PARTY_NOTICES.md",
    ".env.example",
    ".gitignore",
    "Dockerfile",
    "compose.yaml",
]
INCLUDE_DIRS = [
    "src",
    "scripts",
    "config",
    "docs",
    "migrations",
    "tests",
    "tools",
]

# Never ship these, even inside an included directory.
EXCLUDE_DIR_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".venv",
    "node_modules",
    ".git",
}
EXCLUDE_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".zip",
    ".sqlite3",
    ".db",
    ".log",
    ".webm",
    ".mp4",
    ".png",
    ".pdf",
    ".pptx",
    ".docx",
}
EXCLUDE_NAMES = {".coverage", "nul"}


def _iter_files() -> list[Path]:
    files: list[Path] = []
    for name in INCLUDE_FILES:
        path = ROOT / name
        if path.is_file():
            files.append(path)
    for directory in INCLUDE_DIRS:
        base = ROOT / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            parts = set(path.relative_to(ROOT).parts[:-1])
            if parts & EXCLUDE_DIR_NAMES:
                continue
            if path.suffix.lower() in EXCLUDE_SUFFIXES:
                continue
            if path.name in EXCLUDE_NAMES:
                continue
            files.append(path)
    return files


def main() -> int:
    DIST.mkdir(exist_ok=True)
    target = DIST / f"websec-lab-portable-{date.today():%Y%m%d}.zip"
    files = _iter_files()
    total = 0
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            arcname = Path("websec-lab") / path.relative_to(ROOT)
            archive.write(path, arcname.as_posix())
            total += path.stat().st_size
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    print(f"files : {len(files)}")
    print(f"source: {total / 1024 / 1024:.2f} MB")
    print(f"zip   : {target} ({target.stat().st_size / 1024 / 1024:.2f} MB)")
    print(f"sha256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
