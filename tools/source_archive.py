"""Make a source-only build context, excluding runtime keys, browsers and user files."""

import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def source_files():
    names = [
        "pyproject.toml",
        "requirements.lock",
        "environment.yml",
        "README.md",
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
        "CONTRIBUTING.md",
        "PROJECT_TASKS.md",
        "Dockerfile",
        "compose.yaml",
        ".dockerignore",
        ".gitignore",
        ".pre-commit-config.yaml",
        ".env.example",
    ]
    files = [ROOT / name for name in names]
    for folder in ("config", "migrations", "scripts", "src", "tests", "docs", "tools", ".github"):
        files.extend(
            path
            for path in (ROOT / folder).rglob("*")
            if path.is_file()
            and not any(p == "__pycache__" or p.endswith(".egg-info") for p in path.parts)
        )
    return sorted(files)


def main():
    output = ROOT / ".websec-local/linux-verification/context.tgz"
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w:gz") as archive:
        for file in source_files():
            archive.add(file, arcname=file.relative_to(ROOT).as_posix())
    print(output, output.stat().st_size)


if __name__ == "__main__":
    main()
