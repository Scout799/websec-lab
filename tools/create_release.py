"""Build a complete, hash-checked course handoff without local runtime secrets."""

from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from pathlib import Path

from source_archive import source_files

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "deliverables"
DATASETS = [
    "artifacts/final-matrix-v2",
    "artifacts/final-frame-busting-recheck",
    "artifacts/final-controls",
    "artifacts/final-origin-controls",
    "artifacts/final-results",
    "artifacts/samesite-https",
    "artifacts/finalization",
]


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def main():
    acceptance = json.loads((ROOT / "artifacts/finalization/acceptance.json").read_text())
    assert acceptance["passed"]
    files = set(source_files())
    for name in DATASETS:
        files.update(p for p in (ROOT / name).rglob("*") if p.is_file())
    files.update(p for p in OUT.rglob("*") if p.is_file())
    # Retain original evidence while excluding captured login storage and
    # redundant raw video takes. The MP4 and per-chapter checks are included.
    files = {
        p
        for p in files
        if p.suffix.lower() not in {".key", ".webm", ".pyc"}
        and p.name
        not in {
            "storage_state.json",
            "storage-state.json",
            "concat.txt",
            "FILE_MANIFEST.json",
            "SHA256SUMS.txt",
            "release-build.log",
        }
        and "发布" not in p.relative_to(ROOT).parts
        and ".websec-local" not in p.relative_to(ROOT).parts
        and "__pycache__" not in p.relative_to(ROOT).parts
    }
    for path in files:
        assert path.resolve().is_relative_to(ROOT.resolve())
    records = [
        {"path": p.relative_to(ROOT).as_posix(), "bytes": p.stat().st_size, "sha256": digest(p)}
        for p in sorted(files)
    ]
    manifest = OUT / "FILE_MANIFEST.json"
    manifest.write_text(
        json.dumps(
            dict(
                version="1.0.0", files=len(records), manifest_excludes_itself=True, entries=records
            ),
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    sums = OUT / "SHA256SUMS.txt"
    sums.write_text(
        "\n".join(f"{r['sha256']}  {r['path']}" for r in records) + "\n", encoding="utf-8"
    )
    stage = ROOT / ".websec-local/release-stage"
    stage.mkdir(parents=True, exist_ok=True)
    candidate = stage / "WebSec-1.0.0.zip"
    with zipfile.ZipFile(
        candidate, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
    ) as package:
        for path in sorted(files | {manifest, sums}):
            package.write(path, path.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(candidate) as package:
        assert package.testzip() is None
        assert len(package.namelist()) == len(records) + 2
        for record in records:
            assert hashlib.sha256(package.read(record["path"])).hexdigest() == record["sha256"]
        assert not any(".websec-local" in n or n.endswith(".key") for n in package.namelist())
    target = OUT / "发布/WebSec-1.0.0.zip"
    target.parent.mkdir(exist_ok=True)
    if target.exists():
        raise FileExistsError(
            "Use a new release filename instead of overwriting a published package"
        )
    shutil.copy2(candidate, target)
    sha256 = digest(target)
    target.with_suffix(".zip.sha256").write_text(f"{sha256}  {target.name}\n", encoding="ascii")
    result = dict(
        passed=True,
        files=len(records) + 2,
        bytes=target.stat().st_size,
        sha256=sha256,
        crc_verified=True,
        every_payload_hash_verified=True,
        excluded="private runtime, CA keys, browser profiles, raw video takes, login storage",
    )
    # This receipt is external to the immutable package and hashes its final bytes.
    (target.parent / "release-verification.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
