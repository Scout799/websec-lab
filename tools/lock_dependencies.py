"""Freeze the installed project dependency closure, without machine-specific editable paths."""

import tomllib
from importlib.metadata import distribution
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]


def main():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    roots = data["project"]["dependencies"] + data["build-system"]["requires"]
    for extra in ("dev", "report"):
        roots += data["project"]["optional-dependencies"][extra]
    pending = [Requirement(value) for value in roots]
    seen = set()
    versions = {}
    while pending:
        request = pending.pop()
        key = (canonicalize_name(request.name), tuple(sorted(request.extras)))
        if key in seen:
            continue
        seen.add(key)
        package = distribution(request.name)
        versions[canonicalize_name(package.metadata["Name"])] = package.version
        for value in package.requires or []:
            child = Requirement(value)
            if child.marker is None or any(
                child.marker.evaluate({"extra": extra}) for extra in {"", *request.extras}
            ):
                pending.append(child)
    lines = [
        "# Python 3.12: runtime + dev + report; generated from the verified Websec environment.",
        "# Install the project separately: python -m pip install --no-deps -e .",
    ]
    lines += [f"{name}=={versions[name]}" for name in sorted(versions)]
    (ROOT / "requirements.lock").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Locked {len(versions)} distributions")


if __name__ == "__main__":
    main()
