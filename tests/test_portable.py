"""Tests for the zero-install launcher (start.py) and the portable packer."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_start_py_help_runs_without_install() -> None:
    """A teammate unzips the folder and runs `python start.py ...`."""

    result = subprocess.run(
        [sys.executable, str(ROOT / "start.py"), "--help"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    assert "websec-lab" in result.stdout


def test_start_py_config_matches_cli() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "start.py"), "config"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    assert "WebSec Clickjacking Lab" in result.stdout


def test_portable_packer_skips_heavy_directories() -> None:
    from tools.make_portable import EXCLUDE_DIR_NAMES, INCLUDE_DIRS

    assert ".websec-local" not in INCLUDE_DIRS
    assert "artifacts" not in INCLUDE_DIRS
    assert "__pycache__" in EXCLUDE_DIR_NAMES
