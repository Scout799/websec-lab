"""Start all four lab services and wait until they answer their health checks.

Works on Windows and macOS/Linux:

    python start.py demo              # all services, one console window each on Windows
    python start.py demo --no-window  # keep everything in the current terminal
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

SERVICES = ("victim", "attacker", "partner", "auditor")
STARTUP_TIMEOUT = 40.0


def _health(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError):
        return False


def _port_busy(port: int) -> bool:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Start every WebSec lab service")
    parser.add_argument(
        "--no-window", action="store_true", help="run in this terminal instead of new windows"
    )
    parser.add_argument(
        "--defense", default="", help="defense profile for the victim, e.g. xfo-deny"
    )
    args = parser.parse_args(argv)

    from websec_lab.config import load_settings

    settings = load_settings()
    services = [(name, settings.service(name).port) for name in SERVICES]

    # Database first: the victim refuses to serve without its schema.
    subprocess.run(
        [sys.executable, str(ROOT / "start.py"), "db", "upgrade"], cwd=str(ROOT), check=False
    )

    started: list[tuple[str, int]] = []
    for name, port in services:
        if _port_busy(port):
            print(f"[skip] {name}: port {port} already in use")
            continue
        command = [sys.executable, str(ROOT / "start.py"), "run", name]
        child_env = None
        if name == "victim" and args.defense:
            import os

            child_env = dict(os.environ, WEBSEC_DEFENSE_PROFILE=args.defense)
        if args.no_window or sys.platform != "win32":
            subprocess.Popen(command, cwd=str(ROOT), env=child_env)
        else:
            subprocess.Popen(
                command, cwd=str(ROOT), env=child_env, creationflags=subprocess.CREATE_NEW_CONSOLE
            )
        suffix = f" (defense={args.defense})" if child_env else ""
        print(f"[start] {name} -> http://127.0.0.1:{port}{suffix}")
        started.append((name, port))

    if not started:
        print("nothing to start; all ports are busy. Open the URLs below.")
        _print_urls(services)
        return 0

    print("\nwaiting for health checks ...")
    deadline = time.time() + STARTUP_TIMEOUT
    pending = list(started)
    while pending and time.time() < deadline:
        pending = [(name, port) for name, port in pending if not _health(port)]
        if pending:
            time.sleep(0.6)

    for name, port in pending:
        print(f"[fail] {name} did not answer on http://127.0.0.1:{port}/healthz")
    _print_urls(services)
    return 0 if not pending else 1


def _print_urls(services: list[tuple[str, int]]) -> None:
    print("\n入口：")
    print("  victim    http://127.0.0.1:{}/".format(dict(services)["victim"]))
    print("  attacker  http://127.0.0.1:{}/demo/classic".format(dict(services)["attacker"]))
    print("  partner   http://127.0.0.1:{}/wallet".format(dict(services)["partner"]))
    print("  auditor   http://127.0.0.1:{}/audit".format(dict(services)["auditor"]))
    print("\n测试账号：alice / alice-lab")


if __name__ == "__main__":
    raise SystemExit(main())
