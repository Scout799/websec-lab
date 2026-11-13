"""Zero-install launcher for the WebSec clickjacking lab.

The published ``websec-lab`` command only exists after ``pip install .``.
This entry point works straight from a checkout or an unzipped folder, so a
teammate can run everything with only Python installed::

    python start.py doctor
    python start.py db upgrade
    python start.py run victim
    python start.py demo          # start all four services and wait

It puts ``src/`` on ``sys.path`` first, which is exactly what the installed
package would do, so imports, templates and static files resolve the same way.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _setup() -> int:
    """Install runtime dependencies (and optionally the browser) for this machine."""

    requirements = ROOT / "requirements.txt"
    if not requirements.is_file():
        print("requirements.txt is missing next to start.py", file=sys.stderr)
        return 1
    print(f"[setup] python: {sys.executable}")
    print(f"[setup] installing {requirements.name} ...")
    install = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(requirements)],
        cwd=str(ROOT),
    )
    if install.returncode != 0:
        print("[setup] 依赖安装失败，请检查网络或改用国内镜像：", file=sys.stderr)
        print(
            "        python -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple",
            file=sys.stderr,
        )
        return install.returncode
    print("[setup] 依赖安装完成。")
    print(
        "[setup] 动态审计需要浏览器，可选执行：python -m playwright install chromium\n"
        "        已有 Chrome / Edge 的机器可以跳过（会自动发现系统浏览器）。"
    )
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        argv = ["--help"]

    if argv[0] == "setup":
        return _setup()

    if argv[0] == "demo":
        launcher = ROOT / "scripts" / "start_all.py"
        return subprocess.call([sys.executable, str(launcher), *argv[1:]], cwd=str(ROOT))

    from websec_lab.cli import main as cli_main

    return cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
