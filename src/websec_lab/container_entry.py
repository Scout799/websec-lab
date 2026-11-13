"""Container PID entrypoint: provision this container's CA, then serve."""

import os
import sys

from websec_lab.https_lab import setup


def main():
    setup(trust=True)
    os.execv(
        sys.executable,
        [
            sys.executable,
            "-m",
            "websec_lab.https_lab",
            "serve",
            "--profile",
            os.getenv("WEBSEC_DEFENSE_PROFILE", "https-partner-allowlist"),
        ],
    )


if __name__ == "__main__":
    main()
