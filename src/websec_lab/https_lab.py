"""Native loopback HTTPS lab: certificates, pinned Nginx and isolated browser.

No administrator rights or hosts-file edits are required. Browser-only DNS
mapping is scoped to a dedicated profile; TLS verification remains enabled.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import zipfile
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path

import requests
from flask import request
from werkzeug.serving import make_server

from websec_lab.browser import discover_browsers
from websec_lab.config import load_settings, repository_root
from websec_lab.extensions import db
from websec_lab.services import create_app
from websec_lab.victim.services import seed_lab_data

ROOT = repository_root()
RUNTIME = ROOT / ".websec-local"
CERTS = RUNTIME / "certs"
CA = CERTS / "root-ca.crt"
LEAF = CERTS / "lab.crt"
LEAF_KEY = CERTS / "lab.key"
HTTPS_CONFIG = ROOT / "config" / "lab.https.yaml"
STATE = RUNTIME / "https-state.json"
NGINX_VERSION = "1.30.6"
NGINX_SHA256 = "c6ee35edb0a861063323f709192ae50d1eefaf2ea7d00678bd2b22d8542dc61e"
NGINX_HOME = RUNTIME / f"nginx-{NGINX_VERSION}"
HOSTS = ("victim.test", "attacker.test", "same.victim.test", "partner.test", "audit.test")
RESOLVER_RULES = "MAP *.test 127.0.0.1, EXCLUDE localhost"
PORT = 8443
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


def command(args, **kwargs):
    try:
        return subprocess.run(
            args, check=True, capture_output=True, text=True, creationflags=NO_WINDOW, **kwargs
        )
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"Command failed: {args[0]}: {error.stderr.strip()}") from error


def openssl_path() -> str:
    candidates = [Path(sys.prefix) / "Library/bin/openssl.exe"]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("openssl")
    if not found:
        raise RuntimeError("OpenSSL not found in the active environment")
    return found


def setup(*, trust: bool = False) -> dict:
    CERTS.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        account = f"{os.environ['USERDOMAIN']}\\{os.environ['USERNAME']}"
        command(["icacls", str(CERTS), "/inheritance:r", "/grant:r", f"{account}:(OI)(CI)F"])
    nginx = NGINX_HOME / "nginx.exe"
    if os.name != "nt":
        if not shutil.which("nginx"):
            raise RuntimeError("Install nginx and openssl or use docker compose")
        (NGINX_HOME / "conf").mkdir(parents=True, exist_ok=True)
        (NGINX_HOME / "logs").mkdir(exist_ok=True)
        CERTS.chmod(0o700)
    elif not nginx.is_file():
        url = f"https://nginx.org/download/nginx-{NGINX_VERSION}.zip"
        response = requests.get(url, timeout=45)
        response.raise_for_status()
        if hashlib.sha256(response.content).hexdigest() != NGINX_SHA256:
            raise RuntimeError("Nginx archive SHA-256 does not match the pinned release")
        archive = RUNTIME / "nginx.zip"
        archive.write_bytes(response.content)
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.namelist():
                target = (RUNTIME / member).resolve()
                if not target.is_relative_to(RUNTIME.resolve()):
                    raise RuntimeError("Unsafe path in Nginx archive")
            bundle.extractall(RUNTIME)
    tool = openssl_path()
    conf = CERTS / "openssl.cnf"
    conf.write_text("[req]\ndistinguished_name=dn\n[dn]\n", encoding="ascii")
    if not CA.exists():
        command(
            [
                tool,
                "req",
                "-x509",
                "-newkey",
                "rsa:3072",
                "-noenc",
                "-sha256",
                "-days",
                "365",
                "-config",
                str(conf),
                "-subj",
                "/CN=WebSec Local Lab CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout",
                str(CERTS / "root-ca.key"),
                "-out",
                str(CA),
            ]
        )
    if not LEAF.exists():
        command(
            [
                tool,
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-noenc",
                "-sha256",
                "-config",
                str(conf),
                "-subj",
                "/CN=victim.test",
                "-addext",
                "subjectAltName=" + ",".join(f"DNS:{host}" for host in HOSTS),
                "-addext",
                "extendedKeyUsage=serverAuth",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-keyout",
                str(LEAF_KEY),
                "-out",
                str(CERTS / "lab.csr"),
            ]
        )
        command(
            [
                tool,
                "x509",
                "-req",
                "-in",
                str(CERTS / "lab.csr"),
                "-CA",
                str(CA),
                "-CAkey",
                str(CERTS / "root-ca.key"),
                "-CAcreateserial",
                "-days",
                "90",
                "-sha256",
                "-copy_extensions",
                "copy",
                "-out",
                str(LEAF),
            ]
        )
    command([tool, "verify", "-CAfile", str(CA), str(LEAF)])
    if trust:
        if os.name != "nt":
            nss = Path.home() / ".pki/nssdb"
            nss.mkdir(parents=True, exist_ok=True)
            if not (nss / "cert9.db").exists():
                command(["certutil", "-N", "--empty-password", "-d", f"sql:{nss}"])
            command(
                [
                    "certutil",
                    "-A",
                    "-d",
                    f"sql:{nss}",
                    "-n",
                    "WebSec Local Lab CA",
                    "-t",
                    "C,,",
                    "-i",
                    str(CA),
                ]
            )
        else:
            quoted_path = str(CA).replace("'", "''")
            command(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "$ErrorActionPreference='Stop'; "
                    "$labCertificate = "
                    "[System.Security.Cryptography.X509Certificates.X509Certificate2]"
                    f"::new('{quoted_path}'); "
                    "$labStore = [System.Security.Cryptography.X509Certificates.X509Store]"
                    "::new('Root', 'CurrentUser'); "
                    "$labStore.Open('ReadWrite'); "
                    "try { $labStore.Add($labCertificate) } finally { $labStore.Close() }",
                ]
            )
    info = {
        "nginx_version": (
            NGINX_VERSION
            if os.name == "nt"
            else command([nginx_executable(), "-v"]).stderr.strip().split("/")[-1]
        ),
        "archive_sha256": NGINX_SHA256 if os.name == "nt" else None,
        "hosts": HOSTS,
        "certificate": str(LEAF),
        "root_ca": str(CA),
        "root_sha256": hashlib.sha256(ssl.PEM_cert_to_DER_cert(CA.read_text())).hexdigest(),
        "root_thumbprint": hashlib.sha1(ssl.PEM_cert_to_DER_cert(CA.read_text()))
        .hexdigest()
        .upper(),
        "trust_scope": (
            ("CurrentUser Root" if os.name == "nt" else "current-user NSS")
            if trust
            else "not installed by this command"
        ),
    }
    (RUNTIME / "setup.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    return info


def nginx_configuration() -> str:
    services = load_settings(HTTPS_CONFIG).services
    blocks = []
    for name, service in services.items():
        names = service.public_origin.split("//", 1)[1].split(":", 1)[0]
        if name == "attacker":
            names += " same.victim.test"
        blocks.append(f"""
    server {{
        listen {os.getenv('WEBSEC_GATEWAY_BIND', '127.0.0.1')}:{PORT} ssl;
        server_name {names};
        ssl_certificate ../../certs/lab.crt;
        ssl_certificate_key ../../certs/lab.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        location /__lab/ {{ return 404; }}
        location / {{
            proxy_pass http://127.0.0.1:{service.port};
            proxy_set_header Host $http_host;
            proxy_set_header X-Forwarded-Host $http_host;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_redirect off;
        }}
    }}""")
    prefix = """worker_processes 1;
pid logs/websec.pid;
error_log logs/websec-error.log;
events { worker_connections 256; }
http {
    access_log logs/websec-access.log;
    client_body_temp_path logs/client-body;
    proxy_temp_path logs/proxy;
    fastcgi_temp_path logs/fastcgi;
    uwsgi_temp_path logs/uwsgi;
    scgi_temp_path logs/scgi;
    default_type application/octet-stream;
    server {
        listen 127.0.0.1:8443 ssl default_server;
        server_name _;
        ssl_certificate ../../certs/lab.crt;
        ssl_certificate_key ../../certs/lab.key;
        return 421;
    }
"""
    prefix = prefix.replace(
        "listen 127.0.0.1:8443", f"listen {os.getenv('WEBSEC_GATEWAY_BIND', '127.0.0.1')}:8443"
    )
    return prefix + "\n".join(blocks) + "\n}\n"


def https_get(
    host: str, path: str = "/healthz", request_host: str | None = None
) -> tuple[int, str]:
    """Connect to loopback with real DNS hostname/SNI and full CA verification."""
    context = ssl.create_default_context(cafile=str(CA))
    with (
        socket.create_connection(("127.0.0.1", PORT), timeout=5) as raw,
        context.wrap_socket(raw, server_hostname=host) as stream,
    ):
        stream.sendall(
            (
                f"GET {path} HTTP/1.1\r\nHost: {request_host or host}:{PORT}\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
        )
        chunks = []
        while data := stream.recv(65536):
            chunks.append(data)
    response = b"".join(chunks).decode("utf-8", errors="replace")
    return int(response.split(" ", 2)[1]), response


class HttpsLab:
    """Own exactly this lab's four backend servers and gateway process."""

    def __init__(self, profile: str = "https-samesite-lax", database_path: Path | None = None):
        self.profile = profile
        self.database_path = database_path
        self.stop_event = threading.Event()
        self.token = secrets.token_urlsafe(24)
        self._stack = ExitStack()
        self.apps = {}

    def __enter__(self):
        settings = load_settings(HTTPS_CONFIG)
        if self.database_path is not None:
            settings = replace(settings, database_path=self.database_path)
        for port in [PORT, *(s.port for s in settings.services.values())]:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", port))
        previous = os.environ.get("WEBSEC_DEFENSE_PROFILE")
        os.environ["WEBSEC_DEFENSE_PROFILE"] = self.profile
        try:
            for name in settings.services:
                app = create_app(name, settings)
                self.apps[name] = app
                if name == "victim":
                    with app.app_context():
                        db.create_all()
                        seed_lab_data()
                if name == "auditor":

                    @app.post("/__lab/shutdown")
                    def shutdown():
                        if not hmac.compare_digest(
                            request.headers.get("X-Lab-Token", ""), self.token
                        ):
                            return {"error": "forbidden"}, 403
                        self.stop_event.set()
                        return {"status": "stopping"}

                server = make_server("127.0.0.1", settings.service(name).port, app, threaded=True)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                self._stack.callback(server.server_close)
                self._stack.callback(server.shutdown)
            config = NGINX_HOME / "conf/websec.conf"
            config.write_text(nginx_configuration(), encoding="utf-8")
            executable = nginx_executable()
            command([executable, "-p", "./", "-c", "conf/websec.conf", "-t"], cwd=NGINX_HOME)
            self.gateway = subprocess.Popen(
                [executable, "-p", "./", "-c", "conf/websec.conf"],
                cwd=NGINX_HOME,
                creationflags=NO_WINDOW,
            )
            self._stack.callback(self._stop_nginx)
            deadline = time.monotonic() + 10
            while True:
                try:
                    if https_get("victim.test")[0] == 200:
                        break
                except (OSError, ValueError):
                    if time.monotonic() > deadline:
                        raise RuntimeError("HTTPS gateway did not become ready") from None
                    time.sleep(0.2)
            STATE.write_text(
                json.dumps(
                    {
                        "pid": os.getpid(),
                        "profile": self.profile,
                        "stop_token": self.token,
                        "port": PORT,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            return self
        except BaseException:
            self._stack.close()
            raise
        finally:
            if previous is None:
                os.environ.pop("WEBSEC_DEFENSE_PROFILE", None)
            else:
                os.environ["WEBSEC_DEFENSE_PROFILE"] = previous

    def _stop_nginx(self):
        command(
            [nginx_executable(), "-p", "./", "-c", "conf/websec.conf", "-s", "quit"],
            cwd=NGINX_HOME,
        )
        self.gateway.wait(timeout=10)

    def __exit__(self, *_args):
        self._stack.close()
        for app in self.apps.values():
            if "sqlalchemy" in app.extensions:
                with app.app_context():
                    db.session.remove()
                    db.engine.dispose()


def browser_arguments() -> list[str]:
    return [f"--host-resolver-rules={RESOLVER_RULES}", "--no-proxy-server"]


def nginx_executable() -> str:
    return str(NGINX_HOME / "nginx.exe") if os.name == "nt" else str(shutil.which("nginx"))


def listening_ports() -> list[int]:
    ports = [PORT, *(s.port for s in load_settings(HTTPS_CONFIG).services.values())]
    listening = []
    for port in ports:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                listening.append(port)
        except OSError:
            pass
    return listening


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["setup", "serve", "start", "stop", "status", "browser"])
    parser.add_argument("--trust", action="store_true")
    parser.add_argument("--profile", default="https-samesite-lax")
    parser.add_argument("--browser", choices=["chrome", "msedge"], default="chrome")
    args = parser.parse_args()
    RUNTIME.mkdir(exist_ok=True)
    if args.action == "setup":
        print(json.dumps(setup(trust=args.trust), indent=2))
    elif args.action == "serve":
        with HttpsLab(args.profile) as lab:
            signal.signal(signal.SIGTERM, lambda *_: lab.stop_event.set())
            signal.signal(signal.SIGINT, lambda *_: lab.stop_event.set())
            lab.stop_event.wait()
    elif args.action == "start":
        try:
            running = https_get("victim.test")[0] == 200
        except OSError:
            running = False
        if running:
            state = json.loads(STATE.read_text(encoding="utf-8"))
            if state["profile"] != args.profile:
                raise RuntimeError("A different profile is running; stop this lab before switching")
            print(f"HTTPS lab already ready; profile={state['profile']}; pid={state['pid']}")
            return 0
        output = (RUNTIME / "https-server.log").open("a", encoding="utf-8")
        child = subprocess.Popen(
            [sys.executable, "-m", "websec_lab.https_lab", "serve", "--profile", args.profile],
            cwd=ROOT,
            stdout=output,
            stderr=output,
            creationflags=NO_WINDOW,
        )
        output.close()
        deadline = time.monotonic() + 15
        while True:
            try:
                if https_get("victim.test")[0] == 200:
                    break
            except OSError:
                if child.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(
                        "Start failed; inspect .websec-local/https-server.log"
                    ) from None
                time.sleep(0.2)
        print(f"HTTPS lab ready on port {PORT}; profile={args.profile}; pid={child.pid}")
    elif args.action == "stop":
        if not listening_ports():
            print("This lab's HTTPS gateway and four backends are already stopped")
            return 0
        state = json.loads(STATE.read_text(encoding="utf-8"))
        session = requests.Session()
        session.trust_env = False
        response = session.post(
            "http://127.0.0.1:15400/__lab/shutdown",
            headers={"X-Lab-Token": state["stop_token"]},
            timeout=5,
        )
        response.raise_for_status()
        deadline = time.monotonic() + 15
        while True:
            listening = listening_ports()
            if not listening:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(f"Lab shutdown timed out; ports still listening: {listening}")
            time.sleep(0.2)
        print("This lab's HTTPS gateway and four backends have stopped")
    elif args.action == "status":
        for host in HOSTS:
            print(f"https://{host}:{PORT}: {https_get(host)[0]}")
    elif args.action == "browser":
        browser = next(b for b in discover_browsers() if b.channel == args.browser)
        profile = RUNTIME / "manual-browser" / args.browser
        preferences = profile / "Default/Preferences"
        if not preferences.exists():
            preferences.parent.mkdir(parents=True, exist_ok=True)
            preferences.write_text(
                json.dumps(
                    {
                        "profile": {
                            "cookie_controls_mode": 0,
                            "block_third_party_cookies": False,
                        }
                    }
                ),
                encoding="utf-8",
            )
        subprocess.Popen(
            [
                str(browser.executable_path),
                f"--user-data-dir={profile}",
                *browser_arguments(),
                f"https://victim.test:{PORT}/login",
                f"https://attacker.test:{PORT}/cookie-lab",
                f"https://same.victim.test:{PORT}/cookie-lab",
            ],
            creationflags=NO_WINDOW,
        )
        print("Opened the isolated HTTPS lab browser")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
