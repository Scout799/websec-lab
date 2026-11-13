"""Small verified-TLS health check, without importing the application stack."""

import socket
import ssl
from pathlib import Path


def main():
    ca = Path(__file__).resolve().parents[1] / ".websec-local/certs/root-ca.crt"
    context = ssl.create_default_context(cafile=str(ca))
    with (
        socket.create_connection(("127.0.0.1", 8443), timeout=8) as connection,
        context.wrap_socket(connection, server_hostname="victim.test") as tls,
    ):
        tls.sendall(b"GET /healthz HTTP/1.1\r\nHost: victim.test:8443\r\nConnection: close\r\n\r\n")
        response = tls.recv(256)
        if not response.startswith(b"HTTP/1.1 200 "):
            raise RuntimeError(f"Gateway health check failed: {response[:60]!r}")


if __name__ == "__main__":
    main()
