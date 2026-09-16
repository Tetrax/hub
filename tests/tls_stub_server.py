"""Serveur HTTPS minimal pour les tests du backend « local ».

Il reproduit le comportement utile du serveur réel (gunicorn) : il sert HTTPS avec
une paire lue sur disque, écrit son PID, et sur `SIGHUP` il reprend la paire
courante (nouvelle poignée de main → nouveau certificat présenté).

Usage (interne aux tests) :

    python tests/tls_stub_server.py --cert <pem> --key <pem> --port 0 --pidfile <path>
"""

from __future__ import annotations

import argparse
import http.server
import os
import signal
import ssl
import sys
import threading
from pathlib import Path


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 — interface http.server
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args, **kwargs) -> None:  # silence
        return


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--pidfile", default="")
    parser.add_argument(
        "--ignore-hup",
        action="store_true",
        help="ne recharge pas la paire sur SIGHUP (pour tester le rollback)",
    )
    args = parser.parse_args(argv)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)

    def reload_pair(*_):
        if args.ignore_hup:
            return
        try:
            context.load_cert_chain(args.cert, args.key)
        except (OSError, ssl.SSLError):
            pass

    signal.signal(signal.SIGHUP, reload_pair)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    port = server.socket.getsockname()[1]
    if args.pidfile:
        Path(args.pidfile).write_text(f"{os.getpid()}\n", encoding="ascii")
    print(f"ready {port}", flush=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
