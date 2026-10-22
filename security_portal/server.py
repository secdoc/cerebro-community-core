from __future__ import annotations

import argparse
import json
import logging
import mimetypes
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from .config import load_config
from .connectors import collect_integration
from .model import SCHEMA_VERSION, aggregate_overview, data_contract


LOG = logging.getLogger("security_portal")


def build_payload(config: dict, now: datetime | None = None) -> dict[str, Any]:
    integrations = [collect_integration(spec, now=now) for spec in config["integrations"]]
    return {
        "schema_version": SCHEMA_VERSION,
        "data_contract": data_contract(),
        "portal": {
            "title": config["portal"]["title"],
            "refresh_seconds": config["portal"].get("refresh_seconds", 60),
            "classification": config["portal"].get("classification", "Internal"),
        },
        "overview": aggregate_overview(integrations, generated_at=now),
        "integrations": integrations,
    }


class PortalServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], *, config: dict, static_root: Path):
        self.config = config
        self.static_root = static_root.resolve()
        super().__init__(address, PortalHandler)


class PortalHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        LOG.info("request client=%s message=%s", self.client_address[0], format % args)

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        super().end_headers()

    def _json(self, status: HTTPStatus, value: dict) -> None:
        body = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, name: str) -> None:
        portal_server = cast(PortalServer, self.server)
        path = (portal_server.static_root / name).resolve()
        if not path.is_relative_to(portal_server.static_root) or not path.is_file():
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        body = path.read_bytes()
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8" if content_type.startswith(("text/", "application/javascript")) else content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._json(HTTPStatus.OK, {"status": "ok"})
        elif path == "/readyz":
            self._json(HTTPStatus.OK, {"status": "ready"})
        elif path in {"/api/v1/overview", "/api/v1/integrations"}:
            try:
                portal_server = cast(PortalServer, self.server)
                self._json(HTTPStatus.OK, build_payload(portal_server.config))
            except Exception:
                LOG.exception("portal collection failed")
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "collection_failed"})
        elif path in {"/", "/index.html"}:
            self._file("index.html")
        elif path in {"/app.js", "/styles.css"}:
            self._file(path.removeprefix("/"))

        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def _method_not_allowed(self) -> None:
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
        self.send_header("Allow", "GET")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = _method_not_allowed
    do_PUT = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_DELETE = _method_not_allowed


def main() -> None:
    parser = argparse.ArgumentParser(description="Cerebro read-only security visibility")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if args.bind not in {'127.0.0.1', 'localhost'}:
        parser.error('only loopback binding is permitted')
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    config = load_config(args.config)
    static_root = Path(__file__).resolve().parent / "static"
    server = PortalServer((args.bind, args.port), config=config, static_root=static_root)
    LOG.info("portal listening bind=%s port=%s", args.bind, server.server_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
