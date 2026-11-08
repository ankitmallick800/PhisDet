"""Local page for pasting an email.

The page binds to localhost. It does not open links from the message.
Domain age, VirusTotal, and urlscan are asked only about hosts found in
that message, and only for reports that already exist.
"""

from __future__ import annotations

import json
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from phishdet.cli import SAMPLES
from phishdet.intel import investigate, local_view, service_status

_STATIC = Path(__file__).resolve().parent / "static" / "index.html"
_SAMPLES = Path(__file__).resolve().parent / "samples"


def make_server(host: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


def serve(host: str, port: int) -> None:
    httpd = make_server(host, port)
    url = f"http://{host}:{httpd.server_address[1]}/"
    print(f"Phishdet is running at {url}")
    print("Domain age uses RDAP. VirusTotal and urlscan run when you check a message.")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()


class Handler(BaseHTTPRequestHandler):
    server_version = "phishdet"

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in {"/", "/index.html"}:
            self._bytes(200, "text/html; charset=utf-8", _STATIC.read_bytes())
            return
        if path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/config.js":
            body = b'window.PHISHDET_API = "";\n'
            self._bytes(200, "text/javascript; charset=utf-8", body)
            return
        if path == "/api/health":
            self._json(200, _health())
            return
        if path.startswith("/api/sample/"):
            key = path.removeprefix("/api/sample/")
            filename = SAMPLES.get(key)
            if filename is None:
                self._json(404, {"error": "Unknown sample."})
                return
            file_path = _SAMPLES / filename
            if not file_path.exists():
                self._json(404, {"error": "Sample file is missing."})
                return
            self._bytes(200, "text/plain; charset=utf-8", file_path.read_bytes())
            return
        self._json(404, {"error": "Not found."})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path not in {"/api/detect", "/api/intel"}:
            self._json(404, {"error": "Not found."})
            return
        email, error = self._read_email()
        if error is not None:
            self._json(error[0], {"error": error[1]})
            return
        try:
            payload = investigate(email) if path == "/api/intel" else local_view(email)
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
            return
        except FileNotFoundError as exc:
            self._json(500, {"error": str(exc)})
            return
        except Exception:
            traceback.print_exc()
            self._json(500, {"error": "Could not check that email."})
            return
        self._json(200, payload)

    def log_message(self, fmt: str, *args) -> None:
        # Request lines only. The body can contain someone else's mail.
        super().log_message(fmt, *args)

    def _read_email(self) -> tuple[str | None, tuple[int, str] | None]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None, (400, "Content-Length must be a number.")
        if length <= 0:
            return None, (400, "Paste an email first.")
        if length > 2_000_000:
            return None, (413, "Email is larger than 2 MB.")
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, (400, "Request body must be JSON.")
        email = payload.get("email", "")
        if not isinstance(email, str):
            return None, (400, "Email must be text.")
        return email, None

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self._bytes(status, "application/json; charset=utf-8", body)

    def _bytes(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def _health() -> dict:
    metrics = None
    try:
        from phishdet.model import load_bundle

        raw_metrics = load_bundle().get("metrics") or {}
        metrics = {key: raw_metrics[key] for key in ("precision", "recall", "f1", "roc_auc", "test_size") if key in raw_metrics}
    except FileNotFoundError:
        metrics = None
    return {"ok": metrics is not None, "metrics": metrics, "samples": sorted(SAMPLES), "services": service_status()}
