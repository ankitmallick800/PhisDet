"""Vercel API for the hosted page.

The local ``phishdet serve`` command is unchanged. This module is the
entrypoint Vercel loads. It only scores a message the caller pastes, and it
does not open links from that message.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from phishdet.cli import SAMPLES  # noqa: E402
from phishdet.intel import investigate, local_view, service_status  # noqa: E402
from phishdet.model import load_bundle  # noqa: E402

_MAX_BODY = 2_000_000
_SAMPLE_DIR = ROOT / "src" / "phishdet" / "samples"

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=(
        r"https://ankitmallick800\.github\.io"
        r"|http://(localhost|127\.0\.0\.1)(:\d+)?"
    ),
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
    max_age=600,
)


def _health() -> dict:
    metrics = None
    try:
        raw_metrics = load_bundle().get("metrics") or {}
        metrics = {
            key: raw_metrics[key]
            for key in ("precision", "recall", "f1", "roc_auc", "test_size")
            if key in raw_metrics
        }
    except FileNotFoundError:
        metrics = None
    return {
        "ok": metrics is not None,
        "metrics": metrics,
        "samples": sorted(SAMPLES),
        "services": service_status(),
    }


def _read_email(raw: bytes) -> tuple[str | None, JSONResponse | None]:
    if not raw:
        return None, JSONResponse({"error": "Paste an email first."}, status_code=400)
    if len(raw) > _MAX_BODY:
        return None, JSONResponse({"error": "Email is larger than 2 MB."}, status_code=413)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, JSONResponse({"error": "Request body must be JSON."}, status_code=400)
    if not isinstance(payload, dict):
        return None, JSONResponse({"error": "Request body must be JSON."}, status_code=400)
    email = payload.get("email", "")
    if not isinstance(email, str):
        return None, JSONResponse({"error": "Email must be text."}, status_code=400)
    return email, None


def _run(kind: str, email: str) -> Response:
    try:
        payload = investigate(email) if kind == "intel" else local_view(email)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except FileNotFoundError as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)
    except Exception:
        return JSONResponse({"error": "Could not check that email."}, status_code=500)
    return JSONResponse(payload)


@app.get("/")
def home() -> dict:
    return {
        "ok": True,
        "page": "https://ankitmallick800.github.io/PhisDet/",
    }


@app.get("/api/health")
def health() -> dict:
    return _health()


@app.get("/api/sample/{key}")
def sample(key: str) -> Response:
    filename = SAMPLES.get(key)
    if filename is None:
        return JSONResponse({"error": "Unknown sample."}, status_code=404)
    file_path = _SAMPLE_DIR / filename
    if not file_path.is_file():
        return JSONResponse({"error": "Sample file is missing."}, status_code=404)
    return PlainTextResponse(file_path.read_text(encoding="utf-8", errors="replace"))


@app.post("/api/detect")
async def detect_route(request: Request) -> Response:
    email, error = _read_email(await request.body())
    if error is not None:
        return error
    return _run("detect", email or "")


@app.post("/api/intel")
async def intel_route(request: Request) -> Response:
    email, error = _read_email(await request.body())
    if error is not None:
        return error
    return _run("intel", email or "")
