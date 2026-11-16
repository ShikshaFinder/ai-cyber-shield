"""AI Cyber Shield gateway.

A small FastAPI service that sits between the browser extension and the OpenCode server.
It receives capture uploads from the extension, stores them in the workspace, creates scan
jobs, and asks the OpenCode server to run the `shield` agent against a job.

Bound to localhost by Docker. The extension authenticates with the SHIELD_TOKEN bearer token.
"""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

WORKSPACE = Path(os.environ.get("SHIELD_HOME", "/workspace"))
CAPTURES = WORKSPACE / "data" / "captures"
SCANS = WORKSPACE / "data" / "scans"
REPORTS = WORKSPACE / "data" / "reports"
for d in (CAPTURES, SCANS, REPORTS):
    d.mkdir(parents=True, exist_ok=True)

SHIELD_TOKEN = os.environ.get("SHIELD_TOKEN", "")
OPENCODE_URL = os.environ.get("OPENCODE_URL", "http://127.0.0.1:4096")
OPENCODE_PASSWORD = os.environ.get("OPENCODE_SERVER_PASSWORD", "")
SHIELD_MODEL = os.environ.get("SHIELD_MODEL", "").strip()

ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

app = FastAPI(title="AI Cyber Shield gateway", version="2.0.0")


def _require_auth(authorization: str | None) -> None:
    if not SHIELD_TOKEN:
        raise HTTPException(500, "SHIELD_TOKEN is not configured")
    expected = f"Bearer {SHIELD_TOKEN}"
    # length-constant-ish comparison
    if not authorization or len(authorization) != len(expected) or authorization != expected:
        raise HTTPException(401, "invalid or missing token")


def _safe_id(value: str) -> str:
    if not ID_RE.match(value or ""):
        raise HTTPException(400, "invalid id")
    return value


def _opencode_auth() -> tuple[str, str]:
    return ("opencode", OPENCODE_PASSWORD)


@app.get("/api/health")
async def health() -> dict[str, Any]:
    opencode_ok = False
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            r = await client.get(f"{OPENCODE_URL}/global/health", auth=_opencode_auth())
            opencode_ok = r.status_code == 200
    except Exception:
        opencode_ok = False
    return {"status": "ok", "opencode": opencode_ok, "time": int(time.time())}


@app.post("/api/captures")
async def upload_capture(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Receive a capture from the extension.

    Accepts either the extension's categorized JSON files as a map, or a single raw-capture JSON
    body. Stores everything under data/captures/<capture-id>/.
    """
    _require_auth(authorization)
    body = await request.json()
    capture_id = uuid.uuid4().hex[:16]
    target = CAPTURES / capture_id
    target.mkdir(parents=True, exist_ok=True)

    files = body.get("files") if isinstance(body, dict) else None
    if isinstance(files, dict):
        for name, content in files.items():
            safe = os.path.basename(str(name))
            if not safe or safe.startswith("."):
                continue
            data = content if isinstance(content, str) else json.dumps(content, indent=2)
            (target / safe).write_text(data, encoding="utf-8")
    else:
        (target / "complete_raw.json").write_text(json.dumps(body, indent=2), encoding="utf-8")

    meta = {
        "captureId": capture_id,
        "site": (body.get("site") if isinstance(body, dict) else None),
        "receivedAt": int(time.time()),
    }
    (target / "_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return {"captureId": capture_id, "fileCount": len(list(target.iterdir()))}


@app.post("/api/scans")
async def create_scan(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Create a scan job and kick off the shield agent in a new OpenCode session."""
    _require_auth(authorization)
    body = await request.json()
    capture_id = _safe_id(str(body.get("captureId", "")))
    if not (CAPTURES / capture_id).is_dir():
        raise HTTPException(404, "unknown captureId")

    mode = body.get("mode", "passive")
    if mode not in ("passive", "active"):
        raise HTTPException(400, "mode must be passive or active")

    # The scope guard reads a single active scope file, so only one active scan may run at a time
    # (otherwise a second active scan would widen the first scan's allowed targets). Passive scans
    # touch no network and are unrestricted.
    if mode == "active":
        for f in SCANS.glob("*.json"):
            try:
                other = json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            if other.get("mode") == "active" and other.get("status") == "running":
                # Ignore a stale lock from a scan that never completed (older than 2 hours).
                if int(time.time()) - int(other.get("createdAt", 0)) < 7200:
                    raise HTTPException(409, "another active scan is already running; wait for it to finish")

    scope = [s.strip() for s in (body.get("scope") or []) if isinstance(s, str) and s.strip()]
    if mode == "active" and not scope:
        raise HTTPException(400, "active scans require a non-empty scope")

    scan_id = uuid.uuid4().hex[:16]
    job = {
        "scanId": scan_id,
        "captureId": capture_id,
        "mode": mode,
        "scope": scope,
        "notes": str(body.get("notes", ""))[:2000],
        "createdAt": int(time.time()),
        "status": "queued",
    }
    (SCANS / f"{scan_id}.json").write_text(json.dumps(job, indent=2), encoding="utf-8")
    # Keep the active scope where the scope-guard wrapper can read it.
    (WORKSPACE / "data" / "scope.txt").write_text("\n".join(scope) + "\n", encoding="utf-8")

    session_id = await _start_shield_session(scan_id)
    job["status"] = "running"
    job["sessionId"] = session_id
    (SCANS / f"{scan_id}.json").write_text(json.dumps(job, indent=2), encoding="utf-8")
    return {"scanId": scan_id, "sessionId": session_id, "status": "running"}


async def _start_shield_session(scan_id: str) -> str:
    prompt = (
        f"Run the AI Cyber Shield assessment for scan id {scan_id}. "
        f"Read data/scans/{scan_id}.json, follow AGENTS.md, and write the report to "
        f"data/reports/{scan_id}.md and data/reports/{scan_id}.json."
    )
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{OPENCODE_URL}/session",
            auth=_opencode_auth(),
            json={"title": f"shield-{scan_id}"},
        )
        if r.status_code >= 300:
            raise HTTPException(502, f"opencode session failed: {r.status_code}")
        session_id = r.json()["id"]

        part = {"type": "text", "text": prompt}
        payload: dict[str, Any] = {"agent": "shield", "parts": [part]}
        if SHIELD_MODEL and "/" in SHIELD_MODEL:
            provider, model = SHIELD_MODEL.split("/", 1)
            payload["model"] = {"providerID": provider, "modelID": model}
        # Fire-and-forget: the agent runs in the background on the OpenCode server.
        await client.post(
            f"{OPENCODE_URL}/session/{session_id}/prompt_async",
            auth=_opencode_auth(),
            json=payload,
        )
    return session_id


@app.get("/api/scans/{scan_id}")
async def scan_status(scan_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(authorization)
    scan_id = _safe_id(scan_id)
    job_file = SCANS / f"{scan_id}.json"
    if not job_file.is_file():
        raise HTTPException(404, "unknown scanId")
    job = json.loads(job_file.read_text(encoding="utf-8"))
    report_json = REPORTS / f"{scan_id}.json"
    report_md = REPORTS / f"{scan_id}.md"
    job["reportReady"] = report_json.is_file() or report_md.is_file()
    # Release the active-scan lock once the report exists.
    if job["reportReady"] and job.get("status") == "running":
        job["status"] = "complete"
        job_file.write_text(json.dumps(job, indent=2), encoding="utf-8")
    if report_json.is_file():
        try:
            job["report"] = json.loads(report_json.read_text(encoding="utf-8"))
        except Exception:
            job["report"] = None
    return job


@app.exception_handler(HTTPException)
async def _http_error(_: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})
