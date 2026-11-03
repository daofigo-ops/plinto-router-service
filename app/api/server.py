from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = PROJECT_ROOT / "reports"
LATEST_JSON = REPORTS_DIR / "latest.json"
LATEST_HTML = REPORTS_DIR / "latest.html"
LATEST_CSV = REPORTS_DIR / "latest.csv"
INVENTORY_FILE = PROJECT_ROOT / "data" / "device_inventory.json"
PENTEST_LOG = REPORTS_DIR / "pentest_audit.jsonl"


class ScanRunRequest(BaseModel):
    mode: Literal["local", "gateway", "custom"] = "local"
    target: str | None = None
    ports: str | None = None
    timeout: float | None = None
    concurrency: int | None = None
    report_format: Literal["json", "csv", "html", "both", "all"] = "all"
    deep_fingerprint: bool = True
    dns_audit: bool = True
    save_history: bool = True
    update_inventory: bool = True
    pentest: bool = False
    ownership_confirmed: bool = False
    apply_pentest: bool = False
    check_defaults: bool = False
    credentials_file: str | None = None

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, value: str | None) -> str | None:
        if value is None or value.strip() == "":
            return None
        parts = [item.strip() for item in value.split(",") if item.strip()]
        for item in parts:
            port = int(item)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid TCP port: {port}")
        return ",".join(parts)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None


class ScanRunResponse(BaseModel):
    ok: bool
    command: list[str]
    started_at: str
    finished_at: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""


app = FastAPI(
    title="Plinto Local Dashboard API",
    version="0.4B-dashboard",
    description="Local-only API for reading Plinto reports and launching authorized private-network scans.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _read_json(path: Path, fallback: Any) -> Any:
    if not path.exists():
        return fallback
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"Invalid JSON in {path}: {exc}") from exc


def _file_meta(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"exists": False, "path": str(path.relative_to(PROJECT_ROOT))}
    stat = path.stat()
    return {
        "exists": True,
        "path": str(path.relative_to(PROJECT_ROOT)),
        "size_bytes": stat.st_size,
        "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
    }


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "Plinto Local Dashboard API",
        "project_root": str(PROJECT_ROOT),
        "reports_dir": str(REPORTS_DIR),
        "latest_json": _file_meta(LATEST_JSON),
        "latest_html": _file_meta(LATEST_HTML),
        "latest_csv": _file_meta(LATEST_CSV),
        "inventory": _file_meta(INVENTORY_FILE),
        "pentest_log": _file_meta(PENTEST_LOG),
    }


@app.get("/api/latest")
def latest_report() -> dict[str, Any]:
    return _read_json(LATEST_JSON, {"summary": None, "findings": [], "finding_count": 0})


@app.get("/api/summary")
def latest_summary() -> dict[str, Any]:
    payload = _read_json(LATEST_JSON, {"summary": None, "findings": [], "finding_count": 0})
    return {
        "summary": payload.get("summary"),
        "finding_count": payload.get("finding_count", len(payload.get("findings", []))),
        "report_meta": {
            "json": _file_meta(LATEST_JSON),
            "html": _file_meta(LATEST_HTML),
            "csv": _file_meta(LATEST_CSV),
        },
    }


@app.get("/api/inventory")
def inventory() -> dict[str, Any]:
    return _read_json(INVENTORY_FILE, {"services": {}, "updated_at": None})


@app.get("/api/history")
def scan_history() -> dict[str, Any]:
    scans_dir = REPORTS_DIR / "scans"
    items: list[dict[str, Any]] = []
    if scans_dir.exists():
        for run_dir in sorted([p for p in scans_dir.iterdir() if p.is_dir()], reverse=True):
            report_json = run_dir / "report.json"
            report_html = run_dir / "report.html"
            report_csv = run_dir / "report.csv"
            payload = _read_json(report_json, {}) if report_json.exists() else {}
            items.append(
                {
                    "id": run_dir.name,
                    "path": str(run_dir.relative_to(PROJECT_ROOT)),
                    "summary": payload.get("summary"),
                    "finding_count": payload.get("finding_count", len(payload.get("findings", []))),
                    "reports": {
                        "json": _file_meta(report_json),
                        "html": _file_meta(report_html),
                        "csv": _file_meta(report_csv),
                    },
                }
            )
    return {"count": len(items), "items": items}


@app.get("/api/pentest/log")
def pentest_log(limit: int = 200) -> dict[str, Any]:
    if limit < 1:
        limit = 1
    if limit > 1000:
        limit = 1000
    if not PENTEST_LOG.exists():
        return {"count": 0, "items": []}
    lines = PENTEST_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
    items: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            items.append({"raw": line, "parse_error": True})
    return {"count": len(items), "items": items}


@app.get("/api/reports/latest/{kind}")
def download_latest_report(kind: Literal["json", "csv", "html"]):
    path_map = {"json": LATEST_JSON, "csv": LATEST_CSV, "html": LATEST_HTML}
    path = path_map[kind]
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"latest.{kind} does not exist yet. Run a scan first.")
    media_type = {
        "json": "application/json",
        "csv": "text/csv",
        "html": "text/html",
    }[kind]
    return FileResponse(path, media_type=media_type, filename=path.name)


@app.post("/api/scans/run", response_model=ScanRunResponse)
def run_scan(request: ScanRunRequest) -> ScanRunResponse:
    if request.mode == "custom" and not request.target:
        raise HTTPException(status_code=422, detail="Custom mode requires a target IP or CIDR.")

    command = [sys.executable, "-m", "app.main", "scan"]
    if request.mode == "local":
        command.append("--local")
    elif request.mode == "gateway":
        command.extend(["--local", "--gateway"])
    else:
        command.append(request.target or "")

    command.extend(["--format", request.report_format])

    if request.ports:
        command.extend(["--ports", request.ports])
    if request.timeout is not None:
        command.extend(["--timeout", str(request.timeout)])
    if request.concurrency is not None:
        command.extend(["--concurrency", str(request.concurrency)])
    if not request.deep_fingerprint:
        command.append("--no-deep-fingerprint")
    if not request.dns_audit:
        command.append("--no-dns-audit")
    if not request.save_history:
        command.append("--no-history")
    if not request.update_inventory:
        command.append("--no-inventory")

    if request.pentest:
        command.append("--pentest")
        if not request.ownership_confirmed:
            raise HTTPException(status_code=403, detail="Pentest mode requires ownership/authorization confirmation.")
        command.append("--i-own-this-network")
        if request.credentials_file:
            command.extend(["--credentials", request.credentials_file])
        if request.check_defaults:
            command.append("--check-defaults")
        if request.apply_pentest:
            command.append("--apply-pentest")

    started_at = datetime.now(timezone.utc).isoformat()
    try:
        proc = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        finished_at = datetime.now(timezone.utc).isoformat()
        return ScanRunResponse(
            ok=False,
            command=command,
            started_at=started_at,
            finished_at=finished_at,
            exit_code=124,
            stdout=exc.stdout or "",
            stderr=(exc.stderr or "") + "\nScan timed out after 300 seconds.",
        )

    finished_at = datetime.now(timezone.utc).isoformat()
    return ScanRunResponse(
        ok=proc.returncode == 0,
        command=command,
        started_at=started_at,
        finished_at=finished_at,
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def main() -> None:
    import uvicorn

    uvicorn.run(
        "app.api.server:app",
        host="127.0.0.1",
        port=8787,
        reload=False,
    )


if __name__ == "__main__":
    main()
