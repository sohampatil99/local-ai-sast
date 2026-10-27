"""FastAPI backend: runs scans in background threads and serves the dashboard."""
import re
import shutil
import subprocess
import sys
import threading
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sast import report  # noqa: E402
from sast.engine import scan  # noqa: E402
from sast.llm import LocalLLM  # noqa: E402
from storage import Storage  # noqa: E402

BASE = Path(__file__).resolve().parent
WORK = BASE / "data" / "workspaces"
STATIC = BASE / "static"
GIT_URL = re.compile(r"^(https://|git@)[\w.@:/\-~]+$")

app = FastAPI(title="Local AI SAST Engine", version="0.1.0")
store = Storage()


class ScanRequest(BaseModel):
    target: str
    ai: bool = False
    ai_review: bool = False
    model: str | None = None
    ai_limit: int = 15


def _run(scan_id, target, opts, cleanup=None):
    try:
        result = scan(target, scan_id=scan_id, progress=lambda m: store.progress(scan_id, m), **opts)
        store.finish(scan_id, result)
    except Exception as exc:
        store.fail(scan_id, f"{type(exc).__name__}: {exc}")
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)


def _start(target, opts, label=None, cleanup=None):
    scan_id = uuid.uuid4().hex[:12]
    store.create(scan_id, label or target, datetime.now(timezone.utc).isoformat(timespec="seconds"))
    threading.Thread(target=_run, args=(scan_id, target, opts, cleanup), daemon=True).start()
    return {"id": scan_id, "status": "running"}


@app.get("/api/health")
def health():
    llm = LocalLLM()
    ok, detail = llm.status()
    return {"status": "ok", "database": store.kind, "llm": {"available": ok, "model": llm.model, "detail": detail},
            "offline": True}


@app.post("/api/scans")
def create_scan(req: ScanRequest):
    opts = {"ai": req.ai, "ai_review": req.ai_review, "model": req.model, "ai_limit": req.ai_limit}
    target = req.target.strip().strip('"')
    if GIT_URL.match(target):
        dest = WORK / uuid.uuid4().hex[:12]
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(["git", "clone", "--depth", "1", "--", target, str(dest)],
                           check=True, capture_output=True, timeout=180)
        except (OSError, subprocess.SubprocessError) as exc:
            raise HTTPException(400, f"git clone failed: {exc}")
        return _start(str(dest), opts, label=target, cleanup=dest)
    if not Path(target).exists():
        raise HTTPException(400, f"Path not found: {target}")
    return _start(str(Path(target).resolve()), opts)


@app.post("/api/scans/upload")
async def upload_scan(file: UploadFile = File(...), ai: bool = Form(False), ai_review: bool = Form(False)):
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "Upload a .zip archive of the repository")
    dest = WORK / uuid.uuid4().hex[:12]
    dest.mkdir(parents=True, exist_ok=True)
    archive = dest / "upload.zip"
    archive.write_bytes(await file.read())
    try:
        with zipfile.ZipFile(archive) as zf:
            root = dest.resolve()
            for member in zf.infolist():
                out = (dest / member.filename).resolve()
                if not out.is_relative_to(root):  # zip-slip guard
                    raise HTTPException(400, f"Unsafe path in archive: {member.filename}")
            zf.extractall(dest / "src")
    except zipfile.BadZipFile:
        shutil.rmtree(dest, ignore_errors=True)
        raise HTTPException(400, "Not a valid zip file")
    except HTTPException:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    archive.unlink()
    return _start(str(dest / "src"), {"ai": ai, "ai_review": ai_review}, label=file.filename, cleanup=dest)


@app.get("/api/scans")
def list_scans():
    return store.list()


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    item = store.get(scan_id)
    if item is None:
        raise HTTPException(404, "Scan not found")
    return item


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str):
    store.delete(scan_id)
    return {"deleted": scan_id}


@app.get("/api/scans/{scan_id}/report.{fmt}")
def get_report(scan_id: str, fmt: str):
    item = store.get(scan_id)
    if item is None or not item.get("result"):
        raise HTTPException(404, "Scan not finished")
    result = item["result"]
    name = f"sast-report-{scan_id}"
    if fmt == "json":
        return JSONResponse(result, headers={"Content-Disposition": f'attachment; filename="{name}.json"'})
    if fmt == "sarif":
        return Response(report.to_sarif(result), media_type="application/sarif+json",
                        headers={"Content-Disposition": f'attachment; filename="{name}.sarif"'})
    if fmt == "html":
        return HTMLResponse(report.to_html(result))
    if fmt == "patch":
        if not result.get("fix_patch"):
            raise HTTPException(404, "This scan has no AI fixes. Run it with AI triage enabled.")
        return Response(result["fix_patch"], media_type="text/x-diff",
                        headers={"Content-Disposition": f'attachment; filename="{name}.patch"'})
    if fmt == "pdf":
        out = BASE / "data" / "reports" / f"{name}.pdf"
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            report.to_pdf(result, out)
        except Exception as exc:
            raise HTTPException(500, f"PDF export failed: {exc}")
        return FileResponse(out, media_type="application/pdf", filename=f"{name}.pdf")
    raise HTTPException(400, "Format must be json, sarif, html, pdf or patch")


app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
