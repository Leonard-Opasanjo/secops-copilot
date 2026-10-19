"""The dashboard: submit a case, read the analysis, approve or reject actions, download the report."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, PackageLoader, select_autoescape

from . import REPO_URL, __version__
from .actions import ACTIONS, ApprovalRequired
from .analyst_claude import AnalystError, ClaudeAnalyst, claude_available
from .analyst_offline import analyse_offline
from .case import Case, CaseError
from .db import Store
from .models import SEVERITIES
from .report import incident_report

env = Environment(loader=PackageLoader("secops_copilot", "templates"), autoescape=select_autoescape(["html"]))
env.globals.update(version=__version__, repo_url=REPO_URL, severities=SEVERITIES, action_names=ACTIONS)
templates = Jinja2Templates(env=env)
app = FastAPI(title="SecOps Copilot", docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
SECURITY_HEADERS = {
    "content-security-policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                               "form-action 'self'; frame-ancestors 'none'; base-uri 'self'",
    "x-content-type-options": "nosniff", "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()", "cache-control": "no-store",
}


def store() -> Store:
    if not hasattr(app.state, "store"):
        app.state.store = Store(os.environ.get("SECOPS_DB", "secops.db"))
    return app.state.store


def analysts() -> dict[str, bool]:
    return {"offline": True, "claude": claude_available()}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


def run_analysis(case_id: int, analyst_name: str) -> None:
    db = store()
    row = db.get_case(case_id)
    db.start(case_id)
    try:
        case = Case.load(row["title"], row["logs"], row["alerts_json"], row["source"])
        analysis = analyse_offline(case) if analyst_name != "claude" else ClaudeAnalyst().analyse(case)
        db.finish(case_id, analysis)
    except (CaseError, AnalystError, ValueError, RuntimeError, OSError) as e:
        db.fail(case_id, f"{type(e).__name__}: {e}")


def _page(request: Request, name: str, status_code: int = 200, **ctx) -> HTMLResponse:
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return _page(request, "index.html", cases=store().list_cases(), analysts=analysts())


@app.post("/cases")
def create_case(request: Request, background: BackgroundTasks, title: str = Form(""), alerts: str = Form(""),
                logs: str = Form(""), analyst: str = Form("offline")):
    if analyst not in ("offline", "claude"):
        raise HTTPException(400, "unknown analyst")
    if analyst == "claude" and not claude_available():
        return _page(request, "error.html", status_code=400, title="Claude backend not configured",
                     message="Set ANTHROPIC_API_KEY (or log in with the ant CLI) and restart, or use the offline "
                             "analyst.")
    try:
        Case.load(title, logs, alerts)
    except CaseError as e:
        return _page(request, "error.html", status_code=400, title="Invalid case", message=str(e))
    case_id = store().create_case(title.strip() or "Untitled case", alerts, logs, analyst)
    background.add_task(run_analysis, case_id, analyst)
    return RedirectResponse(f"/cases/{case_id}", status_code=303)


def _case_or_404(case_id: int) -> dict:
    row = store().get_case(case_id)
    if row is None:
        raise HTTPException(404, "case not found")
    return row


@app.get("/cases/{case_id}", response_class=HTMLResponse)
def case_page(request: Request, case_id: int):
    row = _case_or_404(case_id)
    case = Case.load(row["title"], row["logs"], row["alerts_json"]) if (row["logs"] or row["alerts_json"]) else None
    return _page(request, "case.html", row=row, case=case, counts=store().status_counts(case_id))


@app.post("/actions/{action_id}/decide")
def decide(action_id: int, decision: str = Form(...), by: str = Form(""), note: str = Form("")):
    try:
        action = store().decide(action_id, decision, by, note)
    except KeyError as e:
        raise HTTPException(404, "action not found") from e
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return RedirectResponse(f"/cases/{action['case_id']}#actions", status_code=303)


@app.post("/actions/{action_id}/execute")
def execute(action_id: int, by: str = Form("")):
    try:
        action = store().execute(action_id, by)
    except KeyError as e:
        raise HTTPException(404, "action not found") from e
    except ApprovalRequired as e:
        raise HTTPException(403, str(e)) from e
    return RedirectResponse(f"/cases/{action['case_id']}#actions", status_code=303)


@app.get("/cases/{case_id}/report.md")
def report(case_id: int):
    row = _case_or_404(case_id)
    if not row["analysis"]:
        raise HTTPException(409, "the case has not been analysed yet")
    case = Case.load(row["title"], row["logs"], row["alerts_json"])
    text = incident_report(case, row["analysis"], row["actions"], case_id=case_id)
    return Response(text, media_type="text/markdown",
                    headers={"content-disposition": f'attachment; filename="incident-{case_id}.md"'})


@app.get("/api/cases")
def api_cases():
    return store().list_cases()


@app.get("/api/cases/{case_id}")
def api_case(case_id: int):
    return JSONResponse(content=_case_or_404(case_id))


@app.get("/healthz")
def healthz():
    return {"ok": True, "analysts": analysts()}


def serve(host: str = "127.0.0.1", port: int = 8000, db: str | None = None) -> None:
    import uvicorn

    if db:
        os.environ["SECOPS_DB"] = str(Path(db))
    uvicorn.run(app, host=host, port=port, log_level="info")
