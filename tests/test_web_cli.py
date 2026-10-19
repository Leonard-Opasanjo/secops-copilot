import json
import subprocess
import sys

from secops_copilot.cli import main
from tests.conftest import SAMPLES, sample

LOGS, ALERTS = sample("brute-force-success")


def test_dashboard_end_to_end(client):
    assert "SecOps Copilot" in client.get("/").text
    r = client.post("/cases", data={"title": "bf", "alerts": ALERTS, "logs": LOGS, "analyst": "offline"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/cases/1"
    page = client.get("/cases/1")
    assert page.status_code == 200 and "critical" in page.text and "succeeded (L5)" in page.text
    assert "nothing runs without a named approver" in page.text
    for h in ("content-security-policy", "x-frame-options"):
        assert h in page.headers
    data = client.get("/api/cases/1").json()
    aid = data["actions"][0]["id"]
    assert client.post(f"/actions/{aid}/execute", data={"by": "x"}).status_code == 403  # not approved
    r = client.post(f"/actions/{aid}/decide", data={"decision": "approved", "by": "J. Mwangi", "note": "t-1"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/cases/1#actions"
    assert client.post(f"/actions/{aid}/decide", data={"decision": "approved", "by": "again"}).status_code == 400
    r = client.post(f"/actions/{aid}/execute", data={"by": "J. Mwangi"}, follow_redirects=False)
    assert r.status_code == 303
    action = next(a for a in client.get("/api/cases/1").json()["actions"] if a["id"] == aid)
    assert action["status"] == "executed" and action["result"].startswith("DRY RUN")
    md = client.get("/cases/1/report.md").text
    assert "# Incident: bf" in md and "| executed | J. Mwangi | t-1 |" in md
    assert client.get("/api/cases").json()[0]["pending"] >= 4
    assert client.get("/healthz").json()["analysts"]["offline"] is True
    assert client.post("/actions/999/decide", data={"decision": "approved", "by": "x"}).status_code == 404


def test_dashboard_rejects_bad_input(client, monkeypatch):
    assert client.post("/cases", data={"title": "x", "alerts": "", "logs": ""}).status_code == 400
    assert client.post("/cases", data={"title": "x", "alerts": "{bad", "logs": "l"}).status_code == 400
    assert client.post("/cases", data={"title": "x", "logs": "l", "analyst": "nope"}).status_code == 400
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.setattr("secops_copilot.web.claude_available", lambda: False)
    r = client.post("/cases", data={"title": "x", "logs": "l", "analyst": "claude"})
    assert r.status_code == 400 and "not configured" in r.text
    assert client.get("/cases/42").status_code == 404 and client.get("/cases/42/report.md").status_code == 404


def test_injection_sample_in_dashboard(client):
    logs, alerts = sample("prompt-injection")
    client.post("/cases", data={"title": "pi", "alerts": alerts, "logs": logs, "analyst": "offline"})
    page = client.get("/cases/1").text
    assert "Tampering detected" in page and "treated as evidence" in page


def test_cli_analyse_and_demo(tmp_path, capsys):
    db = tmp_path / "c.db"
    rc = main(["analyse", "--logs", str(SAMPLES / "brute-force-success/logs.txt"),
               "--alerts", str(SAMPLES / "brute-force-success/alerts.json"), "--db", str(db),
               "--report", str(tmp_path / "r.md"), "--json", str(tmp_path / "r.json")])
    out = capsys.readouterr().out
    assert rc == 0 and "[critical]" in out and "saved as case 1" in out and "need approval" in out
    assert json.loads((tmp_path / "r.json").read_text())["severity"] == "critical"
    assert "## Verified facts" in (tmp_path / "r.md").read_text()
    assert main(["analyse", "--logs", str(SAMPLES / "new-admin-account/logs.txt"), "--no-save"]) == 0
    assert "saved as" not in capsys.readouterr().out
    assert main(["analyse", "--logs", str(tmp_path / "missing.txt")]) == 2
    assert main(["demo", "--db", str(db)]) == 0
    assert "case 4:" in capsys.readouterr().out


def test_cli_claude_without_credentials(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.setattr("secops_copilot.cli.claude_available", lambda: False)
    assert main(["analyse", "--logs", str(SAMPLES / "brute-force-success/logs.txt"), "--analyst", "claude", "--no-save"]) == 2
    assert "credentials" in capsys.readouterr().err


def test_module_entry_point():
    r = subprocess.run([sys.executable, "-m", "secops_copilot.cli", "--version"], capture_output=True, text=True)
    assert r.returncode == 0 and "secops-copilot 0." in r.stdout
