import pytest

from secops_copilot.actions import ApprovalRequired
from secops_copilot.analyst_offline import analyse_offline
from secops_copilot.case import Case
from secops_copilot.db import Store
from secops_copilot.report import incident_report
from tests.conftest import sample

LOGS, ALERTS = sample("brute-force-success")


def make(tmp_path):
    store = Store(tmp_path / "s.db")
    case = Case.load("bf", LOGS, ALERTS)
    cid = store.create_case("bf", ALERTS, LOGS, "offline")
    store.finish(cid, analyse_offline(case))
    return store, cid, case


def test_approval_gate(tmp_path):
    store, cid, _ = make(tmp_path)
    row = store.get_case(cid)
    assert row["status"] == "done" and row["analysis"]["severity"] == "critical"
    actions = row["actions"]
    assert all(a["status"] == "proposed" for a in actions) and len(actions) >= 5
    first = actions[0]["id"]
    with pytest.raises(ApprovalRequired):
        store.execute(first, "ops")
    with pytest.raises(ValueError, match="name"):
        store.decide(first, "approved", "", "")
    with pytest.raises(ValueError):
        store.decide(first, "maybe", "ops")
    approved = store.decide(first, "approved", "J. Mwangi", "ticket 42")
    assert approved["status"] == "approved" and approved["decided_by"] == "J. Mwangi"
    with pytest.raises(ValueError, match="already"):
        store.decide(first, "rejected", "someone")
    done = store.execute(first, "J. Mwangi")
    assert done["status"] == "executed" and done["result"].startswith("DRY RUN: would")
    with pytest.raises(ApprovalRequired):
        store.execute(first, "J. Mwangi")  # not approved any more: executed
    rejected = store.decide(actions[1]["id"], "rejected", "J. Mwangi", "false positive")
    assert rejected["status"] == "rejected"
    with pytest.raises(ApprovalRequired):
        store.execute(actions[1]["id"], "x")
    counts = store.status_counts(cid)
    assert counts["executed"] == 1 and counts["rejected"] == 1 and counts["proposed"] == len(actions) - 2
    events = [e["event"] for e in store.get_case(cid)["audit"]]
    assert events == ["case_created", "analysis_done", "action_approved", "action_executed", "action_rejected"]
    assert store.get_action(999) is None
    with pytest.raises(KeyError):
        store.decide(999, "approved", "x")


def test_list_and_failure(tmp_path):
    store, cid, _ = make(tmp_path)
    other = store.create_case("broken", "", "x", "offline")
    store.fail(other, "boom")
    cases = store.list_cases()
    assert cases[0]["id"] == other and cases[0]["status"] == "failed" and cases[0]["severity"] is None
    assert cases[1]["severity"] == "critical" and cases[1]["pending"] >= 5
    assert store.get_case(999) is None


def test_report_keeps_facts_and_hypotheses_apart_and_redacts(tmp_path):
    store, cid, case = make(tmp_path)
    row = store.get_case(cid)
    store.decide(row["actions"][0]["id"], "approved", "J. Mwangi", "ticket 42")
    md = incident_report(case, row["analysis"], store.get_case(cid)["actions"], case_id=cid)
    assert md.startswith("# Incident: bf") and "Severity: **critical**" in md
    assert md.index("## Verified facts") < md.index("## Hypotheses (not verified)") < md.index("## Response actions")
    assert "L5: Oct 17 02:17:21 bastion-01 sshd[2231]: Accepted password for dave" in md
    assert "| approved | J. Mwangi | ticket 42 |" in md and "Reviewed by:" in md
    secret_case = Case.load("s", "Oct 17 02:40:00 h app[9]: token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.c2lnbmF0dXJlc2lnbmF0dXJl loaded")  # gitleaks:allow (fake value for the redaction tests)
    a = analyse_offline(secret_case)
    md = incident_report(secret_case, {**a.to_dict(), "facts": [{"statement": "s", "evidence": ["L1"]}]})
    assert "eyJhbGci" not in md and "[REDACTED" in md
