from secops_copilot.analyst_offline import analyse_offline
from secops_copilot.case import Case
from tests.conftest import sample


def keys(items, attr):
    return [getattr(x, attr) for x in items]


def test_brute_force_success_sample():
    logs, alerts = sample("brute-force-success")
    a = analyse_offline(Case.load("bf", logs, alerts))
    assert a.severity == "critical" and a.analyst == "offline"
    statements = " | ".join(keys(a.facts, "statement"))
    assert "Alert A1 fired" in statements and "succeeded (L5) after 4 failed attempts" in statements
    assert "support2" in statements and "'sudo' group" in statements
    login_fact = next(f for f in a.facts if "succeeded" in f.statement)
    assert login_fact.evidence == ["L1", "L2", "L3", "L4", "L5"]
    assert any("privileged command after the suspicious login" in s for s in keys(a.facts, "statement"))
    assert any("compromised by password guessing" in h.statement and h.confidence == "high" for h in a.hypotheses)
    actions = {(x.type, x.target) for x in a.proposed_actions}
    assert {("disable_account", "dave"), ("reset_credentials", "dave"), ("block_ip", "203.0.113.9"),
            ("disable_account", "support2"), ("preserve_evidence", "bastion-01"),
            ("isolate_host", "bastion-01")} <= actions
    assert all(f.evidence for f in a.facts) and a.warnings == [] and not a.injection_attempt_detected
    assert a.investigation_steps and "dave" in a.investigation_steps[0].description


def test_new_admin_account_sample():
    logs, alerts = sample("new-admin-account")
    a = analyse_offline(Case.load("na", logs, alerts))
    assert a.severity == "high"
    statements = keys(a.facts, "statement")
    assert any("svc_backup" in s and "created" in s for s in statements)
    assert any("'sudo' group" in s for s in statements) and any("crontab" in s for s in statements)
    assert any("198.51.100.77" in s for s in statements)  # external login noted as a fact
    assert ("disable_account", "svc_backup") in {(x.type, x.target) for x in a.proposed_actions}
    assert not any(x.type == "block_ip" for x in a.proposed_actions)  # carol's login alone is not an attack


def test_prompt_injection_sample_is_flagged_and_ignored():
    logs, alerts = sample("prompt-injection")
    a = analyse_offline(Case.load("pi", logs, alerts))
    assert a.injection_attempt_detected
    assert "prompt injection" in a.facts[0].statement and a.facts[0].evidence == ["L10"]
    assert a.severity in ("high", "medium") and ("block_ip", "203.0.113.45") in {(x.type, x.target) for x in a.proposed_actions}
    assert "benign" not in a.summary.lower()


def test_quiet_logs_stay_informational():
    a = analyse_offline(Case.load("q", "Oct 17 08:02:17 h sshd[1]: Accepted publickey for alice from 10.0.1.20 port 1 ssh2\n"
                                        "Oct 17 08:05:40 h sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"))
    assert a.severity == "informational" and a.proposed_actions == [] and "routine administration" in a.facts[0].statement
