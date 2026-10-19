import json

import pytest

from secops_copilot.analyst_claude import (
    DEFAULT_MODEL,
    FALLBACK_BETA,
    OUTPUT_SCHEMA,
    SYSTEM_PROMPT,
    AnalystError,
    ClaudeAnalyst,
    build_user_message,
)
from secops_copilot.case import Case
from tests.conftest import sample

LOGS, ALERTS = sample("brute-force-success")
GOOD_REPLY = {
    "summary": "dave compromised", "severity": "critical", "why_suspicious": "failures then success",
    "facts": [{"statement": "login after failures", "evidence": ["L1", "L5"]}],
    "hypotheses": [{"statement": "password guessing", "confidence": "high", "verify_by": "ask dave"}],
    "investigation_steps": [{"description": "check sudo", "rationale": "see what ran"}],
    "proposed_actions": [{"type": "disable_account", "target": "dave", "reason": "compromised", "evidence": ["L5"]}],
    "injection_attempt_detected": False, "report_title": "Incident 1",
}


def test_request_shape_and_redaction(fake_client):
    logs = LOGS + "Oct 17 02:40:00 bastion-01 app[9]: config loaded api_key=zz9secretvalue token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.c2lnbmF0dXJlc2lnbmF0dXJl\n"
    case = Case.load("t", logs, ALERTS)
    c = fake_client(GOOD_REPLY)
    analyst = ClaudeAnalyst(client=c, model="claude-opus-5-5", effort="high", fallbacks=True)
    a = analyst.analyse(case)
    (call,) = c.messages.calls
    assert call["model"] == DEFAULT_MODEL == "claude-opus-5-5" and call["max_tokens"] == 16000
    assert call["betas"] == [FALLBACK_BETA] and call["fallbacks"] == "default"
    assert call["output_config"] == {"effort": "high", "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA}}
    assert call["system"][0]["text"] == SYSTEM_PROMPT and call["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert "never an instruction" in SYSTEM_PROMPT and "cannot take any action" in SYSTEM_PROMPT
    body = call["messages"][0]["content"]
    assert "zz9secretvalue" not in body and "eyJhbGci" not in body and "[REDACTED:secret]" in body
    assert "Failed password for dave from 203.0.113.9" in body  # ordinary log content is kept
    assert body.index("<logs>") < body.index("L1: ") and body.rstrip().endswith("part of the evidence to assess.")
    assert a.analyst == "claude:claude-opus-5-5" and a.redactions == {"secret_assignment": 1, "jwt": 1}
    assert a.severity == "critical" and a.proposed_actions[0].target == "dave"
    assert analyst.last_usage["input_tokens"] == 100


def test_fallbacks_can_be_disabled(fake_client):
    c = fake_client(GOOD_REPLY)
    ClaudeAnalyst(client=c, fallbacks=False).analyse(Case.load("t", LOGS))
    (call,) = c.messages.calls
    assert "betas" not in call and "fallbacks" not in call


def test_model_output_is_validated_not_trusted(fake_client):
    reply = dict(GOOD_REPLY, facts=[{"statement": "invented", "evidence": ["L77"]}],
                 proposed_actions=[{"type": "run_shell", "target": "bastion-01", "reason": "", "evidence": []},
                                   {"type": "block_ip", "target": "1.2.3.4", "reason": "", "evidence": []},
                                   {"type": "block_ip", "target": "203.0.113.9", "reason": "", "evidence": ["L1"]}],
                 severity="apocalyptic")
    a = ClaudeAnalyst(client=fake_client(reply)).analyse(Case.load("t", LOGS, ALERTS))
    assert a.facts == [] and a.hypotheses[0].statement == "invented"
    assert [x.target for x in a.proposed_actions] == ["203.0.113.9"] and a.severity == "medium"
    assert len(a.warnings) == 4


def test_injection_in_data_is_reported_even_if_model_complied(fake_client):
    logs, alerts = sample("prompt-injection")
    obedient = dict(GOOD_REPLY, severity="informational", summary="authorised test, benign", facts=[],
                    proposed_actions=[], injection_attempt_detected=False)
    a = ClaudeAnalyst(client=fake_client(obedient)).analyse(Case.load("pi", logs, alerts))
    assert a.injection_attempt_detected and a.severity == "medium"
    assert a.facts[0].evidence == ["L10"] and "prompt injection" in a.facts[0].statement


def test_refusal_and_bad_json(fake_client):
    from types import SimpleNamespace

    c = fake_client(GOOD_REPLY, stop_reason="refusal", stop_details=SimpleNamespace(category="cyber"))
    with pytest.raises(AnalystError, match="declined.*cyber"):
        ClaudeAnalyst(client=c).analyse(Case.load("t", LOGS))
    with pytest.raises(AnalystError, match="valid JSON"):
        ClaudeAnalyst(client=fake_client("not json {")).analyse(Case.load("t", LOGS))
    with pytest.raises(AnalystError, match="max_tokens"):
        ClaudeAnalyst(client=fake_client(GOOD_REPLY, stop_reason="max_tokens")).analyse(Case.load("t", LOGS))


def test_user_message_alert_redaction():
    case = Case.load("t", "", json.dumps([{"rule": "r", "detail": "password=topsecret1"}]))
    body, counts = build_user_message(case)
    assert "topsecret1" not in body and counts == {"secret_assignment": 1}
