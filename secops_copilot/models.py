"""The analysis model shared by every analyst backend, and the validation that keeps it honest."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field

from .case import looks_injected

SEVERITIES = ("critical", "high", "medium", "low", "informational")
CONFIDENCES = ("low", "medium", "high")
_REF = re.compile(r"^[AL]\d+$")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@\\-]{0,127}")  # account or host name: no spaces, quotes or shell syntax


@dataclass
class Fact:
    statement: str
    evidence: list[str]  # references such as "L12" (log line 12) or "A1" (alert 1)


@dataclass
class Hypothesis:
    statement: str
    confidence: str
    verify_by: str


@dataclass
class Step:
    description: str
    rationale: str = ""


@dataclass
class ProposedAction:
    type: str
    target: str
    reason: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class Analysis:
    summary: str
    severity: str
    why_suspicious: str
    facts: list[Fact]
    hypotheses: list[Hypothesis]
    investigation_steps: list[Step]
    proposed_actions: list[ProposedAction]
    report_title: str
    analyst: str
    injection_attempt_detected: bool = False
    redactions: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _clean(text, limit: int = 2000) -> str:
    return _CONTROL.sub("", str(text or "")).strip()[:limit]


def _list(value) -> list:
    return value if isinstance(value, list) else []


def _ref_key(ref: str) -> tuple[str, int]:
    return ref[0], int(ref[1:])


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _target_fits(kind: str, target: str) -> bool:
    """block_ip takes an address, the account actions take a name, the host actions take either."""
    if kind == "block_ip":
        return _is_ip(target)
    if kind in ("disable_account", "reset_credentials"):
        return bool(_NAME.fullmatch(target)) and not _is_ip(target)
    return _is_ip(target) or bool(_NAME.fullmatch(target))


def _names(text: str, indicator: str) -> bool:
    """The indicator appears in the text as a whole token: dave but not davey, 10.0.1.2 but not 10.0.1.20."""
    return re.search(rf"(?<![\w.-]){re.escape(indicator)}(?![\w-]|\.\w)", text) is not None


def validate_analysis(raw: dict, case, *, analyst: str, allowed_actions: dict[str, str],
                      redactions: dict[str, int] | None = None) -> Analysis:
    """Turn an untrusted analysis dict (from a model or a rule engine) into an Analysis, enforcing the rules.

    Facts must cite evidence that exists and that mentions every account, address and host the fact names;
    other facts are demoted to hypotheses. Actions must use an allowed type and name a target of the right kind
    that appears in the case data and in the evidence cited for it; anything else is dropped and recorded in
    `warnings`. Severity and confidence must be in their enums. An injection attempt found by the
    deterministic detector, in the log lines, the alerts or the title, is always reported, whatever the backend
    said.
    """
    refs = case.references()
    indicators = case.indicators()
    warnings: list[str] = []

    severity = _clean(raw.get("severity"), 20).lower()
    if severity not in SEVERITIES:
        warnings.append(f"severity {severity!r} not recognised; set to medium")
        severity = "medium"

    facts: list[Fact] = []
    hypotheses: list[Hypothesis] = []
    for item in _list(raw.get("facts")):
        if not isinstance(item, dict):
            continue
        statement = _clean(item.get("statement"))
        evidence = {e for e in _list(item.get("evidence")) if isinstance(e, str) and _REF.match(e) and e in refs}
        evidence = sorted(evidence, key=_ref_key)[:40]
        if not statement:
            continue
        cited = "\n".join(case.text_of(e) for e in evidence)
        unsupported = [i for i in indicators if i in statement and _names(statement, i) and not _names(cited, i)]
        if not evidence:
            problem = "without valid evidence"
        elif unsupported:
            problem = f"naming {min(unsupported)!r}, which its evidence does not mention,"
        else:
            facts.append(Fact(statement, evidence))
            continue
        warnings.append(f"fact {problem} demoted to hypothesis: {statement[:80]}")
        hypotheses.append(Hypothesis(statement, "low", "The cited evidence does not support it; verify against the "
                                                        "raw data before relying on it."))
    for item in _list(raw.get("hypotheses")):
        if not isinstance(item, dict) or not _clean(item.get("statement")):
            continue
        confidence = _clean(item.get("confidence"), 10).lower()
        hypotheses.append(Hypothesis(_clean(item.get("statement")),
                                     confidence if confidence in CONFIDENCES else "low",
                                     _clean(item.get("verify_by")) or "Not specified."))

    steps = [Step(_clean(s.get("description")), _clean(s.get("rationale")))
             for s in _list(raw.get("investigation_steps")) if isinstance(s, dict) and _clean(s.get("description"))]

    actions: list[ProposedAction] = []
    for item in _list(raw.get("proposed_actions")):
        if not isinstance(item, dict):
            continue
        kind, target = _clean(item.get("type"), 40), _clean(item.get("target"), 200)
        evidence = [e for e in _list(item.get("evidence")) if isinstance(e, str) and e in refs]
        if kind not in allowed_actions:
            warnings.append(f"proposed action {kind!r} is not an allowed action; dropped")
        elif target not in indicators:
            warnings.append(f"proposed {kind} on {target!r} dropped: the target does not appear in the case data")
        elif not _target_fits(kind, target):
            warnings.append(f"proposed {kind} on {target!r} dropped: not a valid target for {kind}")
        elif not any(_names(case.text_of(e), target) for e in evidence):
            warnings.append(f"proposed {kind} on {target!r} dropped: none of its evidence mentions the target")
        elif not any(a.type == kind and a.target == target for a in actions):
            actions.append(ProposedAction(kind, target, _clean(item.get("reason")), evidence))

    injected = [f"L{n}" for n in case.injection_lines()] + [f"A{n}" for n in case.injection_in_alerts()]
    title_injected = looks_injected(case.title)
    if title_injected:
        warnings.append("the case title contains text addressed to an automated analyst")
    if injected:
        facts.insert(0, Fact("The submitted data contains text addressed to an automated analyst (instructions "
                             "to ignore rules, change the verdict or take actions). It is treated as an attempted "
                             "prompt injection and as evidence of tampering, never as guidance.", injected))
    if (injected or title_injected) and SEVERITIES.index(severity) > SEVERITIES.index("medium"):
        warnings.append("severity raised to medium because the data contains an injection attempt")
        severity = "medium"

    return Analysis(
        summary=_clean(raw.get("summary")) or "No summary produced.",
        severity=severity,
        why_suspicious=_clean(raw.get("why_suspicious")),
        facts=facts, hypotheses=hypotheses, investigation_steps=steps, proposed_actions=actions,
        report_title=_clean(raw.get("report_title"), 200) or case.title,
        analyst=analyst,
        injection_attempt_detected=bool(injected or title_injected or raw.get("injection_attempt_detected")),
        redactions=dict(redactions or {}), warnings=warnings,
    )
