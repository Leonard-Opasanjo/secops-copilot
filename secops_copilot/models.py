"""The analysis model shared by every analyst backend, and the validation that keeps it honest."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "informational")
CONFIDENCES = ("low", "medium", "high")
_REF = re.compile(r"^[AL]\d+$")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


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


def _ref_key(ref: str) -> tuple[str, int]:
    return ref[0], int(ref[1:])


def validate_analysis(raw: dict, case, *, analyst: str, allowed_actions: dict[str, str],
                      redactions: dict[str, int] | None = None) -> Analysis:
    """Turn an untrusted analysis dict (from a model or a rule engine) into an Analysis, enforcing the rules.

    Facts must cite evidence that exists; unsupported facts are demoted to hypotheses. Actions must use an
    allowed type and name a target that appears in the case data; anything else is dropped and recorded in
    `warnings`. Severity and confidence must be in their enums. An injection attempt found by the
    deterministic detector is always reported, whatever the backend said.
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
    for item in raw.get("facts") or []:
        if not isinstance(item, dict):
            continue
        statement = _clean(item.get("statement"))
        evidence = [e for e in (item.get("evidence") or []) if isinstance(e, str) and _REF.match(e) and e in refs]
        if not statement:
            continue
        if evidence:
            facts.append(Fact(statement, sorted(set(evidence), key=_ref_key)[:40]))
        else:
            warnings.append(f"fact without valid evidence demoted to hypothesis: {statement[:80]}")
            hypotheses.append(Hypothesis(statement, "low", "No supporting evidence was cited; verify against the "
                                                            "raw data before relying on it."))
    for item in raw.get("hypotheses") or []:
        if not isinstance(item, dict) or not _clean(item.get("statement")):
            continue
        confidence = _clean(item.get("confidence"), 10).lower()
        hypotheses.append(Hypothesis(_clean(item.get("statement")),
                                     confidence if confidence in CONFIDENCES else "low",
                                     _clean(item.get("verify_by")) or "Not specified."))

    steps = [Step(_clean(s.get("description")), _clean(s.get("rationale")))
             for s in (raw.get("investigation_steps") or []) if isinstance(s, dict) and _clean(s.get("description"))]

    actions: list[ProposedAction] = []
    for item in raw.get("proposed_actions") or []:
        if not isinstance(item, dict):
            continue
        kind, target = _clean(item.get("type"), 40), _clean(item.get("target"), 200)
        if kind not in allowed_actions:
            warnings.append(f"proposed action {kind!r} is not an allowed action; dropped")
            continue
        if target not in indicators:
            warnings.append(f"proposed {kind} on {target!r} dropped: the target does not appear in the case data")
            continue
        evidence = [e for e in (item.get("evidence") or []) if isinstance(e, str) and e in refs]
        actions.append(ProposedAction(kind, target, _clean(item.get("reason")), evidence))

    injected = case.injection_lines()
    if injected:
        facts.insert(0, Fact("The submitted data contains text addressed to an automated analyst (instructions "
                             "to ignore rules, change the verdict or take actions). It is treated as an attempted "
                             "prompt injection and as evidence of tampering, never as guidance.",
                             [f"L{n}" for n in injected]))
        if SEVERITIES.index(severity) > SEVERITIES.index("medium"):
            warnings.append("severity raised to medium because the data contains an injection attempt")
            severity = "medium"

    return Analysis(
        summary=_clean(raw.get("summary")) or "No summary produced.",
        severity=severity,
        why_suspicious=_clean(raw.get("why_suspicious")),
        facts=facts, hypotheses=hypotheses, investigation_steps=steps, proposed_actions=actions,
        report_title=_clean(raw.get("report_title"), 200) or case.title,
        analyst=analyst, injection_attempt_detected=bool(injected) or bool(raw.get("injection_attempt_detected")),
        redactions=dict(redactions or {}), warnings=warnings,
    )
