"""The incident report: Markdown, with facts and hypotheses kept apart and evidence quoted (credentials redacted)."""

from __future__ import annotations

from datetime import UTC, datetime

from . import __version__
from .case import Case
from .redact import redact


def _quote(case: Case, ref: str) -> str:
    text, _ = redact(case.text_of(ref))
    return f"{ref}: {text}"


def incident_report(case: Case, analysis: dict, actions: list[dict] | None = None, generated: datetime | None = None,
                    case_id: int | None = None) -> str:
    generated = generated or datetime.now(UTC)
    lines = [f"# {analysis.get('report_title') or case.title}", ""]
    meta = [f"Severity: **{analysis['severity']}**", f"Analyst backend: {analysis['analyst']}",
            f"Generated: {generated:%Y-%m-%d %H:%M} UTC"]
    if case_id:
        meta.insert(0, f"Case {case_id}")
    lines += [" · ".join(meta), ""]
    if analysis.get("injection_attempt_detected"):
        lines += ["> **Warning:** the submitted data contained text addressed to an automated analyst. It was treated "
                  "as evidence of tampering, not as guidance.", ""]
    lines += ["## Summary", "", analysis["summary"], ""]
    if analysis.get("why_suspicious"):
        lines += ["## Why this is suspicious", "", analysis["why_suspicious"], ""]

    lines += ["## Verified facts", "",
              "Each fact cites the alert (A) or log line (L) that supports it. Quoted evidence has credentials "
              "redacted.", ""]
    if not analysis["facts"]:
        lines.append("No facts could be established from the supplied data.")
    for i, f in enumerate(analysis["facts"], 1):
        lines.append(f"{i}. {f['statement']} *(evidence: {', '.join(f['evidence'])})*")
        for ref in f["evidence"][:6]:
            lines.append(f"   > `{_quote(case, ref)}`")
        if len(f["evidence"]) > 6:
            lines.append(f"   > … {len(f['evidence']) - 6} more lines")
    lines.append("")

    lines += ["## Hypotheses (not verified)", ""]
    if not analysis["hypotheses"]:
        lines.append("None.")
    for h in analysis["hypotheses"]:
        lines.append(f"- **{h['confidence']} confidence:** {h['statement']} *Verify by:* {h['verify_by']}")
    lines.append("")

    lines += ["## Investigation steps", ""]
    for i, s in enumerate(analysis["investigation_steps"], 1):
        lines.append(f"{i}. {s['description']}" + (f" — {s['rationale']}" if s.get("rationale") else ""))
    if not analysis["investigation_steps"]:
        lines.append("None proposed.")
    lines.append("")

    lines += ["## Response actions", "",
              "Every action below is a proposal. Nothing is carried out without a named person approving it.", ""]
    rows = actions if actions is not None else [{"type": a["type"], "target": a["target"], "reason": a["reason"],
                                                 "status": "proposed", "decided_by": None, "note": ""}
                                                for a in analysis["proposed_actions"]]
    if rows:
        lines += ["| Action | Target | Reason | Status | Decided by | Note |", "|---|---|---|---|---|---|"]
        for a in rows:
            lines.append(f"| {a['type']} | `{a['target']}` | {a['reason']} | {a['status']} | "
                         f"{a.get('decided_by') or ''} | {a.get('note') or ''} |")
    else:
        lines.append("No actions proposed.")
    lines.append("")

    if analysis.get("warnings"):
        lines += ["## Validation notes", ""] + [f"- {w}" for w in analysis["warnings"]] + [""]
    if analysis.get("redactions"):
        total = sum(analysis["redactions"].values())
        lines += [f"Before the AI service saw the data, {total} credential-like value(s) were redacted "
                  f"({', '.join(f'{k}: {v}' for k, v in analysis['redactions'].items())}).", ""]
    lines += ["---", f"Drafted by SecOps Copilot {__version__}. "
                     "Reviewed by: ______________________  Date: ____________"]
    return "\n".join(lines) + "\n"
