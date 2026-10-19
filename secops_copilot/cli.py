"""Command line: analyse a case from files, run the dashboard, load the sample cases."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .analyst_claude import AnalystError, ClaudeAnalyst, claude_available
from .analyst_offline import analyse_offline
from .case import Case, CaseError
from .report import incident_report

SAMPLES = Path(__file__).resolve().parent / "samples"


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secops-copilot",
                                description="AI security analyst with cited evidence and human approval gates")
    p.add_argument("--version", action="version", version=f"secops-copilot {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyse", help="analyse alerts and logs from files")
    a.add_argument("--logs", metavar="FILE", help="text file with log lines")
    a.add_argument("--alerts", metavar="FILE", help="JSON file with a list of alert objects")
    a.add_argument("--title", default="", help="case title")
    a.add_argument("--analyst", choices=["offline", "claude"], default="offline")
    a.add_argument("--report", metavar="FILE", help="write the Markdown incident report")
    a.add_argument("--json", metavar="FILE", help="write the analysis as JSON")
    a.add_argument("--db", metavar="PATH", default=os.environ.get("SECOPS_DB", "secops.db"))
    a.add_argument("--no-save", action="store_true", help="do not record the case in the database")

    s = sub.add_parser("serve", help="run the dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--db", metavar="PATH", default=os.environ.get("SECOPS_DB", "secops.db"))

    d = sub.add_parser("demo", help="load and analyse the bundled sample cases with the offline analyst")
    d.add_argument("--db", metavar="PATH", default=os.environ.get("SECOPS_DB", "secops.db"))
    return p


def _print(analysis) -> None:
    d = analysis.to_dict() if hasattr(analysis, "to_dict") else analysis
    print(f"[{d['severity']}] {d['summary']}")
    print(f"analyst: {d['analyst']}" + (f" · redacted: {d['redactions']}" if d.get("redactions") else ""))
    print("facts:")
    for f in d["facts"]:
        print(f"  - {f['statement']}  ({', '.join(f['evidence'])})")
    print("hypotheses:")
    for h in d["hypotheses"]:
        print(f"  - [{h['confidence']}] {h['statement']}")
    print("proposed actions (need approval):")
    for a in d["proposed_actions"]:
        print(f"  - {a['type']} {a['target']}: {a['reason']}")
    if not d["proposed_actions"]:
        print("  - none")
    for w in d.get("warnings", []):
        print(f"note: {w}")


def analyse_cmd(args: argparse.Namespace) -> int:
    logs = Path(args.logs).read_text(encoding="utf-8", errors="replace") if args.logs else ""
    alerts = Path(args.alerts).read_text(encoding="utf-8") if args.alerts else ""
    title = args.title or (Path(args.logs or args.alerts).stem if (args.logs or args.alerts) else "case")
    case = Case.load(title, logs, alerts, source=args.logs or args.alerts or "")
    if args.analyst == "claude":
        if not claude_available():
            raise AnalystError("no Anthropic credentials configured (ANTHROPIC_API_KEY or `ant auth login`)")
        analysis = ClaudeAnalyst().analyse(case)
    else:
        analysis = analyse_offline(case)
    actions = None
    if not args.no_save:
        from .db import Store

        db = Store(args.db)
        case_id = db.create_case(case.title, alerts, logs, args.analyst, source=case.source)
        db.finish(case_id, analysis)
        actions = db.get_case(case_id)["actions"]
        print(f"saved as case {case_id} in {args.db}")
    _print(analysis)
    if args.report:
        Path(args.report).write_text(incident_report(case, analysis.to_dict(), actions), encoding="utf-8")
        print(f"report written to {args.report}")
    if args.json:
        Path(args.json).write_text(json.dumps(analysis.to_dict(), indent=2), encoding="utf-8")
        print(f"json written to {args.json}")
    return 0


def demo_cmd(args: argparse.Namespace) -> int:
    from .db import Store

    db = Store(args.db)
    for folder in sorted(p for p in SAMPLES.iterdir() if p.is_dir()):
        logs = (folder / "logs.txt").read_text(encoding="utf-8") if (folder / "logs.txt").exists() else ""
        alerts = (folder / "alerts.json").read_text(encoding="utf-8") if (folder / "alerts.json").exists() else ""
        title = folder.name.replace("-", " ").capitalize()
        case = Case.load(title, logs, alerts, source=str(folder))
        case_id = db.create_case(title, alerts, logs, "offline", source=str(folder))
        db.finish(case_id, analyse_offline(case))
        print(f"case {case_id}: {title}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "analyse":
            return analyse_cmd(args)
        if args.command == "demo":
            return demo_cmd(args)
        from .web import serve

        serve(args.host, args.port, args.db)
        return 0
    except (CaseError, AnalystError, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
