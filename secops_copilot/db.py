"""SQLite store: cases, their analyses, proposed actions with the approval gate, and an audit trail."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from .actions import ACTIONS, STATUSES, ApprovalRequired, DryRunConnector
from .models import Analysis

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY, title TEXT NOT NULL, source TEXT NOT NULL DEFAULT '', alerts_json TEXT NOT NULL,
    logs TEXT NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL, analyst TEXT NOT NULL DEFAULT 'offline',
    error TEXT, analysis_json TEXT, analysed_at TEXT);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id), type TEXT NOT NULL, target TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '', evidence_json TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'proposed',
    decided_by TEXT, decided_at TEXT, note TEXT NOT NULL DEFAULT '', result TEXT);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id), at TEXT NOT NULL, actor TEXT NOT NULL,
    event TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS actions_case ON actions(case_id);
CREATE INDEX IF NOT EXISTS audit_case ON audit(case_id);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | Path, connector: DryRunConnector | None = None):
        self.path = str(path)
        self.connector = connector or DryRunConnector()
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON")
        return c

    def audit(self, case_id: int, actor: str, event: str, detail: str = "") -> None:
        with self._conn() as c:
            c.execute("INSERT INTO audit (case_id, at, actor, event, detail) VALUES (?,?,?,?,?)",
                      (case_id, _now(), actor[:100], event, detail[:2000]))

    # cases ---------------------------------------------------------------------------------------
    def create_case(self, title: str, alerts_json: str, logs: str, analyst: str, source: str = "") -> int:
        with self._conn() as c:
            cur = c.execute("INSERT INTO cases (title, source, alerts_json, logs, created_at, status, analyst) "
                            "VALUES (?,?,?,?,?,'queued',?)", (title, source, alerts_json or "", logs or "", _now(),
                                                              analyst))
            case_id = cur.lastrowid
        self.audit(case_id, "system", "case_created", f"analyst={analyst}")
        return case_id

    def start(self, case_id: int) -> None:
        with self._conn() as c:
            c.execute("UPDATE cases SET status = 'running' WHERE id = ?", (case_id,))

    def fail(self, case_id: int, error: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE cases SET status = 'failed', error = ?, analysed_at = ? WHERE id = ?",
                      (error[:1000], _now(), case_id))
        self.audit(case_id, "system", "analysis_failed", error[:500])

    def finish(self, case_id: int, analysis: Analysis) -> None:
        with self._conn() as c:
            c.execute("UPDATE cases SET status = 'done', analysis_json = ?, analyst = ?, analysed_at = ?, error = NULL "
                      "WHERE id = ?", (json.dumps(analysis.to_dict()), analysis.analyst, _now(), case_id))
            c.execute("DELETE FROM actions WHERE case_id = ? AND status = 'proposed'", (case_id,))
            for a in analysis.proposed_actions:
                c.execute("INSERT INTO actions (case_id, type, target, reason, evidence_json) VALUES (?,?,?,?,?)",
                          (case_id, a.type, a.target, a.reason, json.dumps(a.evidence)))
        self.audit(case_id, "system", "analysis_done",
                   f"{analysis.analyst}: {analysis.severity}, {len(analysis.proposed_actions)} action(s) proposed")

    def get_case(self, case_id: int) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
            if row is None:
                return None
            actions = [self._action(r) for r in c.execute("SELECT * FROM actions WHERE case_id = ? ORDER BY id",
                                                           (case_id,))]
            audit = [dict(r) for r in c.execute("SELECT * FROM audit WHERE case_id = ? ORDER BY id", (case_id,))]
        case = dict(row)
        case["analysis"] = json.loads(case.pop("analysis_json") or "null")
        case["actions"] = actions
        case["audit"] = audit
        return case

    @staticmethod
    def _action(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["evidence"] = json.loads(d.pop("evidence_json") or "[]")
        d["description"] = ACTIONS.get(d["type"], d["type"])
        return d

    def list_cases(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT id, title, created_at, status, analyst, analysed_at, analysis_json FROM cases "
                             "ORDER BY id DESC").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                analysis = json.loads(d.pop("analysis_json") or "null")
                d["severity"] = analysis["severity"] if analysis else None
                d["summary"] = analysis["summary"] if analysis else ""
                d["pending"] = c.execute("SELECT COUNT(*) FROM actions WHERE case_id = ? AND status = 'proposed'",
                                         (r["id"],)).fetchone()[0]
                out.append(d)
            return out

    # actions: the approval gate ------------------------------------------------------------------
    def get_action(self, action_id: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM actions WHERE id = ?", (action_id,)).fetchone()
            return self._action(r) if r else None

    def decide(self, action_id: int, decision: str, by: str, note: str = "") -> dict:
        """A human approves or rejects a proposed action. Only `proposed` actions can be decided."""
        if decision not in ("approved", "rejected"):
            raise ValueError("decision must be approved or rejected")
        by = (by or "").strip()
        if not by:
            raise ValueError("the name of the person deciding is required")
        action = self.get_action(action_id)
        if action is None:
            raise KeyError(action_id)
        if action["status"] != "proposed":
            raise ValueError(f"action is already {action['status']}")
        with self._conn() as c:
            c.execute("UPDATE actions SET status = ?, decided_by = ?, decided_at = ?, note = ? WHERE id = ?",
                      (decision, by[:100], _now(), note.strip()[:1000], action_id))
        self.audit(action["case_id"], by, f"action_{decision}", f"{action['type']} {action['target']}: {note[:200]}")
        return self.get_action(action_id)

    def execute(self, action_id: int, by: str) -> dict:
        """Run an action through the connector. Refuses anything a human has not approved."""
        action = self.get_action(action_id)
        if action is None:
            raise KeyError(action_id)
        if action["status"] != "approved":
            raise ApprovalRequired(f"action {action_id} is {action['status']}; only approved actions can run")
        result = self.connector.execute(action["type"], action["target"])
        with self._conn() as c:
            c.execute("UPDATE actions SET status = 'executed', result = ? WHERE id = ?", (result[:1000], action_id))
        self.audit(action["case_id"], (by or "unknown")[:100], "action_executed",
                   f"{action['type']} {action['target']}: {result[:200]}")
        return self.get_action(action_id)

    def status_counts(self, case_id: int) -> dict[str, int]:
        with self._conn() as c:
            rows = c.execute("SELECT status, COUNT(*) FROM actions WHERE case_id = ? GROUP BY status", (case_id,))
            counts = {s: 0 for s in STATUSES}
            counts.update({r[0]: r[1] for r in rows})
            return counts
