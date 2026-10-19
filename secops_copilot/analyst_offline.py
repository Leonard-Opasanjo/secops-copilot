"""A deterministic, rule-based analyst. Works with no network and no key; also the baseline for the tests."""

from __future__ import annotations

import re
from collections import defaultdict

from .actions import ACTIONS
from .case import Case, host_of
from .models import Analysis, validate_analysis

AUTH_FAIL = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)")
AUTH_OK = re.compile(r"Accepted (\S+) for (\S+) from (\S+)")
SUDO = re.compile(r"sudo:\s+(\S+) : .*COMMAND=(.*)$")
NEW_USER = re.compile(r"useradd\[\d+\]: new user: name=([^,\s]+)")
GROUP_CHANGE = re.compile(r"usermod\[\d+\]: add '([^']+)' to (?:shadow )?group '([^']+)'")
CRON = re.compile(r"crontab\[\d+\]: \((\S+)\) (?:REPLACE|BEGIN EDIT)")
PRIVATE_PREFIX = ("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")
ORDER = ("informational", "low", "medium", "high", "critical")


def _is_private(ip: str) -> bool:
    return ip.startswith(PRIVATE_PREFIX) or ip in ("::1", "localhost")


def analyse_offline(case: Case) -> Analysis:
    fails: dict[str, list[tuple[int, str]]] = defaultdict(list)
    successes: list[tuple[int, str, str, str]] = []
    sudo_cmds: list[tuple[int, str, str]] = []
    new_users: list[tuple[int, str]] = []
    group_changes: list[tuple[int, str, str]] = []
    crons: list[tuple[int, str]] = []
    for n, ln in enumerate(case.lines, 1):
        if m := AUTH_FAIL.search(ln):
            fails[m.group(2)].append((n, m.group(1)))
        elif m := AUTH_OK.search(ln):
            successes.append((n, m.group(1), m.group(2), m.group(3)))
        if m := SUDO.search(ln):
            sudo_cmds.append((n, m.group(1), m.group(2).strip()))
        if m := NEW_USER.search(ln):
            new_users.append((n, m.group(1)))
        if m := GROUP_CHANGE.search(ln):
            group_changes.append((n, m.group(1), m.group(2)))
        if m := CRON.search(ln):
            crons.append((n, m.group(1)))

    facts, hypotheses, steps, actions, reasons = [], [], [], [], []
    severity = "informational"
    suspect_users: set[str] = set()
    suspect_hosts: set[str] = set()

    def raise_to(level: str) -> None:
        nonlocal severity
        if ORDER.index(level) > ORDER.index(severity):
            severity = level

    def add_action(kind: str, target: str, reason: str, evidence: list[str]) -> None:
        if not any(a["type"] == kind and a["target"] == target for a in actions):
            actions.append({"type": kind, "target": target, "reason": reason, "evidence": evidence[:10]})

    for i, alert in enumerate(case.alerts, 1):
        name = alert.get("rule") or alert.get("name") or alert.get("title") or "alert"
        desc = alert.get("description")
        facts.append({"statement": f"Alert A{i} fired: {name}" + (f" ({desc})" if desc else ""), "evidence": [f"A{i}"]})
        sev = str(alert.get("severity", "")).lower()
        if sev in ORDER:
            raise_to(sev)

    for ip, items in fails.items():
        users = sorted({u for _, u in items})
        lines = [f"L{n}" for n, _ in items]
        if len(items) >= 5 or len(users) >= 3:
            facts.append({"statement": f"{len(items)} failed logins from {ip} against {len(users)} account(s): "
                                       f"{', '.join(users[:6])}{'…' if len(users) > 6 else ''}.", "evidence": lines})
            reasons.append(f"repeated authentication failures from {ip}")
            raise_to("high" if len(users) >= 3 or len(items) >= 20 else "medium")
            if _is_private(ip):
                hypotheses.append({"statement": f"{ip} is an internal address; the failures may be a user with a "
                                                "wrong password or a script with stale credentials.",
                                   "confidence": "medium", "verify_by": "Ask the owner of the host at that address."})
            else:
                add_action("block_ip", ip, "Source of repeated failed logins with no legitimate use.", lines)
        else:
            facts.append({"statement": f"{len(items)} failed login(s) from {ip} for {', '.join(users)}.",
                          "evidence": lines})

    for n, method, user, ip in successes:
        prior = [ln for ln, _ in fails.get(ip, []) if ln < n]
        refs = [f"L{x}" for x in prior] + [f"L{n}"]
        host = host_of(case.lines[n - 1])
        if len(prior) >= 3:
            facts.append({"statement": f"A {method} login for {user} from {ip} succeeded (L{n}) after "
                                       f"{len(prior)} failed attempts from the same address.", "evidence": refs})
            hypotheses.append({"statement": f"The account {user} was compromised by password guessing from {ip}.",
                               "confidence": "high",
                               "verify_by": f"Contact {user}; confirm whether they logged in from {ip} at that time; "
                                            "review what the session did."})
            reasons.append(f"successful login for {user} after repeated failures from {ip}")
            raise_to("critical")
            suspect_users.add(user)
            if host:
                suspect_hosts.add(host)
            add_action("disable_account", user, "Likely compromised through password guessing; stop further use "
                                                "until the owner confirms.", refs)
            add_action("reset_credentials", user, "The password was guessed or leaked.", refs)
            if not _is_private(ip):
                add_action("block_ip", ip, "Attacker source address.", refs)
            steps.append({"description": f"Pull every command run by {user} after L{n} (sudo log, shell history, "
                                         "audit log).", "rationale": "Shows what was done with the access."})
        elif not _is_private(ip):
            facts.append({"statement": f"{user} logged in from the external address {ip} (L{n}).",
                          "evidence": [f"L{n}"]})
            hypotheses.append({"statement": f"The login from {ip} may be legitimate remote work or an unauthorised "
                                            "use of valid credentials.", "confidence": "low",
                               "verify_by": f"Confirm with {user} and check the address against the VPN and office "
                                            "ranges."})
            raise_to("low")

    after_suspect = [(n, u, c) for n, u, c in sudo_cmds if u in suspect_users]
    other = [(n, u, c) for n, u, c in sudo_cmds if u not in suspect_users]
    for n, user, cmd in after_suspect:
        facts.append({"statement": f"{user} ran a privileged command after the suspicious login: {cmd[:120]}",
                      "evidence": [f"L{n}"]})
        if f"privileged commands by {user} after the suspicious login" not in reasons:
            reasons.append(f"privileged commands by {user} after the suspicious login")
        raise_to("critical")
        host = host_of(case.lines[n - 1])
        if host:
            suspect_hosts.add(host)
    if other:
        who = ", ".join(sorted({u for _, u, _ in other}))
        facts.append({"statement": f"{len(other)} privileged command(s) by other users ({who}), consistent with "
                                   "routine administration.", "evidence": [f"L{n}" for n, _, _ in other]})

    for n, user in new_users:
        facts.append({"statement": f"A new account '{user}' was created (L{n}).", "evidence": [f"L{n}"]})
        hypotheses.append({"statement": f"The account '{user}' may have been created to keep access, unless a change "
                                        "record exists for it.", "confidence": "medium",
                           "verify_by": "Check the change ticket and ask the administrator who was logged in."})
        reasons.append(f"new account '{user}' created")
        raise_to("medium")
        add_action("disable_account", user, "Unexpected new account; disable until its creation is explained.",
                   [f"L{n}"])
    for n, user, group in group_changes:
        facts.append({"statement": f"'{user}' was added to the '{group}' group (L{n}).", "evidence": [f"L{n}"]})
        if group in ("sudo", "wheel", "admin", "root"):
            reasons.append(f"'{user}' granted administrative group '{group}'")
            raise_to("high")
    for n, user in crons:
        facts.append({"statement": f"The crontab of {user} was changed (L{n}).", "evidence": [f"L{n}"]})
        raise_to("low")

    for host in sorted(suspect_hosts):
        add_action("preserve_evidence", host, "Keep logs and disk state of the affected host before any clean-up.",
                   [])
        if severity == "critical":
            add_action("isolate_host", host, "Contain the host while the extent of the compromise is established.",
                       [])

    steps += [
        {"description": "Confirm the timeline against the raw logs and the alert source, and note any gaps.",
         "rationale": "The analysis only sees the data supplied; missing hours change the picture."},
        {"description": "Search other hosts for the same source addresses and account names.",
         "rationale": "An attacker who succeeded here usually tried elsewhere."},
    ]
    if severity in ("high", "critical"):
        steps.append({"description": "Preserve the evidence before remediation and record who was contacted and when.",
                      "rationale": "Needed for the incident report and for any later review."})

    summary = (f"{severity.capitalize()} severity: " + "; ".join(reasons) + "."
               if reasons else f"{severity.capitalize()} severity: no suspicious pattern was found in the supplied "
                               "data beyond the alerts themselves.")
    raw = {
        "summary": summary, "severity": severity,
        "why_suspicious": ("; ".join(reasons).capitalize() + "." if reasons else
                           "No authentication, account or privilege pattern in the logs matched a known attack shape."),
        "facts": facts, "hypotheses": hypotheses, "investigation_steps": steps, "proposed_actions": actions,
        "report_title": f"Incident: {case.title}",
    }
    return validate_analysis(raw, case, analyst="offline", allowed_actions=ACTIONS)
