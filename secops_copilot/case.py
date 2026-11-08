"""A case: the alerts and log lines under analysis, numbered so that evidence can be cited precisely."""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field

MAX_LINES = 5000
MAX_LINE = 2000
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER = re.compile(r"(?:for (?:invalid )?(?:user )?|user[= ]|USER=|sudo:\s+|name=)([A-Za-z0-9._-]{1,64})")
_SYSLOG_HOST = re.compile(r"^(?:[A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d|\S+T\S+)\s+([A-Za-z0-9][A-Za-z0-9.-]{1,80})\s")
INJECTION = re.compile(
    r"(?i)(ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|guidance)"
    r"|disregard\s+(?:the\s+|your\s+|all\s+)?(?:previous\s+|prior\s+|earlier\s+|above\s+)?(?:instructions|rules|guidance)"
    r"|you\s+are\s+now\s|new\s+instructions?:|system\s+prompt|\bai\s+analyst\b"
    r"|\b(?:note|message|instructions?)\s+(?:to|for)\s+(?:the\s+)?(?:ai|llm|model|assistant|copilot)\b"
    r"|mark\s+(?:this|it|the\s+alert|everything)\s+as\s+(?:benign|safe|resolved|a\s+false\s+positive)"
    r"|(?:auto[- ]?)?approve\s+(?:(?:all|the|this)\s+)?(?:actions?|request)|do\s+not\s+(?:report|escalate|flag))")
_INVISIBLE = re.compile(r"[\u00ad\u200b-\u200f\u2060-\u2064\ufeff]")


def looks_injected(text: str) -> bool:
    """The injection detector, after folding look-alike characters and removing invisible ones."""
    return bool(INJECTION.search(_INVISIBLE.sub("", unicodedata.normalize("NFKC", text))))


def _strings(value):
    """Every key and string value in a decoded JSON value."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)
    elif isinstance(value, str):
        yield value


class CaseError(ValueError):
    pass


def host_of(line: str) -> str | None:
    m = _SYSLOG_HOST.match(line)
    return m.group(1) if m else None


@dataclass
class Case:
    title: str
    alerts: list[dict] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)
    source: str = ""

    @classmethod
    def load(cls, title: str, logs: str = "", alerts_json: str = "", source: str = "") -> Case:
        alerts: list[dict] = []
        if alerts_json and alerts_json.strip():
            try:
                parsed = json.loads(alerts_json)
            except json.JSONDecodeError as e:
                raise CaseError(f"alerts must be JSON: {e}") from e
            if isinstance(parsed, dict):
                parsed = parsed.get("alerts", [parsed])
            if not isinstance(parsed, list) or not all(isinstance(a, dict) for a in parsed):
                raise CaseError("alerts must be a JSON list of objects")
            alerts = parsed[:500]
        lines = [ln.rstrip("\r")[:MAX_LINE] for ln in (logs or "").splitlines() if ln.strip()]
        if len(lines) > MAX_LINES:
            raise CaseError(f"too many log lines ({len(lines)}); the limit is {MAX_LINES}")
        if not lines and not alerts:
            raise CaseError("a case needs at least one alert or one log line")
        return cls(title=(title or "Untitled case").strip()[:200], alerts=alerts, lines=lines, source=source)

    def references(self) -> set[str]:
        return {f"L{i}" for i in range(1, len(self.lines) + 1)} | {f"A{i}" for i in range(1, len(self.alerts) + 1)}

    def text_of(self, ref: str) -> str:
        if ref.startswith("L"):
            return self.lines[int(ref[1:]) - 1]
        return json.dumps(self.alerts[int(ref[1:]) - 1], sort_keys=True)

    def indicators(self) -> set[str]:
        """Every IP, username and host name that appears in the data: the only valid action targets."""
        found: set[str] = set()
        for text in self.lines:
            found.update(_IP.findall(text))
            found.update(_USER.findall(text))
            host = host_of(text)
            if host:
                found.add(host)
        for alert in self.alerts:
            for key in ("source_ip", "src_ip", "ip", "dest_ip", "destination_ip", "user", "username", "account",
                        "host", "hostname", "asset"):
                value = alert.get(key)
                if isinstance(value, str) and value.strip():
                    found.add(value.strip())
            for value in alert.values():
                if isinstance(value, str):
                    found.update(_IP.findall(value))
        return found

    def injection_lines(self) -> list[int]:
        return [i for i, ln in enumerate(self.lines, 1) if looks_injected(ln)]

    def injection_in_alerts(self) -> list[int]:
        return [i for i, a in enumerate(self.alerts, 1) if any(looks_injected(s) for s in _strings(a))]

    def as_prompt_data(self) -> str:
        parts = [f"Case title: {self.title}", "", "<alerts>"]
        parts += [f"A{i}: {json.dumps(a, sort_keys=True)}" for i, a in enumerate(self.alerts, 1)] or ["(none)"]
        parts += ["</alerts>", "", "<logs>"]
        parts += [f"L{i}: {ln}" for i, ln in enumerate(self.lines, 1)] or ["(none)"]
        parts += ["</logs>"]
        return "\n".join(parts)
