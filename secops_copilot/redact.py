"""Remove credentials from text before it leaves the machine. Applied to everything sent to an AI service."""

from __future__ import annotations

import re

PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "[REDACTED:private_key]"),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"), "[REDACTED:aws_access_key]"),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"), "[REDACTED:github_token]"),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED:slack_token]"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED:jwt]"),
    ("bearer_token", re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/-]{16,}=*"), r"\1[REDACTED:bearer_token]"),
    ("url_password", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^/\s@]+@"), r"\1[REDACTED:url_password]@"),
    ("secret_assignment", re.compile(
        # not "pwd" (sudo logs PWD=/path on every line) and not bare "auth" (PAM messages)
        r"(?i)\b(passw(?:or)?d|passphrase|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key)"
        r"(\s*[=:]\s*[\"']?)(?!\[REDACTED)([^\s\"'&,;]{4,})"), r"\1\2[REDACTED:secret]"),
]
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def redact(text: str) -> tuple[str, dict[str, int]]:
    """Return the text with credentials replaced, and a count of replacements by type."""
    counts: dict[str, int] = {}
    for name, pattern, replacement in PATTERNS:
        text, n = pattern.subn(replacement, text)
        if n:
            counts[name] = counts.get(name, 0) + n

    def card(m: re.Match) -> str:
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits):
            counts["card_number"] = counts.get("card_number", 0) + 1
            return "[REDACTED:card_number]"
        return m.group(0)

    text = _CARD.sub(card, text)
    return text, counts
