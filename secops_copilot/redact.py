"""Remove credentials from text before it leaves the machine. Applied to everything sent to an AI service."""

from __future__ import annotations

import re

PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "[REDACTED:private_key]"),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"), "[REDACTED:aws_access_key]"),
    ("github_token", re.compile(r"\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|github_pat_\w{22,})"),
     "[REDACTED:github_token]"),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED:slack_token]"),
    ("api_key", re.compile(r"\b(?:sk[-_][A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35})"), "[REDACTED:api_key]"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED:jwt]"),
    ("bearer_token", re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/-]{16,}=*"), r"\1[REDACTED:bearer_token]"),
    ("basic_auth", re.compile(r"(?i)\b(authorization:\s*basic\s+)[A-Za-z0-9+/]{4,}=*"), r"\1[REDACTED:basic_auth]"),
    ("cookie", re.compile(r"(?i)\b((?:set-)?cookie:\s*)[^\"\r\n]+"), r"\1[REDACTED:cookie]"),
    ("url_password", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^/\s@]+@"), r"\1[REDACTED:url_password]@"),
    # mysql -pSECRET (no space: "-p name" is a database) and sshpass -p SECRET on command lines
    ("cli_password", re.compile(r"(\b(?i:mysql\w*|mariadb\w*)\b[^\n]*?\s-p|\b(?i:sshpass)\s+-p\s*)(?!\[REDACTED)(\S+)"),
     r"\1[REDACTED:secret]"),
    ("secret_assignment", re.compile(
        # not "pwd" (sudo logs PWD=/path on every line) and not bare "auth" (PAM messages); a "_" before the name
        # still counts (DB_PASSWORD=, AWS_SECRET_ACCESS_KEY=), and so does JSON in a log line ("password": "...")
        r"(?i)(?<![A-Za-z0-9])(passw(?:or)?d|passphrase|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret"
        r"|private[_-]?key)([\"']?\s*[=:]\s*[\"']?)(?!\[REDACTED)([^\s\"'&,;]{4,})"), r"\1\2[REDACTED:secret]"),
]
# a JSON key that names a secret, such as "password", "api_key" or "db_password": its whole value is removed
_SECRET_KEY = re.compile(r"(?i)(?:\w*[_-])?(?:passw(?:or)?d|passphrase|secret|token|api[_-]?key|access[_-]?key"
                         r"|private[_-]?key)")
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
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


def redact(text: str, counts: dict[str, int] | None = None) -> tuple[str, dict[str, int]]:
    """Return the text with credentials replaced, and a count of replacements by type (added to `counts` if given)."""
    counts = {} if counts is None else counts
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


def redact_lines(lines: list[str], counts: dict[str, int] | None = None) -> list[str]:
    """Redact log lines one at a time, keeping their numbering. A private key spread over several lines is removed."""
    counts = {} if counts is None else counts
    out, in_key = [], False
    for ln in lines:
        if in_key:
            in_key, ln = not _PEM_END.search(ln), "[REDACTED:private_key]"
        elif (m := _PEM_BEGIN.search(ln)) and not _PEM_END.search(ln, m.end()):
            in_key, ln = True, ln[:m.start()] + "[REDACTED:private_key]"
            counts["private_key"] = counts.get("private_key", 0) + 1
        out.append(redact(ln, counts)[0])
    return out


def redact_json(value, counts: dict[str, int] | None = None):
    """Redact every string in a decoded JSON value (an alert). A string under a secret-named key is replaced whole."""
    counts = {} if counts is None else counts
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(v, str) and len(v) >= 4 and _SECRET_KEY.fullmatch(str(k)):
                counts["secret_assignment"] = counts.get("secret_assignment", 0) + 1
                out[k] = "[REDACTED:secret]"
            else:
                out[k] = redact_json(v, counts)
        return out
    if isinstance(value, list):
        return [redact_json(v, counts) for v in value]
    return redact(value, counts)[0] if isinstance(value, str) else value
