# Contributing

Bug reports, detection rules, redaction patterns and connector designs are welcome.

## Set up

```bash
git clone https://github.com/Leonard-Opasanjo/secops-copilot.git
cd secops-copilot
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

The tests need no network and no API key. To try the Claude backend, set `ANTHROPIC_API_KEY` or log in with the
Anthropic CLI.

## Before you open a pull request

```bash
ruff check .
pytest
bandit -q -c pyproject.toml -r secops_copilot
pip-audit
```

## Adding an offline rule

Rules live in `secops_copilot/analyst_offline.py`. A rule reads the numbered lines, appends facts with their
line references, hypotheses with a confidence and a way to verify, and proposed actions from the allow-list in
`actions.py`. Add a sample or extend one under `secops_copilot/samples/`, and pin the verdict in `tests/test_offline_analyst.py`
down to the evidence references.

## Adding a redaction pattern

Add a `(name, compiled regex, replacement)` tuple to `PATTERNS` in `secops_copilot/redact.py`, a positive case to
`test_each_pattern` and, more importantly, a negative case to `test_log_lines_are_left_alone`. A pattern that
mangles ordinary log syntax does more harm than a missed secret, because it destroys the evidence the analyst
needs.

## Changing the prompt or the schema

`SYSTEM_PROMPT` and `OUTPUT_SCHEMA` in `secops_copilot/analyst_claude.py` are covered by
`tests/test_claude_analyst.py`. Keep the rules about data-as-evidence, evidence citation and no-action in the
prompt; add a test for any new field in the schema; and remember that `validate_analysis` is the real enforcement.

## Writing a connector

Implement a class with `execute(self, kind: str, target: str) -> str` and pass it to `Store(path,
connector=...)`. The store calls it only for actions in the `approved` state. Log what you changed and how to
undo it; the string you return goes into the audit trail. Do not add a code path that bypasses the approval gate.

## Security issues

See [SECURITY.md](SECURITY.md).
