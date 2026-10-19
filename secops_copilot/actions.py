"""Response actions: a fixed allow-list, a human approval gate, and a connector that only ever dry-runs here."""

from __future__ import annotations

ACTIONS: dict[str, str] = {
    "block_ip": "Block the address at the perimeter firewall",
    "disable_account": "Disable the user account in the directory",
    "reset_credentials": "Force a credential reset for the account",
    "isolate_host": "Isolate the host from the network",
    "add_to_watchlist": "Add the indicator to the monitoring watch-list",
    "preserve_evidence": "Snapshot and preserve logs and disk state of the host",
}
STATUSES = ("proposed", "approved", "rejected", "executed")


class ApprovalRequired(PermissionError):
    """Raised when something tries to execute an action that no human has approved."""


class DryRunConnector:
    """The only connector shipped. It records what would happen and changes nothing.

    A real deployment replaces this with a class exposing the same `execute` method that talks to the firewall,
    directory or EDR. The approval gate in the store calls it only for actions in the `approved` state.
    """

    def execute(self, kind: str, target: str) -> str:
        if kind not in ACTIONS:
            raise ValueError(f"unknown action {kind!r}")
        return f"DRY RUN: would {ACTIONS[kind].lower()} for {target}"
