import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "secops_copilot" / "samples"


def sample(name: str):
    folder = SAMPLES / name
    logs = (folder / "logs.txt").read_text() if (folder / "logs.txt").exists() else ""
    alerts = (folder / "alerts.json").read_text() if (folder / "alerts.json").exists() else ""
    return logs, alerts


class FakeMessages:
    """Stands in for client.messages / client.beta.messages: records the request, returns a canned reply."""

    def __init__(self, reply, stop_reason="end_turn", stop_details=None):
        self.reply, self.stop_reason, self.stop_details = reply, stop_reason, stop_details
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        text = self.reply if isinstance(self.reply, str) else json.dumps(self.reply)
        return SimpleNamespace(stop_reason=self.stop_reason, stop_details=self.stop_details,
                               content=[SimpleNamespace(type="text", text=text)],
                               usage=SimpleNamespace(input_tokens=100, output_tokens=50, cache_read_input_tokens=0,
                                                     cache_creation_input_tokens=0))


class FakeClient:
    def __init__(self, reply, **kw):
        self.messages = FakeMessages(reply, **kw)
        self.beta = SimpleNamespace(messages=self.messages)


@pytest.fixture
def fake_client():
    return lambda reply, **kw: FakeClient(reply, **kw)


@pytest.fixture
def client(tmp_path):
    from fastapi.testclient import TestClient

    from secops_copilot import web
    from secops_copilot.db import Store

    web.app.state.store = Store(tmp_path / "t.db")
    with TestClient(web.app) as c:
        yield c
    del web.app.state.store
