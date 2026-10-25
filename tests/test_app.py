"""End-to-end UI test: run detection and an investigation through frontend/app.py."""
import json
from pathlib import Path

from streamlit.testing.v1 import AppTest

from backend import config
from agent import investigator
from test_investigator import GOOD_REPORT

APP = str(Path(__file__).resolve().parents[1] / "frontend" / "app.py")


def test_detect_and_investigate_through_the_ui(db, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", db)
    # Alert 2 is the port-spread alert (3.1x over), which the UI selects first.
    calls = iter([
        {"message": {"content": "", "tool_calls": [
            {"function": {"name": "get_alert_details", "arguments": {"alert_id": 2}}}]}},
        {"message": {"content": "I have enough facts."}},
        {"message": {"content": json.dumps(GOOD_REPORT)}},
    ])
    monkeypatch.setattr(investigator, "chat", lambda *a, **k: next(calls))
    monkeypatch.setattr(investigator, "ollama_status", lambda: {"running": True, "models": ["qwen3:1.7b"]})

    at = AppTest.from_file(APP, default_timeout=60).run()
    assert at.selectbox[0].value == "sample_data/portscan_sample.csv"
    assert any("How it works" in m.value for m in at.markdown)  # empty state before detection

    next(b for b in at.button if "Run detection" in b.label).click().run()
    assert "Detection complete: 2 alert(s) in 24,167 flows" in at.toast[0].value
    assert [m.value for m in at.metric][:3] == ["24,167", "2", "2"]
    assert any("Port spread" in m.value and "3.1× over" in m.value for m in at.markdown)

    next(b for b in at.button if "Investigate" in b.label).click().run()
    texts = " ".join(m.value for m in at.markdown)
    assert "get_alert_details(2)" in texts            # live step shown in the status box
    assert "not confirmed as an attack" in texts      # report summary
    assert "Medium confidence" in texts

    next(b for b in at.button if "Mark reviewed" in b.label).click().run()
    assert [m.value for m in at.metric][2] == "1"
