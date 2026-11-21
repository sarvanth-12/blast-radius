"""Exercise the offline dashboard from rule entry through remediation."""
from pathlib import Path

from streamlit.testing.v1 import AppTest

from data.generate_flows import generate


def test_dashboard_replays_rule_and_compares_suggestion(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    original_root = Path(__file__).resolve().parents[1]
    test_root = tmp_path / "workspace"
    test_root.mkdir()
    for name in ("app.py", "dashboard.css"):
        (test_root / name).write_bytes((original_root / name).read_bytes())
    generate(test_root / "data" / "flows.csv", count=200)
    app = AppTest.from_file(str(test_root / "app.py"), default_timeout=20).run()
    assert not app.exception
    assert not app.error
    next(button for button in app.button if button.label == "Analyze").click().run()
    assert not app.exception
    assert not app.error
    before = app.session_state.analysis["result"].summary
    assert before["flows_checked"] == 200
    assert before["would_break"] > 0 and before["intended_blocked"] > 0
    assert any("Firewall outcomes" in item.value for item in app.markdown)
    assert any("Observed traffic" in item.value for item in app.markdown)

    next(button for button in app.button if button.label == "Re-run with safer rule").click().run()
    assert not app.exception
    after = app.session_state.analysis["after"]
    assert after["would_break"] == 0
    assert after["intended_blocked"] == before["intended_blocked"]

    app.radio[0].set_value("Capture details").run()
    assert not app.exception
    assert any(item.value == "Capture details" for item in app.subheader)
