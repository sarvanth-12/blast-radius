"""Protect policy intent and reject malformed flow input at intake."""
from io import StringIO

import pandas as pd
import pytest

from core.explainer import explain
from core.llm import LLM
from core.replay import FIELDS, load_flows, replay
from core.schema import Rule


@pytest.mark.parametrize(("field", "value"), [
    ("src_ip", "invalid"),
    ("dst_port", "443.5"),
    ("bytes", "9223372036854775808"),
])
def test_invalid_flow_values_are_rejected_when_loading(field, value):
    record = dict(zip(FIELDS, ("2026-01-01T00:00:00Z", "10.40.0.1", "10.50.0.1", "WiFi", "Servers", 443, "tcp", 600, "HTTPS")))
    record[field] = value
    source = StringIO(pd.DataFrame([record]).to_csv(index=False))
    with pytest.raises(ValueError, match=field):
        load_flows(source)


def test_safer_rule_preserves_blocks_on_a_shared_service():
    rows = [
        ("2026-01-01", "10.40.0.5", "10.50.0.11", "WiFi", "Servers", 443, "tcp", 100, "ERP"),
        ("2026-01-01", "10.40.0.8", "10.50.0.11", "WiFi", "Servers", 443, "tcp", 100, "HTTPS"),
        ("2026-01-01", "10.40.0.5", "10.50.0.12", "WiFi", "Servers", 443, "tcp", 100, "Moodle"),
    ]
    flows = pd.DataFrame(rows, columns=FIELDS)
    rule = Rule.from_dict({"action": "block", "src": "WiFi", "dst": "Servers", "ports": [443], "proto": "tcp", "exceptions": []})
    before = replay(flows, rule)
    report = explain(rule, before, LLM(demo=True))
    after = replay(flows, report.safer_rule)
    assert report.shared_service_flows == 1
    assert after.summary["intended_blocked"] == before.summary["intended_blocked"] == 1
    assert after.summary["would_break"] == 1
    assert after.flows.category.tolist() == ["would_break", "intended_blocked", "allowed_by_exception"]
