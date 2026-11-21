"""Regression coverage for the deterministic replay contract."""
import pandas as pd

from core.replay import FIELDS, replay
from core.schema import Rule


def sample() -> pd.DataFrame:
    rows = [
        ("10.40.0.22", "10.50.0.11", "WiFi", "Servers", 443, "tcp", 120, "ERP"),
        ("10.40.0.23", "10.50.0.11", "WiFi", "Servers", 443, "tcp", 180, "ERP"),
        ("10.40.0.22", "10.50.0.10", "WiFi", "Servers", 443, "tcp", 400, "HTTPS"),
        ("10.40.0.22", "10.50.0.10", "WiFi", "Servers", 443, "udp", 200, "QUIC"),
        ("10.30.0.22", "10.50.0.11", "Hostel", "Servers", 443, "tcp", 400, "ERP"),
        ("10.40.0.22", "10.50.0.44", "WiFi", "Servers", 445, "tcp", 1_000_000, "SMB"),
    ]
    return pd.DataFrame([("2026-01-01T00:00:00Z", *row) for row in rows], columns=FIELDS)


def rule(**overrides) -> Rule:
    values = {"action": "block", "src": "WiFi", "dst": "Servers", "ports": [443], "proto": "tcp", "exceptions": []}
    return Rule.from_dict(values | overrides)


def test_block_matches_vlan_protocol_and_port_and_aggregates_critical_flows():
    result = replay(sample(), rule())
    assert result.summary == dict(flows_checked=6, matched=3, intended_blocked=1, would_break=2, allowed_by_exception=0)
    assert result.would_break[["app_label", "flow_count", "total_bytes"]].values.tolist() == [["ERP", 2, 300]]
    assert result.flows.blocked.tolist() == [True, True, True, False, False, False]


def test_exact_destination_exception_preserves_other_blocks():
    result = replay(sample(), rule(exceptions=[{"dst": "10.50.0.11/32", "ports": [443], "proto": "tcp"}]))
    assert result.summary["allowed_by_exception"] == 2
    assert result.summary["would_break"] == 0
    assert result.summary["intended_blocked"] == 1
    assert result.allowed_by_exception.app_label.tolist() == ["ERP"]


def test_cidr_wildcard_port_and_high_traffic_threshold():
    result = replay(sample(), rule(src="10.40.0.22/32", ports=[], proto="any"))
    assert result.summary["matched"] == 4
    assert result.would_break.app_label.tolist() == ["ERP", "SMB"]


def test_allow_records_matches_without_inventing_breakage():
    result = replay(sample(), rule(action="allow"))
    assert result.summary["matched"] == 3
    assert result.flows.allowed.all()
    assert result.affected.empty
    assert result.flows.category.tolist()[:3] == ["allowed"] * 3


def test_empty_input_preserves_result_schema():
    result = replay(sample().iloc[:0], rule())
    assert all(count == 0 for count in result.summary.values())
    assert result.would_break.columns.tolist() == ["src_vlan", "dst_vlan", "dst_port", "app_label", "flow_count", "total_bytes"]
