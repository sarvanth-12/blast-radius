"""Deterministic, vectorized replay of a candidate firewall rule."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import pandas as pd

from core.schema import Rule, VLANS

CRITICAL = {"ERP", "Moodle", "Printing", "DNS", "SSH"}
FIELDS = ["timestamp", "src_ip", "dst_ip", "src_vlan", "dst_vlan", "dst_port", "proto", "bytes", "app_label"]
GROUPS = ["src_vlan", "dst_vlan", "dst_port", "app_label"]


@dataclass
class ReplayResult:
    summary: dict[str, int]
    affected: pd.DataFrame
    would_break: pd.DataFrame
    allowed_by_exception: pd.DataFrame
    flows: pd.DataFrame


def _side(flows: pd.DataFrame, side: str, target: str) -> pd.Series:
    network = ipaddress.ip_network(VLANS.get(target, target), strict=False)
    return flows[f"{side}_ip"].map(lambda ip: ipaddress.ip_address(str(ip)) in network)


def _aggregate(flows: pd.DataFrame) -> pd.DataFrame:
    if flows.empty:
        return pd.DataFrame(columns=GROUPS + ["flow_count", "total_bytes"])
    return flows.groupby(GROUPS, dropna=False).agg(flow_count=("bytes", "size"), total_bytes=("bytes", "sum")).reset_index().sort_values("flow_count", ascending=False)


def replay(flows: pd.DataFrame, rule: Rule) -> ReplayResult:
    """Classify each flow and return compact aggregate tables for the UI and LLM."""
    missing = set(FIELDS) - set(flows.columns)
    if missing:
        raise ValueError(f"Missing CSV columns: {', '.join(sorted(missing))}")
    frame = flows.copy()
    frame["dst_port"] = pd.to_numeric(frame["dst_port"], errors="raise").astype(int)
    frame["bytes"] = pd.to_numeric(frame["bytes"], errors="raise").astype(int)
    if (frame["bytes"] < 0).any():
        raise ValueError("bytes cannot be negative")
    match = _side(frame, "src", rule.src) & _side(frame, "dst", rule.dst) & frame.dst_port.isin(rule.ports)
    if rule.proto != "any":
        match &= frame.proto.str.lower().eq(rule.proto)
    exception = pd.Series(False, index=frame.index)
    for item in rule.exceptions:
        excluded = _side(frame, "dst", item.dst) & frame.dst_port.isin(item.ports)
        if item.proto != "any":
            excluded &= frame.proto.str.lower().eq(item.proto)
        exception |= match & excluded
    blocked = match & ~exception & (rule.action == "block")
    # A high-volume flow is measured relative to the dataset, not a fixed byte threshold.
    high_traffic = frame.bytes >= max(1_000_000, int(frame.bytes.quantile(0.95))) if len(frame) else pd.Series(False, index=frame.index)
    broken = blocked & (frame.app_label.isin(CRITICAL) | high_traffic)
    frame["matched"] = match
    frame["blocked"] = blocked
    frame["allowed"] = ~blocked
    frame["category"] = "unaffected"
    frame.loc[blocked, "category"] = "intended_blocked"
    frame.loc[broken, "category"] = "would_break"
    frame.loc[exception, "category"] = "allowed_by_exception"
    summary = {"flows_checked": len(frame), "matched": int(match.sum()), "intended_blocked": int((blocked & ~broken).sum()), "would_break": int(broken.sum()), "allowed_by_exception": int(exception.sum())}
    return ReplayResult(summary, _aggregate(frame.loc[blocked]), _aggregate(frame.loc[broken]), _aggregate(frame.loc[exception]), frame)

