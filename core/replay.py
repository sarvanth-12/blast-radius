"""Replay one candidate rule against observed, previously allowed flows."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, TextIO

import pandas as pd

from core.schema import Rule, VLANS

CRITICAL = {"erp", "moodle", "printing", "dns"}
HIGH_TRAFFIC_BYTES = 1_000_000
FIELDS = ["timestamp", "src_ip", "dst_ip", "src_vlan", "dst_vlan", "dst_port", "proto", "bytes", "app_label"]
GROUPS = ["src_vlan", "dst_vlan", "dst_port", "app_label"]


@dataclass
class ReplayResult:
    """Per-record decisions plus aggregate counts and grouped views."""

    summary: dict[str, int]
    affected: pd.DataFrame
    would_break: pd.DataFrame
    allowed_by_exception: pd.DataFrame
    flows: pd.DataFrame


def _addresses(series: pd.Series) -> pd.Series:
    try:
        return series.map(lambda value: ipaddress.ip_address(str(value)))
    except ValueError as exc:
        raise ValueError(f"Invalid IP in {series.name}: {exc}") from exc


def _rule_mask(addresses: pd.Series, frame: pd.DataFrame, target: str, ports: tuple[int, ...], proto: str) -> pd.Series:
    network = ipaddress.ip_network(VLANS.get(target, target))
    matches = addresses.map(lambda address: address in network).astype(bool)
    if ports:
        matches &= frame.dst_port.isin(ports)
    if proto != "any":
        matches &= frame.proto.eq(proto)
    return matches


def _aggregate(flows: pd.DataFrame) -> pd.DataFrame:
    totals = flows
    if len(flows) and int(flows.bytes.max()) > (2**63 - 1) // len(flows):
        totals = flows.assign(bytes=flows.bytes.astype(object))
    return (
        totals.groupby(GROUPS, sort=True, dropna=False)
        .agg(flow_count=("bytes", "size"), total_bytes=("bytes", "sum"))
        .reset_index()
        .sort_values("flow_count", ascending=False, kind="stable", ignore_index=True)
    )


def load_flows(source: str | Path | BinaryIO | TextIO) -> pd.DataFrame:
    """Read and validate the required columns in a NetFlow-style CSV."""
    frame = _normalize(pd.read_csv(source, keep_default_na=False, dtype="string", encoding="utf-8-sig"))
    _addresses(frame.src_ip)
    _addresses(frame.dst_ip)
    return frame


def _normalize(flows: pd.DataFrame) -> pd.DataFrame:
    missing = set(FIELDS) - set(flows.columns)
    if missing:
        raise ValueError(f"Missing CSV columns: {', '.join(sorted(missing))}")
    frame = flows.loc[:, FIELDS].copy().reset_index(drop=True)
    for name, limit in (("dst_port", 65535), ("bytes", 2**63 - 1)):
        raw = frame[name].astype("string").str.strip()
        digits = raw.str.fullmatch(r"[0-9]+", na=False)
        canonical = raw.str.lstrip("0").replace("", "0")
        bound = str(limit)
        length = canonical.str.len()
        fits = length.lt(len(bound)) | (length.eq(len(bound)) & canonical.le(bound))
        invalid = ~(digits & fits.fillna(False))
        if invalid.any():
            row = int(invalid[invalid].index[0]) + 1
            raise ValueError(f"Flow record {row}: {name} must be a whole number between 0 and {limit}.")
        frame[name] = canonical.astype("int64")
    for name in ("src_ip", "dst_ip", "src_vlan", "dst_vlan", "app_label", "proto"):
        values = frame[name].astype("string").str.strip()
        if not values.fillna("").ne("").all():
            raise ValueError(f"{name} must contain a value for each flow.")
        frame[name] = values
    frame["proto"] = frame.proto.str.lower()
    return frame


def replay(flows: pd.DataFrame, rule: Rule) -> ReplayResult:
    """Match by CIDR, destination port and protocol, then apply allow exceptions."""
    frame = _normalize(flows)
    sources = _addresses(frame.src_ip)
    destinations = _addresses(frame.dst_ip)
    src_network = ipaddress.ip_network(VLANS.get(rule.src, rule.src))
    matched = sources.map(lambda address: address in src_network).astype(bool)
    matched &= _rule_mask(destinations, frame, rule.dst, rule.ports, rule.proto)
    exception = pd.Series(False, index=frame.index, dtype=bool)
    if rule.action == "block":
        for item in rule.exceptions:
            exception |= matched & _rule_mask(destinations, frame, item.dst, item.ports, item.proto)
    blocked = matched & ~exception & (rule.action == "block")
    critical = frame.app_label.str.casefold().isin(CRITICAL)
    broken = blocked & (critical | frame.bytes.ge(HIGH_TRAFFIC_BYTES))
    intended = blocked & ~broken

    frame["matched"] = matched
    frame["blocked"] = blocked
    frame["allowed"] = ~blocked
    frame["category"] = "unaffected"
    frame.loc[matched & ~blocked, "category"] = "allowed"
    frame.loc[intended, "category"] = "intended_blocked"
    frame.loc[broken, "category"] = "would_break"
    frame.loc[exception, "category"] = "allowed_by_exception"
    summary = {
        "flows_checked": len(frame),
        "matched": int(matched.sum()),
        "intended_blocked": int(intended.sum()),
        "would_break": int(broken.sum()),
        "allowed_by_exception": int(exception.sum()),
    }
    affected = _aggregate(frame.loc[blocked | exception])
    return ReplayResult(summary, affected, _aggregate(frame.loc[broken]), _aggregate(frame.loc[exception]), frame)
