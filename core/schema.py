"""Validated firewall rule schema."""
from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from typing import Any

VLANS = {"Admin": "10.10.0.0/24", "CyberLab": "10.20.0.0/24", "Hostel": "10.30.0.0/22", "WiFi": "10.40.0.0/22", "Servers": "10.50.0.0/24"}


def _network(value: str) -> str:
    if value in VLANS:
        return value
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"Unknown VLAN or invalid CIDR: {value}") from exc
    return value


def _ports(values: Any) -> tuple[int, ...]:
    if not isinstance(values, list) or not values or any(type(p) is not int or not 1 <= p <= 65535 for p in values):
        raise ValueError("ports must be a nonempty list of integers from 1 to 65535")
    return tuple(sorted(set(values)))


@dataclass(frozen=True)
class ExceptionRule:
    dst: str
    ports: tuple[int, ...]
    proto: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ExceptionRule":
        if not isinstance(value, dict) or set(value) != {"dst", "ports", "proto"}:
            raise ValueError("exception requires exactly dst, ports, proto")
        if value["proto"] not in ("tcp", "udp", "any"):
            raise ValueError("proto must be tcp, udp or any")
        return cls(_network(value["dst"]), _ports(value["ports"]), value["proto"])


@dataclass(frozen=True)
class Rule:
    action: str
    src: str
    dst: str
    ports: tuple[int, ...]
    proto: str
    exceptions: tuple[ExceptionRule, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Rule":
        if not isinstance(value, dict) or set(value) != {"action", "src", "dst", "ports", "proto", "exceptions"}:
            raise ValueError("rule requires exactly action, src, dst, ports, proto, exceptions")
        if value["action"] not in ("block", "allow"):
            raise ValueError("action must be block or allow")
        if value["proto"] not in ("tcp", "udp", "any"):
            raise ValueError("proto must be tcp, udp or any")
        if not isinstance(value["exceptions"], list):
            raise ValueError("exceptions must be a list")
        return cls(value["action"], _network(value["src"]), _network(value["dst"]), _ports(value["ports"]), value["proto"], tuple(ExceptionRule.from_dict(x) for x in value["exceptions"]))

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["ports"] = list(self.ports)
        for item in result["exceptions"]:
            item["ports"] = list(item["ports"])
        return result

