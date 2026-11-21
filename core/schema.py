"""Validate and serialize the supported candidate firewall rule."""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any

VLANS = {
    "Admin": "10.10.0.0/24",
    "CyberLab": "10.20.0.0/24",
    "Hostel": "10.30.0.0/22",
    "WiFi": "10.40.0.0/22",
    "Servers": "10.50.0.0/24",
}
RULE_FORMAT = (
    '{"action":"block|allow","src":"VLAN or CIDR","dst":"VLAN or CIDR",'
    '"ports":[443],"proto":"tcp|udp|any","exceptions":'
    '[{"dst":"VLAN or CIDR","ports":[443],"proto":"tcp|udp|any"}]}'
)


def strict_json(raw: str) -> Any:
    """Decode a JSON document, rejecting duplicate keys and non-JSON constants."""
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f"Invalid JSON constant: {value}")

    return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=invalid_constant)


def _network(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Source and destination must be VLAN names or CIDRs.")
    names = {name.lower(): name for name in VLANS}
    if value.lower() in names:
        return names[value.lower()]
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise ValueError(f"Unknown VLAN or invalid CIDR: {value}") from exc


def _ports(values: Any) -> tuple[int, ...]:
    if not isinstance(values, list) or any(
        type(port) is not int or not 1 <= port <= 65535 for port in values
    ):
        raise ValueError("ports must be an array of integers from 1 to 65535.")
    return tuple(sorted(set(values)))


def _proto(value: Any) -> str:
    if value not in ("tcp", "udp", "any"):
        raise ValueError("proto must be tcp, udp or any.")
    return value


@dataclass(frozen=True)
class ExceptionRule:
    """An allowed destination/service subset of a block rule."""

    dst: str
    ports: tuple[int, ...]
    proto: str

    @classmethod
    def from_dict(cls, value: Any) -> ExceptionRule:
        if not isinstance(value, dict) or value.keys() != {"dst", "ports", "proto"}:
            raise ValueError("Each exception requires exactly dst, ports and proto.")
        return cls(_network(value["dst"]), _ports(value["ports"]), _proto(value["proto"]))

    def to_dict(self) -> dict[str, Any]:
        return {"dst": self.dst, "ports": list(self.ports), "proto": self.proto}


@dataclass(frozen=True)
class Rule:
    """A stateless rule. An empty ports array matches every port."""

    action: str
    src: str
    dst: str
    ports: tuple[int, ...]
    proto: str
    exceptions: tuple[ExceptionRule, ...] = ()

    @classmethod
    def from_dict(cls, value: Any) -> Rule:
        if not isinstance(value, dict) or value.keys() != {
            "action", "src", "dst", "ports", "proto", "exceptions"
        }:
            raise ValueError("Rule requires exactly action, src, dst, ports, proto and exceptions.")
        if value["action"] not in ("block", "allow"):
            raise ValueError("action must be block or allow.")
        if not isinstance(value["exceptions"], list):
            raise ValueError("exceptions must be an array.")
        if value["action"] == "allow" and value["exceptions"]:
            raise ValueError("Exceptions apply to block rules only.")
        return cls(
            value["action"], _network(value["src"]), _network(value["dst"]),
            _ports(value["ports"]), _proto(value["proto"]),
            tuple(ExceptionRule.from_dict(item) for item in value["exceptions"]),
        )

    @classmethod
    def from_json(cls, raw: str) -> Rule:
        return cls.from_dict(strict_json(raw))

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action, "src": self.src, "dst": self.dst,
            "ports": list(self.ports), "proto": self.proto,
            "exceptions": [item.to_dict() for item in self.exceptions],
        }
