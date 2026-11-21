"""Translate operator intent into a strictly validated candidate rule."""
from __future__ import annotations

import re

from core.llm import LLM, LLMError
from core.schema import RULE_FORMAT, Rule, VLANS, strict_json

SERVICES = {
    "dns": 53, "https": 443, "erp": 443, "moodle": 443, "smb": 445,
    "ssh": 22, "printing": 9100, "print": 9100,
}
SYSTEM = (
    "You translate one firewall rule. Return exactly one JSON object without Markdown. "
    f"Schema: {RULE_FORMAT}. VLANs: {', '.join(VLANS)}. "
    "An empty ports array means all ports. For any IPv4 network use 0.0.0.0/0. "
    f"Service to port mapping: {SERVICES}. Service names are port aliases only, "
    "so they do not select an application sharing that port. Exceptions apply only to blocks. "
    'If action, endpoints, or intent is unclear, return {"error":"a brief clarification request"}.'
)


def _demo_rule(text: str) -> dict:
    """Parse the documented offline phrasing for supported rule and exception examples."""
    normalized = " ".join(text.strip().rstrip(".").lower().split())
    main, *exceptions = re.split(r"\s+except\s+", normalized)
    match = re.fullmatch(
        r"(block|deny|allow|permit)\s+(?:(.+?)\s+)?from\s+(\S+)\s+to\s+(\S+)(?:\s+(.+))?",
        main,
    )
    if not match:
        return {"error": "Use 'Block TCP 443 from WiFi to Servers' or paste rule JSON."}
    action, leading, src, dst, trailing = match.groups()

    def service(value: str) -> tuple[list[int], str]:
        tokens = re.findall(r"[\w]+|[^\w\s,]", value)
        aliases = {"port", "ports", "on", "traffic", "all", "and"}
        protocols = {token for token in tokens if token in {"tcp", "udp", "any"}}
        values = [token for token in tokens if token not in aliases | protocols]
        if len(protocols) > 1 or any(not (token in SERVICES or token.isascii() and token.isdecimal()) for token in values):
            raise ValueError("Use a port number or a supported service such as HTTPS, DNS, or SMB.")
        ports = [SERVICES[token] if token in SERVICES else int(token) for token in values]
        defaults = {"udp" if token == "dns" else "tcp" for token in values if token in SERVICES}
        return ports, next(iter(protocols or defaults)) if len(protocols or defaults) == 1 else "any"

    try:
        ports, proto = service(" ".join(filter(None, (leading, trailing))))
        parsed_exceptions = []
        for item in exceptions:
            part = re.fullmatch(r"(?:to\s+)?(\S+)(?:\s+(.+))?", item)
            if not part:
                raise ValueError("Use 'except to destination on TCP 443'.")
            target, services = part.groups()
            exception_ports, exception_proto = service(services or "")
            parsed_exceptions.append({"dst": target, "ports": exception_ports, "proto": exception_proto})
        return Rule.from_dict({
            "action": "block" if action in {"block", "deny"} else "allow",
            "src": "0.0.0.0/0" if src == "any" else src,
            "dst": "0.0.0.0/0" if dst == "any" else dst,
            "ports": ports, "proto": proto, "exceptions": parsed_exceptions,
        }).to_dict()
    except ValueError as exc:
        return {"error": str(exc)}


def parse_rule(text: str, llm: LLM) -> Rule:
    """Parse structured JSON locally or retry the cheap model once on invalid output."""
    text = text.strip()
    if not text:
        raise ValueError("Enter a firewall rule.")
    if text.startswith(("{", "[")):
        return Rule.from_json(text)
    instruction = ""
    for _ in range(2):
        response = llm.complete("cheap", SYSTEM, instruction + text, lambda: _demo_rule(text))
        try:
            payload = strict_json(response)
        except ValueError:
            pass
        else:
            if isinstance(payload, dict) and payload.keys() == {"error"} and isinstance(payload["error"], str):
                raise ValueError(payload["error"])
            try:
                return Rule.from_dict(payload)
            except ValueError:
                pass
        instruction = "Your previous reply failed JSON or schema validation. Return only a valid object.\n"
    raise LLMError("The parser returned invalid rule JSON twice. Try pasting a structured rule.")
