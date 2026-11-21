"""Generate synthetic campus flows with dedicated application endpoints."""
from __future__ import annotations

import argparse
import csv
import ipaddress
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Each entry is (source VLAN, destination VLAN, host, port, protocol, app, weight).
PROFILES = [
    ("WiFi", "Servers", "10.50.0.10", 443, "tcp", "HTTPS", 28),
    ("WiFi", "Servers", "10.50.0.11", 443, "tcp", "ERP", 4),
    ("WiFi", "Servers", "10.50.0.12", 443, "tcp", "Moodle", 7),
    ("WiFi", "Servers", "10.50.0.53", 53, "udp", "DNS", 10),
    ("Hostel", "Servers", "10.50.0.53", 53, "udp", "DNS", 10),
    ("Hostel", "Servers", "10.50.0.12", 443, "tcp", "Moodle", 10),
    ("Hostel", "Servers", "10.50.0.44", 445, "tcp", "SMB", 5),
    ("CyberLab", "Servers", "10.50.0.22", 22, "tcp", "SSH", 10),
    ("CyberLab", "Servers", "10.50.0.53", 53, "tcp", "DNS", 3),
    ("CyberLab", "Admin", "10.10.0.44", 445, "tcp", "SMB", 4),
    ("Admin", "Servers", "10.50.0.21", 9100, "tcp", "Printing", 4),
    ("Admin", "Servers", "10.50.0.11", 443, "tcp", "ERP", 4),
    ("Admin", "Servers", "10.50.0.44", 445, "tcp", "SMB", 5),
    ("Servers", "Admin", "10.10.0.45", 9100, "tcp", "Printing", 2),
]
SUBNETS = {
    "Admin": "10.10.0.0/24", "CyberLab": "10.20.0.0/24",
    "Hostel": "10.30.0.0/22", "WiFi": "10.40.0.0/22", "Servers": "10.50.0.0/24",
}
COLUMNS = ["timestamp", "src_ip", "dst_ip", "src_vlan", "dst_vlan", "dst_port", "proto", "bytes", "app_label"]


def generate(path: Path, count: int = 20_000, seed: int = 42) -> None:
    """Write recent synthetic traffic. A fixed seed reproduces the traffic mix."""
    if count < 1:
        raise ValueError("Row count must be positive.")
    rng = random.Random(seed)
    hosts = {name: list(ipaddress.ip_network(cidr).hosts()) for name, cidr in SUBNETS.items()}
    now = datetime.now(timezone.utc).replace(microsecond=0)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(COLUMNS)
        for index in range(count):
            profile = PROFILES[index] if index < len(PROFILES) else rng.choices(
                PROFILES, weights=[item[-1] for item in PROFILES]
            )[0]
            src, dst, address, port, proto, label, _ = profile
            src_ip = rng.choice(hosts[src])
            if label == "ERP" and src == "WiFi":
                src_ip = ipaddress.ip_address(f"10.40.0.{rng.randrange(10, 40)}")
            if label == "Printing" and src == "Admin":
                src_ip = ipaddress.ip_address("10.10.0.60")
            byte_count = rng.randrange(90, 1600) if label == "DNS" else rng.randrange(800, 180_000)
            if label == "SMB" and rng.random() < 0.08:
                byte_count = rng.randrange(1_000_000, 8_000_000)
            stamp = now - timedelta(seconds=rng.randrange(7 * 24 * 3600))
            writer.writerow((stamp.isoformat(), src_ip, address, src, dst, port, proto, byte_count, label))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("flows.csv"))
    parser.add_argument("--rows", type=int, default=20_000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    generate(args.output, args.rows, args.seed)
    print(f"Generated {args.rows:,} flows in {args.output}")
