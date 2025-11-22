#!/usr/bin/env python3
"""
Network Threat Detection Pipeline (Simplified Demo)

This script shows a mini version of a network threat detection pipeline.
It:
  1) Loads Suricata-style JSON alerts from a file.
  2) Extracts key fields (source IP, destination IP, port, signature).
  3) Builds simple statistics (top talkers, top destination ports, top alerts).
  4) Prints a human-readable summary for quick triage.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Dict, Any


@dataclass
class AlertEvent:
    """Represents a simplified Suricata alert event."""
    src_ip: str
    dest_ip: str
    dest_port: int
    signature: str

    @classmethod
    def from_raw(cls, raw: Dict[str, Any]) -> "AlertEvent | None":
        """
        Safely build an AlertEvent from a Suricata-style JSON record.

        Returns None if required fields are missing.
        """
        try:
            src_ip = raw["src_ip"]
            dest_ip = raw["dest_ip"]
            dest_port = int(raw.get("dest_port", 0))
            signature = raw.get("alert", {}).get("signature", "UNKNOWN ALERT")
        except (KeyError, TypeError, ValueError):
            return None

        return cls(
            src_ip=src_ip,
            dest_ip=dest_ip,
            dest_port=dest_port,
            signature=signature,
        )


def load_alerts(path: Path) -> List[AlertEvent]:
    """
    Load Suricata-style alerts from a JSONL file (one JSON object per line).
    Lines that cannot be parsed or do not contain the expected fields are skipped.
    """
    events: List[AlertEvent] = []

    if not path.exists():
        raise FileNotFoundError(f"Alert file not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                # In a real pipeline, log this somewhere
                continue

            event = AlertEvent.from_raw(raw)
            if event is None:
                # Skip records missing required fields
                continue
            events.append(event)

    return events


def summarize_alerts(events: Iterable[AlertEvent]) -> Dict[str, Counter]:
    """
    Build simple frequency statistics over a stream of alert events.
    """
    src_counter: Counter[str] = Counter()
    port_counter: Counter[int] = Counter()
    sig_counter: Counter[str] = Counter()

    for event in events:
        src_counter[event.src_ip] += 1
        port_counter[event.dest_port] += 1
        sig_counter[event.signature] += 1

    return {
        "by_src_ip": src_counter,
        "by_dest_port": port_counter,
        "by_signature": sig_counter,
    }


def print_summary(stats: Dict[str, Counter], top_n: int = 5) -> None:
    """
    Print a human-readable summary of the most active IPs, ports, and alerts.
    """
    print("\n=== Network Threat Snapshot ===\n")

    print(f"Top {top_n} Source IPs (Talkers):")
    for ip, count in stats["by_src_ip"].most_common(top_n):
        print(f"  {ip:<18} -> {count} alerts")

    print(f"\nTop {top_n} Destination Ports:")
    for port, count in stats["by_dest_port"].most_common(top_n):
        print(f"  {str(port):<5} -> {count} alerts")

    print(f"\nTop {top_n} Alert Signatures:")
    for sig, count in stats["by_signature"].most_common(top_n):
        print(f"  {count:>3}x  {sig}")

    print("\n===============================\n")


def build_demo_file(path: Path) -> None:
    """
    Create a tiny demo alert file so the script can be run immediately.

    In a real environment, this would be replaced by live Suricata output.
    """
    sample_records = [
        {
            "src_ip": "10.0.0.5",
            "dest_ip": "192.168.1.10",
            "dest_port": 22,
            "alert": {"signature": "ET SCAN Potential SSH Scan"},
        },
        {
            "src_ip": "10.0.0.5",
            "dest_ip": "192.168.1.11",
            "dest_port": 22,
            "alert": {"signature": "ET SCAN Potential SSH Scan"},
        },
        {
            "src_ip": "172.16.0.9",
            "dest_ip": "192.168.1.20",
            "dest_port": 3389,
            "alert": {"signature": "ET POLICY RDP Outbound Possible"},
        },
        {
            "src_ip": "8.8.8.8",
            "dest_ip": "192.168.1.30",
            "dest_port": 53,
            "alert": {"signature": "ET DNS Suspicious DNS Query"},
        },
    ]

    with path.open("w", encoding="utf-8") as f:
        for record in sample_records:
            f.write(json.dumps(record) + "\n")


def main() -> None:
    """
    Entry point for the script.

    If 'alerts.jsonl' does not exist, a small demo file is created automatically.
    """
    alerts_path = Path("alerts.jsonl")

    if not alerts_path.exists():
        build_demo_file(alerts_path)

    events = load_alerts(alerts_path)
    if not events:
        print("No valid alert events found.")
        return

    stats = summarize_alerts(events)
    print_summary(stats, top_n=3)


if __name__ == "__main__":
    main()
