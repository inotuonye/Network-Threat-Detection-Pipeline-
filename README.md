# Network Threat Detection Pipeline (Python Demo)

This project shows a simple but realistic threat-detection pipeline written in Python. It parses Suricata-style JSON alerts, extracts key details, builds quick statistics, and prints a readable “threat snapshot” that a SOC analyst or security engineer can use for fast triage. 

It’s designed to demonstrate practical security skills, clean coding habits, and the ability to work with network telemetry in a modern cybersecurity environment.

---

## Features

- Parses Suricata-style JSON alerts from a JSONL file (`alerts.jsonl`)
- Normalizes each alert into a dataclass (`AlertEvent`)
- Builds frequency statistics for:
  - Top source IPs (talkers)
  - Top destination ports
  - Top alert signatures
- Automatically generates a demo alert file if none exists
- Prints a clean, human-readable threat summary for quick triage

---

## Technologies Used

- **Python 3.10+**
- Standard Library Only:
  - `json`
  - `dataclasses`
  - `collections.Counter`
  - `pathlib`
  - `typing`

No external dependencies required.

---

## File Structure

network_threat_pipeline.py # Main threat-detection script
alerts.jsonl # Suricata-style alerts (auto-created if missing)
README.md # Project documentation

---

## How to Run the Project

1. Install Python 3.10 or higher.
2. Clone this repository.
3. In the project folder, run:

```bash
python network_threat_pipeline.py

=== Network Threat Snapshot ===

Top 3 Source IPs (Talkers):
  10.0.0.5          -> 2 alerts
  172.16.0.9        -> 1 alerts
  8.8.8.8           -> 1 alerts

Top 3 Destination Ports:
  22    -> 2 alerts
  3389  -> 1 alerts
  53    -> 1 alerts

Top 3 Alert Signatures:
    2x  ET SCAN Potential SSH Scan
    1x  ET POLICY RDP Outbound Possible
    1x  ET DNS Suspicious DNS Query

===============================

