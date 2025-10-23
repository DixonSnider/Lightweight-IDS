# Lightweight IDS — Toy Intrusion Detection from PCAP

A small, readable IDS-style project that scans a PCAP and emits human-friendly alerts for common behaviors:

- SYN flood (too many SYNs without ACKs)  
- Horizontal port scan (many destination ports on one target)  
- Vertical scan (many hosts probed on one port)  
- Suspicious SSH (excessive attempts to TCP/22)  
- UDP amplification hints (lots of small UDP packets to known amplifiers such as 53 and 123)

Goal: demonstrate hands-on familiarity with IDS concepts, heuristic rules, thresholds, and alerting. Suitable as a compact GitHub portfolio project.

---

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

You will need a PCAP file to test. Use public samples (for example, Wireshark sample captures) or generate one locally with `scapy` or traffic tools (see the test PCAP section below).

---

## Usage

```bash
python ids_lite.py --pcap path/to/traffic.pcap --rules sample_rules.yml --out alerts.jsonl
```

- `--pcap` : input PCAP file  
- `--rules`: YAML thresholds (tune to trade off noise vs signal)  
- `--out`  : write alerts as JSON Lines (one JSON object per line)

Quick terminal report:

```bash
python ids_lite.py --pcap path/to/traffic.pcap --rules sample_rules.yml --report
```

---

## What it Detects (Rules)

Rules are configured in `sample_rules.yml`. Example settings:

- `syn_flood.threshold_syns_per_src`: maximum SYNs per source before alert (default: 300)  
- `portscan.unique_dst_ports_per_src`: unique destination ports from one source (default: 50)  
- `vertical_scan.unique_dst_ips_on_port`: unique hosts probed on a single port by one source (default: 30)  
- `ssh_burst.syns_to_22`: SYNs to port 22 from one source (default: 20 within the configured window)  
- `udp_amp.suspect_ports`: list of UDP ports to watch (defaults include 53, 123, 1900, 11211)

This is a toy IDS: deliberately simple, intended for learning and extension rather than production use.

---

## Example Commands

```bash
# JSONL output for downstream tooling
python ids_lite.py --pcap sample.pcap --out alerts.jsonl

# Human-friendly table in the terminal
python ids_lite.py --pcap sample.pcap --report
```

---

## How to Generate a Test PCAP (optional)

Only generate traffic against systems you control.

```bash
# Simulate a burst of TCP SYNs (use on your own machine)
sudo hping3 127.0.0.1 -S -p 80 -i u100 -c 500

# Simulate a horizontal scan with nmap (target a controlled host)
nmap -p 1-200 127.0.0.1
```

Capture traffic with tcpdump in a separate terminal:

```bash
sudo tcpdump -i lo -w sample.pcap tcp or udp
```

---

## Project Structure

```
lightweight-ids/
├── ids_lite.py
├── requirements.txt
├── sample_rules.yml
└── README.md
```

---

## Example Alert (JSON)

```json
{
  "rule": "portscan.horizontal",
  "src": "192.0.2.10",
  "count": 137,
  "window_seconds": 300,
  "evidence": { "unique_dst_ports": [22, 23, 80, 443, "..."] },
  "first_ts": 1734567890.12,
  "last_ts": 1734567995.88
}
```
---

## Disclaimer

Educational use only. Do not generate traffic or scan hosts you do not own or have explicit permission to test. This tool is not production-grade security software.
