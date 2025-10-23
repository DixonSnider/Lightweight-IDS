#!/usr/bin/env python3
"""
mini-ids-lite: simple heuristic IDS over PCAP.
- Extracts lightweight features.
- Applies YAML-configured thresholds.
- Emits JSONL alerts and/or a pretty terminal report.

Requires: scapy, pyyaml, pandas (for convenience), tabulate (for report)
"""
import argparse, json, time, socket, ipaddress, sys
from collections import defaultdict, Counter
from typing import Dict, Any, List

# Lazy imports so the script can at least show --help without deps installed
def _lazy_imports():
    global rdpcap, TCP, UDP
    from scapy.all import rdpcap, TCP, UDP  # type: ignore

def to_ip(obj):
    try:
        return str(ipaddress.ip_address(obj))
    except Exception:
        return str(obj)

def load_rules(path: str) -> Dict[str, Any]:
    import yaml  # type: ignore
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def parse_pcap(pcap_path: str) -> List[Dict[str, Any]]:
    _lazy_imports()
    pkts = rdpcap(pcap_path)
    rows = []
    for p in pkts:
        if not hasattr(p, "time"):  # scapy ensures .time, but be safe
            continue
        ts = float(p.time)
        if p.haslayer(TCP):
            l = p.getlayer(TCP)
            src = to_ip(p[0].src) if hasattr(p[0], "src") else None
            dst = to_ip(p[0].dst) if hasattr(p[0], "dst") else None
            if src and dst:
                flags = int(l.flags)
                rows.append({
                    "ts": ts,
                    "proto": "TCP",
                    "src": src,
                    "dst": dst,
                    "sport": int(l.sport),
                    "dport": int(l.dport),
                    "syn": 1 if (flags & 0x02) else 0,  # SYN
                    "ack": 1 if (flags & 0x10) else 0,  # ACK
                    "rst": 1 if (flags & 0x04) else 0,
                    "fin": 1 if (flags & 0x01) else 0,
                    "len": int(len(p)),
                })
        elif p.haslayer(UDP):
            l = p.getlayer(UDP)
            src = to_ip(p[0].src) if hasattr(p[0], "src") else None
            dst = to_ip(p[0].dst) if hasattr(p[0], "dst") else None
            if src and dst:
                rows.append({
                    "ts": ts,
                    "proto": "UDP",
                    "src": src,
                    "dst": dst,
                    "sport": int(l.sport),
                    "dport": int(l.dport),
                    "syn": 0, "ack": 0, "rst": 0, "fin": 0,
                    "len": int(len(p)),
                })
    return rows

def detect(rows: List[Dict[str, Any]], rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts = []

    # General params
    window = int(rules.get("window_seconds", 300))

    # Pre-aggregate by src
    by_src = defaultdict(list)
    for r in rows:
        by_src[r["src"]].append(r)

    now_ts = int(time.time())
    first_ts = min((r["ts"] for r in rows), default=now_ts)
    last_ts = max((r["ts"] for r in rows), default=now_ts)

    # --- SYN flood: many SYNs without matching ACKs ---
    syn_rule = rules.get("syn_flood", {})
    syn_thresh = int(syn_rule.get("threshold_syns_per_src", 300))
    for src, lst in by_src.items():
        syns = sum(1 for r in lst if r["proto"] == "TCP" and r["syn"] == 1 and r["ack"] == 0)
        acks = sum(1 for r in lst if r["proto"] == "TCP" and r["ack"] == 1)
        if syns >= syn_thresh and acks < syns * 0.1:  # crude heuristic
            alerts.append({
                "rule": "syn_flood",
                "src": src,
                "count": syns,
                "acks_seen": acks,
                "window_seconds": window,
                "evidence": {},
                "first_ts": first_ts, "last_ts": last_ts,
            })

    # --- Port scan (horizontal): many unique dst ports from one src ---
    ps_rule = rules.get("portscan", {})
    uniq_ports_thresh = int(ps_rule.get("unique_dst_ports_per_src", 50))
    for src, lst in by_src.items():
        ports = set(r["dport"] for r in lst if r.get("dport") is not None)
        if len(ports) >= uniq_ports_thresh:
            alerts.append({
                "rule": "portscan.horizontal",
                "src": src,
                "count": len(ports),
                "window_seconds": window,
                "evidence": {"unique_dst_ports": sorted(list(ports))[:50]},
                "first_ts": first_ts, "last_ts": last_ts,
            })

    # --- Vertical scan: many destination IPs on the same port ---
    vs_rule = rules.get("vertical_scan", {})
    uniq_ips_thresh = int(vs_rule.get("unique_dst_ips_on_port", 30))
    by_src_port = defaultdict(set)  # (src, dport) -> set(dst)
    for r in rows:
        if r.get("dport") is not None:
            by_src_port[(r["src"], r["dport"])].add(r["dst"])
    for (src, dport), dsts in by_src_port.items():
        if len(dsts) >= uniq_ips_thresh:
            alerts.append({
                "rule": "portscan.vertical",
                "src": src,
                "port": dport,
                "count": len(dsts),
                "window_seconds": window,
                "evidence": {"example_dsts": list(sorted(dsts))[:25]},
                "first_ts": first_ts, "last_ts": last_ts,
            })

    # --- SSH bursts: lots of SYNs to 22 ---
    ssh_rule = rules.get("ssh_burst", {})
    ssh_syn_thresh = int(ssh_rule.get("syns_to_22", 20))
    for src, lst in by_src.items():
        ssh_syns = sum(1 for r in lst if r["proto"] == "TCP" and r["dport"] == 22 and r["syn"] == 1)
        if ssh_syns >= ssh_syn_thresh:
            alerts.append({
                "rule": "ssh_burst",
                "src": src,
                "count": ssh_syns,
                "window_seconds": window,
                "evidence": {},
                "first_ts": first_ts, "last_ts": last_ts,
            })

    # --- UDP amplification hints: many small UDP to certain ports ---
    udp_rule = rules.get("udp_amp", {})
    suspect_ports = set(int(p) for p in udp_rule.get("suspect_ports", [53, 123, 1900, 11211]))
    small_bytes = int(udp_rule.get("small_payload_len", 120))
    min_hits = int(udp_rule.get("min_hits", 200))
    for src, lst in by_src.items():
        hits = sum(1 for r in lst if r["proto"] == "UDP" and r["dport"] in suspect_ports and r["len"] <= small_bytes)
        if hits >= min_hits:
            alerts.append({
                "rule": "udp_amp_hint",
                "src": src,
                "count": hits,
                "window_seconds": window,
                "evidence": {"ports": sorted(list(suspect_ports))},
                "first_ts": first_ts, "last_ts": last_ts,
            })

    return alerts

def print_report(alerts: List[Dict[str, Any]]):
    if not alerts:
        print("No alerts.")
        return
    try:
        from tabulate import tabulate  # type: ignore
    except Exception:
        # Fallback minimal print
        for a in alerts:
            print(json.dumps(a, indent=2))
        return

    rows = []
    for a in alerts:
        rule = a.get("rule", "")
        src = a.get("src", "")
        count = a.get("count", "")
        extra = []
        if "port" in a: extra.append(f"port={a['port']}")
        if "acks_seen" in a: extra.append(f"acks={a['acks_seen']}")
        rows.append([rule, src, count, "; ".join(extra)])
    print(tabulate(rows, headers=["Rule", "Src", "Count", "Details"], tablefmt="github"))

def main():
    ap = argparse.ArgumentParser(description="mini-ids-lite: simple IDS over pcap")
    ap.add_argument("--pcap", required=True, help="Path to input PCAP")
    ap.add_argument("--rules", default="sample_rules.yml", help="Path to YAML thresholds")
    ap.add_argument("--out", help="Write alerts as JSONL to this file")
    ap.add_argument("--report", action="store_true", help="Print a human-friendly table report")
    args = ap.parse_args()

    rules = load_rules(args.rules)
    rows = parse_pcap(args.pcap)
    alerts = detect(rows, rules)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            for a in alerts:
                f.write(json.dumps(a, sort_keys=True) + "\n")
        print(f"Wrote {len(alerts)} alert(s) to {args.out}")

    if args.report or not args.out:
        print_report(alerts)

if __name__ == "__main__":
    main()
