#!/usr/bin/env python3
"""
SOC-style Log Analyzer (single-file, Python 3.8+)

Parses:
  - Linux auth.log (SSH events)
  - Apache/Nginx access.log (common/combined)

Outputs:
  - JSON report in output/
  - Optional CSV with suspicious IPs

Examples:
  python log_analyzer.py --type auth --input /var/log/auth.log --threshold 10 --csv
  python log_analyzer.py --type web  --input access.log --threshold 30 --csv
"""

import argparse
import csv
import json
import os
import re
from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional


# -------------------- Helpers --------------------

def ensure_outdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def write_csv(path: str, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def safe_int(x: str, default: int = 0) -> int:
    try:
        return int(x)
    except (ValueError, TypeError):
        return default


def load_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.readlines()


# -------------------- Regex: auth.log --------------------
# Example auth.log line:
# Feb 16 03:10:12 myhost sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 2222 ssh2

AUTH_TS_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

SSH_FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?:(invalid user)\s+)?(?P<user>[\w\-.]+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SSH_INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>[\w\-.]+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SSH_FAILED_PUBKEY_RE = re.compile(
    r"Failed publickey for (?:(invalid user)\s+)?(?P<user>[\w\-.]+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SSH_ACCEPTED_PASSWORD_RE = re.compile(
    r"Accepted password for (?P<user>[\w\-.]+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SSH_ACCEPTED_PUBKEY_RE = re.compile(
    r"Accepted publickey for (?P<user>[\w\-.]+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SSH_DISCONNECT_RE = re.compile(
    r"Disconnected from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse_auth_log(lines: Iterable[str]) -> Iterable[Dict[str, Any]]:
    """Parse Linux auth.log focusing on SSH events."""
    now_year = datetime.now().year

    for line in lines:
        line = line.rstrip("\n")

        m = AUTH_TS_RE.match(line)
        if not m:
            continue

        msg = m.group("msg")

        # Build timestamp string including year (auth.log often has no year)
        ts_str = "{} {} {} {}".format(
            m.group("mon"),
            m.group("day"),
            m.group("time"),
            now_year
        )

        try:
            ts = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
        except Exception:
            ts = None

        event = None

        for regex, etype in [
            (SSH_FAILED_PASSWORD_RE, "ssh_failed_password"),
            (SSH_INVALID_USER_RE, "ssh_invalid_user"),
            (SSH_FAILED_PUBKEY_RE, "ssh_failed_publickey"),
            (SSH_ACCEPTED_PASSWORD_RE, "ssh_accepted_password"),
            (SSH_ACCEPTED_PUBKEY_RE, "ssh_accepted_publickey"),
            (SSH_DISCONNECT_RE, "ssh_disconnected"),
        ]:
            mm = regex.search(msg)
            if mm:
                gd = mm.groupdict()
                event = {
                    "timestamp": ts,
                    "event_type": etype,
                    "ip": gd.get("ip"),
                    "user": gd.get("user"),
                    "raw": line,
                }
                break

        if event:
            yield event


# -------------------- Regex: web access.log --------------------
# Example:
# 127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 2326 "ref" "ua"

WEB_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+).*$'
)


def parse_web_log(lines: Iterable[str]) -> Iterable[Dict[str, Any]]:
    """Parse Apache/Nginx access logs (common/combined)."""
    for line in lines:
        line = line.rstrip("\n")
        m = WEB_RE.match(line)
        if not m:
            continue

        ip = m.group("ip")
        if ip == "-" or ip.lower() == "unknown":
            continue

        ts_raw = m.group("ts")
        ts = None
        
        # Try parsing with timezone
        try:
            ts = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z")
        except Exception:
            # Try without timezone
            try:
                ts = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S")
            except Exception:
                ts = None

        status = safe_int(m.group("status"), 0)
        path = m.group("path")
        method = m.group("method")

        if status in (401, 403):
            etype = "web_auth_fail"
        elif 400 <= status <= 499:
            etype = "web_client_error"
        elif 500 <= status <= 599:
            etype = "web_server_error"
        else:
            etype = "web_ok"

        yield {
            "timestamp": ts,
            "event_type": etype,
            "ip": ip,
            "method": method,
            "path": path,
            "status": status,
            "raw": line,
        }


# -------------------- Summarizer --------------------

FAIL_TYPES = {
    "ssh_failed_password",
    "ssh_invalid_user",
    "ssh_failed_publickey",
    "web_auth_fail",
    "web_client_error",
}

SUCCESS_TYPES = {
    "ssh_accepted_password",
    "ssh_accepted_publickey",
    "web_ok",
}


def summarize(events: List[Dict[str, Any]], suspicious_threshold: int) -> Dict[str, Any]:
    by_ip = Counter()
    failed_by_ip = Counter()
    success_by_ip = Counter()
    events_by_type = Counter()
    users_failed = Counter()

    first_seen: Dict[str, datetime] = {}
    last_seen: Dict[str, datetime] = {}

    for e in events:
        ip = e.get("ip") or "UNKNOWN"
        et = e.get("event_type") or "unknown"
        ts = e.get("timestamp")

        by_ip[ip] += 1
        events_by_type[et] += 1

        if et in FAIL_TYPES:
            failed_by_ip[ip] += 1
            user = e.get("user")
            if user:
                users_failed[str(user)] += 1

        if et in SUCCESS_TYPES:
            success_by_ip[ip] += 1

        if isinstance(ts, datetime):
            if ip not in first_seen or ts < first_seen[ip]:
                first_seen[ip] = ts
            if ip not in last_seen or ts > last_seen[ip]:
                last_seen[ip] = ts

    suspicious: List[Dict[str, Any]] = []
    for ip, nfail in failed_by_ip.most_common():
        if ip == "UNKNOWN":
            continue
        if nfail >= suspicious_threshold:
            suspicious.append({
                "ip": ip,
                "failed_events": nfail,
                "total_events": by_ip[ip],
                "success_events": success_by_ip.get(ip, 0),
                "first_seen": first_seen[ip].isoformat() if ip in first_seen and first_seen[ip] else None,
                "last_seen": last_seen[ip].isoformat() if ip in last_seen and last_seen[ip] else None,
            })

    return {
        "stats": {
            "total_events": len(events),
            "unique_ips": len([ip for ip in by_ip.keys() if ip != "UNKNOWN"]),
            "event_types": dict(events_by_type),
        },
        "top": {
            "ips": [{"ip": ip, "events": c} for ip, c in by_ip.most_common(15)],
            "failed_ips": [{"ip": ip, "failed": c} for ip, c in failed_by_ip.most_common(15)],
            "successful_ips": [{"ip": ip, "success": c} for ip, c in success_by_ip.most_common(15)],
            "failed_users": [{"user": u, "failed": c} for u, c in users_failed.most_common(15)],
        },
        "suspicious": suspicious,
    }


# -------------------- CLI --------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="SOC-style Log Analyzer (auth.log / web access.log)")
    ap.add_argument("--type", choices=["auth", "web"], required=True, help="Log type: auth or web")
    ap.add_argument("--input", required=True, help="Path to log file")
    ap.add_argument("--outdir", default="output", help="Output directory")
    ap.add_argument("--threshold", type=int, default=10, help="Suspicious threshold (failed events per IP)")
    ap.add_argument("--csv", action="store_true", help="Also export suspicious IPs to CSV")
    args = ap.parse_args()

    ensure_outdir(args.outdir)
    
    try:
        lines = load_lines(args.input)
    except FileNotFoundError:
        print(f"Error: File '{args.input}' not found.")
        return
    except Exception as e:
        print(f"Error reading file '{args.input}': {e}")
        return

    if args.type == "auth":
        events = list(parse_auth_log(lines))
    else:
        events = list(parse_web_log(lines))

    if not events:
        print("Warning: No events were parsed from the log file.")
        report = {
            "stats": {
                "total_events": 0,
                "unique_ips": 0,
                "event_types": {},
            },
            "top": {
                "ips": [],
                "failed_ips": [],
                "successful_ips": [],
                "failed_users": [],
            },
            "suspicious": [],
        }
    else:
        report = summarize(events, args.threshold)

    out_json = os.path.join(args.outdir, f"report_{args.type}.json")
    write_json(out_json, report)

    if args.csv:
        out_csv = os.path.join(args.outdir, f"suspicious_{args.type}.csv")
        write_csv(
            out_csv,
            report["suspicious"],
            ["ip", "failed_events", "total_events", "success_events", "first_seen", "last_seen"]
        )

    print("\n=== SUMMARY ===")
    print("Input:", args.input)
    print("Parsed events:", report["stats"]["total_events"])
    print("Unique IPs:", report["stats"]["unique_ips"])
    print("Event types:", report["stats"]["event_types"])

    print("\nTop failed IPs:")
    for row in report["top"]["failed_ips"][:10]:
        print(f" - {row['ip']}: {row['failed']}")

    print("\nSuspicious IPs:")
    if not report["suspicious"]:
        print(" (none)")
    else:
        for s in report["suspicious"][:20]:
            print(f" - {s['ip']} | failed={s['failed_events']} total={s['total_events']} success={s['success_events']}")

    print("\nSaved JSON:", out_json)
    if args.csv:
        print("Saved CSV: ", out_csv)


if __name__ == "__main__":
    main()

    