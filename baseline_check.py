"""Headless baseline check for endpointwatch.

Learn what's normal on an endpoint, then flag drift:

  python baseline_check.py --learn      # record current processes + connections
  python baseline_check.py              # check current state against baseline
  python baseline_check.py --out findings.json

Exit codes: 0 clean, 1 anomalies found (cron/CI friendly), 2 usage error.
"""

import argparse
import json
import sys

from core.baseline import BaselineStore

try:
    import psutil
except ImportError:
    psutil = None


def collect_processes():
    if psutil is None:
        return []
    return sorted({
        proc.info["name"] for proc in psutil.process_iter(["name"])
        if proc.info["name"]
    })


def collect_remote_endpoints():
    if psutil is None:
        return []
    endpoints = set()
    for conn in psutil.net_connections(kind="inet"):
        if conn.raddr and conn.raddr.ip:
            endpoints.add(f"{conn.raddr.ip}:{conn.raddr.port}")
    return sorted(endpoints)


def main():
    parser = argparse.ArgumentParser(description="endpointwatch baseline check")
    parser.add_argument("--learn", action="store_true",
                        help="record the current state into the baseline")
    parser.add_argument("--store", default="database/baseline.json")
    parser.add_argument("--min-history", type=int, default=20,
                        help="minimum observations before unknowns flag")
    parser.add_argument("--out", help="write findings as JSON here")
    args = parser.parse_args()

    store = BaselineStore(args.store)

    if args.learn:
        seen = 0
        for name in collect_processes():
            store.observe("process", name)
            seen += 1
        for endpoint in collect_remote_endpoints():
            store.observe("endpoint", endpoint)
            seen += 1
        store.save()
        print(f"Learned {seen} observations into {args.store}")
        return 0

    findings = []
    for name in collect_processes():
        if store.is_anomalous("process", name, args.min_history):
            findings.append({
                "type": "process",
                "value": name,
                "reason": "process not seen during baseline learning",
            })
    for endpoint in collect_remote_endpoints():
        if store.is_anomalous("endpoint", endpoint, args.min_history):
            findings.append({
                "type": "endpoint",
                "value": endpoint,
                "reason": "remote connection target not seen during baseline learning",
            })

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"findings": findings}, f, indent=2)

    if findings:
        for finding in findings:
            print(f"ANOMALY [{finding['type']}] {finding['value']}")
        print(f"{len(findings)} anomalies found")
        return 1

    print("No anomalies. Baseline looks healthy.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
