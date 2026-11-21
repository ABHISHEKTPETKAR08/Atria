#!/usr/bin/env python3
"""
Smart Observability - organiser-stream simulator (for rehearsal and the simulated-telemetry plan).

Emits a shared multi-host telemetry stream with deliberately non-canonical field names, raw log text
containing secrets and failed logins, and a repeating timeline of injected incidents:

    0-30 s    baseline
   30-60 s    db-01     CPU 93-97 % + 10-15 % packet loss        -> cpu+packet_loss alert
   60-90 s    api-01    latency 20 -> 300+ ms + 5-8 % loss       -> latency_jump+packet_loss alert
   90-130 s   cache-01  goes silent                              -> OUTAGE, then recovers
  130-160 s   web-01    memory 93 % + CPU 85 %                   -> memory+cpu alert
  (then repeats)

Usage:
  python3 stream_simulator.py | python3 collector.py --source - --url <ingest-url>
  python3 stream_simulator.py --out stream.jsonl          # then: collector.py --source stream.jsonl
  python3 stream_simulator.py --format csv | ...          # also: --format kv
"""
import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone

HOSTS = ["web-01", "db-01", "api-01", "cache-01"]
BASE = {"web-01": (25, 55, 8.0, 18), "db-01": (35, 62, 4.0, 12), "api-01": (30, 48, 6.0, 20),
        "cache-01": (15, 40, 12.0, 9)}            # cpu %, mem %, Mbps, rtt ms
LOGS = [
    "nginx[812]: 200 GET /api/v1/orders 34ms",
    "sshd[2211]: Failed password for root from 203.0.113.50 port 51432 ssh2",
    "sshd[2214]: Failed password for invalid user admin from 203.0.113.50 port 51440 ssh2",
    "app[90]: login ok user=priya@example.com session_id=8f2c1e9a77b04d1e",
    "deploy[7]: using api_key=sk-demo-ABCDEFGHIJKLMNOPQRSTUV and password=Winter2026!",
    "api-gw[3]: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhcGkiLCJyb2xlIjoic3JlIn0.c2lnbmF0dXJlX2RlbW8",
    "kernel: eth0: link up 1000Mbps full duplex",
    "cron[441]: (root) CMD (/usr/local/bin/backup.sh)",
]


def sample(host: str, t: float) -> dict | None:
    cpu, mem, bw, rtt = BASE[host]
    cpu += random.uniform(-6, 6)
    mem += random.uniform(-2, 2)
    bw *= random.uniform(0.7, 1.3)
    rtt *= random.uniform(0.8, 1.2)
    loss = 0.0
    phase = t % 160
    if host == "db-01" and 30 <= phase < 60:
        cpu, loss = random.uniform(93, 97), random.uniform(10, 15)
    if host == "api-01" and 60 <= phase < 90:
        rtt, loss = random.uniform(300, 380), random.uniform(5, 8)
    if host == "cache-01" and 90 <= phase < 130:
        return None                                   # outage: host stops reporting
    if host == "web-01" and 130 <= phase < 160:
        mem, cpu = random.uniform(92, 96), random.uniform(84, 90)
    msg = random.choice(LOGS) if random.random() < 0.6 else "heartbeat ok"
    return {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "host": host, "cpu": round(max(cpu, 0), 1), "mem": round(mem, 1), "net_mbps": round(bw, 2),
            "rtt_ms": round(rtt, 1), "loss_pct": round(loss, 1), "msg": msg}


def render(rec: dict, fmt: str, header_done: list) -> str:
    if fmt == "jsonl":
        return json.dumps(rec)
    if fmt == "kv":
        return " ".join(f'{k}="{v}"' if " " in str(v) else f"{k}={v}" for k, v in rec.items())
    keys = list(rec)                                  # csv
    row = ",".join(f'"{rec[k]}"' if "," in str(rec[k]) or " " in str(rec[k]) else str(rec[k]) for k in keys)
    if not header_done:
        header_done.append(True)
        return ",".join(keys) + "\n" + row
    return row


def main() -> None:
    ap = argparse.ArgumentParser(description="Simulated organiser telemetry stream")
    ap.add_argument("--format", choices=["jsonl", "csv", "kv"], default="jsonl")
    ap.add_argument("--rate", type=float, default=1.0, help="records per host per second (default 1)")
    ap.add_argument("--out", help="append to this file instead of stdout")
    ap.add_argument("--duration", type=float, default=0, help="stop after N seconds (default: run forever)")
    args = ap.parse_args()
    out = open(args.out, "a", encoding="utf-8") if args.out else sys.stdout
    t0, header_done = time.time(), []
    try:
        while not args.duration or time.time() - t0 < args.duration:
            t = time.time() - t0
            for host in HOSTS:
                rec = sample(host, t)
                if rec:
                    out.write(render(rec, args.format, header_done) + "\n")
            out.flush()
            time.sleep(1 / args.rate)
    except (KeyboardInterrupt, BrokenPipeError):
        pass


if __name__ == "__main__":
    main()
