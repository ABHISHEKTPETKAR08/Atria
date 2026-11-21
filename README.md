# Smart Observability — Privacy-first 2-tier AIOps (CICADA 2026)

```
 Tier-1 Edge (Kali / Ubuntu / Windows)                 Tier-2 Central SaaS (Flask + SQLite WAL)
 ┌────────────────────────────────────┐   HTTPS +     ┌────────────────────────────────────────────┐
 │ raw logs ─► regex scrubber (local) │   Bearer      │ auth ─► allow-list ─► idempotent insert     │
 │ metrics + TCP probes ─► JSON event │ ────────────► │ AIOps: health · baseline · correlation      │
 │ DLP gate ─► write-ahead buffer     │  numeric-only │ recommendations ─► live dashboard (3 s)     │
 └────────────────────────────────────┘   metadata    └────────────────────────────────────────────┘
```

## Run locally
```bash
pip install -r requirements.txt
python host.py                     # dashboard + API on http://0.0.0.0:5000
```
On each teammate PC (only `requests` needed; `pip install psutil` recommended on Windows):
```bash
python collector.py --target local --demo                       # -> http://10.108.72.28:5000/ingest
python collector.py --url http://127.0.0.1:5000/ingest --demo   # same machine
python collector.py --target azure --app-name <app-name>        # -> https://<app-name>.azurewebsites.net/ingest
```
Demo flags: `--demo` mixes synthetic secret-bearing log lines into the egress-proof panel;
`--chaos {cpu_loss,latency,memory,bandwidth}` synthetically perturbs metrics after `--chaos-after` cycles so each
correlation rule can be shown live. Kill `host.py` while a collector runs to demo buffering and replay.

## Organiser telemetry stream (shared stream mode)
The collector can consume the organiser's shared stream instead of local metrics. It auto-detects JSON / JSON lines /
CSV (with header) / `key=value` / SSE `data:` / MQTT `topic {json}`, maps common field names automatically
(`cpu`, `cpu_pct`, `mem`, `rtt_ms`, `loss_pct`, `host`, `hostname`, `ts`, `@timestamp`, ...), aggregates per host every
`--interval` seconds and sends **one allow-listed event per host**. Raw records and log text never leave the node.
```bash
python3 collector.py --source /path/to/stream.jsonl --url <ingest-url>                 # tail a file
nc <host> <port> | python3 collector.py --source - --url <ingest-url>                  # raw TCP stream
curl -N <sse-url> | python3 collector.py --source - --url <ingest-url>                 # server-sent events
kcat -C -b <broker> -t <topic> | python3 collector.py --source - --url <ingest-url>     # Kafka
mosquitto_sub -h <broker> -t '#' -v | python3 collector.py --source - --url <ingest-url>  # MQTT
python3 collector.py --source https://<org>/telemetry --source-header "Authorization: Bearer <t>" --url <ingest-url>
```
If a field isn't recognised, map it: `--map "cpu_usage=load1,server_id=box,latency_ms=ping_avg"`.
Rehearse with the simulator (incidents: CPU+loss, latency jump, outage, memory pressure; logs with secrets):
```bash
python3 stream_simulator.py | python3 collector.py --source - --url <ingest-url>
```

## Real-time SLOs (measured from timestamps)
The dashboard's *Real-time SLOs* panel measures, from event capture timestamps: capture → SaaS (p50/p95),
capture → dashboard (≤ 10 s), alert detection = triggering sample's capture → alert raised (≤ 15 s, engine evaluates
every 2 s in the background), offline detection = last telemetry → OFFLINE (≤ 60 s; threshold 30 s), duplicates
blocked and replayed events. Keep node clocks NTP-synced (`sudo timedatectl set-ntp true`); skew is flagged.

## Deploy to Azure
```powershell
.\deploy_azure.ps1 -AppName smartobs-cicada-<team>
```

## API
| Method | Path | Notes |
|---|---|---|
| GET  | `/`         | Live dashboard |
| GET  | `/health`   | Liveness + DB/WAL status (503 if DB unavailable) |
| GET  | `/events`   | Recent telemetry (`?limit=1..500`, `?server_id=`) |
| GET  | `/insights` | AIOps output: counters, node states, recommendations, real-time SLOs |
| GET  | `/timeseries` | Per-node metric history for the charts (`?minutes=5..60`) |
| POST | `/ingest`   | `Authorization: Bearer <token>`; 201 stored · 200 duplicate · 400 schema · 401 auth · 413 size |

Environment: `PORT`, `DB_PATH`, `INGEST_TOKEN`, `OFFLINE_AFTER_S` (default 30), `FLEET_WINDOW_S`.
