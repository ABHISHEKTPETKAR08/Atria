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
| GET  | `/insights` | AIOps output: counters, node states, recommendations |
| POST | `/ingest`   | `Authorization: Bearer <token>`; 201 stored · 200 duplicate · 400 schema · 401 auth · 413 size |

Environment: `PORT`, `DB_PATH`, `INGEST_TOKEN`, `OFFLINE_AFTER_S`, `FLEET_WINDOW_S`.
