"""
Smart Observability - Tier-2 Central SaaS (Flask + SQLite WAL + AIOps engine)

Privacy-first ingest: collectors only ever send numeric metadata. This service
  * authenticates every write (Bearer token, constant-time compare),
  * enforces a strict field allow-list + type/range validation (anything else -> 400),
  * deduplicates retries via event_id PRIMARY KEY (idempotent at-least-once delivery),
  * correlates multi-signal anomalies into human-readable, actionable recommendations,
  * serves a live dark-mode dashboard that refreshes every 3 s.

Run locally :  python host.py                        -> http://0.0.0.0:5000
Run (prod)  :  gunicorn host:app                     -> binds 0.0.0.0:$PORT (see gunicorn.conf.py)

Endpoints   :  GET /  GET /health  GET /events  GET /insights  POST /ingest
"""
from __future__ import annotations

import hmac
import math
import os
import re
import sqlite3
import statistics
import time
from datetime import datetime, timedelta, timezone

from flask import Flask, Response, g, jsonify, request

# --------------------------------------------------------------------------- #
# Configuration (12-factor: everything overridable through the environment)
# --------------------------------------------------------------------------- #
DB_PATH = os.environ.get("DB_PATH", "received.db")
INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "demo-secret-123")
OFFLINE_AFTER_S = int(os.environ.get("OFFLINE_AFTER_S", "60"))   # stale-data cut-off
FLEET_WINDOW_S = int(os.environ.get("FLEET_WINDOW_S", "3600"))   # forget nodes silent for longer
HISTORY_DEPTH = 60            # samples per node for the adaptive baseline (~5 min at 5 s)
REPLAY_DELAY_S = 30           # received_at - timestamp above this => store-and-forward replay
MAX_FUTURE_SKEW_S = 300       # reject timestamps too far in the future (clock abuse)
MAX_EVENT_AGE_DAYS = 30       # reject absurdly old timestamps

ALLOWED_FIELDS = frozenset({
    "event_id", "server_id", "cpu_usage", "memory_usage", "bandwidth_mbps",
    "latency_ms", "packet_loss", "health", "timestamp",
})
REQUIRED_FIELDS = ALLOWED_FIELDS - {"health"}
METRIC_BOUNDS = {
    "cpu_usage": (0.0, 100.0),
    "memory_usage": (0.0, 100.0),
    "packet_loss": (0.0, 100.0),
    "latency_ms": (0.0, 600_000.0),
    "bandwidth_mbps": (0.0, 1_000_000.0),
}
HEALTH_STATES = ("Excellent", "Good", "Fair", "Poor")
EVENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
SERVER_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")

# AIOps thresholds (single source of truth for health states and rules)
T = {
    "cpu_good": 50, "cpu_fair": 75, "cpu_high": 85, "cpu_crit": 90,
    "mem_good": 65, "mem_fair": 80, "mem_high": 90, "mem_crit": 92,
    "lat_good": 80, "lat_fair": 200, "lat_crit": 500,
    "loss_poor": 2.0,
    "lat_jump_ratio": 2.0, "lat_jump_min_ms": 50,     # "latency jump" vs node baseline
    "lat_rise_ratio": 1.5, "lat_rise_min_ms": 30,     # softer rise, used with bandwidth surge
    "bw_spike_ratio": 3.0, "bw_spike_min": 20,        # Mbps
    "sustain_n": 3,                                   # consecutive samples for single-metric alerts
    "fleet_ratio": 0.5,                               # > this share of nodes degraded => common cause
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024   # telemetry events are tiny; cap request bodies

# --------------------------------------------------------------------------- #
# SQLite (WAL mode, 10 s busy timeout)
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id       TEXT PRIMARY KEY,          -- idempotency key
    server_id      TEXT NOT NULL,
    cpu_usage      REAL NOT NULL,
    memory_usage   REAL NOT NULL,
    bandwidth_mbps REAL NOT NULL,
    latency_ms     REAL NOT NULL,
    packet_loss    REAL NOT NULL,
    health         TEXT,                      -- collector-reported (server recomputes its own)
    timestamp      TEXT NOT NULL,             -- original capture time, UTC ISO-8601
    ts_epoch       REAL NOT NULL,
    received_at    REAL NOT NULL              -- server receive time (liveness / replay detection)
);
CREATE INDEX IF NOT EXISTS idx_events_node_ts  ON events(server_id, ts_epoch DESC);
CREATE INDEX IF NOT EXISTS idx_events_received ON events(received_at DESC);
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0);
INSERT OR IGNORE INTO counters(name, value) VALUES ('duplicates_blocked', 0);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)          # 10 s busy wait instead of "database is locked"
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA synchronous=NORMAL;")           # durable + fast under WAL
    return conn


def init_db() -> str:
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        mode = conn.execute("PRAGMA journal_mode=WAL;").fetchone()[0]   # persistent per DB file
        conn.executescript(SCHEMA)
        conn.commit()
        return mode
    finally:
        conn.close()


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = _connect()
    return g.db


@app.teardown_appcontext
def _close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


JOURNAL_MODE = init_db()   # runs at import so gunicorn workers are ready


# --------------------------------------------------------------------------- #
# Security helpers
# --------------------------------------------------------------------------- #
def _authorized() -> bool:
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    return scheme.lower() == "bearer" and hmac.compare_digest(
        token.strip().encode(), INGEST_TOKEN.encode())


@app.after_request
def _security_headers(resp: Response) -> Response:
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
    if request.path != "/":
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.errorhandler(413)
def _too_large(_e):
    return jsonify(error="payload too large"), 413


# --------------------------------------------------------------------------- #
# Validation (schema allow-list + types + ranges)
# --------------------------------------------------------------------------- #
def _parse_ts(value) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def validate(payload) -> tuple[dict | None, str | None]:
    if not isinstance(payload, dict):
        return None, "body must be a single JSON object"
    unknown = set(payload) - ALLOWED_FIELDS
    if unknown:   # privacy gate: anything outside the allow-list (e.g. raw log text) is refused
        shown = sorted(str(k)[:40] for k in unknown)[:10]
        return None, f"fields not in allow-list: {shown}"
    missing = REQUIRED_FIELDS - set(payload)
    if missing:
        return None, f"missing required fields: {sorted(missing)}"

    ev = {}
    for key, rx in (("event_id", EVENT_ID_RE), ("server_id", SERVER_ID_RE)):
        val = payload[key]
        if not isinstance(val, str) or not rx.match(val):
            return None, f"invalid {key}"
        ev[key] = val

    for key, (lo, hi) in METRIC_BOUNDS.items():
        val = payload[key]
        if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val):
            return None, f"{key} must be a finite number"
        if not lo <= val <= hi:
            return None, f"{key} out of range [{lo:g}, {hi:g}]"
        ev[key] = float(val)

    health = payload.get("health")
    if health is not None and health not in HEALTH_STATES:
        return None, f"health must be one of {list(HEALTH_STATES)}"
    ev["health"] = health

    try:
        ts = _parse_ts(payload["timestamp"])
    except (ValueError, TypeError):
        return None, "timestamp must be ISO-8601 (e.g. 2026-11-20T10:15:30.123Z)"
    now = datetime.now(timezone.utc)
    if ts > now + timedelta(seconds=MAX_FUTURE_SKEW_S):
        return None, "timestamp is in the future (check node clock / NTP)"
    if ts < now - timedelta(days=MAX_EVENT_AGE_DAYS):
        return None, "timestamp too old"
    ev["timestamp"], ev["ts_epoch"] = _iso(ts), ts.timestamp()
    return ev, None


# --------------------------------------------------------------------------- #
# AIOps engine: health states, multi-signal correlation, recommendations
# --------------------------------------------------------------------------- #
def _f(x: float) -> str:
    return (f"{x:.2f}" if abs(x) < 10 else f"{x:.1f}").rstrip("0").rstrip(".")


def _ratio(x: float, base: float) -> str:
    r = x / max(base, 0.01)
    return ">100x" if r > 100 else f"{r:.1f}x"


def _lat_jump(lat: float, base: float | None, ratio: float, min_ms: float) -> bool:
    return base is not None and lat >= base * ratio and lat - base >= min_ms


def classify(ev: dict, base_lat: float | None = None) -> str:
    cpu, mem, lat, loss = ev["cpu_usage"], ev["memory_usage"], ev["latency_ms"], ev["packet_loss"]
    if loss >= T["loss_poor"] or cpu >= T["cpu_crit"] or mem >= T["mem_crit"] or lat >= T["lat_crit"]:
        return "Poor"        # critical breach or packet loss
    if (loss > 0 or cpu >= T["cpu_fair"] or mem >= T["mem_fair"] or lat >= T["lat_fair"]
            or _lat_jump(lat, base_lat, T["lat_jump_ratio"], T["lat_jump_min_ms"])):
        return "Fair"        # elevated baseline / latency
    if cpu >= T["cpu_good"] or mem >= T["mem_good"] or lat >= T["lat_good"]:
        return "Good"        # minor load
    return "Excellent"       # all metrics optimal


SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}


def _rec(severity: str, node: str | None, rule: str, finding: str, action: str, label: str | None = None) -> dict:
    label = label or {"critical": "ALERT", "warning": "WARN", "info": "INFO"}[severity]
    scope = f"Node {node}" if node else "Fleet"
    return {"severity": severity, "rule": rule, "server_id": node,
            "message": f"{label} [{scope}]: {finding} Recommended Action: {action}"}


def node_rules(sid: str, hist: list[dict], base_lat: float | None, base_bw: float | None) -> list[dict]:
    """Correlate signals on the latest sample. Single-metric spikes alone never alert."""
    e = hist[0]
    cpu, mem, bw, lat, loss = (e["cpu_usage"], e["memory_usage"], e["bandwidth_mbps"],
                               e["latency_ms"], e["packet_loss"])
    lossy = loss >= T["loss_poor"]
    jump = _lat_jump(lat, base_lat, T["lat_jump_ratio"], T["lat_jump_min_ms"])
    rise = _lat_jump(lat, base_lat, T["lat_rise_ratio"], T["lat_rise_min_ms"])
    spike = base_bw is not None and bw >= max(base_bw, 0.1) * T["bw_spike_ratio"] and bw >= T["bw_spike_min"]
    out: list[dict] = []

    if cpu >= T["cpu_high"] and lossy:
        out.append(_rec("critical", sid, "cpu+packet_loss",
                        f"High CPU breach ({cpu:.0f}%) correlated with {_f(loss)}% packet loss.",
                        "Restart local telemetry collector or re-balance worker threads; "
                        "inspect the top CPU consumer (top / Task Manager)."))
    if jump and lossy:
        out.append(_rec("critical", sid, "latency_jump+packet_loss",
                        f"Latency jump {_f(base_lat)} -> {_f(lat)} ms ({_ratio(lat, base_lat)} baseline) "
                        f"correlated with {_f(loss)}% packet loss - probable network path degradation.",
                        "Check NIC / Wi-Fi link errors and the upstream gateway; fail over to a wired "
                        "or alternate route."))
    if mem >= T["mem_high"] and cpu >= T["cpu_fair"]:
        out.append(_rec("critical", sid, "memory+cpu",
                        f"Memory pressure ({mem:.0f}%) with CPU at {cpu:.0f}% - swap-thrashing / memory-leak signature.",
                        "Identify the top RSS process and restart the leaking service; add memory or "
                        "scale the workload out."))
    if spike and rise:
        out.append(_rec("warning", sid, "bandwidth_surge+latency",
                        f"Bandwidth surge {_f(bw)} Mbps ({_ratio(bw, base_bw)} baseline {_f(base_bw)}) "
                        f"correlated with latency rise {_f(base_lat)} -> {_f(lat)} ms - link saturation.",
                        "Identify top talkers (iftop / Resource Monitor), apply QoS or rate limits and "
                        "verify the transfer is authorized (possible exfiltration)."))
    if cpu >= T["cpu_high"] and jump and not lossy:
        out.append(_rec("warning", sid, "cpu+latency",
                        f"CPU saturation ({cpu:.0f}%) is inflating latency ({_f(base_lat)} -> {_f(lat)} ms).",
                        "Re-balance worker threads or scale horizontally; profile the hot process."))

    # Temporal correlation: a single critical metric must persist N samples before alerting.
    window = hist[:T["sustain_n"]]
    if not out and len(window) == T["sustain_n"]:
        for key, thr, name, action in (
            ("cpu_usage", T["cpu_crit"], "CPU", "Throttle or reschedule batch jobs; re-balance worker threads."),
            ("memory_usage", T["mem_crit"], "memory", "Restart the leaking service; raise memory limits."),
            ("packet_loss", T["loss_poor"], "packet-loss", "Inspect cabling / Wi-Fi signal and switch port errors."),
            ("latency_ms", T["lat_crit"], "latency", "Trace the route (tracert / mtr) to locate the slow hop."),
        ):
            if all(w[key] >= thr for w in window):
                out.append(_rec("warning", sid, f"sustained_{key}",
                                f"Sustained {name} breach for {len(window)} consecutive samples "
                                f"(latest {_f(e[key])}).", action))
    return out


def analyze(now: float | None = None) -> dict:
    now = now or time.time()
    db = get_db()
    since = now - FLEET_WINDOW_S

    stats = {r["server_id"]: r for r in db.execute(
        "SELECT server_id, COUNT(*) AS n, MAX(received_at) AS last_rx FROM events "
        "WHERE received_at >= ? GROUP BY server_id", (since,))}
    history: dict[str, list[dict]] = {}
    for r in db.execute(
            "SELECT * FROM (SELECT e.*, ROW_NUMBER() OVER (PARTITION BY server_id ORDER BY ts_epoch DESC) AS rn "
            "FROM events e WHERE received_at >= ?) WHERE rn <= ? ORDER BY server_id, rn",
            (since, HISTORY_DEPTH)):
        history.setdefault(r["server_id"], []).append(dict(r))
    replays = {r["server_id"]: r for r in db.execute(
        "SELECT server_id, COUNT(*) AS n, MAX(received_at - ts_epoch) AS max_delay FROM events "
        "WHERE received_at >= ? AND received_at - ts_epoch > ? GROUP BY server_id",
        (now - 120, REPLAY_DELAY_S))}

    nodes, recs, degraded, online = [], [], [], 0
    for sid, hist in sorted(history.items()):
        latest, prev = hist[0], hist[1:]
        # Baseline = median of earlier *clean* samples, so an ongoing incident doesn't become "normal".
        clean = [p for p in prev if p["packet_loss"] < T["loss_poor"]]
        ref = clean if len(clean) >= 3 else prev
        base_lat = statistics.median(p["latency_ms"] for p in ref) if len(ref) >= 3 else None
        base_bw = statistics.median(p["bandwidth_mbps"] for p in ref) if len(ref) >= 3 else None
        age = now - stats[sid]["last_rx"]
        health = classify(latest, base_lat)
        offline = age > OFFLINE_AFTER_S

        if offline:
            recs.append(_rec("critical", sid, "outage",
                             f"No telemetry for {age:.0f}s (threshold {OFFLINE_AFTER_S}s); last known health "
                             f"{health}, last sample {latest['timestamp']}.",
                             "Verify the collector process and the node's network path to the SaaS; "
                             "the collector buffer will replay missed events on reconnect.", label="OUTAGE"))
        else:
            online += 1
            recs.extend(node_rules(sid, hist, base_lat, base_bw))
            if latest["packet_loss"] >= T["loss_poor"] or _lat_jump(
                    latest["latency_ms"], base_lat, T["lat_jump_ratio"], T["lat_jump_min_ms"]):
                degraded.append(sid)
        if sid in replays:
            rp = replays[sid]
            recs.append(_rec("info", sid, "store_and_forward_replay",
                             f"Reconnected - {rp['n']} buffered events replayed with original UTC timestamps "
                             f"(max delay {rp['max_delay']:.0f}s). Zero data loss.",
                             "None required; review the root cause of the earlier connectivity gap.",
                             label="RECOVERED"))

        nodes.append({
            "server_id": sid, "status": "OFFLINE" if offline else health, "health": health,
            "cpu_usage": latest["cpu_usage"], "memory_usage": latest["memory_usage"],
            "bandwidth_mbps": latest["bandwidth_mbps"], "latency_ms": latest["latency_ms"],
            "packet_loss": latest["packet_loss"], "baseline_latency_ms": base_lat,
            "last_seen_s": round(age, 1), "last_timestamp": latest["timestamp"],
            "events_window": stats[sid]["n"],
        })

    if len(degraded) >= 2 and len(degraded) / online > T["fleet_ratio"]:   # strict majority
        recs.append(_rec("critical", None, "fleet_network_degradation",
                         f"{len(degraded)}/{online} online nodes show simultaneous latency jump / packet loss "
                         f"({', '.join(degraded[:6])}) - common upstream cause.",
                         "Investigate the shared path (central SaaS ingress, core switch, ISP/gateway) "
                         "before touching individual nodes."))

    recs.sort(key=lambda r: SEVERITY_RANK[r["severity"]])
    for r in recs:
        r["generated_at"] = _iso(datetime.fromtimestamp(now, timezone.utc))

    total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    last_min = db.execute("SELECT COUNT(*) FROM events WHERE received_at >= ?", (now - 60,)).fetchone()[0]
    dups = db.execute("SELECT value FROM counters WHERE name='duplicates_blocked'").fetchone()[0]
    return {
        "generated_at": _iso(datetime.fromtimestamp(now, timezone.utc)),
        "counters": {
            "total_events": total, "events_last_min": last_min, "duplicates_blocked": dups,
            "nodes_total": len(nodes), "nodes_online": online, "nodes_offline": len(nodes) - online,
            "alerts_active": sum(r["severity"] != "info" for r in recs),
        },
        "recommendations": recs,
        "nodes": nodes,
        "thresholds": {"offline_after_s": OFFLINE_AFTER_S, **T},
    }


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.post("/ingest")
def ingest():
    if not _authorized():   # authenticate before touching the body
        return jsonify(error="unauthorized"), 401, {"WWW-Authenticate": 'Bearer realm="smart-observability"'}
    ev, err = validate(request.get_json(force=True, silent=True))
    if err:
        return jsonify(error=err), 400

    ev["received_at"] = time.time()
    db = get_db()
    try:
        with db:
            db.execute(
                "INSERT INTO events (event_id, server_id, cpu_usage, memory_usage, bandwidth_mbps, latency_ms, "
                "packet_loss, health, timestamp, ts_epoch, received_at) VALUES "
                "(:event_id, :server_id, :cpu_usage, :memory_usage, :bandwidth_mbps, :latency_ms, "
                ":packet_loss, :health, :timestamp, :ts_epoch, :received_at)", ev)
    except sqlite3.IntegrityError:   # same event_id already stored -> idempotent retry
        with db:
            db.execute("UPDATE counters SET value = value + 1 WHERE name='duplicates_blocked'")
        return jsonify(status="duplicate event ignored", event_id=ev["event_id"]), 200
    return jsonify(status="stored", event_id=ev["event_id"], health=classify(ev)), 201


@app.get("/events")
def events():
    try:
        limit = max(1, min(int(request.args.get("limit", 100)), 500))
    except ValueError:
        limit = 100
    sql = ("SELECT event_id, server_id, cpu_usage, memory_usage, bandwidth_mbps, latency_ms, packet_loss, "
           "health, timestamp, received_at FROM events")
    args: tuple = ()
    if request.args.get("server_id"):
        sql += " WHERE server_id = ?"
        args = (request.args["server_id"],)
    rows = get_db().execute(sql + " ORDER BY received_at DESC LIMIT ?", (*args, limit)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/insights")
def insights():
    return jsonify(analyze())


@app.get("/health")
def health():
    try:
        db = get_db()
        mode = db.execute("PRAGMA journal_mode;").fetchone()[0]
        count = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    except sqlite3.Error as exc:
        return jsonify(status="degraded", db="error", detail=type(exc).__name__), 503
    return jsonify(status="ok", service="smart-observability-tier2", db="ok", journal_mode=mode,
                   events=count, time=_iso(datetime.now(timezone.utc)))


@app.get("/")
def dashboard():
    return Response(DASHBOARD_HTML, mimetype="text/html")


# --------------------------------------------------------------------------- #
# Embedded dashboard (no external assets; all dynamic values are HTML-escaped)
# --------------------------------------------------------------------------- #
DASHBOARD_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Smart Observability · AIOps</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2128;--border:#30363d;--text:#e6edf3;--muted:#8b949e;
--green:#3fb950;--blue:#58a6ff;--yellow:#d29922;--red:#f85149;--gray:#6e7681}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
.mono,.rec{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.wrap{max-width:1440px;margin:0 auto;padding:20px 24px 40px}
header{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;padding-bottom:16px;border-bottom:1px solid var(--border);margin-bottom:20px}
h1{font-size:20px;margin:0;font-weight:600}
.sub{color:var(--muted);font-size:12px}
.pill{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--border);border-radius:999px;padding:4px 12px;font-size:12px;color:var(--muted)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green);animation:pulse 2s infinite}
.dot.down{background:var(--red);animation:none}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(63,185,80,.6)}70%{box-shadow:0 0 0 8px rgba(63,185,80,0)}100%{box-shadow:0 0 0 0 rgba(63,185,80,0)}}
section{background:var(--panel);border:1px solid var(--border);border-radius:8px;margin-bottom:20px;overflow:hidden}
section>h2{font-size:13px;font-weight:600;margin:0;padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;gap:8px}
.feed{max-height:340px;overflow:auto}
.rec{padding:10px 16px;border-bottom:1px solid var(--border);border-left:3px solid var(--gray);font-size:12.5px;white-space:pre-wrap;word-break:break-word}
.rec:last-child{border-bottom:none}
.rec.critical{border-left-color:var(--red);background:rgba(248,81,73,.07)}
.rec.warning{border-left-color:var(--yellow);background:rgba(210,153,34,.07)}
.rec.info{border-left-color:var(--blue);background:rgba(88,166,255,.05)}
.rec .act{color:var(--green)}
.rec .meta{color:var(--muted);font-size:11px;margin-top:2px}
.ok{padding:14px 16px;color:var(--green)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:14px 16px}
.card .label{color:var(--muted);font-size:12px}
.card .value{font-size:26px;font-weight:600;margin-top:2px;font-variant-numeric:tabular-nums}
.v-red{color:var(--red)}.v-green{color:var(--green)}.v-yellow{color:var(--yellow)}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:8px 16px;border-bottom:1px solid var(--border);white-space:nowrap}
th{color:var(--muted);font-weight:500;font-size:12px;background:var(--panel2)}
tr:last-child td{border-bottom:none}
td.mono{font-size:12.5px}
.badge{display:inline-block;padding:1px 10px;border-radius:999px;font-size:12px;font-weight:500;border:1px solid}
.b-Excellent{color:var(--green);border-color:rgba(63,185,80,.45);background:rgba(63,185,80,.12)}
.b-Good{color:var(--blue);border-color:rgba(88,166,255,.45);background:rgba(88,166,255,.12)}
.b-Fair{color:var(--yellow);border-color:rgba(210,153,34,.45);background:rgba(210,153,34,.12)}
.b-Poor{color:var(--red);border-color:rgba(248,81,73,.45);background:rgba(248,81,73,.12)}
.b-OFFLINE{color:var(--muted);border-color:var(--red);background:rgba(110,118,129,.18)}
.b-none{color:var(--muted);border-color:var(--border)}
.bar{display:inline-block;width:56px;height:6px;background:var(--border);border-radius:3px;margin-right:8px;vertical-align:middle;overflow:hidden}
.bar>i{display:block;height:100%}
.muted{color:var(--muted)}
.empty{padding:14px 16px;color:var(--muted)}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:8px}
</style></head>
<body><div class="wrap">
<header>
  <div><h1>Smart Observability <span class="muted" style="font-weight:400">· AIOps Command Center</span></h1>
  <div class="sub">Tier-2 Central SaaS · privacy-first edge telemetry · secrets never leave the node</div></div>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <span class="pill"><span id="dot" class="dot"></span><span id="live">connecting…</span></span>
    <span class="pill">refresh 3s · <span id="updated">—</span></span>
  </div>
</header>

<section>
  <h2><span>⚡ Actionable AIOps Recommendation Feed</span><span class="muted" id="feedcount"></span></h2>
  <div class="feed" id="feed"><div class="empty">Waiting for telemetry…</div></div>
</section>

<div class="cards">
  <div class="card"><div class="label">Total events ingested</div><div class="value" id="c-total">0</div></div>
  <div class="card"><div class="label">Ingest rate (events / min)</div><div class="value" id="c-rate">0</div></div>
  <div class="card"><div class="label">Active nodes</div><div class="value v-green" id="c-online">0</div></div>
  <div class="card"><div class="label">Offline nodes (&gt;60s silent)</div><div class="value" id="c-offline">0</div></div>
  <div class="card"><div class="label">Active alerts</div><div class="value" id="c-alerts">0</div></div>
  <div class="card"><div class="label">Duplicates blocked (idempotency)</div><div class="value" id="c-dups">0</div></div>
</div>

<section>
  <h2><span>🖥 Node Fleet</span><span class="muted">health: Excellent · Good · Fair · Poor · OFFLINE</span></h2>
  <div class="scroll"><table>
    <thead><tr><th>Node</th><th>Status</th><th>CPU</th><th>Memory</th><th>Bandwidth</th><th>Latency (baseline)</th><th>Packet loss</th><th>Last seen</th><th>Events (1h)</th></tr></thead>
    <tbody id="fleet"><tr><td colspan="9" class="empty">No nodes reporting yet.</td></tr></tbody>
  </table></div>
</section>

<section>
  <h2><span>📡 Live Sanitized Telemetry</span><span class="muted">allow-listed fields only · newest first</span></h2>
  <div class="scroll"><table>
    <thead><tr><th>Captured (UTC)</th><th>Event ID</th><th>Node</th><th>CPU %</th><th>Mem %</th><th>Mbps</th><th>Latency ms</th><th>Loss %</th><th>Reported health</th></tr></thead>
    <tbody id="events"><tr><td colspan="9" class="empty">No events yet.</td></tr></tbody>
  </table></div>
</section>
<footer>Bearer-auth ingest · schema allow-list · idempotent event_id · SQLite WAL · alert latency = collector interval (5s) + UI refresh (3s) &lt; 10s</footer>
</div>
<script>
const $ = id => document.getElementById(id);
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const num = (v, d = 1) => (v === null || v === undefined) ? "—" : Number(v).toFixed(d);
const color = (v, warn, crit) => v >= crit ? "var(--red)" : v >= warn ? "var(--yellow)" : "var(--green)";
const bar = (v, warn, crit) => `<span class="bar"><i style="width:${Math.min(100, Math.max(0, v))}%;background:${color(v, warn, crit)}"></i></span>${num(v)}%`;
const badge = s => `<span class="badge b-${esc(s || "none")}">${esc(s || "n/a")}</span>`;
const ago = s => s < 60 ? `${Math.round(s)}s ago` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s ago`;

function renderFeed(recs) {
  $("feedcount").textContent = recs.length ? `${recs.length} item(s)` : "";
  if (!recs.length) { $("feed").innerHTML = '<div class="ok">✓ All systems nominal — no correlated anomalies detected.</div>'; return; }
  $("feed").innerHTML = recs.map(r => {
    const [finding, action] = r.message.split(" Recommended Action: ");
    return `<div class="rec ${esc(r.severity)}">${esc(finding)}${action ? ` <span class="act">Recommended Action: ${esc(action)}</span>` : ""}`
         + `<div class="meta">${esc(r.severity.toUpperCase())} · rule=${esc(r.rule)} · ${esc(r.generated_at)}</div></div>`;
  }).join("");
}

function renderFleet(nodes) {
  if (!nodes.length) return;
  $("fleet").innerHTML = nodes.map(n => `<tr>
    <td class="mono">${esc(n.server_id)}</td><td>${badge(n.status)}</td>
    <td>${bar(n.cpu_usage, 75, 90)}</td><td>${bar(n.memory_usage, 80, 92)}</td>
    <td>${num(n.bandwidth_mbps, 2)} Mbps</td>
    <td>${num(n.latency_ms)} ms <span class="muted">(${n.baseline_latency_ms === null ? "learning" : num(n.baseline_latency_ms)})</span></td>
    <td style="color:${color(n.packet_loss, 0.01, 2)}">${num(n.packet_loss)}%</td>
    <td class="${n.status === "OFFLINE" ? "v-red" : "muted"}">${ago(n.last_seen_s)}</td><td>${esc(n.events_window)}</td></tr>`).join("");
}

function renderEvents(evs) {
  if (!evs.length) return;
  $("events").innerHTML = evs.map(e => `<tr>
    <td class="mono">${esc(String(e.timestamp).replace("T", " ").replace("Z", ""))}</td>
    <td class="mono muted">${esc(String(e.event_id).slice(0, 8))}…</td><td class="mono">${esc(e.server_id)}</td>
    <td>${num(e.cpu_usage)}</td><td>${num(e.memory_usage)}</td><td>${num(e.bandwidth_mbps, 2)}</td>
    <td>${num(e.latency_ms)}</td><td>${num(e.packet_loss)}</td><td>${badge(e.health)}</td></tr>`).join("");
}

async function tick() {
  try {
    const [ins, evs] = await Promise.all([
      fetch("/insights", {cache: "no-store"}).then(r => { if (!r.ok) throw r.status; return r.json(); }),
      fetch("/events?limit=25", {cache: "no-store"}).then(r => { if (!r.ok) throw r.status; return r.json(); })]);
    const c = ins.counters;
    $("c-total").textContent = c.total_events.toLocaleString();
    $("c-rate").textContent = c.events_last_min;
    $("c-online").textContent = `${c.nodes_online}/${c.nodes_total}`;
    $("c-offline").textContent = c.nodes_offline; $("c-offline").className = "value " + (c.nodes_offline ? "v-red" : "v-green");
    $("c-alerts").textContent = c.alerts_active; $("c-alerts").className = "value " + (c.alerts_active ? "v-red" : "v-green");
    $("c-dups").textContent = c.duplicates_blocked;
    renderFeed(ins.recommendations); renderFleet(ins.nodes); renderEvents(evs);
    $("dot").className = "dot"; $("live").textContent = "live";
    $("updated").textContent = new Date().toLocaleTimeString();
  } catch (e) { $("dot").className = "dot down"; $("live").textContent = "SaaS unreachable — retrying"; }
}
tick(); setInterval(tick, 3000);
</script></body></html>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    print(f"[smart-observability] Tier-2 SaaS on 0.0.0.0:{port} | db={DB_PATH} journal_mode={JOURNAL_MODE}")
    app.run(host="0.0.0.0", port=port, threaded=True, debug=False)
