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
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone

from flask import Flask, Response, g, jsonify, request

# --------------------------------------------------------------------------- #
# Configuration (12-factor: everything overridable through the environment)
# --------------------------------------------------------------------------- #
ON_AZURE = bool(os.environ.get("WEBSITE_SITE_NAME"))          # set by Azure App Service
# SQLite WAL needs a local filesystem. Azure's /home is a network (SMB) share, so default to local /tmp there.
DB_PATH = os.environ.get("DB_PATH") or ("/tmp/received.db" if ON_AZURE else "received.db")
INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "demo-secret-123")
OFFLINE_AFTER_S = int(os.environ.get("OFFLINE_AFTER_S", "30"))   # stale-data cut-off (6 missed 5 s cycles)
EVAL_INTERVAL_S = 2.0         # background AIOps evaluation period (alerts don't wait for a viewer)
SLO_TARGETS = {"dashboard_s": 10, "alert_s": 15, "offline_s": 60}   # hackathon real-time targets
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
CREATE TABLE IF NOT EXISTS alerts (           -- alert lifecycle, for measured detection latency
    key         TEXT PRIMARY KEY,             -- rule|server_id
    rule        TEXT NOT NULL,
    server_id   TEXT,
    severity    TEXT NOT NULL,
    trigger_ts  REAL NOT NULL,                -- capture time of the sample that triggered it (outage: last rx)
    first_seen  REAL NOT NULL,                -- server time the engine first raised it
    last_seen   REAL NOT NULL,
    resolved_at REAL
);
CREATE INDEX IF NOT EXISTS idx_alerts_first ON alerts(first_seen DESC);
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


def _init_db_with_fallback() -> str:
    """Never let a bad DB_PATH crash the container: fall back to the local temp dir."""
    global DB_PATH
    try:
        return init_db()
    except (sqlite3.Error, OSError) as exc:
        fallback = os.path.join(tempfile.gettempdir(), "received.db")
        if os.path.abspath(DB_PATH) == fallback:
            raise
        print(f"[smart-observability] DB_PATH={DB_PATH} unusable ({exc}); falling back to {fallback}",
              file=sys.stderr, flush=True)
        DB_PATH = fallback
        return init_db()


JOURNAL_MODE = _init_db_with_fallback()   # runs at import so gunicorn workers are ready
print(f"[smart-observability] ready | db={DB_PATH} journal_mode={JOURNAL_MODE} azure={ON_AZURE}", flush=True)


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


def _rec(severity: str, node: str | None, rule: str, finding: str, action: str, label: str | None = None,
         trigger_ts: float | None = None) -> dict:
    label = label or {"critical": "ALERT", "warning": "WARN", "info": "INFO"}[severity]
    scope = f"Node {node}" if node else "Fleet"
    return {"severity": severity, "rule": rule, "server_id": node, "trigger_ts": trigger_ts,
            "message": f"{label} [{scope}]: {finding} Recommended Action: {action}"}


def _pct(vals: list[float], q: float) -> float | None:
    """Nearest-rank percentile."""
    if not vals:
        return None
    srt = sorted(vals)
    return round(srt[max(0, min(len(srt) - 1, math.ceil(q / 100 * len(srt)) - 1))], 2)


def track_alerts(db: sqlite3.Connection, recs: list[dict], now: float) -> None:
    """Persist alert lifecycle so detection latency (first raised - triggering sample's capture time)
    is measured, not assumed. Info items (e.g. replay notices) are not alerts."""
    active = {f"{r['rule']}|{r['server_id'] or '*'}": r for r in recs if r["severity"] != "info"}
    with db:
        open_rows = {row["key"]: row for row in db.execute("SELECT * FROM alerts WHERE resolved_at IS NULL")}
        for key, r in active.items():
            row = open_rows.get(key)
            if row:
                db.execute("UPDATE alerts SET last_seen = ? WHERE key = ?", (now, key))
                r["first_seen"], r["trigger_ts"] = row["first_seen"], row["trigger_ts"]
            else:
                trig = r["trigger_ts"] if r["trigger_ts"] is not None else now
                db.execute(
                    "INSERT INTO alerts (key, rule, server_id, severity, trigger_ts, first_seen, last_seen, resolved_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, NULL) ON CONFLICT(key) DO UPDATE SET severity = excluded.severity, "
                    "trigger_ts = excluded.trigger_ts, first_seen = excluded.first_seen, last_seen = excluded.last_seen, "
                    "resolved_at = NULL WHERE alerts.resolved_at IS NOT NULL",
                    (key, r["rule"], r["server_id"], r["severity"], trig, now, now))
                row = db.execute("SELECT first_seen, trigger_ts FROM alerts WHERE key = ?", (key,)).fetchone()
                r["first_seen"], r["trigger_ts"] = row["first_seen"], row["trigger_ts"]
            r["detected_after_s"] = round(r["first_seen"] - r["trigger_ts"], 1)
        for key in open_rows.keys() - active.keys():
            db.execute("UPDATE alerts SET resolved_at = ? WHERE key = ? AND resolved_at IS NULL", (now, key))


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
    for r in out:
        r["trigger_ts"] = e["ts_epoch"]
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

    # Real-time measurement from timestamps: capture (event timestamp) -> received by the SaaS.
    delays: dict[str, list[float]] = {}
    replayed_5m = 0
    for r in db.execute("SELECT server_id, received_at - ts_epoch AS d FROM events WHERE received_at >= ?",
                        (now - 300,)):
        if r["d"] > REPLAY_DELAY_S:
            replayed_5m += 1           # store-and-forward replays are reported separately, not as live latency
        else:
            delays.setdefault(r["server_id"], []).append(r["d"])
    latest_ts: dict[str, float] = {}

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
                             "the collector buffer will replay missed events on reconnect.", label="OUTAGE",
                             trigger_ts=stats[sid]["last_rx"]))
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
            "ingest_delay_s": round(statistics.median(delays[sid]), 2) if delays.get(sid) else None,
        })
        latest_ts[sid] = latest["ts_epoch"]

    if len(degraded) >= 2 and len(degraded) / online > T["fleet_ratio"]:   # strict majority
        recs.append(_rec("critical", None, "fleet_network_degradation",
                         f"{len(degraded)}/{online} online nodes show simultaneous latency jump / packet loss "
                         f"({', '.join(degraded[:6])}) - common upstream cause.",
                         "Investigate the shared path (central SaaS ingress, core switch, ISP/gateway) "
                         "before touching individual nodes.", trigger_ts=max(latest_ts[d] for d in degraded)))

    track_alerts(db, recs, now)
    recs.sort(key=lambda r: SEVERITY_RANK[r["severity"]])
    for r in recs:
        r["generated_at"] = _iso(datetime.fromtimestamp(now, timezone.utc))
        r["trigger_at"] = _iso(datetime.fromtimestamp(r["trigger_ts"], timezone.utc)) if r["trigger_ts"] else None
        r.pop("trigger_ts", None)
        r.pop("first_seen", None)

    live = [d for v in delays.values() for d in v]
    hist_alerts = db.execute("SELECT rule, first_seen - trigger_ts AS d FROM alerts WHERE first_seen >= ?",
                             (now - 3600,)).fetchall()
    alert_d = [a["d"] for a in hist_alerts if a["rule"] != "outage"]
    offline_d = [a["d"] for a in hist_alerts if a["rule"] == "outage"]
    slo = {
        "targets": SLO_TARGETS, "offline_after_s": OFFLINE_AFTER_S, "eval_interval_s": EVAL_INTERVAL_S,
        "ingest_p50_s": _pct(live, 50), "ingest_p95_s": _pct(live, 95), "ingest_samples": len(live),
        "replayed_5m": replayed_5m,
        "skew_nodes": sorted(sid for sid, v in delays.items() if statistics.median(v) < -1.0),
        "alert_p50_s": _pct(alert_d, 50), "alert_p95_s": _pct(alert_d, 95),
        "alert_max_s": round(max(alert_d), 2) if alert_d else None, "alert_samples": len(alert_d),
        "offline_last_s": round(offline_d[-1], 1) if offline_d else None,
        "offline_max_s": round(max(offline_d), 1) if offline_d else None, "offline_samples": len(offline_d),
    }

    total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    last_min = db.execute("SELECT COUNT(*) FROM events WHERE received_at >= ?", (now - 60,)).fetchone()[0]
    dups = db.execute("SELECT value FROM counters WHERE name='duplicates_blocked'").fetchone()[0]
    return {
        "now": now,
        "generated_at": _iso(datetime.fromtimestamp(now, timezone.utc)),
        "slo": slo,
        "counters": {
            "total_events": total, "events_last_min": last_min, "duplicates_blocked": dups,
            "nodes_total": len(nodes), "nodes_online": online, "nodes_offline": len(nodes) - online,
            "alerts_active": sum(r["severity"] != "info" for r in recs),
        },
        "recommendations": recs,
        "nodes": nodes,
        "thresholds": {"offline_after_s": OFFLINE_AFTER_S, **T},
    }


_eval_lock = threading.Lock()
_eval_started = False


def _evaluator() -> None:
    while True:
        time.sleep(EVAL_INTERVAL_S)
        try:
            with app.app_context():
                analyze()
        except Exception as exc:   # keep evaluating; a transient DB error must not kill the loop
            print(f"[smart-observability] evaluator error: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)


@app.before_request
def _start_evaluator() -> None:
    """One evaluator thread per worker process, started after fork (gunicorn-safe)."""
    global _eval_started
    if not _eval_started:
        with _eval_lock:
            if not _eval_started:
                threading.Thread(target=_evaluator, name="aiops-evaluator", daemon=True).start()
                _eval_started = True


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


@app.get("/timeseries")
def timeseries():
    """Per-node metric history for the fleet charts, bucketed to <= ~240 points per node.
    Ordered by capture time, so replayed (buffered) events land where they belong."""
    try:
        minutes = max(1, min(int(request.args.get("minutes", 15)), 60))
    except ValueError:
        minutes = 15
    now = time.time()
    window = minutes * 60
    bucket = max(5.0, window / 240)
    rows = get_db().execute(
        "SELECT server_id, CAST(ts_epoch / ? AS INTEGER) AS b, AVG(ts_epoch) AS t, AVG(cpu_usage) AS cpu, "
        "AVG(memory_usage) AS mem, AVG(bandwidth_mbps) AS bw, AVG(latency_ms) AS lat, MAX(packet_loss) AS loss, "
        "COUNT(*) AS n "
        "FROM events WHERE ts_epoch >= ? AND ts_epoch <= ? GROUP BY server_id, b ORDER BY server_id, b",
        (bucket, now - window, now + MAX_FUTURE_SKEW_S)).fetchall()
    series: dict[str, list] = {}
    for r in rows:
        series.setdefault(r["server_id"], []).append(
            [round(r["t"], 3), round(r["cpu"], 1), round(r["mem"], 1), round(r["bw"], 3),
             round(r["lat"], 2), round(r["loss"], 1), round(r["n"] * 60 / bucket, 1), r["b"]])
    return jsonify(now=now, window_s=window, bucket_s=bucket,
                   fields=["t", "cpu_usage", "memory_usage", "bandwidth_mbps", "latency_ms", "packet_loss",
                           "events_per_min", "bucket"],
                   series=series)


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
:root{color-scheme:dark;--bg:#0d1117;--panel:#161b22;--panel2:#1c2128;--border:#30363d;--grid:#21262d;--axis:#3d444d;
--text:#e6edf3;--text2:#c9d1d9;--muted:#8b949e;
/* categorical series slots (dark steps, validated on #161b22) - identity of each server */
--s1:#3987e5;--s2:#d95926;--s3:#199e70;--s4:#c98500;--s5:#d55181;--s6:#0ca30c;--s7:#9085e9;--s8:#e66767;
/* status palette - reserved for health, always paired with an icon + label */
--good:#0ca30c;--warning:#fab219;--serious:#ec835a;--critical:#d03b3b;--offline:#898781}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
.mono,.rec{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.wrap{max-width:1440px;margin:0 auto;padding:20px 24px 40px}
header{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;padding-bottom:16px;border-bottom:1px solid var(--border);margin-bottom:20px}
h1{font-size:20px;margin:0;font-weight:600}
.sub{color:var(--muted);font-size:12px}
.pill{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--border);border-radius:999px;padding:4px 12px;font-size:12px;color:var(--muted)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--good);animation:pulse 2s infinite}
.dot.down{background:var(--critical);animation:none}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(12,163,12,.6)}70%{box-shadow:0 0 0 8px rgba(12,163,12,0)}100%{box-shadow:0 0 0 0 rgba(12,163,12,0)}}
section{background:var(--panel);border:1px solid var(--border);border-radius:8px;margin-bottom:20px;overflow:hidden}
section>h2{font-size:13px;font-weight:600;margin:0;padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap}
section>h2 a{color:var(--muted);font-weight:400;text-decoration:none}section>h2 a:hover{color:var(--text)}
.feed{max-height:340px;overflow:auto}
.rec{padding:10px 16px;border-bottom:1px solid var(--border);border-left:3px solid var(--offline);font-size:12.5px;white-space:pre-wrap;word-break:break-word}
.rec:last-child{border-bottom:none}
.rec.critical{border-left-color:var(--critical);background:rgba(208,59,59,.08)}
.rec.warning{border-left-color:var(--warning);background:rgba(250,178,25,.06)}
.rec .act{color:var(--text2)}.rec .act b{color:var(--muted);font-weight:600}
.rec .meta{color:var(--muted);font-size:11px;margin-top:2px}
.ok{padding:14px 16px;color:var(--text2)}.ok i{color:var(--good);font-style:normal;margin-right:6px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:14px 16px}
.card .label{color:var(--muted);font-size:12px}
.card .value{font-size:26px;font-weight:600;margin-top:2px;display:flex;align-items:center;gap:8px}
.card .value[data-s]::before{content:"";width:10px;height:10px;border-radius:50%;background:var(--good)}
.card .value[data-s="bad"]::before{background:var(--critical)}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:8px 16px;border-bottom:1px solid var(--border);white-space:nowrap}
th{color:var(--muted);font-weight:500;font-size:12px;background:var(--panel2)}
tr:last-child td{border-bottom:none}
td.mono{font-size:12.5px}
.key{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px;vertical-align:-1px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:1px 10px;border-radius:999px;font-size:12px;font-weight:500;border:1px solid var(--border);color:var(--text)}
.badge i{font-style:normal;font-weight:700}
.st-good{border-color:rgba(12,163,12,.55);background:rgba(12,163,12,.12)}.st-good i{color:var(--good)}
.st-good2{border-color:rgba(12,163,12,.55)}.st-good2 i{color:var(--good)}
.st-warning{border-color:rgba(250,178,25,.55);background:rgba(250,178,25,.10)}.st-warning i{color:var(--warning)}
.st-critical{border-color:rgba(208,59,59,.6);background:rgba(208,59,59,.14)}.st-critical i{color:var(--critical)}
.st-offline{border-color:var(--border);background:rgba(137,135,129,.14);color:var(--muted)}.st-offline i{color:var(--offline)}
.st-none{color:var(--muted)}
.bar{display:inline-block;width:56px;height:6px;background:var(--grid);border-radius:3px;margin-right:8px;vertical-align:middle;overflow:hidden}
.bar>i{display:block;height:100%;border-radius:3px}
.muted{color:var(--muted)}
.empty{padding:14px 16px;color:var(--muted)}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:8px}
/* packet tracer */
#topo{display:block;width:100%;height:auto;max-height:440px}
#topo text{font-family:system-ui,-apple-system,"Segoe UI",sans-serif}
#topo .nm{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;fill:var(--text)}
#topo .node{cursor:pointer;outline:none;transition:opacity .2s}
#topo .node:focus-visible circle.ring{stroke-width:5}
#topo .lnk{transition:opacity .2s}
.tlegend{display:flex;flex-wrap:wrap;gap:18px;padding:10px 16px;border-top:1px solid var(--border);font-size:12px;color:var(--muted)}
.tlegend span{display:inline-flex;align-items:center;gap:6px}
.g{display:inline-block;border-radius:50%}
/* charts */
.filters{display:flex;flex-wrap:wrap;align-items:center;gap:8px 16px;padding:12px 16px;border-bottom:1px solid var(--border)}
.seg{display:inline-flex;border:1px solid var(--border);border-radius:6px;overflow:hidden}
.seg button{background:none;border:0;border-right:1px solid var(--border);color:var(--muted);padding:4px 12px;font:inherit;font-size:12px;cursor:pointer}
.seg button:last-child{border-right:0}
.seg button[aria-pressed="true"]{background:var(--panel2);color:var(--text);font-weight:600}
.seg button:hover{color:var(--text)}
.legend{display:flex;flex-wrap:wrap;gap:6px}
.legend button{display:inline-flex;align-items:center;gap:8px;background:none;border:1px solid transparent;border-radius:6px;color:var(--text2);padding:3px 8px;font:inherit;font-size:12px;cursor:pointer}
.legend button:hover{border-color:var(--border)}
.legend button[aria-pressed="false"]{color:var(--muted);text-decoration:line-through}
.legend button[aria-pressed="false"] .lk{opacity:.3}
.lk{display:inline-block;width:16px;height:2px;border-radius:1px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(560px,1fr));margin:0 -1px -1px 0}
.chart{background:var(--panel);padding:12px 14px 6px;border-right:1px solid var(--border);border-bottom:1px solid var(--border)}
.chart h3{margin:0;font-size:13px;font-weight:600}.chart h3 small{color:var(--muted);font-weight:400;margin-left:6px}
.chart .plot{position:relative;margin-top:6px}
.chart svg{display:block;outline:none}
.chart svg:focus-visible{box-shadow:0 0 0 2px var(--s1);border-radius:4px}
#tip{position:fixed;z-index:10;pointer-events:none;background:var(--panel2);border:1px solid var(--border);border-radius:8px;padding:8px 10px;font-size:12px;box-shadow:0 8px 24px rgba(0,0,0,.4);display:none;min-width:170px}
#tip .th{color:var(--muted);margin-bottom:4px}
#tip .tr{display:flex;align-items:center;gap:8px;line-height:1.7}
#tip .tr b{color:var(--text);font-variant-numeric:tabular-nums;min-width:64px}
#tip .tr span{color:var(--muted)}
.slo{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));margin:0 -1px -1px 0}
.slo>div{padding:14px 16px;border-right:1px solid var(--border);border-bottom:1px solid var(--border)}
.slo .label{color:var(--muted);font-size:12px}
.slo .value{font-size:24px;font-weight:600;margin-top:2px}
.slo .verdict{display:inline-flex;align-items:center;gap:6px;font-size:12px;margin-top:2px;color:var(--text2)}
.slo .verdict i{font-style:normal;font-weight:700}
.slo .sub{color:var(--muted);font-size:11.5px;margin-top:2px}
.skew{padding:8px 16px;border-top:1px solid var(--border);font-size:12px;color:var(--text2)}.skew b{color:var(--warning)}
@media (prefers-reduced-motion:reduce){.dot{animation:none}}
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
  <div class="card"><div class="label">Active nodes</div><div class="value" id="c-online">0</div></div>
  <div class="card"><div class="label" id="c-offline-l">Offline nodes</div><div class="value" id="c-offline">0</div></div>
  <div class="card"><div class="label">Active alerts</div><div class="value" id="c-alerts">0</div></div>
  <div class="card"><div class="label">Duplicates blocked (idempotency)</div><div class="value" id="c-dups">0</div></div>
</div>

<section>
  <h2><span>⏱ Real-time SLOs · measured from event timestamps</span><span class="muted">capture time → SaaS receive → dashboard · alert raised · offline flagged</span></h2>
  <div class="slo">
    <div><div class="label">Capture → SaaS (p95)</div><div class="value" id="s-ingest">—</div><div class="sub" id="s-ingest-sub">waiting for events</div></div>
    <div><div class="label">Capture → dashboard (p95)</div><div class="value" id="s-dash">—</div><div class="verdict" id="s-dash-v"></div><div class="sub" id="s-dash-sub">measured in this browser</div></div>
    <div><div class="label">Alert detection (p95)</div><div class="value" id="s-alert">—</div><div class="verdict" id="s-alert-v"></div><div class="sub" id="s-alert-sub">no alerts yet</div></div>
    <div><div class="label">Offline detection</div><div class="value" id="s-off">—</div><div class="verdict" id="s-off-v"></div><div class="sub" id="s-off-sub">no outages yet</div></div>
    <div><div class="label">Zero loss · zero duplicates</div><div class="value" id="s-zero">—</div><div class="sub" id="s-zero-sub"></div></div>
  </div>
  <div class="skew" id="s-skew" style="display:none"></div>
</section>

<section>
  <h2><span>🛰 Live Packet Tracer · Edge servers → SaaS</span><span class="muted" id="topo-sub">each dot is a real event or probe</span></h2>
  <svg id="topo" viewBox="0 0 1000 400" role="img" aria-label="Network topology of edge servers connected to the SaaS"></svg>
  <div class="tlegend">
    <span><i class="g" style="width:10px;height:10px;background:var(--text2)"></i>event packet (sanitized JSON)</span>
    <span><i class="g" style="width:6px;height:6px;background:var(--muted)"></i>TCP probe</span>
    <span><b style="color:var(--critical)">✕</b>dropped probe = packet loss</span>
    <span><i class="g" style="width:6px;height:6px;background:var(--good)"></i>ACK (201 stored)</span>
    <span><i class="lk" style="background:var(--good)"></i>link colour = node health</span>
    <span><i class="g" style="width:10px;height:10px;border:2px solid var(--s1)"></i>ring colour = server (matches charts)</span>
  </div>
</section>

<section>
  <h2><span>📈 Fleet Telemetry · all servers together</span><a href="#tbl-events">Table view ↓</a></h2>
  <div class="filters">
    <div class="seg" id="range" role="group" aria-label="Time range">
      <button data-m="5" aria-pressed="false">5 min</button><button data-m="15" aria-pressed="true">15 min</button><button data-m="60" aria-pressed="false">60 min</button>
    </div>
    <div class="legend" id="legend" aria-label="Servers (click to show/hide)"></div>
  </div>
  <div class="grid" id="charts"></div>
</section>

<section>
  <h2><span>🖥 Node Fleet</span><span class="muted">health: Excellent · Good · Fair · Poor · OFFLINE</span></h2>
  <div class="scroll"><table>
    <thead><tr><th>Node</th><th>Status</th><th>CPU</th><th>Memory</th><th>Bandwidth</th><th>Latency (baseline)</th><th>Packet loss</th><th>Capture → SaaS</th><th>Last seen</th><th>Events (1h)</th></tr></thead>
    <tbody id="fleet"><tr><td colspan="10" class="empty">No nodes reporting yet.</td></tr></tbody>
  </table></div>
</section>

<section id="tbl-events">
  <h2><span>📡 Live Sanitized Telemetry</span><span class="muted">allow-listed fields only · newest first</span></h2>
  <div class="scroll"><table>
    <thead><tr><th>Captured (UTC)</th><th>Event ID</th><th>Node</th><th>CPU %</th><th>Mem %</th><th>Mbps</th><th>Latency ms</th><th>Loss %</th><th>Reported health</th></tr></thead>
    <tbody id="events"><tr><td colspan="9" class="empty">No events yet.</td></tr></tbody>
  </table></div>
</section>
<footer>Bearer-auth ingest · schema allow-list · idempotent event_id · SQLite WAL · alert latency = collector interval (5s) + UI refresh (3s) &lt; 10s</footer>
</div>
<div id="tip" role="tooltip"></div>
<script>
"use strict";
const $ = id => document.getElementById(id);
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const num = (v, d = 1) => (v === null || v === undefined) ? "—" : Number(v).toFixed(d);
const NS = "http://www.w3.org/2000/svg";
const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// ---- identity (series colour follows the server, never its rank) ------------------------
const SERIES = ["#3987e5","#d95926","#199e70","#c98500","#d55181","#0ca30c","#9085e9","#e66767"];
const OTHER = "#6e7681";
const slots = new Map();
const colorOf = id => { if (!slots.has(id)) slots.set(id, slots.size < SERIES.length ? SERIES[slots.size] : OTHER); return slots.get(id); };
const assign = ids => [...ids].filter(id => !slots.has(id)).sort().forEach(colorOf);

// ---- status (health) - reserved colours, always icon + label -----------------------------
const STATUS = {
  Excellent: {cls: "st-good", icon: "✓", c: "var(--good)"},
  Good:      {cls: "st-good2", icon: "✓", c: "var(--good)"},
  Fair:      {cls: "st-warning", icon: "▲", c: "var(--warning)"},
  Poor:      {cls: "st-critical", icon: "!", c: "var(--critical)"},
  OFFLINE:   {cls: "st-offline", icon: "○", c: "var(--offline)"},
};
const st = s => STATUS[s] || {cls: "st-none", icon: "·", c: "var(--muted)"};
const badge = s => `<span class="badge ${st(s).cls}"><i>${st(s).icon}</i>${esc(s || "n/a")}</span>`;
const sev = (v, warn, crit) => v >= crit ? "var(--critical)" : v >= warn ? "var(--warning)" : "var(--good)";
const meter = (v, warn, crit) => `<span class="bar"><i style="width:${Math.min(100, Math.max(0, v))}%;background:${sev(v, warn, crit)}"></i></span>${num(v)}%`;
const ago = s => s < 60 ? `${Math.round(s)}s ago` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s ago`;
const svg = (tag, attrs = {}, parent) => { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); if (parent) parent.appendChild(e); return e; };
const text = (parent, attrs, str) => { const t = svg("text", attrs, parent); t.textContent = str; return t; };

const state = {nodes: [], ts: null, rangeMin: 15, hidden: new Set(), focus: null, hoverT: null};

// ---- tooltip (DOM-built: names are untrusted, use textContent) ---------------------------
const tip = $("tip");
function showTip(x, y, title, rows) {
  tip.replaceChildren();
  const h = document.createElement("div"); h.className = "th"; h.textContent = title; tip.appendChild(h);
  for (const r of rows) {
    const row = document.createElement("div"); row.className = "tr";
    const k = document.createElement("i"); k.className = r.dot ? "key" : "lk"; k.style.background = r.color;
    if (r.dot) k.style.marginRight = "0";
    const b = document.createElement("b"); b.textContent = r.value;
    const s = document.createElement("span"); s.textContent = r.label;
    row.append(k, b, s); tip.appendChild(row);
  }
  tip.style.display = "block";
  const w = tip.offsetWidth, hh = tip.offsetHeight;
  tip.style.left = Math.min(window.innerWidth - w - 8, x + 14) + "px";
  tip.style.top = Math.max(8, Math.min(window.innerHeight - hh - 8, y - hh / 2)) + "px";
}
const hideTip = () => { tip.style.display = "none"; };

// ==========================================================================================
// Packet tracer topology
// ==========================================================================================
const T = {W: 1000, H: 400, CX: 500, CY: 190, HW: 100, HH: 38, el: {}, pos: new Map(), packets: [], seen: null, ripples: 0};
(function initTopo() {
  const root = $("topo");
  T.gLinks = svg("g", {}, root); T.gPk = svg("g", {}, root); T.gHub = svg("g", {}, root); T.gNodes = svg("g", {}, root);
  T.ripples = svg("g", {}, T.gHub);
  svg("rect", {x: T.CX - T.HW, y: T.CY - T.HH, width: T.HW * 2, height: T.HH * 2, rx: 12, fill: "#1c2128", stroke: "#58a6ff", "stroke-width": 1.5}, T.gHub);
  text(T.gHub, {x: T.CX, y: T.CY - 12, "text-anchor": "middle", fill: "#e6edf3", "font-size": 14, "font-weight": 600}, "☁ Smart Observability SaaS");
  text(T.gHub, {x: T.CX, y: T.CY + 6, "text-anchor": "middle", fill: "#8b949e", "font-size": 11}, "Tier-2 · POST /ingest · AIOps engine");
  T.hubRate = text(T.gHub, {x: T.CX, y: T.CY + 23, "text-anchor": "middle", fill: "#c9d1d9", "font-size": 11}, "0 events / min");
  T.empty = text(root, {x: T.CX, y: T.CY + 80, "text-anchor": "middle", fill: "#8b949e", "font-size": 13}, "Waiting for edge collectors to connect…");
  requestAnimationFrame(frame);
})();

function hubEdge(x, y) {        // point on the hub rectangle's border towards (x, y)
  const dx = x - T.CX, dy = y - T.CY, s = Math.min(T.HW / Math.abs(dx || 1e-6), T.HH / Math.abs(dy || 1e-6));
  return [T.CX + dx * s, T.CY + dy * s];
}
function nodeEdge(p) {          // point on the node circle towards the hub
  const dx = T.CX - p.x, dy = T.CY - p.y, d = Math.hypot(dx, dy) || 1;
  return [p.x + dx / d * 30, p.y + dy / d * 30];
}
function layout(ids) {
  const n = ids.length, RX = 375, RY = 128;
  ids.forEach((id, i) => {
    const a = n <= 2 ? [Math.PI, 0][i] : Math.PI + (i + 0.5) * 2 * Math.PI / n;
    T.pos.set(id, {x: T.CX + RX * Math.cos(a), y: T.CY + RY * Math.sin(a)});
  });
}

function updateTopo(nodes, counters) {
  T.empty.style.display = nodes.length ? "none" : "";
  T.hubRate.textContent = `${counters.events_last_min} events / min · ${counters.nodes_online}/${counters.nodes_total} nodes online`;
  const ids = nodes.map(n => n.server_id);
  layout(ids);
  for (const id of Object.keys(T.el)) if (!ids.includes(id)) { T.el[id].link.remove(); T.el[id].g.remove(); delete T.el[id]; T.pos.delete(id); }
  for (const n of nodes) {
    const id = n.server_id, p = T.pos.get(id), s = st(n.status), off = n.status === "OFFLINE";
    let e = T.el[id];
    if (!e) {
      e = T.el[id] = {};
      e.link = svg("g", {class: "lnk"}, T.gLinks);
      e.line = svg("line", {"stroke-width": 2, "stroke-linecap": "round"}, e.link);
      e.g = svg("g", {class: "node", tabindex: 0, role: "img"}, T.gNodes);
      e.hit = svg("circle", {r: 40, fill: "transparent"}, e.g);
      e.ring = svg("circle", {class: "ring", r: 24, fill: "#1c2128", "stroke-width": 3}, e.g);
      e.mon = svg("rect", {width: 20, height: 13, rx: 2, fill: "none", stroke: "#c9d1d9", "stroke-width": 1.6}, e.g);
      e.stand = svg("path", {fill: "none", stroke: "#c9d1d9", "stroke-width": 1.6, "stroke-linecap": "round"}, e.g);
      e.name = text(e.g, {class: "nm", "text-anchor": "middle"}, id);
      e.stat = svg("text", {"text-anchor": "middle", "font-size": 12}, e.g);
      e.icon = svg("tspan", {"font-weight": 700}, e.stat); e.slab = svg("tspan", {fill: "#c9d1d9"}, e.stat);
      e.net = text(e.g, {"text-anchor": "middle", "font-size": 11.5, fill: "#8b949e", style: "font-variant-numeric:tabular-nums"}, "");
      e.flash = text(e.g, {"text-anchor": "middle", "font-size": 12, fill: "#c9d1d9", opacity: 0}, "");
      const enter = ev => { state.focus = id; applyFocus(); nodeTip(id, ev); };
      e.g.addEventListener("pointerenter", enter); e.g.addEventListener("pointermove", ev => nodeTip(id, ev));
      e.g.addEventListener("pointerleave", () => { state.focus = null; applyFocus(); hideTip(); });
      e.g.addEventListener("focus", () => { state.focus = id; applyFocus(); const r = e.g.getBoundingClientRect(); nodeTip(id, {clientX: r.right, clientY: r.top + r.height / 2}); });
      e.g.addEventListener("blur", () => { state.focus = null; applyFocus(); hideTip(); });
    }
    e.n = n;
    const [x1, y1] = nodeEdge(p), [x2, y2] = hubEdge(p.x, p.y);
    Object.entries({x1, y1, x2, y2, stroke: s.c, opacity: off ? .7 : .85, "stroke-dasharray": off ? "6 6" : "none"}).forEach(([k, v]) => e.line.setAttribute(k, v));
    e.ring.setAttribute("cx", p.x); e.ring.setAttribute("cy", p.y); e.ring.setAttribute("stroke", colorOf(id));
    e.ring.setAttribute("opacity", off ? .5 : 1);
    e.hit.setAttribute("cx", p.x); e.hit.setAttribute("cy", p.y + 14);
    e.mon.setAttribute("x", p.x - 10); e.mon.setAttribute("y", p.y - 10);
    e.stand.setAttribute("d", `M${p.x} ${p.y + 3}v4M${p.x - 5} ${p.y + 8}h10`);
    const below = p.y >= T.CY - 1 || ids.length <= 2;
    e.name.setAttribute("x", p.x); e.name.setAttribute("y", below ? p.y + 46 : p.y - 68);
    e.stat.setAttribute("x", p.x); e.stat.setAttribute("y", below ? p.y + 63 : p.y - 51);
    e.net.setAttribute("x", p.x); e.net.setAttribute("y", below ? p.y + 79 : p.y - 35);
    e.net.textContent = off ? "link down · no telemetry" : `${n.latency_ms < 10 ? num(n.latency_ms, 2) : num(n.latency_ms, 0)} ms · ${num(n.packet_loss)}% loss · ${num(n.bandwidth_mbps, 2)} Mbps`;
    e.icon.textContent = s.icon + " "; e.icon.setAttribute("fill", s.c);
    e.slab.textContent = off ? `OFFLINE · ${ago(n.last_seen_s)}` : `${n.status} · CPU ${num(n.cpu_usage, 0)}%`;
    e.flash.setAttribute("x", p.x); e.flash.setAttribute("y", below ? p.y - 34 : p.y + 44);
    e.g.setAttribute("aria-label", `${id}: ${n.status}, latency ${num(n.latency_ms)} ms, packet loss ${num(n.packet_loss)}%`);
  }
  applyFocus();
}

function nodeTip(id, ev) {
  const n = (T.el[id] || {}).n; if (!n) return;
  showTip(ev.clientX, ev.clientY, id, [
    {color: st(n.status).c, dot: true, value: n.status, label: "health"},
    {color: colorOf(id), value: num(n.cpu_usage) + "%", label: "CPU"},
    {color: colorOf(id), value: num(n.memory_usage) + "%", label: "memory"},
    {color: colorOf(id), value: num(n.latency_ms, 2) + " ms", label: `latency (baseline ${n.baseline_latency_ms === null ? "learning" : num(n.baseline_latency_ms, 2)})`},
    {color: colorOf(id), value: num(n.packet_loss) + "%", label: "packet loss"},
    {color: colorOf(id), value: num(n.bandwidth_mbps, 2), label: "Mbps"},
    {color: "#8b949e", value: ago(n.last_seen_s), label: "last seen"},
  ]);
}

function applyFocus() {
  for (const [id, e] of Object.entries(T.el)) {
    const dim = state.focus && state.focus !== id ? .25 : 1;
    e.g.style.opacity = dim; e.link.style.opacity = dim;
  }
  for (const b of document.querySelectorAll("#legend button")) b.style.opacity = state.focus && state.focus !== b.dataset.id ? .5 : 1;
  renderCharts();
}

// packets: probes (4 per collector cycle, some dropped per packet_loss), event, ACK back
function spawnPackets(events) {
  const ids = new Set(events.map(e => e.event_id));
  if (T.seen === null) { T.seen = ids; return; }                 // first load: don't replay history
  const fresh = events.filter(e => !T.seen.has(e.event_id)).reverse();   // oldest first
  T.seen = ids;
  if (REDUCED || !fresh.length) return;
  const per = {};
  for (const ev of fresh) (per[ev.server_id] ||= []).push(ev);
  const now = performance.now();
  for (const [id, list] of Object.entries(per)) {
    if (!T.pos.has(id)) continue;
    const replayed = list.filter(e => e.received_at - Date.parse(e.timestamp) / 1000 > 30).length;
    if (replayed && T.el[id]) flash(id, `↻ ${replayed} buffered event${replayed > 1 ? "s" : ""} replayed`);
    list.slice(-12).forEach((ev, k, arr) => {
      const start = now + (arr.length > 1 ? k * (2600 / arr.length) : Math.random() * 1800);
      const dur = 1000 + Math.min(ev.latency_ms, 800) * 1.6;
      for (let p = 0; p < 4; p++) addPacket({kind: "probe", id, start: start + p * 110, dur, drop: Math.random() * 100 < ev.packet_loss});
      addPacket({kind: "event", id, start: start + 480, dur, color: colorOf(id)});
    });
  }
}
function addPacket(p) {
  p.el = svg("circle", {r: p.kind === "event" ? 5.5 : p.kind === "ack" ? 3.5 : 2.6, opacity: 0,
    fill: p.kind === "event" ? p.color : p.kind === "ack" ? "#0ca30c" : "#8b949e",
    stroke: p.kind === "event" ? "#161b22" : "none", "stroke-width": 2}, T.gPk);
  p.dropAt = .35 + Math.random() * .3;
  T.packets.push(p);
}
function flash(id, msg) {
  const f = T.el[id].flash; f.textContent = msg; f.setAttribute("opacity", 1);
  clearTimeout(f._t); f._t = setTimeout(() => f.setAttribute("opacity", 0), 3500);
}
function ripple() {
  if (T.ripples.childNodes.length > 5) return;
  const c = svg("rect", {x: T.CX - T.HW, y: T.CY - T.HH, width: T.HW * 2, height: T.HH * 2, rx: 12, fill: "none", stroke: "#0ca30c", "stroke-width": 2}, T.ripples);
  const t0 = performance.now();
  (function grow(now) {
    const k = (now - t0) / 800; if (k >= 1) { c.remove(); return; }
    const g = 14 * k; c.setAttribute("x", T.CX - T.HW - g); c.setAttribute("y", T.CY - T.HH - g);
    c.setAttribute("width", T.HW * 2 + 2 * g); c.setAttribute("height", T.HH * 2 + 2 * g); c.setAttribute("opacity", .7 * (1 - k));
    requestAnimationFrame(grow);
  })(t0);
}
function frame(now) {
  T.packets = T.packets.filter(p => {
    const pos = T.pos.get(p.id);
    if (!pos) { p.el.remove(); return false; }
    if (now < p.start) return true;
    const [nx, ny] = nodeEdge(pos), [hx, hy] = hubEdge(pos.x, pos.y);
    const [ax, ay, bx, by] = p.kind === "ack" ? [hx, hy, nx, ny] : [nx, ny, hx, hy];
    let k = (now - p.start) / p.dur;
    if (p.kind === "probe" && p.drop && k >= p.dropAt) {
      if (!p.dropped) {
        p.dropped = now; const x = ax + (bx - ax) * p.dropAt, y = ay + (by - ay) * p.dropAt;
        p.el.setAttribute("fill", "#d03b3b"); p.el.setAttribute("cx", x); p.el.setAttribute("cy", y);
        p.x = text(T.gPk, {x: x + 6, y: y - 5, fill: "#d03b3b", "font-size": 13, "font-weight": 700}, "✕");
      }
      const f = (now - p.dropped) / 900;
      if (f >= 1) { p.el.remove(); p.x.remove(); return false; }
      p.el.setAttribute("opacity", 1 - f); p.x.setAttribute("opacity", 1 - f);
      return true;
    }
    if (k >= 1) {
      p.el.remove();
      if (p.kind === "event") { ripple(); addPacket({kind: "ack", id: p.id, start: now, dur: 650}); }
      return false;
    }
    p.el.setAttribute("cx", ax + (bx - ax) * k); p.el.setAttribute("cy", ay + (by - ay) * k);
    p.el.setAttribute("opacity", Math.min(1, k * 6));
    return true;
  });
  requestAnimationFrame(frame);
}

// ==========================================================================================
// Fleet telemetry small multiples (one metric per chart, one line per server, one y-axis)
// ==========================================================================================
const METRICS = [
  {i: 1, title: "CPU usage", unit: "% · per server", max: 100, fmt: v => num(v) + "%"},
  {i: 2, title: "Memory usage", unit: "% · per server", max: 100, fmt: v => num(v) + "%"},
  {i: 4, title: "Latency to SaaS", unit: "ms · TCP handshake", floor: 10, fmt: v => (v < 10 ? num(v, 2) : num(v, 0)) + " ms"},
  {i: 5, title: "Packet loss", unit: "% · failed probes", floor: 5, cap: 100, fmt: v => num(v) + "%"},
  {i: 3, title: "Bandwidth", unit: "Mbps · rx + tx", floor: 1, fmt: v => num(v, 2) + " Mbps"},
  {i: 8, title: "Ingest rate", unit: "events / min · 30 s rolling, by capture time (gaps = outage, refilled on replay)", floor: 5, partial: true, fmt: v => num(v) + " / min"},
];
const charts = METRICS.map(m => {
  const card = document.createElement("div"); card.className = "chart";
  const h = document.createElement("h3"); h.textContent = m.title;
  const sm = document.createElement("small"); sm.textContent = m.unit; h.appendChild(sm);
  const plot = document.createElement("div"); plot.className = "plot";
  card.append(h, plot); $("charts").appendChild(card);
  const s = svg("svg", {tabindex: 0, role: "img", "aria-label": `${m.title} over time for every server`}, plot);
  return {m, plot, s};
});
const M = {l: 44, r: 112, t: 10, b: 24}, CH = 196;

function niceStep(range, count) {
  const raw = range / count, p = Math.pow(10, Math.floor(Math.log10(raw))), f = raw / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
}
const tickFmt = v => Number(v.toFixed(2)).toLocaleString();
function timeLabel(t, secs) {
  const d = new Date(t * 1000), p = n => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}` + (secs ? `:${p(d.getSeconds())}` : "");
}
function visibleSeries() {
  if (!state.ts) return [];
  return Object.entries(state.ts.series).filter(([id]) => !state.hidden.has(id));
}
function allTimes() {
  const set = new Set(); for (const [, pts] of visibleSeries()) for (const p of pts) set.add(p[0]);
  return [...set].sort((a, b) => a - b);
}

function smoothRate(ts) {               // 30 s rolling rate: removes aliasing between collector interval and bucket size
  const k = Math.max(1, Math.round(30 / ts.bucket_s));
  for (const pts of Object.values(ts.series)) {
    if (!pts.length) continue;
    const first = pts[0][7], cnt = new Map(pts.map(p => [p[7], p[6] * ts.bucket_s / 60]));
    for (const p of pts) {
      const span = Math.min(k, p[7] - first + 1);
      let sum = 0; for (let j = 0; j < span; j++) sum += cnt.get(p[7] - j) || 0;
      p[8] = Math.round(sum / (span * ts.bucket_s) * 600) / 10;
    }
  }
  return ts;
}

function renderCharts() {
  if (!state.ts) return;
  const vis = visibleSeries(), t1 = state.ts.now, tw = t1 - state.ts.window_s;
  let first = Infinity; for (const [, pts] of vis) for (const p of pts) if (p[0] >= tw) first = Math.min(first, p[0]);
  const t0 = Number.isFinite(first) ? Math.max(tw, Math.min(first, t1 - 60)) : tw;   // fit to data, >= 60 s span
  const gap = Math.max(state.ts.bucket_s * 3, 20);
  for (const c of charts) {
    c.cross = null;
    const w = Math.max(320, c.plot.clientWidth), pw = w - M.l - M.r, ph = CH - M.t - M.b;
    c.s.replaceChildren(); c.s.setAttribute("width", w); c.s.setAttribute("height", CH); c.s.setAttribute("viewBox", `0 0 ${w} ${CH}`);
    let hi = 0; for (const [, pts] of vis) for (const p of pts) if (p[0] >= t0 && p[c.m.i] > hi) hi = p[c.m.i];
    const step = niceStep(c.m.max || Math.max(c.m.floor, hi * 1.15), 4);
    const ymax = c.m.max || Math.min(c.m.cap || Infinity, Math.max(step, Math.ceil(Math.max(c.m.floor, hi * 1.15) / step) * step));
    const X = t => M.l + (t - t0) / (t1 - t0) * pw, Y = v => M.t + (1 - Math.min(v, ymax) / ymax) * ph;
    c.X = X; c.Y = Y; c.t0 = t0; c.t1 = t1; c.pw = pw;
    for (let v = 0; v <= ymax + 1e-9; v += step) {           // hairline grid + y ticks
      svg("line", {x1: M.l, x2: M.l + pw, y1: Y(v), y2: Y(v), stroke: v === 0 ? "#3d444d" : "#21262d", "stroke-width": 1}, c.s);
      text(c.s, {x: M.l - 6, y: Y(v) + 4, "text-anchor": "end", "font-size": 11, fill: "#8b949e", style: "font-variant-numeric:tabular-nums"}, tickFmt(v));
    }
    const maxTicks = Math.max(2, Math.floor(pw / 90));
    const xs = [15, 30, 60, 120, 300, 600, 900, 1800].find(s => (t1 - t0) / s <= maxTicks) || 1800;
    for (let t = Math.ceil(t0 / xs) * xs; t <= t1; t += xs)
      text(c.s, {x: X(t), y: CH - 6, "text-anchor": "middle", "font-size": 11, fill: "#8b949e", style: "font-variant-numeric:tabular-nums"}, timeLabel(t, xs < 60));
    if (!vis.some(([, pts]) => pts.length)) {
      text(c.s, {x: M.l + pw / 2, y: M.t + ph / 2, "text-anchor": "middle", "font-size": 12, fill: "#8b949e"}, "No telemetry in this range yet");
      continue;
    }
    const ends = [];
    const curBucket = Math.floor(t1 / state.ts.bucket_s);
    for (const [id, all] of vis) {
      const pts = c.m.partial ? all.filter(p => p[7] < curBucket) : all;
      if (!pts.length) continue;
      let d = "", prev = null;
      for (const p of pts) {
        if (p[0] < t0) continue;
        d += (prev === null || p[0] - prev > gap ? "M" : "L") + X(p[0]).toFixed(1) + " " + Y(p[c.m.i]).toFixed(1);
        prev = p[0];
      }
      const op = state.focus && state.focus !== id ? .18 : 1;
      svg("path", {d, fill: "none", stroke: colorOf(id), "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round", opacity: op}, c.s);
      const last = pts[pts.length - 1];
      if (last[0] >= t0) {
        svg("circle", {cx: X(last[0]), cy: Y(last[c.m.i]), r: 4, fill: colorOf(id), stroke: "#161b22", "stroke-width": 2, opacity: op}, c.s);
        ends.push({id, x: X(last[0]), y: Y(last[c.m.i]), op});
      }
    }
    if (vis.length <= 4) {                                  // selective direct labels: only ends that stand alone
      const srt = ends.sort((a, b) => a.y - b.y);
      srt.forEach((e, i) => {
        if ((i > 0 && e.y - srt[i - 1].y < 13) || (i < srt.length - 1 && srt[i + 1].y - e.y < 13)) return;
        text(c.s, {x: Math.min(e.x + 9, w - M.r + 10), y: e.y + 4, "font-size": 11, fill: "#c9d1d9", opacity: e.op}, e.id);
      });
    }
    c.cross = svg("g", {"pointer-events": "none"}, c.s);
    const ov = svg("rect", {x: M.l, y: M.t, width: pw, height: ph, fill: "transparent"}, c.s);
    ov.addEventListener("pointermove", ev => hoverAt(c, ev.clientX - c.s.getBoundingClientRect().left, ev));
    ov.addEventListener("pointerleave", () => { state.hoverT = null; drawCross(); hideTip(); });
    c.s.onkeydown = ev => keyNav(c, ev);
    c.s.onblur = () => { state.hoverT = null; drawCross(); hideTip(); };
  }
  drawCross();
}

function hoverAt(c, px, ev) {
  const times = allTimes(); if (!times.length) return;
  const t = c.t0 + (px - M.l) / c.pw * (c.t1 - c.t0);
  state.hoverT = times.reduce((a, b) => Math.abs(b - t) < Math.abs(a - t) ? b : a);
  drawCross(); chartTip(c, ev.clientX, ev.clientY);
}
function keyNav(c, ev) {
  if (!["ArrowLeft", "ArrowRight"].includes(ev.key)) return;
  ev.preventDefault();
  const times = allTimes(); if (!times.length) return;
  let i = state.hoverT === null ? times.length - 1 : times.indexOf(state.hoverT) + (ev.key === "ArrowRight" ? 1 : -1);
  state.hoverT = times[Math.max(0, Math.min(times.length - 1, i))];
  drawCross();
  const r = c.s.getBoundingClientRect(); chartTip(c, r.left + c.X(state.hoverT), r.top + 40);
}
function valuesAt(t, mi) {
  const tol = Math.max(state.ts.bucket_s * 1.5, 8), out = [];
  for (const [id, pts] of visibleSeries()) {
    let best = null; for (const p of pts) if (Math.abs(p[0] - t) <= tol && (!best || Math.abs(p[0] - t) < Math.abs(best[0] - t))) best = p;
    if (best) out.push({id, p: best, v: best[mi]});
  }
  return out;
}
function drawCross() {                                       // shared crosshair across every chart
  for (const c of charts) {
    if (!c.cross) continue;
    c.cross.replaceChildren();
    if (state.hoverT === null) continue;
    const x = c.X(state.hoverT);
    svg("line", {x1: x, x2: x, y1: M.t, y2: CH - M.b, stroke: "#8b949e", "stroke-width": 1}, c.cross);
    for (const r of valuesAt(state.hoverT, c.m.i))
      svg("circle", {cx: c.X(r.p[0]), cy: c.Y(r.v), r: 4, fill: colorOf(r.id), stroke: "#161b22", "stroke-width": 2}, c.cross);
  }
}
function chartTip(c, x, y) {
  const rows = valuesAt(state.hoverT, c.m.i).sort((a, b) => b.v - a.v)
    .map(r => ({color: colorOf(r.id), value: c.m.fmt(r.v), label: r.id}));
  showTip(x, y, `${c.m.title} · ${timeLabel(state.hoverT, true)}`, rows);
}

function renderLegend(ids) {
  const box = $("legend");
  const have = [...box.querySelectorAll("button")].map(b => b.dataset.id).join("|");
  if (have === ids.join("|")) {
    for (const b of box.querySelectorAll("button")) b.setAttribute("aria-pressed", String(!state.hidden.has(b.dataset.id)));
    return;
  }
  box.replaceChildren();
  for (const id of ids) {
    const b = document.createElement("button"); b.dataset.id = id;
    b.setAttribute("aria-pressed", String(!state.hidden.has(id)));
    const k = document.createElement("i"); k.className = "lk"; k.style.background = colorOf(id);
    b.append(k, document.createTextNode(id));
    b.onclick = () => { state.hidden.has(id) ? state.hidden.delete(id) : state.hidden.add(id); renderLegend(ids); renderCharts(); };
    b.onpointerenter = () => { state.focus = id; applyFocus(); };
    b.onpointerleave = () => { state.focus = null; applyFocus(); };
    box.appendChild(b);
  }
}
for (const b of document.querySelectorAll("#range button")) b.onclick = () => {
  state.rangeMin = +b.dataset.m;
  for (const x of document.querySelectorAll("#range button")) x.setAttribute("aria-pressed", String(x === b));
  for (const c of charts) c.s.style.opacity = .5;           // hold the frame while refetching
  tick();
};
let rz; window.addEventListener("resize", () => { clearTimeout(rz); rz = setTimeout(renderCharts, 120); });

// ==========================================================================================
// Feed, cards, tables
// ==========================================================================================
function renderFeed(recs) {
  $("feedcount").textContent = recs.length ? `${recs.length} item(s)` : "";
  if (!recs.length) { $("feed").innerHTML = '<div class="ok"><i>✓</i>All systems nominal — no correlated anomalies detected.</div>'; return; }
  $("feed").innerHTML = recs.map(r => {
    const [finding, action] = r.message.split(" Recommended Action: ");
    return `<div class="rec ${esc(r.severity)}">${esc(finding)}${action ? ` <span class="act"><b>Recommended Action:</b> ${esc(action)}</span>` : ""}`
         + `<div class="meta">${esc(r.severity.toUpperCase())} · rule=${esc(r.rule)}`
         + (r.detected_after_s !== undefined ? ` · <b>detected ${num(r.detected_after_s)} s</b> after ${r.rule === "outage" ? "last telemetry" : "triggering sample captured"} ${esc(r.trigger_at)}` : "")
         + ` · ${esc(r.generated_at)}</div></div>`;
  }).join("");
}
function renderFleet(nodes) {
  if (!nodes.length) return;
  $("fleet").innerHTML = nodes.map(n => `<tr>
    <td class="mono"><span class="key" style="background:${colorOf(n.server_id)}"></span>${esc(n.server_id)}</td><td>${badge(n.status)}</td>
    <td>${meter(n.cpu_usage, 75, 90)}</td><td>${meter(n.memory_usage, 80, 92)}</td>
    <td>${num(n.bandwidth_mbps, 2)} Mbps</td>
    <td>${num(n.latency_ms)} ms <span class="muted">(${n.baseline_latency_ms === null ? "learning" : num(n.baseline_latency_ms)})</span></td>
    <td>${n.packet_loss >= 2 ? '<b style="color:var(--critical)">▲</b> ' : ""}${num(n.packet_loss)}%</td>
    <td>${n.ingest_delay_s === null ? '<span class="muted">—</span>' : num(n.ingest_delay_s, 2) + " s"}</td>
    <td class="muted">${ago(n.last_seen_s)}</td><td>${esc(n.events_window)}</td></tr>`).join("");
}
function renderEvents(evs) {
  if (!evs.length) return;
  $("events").innerHTML = evs.map(e => `<tr>
    <td class="mono">${esc(String(e.timestamp).replace("T", " ").replace("Z", ""))}</td>
    <td class="mono muted">${esc(String(e.event_id).slice(0, 8))}…</td>
    <td class="mono"><span class="key" style="background:${colorOf(e.server_id)}"></span>${esc(e.server_id)}</td>
    <td>${num(e.cpu_usage)}</td><td>${num(e.memory_usage)}</td><td>${num(e.bandwidth_mbps, 2)}</td>
    <td>${num(e.latency_ms)}</td><td>${num(e.packet_loss)}</td><td>${badge(e.health)}</td></tr>`).join("");
}
const dashDelays = [];                    // capture -> first shown in this browser (server-clock corrected)
let dashSeen = null;
function pct(arr, q) { if (!arr.length) return null; const s = [...arr].sort((a, b) => a - b); return s[Math.max(0, Math.min(s.length - 1, Math.ceil(q / 100 * s.length) - 1))]; }
function measureDashboard(evs, serverNow, clientAt) {
  const ids = new Set(evs.map(e => e.event_id));
  if (dashSeen === null) { dashSeen = ids; return; }
  const offset = serverNow - clientAt;
  for (const e of evs) {
    if (dashSeen.has(e.event_id)) continue;
    const cap = Date.parse(e.timestamp) / 1000;
    if (e.received_at - cap > 30) continue;          // replayed backlog is not live latency
    dashDelays.push(Date.now() / 1000 + offset - cap);
  }
  if (dashDelays.length > 400) dashDelays.splice(0, dashDelays.length - 400);
  dashSeen = ids;
}
function verdict(id, value, target) {
  const el = $(id);
  if (value === null || value === undefined) { el.innerHTML = ""; return; }
  const ok = value <= target;
  el.innerHTML = `<i style="color:${ok ? "var(--good)" : "var(--critical)"}">${ok ? "✓" : "!"}</i>${ok ? "within" : "over"} target ≤ ${target} s`;
}
const secs = v => v === null || v === undefined ? "—" : (Math.abs(v) < 10 ? num(v, 2) : num(v, 1)) + " s";
function renderSLO(slo, c) {
  const t = slo.targets;
  $("s-ingest").textContent = secs(slo.ingest_p95_s);
  $("s-ingest-sub").textContent = slo.ingest_samples ? `p50 ${secs(slo.ingest_p50_s)} · ${slo.ingest_samples} live events, last 5 min` : "waiting for events";
  const d95 = pct(dashDelays, 95);
  $("s-dash").textContent = secs(d95); verdict("s-dash-v", d95, t.dashboard_s);
  $("s-dash-sub").textContent = dashDelays.length ? `p50 ${secs(pct(dashDelays, 50))} · ${dashDelays.length} events seen live in this browser` : "measuring new events…";
  $("s-alert").textContent = secs(slo.alert_p95_s); verdict("s-alert-v", slo.alert_p95_s, t.alert_s);
  $("s-alert-sub").textContent = slo.alert_samples ? `sample capture → alert raised · max ${secs(slo.alert_max_s)} · ${slo.alert_samples} alert(s), last 60 min` : "no alerts yet (engine evaluates every " + slo.eval_interval_s + " s)";
  $("s-off").textContent = secs(slo.offline_last_s); verdict("s-off-v", slo.offline_max_s, t.offline_s);
  $("s-off-sub").textContent = slo.offline_samples ? `last telemetry → OFFLINE · worst ${secs(slo.offline_max_s)} · threshold ${slo.offline_after_s} s` : `none yet · flagged after ${slo.offline_after_s} s of silence`;
  $("s-zero").textContent = `${c.duplicates_blocked} dup blocked`;
  $("s-zero-sub").textContent = `${slo.replayed_5m} buffered events replayed with original timestamps (5 min) · event_id idempotency`;
  $("c-offline-l").textContent = `Offline nodes (>${slo.offline_after_s}s silent)`;
  const sk = $("s-skew");
  if (slo.skew_nodes.length) { sk.style.display = ""; sk.innerHTML = `<b>▲</b> Clock skew: ${esc(slo.skew_nodes.join(", "))} report capture times ahead of the SaaS clock — sync NTP (<span class="mono">sudo timedatectl set-ntp true</span>) for accurate latency.`; }
  else sk.style.display = "none";
}
function setCard(id, value, bad) { const el = $(id); el.textContent = value; if (bad !== undefined) el.dataset.s = bad ? "bad" : "ok"; }

const getJSON = url => fetch(url, {cache: "no-store"}).then(r => { if (!r.ok) throw r.status; return r.json(); });
let busy = false;
async function tick() {
  if (busy) return; busy = true;
  try {
    const [ins, evs, ts] = await Promise.all([getJSON("/insights"), getJSON("/events?limit=100"),
                                              getJSON(`/timeseries?minutes=${state.rangeMin}`)]);
    measureDashboard(evs, ins.now, Date.now() / 1000);
    const c = ins.counters;
    assign([...ins.nodes.map(n => n.server_id), ...Object.keys(ts.series)]);
    setCard("c-total", c.total_events.toLocaleString()); setCard("c-rate", c.events_last_min);
    setCard("c-online", `${c.nodes_online}/${c.nodes_total}`, c.nodes_online < c.nodes_total);
    setCard("c-offline", c.nodes_offline, c.nodes_offline > 0); setCard("c-alerts", c.alerts_active, c.alerts_active > 0);
    setCard("c-dups", c.duplicates_blocked);
    state.nodes = ins.nodes; state.ts = smoothRate(ts);
    renderSLO(ins.slo, c); renderFeed(ins.recommendations); renderFleet(ins.nodes); renderEvents(evs.slice(0, 25));
    updateTopo(ins.nodes, c); spawnPackets(evs);
    renderLegend([...new Set([...ins.nodes.map(n => n.server_id), ...Object.keys(ts.series)])].sort((a, b) => [...slots.keys()].indexOf(a) - [...slots.keys()].indexOf(b)));
    for (const ch of charts) ch.s.style.opacity = 1;
    renderCharts();
    $("dot").className = "dot"; $("live").textContent = "live";
    $("updated").textContent = new Date().toLocaleTimeString();
  } catch (e) { $("dot").className = "dot down"; $("live").textContent = "SaaS unreachable — retrying"; }
  finally { busy = false; }
}
tick(); setInterval(tick, 3000);
</script></body></html>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT") or ("8000" if ON_AZURE else "5000"))   # Azure probes 8000 by default
    print(f"[smart-observability] Tier-2 SaaS on 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, threaded=True, debug=False)
