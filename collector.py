#!/usr/bin/env python3
"""
Smart Observability - Tier-1 Edge Collector (Kali / Ubuntu / Windows)

Each cycle:
  1. samples CPU / memory / bandwidth and probes latency + packet loss to the SaaS (TCP handshakes),
  2. reads raw system logs and scrubs secrets/PII locally (regex engine),
  3. builds an allow-listed, numeric-only JSON event and runs an egress DLP gate on the exact wire bytes,
  4. prints the EGRESS PROOF panel: RAW LOG (left) vs SANITIZED PAYLOAD (right),
  5. writes the event to collector_buffer.json FIRST (write-ahead), then flushes the buffer in order.
     If the SaaS is unreachable events stay queued with their original UTC timestamps and are replayed
     on reconnect. event_id is fixed at capture time, so retries are deduplicated server-side.

Usage:
  python collector.py --target local                          # http://10.108.72.28:5000/ingest
  python collector.py --target azure --app-name <app-name>    # https://<app-name>.azurewebsites.net/ingest
  python collector.py --url http://127.0.0.1:5000/ingest --demo
  python collector.py --target local --demo --chaos cpu_loss  # inject a correlated anomaly for the demo

Env overrides: SMARTOBS_URL, SMARTOBS_LOCAL_URL, SMARTOBS_AZURE_APP, SMARTOBS_TOKEN
Only `requests` is required; `psutil` is used when installed (recommended on Windows for bandwidth).
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import statistics
import subprocess
import sys
import textwrap
import time
import uuid
from datetime import datetime, timezone
from itertools import zip_longest
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    sys.exit("The 'requests' package is required:  pip install requests")

try:
    import psutil  # optional
except ImportError:
    psutil = None

DEFAULT_LOCAL_URL = os.environ.get("SMARTOBS_LOCAL_URL", "http://10.108.72.28:5000/ingest")
AZURE_URL_TEMPLATE = "https://{app}.azurewebsites.net/ingest"
DEFAULT_TOKEN = os.environ.get("SMARTOBS_TOKEN", "demo-secret-123")
BUFFER_FILE = "collector_buffer.json"
DEADLETTER_FILE = "collector_deadletter.json"
MAX_BUFFER = 50_000          # bounded disk usage (~15 MB); oldest dropped beyond this, with a warning
CHECKPOINT_EVERY = 50        # persist flush progress every N delivered events
LINUX_LOG_FILES = ["/var/log/auth.log", "/var/log/syslog", "/var/log/messages", "/var/log/secure"]

# --------------------------------------------------------------------------- #
# 1. Secret / PII scrubbing engine (runs on the node; raw text never leaves)
# --------------------------------------------------------------------------- #
_NOT_REDACTED = r"(?!\[REDACTED)"
SCRUB_RULES: list[tuple[str, re.Pattern, str]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "[REDACTED_PRIVATE_KEY]"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[REDACTED_JWT]"),
    ("bearer_token", re.compile(r"(?i)\b(bearer)\s+" + _NOT_REDACTED + r"[A-Za-z0-9._~+/=-]{8,}"),
     r"\1 [REDACTED_TOKEN]"),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    ("vendor_api_key", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|xox[abprs]-[A-Za-z0-9-]{10,}"
        r"|sk-[A-Za-z0-9_-]{20,}|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35})"),
     "[REDACTED_API_KEY]"),
    ("url_credentials", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"),
     r"\1[REDACTED_CREDENTIALS]@"),
    # key=value / key: value / "key": "value"  ->  key=[REDACTED_SECRET]   (e.g. pass=*** )
    ("password_or_secret", re.compile(
        r"(?i)\b([a-z0-9_-]*?(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key"
        r"|private[_-]?key|client[_-]?secret|credentials?|session[_-]?id)[a-z0-9_]*)"
        r"([\"']?\s*[=:]\s*)" + _NOT_REDACTED + r"(\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)"),
     r"\1\2[REDACTED_SECRET]"),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
     lambda m: "[REDACTED_CARD]" if _luhn(m.group(0)) else m.group(0)),
]
REDACTION_TOKEN = re.compile(r"\[REDACTED_[A-Z_]+\]")


def _luhn(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = sum(d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2) for i, d in enumerate(reversed(digits)))
    return total % 10 == 0


def _apply(repl, m: re.Match) -> str:
    return repl(m) if callable(repl) else m.expand(repl)


def scrub(text: str) -> tuple[str, dict[str, int]]:
    """Returns (scrubbed_text, {rule_name: redaction_count})."""
    counts: dict[str, int] = {}
    for name, rx, repl in SCRUB_RULES:
        def _sub(m, repl=repl, name=name):
            out = _apply(repl, m)
            if out != m.group(0):
                counts[name] = counts.get(name, 0) + 1
            return out
        text = rx.sub(_sub, text)
    return text, counts


def secret_spans(text: str) -> list[tuple[int, int]]:
    spans = sorted((m.start(), m.end()) for _, rx, repl in SCRUB_RULES for m in rx.finditer(text)
                   if _apply(repl, m) != m.group(0))
    merged: list[tuple[int, int]] = []
    for s, e in spans:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(e, merged[-1][1]))
        else:
            merged.append((s, e))
    return merged


DEMO_LOG_LINES = [   # synthetic, well-known example credentials - safe to publish
    "sshd[2211]: Failed password for admin from 10.108.72.90 port 52144 ssh2; debug pass=Hunter2!2026",
    "webapp[884]: POST /login user=alice@corp.example password=S3cr3t!Pass status=200",
    "api-gw[77]: GET /v1/orders Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "deploy.sh: export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE api_key=demo_9f8e7d6c5b4a3210fedcba",
    "db-client[31]: connecting to postgres://svc_user:Pa55w0rd@10.108.72.40:5432/prod",
    'payments[90]: {"card": "4111 1111 1111 1111", "client_secret": "cs_demo_abc123xyz"}',
    "worker[31]: job 8812 completed in 412ms",
]

# --------------------------------------------------------------------------- #
# 2. Raw log sources (file tail / journald / Windows Event Log)
# --------------------------------------------------------------------------- #
class LogSource:
    def __init__(self, path: str | None, demo: bool):
        self.demo, self.first_read = demo, True
        self.kind, self.path, self.offset = "none", None, 0
        for p in ([path] if path else (LINUX_LOG_FILES if os.name != "nt" else [])):
            if p and os.path.isfile(p) and os.access(p, os.R_OK):
                self.kind, self.path, self.offset = "file", p, max(0, os.path.getsize(p) - 4096)
                break
        else:
            if path:
                print(f"[collector] warning: cannot read {path}; falling back to system log", file=sys.stderr)
            if os.name == "nt" and shutil.which("wevtutil"):
                self.kind, self.path = "wevtutil", "Windows System log"
            elif shutil.which("journalctl"):
                self.kind, self.path = "journalctl", "systemd journal"

    def describe(self) -> str:
        src = f"{self.kind}:{self.path}" if self.path else "none"
        return src + (" + synthetic demo secrets" if self.demo else "")

    def read(self, n: int) -> list[str]:
        try:
            if self.kind == "file":
                lines = self._read_file()
            elif self.kind == "journalctl":
                lines = self._run(["journalctl", "-n", str(n), "--no-pager", "-q", "-o", "short-iso"])
            elif self.kind == "wevtutil":
                lines = self._read_wevtutil(n)
            else:
                lines = []
        except (OSError, subprocess.SubprocessError) as exc:
            lines = [f"[collector] log source error: {exc}"]
        lines = [ln.rstrip() for ln in lines if ln.strip()][-n:]
        if self.demo:
            lines += random.sample(DEMO_LOG_LINES, 2)
        return lines

    def _read_file(self) -> list[str]:
        size = os.path.getsize(self.path)
        if size < self.offset:            # rotated / truncated
            self.offset = 0
        with open(self.path, "rb") as fh:
            fh.seek(self.offset)
            data = fh.read(65536)
        cut = data.rfind(b"\n")
        if cut < 0:
            return []
        self.offset += cut + 1
        lines = data[:cut + 1].decode("utf-8", "replace").splitlines()
        if self.first_read:               # first chunk may start mid-line
            self.first_read, lines = False, lines[1:]
        return lines

    @staticmethod
    def _run(cmd: list[str]) -> list[str]:
        out = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=10).stdout
        return out.splitlines()

    def _read_wevtutil(self, n: int) -> list[str]:
        out = "\n".join(self._run(["wevtutil", "qe", "System", f"/c:{n}", "/rd:true", "/f:text"]))
        lines = []
        for block in out.split("Event[")[1:]:
            fields, desc, in_desc = {}, [], False
            for raw in block.splitlines():
                s = raw.strip()
                if in_desc:
                    if s:
                        desc.append(s)
                elif s.startswith("Description:"):
                    in_desc = True
                    if s[12:].strip():
                        desc.append(s[12:].strip())
                elif ":" in s:
                    k, _, v = s.partition(":")
                    fields[k.strip()] = v.strip()
            lines.append(f"{fields.get('Date', '')} {fields.get('Source', '')} [{fields.get('Level', '')}] "
                         f"{' '.join(desc)[:300]}")
        return lines


# --------------------------------------------------------------------------- #
# 3. Metrics (psutil if available, otherwise stdlib: /proc on Linux, Win32 API on Windows)
# --------------------------------------------------------------------------- #
class MetricsSampler:
    def __init__(self):
        self._cpu_prev = self._cpu_times()
        self._net_prev = (time.monotonic(), self._net_bytes())
        if psutil:
            psutil.cpu_percent(interval=None)
        time.sleep(0.5)                   # first CPU delta needs a short window

    def sample(self) -> tuple[float, float, float]:
        return self._cpu(), self._memory(), self._bandwidth()

    # CPU ------------------------------------------------------------------
    @staticmethod
    def _cpu_times() -> tuple[float, float] | None:
        """Returns (idle, total) counters."""
        try:
            if sys.platform.startswith("linux"):
                with open("/proc/stat") as fh:
                    vals = [float(x) for x in fh.readline().split()[1:9]]
                return vals[3] + vals[4], sum(vals)
            if os.name == "nt":
                import ctypes
                idle, kernel, user = (ctypes.c_ulonglong(), ctypes.c_ulonglong(), ctypes.c_ulonglong())
                ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user))
                return float(idle.value), float(kernel.value + user.value)   # kernel time includes idle
        except (OSError, ValueError, AttributeError):
            pass
        return None

    def _cpu(self) -> float:
        if psutil:
            return psutil.cpu_percent(interval=None)
        cur = self._cpu_times()
        if not cur or not self._cpu_prev:
            return 0.0
        d_idle, d_total = cur[0] - self._cpu_prev[0], cur[1] - self._cpu_prev[1]
        self._cpu_prev = cur
        return max(0.0, min(100.0, 100.0 * (1 - d_idle / d_total))) if d_total > 0 else 0.0

    # Memory ---------------------------------------------------------------
    @staticmethod
    def _memory() -> float:
        if psutil:
            return psutil.virtual_memory().percent
        try:
            if sys.platform.startswith("linux"):
                info = {}
                with open("/proc/meminfo") as fh:
                    for line in fh:
                        k, _, v = line.partition(":")
                        info[k] = float(v.split()[0])
                return 100.0 * (1 - info["MemAvailable"] / info["MemTotal"])
            if os.name == "nt":
                import ctypes

                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong)] + [
                        (f, ctypes.c_ulonglong) for f in ("ullTotalPhys", "ullAvailPhys", "ullTotalPageFile",
                                                          "ullAvailPageFile", "ullTotalVirtual", "ullAvailVirtual",
                                                          "ullAvailExtendedVirtual")]
                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(stat)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
                return float(stat.dwMemoryLoad)
        except (OSError, KeyError, ValueError, ZeroDivisionError, AttributeError):
            pass
        return 0.0

    # Bandwidth ------------------------------------------------------------
    @staticmethod
    def _net_bytes() -> int:
        if psutil:
            c = psutil.net_io_counters()
            return c.bytes_sent + c.bytes_recv
        try:
            if sys.platform.startswith("linux"):
                total = 0
                with open("/proc/net/dev") as fh:
                    for line in fh.readlines()[2:]:
                        iface, _, data = line.partition(":")
                        if iface.strip() != "lo":
                            cols = data.split()
                            total += int(cols[0]) + int(cols[8])
                return total
            if os.name == "nt":   # first "<label> <recv> <sent>" row of `netstat -e` is Bytes (locale-safe)
                out = subprocess.run(["netstat", "-e"], capture_output=True, text=True, timeout=5).stdout
                for line in out.splitlines():
                    m = re.match(r"^\S+\s+(\d+)\s+(\d+)\s*$", line.strip())
                    if m:
                        return int(m.group(1)) + int(m.group(2))
        except (OSError, ValueError, IndexError, subprocess.SubprocessError):
            pass
        return 0

    def _bandwidth(self) -> float:
        now, cur = time.monotonic(), self._net_bytes()
        t0, b0 = self._net_prev
        self._net_prev = (now, cur)
        return max(0.0, (cur - b0) * 8 / max(now - t0, 1e-3) / 1e6)


class Prober:
    """Latency + packet loss to the SaaS, measured the way the events actually travel.

    tcp  : TCP handshakes, trying every resolved address IPv4-first (a broken IPv6 route or an
           unreachable first address must not read as 100 % loss) and remembering the one that works.
    http : lightweight HTTPS round trips to /health over the shipper's session - used when a proxy is
           configured (direct TCP would bypass it) or, in auto mode, when raw TCP keeps failing while
           HTTPS delivery succeeds (filtered networks).
    """

    def __init__(self, url: str, session, mode: str = "auto", count: int = 4, timeout: float = 0.8):
        p = urlparse(url)
        self.host, self.port = p.hostname, p.port or (443 if p.scheme == "https" else 80)
        self.health_url = f"{p.scheme}://{p.netloc}/health"
        self.session, self.count, self.timeout = session, count, timeout
        self.proxy = requests.utils.select_proxy(url, requests.utils.get_environ_proxies(url))
        self.auto = mode == "auto"
        self.mode = mode if mode != "auto" else ("http" if self.proxy else "tcp")
        self.good: tuple | None = None
        self.streak = 0

    def describe(self) -> str:
        if self.mode == "http":
            return "HTTPS round trips to /health" + (f" (via proxy {self.proxy})" if self.proxy else "")
        return "TCP handshakes, all resolved addresses, IPv4 first" + (" (auto-fallback to HTTPS)" if self.auto else "")

    def _addrs(self) -> list[tuple]:
        infos = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        infos.sort(key=lambda i: i[0] != socket.AF_INET)
        addrs = list(dict.fromkeys((i[0], i[4]) for i in infos))
        if self.good in addrs:
            addrs.remove(self.good)
            addrs.insert(0, self.good)
        return addrs

    def _tcp_once(self, addrs) -> float | None:
        for fam, addr in addrs:
            t0 = time.perf_counter()
            try:
                with socket.socket(fam, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    s.connect(addr)
                self.good = (fam, addr)
                return (time.perf_counter() - t0) * 1000
            except OSError:
                continue
        return None

    def _http_once(self) -> float | None:
        t0 = time.perf_counter()
        try:
            if self.session.get(self.health_url, timeout=(1.5, 1.5)).status_code < 500:
                return (time.perf_counter() - t0) * 1000
        except requests.RequestException:
            pass
        return None

    def measure(self) -> tuple[float, float]:
        if self.mode == "tcp":
            try:
                addrs = self._addrs()
            except socket.gaierror:
                return self.timeout * 1000, 100.0
            once = lambda: self._tcp_once(addrs)   # noqa: E731
        else:
            once = self._http_once
        rtts: list[float | None] = []
        for i in range(self.count):
            rtts.append(once())
            if i == 1 and rtts[0] is None and rtts[1] is None:   # target unreachable: don't burn the cycle
                rtts += [None] * (self.count - 2)
                break
        ok = [r for r in rtts if r is not None]
        loss = 100.0 * (self.count - len(ok)) / self.count
        return round(statistics.median(ok) if ok else self.timeout * 1000, 2), round(loss, 1)

    def observe(self, measured_loss: float, delivered: bool) -> str | None:
        """Auto mode: raw TCP blocked while HTTPS delivery works => the probe, not the link, is broken."""
        if not self.auto or self.mode != "tcp":
            return None
        self.streak = self.streak + 1 if (measured_loss >= 100 and delivered) else 0
        if self.streak >= 2:
            self.mode = "http"
            return ("raw TCP probes fail on this network while HTTPS delivery works - "
                    "switched to HTTPS round-trip probes")
        return None


def local_health(cpu: float, mem: float, lat: float, loss: float) -> str:   # mirrors Tier-2 thresholds
    if loss >= 2 or cpu >= 90 or mem >= 92 or lat >= 500:
        return "Poor"
    if loss > 0 or cpu >= 75 or mem >= 80 or lat >= 200:
        return "Fair"
    if cpu >= 50 or mem >= 65 or lat >= 80:
        return "Good"
    return "Excellent"


def apply_chaos(mode: str, cpu, mem, bw, lat, loss):
    """Synthetic, clearly-labelled metric perturbation so judges can watch the AIOps rules fire."""
    u = random.uniform
    if mode == "cpu_loss":
        cpu, loss = u(88, 97), u(8, 15)
    elif mode == "latency":
        lat, loss = lat + u(250, 400), max(loss, u(4, 8))
    elif mode == "memory":
        mem, cpu = u(91, 96), u(80, 90)
    elif mode == "bandwidth":
        bw, lat = u(80, 150), lat + u(60, 120)
    return cpu, mem, bw, lat, loss


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def wire_bytes(event: dict) -> bytes:
    """Canonical serialization: the bytes shown in the proof panel are the bytes sent (and re-sent)."""
    return json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --------------------------------------------------------------------------- #
# 4. Write-ahead disk buffer + in-order shipper (zero data loss, idempotent retries)
# --------------------------------------------------------------------------- #
class DiskBuffer:
    def __init__(self, path: str):
        self.path = path
        self.events: list[dict] = self._load()

    def _load(self) -> list[dict]:
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
            return [e for e in data if isinstance(e, dict) and "event_id" in e] if isinstance(data, list) else []
        except FileNotFoundError:
            return []
        except (json.JSONDecodeError, OSError):
            backup = f"{self.path}.corrupt-{int(time.time())}"
            os.replace(self.path, backup)
            print(f"[collector] buffer unreadable; preserved as {backup}", file=sys.stderr)
            return []

    def save(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.events, fh, separators=(",", ":"))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)       # atomic: never a half-written buffer

    def append(self, event: dict) -> None:
        self.events.append(event)
        if len(self.events) > MAX_BUFFER:
            dropped = len(self.events) - MAX_BUFFER
            self.events = self.events[dropped:]
            print(f"[collector] WARNING buffer cap {MAX_BUFFER} reached; dropped {dropped} oldest", file=sys.stderr)
        self.save()

    def drop_front(self, n: int) -> None:
        if n:
            self.events = self.events[n:]
            self.save()

    def __len__(self) -> int:
        return len(self.events)


class Shipper:
    def __init__(self, url: str, token: str, buffer_path: str):
        self.url = url
        self.buffer = DiskBuffer(buffer_path)
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                     "User-Agent": "smart-observability-collector/1.0"})

    def flush(self) -> dict:
        res = {"delivered": 0, "duplicates": 0, "deadlettered": 0, "error": None, "attempted": len(self.buffer),
               "oldest": self.buffer.events[0]["timestamp"] if self.buffer.events else None, "last": None}
        q, i = self.buffer.events, 0
        while i < len(q):
            try:
                r = self.session.post(self.url, data=wire_bytes(q[i]), timeout=(5, 20))
            except requests.ReadTimeout:
                res["error"] = ("SaaS accepted the connection but did not answer within 20s "
                                "(app restarting / cold start / overloaded - network is fine)")
                break
            except requests.ConnectionError as exc:
                kind = "DNS lookup failed" if "resolve" in str(exc).lower() or "name" in str(exc).lower() else "cannot connect"
                res["error"] = f"SaaS unreachable - {kind} (check Wi-Fi / DNS / firewall)"
                break
            except requests.RequestException as exc:
                res["error"] = f"SaaS unreachable ({type(exc).__name__})"
                break
            if r.status_code in (200, 201):
                res["duplicates" if r.status_code == 200 else "delivered"] += 1
                res["last"] = _safe_json(r)
                i += 1
            elif r.status_code in (400, 413, 415, 422):   # poison event: park it, don't block the queue
                self._deadletter(q[i], r)
                res["deadlettered"] += 1
                i += 1
            elif r.status_code in (401, 403):
                res["error"] = f"auth rejected (HTTP {r.status_code}) - check --token; events retained"
                break
            else:
                res["error"] = f"HTTP {r.status_code} from SaaS - will retry"
                break
            if i >= CHECKPOINT_EVERY:                     # crash-safe progress; re-sends dedupe server-side
                self.buffer.drop_front(i)
                q, i = self.buffer.events, 0
        self.buffer.drop_front(i)
        res["remaining"] = len(self.buffer)
        return res

    @staticmethod
    def _deadletter(event: dict, resp) -> None:
        entry = {"event": event, "status": resp.status_code, "reason": _safe_json(resp), "at": utc_now_iso()}
        with open(DEADLETTER_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")


def _safe_json(resp):
    try:
        return resp.json()
    except ValueError:
        return {"body": resp.text[:200]}


# --------------------------------------------------------------------------- #
# 5. Egress Proof Panel (side-by-side terminal rendering)
# --------------------------------------------------------------------------- #
class Style:
    def __init__(self, enabled: bool):
        e = enabled
        self.R, self.G, self.Y, self.C = ("\033[31m", "\033[32m", "\033[33m", "\033[36m") if e else ("",) * 4
        self.B, self.D, self.X, self.HL = ("\033[1m", "\033[2m", "\033[0m", "\033[1;97;41m") if e else ("",) * 4
        self.OK = "\033[1;30;42m" if e else ""


def _paint(text: str, style: str, spans, hl: str, reset: str) -> str:
    out, pos = [], 0
    for s, e in spans:
        out += [style, text[pos:s], hl, text[s:e], reset]
        pos = e
    out += [style, text[pos:], reset]
    return "".join(out)


def render_panel(st: Style, cycle: int, url: str, raw: list[str], scrubbed: list[str], counts: dict,
                 event: dict, wire: bytes, leaks: dict) -> None:
    width = max(90, min(shutil.get_terminal_size((160, 40)).columns, 220))
    col = (width - 3) // 2

    def wrapped(lines, bullet="• "):
        for line in lines or ["(no new log lines this cycle)"]:
            for j, seg in enumerate(textwrap.wrap(line, col - 2, break_long_words=True,
                                                  break_on_hyphens=False) or [""]):
                yield (bullet if j == 0 else "  ") + seg

    left = [(f"RAW LOG  (local only - NEVER transmitted)", st.B + st.R), ("─" * col, st.D)]
    left += [(ln, "") for ln in wrapped(raw)]
    right = [("SANITIZED PAYLOAD  (exact JSON leaving this node)", st.B + st.G), ("─" * col, st.D)]
    right += [(seg, st.G) for line in json.dumps(event, indent=2, sort_keys=True).splitlines()
              for seg in textwrap.wrap(line, col, drop_whitespace=False) or [""]]
    right += [("", ""), ("scrubbed log (kept on node, not sent):", st.D)]
    right += [(ln, st.D) for ln in wrapped(scrubbed, "  ")]

    title = f" EGRESS PROOF · cycle {cycle} · {event['timestamp']} · -> {url} "
    print("\n" + st.C + st.B + title.center(width, "═") + st.X)
    for (lt, ls), (rt, rs) in zip_longest(left, right, fillvalue=("", "")):
        lpad, rpad = lt.ljust(col)[:col], rt.ljust(col)[:col]
        lspans = secret_spans(lpad) if ls == "" else []
        rspans = [m.span() for m in REDACTION_TOKEN.finditer(rpad)] if rs == st.D else []
        print(_paint(lpad, ls, lspans, st.HL, st.X) + f" {st.D}│{st.X} " + _paint(rpad, rs, rspans, st.Y, st.X))
    red = ", ".join(f"{k}×{v}" for k, v in counts.items()) or "none in this batch"
    dlp = (f"{st.OK} PASS {st.X} 0 secret patterns in egress bytes" if not leaks
           else f"{st.HL} FAIL {st.X} {leaks} -> EVENT BLOCKED")
    print(f"{st.D}{'─' * width}{st.X}")
    print(f"Redactions: {st.Y}{red}{st.X}  |  DLP egress gate: {dlp}  |  "
          f"wire {len(wire)} B sha256:{hashlib.sha256(wire).hexdigest()[:16]}…")


# --------------------------------------------------------------------------- #
# Target resolution / main loop
# --------------------------------------------------------------------------- #
def resolve_target(args) -> str:
    url = args.url or os.environ.get("SMARTOBS_URL")
    if not url:
        if args.target == "azure":
            app = args.app_name or os.environ.get("SMARTOBS_AZURE_APP")
            if not app:
                sys.exit("--target azure needs --app-name <name> (or SMARTOBS_AZURE_APP)")
            url = AZURE_URL_TEMPLATE.format(app=app)
        else:
            url = DEFAULT_LOCAL_URL
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        sys.exit(f"invalid target URL: {url}")
    if p.scheme == "http":
        try:
            ip = ipaddress.ip_address(p.hostname)
            private = ip.is_private or ip.is_loopback
        except ValueError:
            private = p.hostname == "localhost"
        if not private:
            print("[collector] WARNING: plain HTTP to a non-private host - bearer token travels in clear text. "
                  "Use https://", file=sys.stderr)
    return url


def detect_server_id(host: str, port: int) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((host, port))       # UDP connect sends no packets; just picks the egress interface
            sid = s.getsockname()[0]
    except OSError:
        sid = socket.gethostname()
    return re.sub(r"[^A-Za-z0-9._:-]", "-", sid)[:64]


def parse_args():
    ap = argparse.ArgumentParser(description="Smart Observability Tier-1 edge collector")
    ap.add_argument("--target", choices=["local", "azure"], default="local",
                    help=f"local = {DEFAULT_LOCAL_URL}; azure = {AZURE_URL_TEMPLATE}")
    ap.add_argument("--app-name", help="Azure App Service name (for --target azure)")
    ap.add_argument("--url", help="explicit ingest URL (overrides --target)")
    ap.add_argument("--token", default=DEFAULT_TOKEN, help="bearer token (default: $SMARTOBS_TOKEN or demo token)")
    ap.add_argument("--server-id", help="node identity (default: this node's egress IP)")
    ap.add_argument("--interval", type=float, default=5.0, help="seconds between cycles (default 5)")
    ap.add_argument("--log-file", help="raw log file to tail (default: auto-detect)")
    ap.add_argument("--log-lines", type=int, default=3, help="raw log lines per cycle (default 3)")
    ap.add_argument("--buffer", default=BUFFER_FILE, help=f"buffer file (default {BUFFER_FILE})")
    ap.add_argument("--demo", action="store_true", help="mix synthetic secret-bearing log lines into each cycle")
    ap.add_argument("--chaos", choices=["cpu_loss", "latency", "memory", "bandwidth"],
                    help="synthetically perturb metrics to demo correlated anomalies")
    ap.add_argument("--chaos-after", type=int, default=4, help="cycles of normal data before chaos starts")
    ap.add_argument("--probe", choices=["auto", "tcp", "http"], default="auto",
                    help="latency/loss method: tcp handshakes, https round trips, or auto (default)")
    ap.add_argument("--once", action="store_true", help="run a single cycle and exit")
    ap.add_argument("--no-color", action="store_true")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    if os.name == "nt":
        os.system("")                     # enable ANSI escape processing on Windows 10+
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    st = Style(not args.no_color and sys.stdout.isatty())

    url = resolve_target(args)
    p = urlparse(url)
    host, port = p.hostname, p.port or (443 if p.scheme == "https" else 80)
    server_id = args.server_id or detect_server_id(host, port)
    sampler, logs = MetricsSampler(), LogSource(args.log_file, args.demo)
    shipper = Shipper(url, args.token, args.buffer)
    prober = Prober(url, shipper.session, args.probe)

    print(f"{st.B}Smart Observability · Tier-1 Edge Collector{st.X}")
    print(f"  node       : {server_id}\n  target     : {url}\n  log source : {logs.describe()}")
    print(f"  probe      : {prober.describe()}")
    print(f"  metrics    : {'psutil' if psutil else 'stdlib (/proc or Win32)'}\n  buffer     : "
          f"{os.path.abspath(args.buffer)} ({len(shipper.buffer)} pending from previous run)")
    if args.chaos:
        print(f"  {st.Y}CHAOS MODE '{args.chaos}' after cycle {args.chaos_after}: metrics synthetically perturbed{st.X}")

    cycle, was_offline = 0, len(shipper.buffer) > 0
    try:
        while True:
            cycle += 1
            started = time.monotonic()
            cpu, mem, bw = sampler.sample()
            lat, loss = prober.measure()
            measured_loss = loss
            if args.chaos and cycle > args.chaos_after:
                cpu, mem, bw, lat, loss = apply_chaos(args.chaos, cpu, mem, bw, lat, loss)

            event = {   # allow-listed, numeric-only metadata
                "event_id": uuid.uuid4().hex, "server_id": server_id,   # event_id = idempotency key fixed at capture
                "cpu_usage": round(cpu, 1), "memory_usage": round(mem, 1), "bandwidth_mbps": round(bw, 3),
                "latency_ms": round(lat, 2), "packet_loss": round(loss, 1),
                "health": local_health(cpu, mem, lat, loss), "timestamp": utc_now_iso(),
            }
            raw = logs.read(args.log_lines)
            scrubbed, counts = [], {}
            for line in raw:
                clean, c = scrub(line)
                scrubbed.append(clean)
                for k, v in c.items():
                    counts[k] = counts.get(k, 0) + v
            wire = wire_bytes(event)
            _, leaks = scrub(wire.decode("utf-8"))      # DLP gate on the exact egress bytes
            render_panel(st, cycle, url, raw, scrubbed, counts, event, wire, leaks)
            if leaks:
                print(f"{st.R}✖ egress blocked by DLP gate - event discarded{st.X}")
            else:
                shipper.buffer.append(event)           # write-ahead: persisted before any network I/O
                res = shipper.flush()
                sent = res["delivered"] + res["duplicates"]
                if res["error"]:
                    was_offline = True
                    print(f"{st.R}✖ {res['error']} - queued to {args.buffer} "
                          f"({res['remaining']} pending, oldest {res['oldest']}){st.X}")
                else:
                    if was_offline and res["attempted"] > 1:
                        print(f"{st.C}↻ RECONNECTED - replayed {sent} buffered events with original UTC timestamps "
                              f"(oldest {res['oldest']}; {res['duplicates']} duplicate(s) ignored by server "
                              f"idempotency){st.X}")
                    was_offline = False
                    srv = (res["last"] or {})
                    print(f"{st.G}✔ delivered -> {srv.get('status', 'ok')} (server health={srv.get('health', '?')})"
                          f" | buffer: {res['remaining']} pending{st.X}")
                note = prober.observe(measured_loss, not res["error"] and sent > 0)
                if note:
                    print(f"{st.Y}! {note}{st.X}")
                if res["deadlettered"]:
                    print(f"{st.Y}! {res['deadlettered']} event(s) rejected by schema -> {DEADLETTER_FILE}{st.X}")
            if args.once:
                return 0 if not len(shipper.buffer) else 2
            time.sleep(max(0.0, args.interval - (time.monotonic() - started)))
    except KeyboardInterrupt:
        print(f"\nstopped. {len(shipper.buffer)} event(s) remain buffered in {args.buffer} and will replay next run.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
