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
import collections
import csv
import hashlib
import ipaddress
import json
import math
import os
import random
import re
import shutil
import socket
import statistics
import subprocess
import sys
import textwrap
import threading
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


# Failed-login detector: ONE pattern per failed attempt (sshd also logs "pam_unix(sshd:auth): authentication
# failure" for the same attempt, so that line is deliberately not counted). Only the COUNT leaves the node.
FAILED_LOGIN_RE = re.compile(
    r"(?i)failed (?:password|publickey|keyboard-interactive|none) for"
    r"|FAILED LOGIN|FAILED SU|login incorrect|incorrect password attempt"
    r"|pam_unix\((?!sshd)[^)]*:auth\): authentication failure"
    r"|an account failed to log on|event id:?\s*4625")


def count_failed_logins(lines) -> int:
    return sum(1 for ln in lines if FAILED_LOGIN_RE.search(ln))


def disk_usage_pct() -> float | None:
    """% used of the system disk (/ on Linux, the system drive on Windows)."""
    try:
        root = (os.environ.get("SystemDrive", "C:") + "\\") if os.name == "nt" else "/"
        u = shutil.disk_usage(root)
        return 100.0 * u.used / u.total if u.total else None
    except OSError:
        return None


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
        self.primed = False                 # the first read is history: shown, not counted
        self.cursor: str | None = None      # journald cursor -> each line is read (and counted) once
        self.win_security: bool | None = None
        self.last_win: float | None = None
        self.notes: list[str] = []
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

    def read(self, n: int) -> tuple[list[str], int | None]:
        """(newest n lines for the proof panel, failed logins counted in ALL new lines - None if unknown)."""
        failed = None
        try:
            if self.kind == "file":
                lines = self._read_file()
            elif self.kind == "journalctl":
                lines = self._read_journal(n)
            elif self.kind == "wevtutil":
                lines = self._read_wevtutil(n)
            else:
                lines = []
            lines = [ln.rstrip() for ln in lines if ln.strip()]
            if self.kind in ("file", "journalctl"):
                failed = count_failed_logins(lines) if self.primed else 0
            elif self.kind == "wevtutil":
                failed = self._win_failed_logins()
        except (OSError, subprocess.SubprocessError) as exc:
            lines = [f"[collector] log source error: {exc}"]
        self.primed = True
        lines = lines[-n:]
        if self.demo:
            demo = random.sample(DEMO_LOG_LINES, 2)
            lines += demo
            failed = (failed or 0) + count_failed_logins(demo)
        return lines, failed

    def _read_journal(self, n: int) -> list[str]:
        cmd = ["journalctl", "--no-pager", "-q", "-o", "short-iso", "--show-cursor"]
        if self.cursor:
            cmd.append(f"--after-cursor={self.cursor}")
        else:
            cmd += ["-n", str(max(n, 20))]
        out = []
        for ln in self._run(cmd):
            if ln.startswith("-- cursor: "):
                self.cursor = ln[len("-- cursor: "):].strip()
            else:
                out.append(ln)
        return out

    def _win_failed_logins(self) -> int | None:
        """Windows: count Security-log event 4625 (failed logon) since the last cycle. Needs an Administrator
        terminal; without it we send no count rather than a misleading zero."""
        if self.win_security is False:
            return None
        now = time.time()
        window_ms = int(max(1.0, now - (self.last_win or now - 5)) * 1000)
        self.last_win = now
        query = f"*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= {window_ms}]]]"
        r = subprocess.run(["wevtutil", "qe", "Security", f"/q:{query}", "/c:5000", "/f:text"],
                           capture_output=True, text=True, errors="replace", timeout=10)
        if r.returncode != 0:
            self.win_security = False
            self.notes.append("failed-login counts on Windows need an Administrator terminal (Security log); "
                              "sending none")
            return None
        self.win_security = True
        return r.stdout.count("Event[")

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


def chaos_disk(disk: float | None, step: int) -> float:
    """Synthetic disk filling ~1.2 % per cycle from 86 %, to demo the predictive and disk-full alerts."""
    return min(99.0, max(disk or 0.0, 86.0) + 1.2 * step)


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

    def extend(self, events: list[dict]) -> None:
        for e in events[:-1]:
            self.events.append(e)
        if events:
            self.append(events[-1])                  # single save (and cap check) for the whole batch

    def drop_front(self, n: int) -> None:
        if n:
            self.events = self.events[n:]
            self.save()

    def __len__(self) -> int:
        return len(self.events)


OPTIONAL_SEND_FIELDS = ("disk_usage", "failed_logins")


class Shipper:
    def __init__(self, url: str, token: str, buffer_path: str):
        self.compat = False                 # True once the SaaS rejected the optional fields (older deploy)
        self.url = url
        self.buffer = DiskBuffer(buffer_path)
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                     "User-Agent": "smart-observability-collector/1.0"})

    def flush(self) -> dict:
        res = {"delivered": 0, "duplicates": 0, "deadlettered": 0, "error": None, "attempted": len(self.buffer),
               "notes": [],
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
            elif r.status_code == 400 and "allow-list" in str(_safe_json(r)) and \
                    any(f in q[i] for f in OPTIONAL_SEND_FIELDS):
                for f in OPTIONAL_SEND_FIELDS:           # older SaaS: resend this event without the new fields
                    q[i].pop(f, None)
                if not self.compat:
                    self.compat = True
                    res["notes"].append("SaaS does not accept disk_usage / failed_logins yet (older deploy) - "
                                        "sending without them until the collector restarts")
                continue
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
                 events: list[dict], wires: list[bytes], leaks: dict, source: str = "local system log") -> None:
    width = max(90, min(shutil.get_terminal_size((160, 40)).columns, 220))
    col = (width - 3) // 2

    def wrapped(lines, bullet="• "):
        for line in lines or ["(no new log lines this cycle)"]:
            for j, seg in enumerate(textwrap.wrap(line, col - 2, break_long_words=True,
                                                  break_on_hyphens=False) or [""]):
                yield (bullet if j == 0 else "  ") + seg

    left = [(f"RAW {source.upper()}  (local only - NEVER transmitted)"[:col], st.B + st.R), ("─" * col, st.D)]
    left += [(ln, "") for ln in wrapped(raw)]
    head = "SANITIZED PAYLOAD" if len(events) == 1 else f"SANITIZED PAYLOADS  ({len(events)} events, one per host)"
    right = [(f"{head}  (exact JSON leaving this node)"[:col], st.B + st.G), ("─" * col, st.D)]
    if len(events) == 1:
        right += [(seg, st.G) for line in json.dumps(events[0], indent=2, sort_keys=True).splitlines()
                  for seg in textwrap.wrap(line, col, drop_whitespace=False) or [""]]
    elif not events:
        right += [("(no metric records in this window - nothing sent)", st.D)]
    else:
        for w in wires[:5]:
            right += [(seg, st.G) for seg in textwrap.wrap(w.decode("utf-8"), col, break_long_words=True) or [""]]
        if len(wires) > 5:
            right += [(f"… +{len(wires) - 5} more events (same schema, all in the wire total below)", st.D)]
    right += [("", ""), ("scrubbed log (kept on node, not sent):", st.D)]
    right += [(ln, st.D) for ln in wrapped(scrubbed, "  ")]

    title = f" EGRESS PROOF · cycle {cycle} · {utc_now_iso()} · -> {url} "
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
    blob = b"\n".join(wires)
    print(f"Redactions: {st.Y}{red}{st.X}  |  DLP egress gate: {dlp}  |  "
          f"wire {len(blob)} B in {len(wires)} event(s) sha256:{hashlib.sha256(blob).hexdigest()[:16]}…")


# --------------------------------------------------------------------------- #
# 6. Organiser telemetry stream adapter (shared stream -> per-host, allow-listed metadata)
# --------------------------------------------------------------------------- #
def _nk(key) -> str:
    """Normalised field name: 'CPU_Usage', 'cpu.usage', 'cpuUsage' -> 'cpuusage'."""
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


_ALIASES = {   # tried in order; matched case/punctuation-insensitively; override any with --map
    "server_id": ["server_id", "host", "hostname", "host.name", "node", "node_name", "server", "server_name",
                  "device", "device_id", "instance", "instance_id", "machine", "agent.name", "source_host"],
    "tenant": ["tenant", "tenant_id", "org", "org_id", "organization", "customer", "account", "team"],
    "timestamp": ["timestamp", "@timestamp", "ts", "time", "datetime", "event_time", "date", "created_at"],
    "cpu_usage": ["cpu_usage", "cpu", "cpu_pct", "cpu_percent", "cpu_util", "cpu_utilization", "cpu.usage",
                  "cpu.pct", "cpu_load", "system.cpu.total.pct"],
    "memory_usage": ["memory_usage", "mem", "memory", "mem_pct", "mem_percent", "memory_pct", "memory_percent",
                     "mem_usage", "ram", "ram_usage", "ram_pct", "memory.used.pct", "system.memory.used.pct"],
    "bandwidth_mbps": ["bandwidth_mbps", "bandwidth", "bw", "bw_mbps", "net_mbps", "network_mbps", "throughput",
                       "throughput_mbps", "traffic_mbps"],
    "latency_ms": ["latency_ms", "latency", "rtt", "rtt_ms", "ping", "ping_ms", "delay_ms", "delay",
                   "response_time_ms", "response_time"],
    "packet_loss": ["packet_loss", "loss", "packetloss", "loss_pct", "loss_percent", "packet_loss_pct",
                    "pkt_loss", "drop_rate", "drops_pct"],
    "message": ["message", "msg", "log", "raw", "line", "text", "event", "body"],
    "disk_usage": ["disk_usage", "disk", "disk_pct", "disk_percent", "disk_used_pct", "disk.used.pct",
                   "fs_used_pct", "filesystem.used.pct", "system.filesystem.used.pct", "storage_pct"],
    "failed_logins": ["failed_logins", "failed_login", "login_failures", "auth_failures", "failed_auth",
                      "failed_logons", "failedlogins"],
}
ALIASES = {k: [_nk(a) for a in v] for k, v in _ALIASES.items()}
STREAM_METRICS = ("cpu_usage", "memory_usage", "bandwidth_mbps", "latency_ms", "packet_loss")
STREAM_OPTIONAL = ("disk_usage", "failed_logins")
METRIC_CLAMP = {"cpu_usage": 100.0, "memory_usage": 100.0, "packet_loss": 100.0, "disk_usage": 100.0,
                "latency_ms": 600_000.0, "bandwidth_mbps": 1_000_000.0, "failed_logins": 1_000_000.0}
KV_RE = re.compile(r"""([A-Za-z_@][\w.@-]*)\s*[=:]\s*("[^"]*"|'[^']*'|[^\s,;]+)""")


def _flatten(obj: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in obj.items():
        if isinstance(v, dict):
            out.update(_flatten(v, f"{prefix}{k}."))
        elif not isinstance(v, (list, tuple)):
            out[f"{prefix}{k}"] = v
    return out


def _num(v) -> float | None:
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v) if math.isfinite(v) else None
    m = re.match(r"\s*(-?\d+(?:\.\d+)?)", str(v))          # tolerates units: "93%", "120ms", "1.5 Mbps"
    return float(m.group(1)) if m else None


def _ts(v) -> float | None:
    if isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r"\s*\d{9,}(\.\d+)?\s*", v)):
        n = float(v)
        n = n / 1000 if n > 1e12 else n                        # epoch milliseconds
        return n if n > 1e9 else None
    try:
        dt = datetime.fromisoformat(str(v).strip().replace("Z", "+00:00").replace(" ", "T", 1))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def normalize_record(rec: dict, mapping: dict) -> dict:
    by = {}
    for k, v in rec.items():
        by.setdefault(_nk(k), (k, v))
    out = {"metrics": {}, "optional": {}, "host": None, "tenant": None, "ts": None, "message": None}
    for field, cands in ALIASES.items():
        for alias in ([mapping[field]] if field in mapping else cands):
            if alias not in by:
                continue
            key, val = by[alias]
            if field in STREAM_METRICS or field in STREAM_OPTIONAL:
                x = _num(val)
                if x is None:
                    continue
                if field in ("cpu_usage", "memory_usage", "packet_loss", "disk_usage") and 0 <= x <= 1 and \
                        re.search(r"ratio|fraction|\.pct$", str(key).lower()):
                    x *= 100                                    # fractional percentages (e.g. metricbeat .pct)
                x = min(max(x, 0.0), METRIC_CLAMP[field])
                out["metrics" if field in STREAM_METRICS else "optional"][field] = x
            elif field == "message":
                if isinstance(val, str):
                    out["message"] = val
            elif field == "timestamp":
                out["ts"] = _ts(val)
            elif field in ("server_id", "tenant") and str(val).strip():
                out["host" if field == "server_id" else "tenant"] = str(val).strip()
            break
    return out


class StreamSource:
    """Reads the shared organiser telemetry stream and turns it into one allow-listed event per host per cycle.

    Sources : a file (tailed, rotation-safe) · '-'/'stdin' (pipe in nc, curl -N, kcat, mosquitto_sub ...)
              · an http(s):// URL polled every cycle (JSON list/object or JSON lines; de-duplicated).
    Formats : JSON / JSON lines / arrays, SSE 'data:' lines, 'topic {json}' (MQTT -v), CSV with header,
              key=value pairs, plain log lines (kept local: shown in the proof panel, never sent).
    """

    def __init__(self, spec: str, mapping: dict, default_host: str, from_start: bool = False,
                 headers: dict | None = None):
        self.spec, self.mapping, self.default_host = spec, mapping, default_host
        self.q: collections.deque = collections.deque(maxlen=200_000)
        self.csv_header: list[str] | None = None
        self.lines = self.records = self.metric_records = 0
        self.hosts: set[str] = set()
        self.missing_reported: set[str] = set()
        self.notes: list[str] = []
        self.ts_fallback_noted = False
        self.eof = False
        if spec in ("-", "stdin"):
            self.kind = "stdin"
            threading.Thread(target=self._read_stdin, daemon=True).start()
        elif spec.startswith(("http://", "https://")):
            self.kind, self.http = "http", requests.Session()   # separate session: never send our SaaS token
            self.http.headers.update(headers or {})
            self.seen: collections.deque = collections.deque(maxlen=20_000)
            self.seen_set: set = set()
        else:
            self.kind, self.path = "file", spec[5:] if spec.startswith("file:") else spec
            threading.Thread(target=self._tail, args=(from_start,), daemon=True).start()

    def describe(self) -> str:
        if self.kind == "stdin":
            return "stdin (piped stream)"
        return f"polling {self.spec}" if self.kind == "http" else f"tailing {self.path}"

    # readers -------------------------------------------------------------
    def _read_stdin(self) -> None:
        for line in sys.stdin:
            self.q.append(line)
        self.eof = True

    def _tail(self, from_start: bool) -> None:
        fh, ino, partial = None, None, ""
        while True:
            try:
                if fh is None:
                    fh = open(self.path, "r", encoding="utf-8", errors="replace")
                    ino = os.fstat(fh.fileno()).st_ino
                    if not from_start:
                        fh.seek(0, os.SEEK_END)
                    from_start = True                 # a rotated-in file is read from its start
                line = fh.readline()
                if line:
                    if line.endswith("\n"):
                        self.q.append(partial + line)
                        partial = ""
                    else:
                        partial += line
                    continue
                time.sleep(0.2)
                st = os.stat(self.path)
                if st.st_ino != ino or st.st_size < fh.tell():
                    fh.close()
                    fh = None
            except OSError:
                if fh:
                    fh.close()
                fh = None
                time.sleep(1)

    def _poll(self) -> None:
        try:
            r = self.http.get(self.spec, timeout=(5, 10))
            r.raise_for_status()
        except requests.RequestException as exc:
            self.notes.append(f"stream poll failed: {type(exc).__name__}")
            return
        try:
            body = r.json()
            items = body if isinstance(body, list) else next(
                (body[k] for k in ("records", "data", "items", "events", "metrics", "results")
                 if isinstance(body, dict) and isinstance(body.get(k), list)), [body])
            lines = [json.dumps(i, sort_keys=True) for i in items]
        except ValueError:
            lines = r.text.splitlines()
        ts_keys = set(ALIASES["timestamp"])
        for line in lines:
            try:                                      # only timestamped records can be repeats; a snapshot
                rec = json.loads(line)                # endpoint without timestamps is fresh on every poll
                stamped = isinstance(rec, dict) and any(_nk(k) in ts_keys for k in _flatten(rec))
            except ValueError:
                stamped = False
            if not stamped:
                self.q.append(line)
                continue
            if line in self.seen_set:                 # repeated timestamped record: already ingested
                continue
            if len(self.seen) == self.seen.maxlen:
                self.seen_set.discard(self.seen[0])
            self.seen.append(line)
            self.seen_set.add(line)
            self.q.append(line)

    # parsing -------------------------------------------------------------
    def _parse(self, line: str) -> list[dict]:
        s = line.strip()
        if s.startswith("data:"):                     # server-sent events
            s = s[5:].strip()
        if not s.startswith(("{", "[")) and "{" in s and s.endswith("}"):
            s = s[s.index("{"):]                      # 'topic {json}' (mosquitto_sub -v)
        if s.startswith(("{", "[")):
            try:
                obj = json.loads(s)
                if isinstance(obj, dict):
                    return [_flatten(obj)]
                if isinstance(obj, list):
                    return [_flatten(o) for o in obj if isinstance(o, dict)]
            except ValueError:
                pass
        if "," in s:
            cells = next(csv.reader([s]))
            known = {a for v in ALIASES.values() for a in v}
            if self.csv_header is None and len(cells) >= 3 and \
                    all(re.fullmatch(r"[A-Za-z_@][\w .@-]*", c.strip()) for c in cells) and \
                    sum(_nk(c) in known for c in cells) >= 2:
                self.csv_header = [c.strip() for c in cells]
                return []
            if self.csv_header and len(cells) == len(self.csv_header):
                return [dict(zip(self.csv_header, (c.strip() for c in cells)))]
        kv = {k: v.strip("\"'") for k, v in KV_RE.findall(s)}
        return [kv] if kv else []

    # aggregation ---------------------------------------------------------
    def collect(self) -> tuple[list[dict], list[str]]:
        if self.kind == "http":
            self._poll()
        lines = []
        while self.q:
            lines.append(self.q.popleft())
        now = time.time()
        groups: dict[str, dict] = {}
        raw: list[str] = []

        def group(sid: str) -> dict:
            return groups.setdefault(sid, {"vals": {m: [] for m in STREAM_METRICS}, "ts": [], "disk": [],
                                           "fails": 0, "fails_known": False})

        for line in lines:
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            self.lines += 1
            raw.append(line)
            recs = self._parse(line)
            counted, line_host = False, None
            for rec in recs:
                self.records += 1
                n = normalize_record(rec, self.mapping)
                host = n["host"] or self.default_host
                sid = re.sub(r"[^A-Za-z0-9._:-]", "-", f"{n['tenant']}:{host}" if n["tenant"] else host)[:64]
                g = group(sid)
                line_host = line_host or sid
                if "failed_logins" in n["optional"]:             # the stream reports a count: trust it
                    g["fails"] += int(n["optional"]["failed_logins"])
                    g["fails_known"] = counted = True
                elif n["message"] is not None:                   # otherwise count failure lines locally
                    g["fails"] += 1 if FAILED_LOGIN_RE.search(n["message"]) else 0
                    g["fails_known"] = counted = True
                if "disk_usage" in n["optional"]:
                    g["disk"].append(n["optional"]["disk_usage"])
                if not n["metrics"]:
                    continue                          # log-only record: its text stays on this node
                self.metric_records += 1
                for m, x in n["metrics"].items():
                    g["vals"][m].append(x)
                g["ts"].append(n["ts"] or now)
            if not counted and FAILED_LOGIN_RE.search(line):     # plain / key=value log text
                g = group(line_host or self.default_host)
                g["fails"] += 1
                g["fails_known"] = True
        events = []
        for sid, g in groups.items():
            if not g["ts"]:
                continue                              # no metrics for this host in this window: nothing to send
            self.hosts.add(sid)
            vals = {}
            for m in STREAM_METRICS:
                xs = g["vals"][m]
                if not xs and m not in self.missing_reported:
                    self.missing_reported.add(m)
                    self.notes.append(f"stream has no field for {m} (sent as 0) - map one with --map {m}=<field>")
                vals[m] = (max(xs) if m == "packet_loss" else sum(xs) / len(xs)) if xs else 0.0
            ts = max(g["ts"])
            if abs(ts - now) > 300:                   # recorded dataset or skewed source clock
                if not self.ts_fallback_noted:
                    self.ts_fallback_noted = True
                    self.notes.append(f"stream timestamps are {ts - now:+.0f}s from this clock - "
                                      "using receive time for real-time measurement")
                ts = now
            events.append({
                "event_id": uuid.uuid4().hex, "server_id": sid,
                "cpu_usage": round(vals["cpu_usage"], 1), "memory_usage": round(vals["memory_usage"], 1),
                "bandwidth_mbps": round(vals["bandwidth_mbps"], 3), "latency_ms": round(vals["latency_ms"], 2),
                "packet_loss": round(vals["packet_loss"], 1),
                "health": local_health(vals["cpu_usage"], vals["memory_usage"], vals["latency_ms"],
                                       vals["packet_loss"]),
                "timestamp": datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds")
                                     .replace("+00:00", "Z"),
            })
            if g["disk"]:
                events[-1]["disk_usage"] = round(sum(g["disk"]) / len(g["disk"]), 1)
            if g["fails_known"]:
                events[-1]["failed_logins"] = g["fails"]
        return sorted(events, key=lambda e: e["server_id"]), raw

    def pop_notes(self) -> list[str]:
        notes, self.notes = self.notes, []
        return notes


def parse_map(spec: str | None) -> dict:
    mapping = {}
    for part in filter(None, (spec or "").split(",")):
        field, _, src = part.partition("=")
        if field.strip() not in ALIASES or not src.strip():
            sys.exit(f"--map: use <field>=<stream field>, field one of {sorted(ALIASES)}")
        mapping[field.strip()] = _nk(src)
    return mapping


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
    ap.add_argument("--chaos", choices=["cpu_loss", "latency", "memory", "bandwidth", "disk", "bruteforce"],
                    help="synthetically perturb metrics to demo correlated anomalies")
    ap.add_argument("--chaos-after", type=int, default=4, help="cycles of normal data before chaos starts")
    ap.add_argument("--probe", choices=["auto", "tcp", "http"], default="auto",
                    help="latency/loss method: tcp handshakes, https round trips, or auto (default)")
    ap.add_argument("--source", default="local",
                    help="telemetry source: 'local' (this PC, default) or the organiser stream: a file path, "
                         "'-' for stdin (pipe nc / curl -N / kcat / mosquitto_sub), or an http(s):// URL to poll")
    ap.add_argument("--map", help="field mapping for the stream, e.g. 'cpu_usage=cpu.pct,server_id=hostname'")
    ap.add_argument("--from-start", action="store_true", help="file source: read from the beginning, not the end")
    ap.add_argument("--source-header", action="append", default=[],
                    help="HTTP header for a URL source, e.g. 'Authorization: Bearer abc' (repeatable)")
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
    shipper = Shipper(url, args.token, args.buffer)
    stream = None
    if args.source != "local":
        headers = dict(h.split(":", 1) for h in args.source_header if ":" in h)
        stream = StreamSource(args.source, parse_map(args.map), args.server_id or "stream-node",
                              args.from_start, {k.strip(): v.strip() for k, v in headers.items()})
    else:
        sampler, logs = MetricsSampler(), LogSource(args.log_file, args.demo)
        prober = Prober(url, shipper.session, args.probe)

    print(f"{st.B}Smart Observability · Tier-1 Edge Collector{st.X}")
    if stream:
        print(f"  source     : organiser stream - {stream.describe()} (format auto-detected)")
        print(f"  nodes      : one per host in the stream (tenant:host when a tenant field exists)")
        print(f"  target     : {url}\n  window     : {args.interval:g}s aggregation per host")
    else:
        print(f"  node       : {server_id}\n  target     : {url}\n  log source : {logs.describe()}")
        print(f"  probe      : {prober.describe()}")
    print(f"  metrics    : {'from stream fields' if stream else ('psutil' if psutil else 'stdlib (/proc or Win32)')}\n  buffer     : "
          f"{os.path.abspath(args.buffer)} ({len(shipper.buffer)} pending from previous run)")
    if args.chaos:
        print(f"  {st.Y}CHAOS MODE '{args.chaos}' after cycle {args.chaos_after}: metrics synthetically perturbed{st.X}")

    cycle, was_offline = 0, len(shipper.buffer) > 0
    try:
        while True:
            cycle += 1
            started = time.monotonic()
            if stream:
                events, raw = stream.collect()
                raw = raw[-max(args.log_lines * 2, 6):]   # proof panel shows the newest raw stream lines
                if args.demo:
                    raw += random.sample(DEMO_LOG_LINES, 2)
                for note in stream.pop_notes():
                    print(f"{st.Y}! {note}{st.X}")
            else:
                cpu, mem, bw = sampler.sample()
                lat, loss = prober.measure()
                disk = disk_usage_pct()
                raw, failed = logs.read(args.log_lines)
                measured_loss = loss
                if args.chaos and cycle > args.chaos_after:
                    cpu, mem, bw, lat, loss = apply_chaos(args.chaos, cpu, mem, bw, lat, loss)
                    if args.chaos == "disk":
                        disk = chaos_disk(disk, cycle - args.chaos_after)
                    elif args.chaos == "bruteforce":
                        failed = (failed or 0) + random.randint(25, 60)
                events = [{   # allow-listed, numeric-only metadata; event_id = idempotency key fixed at capture
                    "event_id": uuid.uuid4().hex, "server_id": server_id,
                    "cpu_usage": round(cpu, 1), "memory_usage": round(mem, 1), "bandwidth_mbps": round(bw, 3),
                    "latency_ms": round(lat, 2), "packet_loss": round(loss, 1),
                    "health": local_health(cpu, mem, lat, loss), "timestamp": utc_now_iso(),
                }]
                if disk is not None:
                    events[0]["disk_usage"] = round(disk, 1)
                if failed is not None:
                    events[0]["failed_logins"] = int(failed)
                for note in logs.notes:
                    print(f"{st.Y}! {note}{st.X}")
                logs.notes.clear()
            if shipper.compat:                         # SaaS predates the optional fields: keep proof == wire
                for e in events:
                    for f in OPTIONAL_SEND_FIELDS:
                        e.pop(f, None)
            scrubbed, counts = [], {}
            for line in raw:
                clean, c = scrub(line)
                scrubbed.append(clean)
                for k, v in c.items():
                    counts[k] = counts.get(k, 0) + v
            wires = [wire_bytes(e) for e in events]
            _, leaks = scrub(b"\n".join(wires).decode("utf-8"))      # DLP gate on the exact egress bytes
            render_panel(st, cycle, url, raw, scrubbed, counts, events, wires, leaks,
                         "organiser stream" if stream else "system log")
            if leaks:
                print(f"{st.R}✖ egress blocked by DLP gate - {len(events)} event(s) discarded{st.X}")
            elif not events and not len(shipper.buffer):
                print(f"{st.D}· no metric records this window{' (stream ended)' if stream and stream.eof else ''}{st.X}")
            else:
                shipper.buffer.extend(events)          # write-ahead: persisted before any network I/O
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
                    if stream:
                        print(f"{st.G}✔ delivered {sent} event(s) for {len(events)} host(s) this window "
                              f"| hosts seen: {len(stream.hosts)} | buffer: {res['remaining']} pending{st.X}")
                    else:
                        print(f"{st.G}✔ delivered -> {srv.get('status', 'ok')} (server health={srv.get('health', '?')})"
                              f" | buffer: {res['remaining']} pending{st.X}")
                if not stream:
                    note = prober.observe(measured_loss, not res["error"] and sent > 0)
                    if note:
                        print(f"{st.Y}! {note}{st.X}")
                for note in res["notes"]:
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
