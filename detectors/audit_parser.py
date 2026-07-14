"""
Tail /var/log/audit/audit.log and parse auditd events for priv-esc rules.

Supported rule keys (configured via ``watch_keys`` in config):
  priv_esc_root    – CRITICAL  privilege escalation to uid 0
  sudoers_change   – HIGH      sudoers / sudoers.d write
  cron_change      – HIGH      cron file written
  suid_change      – HIGH      setuid/setgid bit change (chmod)
  capset_usage     – HIGH      capset() syscall (capability grant)
  uid_change       – MEDIUM    setuid/setreuid/setresuid call
  module_insertion – CRITICAL  init_module / finit_module (kernel module load)

The detector starts reading from EOF (skips historical events) and tails
the file in a background thread.  On daemon restart it starts fresh — no
stale re-alerts.  Each auditd event has a unique serial number that is
included in the finding's item_key, so the BaseDetector diff layer can
never suppress a genuinely new event.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from detectors.base import BaseDetector, Finding
from storage.db import Database

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------

DEFAULT_LOG_PATH = "/var/log/audit/audit.log"
DEFAULT_POLL_INTERVAL = 0.5  # seconds between tail reads
DEFAULT_REOPEN_INTERVAL = 5.0  # seconds to wait before reopening after rotation

# key → (severity, human-readable label)
DEFAULT_WATCH_KEYS: dict[str, tuple[str, str]] = {
    "priv_esc_root":    ("critical", "Privilege escalation to root"),
    "sudoers_change":   ("high",     "sudoers policy changed"),
    "cron_change":      ("high",     "Cron job file changed"),
    "suid_change":      ("high",     "SUID/SGID bit changed"),
    "capset_usage":     ("high",     "capset() syscall (capability grant)"),
    "uid_change":       ("medium",   "UID-change syscall"),
    "module_insertion": ("critical", "Kernel module insertion"),
}

# ---------------------------------------------------------------------------
# Auditd log line parsing
# ---------------------------------------------------------------------------

# Matches key="value"  or  key=bare_value (no spaces, no quotes needed)
_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
# msg=audit(1234567890.000:12345)
_SERIAL_RE = re.compile(r"audit\([\d.]+:(\d+)\)")


def _parse_kv(line: str) -> dict[str, str]:
    """Extract all key=value pairs from one auditd log line."""
    result: dict[str, str] = {}
    for m in _KV_RE.finditer(line):
        val = m.group(2)
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        result[m.group(1)] = val
    return result


def _serial(fields: dict[str, str]) -> str | None:
    """Return the numeric serial from a parsed fields dict (from 'msg')."""
    msg = fields.get("msg", "")
    m = _SERIAL_RE.search(msg)
    return m.group(1) if m else None


def _timestamp_from_msg(msg: str) -> str:
    """Parse ISO-8601 timestamp from msg=audit(ts.ms:serial)."""
    m = re.search(r"audit\(([\d.]+):\d+\)", msg)
    if m:
        try:
            ts = float(m.group(1))
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        except (ValueError, OSError):
            pass
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Event buffer
# ---------------------------------------------------------------------------

class _EventBuffer:
    """
    Accumulates auditd records (lines) that share the same serial number,
    then flushes them as a single merged field dict when the serial changes.
    """

    def __init__(self) -> None:
        self._serial: str | None = None
        self._lines: list[dict[str, str]] = []

    def feed(self, line: str) -> dict[str, str] | None:
        """
        Feed one log line.  Returns a merged field dict when a complete
        event is displaced (i.e. a new serial arrives), else None.
        """
        line = line.strip()
        if not line:
            return None

        fields = _parse_kv(line)
        # Preserve the raw 'type' field name — it appears before msg= in each line
        rec_type = fields.get("type", "")
        ser = _serial(fields)

        if ser is None:
            # Malformed line — ignore
            return None

        flushed: dict[str, str] | None = None
        if ser != self._serial and self._serial is not None:
            flushed = self._flush()

        if ser != self._serial:
            self._serial = ser
            self._lines = []

        # Prefix duplicate keys with their record type to avoid collision
        if rec_type and rec_type != "UNKNOWN":
            prefixed = {f"{rec_type}_{k}" if k in self._merged_keys() else k: v
                        for k, v in fields.items()}
        else:
            prefixed = fields

        self._lines.append(prefixed)
        return flushed

    def flush_final(self) -> dict[str, str] | None:
        """Flush whatever is buffered (call on EOF / stop)."""
        if self._lines:
            return self._flush()
        return None

    def _flush(self) -> dict[str, str]:
        merged: dict[str, str] = {}
        for rec in self._lines:
            merged.update(rec)
        self._lines = []
        return merged

    def _merged_keys(self) -> set[str]:
        s: set[str] = set()
        for rec in self._lines:
            s.update(rec.keys())
        return s


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class AuditParserDetector(BaseDetector):
    """
    Background-thread log tailer + auditd event parser.

    Lifecycle:
        start()   → open log at EOF, launch tail thread
        scan()    → drain pending findings (called by watch_drain_loop)
        stop()    → signal thread, join

    Baseline strategy:
        Each finding's item_key includes the event serial, so no two events
        share a hash.  upsert_baseline_entries (merge, no prune) is used —
        we never want to "forget" an event we already alerted on.
    """

    name = "audit_parser"

    def __init__(self, db: Database, config: dict[str, Any] | None = None) -> None:
        super().__init__(db, config)
        self.log_path = Path(self.config.get("log_path", DEFAULT_LOG_PATH))
        self.poll_interval = float(
            self.config.get("poll_interval_seconds", DEFAULT_POLL_INTERVAL)
        )
        self.reopen_interval = float(
            self.config.get("reopen_interval_seconds", DEFAULT_REOPEN_INTERVAL)
        )

        # Merge user-supplied key overrides with defaults
        user_keys: dict[str, Any] = self.config.get("watch_keys") or {}
        self.watch_keys: dict[str, tuple[str, str]] = dict(DEFAULT_WATCH_KEYS)
        for k, v in user_keys.items():
            if isinstance(v, dict):
                sev = str(v.get("severity", "high"))
                label = str(v.get("label", k))
            else:
                sev = str(v)
                label = k
            self.watch_keys[k] = (sev, label)

        self._pending: list[Finding] = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = False

    # ------------------------------------------------------------------
    # BaseDetector interface
    # ------------------------------------------------------------------

    def scan(self) -> list[Finding]:
        """Drain and return findings queued by the tail thread."""
        if not self._started:
            self.start()
        with self._lock:
            found = list(self._pending)
            self._pending.clear()
        return found

    def save_baseline(self, findings: list[Finding]) -> None:
        """Merge-only: never prune audit event hashes (they're historical)."""
        if not findings:
            return
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (self.name, f.item_hash(), now, now, f.item_key, f.baseline_payload())
            for f in findings
        ]
        self.db.upsert_baseline_entries(rows)

    def start(self) -> None:
        if self._started:
            return
        if not self.log_path.exists():
            logger.warning(
                "audit_parser: log file not found: %s "
                "(auditd not running or path wrong)",
                self.log_path,
            )
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._tail_loop,
            name="audit_parser_tail",
            daemon=True,
        )
        self._thread.start()
        self._started = True
        logger.info("audit_parser: tailing %s", self.log_path)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None
        self._started = False

    # ------------------------------------------------------------------
    # Tail loop (background thread)
    # ------------------------------------------------------------------

    def _tail_loop(self) -> None:
        buf = _EventBuffer()
        fh = None
        inode: int | None = None

        try:
            fh, inode = self._open_at_eof()
        except OSError as exc:
            logger.warning("audit_parser: cannot open %s: %s", self.log_path, exc)

        while not self._stop_event.is_set():
            # --- detect log rotation (inode changed / file truncated) ---
            if fh is not None:
                try:
                    stat = self.log_path.stat()
                    if stat.st_ino != inode or stat.st_size < fh.tell():
                        logger.info("audit_parser: log rotated, reopening")
                        fh.close()
                        fh = None
                except OSError:
                    fh.close()
                    fh = None

            # --- reopen after rotation or initial failure ---
            if fh is None:
                try:
                    fh, inode = self._open_at_eof()
                except OSError:
                    self._stop_event.wait(self.reopen_interval)
                    continue

            # --- read available lines ---
            try:
                while True:
                    line = fh.readline()
                    if not line:
                        break
                    completed = buf.feed(line)
                    if completed:
                        self._process_event(completed)
            except OSError as exc:
                logger.warning("audit_parser: read error: %s", exc)
                fh.close()
                fh = None

            self._stop_event.wait(self.poll_interval)

        # Flush partial event on shutdown
        if fh is not None:
            final = buf.flush_final()
            if final:
                self._process_event(final)
            fh.close()

    def _open_at_eof(self):
        """Open the log file and seek to end.  Returns (file_obj, inode)."""
        path = str(self.log_path)
        fh = open(path, "r", encoding="utf-8", errors="replace")  # noqa: WPS515
        fh.seek(0, 2)  # SEEK_END
        inode = self.log_path.stat().st_ino
        return fh, inode

    # ------------------------------------------------------------------
    # Event processing
    # ------------------------------------------------------------------

    def _process_event(self, fields: dict[str, str]) -> None:
        """
        Check whether this merged event matches a watched key; if so,
        queue a Finding.
        """
        # auditd records the rule key in key= (or SYSCALL_key=)
        rule_key = (
            fields.get("key")
            or fields.get("SYSCALL_key")
            or fields.get("KERN_key")
            or ""
        )
        # Strip surrounding quotes that some kernel versions leave in
        rule_key = rule_key.strip('"')

        if not rule_key or rule_key not in self.watch_keys:
            return

        severity, label = self.watch_keys[rule_key]

        ser = (
            fields.get("msg")
            and _SERIAL_RE.search(fields["msg"])
            and _SERIAL_RE.search(fields["msg"]).group(1)  # type: ignore[union-attr]
        ) or fields.get("msg", "0")

        ts = _timestamp_from_msg(fields.get("msg", ""))

        # Build a compact but informative detail dict
        detail_fields = (
            "type", "syscall", "pid", "uid", "auid",
            "comm", "exe", "name", "res", "success",
        )
        details: dict[str, Any] = {
            "key": rule_key,
            "serial": ser,
            "timestamp": ts,
        }
        for field in detail_fields:
            for prefix in ("", "SYSCALL_", "PATH_", "KERN_"):
                val = fields.get(f"{prefix}{field}")
                if val is not None:
                    details[field] = val
                    break

        exe = details.get("exe") or details.get("comm") or "unknown"
        uid = details.get("uid", "?")

        finding = Finding(
            detector_name=self.name,
            severity=severity,
            message=f"{label} — uid={uid} exe={exe}",
            # serial makes every real event unique → diff never suppresses it
            item_key=f"{rule_key}:{ser}",
            details=details,
        )
        with self._lock:
            self._pending.append(finding)
        logger.debug(
            "audit_parser: queued finding key=%s serial=%s severity=%s",
            rule_key, ser, severity,
        )
