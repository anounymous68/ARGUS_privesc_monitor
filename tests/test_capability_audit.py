"""Tests for capability_check and audit_parser detectors."""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from detectors.audit_parser import (
    AuditParserDetector,
    _EventBuffer,
    _parse_kv,
    _serial,
)
from detectors.capability_check import CapabilityCheckDetector
from storage.db import Database


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _db(tmp: str) -> Database:
    return Database(Path(tmp) / "t.db")


# ---------------------------------------------------------------------------
# CapabilityCheckDetector tests
# ---------------------------------------------------------------------------

GETCAP_OUTPUT = """\
/usr/bin/ping = cap_net_raw+ep
/usr/bin/python3.11 = cap_setuid+ep
"""


class TestCapabilityCheckDetector(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = _db(self._tmp.name)
        self.det = CapabilityCheckDetector(
            self.db, config={"scan_roots": ["/usr"], "timeout_seconds": 10}
        )

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def _patch_getcap(self, stdout: str, returncode: int = 0):
        result = mock.Mock()
        result.stdout = stdout
        result.stderr = ""
        result.returncode = returncode
        return mock.patch("subprocess.run", return_value=result)

    def test_scan_parses_getcap_output(self) -> None:
        with self._patch_getcap(GETCAP_OUTPUT):
            findings = self.det.scan()
        self.assertEqual(len(findings), 2)
        keys = {f.item_key for f in findings}
        self.assertIn("cap:/usr/bin/ping:cap_net_raw+ep", keys)
        self.assertIn("cap:/usr/bin/python3.11:cap_setuid+ep", keys)
        self.assertTrue(all(f.severity == "high" for f in findings))

    def test_no_realert_on_unchanged(self) -> None:
        with self._patch_getcap(GETCAP_OUTPUT):
            first = self.det.run_once()
        self.assertEqual(len(first), 2)
        with self._patch_getcap(GETCAP_OUTPUT):
            second = self.det.run_once()
        self.assertEqual(second, [])

    def test_new_cap_alerts_high(self) -> None:
        with self._patch_getcap(GETCAP_OUTPUT):
            self.det.run_once()
        extended = GETCAP_OUTPUT + "/usr/bin/vim = cap_dac_override+ep\n"
        with self._patch_getcap(extended):
            novel = self.det.run_once()
        highs = [f for f in novel if f.severity == "high"]
        self.assertEqual(len(highs), 1)
        self.assertIn("vim", highs[0].details["path"])

    def test_removed_cap_alerts_low(self) -> None:
        with self._patch_getcap(GETCAP_OUTPUT):
            self.det.run_once()
        shrunk = "/usr/bin/ping = cap_net_raw+ep\n"
        with self._patch_getcap(shrunk):
            delta = self.det.run_once()
        lows = [f for f in delta if f.severity == "low"]
        self.assertEqual(len(lows), 1)
        self.assertIn("python3.11", lows[0].message)

    def test_getcap_not_found_returns_empty(self) -> None:
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            findings = self.det.scan()
        self.assertEqual(findings, [])

    def test_getcap_timeout_returns_empty(self) -> None:
        import subprocess
        with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("getcap", 10)):
            findings = self.det.scan()
        self.assertEqual(findings, [])

    def test_changed_caps_on_same_path_alerts(self) -> None:
        with self._patch_getcap("/usr/bin/ping = cap_net_raw+ep\n"):
            self.det.run_once()
        with self._patch_getcap("/usr/bin/ping = cap_net_raw+cap_net_admin+ep\n"):
            delta = self.det.run_once()
        highs = [f for f in delta if f.severity == "high"]
        self.assertEqual(len(highs), 1)
        self.assertIn("cap_net_admin", highs[0].details["caps"])


# ---------------------------------------------------------------------------
# _EventBuffer + _parse_kv unit tests
# ---------------------------------------------------------------------------

class TestAuditEventBuffer(unittest.TestCase):
    def test_parse_kv_bare_and_quoted(self) -> None:
        line = 'type=SYSCALL msg=audit(1000.0:42): key="priv_esc_root" uid=1000'
        fields = _parse_kv(line)
        self.assertEqual(fields["type"], "SYSCALL")
        self.assertEqual(fields["key"], "priv_esc_root")
        self.assertEqual(fields["uid"], "1000")

    def test_serial_extracted(self) -> None:
        fields = _parse_kv('type=SYSCALL msg=audit(123.456:789): uid=0')
        self.assertEqual(_serial(fields), "789")

    def test_buffer_flushes_on_new_serial(self) -> None:
        buf = _EventBuffer()
        line1 = 'type=SYSCALL msg=audit(1.0:1): key="uid_change" uid=1000'
        line2 = 'type=EXECVE msg=audit(1.0:1): argc=1 a0="sudo"'
        line3 = 'type=SYSCALL msg=audit(2.0:2): key="suid_change" uid=0'

        self.assertIsNone(buf.feed(line1))
        self.assertIsNone(buf.feed(line2))
        flushed = buf.feed(line3)
        self.assertIsNotNone(flushed)
        # merged fields should contain both records' keys
        self.assertIn("key", flushed)  # type: ignore[arg-type]

    def test_buffer_flush_final(self) -> None:
        buf = _EventBuffer()
        buf.feed('type=SYSCALL msg=audit(3.0:99): key="module_insertion" uid=0')
        final = buf.flush_final()
        self.assertIsNotNone(final)
        self.assertEqual(final["key"], "module_insertion")  # type: ignore[index]


# ---------------------------------------------------------------------------
# AuditParserDetector integration tests
# ---------------------------------------------------------------------------

def _audit_line(serial: int, key: str, uid: int = 1000) -> str:
    ts = 1_700_000_000.0 + serial
    return (
        f'type=SYSCALL msg=audit({ts:.3f}:{serial}): arch=c000003e syscall=59 '
        f'success=yes exit=0 a0=1 a1=2 a2=3 a3=4 items=1 ppid=100 pid=200 '
        f'auid={uid} uid={uid} gid={uid} euid=0 suid=0 fsuid=0 egid={uid} '
        f'sgid={uid} fsgid={uid} tty=pts0 ses=1 comm="sudo" exe="/usr/bin/sudo" '
        f'key="{key}"\n'
    )


class TestAuditParserDetector(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.db = _db(self._tmp.name)
        self.log = self.tmp / "audit.log"
        self.log.write_text("", encoding="utf-8")

    def tearDown(self) -> None:
        if hasattr(self, "det"):
            self.det.stop()
        self.db.close()
        self._tmp.cleanup()

    def _make_det(self, **extra_cfg) -> AuditParserDetector:
        cfg = {
            "log_path": str(self.log),
            "poll_interval_seconds": 0.05,
            **extra_cfg,
        }
        det = AuditParserDetector(self.db, config=cfg)
        det.start()
        time.sleep(0.15)  # let thread reach EOF
        return det

    def _wait_for_findings(self, det, *, timeout=3.0, count=1) -> list:
        deadline = time.time() + timeout
        while time.time() < deadline:
            found = det.run_once()
            if len(found) >= count:
                return found
            time.sleep(0.05)
        return []

    def test_matching_key_produces_finding(self) -> None:
        self.det = self._make_det()
        self.log.write_text(_audit_line(1, "priv_esc_root", uid=0), encoding="utf-8")
        # Write a second event to flush the buffer
        with self.log.open("a", encoding="utf-8") as f:
            f.write(_audit_line(2, "uid_change", uid=1000))
        findings = self._wait_for_findings(self.det, count=1)
        sev = {f.severity for f in findings}
        self.assertIn("critical", sev)
        keys = {f.details.get("key") for f in findings}
        self.assertIn("priv_esc_root", keys)

    def test_unmatched_key_not_surfaced(self) -> None:
        self.det = self._make_det()
        with self.log.open("a", encoding="utf-8") as f:
            f.write(_audit_line(10, "some_other_key"))
            f.write(_audit_line(11, "irrelevant"))
        time.sleep(0.5)
        findings = self.det.run_once()
        self.assertEqual(findings, [])

    def test_severity_mapped_per_key(self) -> None:
        self.det = self._make_det()
        with self.log.open("a", encoding="utf-8") as f:
            f.write(_audit_line(20, "module_insertion", uid=0))
            f.write(_audit_line(21, "uid_change", uid=500))  # flushes previous
        findings = self._wait_for_findings(self.det, count=1)
        crits = [f for f in findings if f.severity == "critical"]
        self.assertTrue(crits, f"expected critical, got: {findings}")

    def test_each_serial_unique_no_dedup(self) -> None:
        self.det = self._make_det()
        with self.log.open("a", encoding="utf-8") as f:
            f.write(_audit_line(30, "suid_change"))
            f.write(_audit_line(31, "suid_change"))  # same key, new serial
            f.write(_audit_line(32, "capset_usage"))  # flushes 31
        findings = self._wait_for_findings(self.det, count=2)
        suid = [f for f in findings if f.details.get("key") == "suid_change"]
        self.assertGreaterEqual(len(suid), 2, "both events should alert")

    def test_save_baseline_merges_not_prunes(self) -> None:
        self.det = self._make_det()
        with self.log.open("a", encoding="utf-8") as f:
            f.write(_audit_line(40, "cron_change"))
            f.write(_audit_line(41, "sudoers_change"))  # flushes 40
        self._wait_for_findings(self.det, count=1)
        hashes_after = self.db.get_baseline_hashes("audit_parser")
        self.assertTrue(hashes_after)
        # Empty drain must not remove baseline entries
        self.det.run_once()
        self.assertEqual(self.db.get_baseline_hashes("audit_parser"), hashes_after)


if __name__ == "__main__":
    unittest.main()
