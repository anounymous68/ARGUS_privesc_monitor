"""Tests for watchdog-based sudoers/cron content-change detectors."""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from detectors.content_watch import ContentWatchDetector, unified_content_diff
from detectors.cron_check import CronCheckDetector
from detectors.sudoers_check import SudoersCheckDetector
from storage.db import Database


class TestUnifiedDiff(unittest.TestCase):
    def test_diff_contains_old_and_new(self) -> None:
        diff = unified_content_diff("/etc/sudoers", "root ALL=(ALL) ALL\n", "alice ALL=(ALL) NOPASSWD: ALL\n")
        self.assertIn("alice", diff)
        self.assertIn("root", diff)
        self.assertIn("---", diff)


class _WatchTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.db = Database(self.root / "test.db")

    def tearDown(self) -> None:
        if hasattr(self, "det") and self.det is not None:
            self.det.stop()
        self.db.close()
        self._tmp.cleanup()

    def _wait_for_findings(self, det: ContentWatchDetector, *, timeout: float = 3.0) -> list:
        deadline = time.time() + timeout
        while time.time() < deadline:
            findings = det.run_once()
            if findings:
                return findings
            time.sleep(0.05)
        return []


class TestSudoersCheckDetector(_WatchTestBase):
    def test_modify_emits_high_finding_with_diff(self) -> None:
        etc = self.root / "etc"
        sudoers_d = etc / "sudoers.d"
        sudoers_d.mkdir(parents=True)
        sudoers = etc / "sudoers"
        sudoers.write_text("root ALL=(ALL) ALL\n", encoding="utf-8")

        self.det = SudoersCheckDetector(
            self.db,
            config={
                "watch_files": [str(sudoers)],
                "watch_dirs": [str(sudoers_d)],
            },
        )
        self.det.start()
        time.sleep(0.2)  # let observer attach

        sudoers.write_text(
            "root ALL=(ALL) ALL\nalice ALL=(ALL) NOPASSWD: ALL\n",
            encoding="utf-8",
        )
        findings = self._wait_for_findings(self.det)
        self.assertTrue(findings, "expected watchdog finding on sudoers change")
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("diff", findings[0].details)
        self.assertIn("alice", findings[0].details["diff"])
        self.assertEqual(findings[0].detector_name, "sudoers_check")

        # Unchanged content must not re-alert via baseline / empty drain
        self.assertEqual(self.det.run_once(), [])

    def test_new_dropin_file(self) -> None:
        etc = self.root / "etc"
        sudoers_d = etc / "sudoers.d"
        sudoers_d.mkdir(parents=True)
        sudoers = etc / "sudoers"
        sudoers.write_text("root ALL=(ALL) ALL\n", encoding="utf-8")

        self.det = SudoersCheckDetector(
            self.db,
            config={
                "watch_files": [str(sudoers)],
                "watch_dirs": [str(sudoers_d)],
            },
        )
        self.det.start()
        time.sleep(0.2)

        dropin = sudoers_d / "99-backdoor"
        dropin.write_text("bob ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")
        findings = self._wait_for_findings(self.det)
        self.assertTrue(findings)
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("bob", findings[0].details["diff"])


class TestCronCheckDetector(_WatchTestBase):
    def test_crontab_and_spool_changes(self) -> None:
        etc = self.root / "etc"
        cron_d = etc / "cron.d"
        cron_d.mkdir(parents=True)
        crontab = etc / "crontab"
        crontab.write_text("SHELL=/bin/sh\n", encoding="utf-8")

        spool = self.root / "var" / "spool" / "cron" / "crontabs"
        spool.mkdir(parents=True)
        user_cron = spool / "root"
        user_cron.write_text("0 * * * * /usr/bin/true\n", encoding="utf-8")

        self.det = CronCheckDetector(
            self.db,
            config={
                "watch_files": [str(crontab)],
                "watch_dirs": [str(cron_d), str(spool.parent)],
                "recursive": True,
            },
        )
        self.det.start()
        time.sleep(0.2)

        crontab.write_text(
            "SHELL=/bin/sh\n* * * * * root /tmp/evil\n",
            encoding="utf-8",
        )
        findings = self._wait_for_findings(self.det)
        self.assertTrue(findings, "expected finding for /etc/crontab change")
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("/tmp/evil", findings[0].details["diff"])
        self.assertEqual(findings[0].detector_name, "cron_check")


class TestContentWatchBaselineMerge(unittest.TestCase):
    def test_empty_scan_does_not_wipe_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "t.db")
            root = Path(tmp) / "w"
            root.mkdir()
            target = root / "file"
            target.write_text("a\n", encoding="utf-8")

            class _Tiny(ContentWatchDetector):
                name = "tiny"

            det = _Tiny(
                db,
                config={"watch_files": [str(target)], "watch_dirs": []},
            )
            det.start()
            time.sleep(0.15)
            target.write_text("b\n", encoding="utf-8")

            deadline = time.time() + 3
            novel = []
            while time.time() < deadline:
                novel = det.run_once()
                if novel:
                    break
                time.sleep(0.05)
            self.assertTrue(novel)
            hashes_after = db.get_baseline_hashes("tiny")
            self.assertTrue(hashes_after)

            # Empty drain must keep baseline entries
            self.assertEqual(det.run_once(), [])
            self.assertEqual(db.get_baseline_hashes("tiny"), hashes_after)

            det.stop()
            db.close()


if __name__ == "__main__":
    unittest.main()
