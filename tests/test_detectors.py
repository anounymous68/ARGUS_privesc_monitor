"""Skeleton tests for detector baseline/diff behavior. Concrete detectors later."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from detectors.base import BaseDetector, Finding
from storage.db import Database


class StubDetector(BaseDetector):
    name = "stub"

    def __init__(self, db: Database, findings: list[Finding] | None = None) -> None:
        super().__init__(db)
        self._findings = findings or []

    def scan(self) -> list[Finding]:
        return list(self._findings)


def _finding(key: str, message: str = "test") -> Finding:
    return Finding(
        detector_name="stub",
        severity="medium",
        message=message,
        item_key=key,
    )


class TestBaselineDiff(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self._tmp.name) / "test.db")

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def test_diff_returns_only_new_hashes(self) -> None:
        a, b, c = _finding("a"), _finding("b"), _finding("c")
        old = {a.item_hash(), b.item_hash()}
        novel = StubDetector(self.db).diff(old, [a, b, c])
        self.assertEqual([f.item_key for f in novel], ["c"])

    def test_run_once_does_not_realert_unchanged(self) -> None:
        findings = [_finding("suid-/usr/bin/pass"), _finding("writable-/etc")]
        det = StubDetector(self.db, findings)
        first = det.run_once()
        self.assertEqual(len(first), 2)

        second = det.run_once()
        self.assertEqual(second, [])

    def test_run_once_alerts_only_newly_appeared(self) -> None:
        det = StubDetector(self.db, [_finding("one")])
        self.assertEqual(len(det.run_once()), 1)

        det._findings = [_finding("one"), _finding("two")]
        novel = det.run_once()
        self.assertEqual([f.item_key for f in novel], ["two"])


if __name__ == "__main__":
    unittest.main()
