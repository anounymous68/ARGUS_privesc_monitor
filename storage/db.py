"""SQLite storage for baselines and alert history."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable, Sequence


SCHEMA = """
CREATE TABLE IF NOT EXISTS baselines (
    detector_name TEXT NOT NULL,
    item_hash     TEXT NOT NULL,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    PRIMARY KEY (detector_name, item_hash)
);

CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT NOT NULL,
    detector_name TEXT NOT NULL,
    severity      TEXT NOT NULL,
    message       TEXT NOT NULL,
    acknowledged  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_baselines_detector
    ON baselines (detector_name);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
    ON alerts (timestamp);
"""


class Database:
    """Thin SQLite wrapper used by detectors and (later) alert plumbing."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def get_baseline_hashes(self, detector_name: str) -> set[str]:
        cur = self._conn.execute(
            "SELECT item_hash FROM baselines WHERE detector_name = ?",
            (detector_name,),
        )
        return {row["item_hash"] for row in cur.fetchall()}

    def upsert_baselines(
        self, rows: Sequence[tuple[str, str, str, str]]
    ) -> None:
        """
        rows: (detector_name, item_hash, first_seen, last_seen)

        On conflict: keep original first_seen, refresh last_seen.
        """
        self._conn.executemany(
            """
            INSERT INTO baselines (detector_name, item_hash, first_seen, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(detector_name, item_hash) DO UPDATE SET
                last_seen = excluded.last_seen
            """,
            rows,
        )
        self._conn.commit()

    def insert_alert(
        self,
        timestamp: str,
        detector_name: str,
        severity: str,
        message: str,
        acknowledged: bool = False,
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO alerts (timestamp, detector_name, severity, message, acknowledged)
            VALUES (?, ?, ?, ?, ?)
            """,
            (timestamp, detector_name, severity, message, int(acknowledged)),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def acknowledge_alert(self, alert_id: int) -> None:
        self._conn.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ?",
            (alert_id,),
        )
        self._conn.commit()

    def recent_alerts(self, limit: int = 50) -> list[sqlite3.Row]:
        cur = self._conn.execute(
            """
            SELECT id, timestamp, detector_name, severity, message, acknowledged
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        return list(cur.fetchall())
