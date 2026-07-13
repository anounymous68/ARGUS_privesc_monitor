"""Shared watchdog-based file content change detection."""

from __future__ import annotations

import difflib
import hashlib
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from detectors.base import BaseDetector, Finding
from storage.db import Database

logger = logging.getLogger(__name__)

# Keep finding payloads / Telegram messages bounded
_MAX_DIFF_CHARS = 3500


def unified_content_diff(path: str, old: str, new: str) -> str:
    """Return a unified diff string for old → new file content."""
    diff = "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"{path} (old)",
            tofile=f"{path} (new)",
            lineterm="",
        )
    )
    if not diff:
        # Binary-ish or whitespace-only edge case — still surface a marker
        return f"(content changed; no textual diff for {path})"
    if len(diff) > _MAX_DIFF_CHARS:
        return (
            diff[: _MAX_DIFF_CHARS]
            + f"\n… diff truncated ({len(diff) - _MAX_DIFF_CHARS} more chars)"
        )
    return diff


class _ContentChangeHandler(FileSystemEventHandler):
    """Forwards relevant file events to ContentWatchDetector."""

    def __init__(self, detector: ContentWatchDetector) -> None:
        super().__init__()
        self._detector = detector

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._detector._handle_fs_event(event.src_path, event_type="created")

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._detector._handle_fs_event(event.src_path, event_type="modified")

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._detector._handle_fs_event(event.src_path, event_type="deleted")

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        # Treat as delete old + create/modify new
        self._detector._handle_fs_event(event.src_path, event_type="deleted")
        dest = getattr(event, "dest_path", None)
        if dest:
            self._detector._handle_fs_event(dest, event_type="created")


class ContentWatchDetector(BaseDetector):
    """
    Event-driven detector: watchdog watches paths; scan() drains findings.

    Unlike inventory detectors, an empty scan must NOT wipe the baseline —
    save_baseline merges event hashes only.
    """

    # Subclasses set defaults; config may override
    default_watch_files: tuple[str, ...] = ()
    default_watch_dirs: tuple[str, ...] = ()
    recursive_dirs: bool = True

    def __init__(self, db: Database, config: dict[str, Any] | None = None) -> None:
        super().__init__(db, config)
        files = self.config.get("watch_files") or list(self.default_watch_files)
        dirs = self.config.get("watch_dirs") or list(self.default_watch_dirs)
        self.watch_files: list[Path] = [Path(p) for p in files]
        self.watch_dirs: list[Path] = [Path(p) for p in dirs]
        self._recursive = bool(self.config.get("recursive", self.recursive_dirs))

        self._cache: dict[str, str] = {}
        self._pending: list[Finding] = []
        self._lock = threading.Lock()
        self._debounce: dict[str, threading.Timer] = {}
        self._debounce_seconds = float(self.config.get("debounce_seconds", 0.15))
        self._observer: Observer | None = None
        self._started = False

        # Paths we care about (exact files + anything under watch_dirs)
        self._watched_file_set = {str(p.resolve()) if p.exists() else str(p) for p in self.watch_files}

    def start(self) -> None:
        """Seed content cache and start the watchdog observer."""
        if self._started:
            return
        self._seed_cache()
        handler = _ContentChangeHandler(self)
        observer = Observer()

        # Watch parent dirs of individual files
        scheduled: set[str] = set()
        for file_path in self.watch_files:
            parent = file_path.parent
            key = str(parent)
            if key in scheduled:
                continue
            if not parent.is_dir():
                logger.warning("%s: parent not a directory: %s", self.name, parent)
                continue
            observer.schedule(handler, key, recursive=False)
            scheduled.add(key)
            logger.info("%s: watching file via %s (%s)", self.name, parent, file_path.name)

        for dir_path in self.watch_dirs:
            key = str(dir_path)
            if key in scheduled:
                continue
            if not dir_path.is_dir():
                logger.warning("%s: watch dir missing: %s", self.name, dir_path)
                continue
            observer.schedule(handler, key, recursive=self._recursive)
            scheduled.add(key)
            logger.info("%s: watching directory %s (recursive=%s)", self.name, dir_path, self._recursive)

        if not scheduled:
            logger.warning("%s: no watch targets available — observer not started", self.name)
            self._started = True
            return

        observer.start()
        self._observer = observer
        self._started = True

    def stop(self) -> None:
        """Stop the watchdog observer."""
        with self._lock:
            timers = list(self._debounce.values())
            self._debounce.clear()
        for timer in timers:
            timer.cancel()
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        self._started = False

    def scan(self) -> list[Finding]:
        """Return and clear findings queued by filesystem events."""
        if not self._started:
            # Lazy start so run_once works without an explicit daemon wire-up
            self.start()
        with self._lock:
            findings = list(self._pending)
            self._pending.clear()
        return findings

    def save_baseline(self, findings: list[Finding]) -> None:
        """Merge event findings into baseline; never wipe on empty drain."""
        if not findings:
            return
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (
                self.name,
                f.item_hash(),
                now,
                now,
                f.item_key,
                f.baseline_payload(),
            )
            for f in findings
        ]
        self.db.upsert_baseline_entries(rows)

    def _seed_cache(self) -> None:
        for path in self._iter_seed_paths():
            content = self._read_text(path)
            if content is not None:
                self._cache[str(path)] = content

    def _iter_seed_paths(self) -> Iterable[Path]:
        for path in self.watch_files:
            if path.is_file():
                yield path
        for root in self.watch_dirs:
            if not root.is_dir():
                continue
            if self._recursive:
                for p in root.rglob("*"):
                    if p.is_file():
                        yield p
            else:
                for p in root.iterdir():
                    if p.is_file():
                        yield p

    def _is_watched_path(self, path: Path) -> bool:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path

        for watched in self.watch_files:
            try:
                if resolved == watched.resolve() or path == watched:
                    return True
            except OSError:
                if path == watched or str(path) == str(watched):
                    return True

        for root in self.watch_dirs:
            try:
                resolved.relative_to(root.resolve())
                return True
            except (ValueError, OSError):
                try:
                    path.relative_to(root)
                    return True
                except ValueError:
                    continue
        return False

    def _handle_fs_event(self, src_path: str | bytes, *, event_type: str) -> None:
        path = Path(src_path if isinstance(src_path, str) else src_path.decode("utf-8", "replace"))
        if not self._is_watched_path(path):
            # Parent-dir watches see sibling files (e.g. other /etc entries)
            return

        key = str(path)
        # Coalesce bursts (truncate+write, replace delete+create) into one flush.
        with self._lock:
            existing = self._debounce.pop(key, None)
            if existing is not None:
                existing.cancel()
            timer = threading.Timer(
                self._debounce_seconds,
                self._flush_path,
                args=(path, event_type),
            )
            timer.daemon = True
            self._debounce[key] = timer
            timer.start()

    def _flush_path(self, path: Path, event_type: str) -> None:
        key = str(path)
        with self._lock:
            self._debounce.pop(key, None)
            old = self._cache.get(key, "")

        if path.exists() and path.is_file():
            new_content = self._read_text(path)
            if new_content is None:
                return
            new = new_content
            effective_event = "created" if old == "" and new else event_type
            if event_type == "deleted" and new:
                # replace()/rename race: delete seen first, file already back
                effective_event = "modified"
        else:
            new = ""
            effective_event = "deleted"

        with self._lock:
            old = self._cache.get(key, "")
            if old == new:
                return
            if new:
                self._cache[key] = new
            else:
                self._cache.pop(key, None)
            finding = self._finding_for_change(path, old, new, effective_event)
            self._pending.append(finding)

    def _finding_for_change(
        self, path: Path, old: str, new: str, event_type: str
    ) -> Finding:
        diff_text = unified_content_diff(str(path), old, new)
        content_fp = hashlib.sha256(f"{old}\0{new}".encode("utf-8", "replace")).hexdigest()[:16]
        return Finding(
            detector_name=self.name,
            severity="high",
            message=f"{event_type.upper()} {path}",
            item_key=f"{event_type}:{path}:{content_fp}",
            details={
                "path": str(path),
                "event": event_type,
                "diff": diff_text,
                "old_sha256": hashlib.sha256(old.encode("utf-8", "replace")).hexdigest(),
                "new_sha256": hashlib.sha256(new.encode("utf-8", "replace")).hexdigest(),
            },
        )

    @staticmethod
    def _read_text(path: Path) -> str | None:
        try:
            # sudoers/cron are text; ignore decode errors rather than crash
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.debug("Cannot read %s: %s", path, exc)
            return None
