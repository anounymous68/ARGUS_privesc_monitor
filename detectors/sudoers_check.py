"""Real-time monitoring of /etc/sudoers and /etc/sudoers.d/ via watchdog."""

from __future__ import annotations

from detectors.content_watch import ContentWatchDetector


class SudoersCheckDetector(ContentWatchDetector):
    """
    Watch sudoers policy files for privilege-escalation enabling changes.

    On create/modify/delete, emit severity=HIGH with a unified content diff.
    """

    name = "sudoers_check"
    default_watch_files = ("/etc/sudoers",)
    default_watch_dirs = ("/etc/sudoers.d",)
    recursive_dirs = False
