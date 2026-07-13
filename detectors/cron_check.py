"""Real-time monitoring of system/user cron locations via watchdog."""

from __future__ import annotations

from detectors.content_watch import ContentWatchDetector


class CronCheckDetector(ContentWatchDetector):
    """
    Watch cron schedules for unexpected persistence / job injection.

    Targets:
      - /etc/crontab
      - /etc/cron.d/
      - /var/spool/cron/  (includes distro variants like crontabs/)

    On create/modify/delete, emit severity=HIGH with a unified content diff.
    """

    name = "cron_check"
    default_watch_files = ("/etc/crontab",)
    default_watch_dirs = ("/etc/cron.d", "/var/spool/cron")
    recursive_dirs = True
