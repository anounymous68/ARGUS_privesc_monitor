"""PrivescMonitor — continuous privilege-escalation vector & anomaly daemon."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path


def load_config(path: Path) -> dict:
    """Load YAML config. Implementation filled in later steps."""
    import yaml

    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


async def run_daemon(config: dict) -> None:
    """Main monitoring loop. Wired up in later steps."""
    logging.info("PrivescMonitor started (skeleton — no detectors registered yet)")
    # Future: register detectors, scan on interval, alert on diffs
    await asyncio.Event().wait()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="PrivescMonitor — real-time Linux priv-esc vector detection"
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=Path(__file__).resolve().parent / "config.yaml",
        help="Path to config.yaml",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if not args.config.is_file():
        logging.error("Config not found: %s", args.config)
        return 1

    config = load_config(args.config)
    try:
        asyncio.run(run_daemon(config))
    except KeyboardInterrupt:
        logging.info("Shutting down")
    return 0


if __name__ == "__main__":
    sys.exit(main())
