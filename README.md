# PrivescMonitor

Continuous **blue-team** daemon for Linux privilege-escalation *vector detection*
and behavioral anomalies, with real-time admin alerts (Telegram).

This is **not** an exploit toolkit and **not** a linPEAS clone. linPEAS is a
one-shot enumeration script; PrivescMonitor is a long-running monitor that
baselines system state and alerts only on **new** findings.

## Status

Step 1 — project skeleton (no concrete detectors yet).

## Layout

```
privesc_monitor/
├── main.py              # asyncio daemon entrypoint
├── config.yaml          # daemon / Telegram / detector toggles
├── requirements.txt
├── detectors/
│   ├── __init__.py
│   └── base.py          # BaseDetector + Finding + baseline diff
├── alerts/              # alert backends (Telegram later)
├── storage/
│   ├── __init__.py
│   └── db.py            # SQLite baselines + alerts
├── tests/
│   └── test_detectors.py
└── README.md
```

## Diffing strategy (alert fatigue)

1. Each detector `scan()` returns the **current** set of findings.
2. Every finding has a stable `item_hash` (SHA-256 of identity + content).
3. Known hashes live in SQLite `baselines` keyed by `(detector_name, item_hash)`.
4. `diff(old, new)` emits only findings whose hash is **not** in the baseline.
5. After diff, `save_baseline()` upserts the full current set (`first_seen` / `last_seen`).
6. Unchanged findings stay silent on subsequent scans. Removals are not alerted.

## Quick start (skeleton)

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py -c config.yaml
python -m unittest tests.test_detectors -v
```

## Requirements

- Python 3.11+
- Linux target (production); skeleton runs on any OS for unit tests
- Stack: `psutil`, `watchdog`, `PyYAML`, `requests`, `sqlite3`, `asyncio`
