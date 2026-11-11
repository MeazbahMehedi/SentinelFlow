# Release validation

Release: 1.2.0, 11 November 2026.

## Executed checks

| Check | Result |
|---|---|
| `python -m pytest -q` | **161 passed** on Python 3.13 |
| `ruff check .` and `ruff format --check .` | Clean |
| `node --check` on all JavaScript | Clean |
| `python scripts/evaluate.py` | Threat fixture: 548 packets, 9 alerts covering all nine detectors; normal fixture: 60 packets, zero alerts |
| `python scripts/browser_check.py` | Passed against the actual `run.py` Waitress launcher in an isolated workspace |
| Desktop and mobile | Ten pages at 1440 px and 390 px in dark and light themes, with no horizontal overflow |
| Browser interactions | Account creation, demo replay, nine detections, command palette navigation, triage notes, developer profile edit, theme persistence, mobile navigation |
| Accounts | Duplicate email rejected; a second account cannot read the first account's data or edit shared profiles |
| Shutdown | Repeated Ctrl+C during an active replay exits with code 0 and no traceback |
| JavaScript | No uncaught page errors during the exercised workflows |
| Screenshots | Regenerated with `scripts/capture_screenshots.py` and visually inspected |

## Regression coverage for 1.2 fixes

- A server replying to 30 client connections produces no port-scan alert.
- Mid-stream (ACK-only) traffic to many ports produces no alert.
- Connections to 25 internet hosts produce no host-scan alert.
- Multicast, broadcast, directed-broadcast and IPv6 multicast traffic produces no scan or exfiltration alert.
- A packet 5 seconds out of order still matches an indicator; packets older than the window are ignored.
- A successful sign-in to one account does not reset the address throttle used against another.
- Changing a password or revoking sessions signs out other browsers, for both pages and API calls.
- The identity database contains no traffic tables; legacy 1.x data migrates once and an interrupted migration resumes cleanly.
- Retention limits stop ingestion with an explicit error at exactly the configured count under batched writes.
- Only one live capture can hold the host capture lock, and the lock is released when opening the interface fails.

## Reproduce

```bash
python -m pip install -r requirements-dev.txt
ruff check . && ruff format --check .
python -m pytest -q
python scripts/evaluate.py
python -m playwright install chromium
python scripts/browser_check.py
```

To use an installed Chrome instead of Playwright's Chromium, set `SENTINELFLOW_CHROME` to its executable path.

## Environment boundaries

Physical network capture was not exercised because the validation environment does not permit raw capture; the driver-missing, permission-error, interface-selection and capture-lock paths are covered by tests. Windows Npcap and native Windows/macOS installs should be checked on the demonstration computer.

The bundled fixtures are synthetic coverage examples. They do not establish production throughput or real-world detection accuracy.

The diagrams in `docs/diagrams/` and `scripts/build_srs.py` document the 1.1 software requirements specification; the README architecture section reflects 1.2.
