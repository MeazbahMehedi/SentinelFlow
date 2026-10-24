# Release validation

Release: 1.1.1, 24 October 2026.

## GitHub profile update

The 1.1.1 update adds fixed GitHub-sourced profile cards. Its backend/API checks passed, including a 101-repository paginated fixture, independent profile/repository failures, stale profile retention, unsafe URL rejection, and denied POST writes. A real public API fetch succeeded for both configured accounts and returned avatar URLs. Desktop light/dark layout, filters, and both real GitHub avatars were inspected using a rendered Flask page in the managed static preview. The preview environment cannot execute Python, so the live Flask backend was checked through its test client and real API calls rather than a full browser-to-Flask session in this update. Earlier full-app browser checks below refer to release 1.1.0.

See [GITHUB_PROFILE_UPDATE.md](GITHUB_PROFILE_UPDATE.md) for the specification supplement.

## Executed checks

| Check | Result |
|---|---|
| `python -m pytest -q` | **111 passed** on Python 3.12; latest full run completed in 10.96 seconds |
| `python scripts/evaluate.py` | Threat fixture: 501 packets and six detector categories; normal fixture: 60 packets and zero alerts |
| `python scripts/browser_check.py` | Passed against the actual `run.py` Waitress launcher in an isolated workspace |
| Desktop browser | Ten pages checked at 1440 px width in both dark and light themes |
| Mobile browser | Ten pages checked at 390 px width in both themes, without document-level horizontal overflow |
| Browser interactions | Account creation, replay, six detections, triage note persistence, developer profile edit, and mobile navigation passed |
| JavaScript | No uncaught exceptions observed during the exercised browser workflows |
| Accounts | Gmail alias duplicate rejected; second browser account could not access first account data; role changes and legacy migration passed |
| Appearance | Real theme toggle, saved preference, and theme persistence passed |
| Shutdown | Repeated Ctrl+C with paused replay and active SSE connection exited with code 0 and no traceback |
| GitHub | Public API fetched from both configured accounts; cache/error paths also covered by deterministic tests |
| Word specification | 28 pages, rendered and visually inspected; nine diagrams and 59 functional requirements |

## Tested behavior

- Six detector thresholds, evidence, distinct counting, window expiration, duplicate suppression, disabled rules, SYN ACK exclusions, DNS response exclusions, and IPv6 local ranges.
- PCAP and single-interface PCAPNG parsing, IPv6, DNS normalization, timestamp sorting, invalid captures, unsupported link types, and rejection of multi-interface PCAPNG.
- Replay invariance at 1x, 4x, and 32x, pause/resume/stop, active worker exclusion, restart replacement, frozen rule snapshots, and interrupted session handling.
- Authenticated page/API access, CSRF rejection, security headers, password update, invalid configuration, and readable live permission errors.
- Developer links, image/CV uploads, escaped profile text, private media paths, CSV formula escaping, alert triage, and session deletion cascades.
- EVE alert imports, malformed input rejection, and compatibility with investigation and analytics pages.
- Gmail canonicalization, duplicate prevention, database migration, linked legacy email, private streams/exports/records, administrator-only capture/profile editing, role management, and self-demotion protection.
- Npcap absence, friendly interface enumeration, unavailable adapter handling, WinPcap error conversion, loopback normalization, and session quota before opening capture sockets.
- Read-only GitHub allowlisting, public metadata parsing, five-minute cache, network failures, stale results, and rate-limit cooldowns.

## Reproduce

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python scripts/evaluate.py
```

Optional browser check:

```bash
python -m playwright install chromium
python scripts/browser_check.py
```

The browser check launches the actual application with a temporary data directory and an available local port. It does not change your normal account, sessions, or profiles.

## Environment boundaries

Physical network capture was not exercised because the release environment does not permit the required raw capture operations. Its permission failure path was tested. Windows Npcap and native Windows/macOS installation require checks on the intended demonstration computer. The supplied GitHub Actions workflow has not yet run in the user's repository.

The bundled fixtures are synthetic coverage examples. They do not establish production throughput, real-world detection accuracy, or the absence of all defects.
