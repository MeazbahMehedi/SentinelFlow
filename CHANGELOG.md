# Changelog

## 1.2.0

### Detection
- Added a bidirectional flow table. Port-scan, brute-force and beaconing rules now count only connection openers, so servers replying to clients and traffic captured mid-stream no longer raise scan alerts.
- Host-scan now counts only local-network destinations; ordinary web browsing to many internet hosts no longer triggers it.
- Multicast, broadcast (including directed broadcast), loopback and link-local destinations are excluded from scan and outbound-volume rules.
- Slightly out-of-order packets are now evaluated instead of being silently skipped; only packets older than an active window are ignored.
- New detectors: authentication brute force (T1110), periodic beaconing (T1071), and DNS tunneling (T1071.004).
- Every rule is mapped to a MITRE ATT&CK technique and tactic, shown in the UI and exports.
- Indicators accept CIDR networks; a new domain indicator list matches DNS queries and subdomains.
- IPv6 unique-local addresses (`fc00::/7`) added to the default local networks.

### Performance
- Packets and alerts are written in batched transactions; the retained-packet count is tracked in memory instead of counting the table for every packet.
- Dashboard updates use revision-aware polling (`/api/snapshot?rev=N` returns 204 when unchanged) instead of long-lived event streams that each occupied a server thread.
- Dashboard summaries are cached per workspace revision and shared across tabs.
- New indexes for session time ranges, destinations, alert status and alert sources.
- Optional idle-gap skipping during replay.

### Security
- Sign-in throttling per address and per account; a successful sign-in no longer resets the address counter.
- Timing-safe sign-in for unknown accounts.
- Session versioning: password changes and "Sign out other browsers" revoke other sessions.
- Identity database no longer contains captured traffic; 1.x data is migrated into `workspaces/primary/` on first start.
- Only one live capture may run on a host at a time.
- Registration accepts any valid email address; Gmail aliases are still canonicalized.

### Interface
- Command palette (Ctrl+K) for pages, hosts and alerts.
- Timeline tooltips, a severity strip, and ATT&CK tags throughout.
- Host explorer conversation map, risk scores, and host profiles (services, peers, active window).
- Bulk alert triage, a new-detection banner, and per-alert evidence JSON export.
- Analytics: ATT&CK tactic breakdown and top destination services.
- Replay timelines with detection markers.

### Code quality
- Application split into Flask blueprints and service modules; templates, CSS and JavaScript reformatted for readability.
- `pyproject.toml`, ruff linting and formatting, CI lint job, coverage reporting, browser check in CI, Dockerfile.
- Developer profile GitHub links are no longer re-added on every restart after being cleared.
- 161 automated tests (previously 111).
