# Security policy

SentinelFlow is a local educational monitoring application. Its default launcher listens only on `127.0.0.1`; explicit HOST and TRUSTED_HOSTS configuration can enable trusted LAN access. Do not expose it directly to the internet or use it as your only security control.

## Implemented protections

- Passwords are hashed with Werkzeug's password-hashing API.
- Mutating routes require a session CSRF token.
- Login attempts are throttled locally per remote address.
- Jinja autoescaping and DOM text insertion protect displayed capture metadata.
- SQL queries use parameters for user-controlled data.
- Session cookies are HttpOnly and SameSite Strict.
- Responses include CSP, frame restrictions, MIME-sniffing protection, and no-store caching.
- Uploaded capture files use random temporary names and bounded input sizes.
- Images are decoded, resized, and re-encoded. CVs are PDF-envelope checked and served as attachments.
- Runtime data and uploads are excluded from version control.
- Gmail addresses are canonicalized and protected by a unique database index.
- Request data is scoped to the authenticated account database, including streams, exports, mutation routes, and worker state.
- GitHub integration reads only the two configured public accounts, caches results, and honors error cooldowns.

## Operational boundaries

The first-run setup creates the administrator, so complete setup before granting access to another local user. The application is single-process and intended for a small local team. New accounts receive isolated analysis workspaces. Only administrators may capture host traffic, edit shared developer profiles, or change other account roles. Gmail uniqueness is not ownership verification; public deployment requires a verification mechanism. Its live capture process may need OS capture privileges; consider that privilege boundary when choosing a deployment environment.

CV validation is not malware scanning. Captured DNS strings and imported alert metadata are untrusted. Keep dependencies updated and avoid importing sensitive captures into a machine you do not control. Stored packet metadata can still reveal private network activity even though raw payloads are not retained.

To report a vulnerability after publishing, enable GitHub private vulnerability reporting or add the maintainers' verified security contact here. Do not publish credentials, real PCAPs, or CVs in a public issue. No unverified contact address is supplied.
