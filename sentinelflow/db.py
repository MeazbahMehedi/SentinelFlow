"""SQLite persistence.

Two kinds of database are used:

* :class:`IdentityStore` (``sentinelflow.db``) holds accounts and the shared
  developer profiles. It never stores captured traffic.
* :class:`Store` (``workspaces/<id>/workspace.db``) is a private investigation
  workspace: configuration, sessions, packets, alerts and its audit trail.

Connections are short-lived and never shared across threads. Each store keeps
an in-process ``revision`` counter that increases after every committed write,
which lets the web layer cache expensive aggregates until data changes.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_RULES = {
    "port_scan": {"enabled": True, "threshold": 12, "window": 30},
    "host_scan": {"enabled": True, "threshold": 10, "window": 30},
    "syn_burst": {"enabled": True, "threshold": 80, "window": 10},
    "dns_burst": {"enabled": True, "threshold": 60, "window": 30},
    "outbound_volume": {"enabled": True, "threshold": 250000, "window": 60},
    "indicator_match": {"enabled": True, "threshold": 1, "window": 60},
    "brute_force": {"enabled": True, "threshold": 20, "window": 60},
    "beaconing": {"enabled": True, "threshold": 8, "window": 600},
    "dns_tunneling": {"enabled": True, "threshold": 10, "window": 60},
}
DEFAULT_SETTINGS = {
    "indicators": ["203.0.113.66"],
    "domain_indicators": ["malware.example.test"],
    "local_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"],
    "max_packets": 100000,
}
DEFAULT_PROFILES = [
    ("Your name", "Backend and detection engineer", "https://github.com/MeazbahMehedi"),
    (
        "Your teammate",
        "Frontend and research engineer",
        "https://github.com/ItsMONIKAAKTER",
    ),
]
WORKSPACE_TABLES = (
    "config",
    "sessions",
    "replay_packets",
    "packets",
    "alerts",
    "audit",
)

WORKSPACE_SCHEMA = """
CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  source TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ready',
  total INTEGER NOT NULL DEFAULT 0,
  processed INTEGER NOT NULL DEFAULT 0,
  speed REAL NOT NULL DEFAULT 1,
  created REAL NOT NULL,
  error TEXT NOT NULL DEFAULT '',
  dropped INTEGER NOT NULL DEFAULT 0,
  rule_snapshot TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS replay_packets(
  session_id INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
  seq INTEGER,
  event TEXT NOT NULL,
  PRIMARY KEY(session_id, seq)
);
CREATE TABLE IF NOT EXISTS packets(
  id INTEGER PRIMARY KEY,
  session_id INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
  ts REAL, src TEXT, dst TEXT, sport INTEGER, dport INTEGER,
  proto TEXT, length INTEGER, flags TEXT, dns TEXT
);
CREATE INDEX IF NOT EXISTS packets_session ON packets(session_id, id);
CREATE INDEX IF NOT EXISTS packets_session_ts ON packets(session_id, ts);
CREATE INDEX IF NOT EXISTS packets_src ON packets(src);
CREATE INDEX IF NOT EXISTS packets_dst ON packets(dst);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY,
  session_id INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
  ts REAL, rule TEXT, severity TEXT, src TEXT, dst TEXT, title TEXT, evidence TEXT,
  status TEXT NOT NULL DEFAULT 'new',
  note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS alerts_session ON alerts(session_id, id);
CREATE INDEX IF NOT EXISTS alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS alerts_src ON alerts(src);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts REAL, action TEXT, detail TEXT);
"""

IDENTITY_SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS profiles(
  id INTEGER PRIMARY KEY,
  name TEXT, role TEXT, bio TEXT, skills TEXT, email TEXT,
  github TEXT, linkedin TEXT, website TEXT,
  photo TEXT DEFAULT '', cv TEXT DEFAULT ''
);
"""


class BaseStore:
    """Thin helper around short-lived SQLite connections."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self.revision = 0
        self._revision_lock = threading.Lock()
        self.initialize()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=20)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            changed = conn.total_changes
            conn.commit()
            if changed:
                self.bump()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def bump(self) -> None:
        with self._revision_lock:
            self.revision += 1

    def initialize(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def rows(self, sql: str, args=()) -> list[dict]:
        with self.connect() as c:
            return [dict(x) for x in c.execute(sql, args).fetchall()]

    def one(self, sql: str, args=()) -> dict | None:
        rows = self.rows(sql, args)
        return rows[0] if rows else None

    def execute(self, sql: str, args=()) -> int:
        with self.connect() as c:
            return c.execute(sql, args).lastrowid

    @staticmethod
    def _columns(conn: sqlite3.Connection, table: str, schema: str = "main") -> set[str]:
        return {row[1] for row in conn.execute(f"PRAGMA {schema}.table_info({table})")}


class Store(BaseStore):
    """A private investigation workspace."""

    def initialize(self) -> None:
        with self.connect() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(WORKSPACE_SCHEMA)
            for key, value in (
                ("rules", DEFAULT_RULES),
                ("settings", DEFAULT_SETTINGS),
            ):
                c.execute("INSERT OR IGNORE INTO config VALUES(?,?)", (key, json.dumps(value)))
            self._upgrade_config(c)
            c.execute(
                "UPDATE sessions SET status='interrupted', error=? "
                "WHERE status IN ('running','paused')",
                ("Application restarted. Restart this session to rebuild its detection state.",),
            )

    @staticmethod
    def _upgrade_config(c: sqlite3.Connection) -> None:
        """Add rules and settings introduced by newer releases without changing user values."""
        for key, defaults in (("rules", DEFAULT_RULES), ("settings", DEFAULT_SETTINGS)):
            row = c.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
            stored = json.loads(row["value"])
            merged = {**deepcopy(defaults), **stored}
            if key == "settings" and "domain_indicators" not in stored:
                merged["domain_indicators"] = []
            if merged != stored:
                c.execute("UPDATE config SET value=? WHERE key=?", (json.dumps(merged), key))

    def config(self, key: str):
        return json.loads(self.one("SELECT value FROM config WHERE key=?", (key,))["value"])

    def set_config(self, key: str, value) -> None:
        self.execute("UPDATE config SET value=? WHERE key=?", (json.dumps(value), key))

    def audit(self, action: str, detail: str = "") -> None:
        self.execute(
            "INSERT INTO audit(ts,action,detail) VALUES(?,?,?)",
            (time.time(), action, detail[:500]),
        )


class IdentityStore(BaseStore):
    """Accounts and shared developer profiles. Contains no captured traffic."""

    def initialize(self) -> None:
        with self.connect() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(IDENTITY_SCHEMA)
            columns = self._columns(c, "users")
            if "email" not in columns:
                c.execute("ALTER TABLE users ADD COLUMN email TEXT")
            if "role" not in columns:
                c.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'analyst'")
                c.execute("UPDATE users SET role='admin' WHERE id=(SELECT MIN(id) FROM users)")
            if "session_version" not in columns:
                c.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
            c.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS users_gmail_unique "
                "ON users(email) WHERE email IS NOT NULL"
            )
            c.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS users_name_casefold ON users(lower(username))"
            )
            if not c.execute("SELECT 1 FROM profiles").fetchone():
                for name, role, github in DEFAULT_PROFILES:
                    c.execute(
                        "INSERT INTO profiles(name,role,bio,skills,email,github,linkedin,website) "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (
                            name,
                            role,
                            "Add your background, contribution, and research interests here.",
                            "Python, Network Security, Software Engineering",
                            "",
                            github,
                            "",
                            "",
                        ),
                    )

    def first_user_id(self) -> int | None:
        row = self.one("SELECT MIN(id) AS id FROM users")
        return row["id"] if row else None


def migrate_legacy_workspace(identity_path: Path, workspace_path: Path) -> bool:
    """Move pre-1.2 workspace tables out of the identity database.

    Releases before 1.2 stored the first administrator's captures in the same
    file as every account's password hash. The data is copied into the primary
    workspace in a single transaction and the legacy tables are dropped only
    after a migration marker has been committed, so an interrupted upgrade can
    safely resume.
    """
    if not identity_path.exists():
        return False
    with sqlite3.connect(identity_path) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    legacy = [t for t in WORKSPACE_TABLES if t in tables]
    if not legacy:
        return False

    workspace = Store(workspace_path)
    with workspace.connect() as c:
        migrated = c.execute("SELECT 1 FROM config WHERE key='legacy_migrated'").fetchone()
        has_data = c.execute("SELECT 1 FROM sessions LIMIT 1").fetchone()
        if not migrated and has_data:
            log.warning(
                "Legacy workspace tables found but primary workspace is not empty; skipped."
            )
            return False
        if not migrated:
            c.execute("ATTACH DATABASE ? AS legacy", (str(identity_path),))
            for table in legacy:
                if table == "config":
                    c.execute("DELETE FROM main.config")
                shared = sorted(
                    BaseStore._columns(c, table) & BaseStore._columns(c, table, "legacy")
                )
                cols = ",".join(shared)
                c.execute(f"INSERT INTO main.{table}({cols}) SELECT {cols} FROM legacy.{table}")
            c.execute("INSERT OR REPLACE INTO config VALUES('legacy_migrated','true')")
            c.commit()
            c.execute("DETACH DATABASE legacy")
            Store._upgrade_config(c)
            c.execute(
                "UPDATE sessions SET status='interrupted', error=? "
                "WHERE status IN ('running','paused')",
                ("Application restarted. Restart this session to rebuild its detection state.",),
            )
    with sqlite3.connect(identity_path) as conn:
        conn.execute("PRAGMA foreign_keys=OFF")
        for table in (
            "replay_packets",
            "packets",
            "alerts",
            "sessions",
            "audit",
            "config",
        ):
            if table in legacy:
                conn.execute(f"DROP TABLE IF EXISTS {table}")
    with sqlite3.connect(identity_path) as conn:
        conn.execute("VACUUM")
    log.info("Moved legacy workspace tables into %s", workspace_path)
    return True
