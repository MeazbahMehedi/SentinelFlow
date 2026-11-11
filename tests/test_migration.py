import json
import sqlite3

from werkzeug.security import generate_password_hash

from sentinelflow import create_app
from sentinelflow.db import DEFAULT_RULES

LEGACY_SCHEMA = """
CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
  email TEXT, role TEXT NOT NULL DEFAULT 'analyst');
CREATE TABLE config(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE sessions(id INTEGER PRIMARY KEY, name TEXT NOT NULL, source TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ready', total INTEGER NOT NULL DEFAULT 0, processed INTEGER NOT NULL DEFAULT 0,
  speed REAL NOT NULL DEFAULT 1, created REAL NOT NULL, error TEXT NOT NULL DEFAULT '', dropped INTEGER NOT NULL DEFAULT 0,
  rule_snapshot TEXT NOT NULL DEFAULT '{}');
CREATE TABLE replay_packets(session_id INTEGER, seq INTEGER, event TEXT NOT NULL, PRIMARY KEY(session_id,seq));
CREATE TABLE packets(id INTEGER PRIMARY KEY, session_id INTEGER, ts REAL, src TEXT, dst TEXT, sport INTEGER,
  dport INTEGER, proto TEXT, length INTEGER, flags TEXT, dns TEXT);
CREATE TABLE alerts(id INTEGER PRIMARY KEY, session_id INTEGER, ts REAL, rule TEXT, severity TEXT, src TEXT,
  dst TEXT, title TEXT, evidence TEXT, status TEXT NOT NULL DEFAULT 'new', note TEXT NOT NULL DEFAULT '');
CREATE TABLE profiles(id INTEGER PRIMARY KEY, name TEXT, role TEXT, bio TEXT, skills TEXT, email TEXT,
  github TEXT, linkedin TEXT, website TEXT, photo TEXT DEFAULT '', cv TEXT DEFAULT '');
CREATE TABLE audit(id INTEGER PRIMARY KEY, ts REAL, action TEXT, detail TEXT);
"""


def build_legacy(directory):
    directory.mkdir()
    with sqlite3.connect(directory / "sentinelflow.db") as c:
        c.executescript(LEGACY_SCHEMA)
        c.execute(
            "INSERT INTO users VALUES(1,'owner',?,'owner@gmail.com','admin')",
            (generate_password_hash("owner-password-123"),),
        )
        legacy_rules = {k: v for k, v in DEFAULT_RULES.items() if k in ("port_scan", "host_scan")}
        legacy_rules["port_scan"] = dict(legacy_rules["port_scan"], threshold=33)
        c.execute("INSERT INTO config VALUES('rules',?)", (json.dumps(legacy_rules),))
        c.execute(
            "INSERT INTO config VALUES('settings',?)",
            (
                json.dumps(
                    {"indicators": [], "local_networks": ["10.0.0.0/8"], "max_packets": 5000}
                ),
            ),
        )
        c.execute(
            "INSERT INTO sessions(id,name,source,status,created) VALUES(7,'Old capture','pcap','running',0)"
        )
        c.execute(
            "INSERT INTO packets(session_id,ts,src,dst,sport,dport,proto,length,flags,dns) "
            "VALUES(7,1,'10.0.0.1','10.0.0.2',1,2,'TCP',60,'S','')"
        )
        c.execute(
            "INSERT INTO alerts(session_id,ts,rule,severity,src,dst,title,evidence,note) "
            "VALUES(7,1,'port_scan','high','10.0.0.1','10.0.0.2','Possible port scan','{}','kept note')"
        )
        c.execute("INSERT INTO audit(ts,action,detail) VALUES(1,'legacy','before upgrade')")


def test_legacy_workspace_is_moved_out_of_identity_database(tmp_path):
    directory = tmp_path / "legacy"
    build_legacy(directory)
    app = create_app({"TESTING": True, "DATA_DIR": directory})
    try:
        identities = app.extensions["identities"]
        store = app.extensions["store"]
        tables = {
            r["name"] for r in identities.rows("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert tables == {"users", "profiles"}
        assert identities.one("SELECT session_version FROM users")["session_version"] == 0
        assert store.one("SELECT status FROM sessions WHERE id=7")["status"] == "interrupted"
        assert store.one("SELECT note FROM alerts")["note"] == "kept note"
        assert store.one("SELECT COUNT(*) n FROM packets")["n"] == 1
        assert store.one("SELECT detail FROM audit WHERE action='legacy'")
        rules = store.config("rules")
        assert rules["port_scan"]["threshold"] == 33 and set(rules) == set(DEFAULT_RULES)
        assert store.config("settings")["domain_indicators"] == []
    finally:
        app.extensions["shutdown"]()

    # A second start is a no-op and keeps the data.
    again = create_app({"TESTING": True, "DATA_DIR": directory})
    try:
        assert again.extensions["store"].one("SELECT COUNT(*) n FROM alerts")["n"] == 1
    finally:
        again.extensions["shutdown"]()


def test_interrupted_migration_resumes(tmp_path):
    """If the process stopped after copying but before dropping legacy tables, finish cleanly."""
    directory = tmp_path / "legacy"
    build_legacy(directory)
    app = create_app({"TESTING": True, "DATA_DIR": directory})
    app.extensions["shutdown"]()
    with sqlite3.connect(directory / "sentinelflow.db") as c:
        c.execute(
            "CREATE TABLE sessions(id INTEGER PRIMARY KEY, name TEXT, source TEXT, created REAL)"
        )
        c.execute("INSERT INTO sessions VALUES(99,'stale copy','pcap',0)")
    app = create_app({"TESTING": True, "DATA_DIR": directory})
    try:
        store = app.extensions["store"]
        assert store.one("SELECT COUNT(*) n FROM sessions")["n"] == 1
        tables = {
            r["name"]
            for r in app.extensions["identities"].rows(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert "sessions" not in tables
    finally:
        app.extensions["shutdown"]()
