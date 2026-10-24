"""SQLite persistence. Connections are short-lived and never shared across threads."""
import json
import sqlite3
import time
from contextlib import contextmanager

DEFAULT_RULES = {
    'port_scan': {'enabled': True, 'threshold': 12, 'window': 30},
    'host_scan': {'enabled': True, 'threshold': 10, 'window': 30},
    'syn_burst': {'enabled': True, 'threshold': 80, 'window': 10},
    'dns_burst': {'enabled': True, 'threshold': 60, 'window': 30},
    'outbound_volume': {'enabled': True, 'threshold': 250000, 'window': 60},
    'indicator_match': {'enabled': True, 'threshold': 1, 'window': 60},
}
DEFAULT_SETTINGS = {'indicators': ['203.0.113.66'], 'local_networks': ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'], 'max_packets': 100000}

class Store:
    def __init__(self, path):
        self.path = str(path)
        self.initialize()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=20)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys=ON')
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self):
        with self.connect() as c:
            c.execute('PRAGMA journal_mode=WAL')
            c.executescript('''
            CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY, name TEXT NOT NULL, source TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'ready', total INTEGER NOT NULL DEFAULT 0, processed INTEGER NOT NULL DEFAULT 0,
              speed REAL NOT NULL DEFAULT 1, created REAL NOT NULL, error TEXT NOT NULL DEFAULT '', dropped INTEGER NOT NULL DEFAULT 0,
              rule_snapshot TEXT NOT NULL DEFAULT '{}');
            CREATE TABLE IF NOT EXISTS replay_packets(session_id INTEGER REFERENCES sessions(id) ON DELETE CASCADE, seq INTEGER,
              event TEXT NOT NULL, PRIMARY KEY(session_id,seq));
            CREATE TABLE IF NOT EXISTS packets(id INTEGER PRIMARY KEY, session_id INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
              ts REAL, src TEXT, dst TEXT, sport INTEGER, dport INTEGER, proto TEXT, length INTEGER, flags TEXT, dns TEXT);
            CREATE INDEX IF NOT EXISTS packets_session ON packets(session_id,id);
            CREATE INDEX IF NOT EXISTS packets_src ON packets(src);
            CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, session_id INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
              ts REAL, rule TEXT, severity TEXT, src TEXT, dst TEXT, title TEXT, evidence TEXT,
              status TEXT NOT NULL DEFAULT 'new', note TEXT NOT NULL DEFAULT '');
            CREATE INDEX IF NOT EXISTS alerts_session ON alerts(session_id,id);
            CREATE TABLE IF NOT EXISTS profiles(id INTEGER PRIMARY KEY, name TEXT, role TEXT, bio TEXT, skills TEXT,
              email TEXT, github TEXT, linkedin TEXT, website TEXT, photo TEXT DEFAULT '', cv TEXT DEFAULT '');
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts REAL, action TEXT, detail TEXT);
            ''')
            # Additive upgrade preserves the original account and its existing captures.
            columns={row['name'] for row in c.execute('PRAGMA table_info(users)')}
            if 'email' not in columns:
                c.execute('ALTER TABLE users ADD COLUMN email TEXT')
            if 'role' not in columns:
                c.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'analyst'")
                c.execute("UPDATE users SET role='admin' WHERE id=(SELECT MIN(id) FROM users)")
            c.execute('CREATE UNIQUE INDEX IF NOT EXISTS users_gmail_unique ON users(email) WHERE email IS NOT NULL')
            c.execute('CREATE UNIQUE INDEX IF NOT EXISTS users_name_casefold ON users(lower(username))')
            for key,value in [('rules',DEFAULT_RULES),('settings',DEFAULT_SETTINGS)]:
                c.execute('INSERT OR IGNORE INTO config VALUES(?,?)',(key,json.dumps(value)))
            if not c.execute('SELECT 1 FROM profiles').fetchone():
                for name,role in [('Your name','Backend and detection engineer'),('Your teammate','Frontend and research engineer')]:
                    c.execute('INSERT INTO profiles(name,role,bio,skills,email,github,linkedin,website) VALUES(?,?,?,?,?,?,?,?)',
                        (name,role,'Add your background, contribution, and research interests here.','Python, Network Security, Software Engineering','','','',''))
            for pid,handle in [(1,'MeazbahMehedi'),(2,'ItsMONIKAAKTER')]:
                c.execute("UPDATE profiles SET github=? WHERE id=? AND (github='' OR github IS NULL)",('https://github.com/'+handle,pid))
            c.execute("UPDATE sessions SET status='interrupted',error='Application restarted. Restart this session to rebuild its detection state.' WHERE status IN ('running','paused')")

    def rows(self, sql, args=()):
        with self.connect() as c:
            return [dict(x) for x in c.execute(sql,args).fetchall()]

    def one(self, sql, args=()):
        rows=self.rows(sql,args)
        return rows[0] if rows else None

    def execute(self, sql, args=()):
        with self.connect() as c:
            return c.execute(sql,args).lastrowid

    def config(self,key):
        return json.loads(self.one('SELECT value FROM config WHERE key=?',(key,))['value'])

    def set_config(self,key,value):
        self.execute('UPDATE config SET value=? WHERE key=?',(json.dumps(value),key))

    def audit(self,action,detail=''):
        self.execute('INSERT INTO audit(ts,action,detail) VALUES(?,?,?)',(time.time(),action,detail[:500]))
