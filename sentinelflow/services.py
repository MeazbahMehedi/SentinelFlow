"""Process-wide services: identity store, per-account workspaces and engines."""

from __future__ import annotations

import threading
from pathlib import Path

from .db import IdentityStore, Store, migrate_legacy_workspace
from .engine import Engine
from .github import GitHubProjects
from .security import LoginLimiter


class Services:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.stopping = threading.Event()
        identity_path = root / "sentinelflow.db"
        primary_dir = root / "workspaces" / "primary"
        primary_dir.mkdir(parents=True, exist_ok=True)
        self.identities = IdentityStore(identity_path)
        migrate_legacy_workspace(identity_path, primary_dir / "workspace.db")
        self.primary_store = Store(primary_dir / "workspace.db")
        self.primary_engine = Engine(self.primary_store)
        self.github = GitHubProjects(root / "github-cache")
        self.limiter = LoginLimiter()
        self._lock = threading.RLock()
        self._workspaces: dict[int, tuple[Store, Engine]] = {}
        (root / "media").mkdir(exist_ok=True)
        (root / "tmp").mkdir(exist_ok=True)

    def workspace_for(self, uid: int) -> tuple[Store, Engine]:
        """Return the private store and engine for an account.

        The first (owner) account uses the primary workspace, which also
        receives data migrated from releases before 1.2.
        """
        uid = int(uid)
        with self._lock:
            first = self.identities.first_user_id()
            if first is None or uid == first:
                return self.primary_store, self.primary_engine
            if uid not in self._workspaces:
                if not self.identities.one("SELECT id FROM users WHERE id=?", (uid,)):
                    raise ValueError("Unknown account.")
                directory = self.root / "workspaces" / str(uid)
                directory.mkdir(parents=True, exist_ok=True)
                store = Store(directory / "workspace.db")
                self._workspaces[uid] = (store, Engine(store))
            return self._workspaces[uid]

    def engines(self) -> list[Engine]:
        with self._lock:
            return [self.primary_engine] + [engine for _, engine in self._workspaces.values()]

    def shutdown(self) -> None:
        self.stopping.set()
        engines = self.engines()
        # Signal every worker before waiting for any of them.
        for engine in engines:
            engine.stop_event.set()
        for engine in engines:
            engine.shutdown()
