"""SentinelFlow: real-time network threat detection with a live dashboard and PCAP replay."""

from __future__ import annotations

import atexit
import os
import secrets
from datetime import timedelta
from pathlib import Path

from flask import Flask

from .services import Services
from .version import __version__

__all__ = ["create_app", "__version__"]


def _secret_key(root: Path) -> str:
    path = root / "secret.key"
    if not path.exists():
        try:
            with path.open("x") as f:
                f.write(secrets.token_hex(32))
            path.chmod(0o600)
        except FileExistsError:
            pass
    return path.read_text().strip()


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    root = Path(os.getenv("SENTINELFLOW_DATA", str(Path.cwd() / "instance")))
    if test_config:
        root = Path(test_config.get("DATA_DIR", root))
    root.mkdir(parents=True, exist_ok=True)

    trusted_hosts = os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1,[::1]")
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY") or _secret_key(root),
        MAX_CONTENT_LENGTH=33 * 1024 * 1024,
        MAX_FORM_MEMORY_SIZE=200_000,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        DATA_DIR=root,
        TRUSTED_HOSTS=[x.strip() for x in trusted_hosts.split(",") if x.strip()],
    )
    if test_config:
        app.config.update(test_config)

    services = Services(root)
    # Stable extension names used by the launcher, scripts and tests.
    app.extensions.update(
        sentinelflow=services,
        identities=services.identities,
        store=services.primary_store,
        engine=services.primary_engine,
        workspace_for=services.workspace_for,
        github_projects=services.github,
        shutdown=services.shutdown,
        stopping=services.stopping,
    )
    atexit.register(services.shutdown)

    from . import web

    web.register(app)
    return app
