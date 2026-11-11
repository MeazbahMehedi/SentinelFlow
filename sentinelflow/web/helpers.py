"""Request-scoped helpers shared by the blueprints."""

from __future__ import annotations

from flask import abort, current_app, g, request, session

from ..services import Services


def services() -> Services:
    return current_app.extensions["sentinelflow"]


def workspace():
    """Return ``(store, engine)`` for the signed-in account."""
    if "workspace" not in g:
        uid = session.get("uid")
        svc = services()
        g.workspace = svc.workspace_for(uid) if uid else (svc.primary_store, svc.primary_engine)
    return g.workspace


def store():
    return workspace()[0]


def engine():
    return workspace()[1]


def current_user() -> dict | None:
    if "current_user" not in g:
        uid = session.get("uid")
        g.current_user = (
            services().identities.one(
                "SELECT id, username, email, role, session_version FROM users WHERE id=?", (uid,)
            )
            if uid
            else None
        )
    return g.current_user


def is_admin() -> bool:
    user = current_user()
    return bool(user and user["role"] == "admin")


def require_admin() -> None:
    if not is_admin():
        abort(403, description="This action requires an administrator account.")


def selected_session() -> int | None:
    raw = request.args.get("session", "")
    if not raw:
        return None
    try:
        sid = int(raw)
    except ValueError:
        abort(400, description="Invalid session filter.")
    if not store().one("SELECT id FROM sessions WHERE id=?", (sid,)):
        abort(404, description="Session not found.")
    return sid


def page_number() -> int:
    try:
        return max(1, int(request.args.get("p", 1)))
    except ValueError:
        return 1


def upload_name(filename: str) -> str:
    return filename.replace("\\", "/").rsplit("/", 1)[-1][:100]
