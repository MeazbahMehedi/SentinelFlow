"""HTTP layer: blueprints, request guards, template helpers and error pages."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime

from flask import Flask, abort, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import HTTPException

from ..detection import RULE_INFO, rule_info
from ..version import __version__
from . import admin, alerts, api, auth, capture_lab, exports, pages
from .helpers import current_user, is_admin, services

PUBLIC_ENDPOINTS = {"auth.login", "auth.setup", "auth.register", "static"}

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data: https://avatars.githubusercontent.com; connect-src 'self'; "
    "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
)


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(24)
    return session["csrf"]


def register(app: Flask) -> None:
    for module in (auth, pages, capture_lab, alerts, admin, api, exports):
        app.register_blueprint(module.bp)

    @app.context_processor
    def template_context():
        return dict(
            csrf_token=csrf_token,
            pages=pages.PAGES,
            rule_info=RULE_INFO,
            info_for=rule_info,
            current_user=current_user(),
            is_admin=is_admin(),
            version=__version__,
        )

    @app.template_filter("utc")
    def utc(value):
        if value is None:
            return "—"
        try:
            return datetime.fromtimestamp(float(value), UTC).strftime("%d %b %Y · %H:%M:%S")
        except (OverflowError, ValueError, OSError):
            return "Invalid timestamp"

    @app.template_filter("bytes")
    def human_bytes(n):
        n = float(n or 0)
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024 or unit == "GB":
                return f"{n:,.0f} B" if unit == "B" else f"{n:,.1f} {unit}"
            n /= 1024
        return f"{n:,.1f} GB"

    @app.before_request
    def protect():
        if request.endpoint == "static":
            return None
        if request.method == "POST":
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            if not secrets.compare_digest(str(token), str(session.get("csrf", "missing"))):
                abort(400, description="Your form expired. Refresh the page and try again.")
        if session.get("uid"):
            user = current_user()
            if not user or user["session_version"] != session.get("sv", 0):
                # Account removed, password changed or sessions revoked elsewhere.
                csrf = session.get("csrf")
                session.clear()
                if csrf:
                    session["csrf"] = csrf
                g.pop("current_user", None)
                g.pop("workspace", None)
        identities = services().identities
        has_user = bool(identities.one("SELECT id FROM users LIMIT 1"))
        if not has_user and request.endpoint not in PUBLIC_ENDPOINTS:
            return redirect(url_for("auth.setup"))
        if has_user and request.endpoint == "auth.setup":
            return redirect(
                url_for("pages.overview") if session.get("uid") else url_for("auth.login")
            )
        if has_user and not session.get("uid") and request.endpoint not in PUBLIC_ENDPOINTS:
            if request.path.startswith("/api/"):
                return jsonify(error="Authentication required."), 401
            return redirect(url_for("auth.login"))
        return None

    @app.after_request
    def security_headers(response):
        response.headers.update(
            {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "same-origin",
                "Cache-Control": "no-store",
                "Content-Security-Policy": CONTENT_SECURITY_POLICY,
            }
        )
        return response

    @app.errorhandler(HTTPException)
    def http_error(e):
        if request.path.startswith("/api/"):
            return jsonify(error=e.description), e.code
        return render_template("error.html", code=e.code, message=e.description), e.code
