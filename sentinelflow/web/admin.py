"""Workspace configuration, account security, roles and developer profiles."""

from __future__ import annotations

import io
import ipaddress
import re
import secrets
import sqlite3
from urllib.parse import urlparse

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from PIL import Image, UnidentifiedImageError
from werkzeug.security import generate_password_hash

from ..accounts import canonical_email
from ..detection import RULE_INFO
from ..security import verify_password
from .auth import sign_in
from .helpers import current_user, is_admin, require_admin, services, store

bp = Blueprint("admin", __name__)

_DOMAIN = re.compile(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}")
MAX_UPLOAD = 5 * 1024 * 1024


@bp.post("/rules")
def save_rules():
    rules = store().config("rules")
    try:
        for key in RULE_INFO:
            threshold = int(request.form.get(key + "_threshold", "0"))
            window = int(request.form.get(key + "_window", "0"))
            if not 1 <= threshold <= 100_000_000 or not 1 <= window <= 3600:
                raise ValueError("Thresholds must be 1–100,000,000 and windows 1–3,600 seconds.")
            rules[key] = {
                "enabled": request.form.get(key + "_enabled") == "on",
                "threshold": threshold,
                "window": window,
            }
        store().set_config("rules", rules)
        store().audit("rules_saved", "Applies to new or restarted sessions")
        flash("Rules saved. Start a new session or restart a capture to apply them.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("pages.rules"))


def _indicator(value: str) -> str:
    """Normalize an IP address or CIDR network; single addresses lose their prefix."""
    network = ipaddress.ip_network(value, strict=False)
    return str(network.network_address) if network.num_addresses == 1 else str(network)


def _lines(field: str) -> list[str]:
    return [x.strip() for x in request.form.get(field, "").splitlines() if x.strip()]


@bp.post("/settings")
def save_settings():
    try:
        indicators = [_indicator(x) for x in _lines("indicators")]
        domains = [x.lower().rstrip(".") for x in _lines("domain_indicators")]
        for domain in domains:
            if not _DOMAIN.fullmatch(domain):
                raise ValueError(f"{domain[:80]} is not a valid domain name.")
        networks = [str(ipaddress.ip_network(x, strict=False)) for x in _lines("local_networks")]
        limit = int(request.form.get("max_packets", "100000"))
        if (
            not networks
            or len(indicators) > 1000
            or len(domains) > 1000
            or len(networks) > 100
            or not 1000 <= limit <= 500_000
        ):
            raise ValueError(
                "Supply 1–100 local networks, up to 1,000 indicators of each kind, "
                "and a packet limit of 1,000–500,000."
            )
        store().set_config(
            "settings",
            dict(
                indicators=indicators,
                domain_indicators=domains,
                local_networks=networks,
                max_packets=limit,
            ),
        )
        store().audit("settings_saved")
        flash("Settings saved. Detection changes apply to new sessions.", "success")
    except ValueError as exc:
        flash("Invalid settings: " + str(exc), "error")
    return redirect(url_for("pages.settings"))


def _user() -> dict:
    return services().identities.one("SELECT * FROM users WHERE id=?", (session["uid"],))


@bp.post("/account/email")
def link_email():
    user = _user()
    try:
        if user["email"]:
            raise ValueError("This account already has an email address linked.")
        if not verify_password(user["password"], request.form.get("password", "")):
            raise ValueError("Your current password is incorrect.")
        email = canonical_email(request.form.get("email", ""))
        services().identities.execute("UPDATE users SET email=? WHERE id=?", (email, user["id"]))
        flash("Email address linked. You can now sign in with it.", "success")
    except sqlite3.IntegrityError:
        flash("Unable to link this email. The address may already be registered.", "error")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("pages.settings"))


def _rotate_sessions(user_id: int, **changes) -> None:
    """Apply ``changes`` and invalidate every other signed-in browser."""
    identities = services().identities
    assignments = "".join(f"{key}=?, " for key in changes)
    identities.execute(
        f"UPDATE users SET {assignments}session_version=session_version+1 WHERE id=?",
        (*changes.values(), user_id),
    )
    sign_in(identities.one("SELECT * FROM users WHERE id=?", (user_id,)))


@bp.post("/settings/password")
def password():
    user = _user()
    new = request.form.get("new_password", "")
    if not verify_password(user["password"], request.form.get("current_password", "")) or not (
        12 <= len(new) <= 128
    ):
        flash("Check your current password. New password must be 12–128 characters.", "error")
    else:
        _rotate_sessions(user["id"], password=generate_password_hash(new))
        store().audit("password_changed", "Other signed-in sessions were signed out")
        flash("Password updated. Other signed-in browsers were signed out.", "success")
    return redirect(url_for("pages.settings"))


@bp.post("/account/sessions/revoke")
def revoke_sessions():
    _rotate_sessions(session["uid"])
    store().audit("sessions_revoked")
    flash("Every other browser signed in to this account was signed out.", "success")
    return redirect(url_for("pages.settings"))


@bp.post("/accounts/<int:uid>/role")
def account_role(uid: int):
    require_admin()
    role = request.form.get("role", "")
    if role not in ("admin", "analyst") or uid == session["uid"]:
        abort(
            400,
            description="Choose a valid role for another account. You cannot change your own role.",
        )
    identities = services().identities
    if not identities.one("SELECT id FROM users WHERE id=?", (uid,)):
        abort(404)
    identities.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
    if role == "analyst":
        other_store, other_engine = services().workspace_for(uid)
        with other_engine.lock:
            active = other_store.one(
                "SELECT source FROM sessions WHERE id=?", (other_engine.active_id,)
            )
            if active and active["source"] == "live" and other_engine.busy:
                other_engine.stop_event.set()
    store().audit("account_role_changed", f"Account {uid}: {role}")
    flash("Account permissions updated.", "success")
    return redirect(url_for("pages.settings"))


PROFILE_FIELDS = [
    ("name", 80),
    ("role", 120),
    ("bio", 3000),
    ("skills", 500),
    ("email", 160),
    ("github", 300),
    ("linkedin", 300),
    ("website", 300),
]


def _save_upload(kind: str, data: bytes, target) -> None:
    if kind == "photo":
        with Image.open(io.BytesIO(data)) as image:
            if image.width * image.height > 20_000_000:
                raise ValueError("Photo is too large. Use an image below 20 megapixels.")
            image.thumbnail((1000, 1000))
            image.convert("RGB").save(target, "PNG")
    else:
        if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-2048:]:
            raise ValueError("CV must be a PDF file.")
        target.write_bytes(data)


@bp.route("/team/<int:pid>/edit", methods=["GET", "POST"])
def profile_edit(pid: int):
    if not is_admin():
        abort(403, description="Only the administrator can edit the project developer profiles.")
    identities = services().identities
    media_dir = services().root / "media"
    profile = identities.one("SELECT * FROM profiles WHERE id=?", (pid,))
    if not profile:
        abort(404)
    if request.method == "POST":
        values = {key: request.form.get(key, "").strip()[:limit] for key, limit in PROFILE_FIELDS}
        new_files, old_files = [], []
        try:
            if not values["name"]:
                raise ValueError("A developer name is required.")
            for key in ("github", "linkedin", "website"):
                parsed = urlparse(values[key])
                if values[key] and (parsed.scheme not in ("http", "https") or not parsed.netloc):
                    raise ValueError("Profile links must be full HTTP or HTTPS URLs.")
            if values["email"] and (
                "@" not in values["email"] or any(x in values["email"] for x in "\r\n")
            ):
                raise ValueError("Enter a valid email address.")
            for kind in ("photo", "cv"):
                field = request.files.get(kind)
                if not field or not field.filename:
                    continue
                data = field.read(MAX_UPLOAD + 1)
                if len(data) > MAX_UPLOAD:
                    raise ValueError("Each photo or CV must be at most 5 MiB.")
                name = secrets.token_hex(20) + (".png" if kind == "photo" else ".pdf")
                target = media_dir / name
                _save_upload(kind, data, target)
                new_files.append(target)
                if profile[kind]:
                    old_files.append(media_dir / profile[kind])
                profile[kind] = name
            identities.execute(
                "UPDATE profiles SET name=?,role=?,bio=?,skills=?,email=?,github=?,linkedin=?,"
                "website=?,photo=?,cv=? WHERE id=?",
                tuple(values[k] for k, _ in PROFILE_FIELDS)
                + (profile["photo"], profile["cv"], pid),
            )
            for target in old_files:
                target.unlink(missing_ok=True)
            store().audit("profile_updated", f"Developer {pid}")
            flash("Developer profile updated.", "success")
            return redirect(url_for("pages.team"))
        except (ValueError, UnidentifiedImageError, Image.DecompressionBombError, OSError) as exc:
            for target in new_files:
                target.unlink(missing_ok=True)
            flash("Profile could not be saved: " + str(exc), "error")
    return render_template(
        "profile_edit.html",
        page="team",
        title="Edit developer",
        subtitle="Make this project yours.",
        profile=profile,
    )


@bp.get("/media/<name>")
def media(name: str):
    if not services().identities.one("SELECT id FROM profiles WHERE photo=? OR cv=?", (name, name)):
        abort(404)
    target = services().root / "media" / name
    if not target.is_file():
        abort(404)
    is_pdf = name.endswith(".pdf")
    return send_file(
        target, as_attachment=is_pdf, download_name="developer-cv.pdf" if is_pdf else name
    )


__all__ = ["bp", "current_user"]
