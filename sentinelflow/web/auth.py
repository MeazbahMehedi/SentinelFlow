"""Account creation, sign-in and sign-out."""

from __future__ import annotations

import sqlite3

from flask import Blueprint, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import generate_password_hash

from ..accounts import canonical_email
from ..security import TooManyAttempts, verify_password
from .helpers import services, store

bp = Blueprint("auth", __name__)


def sign_in(user: dict) -> None:
    session.clear()
    # Drop anything resolved for the anonymous request before sign-in.
    g.pop("workspace", None)
    g.pop("current_user", None)
    session.update(
        uid=user["id"],
        username=user["username"],
        sv=user.get("session_version") or 0,
        permanent=True,
    )


def create_account(first: bool = False) -> dict:
    identities = services().identities
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    email = canonical_email(request.form.get("email", ""))
    if not 3 <= len(username) <= 40 or not 12 <= len(password) <= 128:
        raise ValueError("Use a username of 3–40 characters and a password of 12–128 characters.")
    if "@" in username or any(ord(ch) < 32 for ch in username):
        raise ValueError("Your username cannot contain @ or control characters.")
    with services()._lock:
        if first and identities.one("SELECT id FROM users LIMIT 1"):
            raise ValueError("An administrator already exists. Use Create account instead.")
        if identities.one("SELECT id FROM users WHERE email=?", (email,)):
            raise ValueError("This email address already has an account. Sign in instead.")
        if identities.one("SELECT id FROM users WHERE lower(username)=lower(?)", (username,)):
            raise ValueError("That username is already in use.")
        try:
            uid = identities.execute(
                "INSERT INTO users(username,password,email,role) VALUES(?,?,?,?)",
                (
                    username,
                    generate_password_hash(password),
                    email,
                    "admin" if first else "analyst",
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("That email address or username already has an account.") from exc
    return identities.one("SELECT * FROM users WHERE id=?", (uid,))


@bp.route("/setup", methods=["GET", "POST"])
def setup():
    if request.method == "POST":
        try:
            user = create_account(first=True)
            sign_in(user)
            store().audit("workspace_created", user["username"])
            return redirect(url_for("pages.overview"))
        except ValueError as exc:
            flash(str(exc), "error")
    return render_template("auth.html", mode="setup")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if not services().identities.one("SELECT id FROM users LIMIT 1"):
        return redirect(url_for("auth.setup"))
    if request.method == "POST":
        try:
            user = create_account()
            sign_in(user)
            store().audit("account_created", "Private workspace initialized")
            return redirect(url_for("pages.overview"))
        except ValueError as exc:
            flash(str(exc), "error")
    return render_template("auth.html", mode="register")


def _find_user(identity: str) -> tuple[dict | None, str]:
    identities = services().identities
    if "@" in identity:
        try:
            identity = canonical_email(identity)
        except ValueError:
            pass
        return identities.one("SELECT * FROM users WHERE email=?", (identity,)), identity
    user = identities.one("SELECT * FROM users WHERE lower(username)=lower(?)", (identity,))
    return user, identity.lower()


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        limiter = services().limiter
        address = request.remote_addr or "local"
        user, identity = _find_user(request.form.get("username", "").strip())
        account = f"user:{user['id']}" if user else f"name:{identity}"
        try:
            limiter.check(address, account)
        except TooManyAttempts as exc:
            minutes = max(1, round(exc.retry_after / 60))
            abort(429, description=f"Too many sign-in attempts. Try again in {minutes} minute(s).")
        if verify_password(user["password"] if user else None, request.form.get("password", "")):
            limiter.success(account)
            sign_in(user)
            return redirect(url_for("pages.overview"))
        limiter.failure(address, account)
        flash("Email, username, or password is incorrect.", "error")
    return render_template("auth.html", mode="login")


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
