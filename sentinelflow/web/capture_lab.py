"""Capture lab actions: imports, replay controls, live capture and session retention."""

from __future__ import annotations

import secrets
import tempfile
from pathlib import Path

from flask import Blueprint, abort, flash, redirect, request, url_for

from ..engine import MAX_SESSIONS
from ..integrations import import_eve, read_eve
from ..packets import make_demo, read_capture
from .helpers import engine, require_admin, services, store, upload_name

bp = Blueprint("capture", __name__)

REPLAY_SPEEDS = (0.25, 0.5, 1, 2, 4, 8, 16, 32)
IDLE_GAP_SECONDS = 2.0
MAX_UPLOAD_BYTES = 32 * 1024 * 1024


def _ensure_capacity() -> None:
    if store().one("SELECT COUNT(*) n FROM sessions")["n"] >= MAX_SESSIONS:
        raise ValueError("Session limit reached. Delete an older session first.")


def _speed() -> float:
    try:
        speed = float(request.form.get("speed", "1"))
    except ValueError:
        raise ValueError("Invalid replay speed.") from None
    if speed not in REPLAY_SPEEDS:
        raise ValueError("Choose one of the supported replay speeds.")
    return speed


@bp.post("/replay/upload")
def upload():
    f = request.files.get("capture")
    if (
        not f
        or not f.filename
        or Path(f.filename).suffix.lower() not in (".pcap", ".pcapng", ".cap")
    ):
        flash("Choose a PCAP, PCAPNG, or CAP capture.", "error")
        return redirect(url_for("pages.replay"))
    tmp_dir = services().root / "tmp"
    path = None
    try:
        with tempfile.NamedTemporaryFile(dir=tmp_dir, delete=False, suffix=".pcap") as temp:
            path = Path(temp.name)
            f.save(temp)
        if path.stat().st_size > MAX_UPLOAD_BYTES:
            raise ValueError("The capture limit is 32 MiB.")
        _ensure_capacity()
        sid = engine().import_events(upload_name(f.filename), read_capture(path))
        flash("Capture imported. Press Start to replay it.", "success")
        return redirect(url_for("pages.replay", session=sid))
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("pages.replay"))
    finally:
        if path:
            path.unlink(missing_ok=True)


@bp.post("/replay/eve")
def eve_upload():
    f = request.files.get("eve")
    if not f or not f.filename:
        abort(400, description="Select an EVE JSON file.")
    path = services().root / "tmp" / f"{secrets.token_hex(12)}.json"
    try:
        _ensure_capacity()
        f.save(path)
        if path.stat().st_size > MAX_UPLOAD_BYTES:
            raise ValueError("EVE file limit is 32 MiB.")
        sid = import_eve(store(), upload_name(f.filename), read_eve(path))
        flash(
            "Suricata alerts imported. This session contains alerts, not packet evidence.",
            "success",
        )
        return redirect(url_for("pages.alerts", session=sid))
    except (ValueError, UnicodeError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("pages.replay"))
    finally:
        path.unlink(missing_ok=True)


@bp.post("/replay/demo")
def demo():
    try:
        _ensure_capacity()
    except ValueError as exc:
        abort(400, description=str(exc))
    path = services().root / "tmp" / f"{secrets.token_hex(12)}.pcap"
    try:
        make_demo(path)
        sid = engine().import_events("Guided threat simulation", read_capture(path), "demo")
    finally:
        path.unlink(missing_ok=True)
    flash("Demonstration capture loaded. Start replay at 4× for a quick walkthrough.", "success")
    return redirect(url_for("pages.replay", session=sid))


@bp.post("/sessions/<int:sid>/<action>")
def control(sid: int, action: str):
    try:
        if action == "start":
            max_gap = IDLE_GAP_SECONDS if request.form.get("skip_idle") == "on" else None
            engine().start_replay(sid, _speed(), max_gap=max_gap)
        else:
            engine().control(sid, action, _speed() if action == "speed" else None)
        flash("Session command accepted.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("pages.replay", session=sid))


@bp.post("/live/start")
def live_start():
    require_admin()
    try:
        sid = engine().start_live(request.form.get("interface", ""))
        flash("Live monitoring started.", "success")
        return redirect(url_for("pages.replay", session=sid))
    except Exception as exc:  # noqa: BLE001 - driver errors are shown to the operator
        flash("Capture could not start. " + str(exc)[:600], "error")
        return redirect(url_for("pages.replay"))


@bp.post("/sessions/<int:sid>/delete")
def delete_session(sid: int):
    eng = engine()
    with eng.lock:
        if eng.active_id == sid and eng.busy:
            flash("Stop this session before deleting it.", "error")
        else:
            store().execute("DELETE FROM sessions WHERE id=?", (sid,))
            store().audit("session_deleted", str(sid))
            flash("Session and its retained traffic were deleted.", "success")
    return redirect(url_for("pages.settings"))
