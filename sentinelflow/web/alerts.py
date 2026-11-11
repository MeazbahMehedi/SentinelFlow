"""Alert triage: single and bulk status updates, evidence export."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from flask import Blueprint, Response, abort, flash, redirect, request, url_for

from .. import analytics
from .helpers import store

bp = Blueprint("alerts", __name__)

MAX_BULK = 500


@bp.post("/alerts/<int:aid>")
def update(aid: int):
    if not store().one("SELECT id FROM alerts WHERE id=?", (aid,)):
        abort(404)
    status = request.form.get("status", "")
    if status not in analytics.ALERT_STATUSES:
        abort(400)
    store().execute(
        "UPDATE alerts SET status=?, note=? WHERE id=?",
        (status, request.form.get("note", "")[:3000], aid),
    )
    store().audit("alert_updated", f"{aid}: {status}")
    flash("Investigation saved.", "success")
    return redirect(url_for("pages.alert_detail", aid=aid))


@bp.post("/alerts/bulk")
def bulk_update():
    status = request.form.get("status", "")
    if status not in analytics.ALERT_STATUSES:
        abort(400, description="Choose a valid status.")
    try:
        ids = sorted({int(x) for x in request.form.getlist("ids")})[:MAX_BULK]
    except ValueError:
        abort(400, description="Invalid alert selection.")
    if not ids:
        flash("Select at least one alert.", "error")
    else:
        marks = ",".join("?" * len(ids))
        with store().connect() as c:
            changed = c.execute(
                f"UPDATE alerts SET status=? WHERE id IN ({marks})", [status, *ids]
            ).rowcount
        store().audit("alerts_bulk_updated", f"{changed} alerts: {status}")
        flash(f"{changed} alert(s) marked {status.replace('_', ' ')}.", "success")
    target = request.form.get("next", "")
    if not target.startswith("/alerts") or target.startswith("//"):
        target = url_for("pages.alerts")
    return redirect(target)


@bp.get("/alerts/<int:aid>/evidence.json")
def evidence(aid: int):
    alert = analytics.load_alert(store(), aid)
    if not alert:
        abort(404)
    info = alert.pop("info")
    report = {
        "generated_utc": datetime.now(UTC).isoformat(),
        "alert": alert,
        "mitre_attack": {
            "technique": info.mitre_id,
            "name": info.mitre_name,
            "tactic": info.tactic,
        },
        "trigger_window_packets": analytics.alert_evidence(store(), alert),
        "interpretation": "Behavioral indicator, not proof of compromise.",
    }
    return Response(
        json.dumps(report, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=sentinelflow-alert-{aid}.json"},
    )
