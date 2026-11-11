"""CSV and JSON exports of the selected scope."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

from flask import Blueprint, Response, abort

from .. import analytics
from ..version import __version__
from .helpers import selected_session, store

bp = Blueprint("exports", __name__)

FIELDS = {
    "packets": [
        "id",
        "session_id",
        "ts",
        "src",
        "dst",
        "sport",
        "dport",
        "proto",
        "length",
        "flags",
        "dns",
    ],
    "alerts": [
        "id",
        "session_id",
        "ts",
        "rule",
        "severity",
        "src",
        "dst",
        "title",
        "evidence",
        "status",
        "note",
    ],
}
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _cell(value):
    """Defuse spreadsheet formulas in user-supplied notes and captured DNS labels."""
    text = str(value)
    return "'" + text if text.lstrip().startswith(FORMULA_PREFIXES) else value


@bp.get("/export/<kind>")
def export(kind: str):
    sid = selected_session()
    if kind == "summary":
        report = dict(analytics.summary(store(), sid))
        report["generated_utc"] = datetime.now(UTC).isoformat()
        report["generator"] = f"SentinelFlow {__version__}"
        report["interpretation"] = (
            "Behavioral indicators, not proof of compromise. "
            "Synthetic sessions are explicitly labeled demo."
        )
        return Response(
            json.dumps(report, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=sentinelflow-report.json"},
        )
    if kind not in FIELDS:
        abort(404)
    w, args = analytics.scope(sid)
    rows = store().rows("SELECT * FROM " + kind + w + " ORDER BY id DESC LIMIT 100000", args)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    fields = FIELDS[kind]
    writer.writerow(fields)
    for row in rows:
        writer.writerow([_cell(row[k]) for k in fields])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=sentinelflow-{kind}.csv"},
    )
