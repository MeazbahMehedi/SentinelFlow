"""The ten navigation pages and the host and alert investigation views."""

from __future__ import annotations

import ipaddress

from flask import Blueprint, abort, render_template, request

from .. import analytics, capture
from ..github import DEVELOPERS
from .helpers import is_admin, page_number, selected_session, services, store

bp = Blueprint("pages", __name__)

PAGES = {
    "overview": ("Overview", "Your network, in focus."),
    "traffic": ("Live traffic", "Follow every connection."),
    "alerts": ("Threat alerts", "Signals worth investigating."),
    "replay": ("PCAP replay", "Turn captures into a live investigation."),
    "hosts": ("Host explorer", "Know the devices behind the traffic."),
    "analytics": ("Analytics", "Understand the shape of your network."),
    "rules": ("Detection rules", "Make every signal explainable."),
    "team": ("The developers", "Built with curiosity. Designed for clarity."),
    "repositories": ("GitHub projects", "Follow the work behind the developers."),
    "settings": ("Settings", "A workspace that works your way."),
}

NO_CAPTURE_STATUS = {
    "ready": False,
    "interfaces": [],
    "message": "Live host capture requires an administrator account. "
    "You can import and replay your own PCAP files.",
    "platform": "",
    "help_url": "https://scapy.readthedocs.io/en/stable/installation.html",
}


def render_page(page: str, **context):
    sid = selected_session()
    data = analytics.summary(store(), sid)
    title, subtitle = PAGES[page]
    return render_template(
        f"{page}.html", page=page, title=title, subtitle=subtitle, selected=sid, **data, **context
    )


@bp.get("/")
def overview():
    return render_page("overview")


@bp.get("/traffic")
def traffic():
    sid = selected_session()
    query = request.args.get("q", "")[:150]
    result = analytics.traffic_page(store(), sid, query, page_number())
    return render_page("traffic", result=result, q=query)


@bp.get("/alerts")
def alerts():
    sid = selected_session()
    query = request.args.get("q", "")[:150]
    status = request.args.get("status", "")
    severity = request.args.get("severity", "")
    result = analytics.alerts_page(store(), sid, query, status, severity, page_number())
    return render_page("alerts", result=result, q=query, status=status, severity=severity)


@bp.get("/replay")
def replay():
    status = capture.capture_diagnostics() if is_admin() else NO_CAPTURE_STATUS
    return render_page(
        "replay",
        capture_status=status,
        interfaces=status["interfaces"],
        timelines=analytics.session_timelines(store()),
    )


@bp.get("/hosts")
def hosts():
    sid = selected_session()
    return render_page("hosts", hosts=analytics.hosts(store(), sid))


@bp.get("/analytics", endpoint="analytics")
def analytics_page():
    sid = selected_session()
    return render_page(
        "analytics",
        hosts=analytics.hosts(store(), sid, limit=8),
        **analytics.detection_breakdown(store(), sid),
    )


@bp.get("/rules")
def rules():
    return render_page("rules", rules=store().config("rules"), settings=store().config("settings"))


@bp.get("/team")
def team():
    return render_page(
        "team", profiles=services().identities.rows("SELECT * FROM profiles ORDER BY id")
    )


@bp.get("/repositories")
def repositories():
    return render_page("repositories", github_developers=DEVELOPERS)


@bp.get("/settings")
def settings():
    accounts = (
        services().identities.rows(
            "SELECT id,username,email,role FROM users ORDER BY id LIMIT 1000"
        )
        if is_admin()
        else []
    )
    return render_page(
        "settings",
        settings=store().config("settings"),
        audit=store().rows("SELECT * FROM audit ORDER BY id DESC LIMIT 30"),
        accounts=accounts,
    )


@bp.get("/hosts/<path:ip>")
def host_detail(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        abort(404)
    sid = selected_session()
    cond = " AND session_id=?" if sid else ""
    args = [ip, ip] + ([sid] if sid else [])
    packets = store().rows(
        "SELECT * FROM packets WHERE (src=? OR dst=?)" + cond + " ORDER BY id DESC LIMIT 100", args
    )
    alerts = store().rows(
        "SELECT * FROM alerts WHERE (src=? OR dst=?)" + cond + " ORDER BY id DESC LIMIT 50", args
    )
    return render_template(
        "host_detail.html",
        page="hosts",
        title="Host investigation",
        subtitle=ip,
        selected=sid,
        records=packets,
        alerts=alerts,
        ip=ip,
        profile=analytics.host_profile(store(), ip, sid),
    )


@bp.get("/alerts/<int:aid>")
def alert_detail(aid: int):
    alert = analytics.load_alert(store(), aid)
    if not alert:
        abort(404)
    session_row = store().one("SELECT * FROM sessions WHERE id=?", (alert["session_id"],))
    others = store().rows(
        "SELECT * FROM alerts WHERE session_id=? AND src=? AND id<>? ORDER BY ts LIMIT 30",
        (alert["session_id"], alert["src"], aid),
    )
    return render_template(
        "alert_detail.html",
        page="alerts",
        title="Alert investigation",
        subtitle=alert["title"],
        alert=alert,
        related=analytics.alert_evidence(store(), alert),
        others=others,
        session_row=session_row,
    )
