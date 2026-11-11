"""Read-side queries for dashboards, explorers and exports.

The dashboard summary is the most expensive query set. It is cached per
workspace and session filter and recomputed only when the workspace revision
changes, so any number of open browser tabs share one computation.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass

from .detection import RULE_INFO, rule_info

PAGE_SIZE = 50
SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 10, "low": 5}
OPEN_STATUSES = ("new", "investigating")
ALERT_STATUSES = ("new", "investigating", "resolved", "false_positive")
SEVERITIES = ("critical", "high", "medium", "low")
TIMELINE_BUCKETS = 40

_cache: dict[tuple, tuple[int, dict]] = {}
_cache_lock = threading.Lock()


def scope(sid: int | None, column: str = "session_id") -> tuple[str, list]:
    return (f" WHERE {column}=?", [sid]) if sid else ("", [])


def _compute_summary(store, sid: int | None) -> dict:
    w, args = scope(sid)
    with store.connect() as c:

        def one(sql, params):
            return dict(c.execute(sql, params).fetchone())

        def rows(sql, params):
            return [dict(r) for r in c.execute(sql, params).fetchall()]

        totals = one(
            "SELECT COUNT(*) packets, COALESCE(SUM(length),0) bytes, COUNT(DISTINCT src) sources, "
            "MIN(ts) first, MAX(ts) last FROM packets" + w,
            args,
        )
        totals["connections"] = one(
            "SELECT COUNT(*) n FROM (SELECT 1 FROM packets"
            + w
            + " GROUP BY src,sport,dst,dport,proto)",
            args,
        )["n"]
        totals["hosts"] = one(
            "SELECT COUNT(*) n FROM (SELECT src FROM packets"
            + w
            + " UNION SELECT dst FROM packets"
            + w
            + ")",
            args + args,
        )["n"]
        alert_counts = one(
            "SELECT COUNT(*) total, COALESCE(SUM(status IN ('new','investigating')),0) open "
            "FROM alerts" + w,
            args,
        )
        totals["alerts"] = alert_counts["total"]
        totals["open_alerts"] = alert_counts["open"]
        protocols = rows(
            "SELECT proto label, COUNT(*) value, SUM(length) bytes FROM packets"
            + w
            + " GROUP BY proto ORDER BY value DESC",
            args,
        )
        series = []
        if totals["first"] is not None:
            span = max(1.0, totals["last"] - totals["first"])
            width = max(1.0, span / (TIMELINE_BUCKETS - 1))
            buckets = rows(
                "SELECT CAST((ts-?)/? AS INTEGER) bucket, COUNT(*) packets, SUM(length) bytes "
                "FROM packets" + w + " GROUP BY bucket ORDER BY bucket",
                [totals["first"], width] + args,
            )
            by = {b["bucket"]: b for b in buckets}
            series = [
                dict(
                    ts=totals["first"] + i * width,
                    packets=by.get(i, {}).get("packets", 0),
                    bytes=by.get(i, {}).get("bytes", 0),
                )
                for i in range(max(by) + 1)
            ]
        sessions = rows("SELECT * FROM sessions ORDER BY id DESC LIMIT 100", [])
        alerts = rows("SELECT * FROM alerts" + w + " ORDER BY id DESC LIMIT 8", args)
        severity = rows("SELECT severity, COUNT(*) n FROM alerts" + w + " GROUP BY severity", args)
    for alert in alerts:
        alert["mitre"] = rule_info(alert["rule"]).mitre_id
    return dict(
        totals=totals,
        protocols=protocols,
        series=series,
        sessions=sessions,
        alerts=alerts,
        severity_totals={r["severity"]: r["n"] for r in severity},
    )


def summary(store, sid: int | None = None) -> dict:
    key = (store.path, sid)
    revision = store.revision
    with _cache_lock:
        cached = _cache.get(key)
        if cached and cached[0] == revision:
            return cached[1]
    result = _compute_summary(store, sid)
    result["revision"] = revision
    with _cache_lock:
        if len(_cache) > 512:
            _cache.clear()
        _cache[key] = (revision, result)
    return result


@dataclass
class Page:
    records: list[dict]
    count: int
    number: int

    @property
    def total_pages(self) -> int:
        return max(1, (self.count + PAGE_SIZE - 1) // PAGE_SIZE)


def _paginate(store, table: str, conditions: list[str], args: list, number: int) -> Page:
    clause = " WHERE " + " AND ".join(conditions) if conditions else ""
    count = store.one(f"SELECT COUNT(*) n FROM {table}" + clause, args)["n"]
    number = min(max(1, number), max(1, (count + PAGE_SIZE - 1) // PAGE_SIZE))
    records = store.rows(
        f"SELECT * FROM {table}" + clause + " ORDER BY id DESC LIMIT ? OFFSET ?",
        args + [PAGE_SIZE, (number - 1) * PAGE_SIZE],
    )
    return Page(records, count, number)


def _like(fields: list[str], query: str, conditions: list[str], args: list) -> None:
    if query:
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conditions.append("(" + " OR ".join(f"{f} LIKE ? ESCAPE '\\'" for f in fields) + ")")
        args.extend(["%" + escaped + "%"] * len(fields))


def traffic_page(store, sid, query: str, number: int) -> Page:
    conditions, args = (["session_id=?"], [sid]) if sid else ([], [])
    _like(["src", "dst", "proto", "dns"], query, conditions, args)
    return _paginate(store, "packets", conditions, args, number)


def alerts_page(store, sid, query: str, status: str, severity: str, number: int) -> Page:
    conditions, args = (["session_id=?"], [sid]) if sid else ([], [])
    _like(["src", "dst", "title", "rule"], query, conditions, args)
    if status in ALERT_STATUSES:
        conditions.append("status=?")
        args.append(status)
    if severity in SEVERITIES:
        conditions.append("severity=?")
        args.append(severity)
    page = _paginate(store, "alerts", conditions, args, number)
    for alert in page.records:
        alert["mitre"] = rule_info(alert["rule"]).mitre_id
    return page


def risk_scores(store, sid) -> dict[str, int]:
    """Per-source risk from open alerts: severity-weighted and capped at 100."""
    w, args = scope(sid)
    extra = " AND " if w else " WHERE "
    rows = store.rows(
        "SELECT src, severity, COUNT(*) n FROM alerts"
        + w
        + extra
        + "status IN ('new','investigating') GROUP BY src, severity",
        args,
    )
    scores: dict[str, int] = {}
    for row in rows:
        scores[row["src"]] = (
            scores.get(row["src"], 0) + SEVERITY_WEIGHT.get(row["severity"], 5) * row["n"]
        )
    return {ip: min(100, score) for ip, score in scores.items()}


def hosts(store, sid, limit: int = 100) -> list[dict]:
    w, args = scope(sid)
    rows = store.rows(
        "SELECT ip, SUM(sent) sent, SUM(received) received, SUM(n) packets FROM ("
        "SELECT src ip, SUM(length) sent, 0 received, COUNT(*) n FROM packets"
        + w
        + " GROUP BY src "
        "UNION ALL SELECT dst ip, 0 sent, SUM(length) received, COUNT(*) n FROM packets"
        + w
        + " GROUP BY dst) GROUP BY ip ORDER BY sent+received DESC LIMIT ?",
        args + args + [limit],
    )
    scores = risk_scores(store, sid)
    for row in rows:
        row["risk"] = scores.get(row["ip"], 0)
    return rows


def risk_level(score: int) -> str:
    if score >= 60:
        return "critical"
    if score >= 30:
        return "high"
    if score > 0:
        return "medium"
    return "low"


def host_profile(store, ip: str, sid) -> dict:
    cond = " AND session_id=?" if sid else ""
    extra = [sid] if sid else []
    stats = store.one(
        "SELECT COUNT(*) packets, MIN(ts) first, MAX(ts) last, "
        "COALESCE(SUM(CASE WHEN src=? THEN length ELSE 0 END),0) sent, "
        "COALESCE(SUM(CASE WHEN dst=? THEN length ELSE 0 END),0) received "
        "FROM packets WHERE (src=? OR dst=?)" + cond,
        [ip, ip, ip, ip] + extra,
    )
    services = store.rows(
        "SELECT proto, dport port, COUNT(*) n FROM packets WHERE dst=? AND proto IN ('TCP','UDP')"
        + cond
        + " GROUP BY proto, dport ORDER BY n DESC LIMIT 8",
        [ip] + extra,
    )
    peers = store.rows(
        "SELECT peer, COUNT(*) n, SUM(length) bytes FROM ("
        "SELECT dst peer, length FROM packets WHERE src=?" + cond + " UNION ALL "
        "SELECT src peer, length FROM packets WHERE dst=?" + cond + ") "
        "GROUP BY peer ORDER BY bytes DESC LIMIT 8",
        [ip] + extra + [ip] + extra,
    )
    score = risk_scores(store, sid).get(ip, 0)
    return dict(
        stats=stats, services=services, peers=peers, risk=score, risk_level=risk_level(score)
    )


def detection_breakdown(store, sid) -> dict:
    w, args = scope(sid)
    rule_counts = store.rows(
        "SELECT rule, COUNT(*) n FROM alerts" + w + " GROUP BY rule ORDER BY n DESC", args
    )
    tactics: dict[str, int] = {}
    for row in rule_counts:
        info = rule_info(row["rule"])
        row["title"] = info.title
        row["mitre"] = info.mitre_id
        tactics[info.tactic] = tactics.get(info.tactic, 0) + row["n"]
    severity_counts = store.rows(
        "SELECT severity, COUNT(*) n FROM alerts" + w + " GROUP BY severity", args
    )
    ports = store.rows(
        "SELECT proto, dport port, COUNT(*) n, SUM(length) bytes FROM packets"
        + w
        + (" AND " if w else " WHERE ")
        + "proto IN ('TCP','UDP') AND dport < 49152 GROUP BY proto, dport ORDER BY n DESC LIMIT 10",
        args,
    )
    return dict(
        rule_counts=rule_counts,
        severity_counts=severity_counts,
        tactics=sorted(tactics.items(), key=lambda x: -x[1]),
        top_ports=ports,
    )


def graph(store, sid, limit: int = 60) -> dict:
    """Who-talks-to-whom edges, heaviest first, for the host graph."""
    w, args = scope(sid)
    edges = store.rows(
        "SELECT src source, dst target, COUNT(*) packets, SUM(length) bytes FROM packets"
        + w
        + " GROUP BY src, dst ORDER BY bytes DESC LIMIT ?",
        args + [limit],
    )
    scores = risk_scores(store, sid)
    names = {e["source"] for e in edges} | {e["target"] for e in edges}
    nodes = [{"id": ip, "risk": scores.get(ip, 0)} for ip in sorted(names)]
    return dict(nodes=nodes, edges=edges)


def session_timelines(store) -> dict[int, dict]:
    """Capture span and alert positions for each session's progress timeline."""
    spans = {
        row["session_id"]: row
        for row in store.rows(
            "SELECT session_id, MIN(ts) first, MAX(ts) last FROM packets GROUP BY session_id"
        )
    }
    markers: dict[int, list] = {}
    for alert in store.rows(
        "SELECT id, session_id, ts, severity, title FROM alerts ORDER BY ts LIMIT 2000"
    ):
        span = spans.get(alert["session_id"])
        if not span:
            continue
        width = max(1e-6, span["last"] - span["first"])
        position = min(100.0, max(0.0, (alert["ts"] - span["first"]) / width * 100))
        markers.setdefault(alert["session_id"], []).append(dict(alert, position=round(position, 2)))
    return markers


def alert_evidence(store, alert: dict) -> list[dict]:
    window = alert["evidence"].get("window_seconds", 0)
    return store.rows(
        "SELECT * FROM packets WHERE session_id=? AND src=? AND ts BETWEEN ? AND ? "
        "ORDER BY ts DESC LIMIT 100",
        (alert["session_id"], alert["src"], alert["ts"] - window, alert["ts"]),
    )


def load_alert(store, aid: int) -> dict | None:
    alert = store.one("SELECT * FROM alerts WHERE id=?", (aid,))
    if alert:
        alert["evidence"] = json.loads(alert["evidence"])
        alert["info"] = rule_info(alert["rule"])
    return alert


__all__ = ["RULE_INFO", "summary"]
