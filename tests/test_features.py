import json
import threading
import time

import pytest

from sentinelflow import analytics
from sentinelflow import engine as engine_module
from sentinelflow.packets import make_packet, normalize_bytes


def scan_events(n=15):
    return [
        normalize_bytes(make_packet("10.0.0.1", "10.0.0.2", dport=30 + i, flags=2), 100 + i * 0.01)
        for i in range(n)
    ]


def run(app, events):
    engine = app.extensions["engine"]
    sid = engine.import_events("sample", events)
    engine.start_replay(sid, 32)
    engine.worker.join(5)
    return sid


def test_snapshot_revision_short_circuits(client, app):
    first = client.get("/api/snapshot").json
    assert "revision" in first
    assert client.get(f"/api/snapshot?rev={first['revision']}").status_code == 204
    run(app, scan_events())
    changed = client.get(f"/api/snapshot?rev={first['revision']}")
    assert changed.status_code == 200 and changed.json["totals"]["packets"] == 15


def test_summary_is_cached_until_data_changes(app):
    store = app.extensions["store"]
    a = analytics.summary(store)
    assert analytics.summary(store) is a
    store.audit("touch")
    assert analytics.summary(store) is not a


def test_batched_writer_keeps_counts(app):
    events = [
        normalize_bytes(make_packet("10.0.0.1", "10.0.0.9", sport=1000 + i), 100 + i * 0.001)
        for i in range(1200)
    ]
    sid = run(app, events)
    store = app.extensions["store"]
    assert store.one("SELECT processed FROM sessions WHERE id=?", (sid,))["processed"] == 1200
    assert store.one("SELECT COUNT(*) n FROM packets")["n"] == 1200


def test_retention_limit_stops_with_error(app):
    store = app.extensions["store"]
    settings = store.config("settings")
    settings["max_packets"] = 1000
    store.set_config("settings", settings)
    events = [
        normalize_bytes(make_packet("10.0.0.1", "10.0.0.9", sport=1000 + i), 100 + i * 0.001)
        for i in range(1100)
    ]
    sid = run(app, events)
    row = store.one("SELECT * FROM sessions WHERE id=?", (sid,))
    assert row["status"] == "error" and "limit" in row["error"]
    assert store.one("SELECT COUNT(*) n FROM packets")["n"] == 1000


def test_idle_gaps_are_compressed(app):
    engine = app.extensions["engine"]
    events = [normalize_bytes(make_packet("10.0.0.1", "10.0.0.2"), ts) for ts in (100, 160, 220)]
    sid = engine.import_events("gappy", events)
    started = time.monotonic()
    engine.start_replay(sid, 32, max_gap=0.5)
    engine.worker.join(5)
    assert time.monotonic() - started < 2
    assert app.extensions["store"].one("SELECT status FROM sessions")["status"] == "finished"


def test_only_one_live_capture_per_host(app, monkeypatch):
    assert engine_module._live_lock.acquire(blocking=False)
    try:
        with pytest.raises(ValueError, match="Only one live capture"):
            app.extensions["engine"].start_live("eth0")
    finally:
        engine_module._live_lock.release()


def test_live_lock_released_when_socket_fails(app, monkeypatch):
    def fail(_):
        raise ValueError("no adapter")

    monkeypatch.setattr("sentinelflow.engine.open_capture_socket", fail)
    with pytest.raises(ValueError, match="no adapter"):
        app.extensions["engine"].start_live("eth0")
    assert engine_module._live_lock.acquire(blocking=False)
    engine_module._live_lock.release()


def test_bulk_alert_triage(client, token, app):
    events = scan_events() + [
        normalize_bytes(make_packet("10.0.0.1", "203.0.113.66", sport=999), 101)
    ]
    run(app, events)
    store = app.extensions["store"]
    ids = [r["id"] for r in store.rows("SELECT id FROM alerts")]
    assert len(ids) >= 2
    r = client.post(
        "/alerts/bulk",
        data={
            "csrf_token": token,
            "status": "resolved",
            "ids": ids,
            "next": "/alerts?severity=high",
        },
    )
    assert r.status_code == 302 and r.headers["Location"].endswith("/alerts?severity=high")
    assert {r["status"] for r in store.rows("SELECT status FROM alerts")} == {"resolved"}


def test_bulk_redirect_is_local_only(client, token):
    r = client.post(
        "/alerts/bulk",
        data={"csrf_token": token, "status": "resolved", "ids": [], "next": "//evil.test/alerts"},
    )
    assert r.headers["Location"].endswith("/alerts")


def test_alert_evidence_export(client, app):
    run(app, scan_events())
    report = json.loads(client.get("/alerts/1/evidence.json").data)
    assert report["mitre_attack"]["technique"] == "T1046"
    assert len(report["trigger_window_packets"]) >= 12


def test_graph_and_host_profile(client, app):
    run(app, scan_events())
    data = client.get("/api/graph").json
    assert {n["id"] for n in data["nodes"]} == {"10.0.0.1", "10.0.0.2"}
    assert next(n for n in data["nodes"] if n["id"] == "10.0.0.1")["risk"] == 20
    page = client.get("/hosts/10.0.0.2")
    assert page.status_code == 200 and b"TCP/30" in page.data


def test_settings_accept_cidr_and_domains(client, token, app):
    client.post(
        "/settings",
        data={
            "csrf_token": token,
            "indicators": "203.0.113.5\n198.51.100.0/24",
            "domain_indicators": "Bad.Example.\n",
            "local_networks": "10.0.0.0/8",
            "max_packets": 100000,
        },
    )
    settings = app.extensions["store"].config("settings")
    assert settings["indicators"] == ["203.0.113.5", "198.51.100.0/24"]
    assert settings["domain_indicators"] == ["bad.example"]


def test_settings_reject_bad_domain(client, token, app):
    previous = app.extensions["store"].config("settings")
    client.post(
        "/settings",
        data={
            "csrf_token": token,
            "indicators": "",
            "domain_indicators": "not a domain",
            "local_networks": "10.0.0.0/8",
            "max_packets": 100000,
        },
    )
    assert app.extensions["store"].config("settings") == previous


def test_replay_page_shows_timeline_markers(client, app):
    run(app, scan_events())
    assert b"timeline-marker" in client.get("/replay").data


def test_concurrent_snapshots_share_one_computation(client, app):
    run(app, scan_events())
    results = []

    def fetch():
        results.append(client.get("/api/snapshot").status_code)

    threads = [threading.Thread(target=fetch) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == [200] * 8
