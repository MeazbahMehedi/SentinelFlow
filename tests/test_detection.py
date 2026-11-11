from copy import deepcopy

import pytest

from sentinelflow.db import DEFAULT_RULES, DEFAULT_SETTINGS
from sentinelflow.detection import (
    RULE_INFO,
    Detector,
    base_domain,
    shannon_entropy,
    tunneling_score,
)
from sentinelflow.flows import FlowTable


def event(**kwargs):
    e = dict(
        ts=100,
        src="10.0.0.10",
        dst="10.0.0.20",
        sport=45000,
        dport=443,
        proto="TCP",
        length=100,
        flags="A",
        dns="",
        dns_response=False,
    )
    e.update(kwargs)
    return e


def only(rule, threshold=3, window=None):
    rules = deepcopy(DEFAULT_RULES)
    for key in rules:
        rules[key]["enabled"] = key == rule
    rules[rule]["threshold"] = threshold
    if window:
        rules[rule]["window"] = window
    return Detector(rules, deepcopy(DEFAULT_SETTINGS))


@pytest.fixture
def detector():
    return Detector(deepcopy(DEFAULT_RULES), deepcopy(DEFAULT_SETTINGS))


def test_every_rule_has_mitre_mapping():
    assert set(RULE_INFO) == set(DEFAULT_RULES)
    assert all(info.mitre_id.startswith("T") and info.tactic for info in RULE_INFO.values())


@pytest.mark.parametrize(
    "rule",
    ["port_scan", "host_scan", "syn_burst", "dns_burst", "outbound_volume", "indicator_match"],
)
def test_rules_trigger_with_evidence(rule):
    d = only(rule, threshold=3 if rule != "outbound_volume" else 250)
    hits = []
    for i in range(3):
        kwargs = dict(ts=100 + i * 0.1, sport=45000 + i)
        if rule == "port_scan":
            kwargs.update(dport=80 + i, flags="S")
        if rule == "host_scan":
            kwargs.update(dst=f"10.0.0.{20 + i}", flags="S")
        if rule == "syn_burst":
            kwargs["flags"] = "S"
        if rule == "dns_burst":
            kwargs.update(proto="UDP", dns="example.test")
        if rule in ("outbound_volume", "indicator_match"):
            kwargs["dst"] = "203.0.113.66"
        hits += d.observe(event(**kwargs))
    assert len(hits) == 1
    assert hits[0]["rule"] == rule
    assert hits[0]["evidence"]["observed"] >= hits[0]["evidence"]["threshold"]
    assert hits[0]["evidence"]["mitre"].startswith(RULE_INFO[rule].mitre_id)


def test_normal_traffic_no_alert(detector):
    assert not [a for i in range(50) for a in detector.observe(event(ts=100 + i * 0.1))]


def test_window_expiration(detector):
    for i in range(20):
        assert not detector.observe(event(ts=100 + i * 31, dport=100 + i, flags="S"))


def test_threshold_boundary_and_duplicate_suppression(detector):
    for i in range(11):
        assert not detector.observe(event(dport=100 + i, ts=100 + i * 0.1, flags="S"))
    assert detector.observe(event(dport=111, ts=101.1, flags="S"))[0]["rule"] == "port_scan"
    assert not detector.observe(event(dport=112, ts=101.2, flags="S"))


def test_server_replies_are_not_a_port_scan(detector):
    """Regression: a server answering many client connections used to look like a scan."""
    hits = []
    for i in range(30):
        ts = 1000 + i * 0.5
        client = dict(src="10.0.0.5", dst="10.0.0.80", sport=50000 + i, dport=443)
        hits += detector.observe(event(ts=ts, flags="S", **client))
        hits += detector.observe(
            event(
                ts=ts + 0.01,
                src="10.0.0.80",
                dst="10.0.0.5",
                sport=443,
                dport=50000 + i,
                flags="SA",
            )
        )
        hits += detector.observe(event(ts=ts + 0.02, flags="A", **client))
    assert not hits


def test_mid_stream_traffic_is_not_a_scan(detector):
    """Capture started mid-connection: ACK-only packets never open flows."""
    hits = [
        a
        for i in range(40)
        for a in detector.observe(event(ts=100 + i * 0.1, dport=1000 + i, flags="PA"))
    ]
    assert not hits


def test_browsing_many_internet_hosts_is_not_a_host_scan(detector):
    hits = [
        a
        for i in range(25)
        for a in detector.observe(
            event(ts=100 + i, src="192.168.1.20", dst=f"151.101.{i}.1", sport=51000 + i, flags="S")
        )
    ]
    assert not hits


def test_multicast_and_broadcast_are_ignored(detector):
    hits = []
    for i in range(30):
        for dst in ("224.0.0.251", "255.255.255.255", "10.255.255.255", "ff02::fb"):
            hits += detector.observe(
                event(
                    ts=100 + i * 0.1, dst=dst, proto="UDP", sport=5353 + i, dport=5353, length=9000
                )
            )
    assert not hits


def test_disabled_rule():
    rules = deepcopy(DEFAULT_RULES)
    for rule in rules.values():
        rule["enabled"] = False
    d = Detector(rules, DEFAULT_SETTINGS)
    assert not d.observe(event(dst="203.0.113.66", flags="S"))


def test_syn_ack_not_counted(detector):
    assert not [
        a for i in range(100) for a in detector.observe(event(ts=100 + i * 0.01, flags="SA"))
    ]


def test_dns_answers_not_queries(detector):
    hits = [
        a
        for i in range(100)
        for a in detector.observe(
            event(ts=100 + i * 0.01, proto="UDP", dns="example.test", dns_response=True)
        )
    ]
    assert not hits


def test_late_event_does_not_rewind_window(detector):
    detector.observe(event(ts=1000))
    assert not detector.observe(event(ts=100, dst="203.0.113.66"))
    assert detector.clock == 1000


def test_slightly_late_event_still_counts():
    d = only("indicator_match", threshold=1)
    d.observe(event(ts=1000))
    hits = d.observe(event(ts=995, dst="203.0.113.66"))
    assert hits and hits[0]["rule"] == "indicator_match"


def test_ipv6_local_config():
    settings = deepcopy(DEFAULT_SETTINGS)
    settings["local_networks"] = ["fd00::/8"]
    d = Detector(DEFAULT_RULES, settings)
    assert d.local("fd00::1")
    assert not d.local("2001:db8::1")


def test_cidr_and_domain_indicators():
    settings = deepcopy(DEFAULT_SETTINGS)
    settings.update(indicators=["198.51.100.0/24"], domain_indicators=["bad.example"])
    rules = deepcopy(DEFAULT_RULES)
    d = Detector(rules, settings)
    cidr = d.observe(event(dst="198.51.100.9"))
    assert [a["evidence"]["matched_indicator"] for a in cidr if a["rule"] == "indicator_match"] == [
        "198.51.100.0/24"
    ]
    dns = d.observe(
        event(ts=101, dst="10.0.0.1", proto="UDP", sport=5000, dport=53, dns="cdn.bad.example")
    )
    assert [a["evidence"]["matched_indicator"] for a in dns if a["rule"] == "indicator_match"] == [
        "bad.example"
    ]
    assert not d.observe(
        event(ts=102, dst="10.0.0.1", proto="UDP", sport=5001, dport=53, dns="notbad.example")
    )


def test_brute_force():
    d = only("brute_force", threshold=10)
    hits = [
        a
        for i in range(10)
        for a in d.observe(event(ts=100 + i, dport=22, sport=40000 + i, flags="S"))
    ]
    assert len(hits) == 1 and hits[0]["rule"] == "brute_force"


def test_brute_force_ignores_retransmitted_syn():
    d = only("brute_force", threshold=5)
    assert not [a for i in range(20) for a in d.observe(event(ts=100 + i, dport=22, flags="S"))]


def test_regular_beaconing_detected():
    d = only("beaconing", threshold=8, window=600)
    hits = [
        a
        for i in range(8)
        for a in d.observe(event(ts=100 + i * 30, dst="198.51.100.7", sport=40000 + i, flags="S"))
    ]
    assert len(hits) == 1
    assert hits[0]["evidence"]["mean_interval_seconds"] == 30


def test_irregular_connections_are_not_beaconing():
    d = only("beaconing", threshold=8, window=600)
    times = [100, 103, 140, 141, 200, 290, 291, 400, 405, 470]
    hits = [
        a
        for i, ts in enumerate(times)
        for a in d.observe(event(ts=ts, dst="198.51.100.7", sport=40000 + i, flags="S"))
    ]
    assert not hits


def test_dns_tunneling():
    d = only("dns_tunneling", threshold=5)
    hits = []
    for i in range(5):
        name = f"{'a1b2c3d4e5f6' * 3}{i:04x}.data.tunnel.example"
        hits += d.observe(event(ts=100 + i, proto="UDP", sport=5000 + i, dport=53, dns=name))
    assert len(hits) == 1
    assert hits[0]["evidence"]["longest_label"] >= 30


def test_ordinary_dns_names_are_not_tunneling():
    for name in ("www.google.com", "api.github.com", "mail.example.co.uk", "a.b.c.d.example.test"):
        assert tunneling_score(name) is None


def test_dns_helpers():
    assert base_domain("x.y.Example.TEST.") == "example.test"
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2


def test_flow_table_reopens_after_close():
    flows = FlowTable()
    syn = event(flags="S")
    assert flows.observe(syn, 100)
    assert not flows.observe(syn, 100.5)
    assert not flows.observe(event(flags="FA"), 101)
    assert flows.observe(syn, 102)


def test_flow_table_is_bounded():
    flows = FlowTable(max_flows=100)
    for i in range(500):
        flows.observe(event(proto="UDP", sport=10000 + i), 100)
    assert len(flows) <= 101
