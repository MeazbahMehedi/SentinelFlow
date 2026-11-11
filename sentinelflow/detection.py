"""Explainable, event-time behavioral detection scoped to one monitoring session.

Every rule counts observations inside a sliding window keyed by the entities
involved (for example source and destination). Rules never inspect payloads
beyond DNS query names, and every alert carries the evidence that triggered it.
"""

from __future__ import annotations

import ipaddress
import math
import statistics
from collections import Counter, defaultdict, deque
from itertools import pairwise
from typing import NamedTuple

from .flows import FlowTable, is_connection_attempt


class RuleInfo(NamedTuple):
    title: str
    severity: str
    description: str
    mitre_id: str
    mitre_name: str
    tactic: str


RULE_INFO: dict[str, RuleInfo] = {
    "port_scan": RuleInfo(
        "Possible port scan",
        "high",
        "Distinct destination ports in new connections from one source to one target.",
        "T1046",
        "Network Service Discovery",
        "Discovery",
    ),
    "host_scan": RuleInfo(
        "Possible host scan",
        "high",
        "Distinct local-network hosts receiving new connections from one source "
        "(an internal sweep). Internet, multicast and broadcast destinations are ignored.",
        "T1018",
        "Remote System Discovery",
        "Discovery",
    ),
    "syn_burst": RuleInfo(
        "SYN burst indicator",
        "high",
        "TCP SYN packets without ACK from one source. This is a burst heuristic, "
        "not handshake reconstruction.",
        "T1498",
        "Network Denial of Service",
        "Impact",
    ),
    "dns_burst": RuleInfo(
        "DNS query burst",
        "medium",
        "DNS queries from one source; resolver traffic can legitimately be high.",
        "T1071.004",
        "Application Layer Protocol: DNS",
        "Command and Control",
    ),
    "outbound_volume": RuleInfo(
        "Large outbound transfer",
        "medium",
        "Bytes from a configured local network to a public address outside those networks.",
        "T1048",
        "Exfiltration Over Alternative Protocol",
        "Exfiltration",
    ),
    "indicator_match": RuleInfo(
        "Indicator match",
        "critical",
        "Destination IP, network or queried domain matches your configured indicator list.",
        "T1071",
        "Application Layer Protocol",
        "Command and Control",
    ),
    "brute_force": RuleInfo(
        "Authentication brute force",
        "high",
        "New connections from one source to one authentication service "
        "(SSH, RDP, SMB, FTP, databases and similar).",
        "T1110",
        "Brute Force",
        "Credential Access",
    ),
    "beaconing": RuleInfo(
        "Periodic beaconing",
        "medium",
        "Connections from one source to one service at highly regular intervals, "
        "a pattern typical of command-and-control check-ins.",
        "T1071",
        "Application Layer Protocol",
        "Command and Control",
    ),
    "dns_tunneling": RuleInfo(
        "Possible DNS tunneling",
        "high",
        "DNS queries with unusually long or high-entropy names under one domain.",
        "T1071.004",
        "Application Layer Protocol: DNS",
        "Command and Control",
    ),
}

SURICATA_INFO = RuleInfo(
    "Suricata signature",
    "medium",
    "Imported Suricata signature alert.",
    "",
    "",
    "External",
)

AUTH_PORTS = frozenset({21, 22, 23, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900, 5985})

BEACON_MIN_INTERVAL = 1.0
BEACON_MAX_JITTER = 0.15
TUNNEL_NAME_LENGTH = 52
TUNNEL_LABEL_LENGTH = 30
TUNNEL_ENTROPY_LABEL = 16
TUNNEL_ENTROPY = 3.5

STATE_CLEANUP_INTERVAL = 1000


def rule_info(rule: str) -> RuleInfo:
    return RULE_INFO.get(rule, SURICATA_INFO)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def base_domain(name: str) -> str:
    """Approximate registered domain (last two labels; no public suffix list)."""
    labels = [label for label in name.lower().rstrip(".").split(".") if label]
    return ".".join(labels[-2:]) if labels else ""


def tunneling_score(name: str) -> dict | None:
    """Return evidence when a DNS name looks like encoded data, else None."""
    labels = [label for label in name.rstrip(".").split(".") if label]
    if len(labels) < 3:
        return None
    query_labels = labels[:-2]
    longest = max(query_labels, key=len)
    entropy = shannon_entropy(longest)
    suspicious = (
        len(name) >= TUNNEL_NAME_LENGTH
        or len(longest) >= TUNNEL_LABEL_LENGTH
        or (len(longest) >= TUNNEL_ENTROPY_LABEL and entropy >= TUNNEL_ENTROPY)
    )
    if not suspicious:
        return None
    return {
        "name_length": len(name),
        "longest_label": len(longest),
        "entropy": round(entropy, 2),
    }


class Detector:
    """Stateful detector. Feed events in capture-time order with :meth:`observe`."""

    def __init__(self, rules: dict, settings: dict) -> None:
        self.rules = rules
        self.networks = [
            ipaddress.ip_network(n, strict=False) for n in settings.get("local_networks", [])
        ]
        self.indicator_ips: set[str] = set()
        self.indicator_networks: list = []
        for value in settings.get("indicators", []):
            network = ipaddress.ip_network(value, strict=False)
            if network.num_addresses == 1:
                self.indicator_ips.add(str(network.network_address))
            else:
                self.indicator_networks.append(network)
        self.indicator_domains = {
            d.lower().rstrip(".") for d in settings.get("domain_indicators", []) if d
        }
        self.broadcasts = {
            str(n.broadcast_address) for n in self.networks if n.version == 4 and n.prefixlen < 31
        }
        self.windows: defaultdict[tuple, deque] = defaultdict(deque)
        self.last_alert: dict[tuple, float] = {}
        self.flows = FlowTable()
        self.clock = float("-inf")
        self.count = 0
        self._address_cache: dict[str, tuple[bool, bool]] = {}

    # Address classification -------------------------------------------------
    def _classify(self, ip: str) -> tuple[bool, bool]:
        """Return ``(is_local, is_special)`` for an address, cached."""
        cached = self._address_cache.get(ip)
        if cached is None:
            address = ipaddress.ip_address(ip)
            local = any(address.version == n.version and address in n for n in self.networks)
            special = (
                address.is_multicast
                or address.is_unspecified
                or address.is_loopback
                or address.is_link_local
                or ip == "255.255.255.255"
                or ip in self.broadcasts
            )
            if len(self._address_cache) > 50_000:
                self._address_cache.clear()
            cached = self._address_cache[ip] = (local, special)
        return cached

    def local(self, ip: str) -> bool:
        return self._classify(ip)[0]

    def special(self, ip: str) -> bool:
        return self._classify(ip)[1]

    def _indicator(self, event: dict) -> str | None:
        dst = event["dst"]
        if dst in self.indicator_ips:
            return dst
        if self.indicator_networks:
            address = ipaddress.ip_address(dst)
            for network in self.indicator_networks:
                if address.version == network.version and address in network:
                    return str(network)
        query = (event.get("dns") or "").lower().rstrip(".")
        if query and self.indicator_domains and not event.get("dns_response"):
            for domain in self.indicator_domains:
                if query == domain or query.endswith("." + domain):
                    return domain
        return None

    # Main entry point -------------------------------------------------------
    def observe(self, e: dict) -> list[dict]:
        # Late events never move the logical clock backwards; they still count
        # in windows that have not expired yet.
        now = max(self.clock, e["ts"])
        self.clock = now
        self.count += 1
        new_flow = self.flows.observe(e, now)
        candidates: list[tuple[str, tuple, object, dict]] = []

        if new_flow and e["proto"] in ("TCP", "UDP"):
            candidates.append(("port_scan", (e["src"], e["dst"]), e["dport"], {}))
            if e["dport"] in AUTH_PORTS:
                candidates.append(("brute_force", (e["src"], e["dst"], e["dport"]), 1, {}))
            candidates.append(("beaconing", (e["src"], e["dst"], e["dport"]), e["ts"], {}))
        if new_flow and self.local(e["dst"]) and not self.special(e["dst"]):
            candidates.append(("host_scan", (e["src"],), e["dst"], {}))
        if is_connection_attempt(e):
            candidates.append(("syn_burst", (e["src"],), 1, {}))
        if e.get("dns") and not e.get("dns_response", False):
            candidates.append(("dns_burst", (e["src"],), 1, {}))
            tunnel = tunneling_score(e["dns"])
            if tunnel:
                tunnel["example_query"] = e["dns"][:120]
                candidates.append(("dns_tunneling", (e["src"], base_domain(e["dns"])), 1, tunnel))
        if self.local(e["src"]) and not self.local(e["dst"]) and not self.special(e["dst"]):
            candidates.append(("outbound_volume", (e["src"],), e["length"], {}))
        matched = self._indicator(e)
        if matched:
            candidates.append(
                (
                    "indicator_match",
                    (e["src"], e["dst"]),
                    1,
                    {"matched_indicator": matched},
                )
            )

        result = [alert for c in candidates if (alert := self._evaluate(e, now, *c))]
        if self.count % STATE_CLEANUP_INTERVAL == 0:
            self._cleanup(now)
        return result

    def _evaluate(self, e: dict, now: float, rule: str, parts: tuple, value, extra: dict):
        cfg = self.rules.get(rule)
        if not cfg or not cfg["enabled"]:
            return None
        key = (rule, *parts)
        window = self.windows[key]
        cutoff = now - cfg["window"]
        while window and window[0][0] < cutoff:
            window.popleft()
        # Very late packets remain visible in traffic but cannot affect expired windows.
        if e["ts"] < cutoff:
            return None
        window.append((e["ts"], value))

        evidence: dict = {}
        if rule in ("port_scan", "host_scan"):
            observed = len({x[1] for x in window})
        elif rule == "outbound_volume":
            observed = sum(x[1] for x in window)
        elif rule == "beaconing":
            observed = len(window)
            if observed < cfg["threshold"]:
                return None
            times = sorted(x[1] for x in window)
            intervals = [b - a for a, b in pairwise(times)]
            mean = statistics.fmean(intervals)
            jitter = statistics.pstdev(intervals) / mean if mean > 0 else 1.0
            if mean < BEACON_MIN_INTERVAL or jitter > BEACON_MAX_JITTER:
                return None
            evidence = {
                "mean_interval_seconds": round(mean, 3),
                "jitter_ratio": round(jitter, 3),
            }
        else:
            observed = len(window)

        if observed < cfg["threshold"]:
            return None
        if now - self.last_alert.get(key, float("-inf")) < cfg["window"]:
            return None
        self.last_alert[key] = now
        info = RULE_INFO[rule]
        evidence.update(
            observed=observed,
            threshold=cfg["threshold"],
            window_seconds=cfg["window"],
            description=info.description,
            event_time=e["ts"],
            mitre=f"{info.mitre_id} {info.mitre_name}",
            note="Rule indicator; investigate context before concluding malicious intent.",
            **extra,
        )
        return dict(
            ts=e["ts"],
            rule=rule,
            severity=info.severity,
            src=e["src"],
            dst=e["dst"],
            title=info.title,
            evidence=evidence,
        )

    def _cleanup(self, now: float) -> None:
        """Bound inactive state without retaining every source forever."""
        for key in list(self.windows):
            cfg = self.rules.get(key[0])
            cutoff = now - (cfg["window"] if cfg else 0)
            window = self.windows[key]
            while window and window[0][0] < cutoff:
                window.popleft()
            if not window:
                del self.windows[key]
                self.last_alert.pop(key, None)
