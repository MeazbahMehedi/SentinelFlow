"""Bidirectional flow tracking used to identify connection initiators.

Counting every packet makes server responses look like scans: a web server
replying to fifteen client connections "contacts" fifteen client ports. The
flow table answers a narrower question for each packet: *does this packet open
a new connection, and if so, who initiated it?*
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

FlowKey = tuple[str, str, int, str, int]

TCP_IDLE_TIMEOUT = 300.0
DATAGRAM_IDLE_TIMEOUT = 120.0
MAX_TRACKED_FLOWS = 200_000


@dataclass(slots=True)
class Flow:
    initiator: tuple[str, int] | None
    last_seen: float
    closed: bool = False


def flow_key(event: dict) -> FlowKey:
    """Return a direction-independent key for an event."""
    a = (event["src"], int(event["sport"]))
    b = (event["dst"], int(event["dport"]))
    low, high = (a, b) if a <= b else (b, a)
    return (event["proto"], low[0], low[1], high[0], high[1])


def is_connection_attempt(event: dict) -> bool:
    """A TCP SYN without ACK is an explicit attempt to open a connection."""
    flags = event.get("flags", "")
    return event["proto"] == "TCP" and "S" in flags and "A" not in flags


class FlowTable:
    """Bounded LRU table of recently active flows."""

    def __init__(self, max_flows: int = MAX_TRACKED_FLOWS) -> None:
        self.max_flows = max_flows
        self._flows: OrderedDict[FlowKey, Flow] = OrderedDict()

    def __len__(self) -> int:
        return len(self._flows)

    def _expire(self, now: float) -> None:
        while self._flows:
            key, flow = next(iter(self._flows.items()))
            timeout = TCP_IDLE_TIMEOUT if key[0] == "TCP" else DATAGRAM_IDLE_TIMEOUT
            if now - flow.last_seen <= timeout and len(self._flows) <= self.max_flows:
                break
            self._flows.popitem(last=False)

    def observe(self, event: dict, now: float) -> bool:
        """Record ``event`` and return True when it opens a new flow.

        * TCP flows open only on SYN without ACK. Mid-stream packets of a
          connection that started before capture are tracked but never treated
          as new, so their direction cannot be misread.
        * UDP, ICMP and other protocols open on the first packet seen for a
          5-tuple; the sender of that packet is the initiator.
        """
        self._expire(now)
        key = flow_key(event)
        sender = (event["src"], int(event["sport"]))
        flow = self._flows.get(key)
        flags = event.get("flags", "")

        if event["proto"] == "TCP":
            attempt = is_connection_attempt(event)
            opens = attempt and (flow is None or flow.closed or flow.initiator != sender)
            if flow is None or opens:
                flow = Flow(initiator=sender if attempt else None, last_seen=now)
                self._flows[key] = flow
            if "F" in flags or "R" in flags:
                flow.closed = True
            elif attempt:
                flow.closed = False
        else:
            opens = flow is None
            if opens:
                flow = Flow(initiator=sender, last_seen=now)
                self._flows[key] = flow

        flow.last_seen = now
        self._flows.move_to_end(key)
        return opens
