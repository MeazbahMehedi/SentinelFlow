"""Background capture and replay worker. One worker per workspace."""

from __future__ import annotations

import json
import queue
import threading
import time

from .capture import open_capture_socket
from .detection import Detector
from .packets import normalize

BATCH_SIZE = 250
FLUSH_INTERVAL = 0.25
LIVE_QUEUE_SIZE = 20000
MAX_SESSIONS = 100

# Packet capture is a host-wide resource; only one account may sniff at a time.
_live_lock = threading.Lock()
_live_owner: list = [None]


class RetentionLimitReached(ValueError):
    pass


class SessionWriter:
    """Buffers analyzed packets and alerts and writes them in transactions.

    Committing every packet separately (and recounting the packets table each
    time) made ingestion slower as the database grew, which dropped live
    packets. Writes are now grouped and the retained-packet count is tracked
    in memory.
    """

    def __init__(self, store, sid: int, max_packets: int) -> None:
        self.store = store
        self.sid = sid
        self.max_packets = max_packets
        self.retained = store.one("SELECT COUNT(*) AS n FROM packets")["n"]
        self.packets: list[tuple] = []
        self.alerts: list[tuple] = []
        self.last_flush = time.monotonic()

    def add(self, event: dict, alerts: list[dict]) -> None:
        if self.retained + len(self.packets) >= self.max_packets:
            self.flush()
            raise RetentionLimitReached(
                "Retained packet limit reached. Delete an old session in Settings before continuing."
            )
        e = event
        self.packets.append(
            (
                self.sid,
                e["ts"],
                e["src"],
                e["dst"],
                e["sport"],
                e["dport"],
                e["proto"],
                e["length"],
                e["flags"],
                e["dns"],
            )
        )
        for a in alerts:
            self.alerts.append(
                (
                    self.sid,
                    a["ts"],
                    a["rule"],
                    a["severity"],
                    a["src"],
                    a["dst"],
                    a["title"],
                    json.dumps(a["evidence"]),
                )
            )
        if len(self.packets) >= BATCH_SIZE or alerts:
            self.flush()
        else:
            self.maybe_flush()

    def maybe_flush(self) -> None:
        if self.packets and time.monotonic() - self.last_flush >= FLUSH_INTERVAL:
            self.flush()

    def flush(self) -> None:
        self.last_flush = time.monotonic()
        if not self.packets and not self.alerts:
            return
        with self.store.connect() as c:
            c.executemany(
                "INSERT INTO packets(session_id,ts,src,dst,sport,dport,proto,length,flags,dns) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                self.packets,
            )
            c.executemany(
                "INSERT INTO alerts(session_id,ts,rule,severity,src,dst,title,evidence) "
                "VALUES(?,?,?,?,?,?,?,?)",
                self.alerts,
            )
            c.execute(
                "UPDATE sessions SET processed=processed+? WHERE id=?",
                (len(self.packets), self.sid),
            )
        self.retained += len(self.packets)
        self.packets.clear()
        self.alerts.clear()


class Engine:
    def __init__(self, store) -> None:
        self.store = store
        self.lock = threading.RLock()
        self.worker: threading.Thread | None = None
        self.active_id: int | None = None
        self.stop_event = threading.Event()
        self.paused = False
        self.speed = 1.0
        self.max_gap: float | None = None

    @property
    def busy(self) -> bool:
        return bool(self.worker and self.worker.is_alive())

    def _available(self) -> None:
        if self.busy:
            raise ValueError("Stop the active monitoring or replay session first.")

    def import_events(self, name: str, events: list[dict], source: str = "pcap") -> int:
        with self.store.connect() as c:
            sid = c.execute(
                "INSERT INTO sessions(name,source,total,created) VALUES(?,?,?,?)",
                (name, source, len(events), time.time()),
            ).lastrowid
            c.executemany(
                "INSERT INTO replay_packets VALUES(?,?,?)",
                [(sid, i, json.dumps(e)) for i, e in enumerate(events)],
            )
        self.store.audit("capture_import", f"Session {sid}: {len(events)} supported packets")
        return sid

    def _prepare(self, sid: int, speed: float) -> tuple[Detector, SessionWriter]:
        self.stop_event = threading.Event()
        self.paused = False
        self.speed = speed
        self.active_id = sid
        rules = self.store.config("rules")
        settings = self.store.config("settings")
        with self.store.connect() as c:
            c.execute("DELETE FROM packets WHERE session_id=?", (sid,))
            c.execute("DELETE FROM alerts WHERE session_id=?", (sid,))
            c.execute(
                "UPDATE sessions SET status='running',processed=0,error='',dropped=0,speed=?,"
                "rule_snapshot=? WHERE id=?",
                (speed, json.dumps({"rules": rules, "settings": settings}), sid),
            )
        writer = SessionWriter(self.store, sid, int(settings["max_packets"]))
        return Detector(rules, settings), writer

    # Replay -----------------------------------------------------------------
    def start_replay(self, sid: int, speed: float = 1, max_gap: float | None = None) -> None:
        with self.lock:
            self._available()
            row = self.store.one("SELECT * FROM sessions WHERE id=?", (sid,))
            if not row or row["source"] not in ("pcap", "demo"):
                raise ValueError("Select a replayable capture.")
            self.max_gap = max_gap
            detector, writer = self._prepare(sid, speed)
            self.worker = threading.Thread(
                target=self._replay,
                args=(sid, detector, writer),
                daemon=True,
                name="pcap-replay",
            )
            self.worker.start()
        self.store.audit("replay_start", str(sid))

    def _wait(self, delta: float, writer: SessionWriter) -> bool:
        """Sleep for ``delta`` capture-seconds at the current speed. False if stopped."""
        remaining = max(0.0, delta)
        if self.max_gap is not None:
            remaining = min(remaining, self.max_gap)
        while remaining > 0 and not self.stop_event.is_set():
            writer.maybe_flush()
            if self.paused:
                self.stop_event.wait(0.05)
                continue
            step = min(0.05, remaining / max(0.25, self.speed))
            start = time.monotonic()
            if self.stop_event.wait(step):
                return False
            if not self.paused:
                remaining -= (time.monotonic() - start) * self.speed
        while self.paused and not self.stop_event.is_set():
            writer.flush()
            self.stop_event.wait(0.05)
        return not self.stop_event.is_set()

    def _replay(self, sid: int, detector: Detector, writer: SessionWriter) -> None:
        try:
            events = self.store.rows(
                "SELECT event FROM replay_packets WHERE session_id=? ORDER BY seq",
                (sid,),
            )
            last = None
            for row in events:
                e = json.loads(row["event"])
                if not self._wait(e["ts"] - last if last is not None else 0, writer):
                    break
                writer.add(e, detector.observe(e))
                last = e["ts"]
            writer.flush()
            status = "stopped" if self.stop_event.is_set() else "finished"
            self.store.execute("UPDATE sessions SET status=? WHERE id=?", (status, sid))
        except Exception as exc:  # noqa: BLE001 - any worker failure is recorded on the session
            self._fail(sid, exc, writer)

    def _fail(self, sid: int, exc: Exception, writer: SessionWriter | None = None) -> None:
        if writer is not None:
            try:
                writer.flush()
            except Exception:  # noqa: BLE001 - report the original failure
                pass
        self.store.execute(
            "UPDATE sessions SET status='error',error=? WHERE id=?",
            (str(exc)[:400], sid),
        )
        self.store.audit("worker_error", f"{sid}: {str(exc)[:250]}")

    # Controls ---------------------------------------------------------------
    def control(self, sid: int, action: str, speed: float | None = None) -> None:
        with self.lock:
            if sid != self.active_id or not self.busy:
                raise ValueError("This session is not active.")
            if action == "pause":
                source = self.store.one("SELECT source FROM sessions WHERE id=?", (sid,))["source"]
                if source == "live":
                    raise ValueError("Live capture cannot be paused. Stop it instead.")
                self.paused = True
                self.store.execute("UPDATE sessions SET status='paused' WHERE id=?", (sid,))
            elif action == "resume":
                self.paused = False
                self.store.execute("UPDATE sessions SET status='running' WHERE id=?", (sid,))
            elif action == "stop":
                self.stop_event.set()
            elif action == "speed" and speed is not None:
                self.speed = speed
                self.store.execute("UPDATE sessions SET speed=? WHERE id=?", (speed, sid))
            else:
                raise ValueError("Unknown session action.")

    # Live capture -----------------------------------------------------------
    def start_live(self, iface: str) -> int:
        with self.lock:
            self._available()
            if self.store.one("SELECT COUNT(*) n FROM sessions")["n"] >= MAX_SESSIONS:
                raise ValueError(
                    "Session limit reached. Delete an older session before starting capture."
                )
            if not _live_lock.acquire(blocking=False):
                raise ValueError(
                    "Another account is already running live capture on this host. "
                    "Only one live capture can run at a time."
                )
            try:
                sock, sniffer_class = open_capture_socket(iface)
            except Exception:
                _live_lock.release()
                raise
            try:
                sid = self.store.execute(
                    "INSERT INTO sessions(name,source,total,created) VALUES(?,'live',0,?)",
                    (f"Live · {iface}", time.time()),
                )
                detector, writer = self._prepare(sid, 1)
                _live_owner[0] = self
                self.worker = threading.Thread(
                    target=self._live,
                    args=(sid, detector, writer, sock, sniffer_class),
                    daemon=True,
                    name="live-capture",
                )
                self.worker.start()
            except Exception:
                sock.close()
                _live_owner[0] = None
                _live_lock.release()
                raise
        self.store.audit("live_start", iface)
        return sid

    def _live(self, sid, detector, writer, sock, sniffer_class) -> None:
        pending: queue.Queue = queue.Queue(maxsize=LIVE_QUEUE_SIZE)
        dropped = [0]

        def callback(pkt) -> None:
            try:
                event = normalize(pkt)
                if event:
                    pending.put_nowait(event)
            except Exception:  # noqa: BLE001 - queue full or undecodable frame
                dropped[0] += 1

        sniffer = sniffer_class(opened_socket=sock, store=False, prn=callback)
        try:
            sniffer.start()
            while not self.stop_event.is_set():
                if getattr(sniffer, "exception", None):
                    raise RuntimeError(str(sniffer.exception))
                try:
                    event = pending.get(timeout=0.2)
                except queue.Empty:
                    writer.maybe_flush()
                    continue
                writer.add(event, detector.observe(event))
            writer.flush()
            self.store.execute("UPDATE sessions SET status='stopped' WHERE id=?", (sid,))
        except Exception as exc:  # noqa: BLE001 - any worker failure is recorded on the session
            self._fail(sid, exc, writer)
        finally:
            try:
                if sniffer.running:
                    sniffer.stop()
            except Exception as exc:  # noqa: BLE001
                self.store.audit("capture_cleanup", str(exc)[:200])
            finally:
                sock.close()
                _live_owner[0] = None
                _live_lock.release()
            # Queue contents remaining at Stop were captured but not analyzed.
            self.store.execute(
                "UPDATE sessions SET dropped=? WHERE id=?",
                (dropped[0] + pending.qsize(), sid),
            )

    def shutdown(self) -> None:
        self.stop_event.set()
        if self.busy:
            self.worker.join(timeout=3)
