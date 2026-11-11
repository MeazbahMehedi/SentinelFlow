"""Authentication helpers: login throttling and timing-safe password checks."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from werkzeug.security import check_password_hash, generate_password_hash

# Verified against when an account does not exist so that response time does
# not reveal which usernames or email addresses are registered.
_DUMMY_HASH = generate_password_hash("sentinelflow-timing-equalizer")


def verify_password(stored_hash: str | None, password: str) -> bool:
    if not stored_hash:
        check_password_hash(_DUMMY_HASH, password)
        return False
    return check_password_hash(stored_hash, password)


class TooManyAttempts(Exception):
    def __init__(self, retry_after: int) -> None:
        super().__init__("Too many sign-in attempts.")
        self.retry_after = retry_after


class LoginLimiter:
    """Sliding-window limits on failed sign-ins per client address and per account.

    A successful sign-in clears only that account's failures. The address
    budget is never reset, so signing in to an attacker-controlled account
    cannot be used to keep guessing another account's password.
    """

    def __init__(
        self,
        address_limit: int = 20,
        address_window: int = 300,
        account_limit: int = 8,
        account_window: int = 900,
    ) -> None:
        self.limits = {
            "address": (address_limit, address_window),
            "account": (account_limit, account_window),
        }
        self._failures: defaultdict[tuple[str, str], deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: tuple[str, str], now: float) -> deque:
        window = self.limits[key[0]][1]
        events = self._failures[key]
        while events and now - events[0] >= window:
            events.popleft()
        if not events:
            self._failures.pop(key, None)
            events = self._failures[key]
        return events

    def check(self, address: str, account: str) -> None:
        now = time.time()
        with self._lock:
            for key in (("address", address), ("account", account.lower())):
                events = self._prune(key, now)
                limit, window = self.limits[key[0]]
                if len(events) >= limit:
                    raise TooManyAttempts(int(window - (now - events[0])) + 1)

    def failure(self, address: str, account: str) -> None:
        now = time.time()
        with self._lock:
            self._failures[("address", address)].append(now)
            self._failures[("account", account.lower())].append(now)
            if len(self._failures) > 10_000:
                for key in list(self._failures):
                    self._prune(key, now)

    def success(self, account: str) -> None:
        with self._lock:
            self._failures.pop(("account", account.lower()), None)
