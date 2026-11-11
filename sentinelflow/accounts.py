"""Email address normalization used for account identity."""

from __future__ import annotations

import re

GMAIL_DOMAINS = ("gmail.com", "googlemail.com")
_LOCAL_PART = re.compile(r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*")
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def canonical_gmail(value: str) -> str:
    """Return the canonical mailbox for a Gmail address.

    Gmail ignores dots and ``+tag`` suffixes in consumer mailbox names, so
    ``An.Alyst+class@googlemail.com`` and ``analyst@gmail.com`` are the same
    account. Non-Gmail addresses raise :class:`ValueError`.
    """
    value = str(value).strip().lower()
    if len(value) > 254 or value.count("@") != 1:
        raise ValueError("Enter a valid Gmail address.")
    local, domain = value.split("@")
    if domain not in GMAIL_DOMAINS:
        raise ValueError("Registration requires a Gmail address ending in @gmail.com.")
    base, separator, tag = local.partition("+")
    if not re.fullmatch(r"[a-z0-9]+(?:\.[a-z0-9]+)*", base) or len(base) > 64:
        raise ValueError("Enter a valid Gmail address.")
    if separator and (not tag or not re.fullmatch(r"[a-z0-9._+\-]{1,64}", tag)):
        raise ValueError("Enter a valid Gmail address.")
    return base.replace(".", "") + "@gmail.com"


def canonical_email(value: str) -> str:
    """Validate and normalize any email address.

    Gmail addresses are reduced to their canonical mailbox so aliases cannot
    create duplicate accounts. Other providers are lower-cased only.
    """
    value = str(value).strip().lower()
    if len(value) > 254 or value.count("@") != 1:
        raise ValueError("Enter a valid email address.")
    local, domain = value.split("@")
    if domain in GMAIL_DOMAINS:
        return canonical_gmail(value)
    labels = domain.split(".")
    if (
        not 1 <= len(local) <= 64
        or not _LOCAL_PART.fullmatch(local)
        or len(labels) < 2
        or not all(_DOMAIN_LABEL.fullmatch(label) for label in labels)
        or labels[-1].isdigit()
    ):
        raise ValueError("Enter a valid email address.")
    return value
