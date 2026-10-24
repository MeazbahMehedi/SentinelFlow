"""Gmail identity normalization and per-account local workspace routing."""
import re


def canonical_gmail(value):
    value=str(value).strip().lower()
    if len(value)>254 or value.count('@')!=1:
        raise ValueError('Enter a valid Gmail address.')
    local,domain=value.split('@')
    if domain not in ('gmail.com','googlemail.com'):
        raise ValueError('Registration requires a Gmail address ending in @gmail.com.')
    base,separator,tag=local.partition('+')
    if not re.fullmatch(r'[a-z0-9]+(?:\.[a-z0-9]+)*',base) or len(base)>64:
        raise ValueError('Enter a valid Gmail address.')
    if separator and (not tag or not re.fullmatch(r'[a-z0-9._+\-]{1,64}',tag)):
        raise ValueError('Enter a valid Gmail address.')
    # Gmail ignores dots and plus tags in consumer gmail.com mailbox names.
    return base.replace('.','')+'@gmail.com'
