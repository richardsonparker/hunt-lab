"""
Shared deterministic identity helpers: timestamps, hashes, GUIDs, logon IDs.

These are pure functions of their inputs (plus the run's seed for hashing)
so that the same Image path or the same (host, time, seq) tuple always
produces the same forensic identifier anywhere in the dataset.
"""

import hashlib
from datetime import timezone

_HASH_CACHE = {}


def format_time(dt):
    """ISO 8601 with explicit offset, millisecond precision. First-key value
    for every JSONL record per spec 6.1."""
    offset = dt.strftime("%z")
    offset = offset[:3] + ":" + offset[3:]
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "{:03d}".format(dt.microsecond // 1000) + offset


def format_utc_time(dt):
    """Traditional Sysmon/Windows UtcTime style: 'YYYY-MM-DD HH:MM:SS.fff' in UTC."""
    u = dt.astimezone(timezone.utc)
    return u.strftime("%Y-%m-%d %H:%M:%S.") + "{:03d}".format(u.microsecond // 1000)


def stable_hashes(seed, image_path):
    """A given Image path always maps to the same hash set for this seed."""
    key = (seed, image_path)
    if key in _HASH_CACHE:
        return _HASH_CACHE[key]
    basis = hashlib.sha256("{}::{}".format(seed, image_path).encode("utf-8")).digest()
    sha256 = hashlib.sha256(basis).hexdigest()
    md5 = hashlib.md5(basis).hexdigest()
    imphash = hashlib.md5(basis[::-1]).hexdigest()[:16]
    result = {
        "SHA256": sha256.upper(),
        "MD5": md5.upper(),
        "IMPHASH": imphash.upper(),
    }
    _HASH_CACHE[key] = result
    return result


def hashes_field(seed, image_path):
    h = stable_hashes(seed, image_path)
    return "MD5={},SHA256={},IMPHASH={}".format(h["MD5"], h["SHA256"], h["IMPHASH"])


def make_process_guid(machine_guid, dt, seq):
    time_hex = format(int(dt.astimezone(timezone.utc).timestamp()), "08x")
    return "{{{}-{}-{:08x}}}".format(machine_guid[:8], time_hex, seq)


def make_logon_id(rng_or_seedint):
    if hasattr(rng_or_seedint, "getrandbits"):
        val = rng_or_seedint.getrandbits(24) | 0x30000
    else:
        val = (int(rng_or_seedint) & 0xFFFFFF) | 0x30000
    return "0x{:x}".format(val)


def biased_business_hour_offset(rng):
    """Seconds-into-day offset biased toward a 08:00-18:00 business-hours peak."""
    if rng.random() < 0.75:
        return rng.randint(8 * 3600, 18 * 3600)
    return rng.randint(0, 24 * 3600 - 1)


class SeqCounters:
    """Small per-host monotonic sequence counters for ProcessGuids etc."""

    def __init__(self):
        self._counters = {}

    def next(self, host):
        n = self._counters.get(host, 0) + 1
        self._counters[host] = n
        return n
