"""
Fixed-offset timezone handling.

Real IANA tz data (zoneinfo) is not guaranteed to be present on a bare
Windows Python install without the optional `tzdata` package, so this
project treats the configured timezone as a single fixed UTC offset for the
whole run rather than depending on zoneinfo/tzdata. That matches the spec's
"single timezone with an explicit UTC offset" requirement without adding a
non-stdlib dependency.
"""

import datetime

TZ_OFFSETS_HOURS = {
    "Asia/Jerusalem": 3.0,
    "UTC": 0.0,
    "Europe/London": 1.0,
    "Europe/Berlin": 2.0,
    "America/New_York": -4.0,
    "America/Los_Angeles": -7.0,
    "Asia/Kolkata": 5.5,
    "Asia/Tokyo": 9.0,
    "Australia/Sydney": 10.0,
}


def get_tzinfo(name):
    if name not in TZ_OFFSETS_HOURS:
        raise ValueError(
            "Unsupported --timezone '{}'. Supported: {}".format(name, ", ".join(TZ_OFFSETS_HOURS))
        )
    hours = TZ_OFFSETS_HOURS[name]
    return datetime.timezone(datetime.timedelta(hours=hours), name)
