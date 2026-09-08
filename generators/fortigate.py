"""
FortiGate (fortigate) traffic log line builder + benign baseline.

Space-separated key=value syslog matching FortiOS traffic log structure.
"""

import datetime

DEVNAME = "FGT-EDGE01"
DEVID = "FGT60F1234567890"

COMMON_APPS = [
    ("HTTPS", "web-browsing", 443),
    ("DNS", "dns", 53),
    ("Microsoft.Office.365", "cloud.email", 443),
    ("Windows.Update", "update", 443),
    ("HTTP", "web-browsing", 80),
]

COUNTRIES = ["United States", "Ireland", "Germany", "Netherlands", "Israel", "Reserved"]

# RFC 5737 documentation ranges only -- never route anywhere real.
BENIGN_EXTERNAL_BLOCKS = ["192.0.2.", "198.51.100."]
ATTACKER_INFRA_BLOCK = "203.0.113."


def benign_external_ip(rng):
    return rng.choice(BENIGN_EXTERNAL_BLOCKS) + str(rng.randint(2, 254))


def attacker_infra_ip(rng):
    return ATTACKER_INFRA_BLOCK + str(rng.randint(2, 254))


def _q(value):
    s = str(value)
    if " " in s:
        return '"{}"'.format(s)
    return s


def traffic_log(time_dt, srcip, srcport, srcintf, dstip, dstport, dstintf, sessionid,
                 proto, action, policyid, service, app, appcat, dstcountry, srccountry,
                 duration, sentbyte, rcvdbyte, sentpkt, rcvdpkt, subtype="forward",
                 trandisp="noop", transip=None, transport=None, level="notice"):
    date_str = time_dt.strftime("%Y-%m-%d")
    time_str = time_dt.strftime("%H:%M:%S")
    eventtime = int(time_dt.timestamp() * 1000000000)
    fields = [
        ("date", date_str), ("time", time_str), ("devname", DEVNAME), ("devid", DEVID),
        ("logid", "0000000013"), ("type", "traffic"), ("subtype", subtype), ("level", level),
        ("vd", "root"), ("eventtime", eventtime),
        ("srcip", srcip), ("srcport", srcport), ("srcintf", srcintf), ("srcintfrole", "lan" if srcintf != "wan1" else "wan"),
        ("dstip", dstip), ("dstport", dstport), ("dstintf", dstintf), ("dstintfrole", "wan" if dstintf == "wan1" else "lan"),
        ("sessionid", sessionid), ("proto", proto), ("action", action), ("policyid", policyid),
        ("policytype", "policy"), ("service", service), ("dstcountry", dstcountry), ("srccountry", srccountry),
        ("trandisp", trandisp),
    ]
    if transip:
        fields.append(("transip", transip))
    if transport:
        fields.append(("transport", transport))
    fields.extend([
        ("appid", abs(hash(app)) % 50000), ("app", app), ("appcat", appcat),
        ("duration", duration), ("sentbyte", sentbyte), ("rcvdbyte", rcvdbyte),
        ("sentpkt", sentpkt), ("rcvdpkt", rcvdpkt),
    ])
    return " ".join("{}={}".format(k, _q(v)) for k, v in fields)


_session_ctr = [10_000_000]


def generate_benign(seed, environment, rng, day_start, count, identity):
    from scenario.identity import biased_business_hour_offset
    hosts = [h for h in environment["hosts"] if h["role"] != "firewall"]

    for _ in range(count):
        host = rng.choice(hosts)
        t = day_start + datetime.timedelta(seconds=biased_business_hour_offset(rng))
        app, appcat, port = rng.choice(COMMON_APPS)
        dst_ip = benign_external_ip(rng)
        duration = rng.randint(1, 120)
        sentpkt = rng.randint(3, 200)
        rcvdpkt = rng.randint(3, 400)
        _session_ctr[0] += 1
        action = "accept" if rng.random() > 0.05 else "deny"
        line = traffic_log(
            t, host["ip"], rng.randint(1025, 65000), "internal", dst_ip, port, "wan1",
            _session_ctr[0], "tcp" if port != 53 else "udp", action, rng.randint(1, 5),
            app.lower(), app, appcat, rng.choice(COUNTRIES), "Israel", duration,
            sentpkt * rng.randint(60, 900), rcvdpkt * rng.randint(200, 3000), sentpkt, rcvdpkt,
        )
        yield "fortigate", t, line
